// Unit tests for api/src/observability/mirror-failures.js — the durable
// failure ledger + self-healing retry for failed BACKGROUND ("waitUntil")
// Arweave mirror uploads (Tarn issue #47).
//
// D1 is mocked with a small in-memory store that understands exactly the SQL
// the module issues, so dedup / retry / prune logic is exercised against real
// state transitions (not just "did it call .run()"). No live network / wrangler.
//
// Run: node --test tests/unit/observability-mirror-failures.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  recordMirrorFailure,
  mirrorUploadWithTracking,
  countOpenMirrorFailures,
  selectRetryableMirrorFailures,
  markMirrorResolved,
  retryMirrorFailures,
  pruneResolvedMirrorFailures,
  MAX_STORED_BYTES,
} from '../../api/src/observability/mirror-failures.js';

const NOW = 1_700_000_000_000;

// ---- in-memory mock D1 for arweave_mirror_failures ----
// Implements the subset of statements mirror-failures.js issues:
//   SELECT id FROM ... WHERE intended_txid=? AND resolved_at IS NULL
//   UPDATE ... SET attempt_count = attempt_count + 1, last_attempt_at, error_message WHERE id=?
//   INSERT INTO arweave_mirror_failures (...)
//   SELECT COUNT(*) AS c ... WHERE resolved_at IS NULL
//   SELECT id, intended_txid, namespace, signed_data_item, attempt_count ... (retry select)
//   UPDATE ... SET resolved_at=?, last_attempt_at=? WHERE id=?
//   DELETE ... WHERE resolved_at IS NOT NULL AND resolved_at < ?
function makeDB() {
  const rows = [];
  let nextId = 1;

  function prepare(sql) {
    return {
      _sql: sql,
      _p: [],
      bind(...p) { this._p = p; return this; },

      async first() {
        // dedup lookup
        if (/SELECT id FROM arweave_mirror_failures WHERE intended_txid/.test(this._sql)) {
          const txid = this._p[0];
          const r = rows.find((x) => x.intended_txid === txid && x.resolved_at == null);
          return r ? { id: r.id } : null;
        }
        // open count
        if (/COUNT\(\*\) AS c FROM arweave_mirror_failures WHERE resolved_at IS NULL/.test(this._sql)) {
          return { c: rows.filter((x) => x.resolved_at == null).length };
        }
        return null;
      },

      async all() {
        // retry select
        if (/FROM arweave_mirror_failures\s+WHERE resolved_at IS NULL AND signed_data_item IS NOT NULL/.test(this._sql)) {
          const limit = this._p[0];
          const results = rows
            .filter((x) => x.resolved_at == null && x.signed_data_item != null)
            .sort((a, b) => a.created_at - b.created_at)
            .slice(0, limit)
            .map((x) => ({
              id: x.id,
              intended_txid: x.intended_txid,
              namespace: x.namespace,
              signed_data_item: x.signed_data_item,
              attempt_count: x.attempt_count,
            }));
          return { results };
        }
        return { results: [] };
      },

      async run() {
        if (/^INSERT INTO arweave_mirror_failures/.test(this._sql.trim())) {
          const [created_at, namespace, intended_txid, data_lookup_key, tags_json, signed_data_item, error_message, last_attempt_at] = this._p;
          rows.push({
            id: nextId++,
            created_at, namespace, intended_txid, data_lookup_key, tags_json,
            signed_data_item, error_message,
            attempt_count: 1, last_attempt_at, resolved_at: null,
          });
          return { meta: { changes: 1 } };
        }
        // bump attempt (record dedup OR retry failure)
        if (/SET attempt_count = attempt_count \+ 1/.test(this._sql)) {
          // last param is id; figure out which form
          const id = this._p[this._p.length - 1];
          const r = rows.find((x) => x.id === id);
          if (r) {
            r.attempt_count += 1;
            // forms: (now, errMsg, id) for both dedup-record and retry-bump
            r.last_attempt_at = this._p[0];
            if (this._p[1] != null) r.error_message = this._p[1];
            return { meta: { changes: 1 } };
          }
          return { meta: { changes: 0 } };
        }
        // mark resolved
        if (/SET resolved_at = \?1, last_attempt_at = \?1 WHERE id = \?2/.test(this._sql)) {
          const [ts, id] = this._p;
          const r = rows.find((x) => x.id === id);
          if (r) { r.resolved_at = ts; r.last_attempt_at = ts; return { meta: { changes: 1 } }; }
          return { meta: { changes: 0 } };
        }
        // prune resolved
        if (/DELETE FROM arweave_mirror_failures WHERE resolved_at IS NOT NULL AND resolved_at < \?1/.test(this._sql)) {
          const cutoff = this._p[0];
          const before = rows.length;
          for (let i = rows.length - 1; i >= 0; i--) {
            if (rows[i].resolved_at != null && rows[i].resolved_at < cutoff) rows.splice(i, 1);
          }
          return { meta: { changes: before - rows.length } };
        }
        return { meta: { changes: 0 } };
      },
    };
  }

  return { _rows: rows, prepare };
}

const TAGS = [
  { name: 'App', value: 'tarn' },
  { name: 'Type', value: 'cred' },
  { name: 'Lk', value: 'abc123' },
];

describe('recordMirrorFailure', () => {
  it('inserts a row with metadata + stored bytes when under the cap', async () => {
    const db = makeDB();
    const bytes = new Uint8Array(1024);
    const res = await recordMirrorFailure(db, {
      namespace: 'cred',
      intendedTxid: 'tx1',
      tags: TAGS,
      signedDataItem: bytes,
      errorMessage: 'turbo_403: dry wallet',
      now: NOW,
    });
    assert.equal(res.recorded, true);
    assert.equal(res.storedBytes, true);
    assert.equal(db._rows.length, 1);
    const row = db._rows[0];
    assert.equal(row.namespace, 'cred');
    assert.equal(row.intended_txid, 'tx1');
    assert.equal(row.data_lookup_key, 'abc123'); // derived from Lk tag
    assert.equal(row.attempt_count, 1);
    assert.equal(row.resolved_at, null);
    assert.ok(row.signed_data_item instanceof Uint8Array);
  });

  it('records metadata only (NULL bytes) when the signed item exceeds the cap', async () => {
    const db = makeDB();
    const tooBig = new Uint8Array(MAX_STORED_BYTES + 1);
    const res = await recordMirrorFailure(db, {
      namespace: 'share-log',
      intendedTxid: 'txBig',
      tags: TAGS,
      signedDataItem: tooBig,
      now: NOW,
    });
    assert.equal(res.recorded, true);
    assert.equal(res.storedBytes, false);
    assert.equal(db._rows[0].signed_data_item, null);
  });

  it('de-dupes: a second failure for the same open txid bumps attempt_count, no new row', async () => {
    const db = makeDB();
    await recordMirrorFailure(db, { namespace: 'cred', intendedTxid: 'txDup', tags: TAGS, signedDataItem: new Uint8Array(8), now: NOW });
    const res2 = await recordMirrorFailure(db, { namespace: 'cred', intendedTxid: 'txDup', tags: TAGS, signedDataItem: new Uint8Array(8), errorMessage: 'again', now: NOW + 1000 });
    assert.equal(res2.deduped, true);
    assert.equal(db._rows.length, 1);
    assert.equal(db._rows[0].attempt_count, 2);
    assert.equal(db._rows[0].error_message, 'again');
    assert.equal(db._rows[0].last_attempt_at, NOW + 1000);
  });

  it('is best-effort: never throws, returns recorded:false when db.prepare throws', async () => {
    const badDb = { prepare() { throw new Error('d1 down'); } };
    const res = await recordMirrorFailure(badDb, { namespace: 'cred', intendedTxid: 'x', now: NOW });
    assert.equal(res.recorded, false);
    assert.match(res.error, /d1 down/);
  });

  it('returns recorded:false when namespace missing', async () => {
    const db = makeDB();
    const res = await recordMirrorFailure(db, { intendedTxid: 'x', now: NOW });
    assert.equal(res.recorded, false);
    assert.equal(db._rows.length, 0);
  });
});

describe('mirrorUploadWithTracking', () => {
  it('does NOT record on a successful upload', async () => {
    const db = makeDB();
    const r = await mirrorUploadWithTracking({
      uploadFn: async () => ({ ok: true, turboTxid: 'tx1' }),
      db, namespace: 'cred', intendedTxid: 'tx1', tags: TAGS, signedDataItem: new Uint8Array(8), now: NOW,
    });
    assert.equal(r.ok, true);
    assert.equal(db._rows.length, 0);
  });

  it('records a failure row when the upload returns ok:false', async () => {
    const db = makeDB();
    const r = await mirrorUploadWithTracking({
      uploadFn: async () => ({ ok: false, status: 503, body: 'turbo down' }),
      db, namespace: 'cred', intendedTxid: 'tx2', tags: TAGS, signedDataItem: new Uint8Array(8), now: NOW,
    });
    assert.equal(r.ok, false);
    assert.equal(db._rows.length, 1);
    assert.equal(db._rows[0].intended_txid, 'tx2');
    assert.match(db._rows[0].error_message, /turbo_503/);
  });

  it('records a failure row and does not throw when the upload throws', async () => {
    const db = makeDB();
    const r = await mirrorUploadWithTracking({
      uploadFn: async () => { throw new Error('socket reset'); },
      db, namespace: 'share-inbox', intendedTxid: 'tx3', tags: TAGS, signedDataItem: new Uint8Array(8), now: NOW,
    });
    assert.equal(r.ok, false);
    assert.equal(db._rows.length, 1);
    assert.match(db._rows[0].error_message, /socket reset/);
  });
});

describe('countOpenMirrorFailures', () => {
  it('counts only unresolved rows', async () => {
    const db = makeDB();
    await recordMirrorFailure(db, { namespace: 'cred', intendedTxid: 'a', tags: TAGS, signedDataItem: new Uint8Array(8), now: NOW });
    await recordMirrorFailure(db, { namespace: 'cred', intendedTxid: 'b', tags: TAGS, signedDataItem: new Uint8Array(8), now: NOW });
    await markMirrorResolved(db, db._rows[0].id, NOW + 5);
    const { count, error } = await countOpenMirrorFailures(db);
    assert.equal(error, null);
    assert.equal(count, 1);
  });

  it('returns count 0 + error on a broken db, never throws', async () => {
    const badDb = { prepare() { throw new Error('boom'); } };
    const { count, error } = await countOpenMirrorFailures(badDb);
    assert.equal(count, 0);
    assert.match(error, /boom/);
  });
});

describe('selectRetryableMirrorFailures', () => {
  it('returns only unresolved rows WITH stored bytes, oldest-first, bounded', async () => {
    const db = makeDB();
    // row with bytes (retryable)
    await recordMirrorFailure(db, { namespace: 'cred', intendedTxid: 'r1', tags: TAGS, signedDataItem: new Uint8Array(8), now: NOW });
    // row WITHOUT bytes (over cap → metadata only → NOT retryable)
    await recordMirrorFailure(db, { namespace: 'cred', intendedTxid: 'r2', tags: TAGS, signedDataItem: new Uint8Array(MAX_STORED_BYTES + 1), now: NOW + 1 });
    // another with bytes
    await recordMirrorFailure(db, { namespace: 'cred', intendedTxid: 'r3', tags: TAGS, signedDataItem: new Uint8Array(8), now: NOW + 2 });

    const sel = await selectRetryableMirrorFailures(db, 10);
    const txids = sel.map((r) => r.intended_txid);
    assert.deepEqual(txids, ['r1', 'r3']); // r2 excluded (no bytes), oldest-first
  });

  it('respects the limit', async () => {
    const db = makeDB();
    for (let i = 0; i < 5; i++) {
      await recordMirrorFailure(db, { namespace: 'cred', intendedTxid: 'x' + i, tags: TAGS, signedDataItem: new Uint8Array(8), now: NOW + i });
    }
    const sel = await selectRetryableMirrorFailures(db, 3);
    assert.equal(sel.length, 3);
  });
});

describe('retryMirrorFailures', () => {
  it('re-uploads stored bytes; resolves on success, bumps attempt on failure', async () => {
    const db = makeDB();
    await recordMirrorFailure(db, { namespace: 'cred', intendedTxid: 'ok1', tags: TAGS, signedDataItem: new Uint8Array([1, 2, 3]), now: NOW });
    await recordMirrorFailure(db, { namespace: 'cred', intendedTxid: 'fail1', tags: TAGS, signedDataItem: new Uint8Array([4, 5, 6]), now: NOW + 1 });

    // Uploader: succeeds for the first row's bytes, fails for the second.
    const seen = [];
    const uploadImpl = async (bytes) => {
      seen.push(Array.from(bytes));
      return bytes[0] === 1 ? { ok: true } : { ok: false, status: 500, body: 'still down' };
    };

    const summary = await retryMirrorFailures(db, { uploadImpl, batch: 10, now: NOW + 100 });
    assert.equal(summary.attempted, 2);
    assert.equal(summary.resolved, 1);
    assert.equal(summary.stillFailing, 1);

    const okRow = db._rows.find((r) => r.intended_txid === 'ok1');
    const failRow = db._rows.find((r) => r.intended_txid === 'fail1');
    assert.equal(okRow.resolved_at, NOW + 100);
    assert.equal(failRow.resolved_at, null);
    assert.equal(failRow.attempt_count, 2); // bumped
    assert.match(failRow.error_message, /still down/);
    // The uploader actually received the stored bytes.
    assert.deepEqual(seen.sort((a, b) => a[0] - b[0]), [[1, 2, 3], [4, 5, 6]]);
  });

  it('normalizes ArrayBuffer-backed BLOBs to Uint8Array before upload', async () => {
    const db = makeDB();
    await recordMirrorFailure(db, { namespace: 'cred', intendedTxid: 'ab1', tags: TAGS, signedDataItem: new Uint8Array([9]), now: NOW });
    // Simulate D1 returning the BLOB as an ArrayBuffer.
    db._rows[0].signed_data_item = new Uint8Array([9, 9, 9]).buffer;

    let got = null;
    const uploadImpl = async (bytes) => { got = bytes; return { ok: true }; };
    const summary = await retryMirrorFailures(db, { uploadImpl, batch: 5, now: NOW + 1 });
    assert.equal(summary.resolved, 1);
    assert.ok(got instanceof Uint8Array);
    assert.deepEqual(Array.from(got), [9, 9, 9]);
  });

  it('is a no-op (empty summary) when there is nothing to retry', async () => {
    const db = makeDB();
    const summary = await retryMirrorFailures(db, { uploadImpl: async () => ({ ok: true }), batch: 5, now: NOW });
    assert.deepEqual(summary, { attempted: 0, resolved: 0, stillFailing: 0, errors: 0 });
  });
});

describe('pruneResolvedMirrorFailures', () => {
  it('deletes resolved rows older than the cutoff, keeps open + recent rows', async () => {
    const db = makeDB();
    const DAY = 24 * 60 * 60 * 1000;
    // open row
    await recordMirrorFailure(db, { namespace: 'cred', intendedTxid: 'open', tags: TAGS, signedDataItem: new Uint8Array(8), now: NOW });
    // old resolved row
    await recordMirrorFailure(db, { namespace: 'cred', intendedTxid: 'oldres', tags: TAGS, signedDataItem: new Uint8Array(8), now: NOW });
    // recent resolved row
    await recordMirrorFailure(db, { namespace: 'cred', intendedTxid: 'newres', tags: TAGS, signedDataItem: new Uint8Array(8), now: NOW });
    await markMirrorResolved(db, db._rows.find((r) => r.intended_txid === 'oldres').id, NOW - 30 * DAY);
    await markMirrorResolved(db, db._rows.find((r) => r.intended_txid === 'newres').id, NOW - 1 * DAY);

    const res = await pruneResolvedMirrorFailures(db, { now: NOW, retentionDays: 7 });
    assert.equal(res.deleted, 1);
    const remaining = db._rows.map((r) => r.intended_txid).sort();
    assert.deepEqual(remaining, ['newres', 'open']); // oldres pruned, open never pruned
  });
});
