// Batch create: partial-failure resume via the idempotency key (tarn#67).
//
// Before this fix, a mid-batch Turbo failure returned `status: 'partial'`
// WITHOUT storing anything under the X-Idempotency-Key — so a retry with the
// same key re-processed the batch from index 0, re-uploading entries that had
// already landed on Arweave as fresh DataItems (duplicate permanent writes,
// wasted wallet spend; reads dedupe by Eid so user data stayed correct).
//
// These tests drive the REAL handleBatchCreate (real signing, real idempotency
// module) against a D1 shim and a scripted Turbo endpoint, asserting:
//   (a) a mid-batch failure persists a __batchProgress record under the key;
//   (b) the retry RESUMES at failedAt — landed entries are not re-signed or
//       re-uploaded, and keep their original txids in the final response;
//   (c) after full success the stored response is final (no progress marker)
//       and a further replay returns it verbatim with zero Turbo calls.
//
// Run: node --import tsx --test tests/unit/write-batch-partial-idempotency.test.js
//   or via the umbrella: npm run test:unit

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import { handleBatchCreate } from '../../api/src/routes/write.js';
import { signJWT, _resetHMACKey } from '../../api/src/auth.js';

const JWT_SECRET = btoa('batch-partial-idem-test-secret-0123456789ab');
const APP_SIGNING_KEY = '33'.repeat(32);
const APP = 'bookish';
const TYPE = 'books';
const DLK = 'c'.repeat(64);
const IDEM_KEY = 'batch-retry-key-0001';

const TURBO_UPLOAD_URL = 'https://upload.ardrive.io/v1/tx/ethereum';
const originalFetch = globalThis.fetch;

// Scripted Turbo: outcomes[i] ('ok' | 'fail') decides upload call i.
function interceptTurbo(outcomes) {
  const calls = { count: 0 };
  globalThis.fetch = async (url) => {
    if (String(url) !== TURBO_UPLOAD_URL) {
      throw new Error(`unexpected fetch in batch test: ${url}`);
    }
    const outcome = outcomes[Math.min(calls.count, outcomes.length - 1)];
    calls.count += 1;
    if (outcome === 'fail') {
      return { ok: false, status: 503, async text() { return 'turbo down'; } };
    }
    return { ok: true, status: 200, async text() { return JSON.stringify({ id: 'turbo-accepted' }); } };
  };
  return calls;
}

// D1 shim covering the SQL the batch path issues: write rate limit counter,
// account rules lookup, the idempotency_keys table, and tolerant defaults for
// entries/cache_meta/pending_txs writes.
function makeD1() {
  const idemRows = new Map();   // scoped_key -> { response_json, status_code }
  const counters = new Map();   // write_rate_limits key -> count
  const entryWrites = [];       // txids written through to entries
  return {
    _idemRows: idemRows,
    _entryWrites: entryWrites,
    prepare(sql) {
      let args = [];
      return {
        bind(...a) { args = a; return this; },
        async first() {
          if (/INSERT INTO write_rate_limits/.test(sql)) {
            const next = (counters.get(args[0]) ?? 0) + 1;
            counters.set(args[0], next);
            return { count: next };
          }
          if (/SELECT rules_json FROM accounts/.test(sql)) {
            return { rules_json: '[]' }; // explicit no-restrictions
          }
          if (/SELECT response_json, status_code FROM idempotency_keys/.test(sql)) {
            return idemRows.get(args[0]) ?? null;
          }
          return null;
        },
        async run() {
          if (/INSERT INTO idempotency_keys/.test(sql)) {
            idemRows.set(args[0], { response_json: args[1], status_code: args[2] });
          }
          if (/INSERT INTO entries/.test(sql)) {
            entryWrites.push(args[0]);
          }
          return { success: true };
        },
        async all() { return { results: [] }; },
      };
    },
    async batch(stmts) {
      for (const s of stmts) await s.run();
      return stmts.map(() => ({ results: [] }));
    },
  };
}

function b64(fillByte) {
  const bytes = new Uint8Array(48).fill(fillByte);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function batchBody() {
  const tagsFor = (eid) => [
    { name: 'App', value: APP },
    { name: 'Type', value: TYPE },
    { name: 'Lk', value: DLK },
    { name: 'Eid', value: eid },
  ];
  return {
    entries: [
      { data: b64(0x01), tags: tagsFor('e1') },
      { data: b64(0x02), tags: tagsFor('e2') },
      { data: b64(0x03), tags: tagsFor('e3') },
    ],
  };
}

function makeRequest(jwt, body) {
  return {
    url: 'https://api.tarn.dev/api/v1/entries/batch',
    headers: {
      get(name) {
        if (name === 'Authorization') return `Bearer ${jwt}`;
        if (name.toLowerCase() === 'x-idempotency-key') return IDEM_KEY;
        if (name === 'CF-Connecting-IP') return '127.0.0.1';
        return null;
      },
    },
    async json() { return body; },
  };
}

const ctx = { waitUntil(p) { Promise.resolve(p).catch(() => {}); } };
const cors = {};

async function userJwt() {
  return await signJWT({ sub: DLK, role: 'user', app: APP }, JWT_SECRET);
}

describe('tarn#67 — batch partial failure resumes via idempotency key', () => {
  beforeEach(() => {
    _resetHMACKey();
    globalThis.__TARN_SKIP_TURBO__ = false; // real upload path → interceptor
  });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it('mid-batch failure stores progress; retry resumes at failedAt without re-uploading landed entries', async () => {
    const db = makeD1();
    const env = { DB: db, JWT_SECRET, APP_SIGNING_KEY };
    const jwt = await userJwt();

    // Attempt 1: entry 0 lands, entry 1's upload fails.
    const turbo1 = interceptTurbo(['ok', 'fail']);
    const res1 = await handleBatchCreate(makeRequest(jwt, batchBody()), env, ctx, cors);
    assert.equal(res1.status, 502);
    const body1 = await res1.json();
    assert.equal(body1.status, 'partial');
    assert.equal(body1.failedAt, 1);
    assert.equal(body1.entries.length, 1);
    assert.equal(turbo1.count, 2, 'attempt 1: one landed upload + one failed upload');
    const landedTxid = body1.entries[0].txid;

    // Progress record persisted under the key, marked as such.
    const stored1 = JSON.parse([...db._idemRows.values()][0].response_json);
    assert.equal(stored1.__batchProgress, true);
    assert.equal(stored1.entries.length, 1);
    assert.equal(stored1.entries[0].txid, landedTxid);

    // Attempt 2 (same key, same batch): Turbo healthy again.
    const turbo2 = interceptTurbo(['ok', 'ok', 'ok']);
    const res2 = await handleBatchCreate(makeRequest(jwt, batchBody()), env, ctx, cors);
    assert.equal(res2.status, 200);
    const body2 = await res2.json();
    assert.equal(body2.count, 3);
    assert.equal(body2.status, 'pending');
    assert.equal(turbo2.count, 2, 'retry uploads ONLY the two un-landed entries — entry 0 is not re-uploaded');
    assert.equal(body2.entries[0].txid, landedTxid, 'landed entry keeps its original txid');

    // Final stored response replaced the progress record.
    const stored2 = JSON.parse([...db._idemRows.values()][0].response_json);
    assert.equal(stored2.__batchProgress, undefined);
    assert.equal(stored2.entries.length, 3);

    // Attempt 3 (replay after success): served from cache, zero Turbo calls.
    const turbo3 = interceptTurbo(['ok']);
    const res3 = await handleBatchCreate(makeRequest(jwt, batchBody()), env, ctx, cors);
    assert.equal(res3.status, 200);
    const body3 = await res3.json();
    assert.deepEqual(body3.entries.map(e => e.txid), body2.entries.map(e => e.txid));
    assert.equal(turbo3.count, 0, 'cached replay performs no uploads');
  });

  it('full success on the first attempt stores a final response (no progress marker)', async () => {
    const db = makeD1();
    const env = { DB: db, JWT_SECRET, APP_SIGNING_KEY };
    const jwt = await userJwt();

    const turbo = interceptTurbo(['ok', 'ok', 'ok']);
    const res = await handleBatchCreate(makeRequest(jwt, batchBody()), env, ctx, cors);
    assert.equal(res.status, 200);
    assert.equal(turbo.count, 3);
    const stored = JSON.parse([...db._idemRows.values()][0].response_json);
    assert.equal(stored.__batchProgress, undefined);
    assert.equal(stored.entries.length, 3);
  });
});
