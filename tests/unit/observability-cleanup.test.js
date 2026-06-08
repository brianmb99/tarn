// Unit tests for api/src/observability/cleanup.js — the aux-table reap.
// Covers (a) the PURE plan builder (right tables, predicates, cutoffs) and
// (b) the executor against a mocked D1 (deleted counts, per-statement
// isolation on failure).
//
// Run: node --test tests/unit/observability-cleanup.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCleanupPlan,
  runCleanup,
  DEFAULT_AUDIT_RETENTION_DAYS,
} from '../../api/src/observability/cleanup.js';

const NOW = 1_700_000_000_000;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

describe('buildCleanupPlan — query selection', () => {
  it('targets exactly the four aux tables', () => {
    const plan = buildCleanupPlan({ now: NOW });
    const tables = plan.map((p) => p.table).sort();
    assert.deepEqual(tables, [
      'account_key_fetch_log',
      'auth_nonces',
      'step_up_tokens',
      'webauthn_challenges',
    ]);
  });

  it('step_up_tokens: reaps expired OR consumed rows, bound to now', () => {
    const plan = buildCleanupPlan({ now: NOW });
    const step = plan.find((p) => p.table === 'step_up_tokens');
    assert.match(step.sql, /DELETE FROM step_up_tokens/);
    assert.match(step.sql, /expires_at < \?1/);
    assert.match(step.sql, /consumed_at IS NOT NULL/);
    assert.deepEqual(step.params, [NOW]);
  });

  it('webauthn_challenges: reaps expired OR consumed rows, bound to now', () => {
    const plan = buildCleanupPlan({ now: NOW });
    const step = plan.find((p) => p.table === 'webauthn_challenges');
    assert.match(step.sql, /DELETE FROM webauthn_challenges/);
    assert.match(step.sql, /expires_at < \?1/);
    assert.match(step.sql, /consumed_at IS NOT NULL/);
    assert.deepEqual(step.params, [NOW]);
  });

  it('auth_nonces: reaps expired rows only (no consumed_at column exists)', () => {
    const plan = buildCleanupPlan({ now: NOW });
    const step = plan.find((p) => p.table === 'auth_nonces');
    assert.match(step.sql, /DELETE FROM auth_nonces WHERE expires_at < \?1/);
    // Must NOT reference consumed_at — that column does not exist in 0012.
    assert.doesNotMatch(step.sql, /consumed_at/);
    assert.deepEqual(step.params, [NOW]);
  });

  it('account_key_fetch_log: retention cutoff using fetched_at, default 90 days', () => {
    const plan = buildCleanupPlan({ now: NOW });
    const step = plan.find((p) => p.table === 'account_key_fetch_log');
    assert.match(step.sql, /DELETE FROM account_key_fetch_log WHERE fetched_at < \?1/);
    const expectedCutoff = NOW - DEFAULT_AUDIT_RETENTION_DAYS * MS_PER_DAY;
    assert.deepEqual(step.params, [expectedCutoff]);
    assert.equal(step.kind, 'retention');
  });

  it('honors a custom audit retention window', () => {
    const plan = buildCleanupPlan({ now: NOW, auditRetentionDays: 30 });
    const step = plan.find((p) => p.table === 'account_key_fetch_log');
    assert.deepEqual(step.params, [NOW - 30 * MS_PER_DAY]);
  });
});

// ============ executor against mocked D1 ============
//
// The mock models four tables of rows. Each DELETE statement filters rows by
// the cleanup predicate and returns { meta: { changes } } like Workers D1.

function mockDB(seed) {
  // seed: { table: [rows...] }
  const tables = JSON.parse(JSON.stringify(seed));
  return {
    _tables: tables,
    prepare(sql) {
      return {
        _sql: sql,
        _params: [],
        bind(...params) { this._params = params; return this; },
        async run() {
          const sql = this._sql;
          const p = this._params;
          let removed = 0;

          function sweep(name, predicate) {
            const before = tables[name].length;
            tables[name] = tables[name].filter((row) => !predicate(row));
            removed = before - tables[name].length;
          }

          if (/DELETE FROM step_up_tokens/.test(sql)) {
            const now = p[0];
            sweep('step_up_tokens', (r) => r.expires_at < now || r.consumed_at != null);
          } else if (/DELETE FROM webauthn_challenges/.test(sql)) {
            const now = p[0];
            sweep('webauthn_challenges', (r) => r.expires_at < now || r.consumed_at != null);
          } else if (/DELETE FROM auth_nonces/.test(sql)) {
            const now = p[0];
            sweep('auth_nonces', (r) => r.expires_at < now);
          } else if (/DELETE FROM account_key_fetch_log/.test(sql)) {
            const cutoff = p[0];
            sweep('account_key_fetch_log', (r) => r.fetched_at < cutoff);
          } else {
            throw new Error('unexpected SQL: ' + sql);
          }
          return { meta: { changes: removed } };
        },
      };
    },
  };
}

describe('runCleanup — execution + deleted counts', () => {
  it('deletes exactly the dead rows and leaves live rows intact', async () => {
    const db = mockDB({
      step_up_tokens: [
        { token: 'a', expires_at: NOW - 1000, consumed_at: null }, // expired
        { token: 'b', expires_at: NOW + 60000, consumed_at: NOW - 5 }, // consumed (live ttl)
        { token: 'c', expires_at: NOW + 60000, consumed_at: null }, // LIVE — keep
      ],
      webauthn_challenges: [
        { challenge: 'x', expires_at: NOW - 1, consumed_at: null }, // expired
        { challenge: 'y', expires_at: NOW + 60000, consumed_at: null }, // LIVE — keep
      ],
      auth_nonces: [
        { nonce: 'n1', expires_at: NOW - 1 }, // expired
        { nonce: 'n2', expires_at: NOW + 1000 }, // LIVE — keep
      ],
      account_key_fetch_log: [
        { id: 1, fetched_at: NOW - 100 * MS_PER_DAY }, // older than 90d
        { id: 2, fetched_at: NOW - 10 * MS_PER_DAY }, // recent — keep
      ],
    });

    const plan = buildCleanupPlan({ now: NOW });
    const res = await runCleanup(db, plan);

    assert.equal(res.tables.step_up_tokens.deleted, 2);
    assert.equal(res.tables.webauthn_challenges.deleted, 1);
    assert.equal(res.tables.auth_nonces.deleted, 1);
    assert.equal(res.tables.account_key_fetch_log.deleted, 1);
    assert.equal(res.totalDeleted, 5);
    assert.deepEqual(res.errors, {});

    // Live rows survive.
    assert.equal(db._tables.step_up_tokens.length, 1);
    assert.equal(db._tables.step_up_tokens[0].token, 'c');
    assert.equal(db._tables.webauthn_challenges.length, 1);
    assert.equal(db._tables.auth_nonces.length, 1);
    assert.equal(db._tables.account_key_fetch_log.length, 1);
    assert.equal(db._tables.account_key_fetch_log[0].id, 2);
  });

  it('is conservative — a table with only live rows deletes nothing', async () => {
    const db = mockDB({
      step_up_tokens: [{ token: 'live', expires_at: NOW + 99999, consumed_at: null }],
      webauthn_challenges: [{ challenge: 'live', expires_at: NOW + 99999, consumed_at: null }],
      auth_nonces: [{ nonce: 'live', expires_at: NOW + 99999 }],
      account_key_fetch_log: [{ id: 1, fetched_at: NOW - 1 * MS_PER_DAY }],
    });
    const res = await runCleanup(db, buildCleanupPlan({ now: NOW }));
    assert.equal(res.totalDeleted, 0);
  });

  it('isolates per-statement failures — one bad table does not abort the rest', async () => {
    const db = mockDB({
      step_up_tokens: [{ token: 'a', expires_at: NOW - 1, consumed_at: null }],
      webauthn_challenges: [],
      auth_nonces: [{ nonce: 'n', expires_at: NOW - 1 }],
      account_key_fetch_log: [],
    });
    // Make the webauthn_challenges DELETE throw.
    const origPrepare = db.prepare.bind(db);
    db.prepare = (sql) => {
      if (/webauthn_challenges/.test(sql)) {
        return { bind() { return this; }, async run() { throw new Error('simulated D1 failure'); } };
      }
      return origPrepare(sql);
    };

    const res = await runCleanup(db, buildCleanupPlan({ now: NOW }));
    // The failing table is recorded as an error...
    assert.match(res.errors.webauthn_challenges, /simulated D1 failure/);
    assert.equal(res.tables.webauthn_challenges.deleted, 0);
    // ...but the other tables still got swept.
    assert.equal(res.tables.step_up_tokens.deleted, 1);
    assert.equal(res.tables.auth_nonces.deleted, 1);
    assert.equal(res.totalDeleted, 2);
  });
});
