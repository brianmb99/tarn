// Unit tests for api/src/observability/scheduled.js — the orchestrator that
// composes readiness + drift + funding + cleanup into one report, persists it,
// and alerts. Everything (D1, Arweave GraphQL, Turbo) is mocked via injectable
// fetch + a mock DB; no live network or wrangler.
//
// Run: node --test tests/unit/observability-scheduled.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  runScheduledChecks,
  checkReadiness,
  maybeAlert,
} from '../../api/src/observability/scheduled.js';

const NOW = 1_700_000_000_000;
const MIN = 60 * 1000;

// A valid-shaped (but throwaway) hex private key so getAddress() succeeds.
// 32 bytes hex. Not a real funded wallet — these tests never sign or upload.
const FAKE_SIGNING_KEY = '1'.repeat(64);

// ---- mock fetch router ----
// Routes by URL substring so one mock serves GraphQL, Turbo price, Turbo
// balance, and the alert webhook.
function makeFetch(overrides = {}) {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url, opts });
    if (url.includes('/graphql')) {
      return overrides.graphql
        ? overrides.graphql(url, opts)
        : { ok: true, status: 200, json: async () => ({ data: { transactions: { pageInfo: { hasNextPage: false }, edges: [] } } }) };
    }
    if (url.includes('/price/bytes/')) {
      return overrides.price
        ? overrides.price()
        : { ok: true, status: 200, json: async () => ({ winc: '1000' }) };
    }
    if (url.includes('/account/balance/')) {
      return overrides.balance
        ? overrides.balance()
        : { ok: true, status: 200, json: async () => ({ winc: '1000000000000' }) };
    }
    if (overrides.webhook && url === overrides.webhookUrl) {
      return overrides.webhook(url, opts);
    }
    // default: treat as webhook success
    return { ok: true, status: 200, json: async () => ({}) };
  };
  fn.calls = calls;
  return fn;
}

// ---- mock D1 ----
// Returns 0 for every COUNT and null for every MAX by default so drift sees
// D1=0 / Arweave=0 (healthy). Records inserts into health_reports.
function makeDB(overrides = {}) {
  const inserted = [];
  return {
    _inserted: inserted,
    prepare(sql) {
      return {
        _sql: sql,
        _params: [],
        bind(...p) { this._params = p; return this; },
        async first() {
          if (overrides.first) {
            const r = overrides.first(this._sql, this._params);
            if (r !== undefined) return r;
          }
          if (/COUNT\(\*\) AS c/.test(this._sql)) return { c: 0 };
          if (/MAX\(/.test(this._sql)) return { m: null };
          return null;
        },
        // Mirror-failures retry select issues .all(); default empty so the
        // retry leg is a no-op unless a test overrides it.
        async all() {
          if (overrides.all) {
            const r = overrides.all(this._sql, this._params);
            if (r !== undefined) return r;
          }
          return { results: [] };
        },
        async run() {
          if (/INSERT INTO health_reports/.test(this._sql)) {
            inserted.push({ created_at: this._params[0], healthy: this._params[1], report_json: this._params[2] });
          }
          // cleanup deletes / prune / mirror updates
          return { meta: { changes: 0 } };
        },
      };
    },
  };
}

describe('checkReadiness', () => {
  it('ok when signing key parses and Turbo price is reachable', async () => {
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY };
    const r = await checkReadiness(env, { fetchImpl: makeFetch() });
    assert.equal(r.signing_key.ok, true);
    assert.ok(r.signing_key.address.startsWith('0x'));
    assert.equal(r.turbo.ok, true);
    assert.equal(r.ok, true);
  });

  it('not ok when APP_SIGNING_KEY is missing', async () => {
    const r = await checkReadiness({}, { fetchImpl: makeFetch() });
    assert.equal(r.signing_key.ok, false);
    assert.equal(r.signing_key.error, 'missing');
    assert.equal(r.ok, false);
  });

  it('not ok when Turbo ping fails', async () => {
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY };
    const r = await checkReadiness(env, {
      fetchImpl: makeFetch({ price: () => { throw new Error('down'); } }),
    });
    assert.equal(r.signing_key.ok, true);
    assert.equal(r.turbo.ok, false);
    assert.equal(r.ok, false);
  });
});

describe('runScheduledChecks — healthy path', () => {
  it('produces a healthy report when everything is nominal and persists it', async () => {
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB() };
    const report = await runScheduledChecks(env, { fetchImpl: makeFetch(), now: NOW });

    assert.equal(report.healthy, true, JSON.stringify(report.flags));
    assert.deepEqual(report.flags, []);
    assert.equal(report.checks.readiness.ok, true);
    assert.equal(report.checks.drift.healthy, true);
    assert.equal(report.checks.funding.low_funding, false);
    // Persisted exactly one row, marked healthy=1.
    assert.equal(env.DB._inserted.length, 1);
    assert.equal(env.DB._inserted[0].healthy, 1);
  });
});

describe('runScheduledChecks — drift detection', () => {
  it('flags DRIFT when Arweave has settled rows D1 is missing', async () => {
    // GraphQL returns 2 edges both older than the 30-min lag window for the
    // FIRST namespace queried (cred). D1 reports 0 cred rows => drift.
    let firstGraphqlServed = false;
    const fetchImpl = makeFetch({
      graphql: async () => {
        if (!firstGraphqlServed) {
          firstGraphqlServed = true;
          const oldTs = Math.floor((NOW - 90 * MIN) / 1000);
          return {
            ok: true, status: 200,
            json: async () => ({ data: { transactions: { pageInfo: { hasNextPage: false }, edges: [
              { cursor: 'c1', node: { id: 'tx1', block: { timestamp: oldTs, height: 1 } } },
              { cursor: 'c2', node: { id: 'tx2', block: { timestamp: oldTs, height: 2 } } },
            ] } } }),
          };
        }
        return { ok: true, status: 200, json: async () => ({ data: { transactions: { pageInfo: { hasNextPage: false }, edges: [] } } }) };
      },
    });
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB() };
    const report = await runScheduledChecks(env, { fetchImpl, now: NOW });

    assert.ok(report.flags.includes('DRIFT'), 'expected DRIFT flag: ' + JSON.stringify(report.flags));
    assert.equal(report.healthy, false);
    assert.ok(report.checks.drift.drifted.includes('cred'));
    assert.equal(env.DB._inserted[0].healthy, 0);
  });

  it('does NOT flag drift for purely recent (in-flight) Arweave activity', async () => {
    const fetchImpl = makeFetch({
      graphql: async () => {
        const recentTs = Math.floor((NOW - 5 * MIN) / 1000); // within lag window
        return {
          ok: true, status: 200,
          json: async () => ({ data: { transactions: { pageInfo: { hasNextPage: false }, edges: [
            { cursor: 'c1', node: { id: 'tx1', block: { timestamp: recentTs, height: 1 } } },
          ] } } }),
        };
      },
    });
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB() };
    const report = await runScheduledChecks(env, { fetchImpl, now: NOW });
    assert.ok(!report.flags.includes('DRIFT'), 'recent writes must not flag drift');
  });
});

describe('runScheduledChecks — funding', () => {
  it('flags LOW_FUNDING when balance is tiny against real burn', async () => {
    const fetchImpl = makeFetch({
      price: () => ({ ok: true, status: 200, json: async () => ({ winc: '1000000' }) }),
      balance: () => ({ ok: true, status: 200, json: async () => ({ winc: '1' }) }), // ~empty
    });
    // D1 reports recent writes so burn > 0.
    const env = {
      APP_SIGNING_KEY: FAKE_SIGNING_KEY,
      DB: makeDB({
        first: (sql) => {
          if (/COUNT\(\*\) AS c FROM entries/.test(sql)) return { c: 1000 };
          return undefined;
        },
      }),
    };
    const report = await runScheduledChecks(env, { fetchImpl, now: NOW });
    assert.ok(report.flags.includes('LOW_FUNDING'), 'expected LOW_FUNDING: ' + JSON.stringify(report.flags));
    assert.equal(report.checks.funding.low_funding, true);
  });
});

describe('runScheduledChecks — mirror failures (issue #47)', () => {
  it('flags STUCK_MIRRORS and surfaces the open count when failures remain', async () => {
    // Open mirror-failure count = 3. No retryable rows (.all returns empty), so
    // retry resolves nothing and STUCK_MIRRORS fires.
    const env = {
      APP_SIGNING_KEY: FAKE_SIGNING_KEY,
      DB: makeDB({
        first: (sql) => {
          if (/COUNT\(\*\) AS c FROM arweave_mirror_failures WHERE resolved_at IS NULL/.test(sql)) return { c: 3 };
          return undefined;
        },
      }),
    };
    const report = await runScheduledChecks(env, { fetchImpl: makeFetch(), now: NOW });
    assert.ok(report.flags.includes('STUCK_MIRRORS'), 'expected STUCK_MIRRORS: ' + JSON.stringify(report.flags));
    assert.equal(report.healthy, false);
    assert.equal(report.checks.mirror_failures.open, 3);
    assert.equal(env.DB._inserted[0].healthy, 0);
  });

  it('does NOT flag STUCK_MIRRORS when the open count is zero', async () => {
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB() };
    const report = await runScheduledChecks(env, { fetchImpl: makeFetch(), now: NOW });
    assert.ok(!report.flags.includes('STUCK_MIRRORS'));
    assert.equal(report.checks.mirror_failures.open, 0);
  });

  it('self-heals: a retryable row that re-uploads OK does not leave STUCK_MIRRORS', async () => {
    // One retryable row is returned by the retry select; the injected uploader
    // succeeds, the row is marked resolved, and the post-retry open count is 0.
    let resolvedId = null;
    let openCount = 1; // before retry
    const env = {
      APP_SIGNING_KEY: FAKE_SIGNING_KEY,
      DB: makeDB({
        all: (sql) => {
          if (/FROM arweave_mirror_failures\s+WHERE resolved_at IS NULL AND signed_data_item IS NOT NULL/.test(sql)) {
            return { results: [{ id: 42, intended_txid: 't', namespace: 'cred', signed_data_item: new Uint8Array([1]), attempt_count: 1 }] };
          }
          return undefined;
        },
        first: (sql, params) => {
          if (/COUNT\(\*\) AS c FROM arweave_mirror_failures WHERE resolved_at IS NULL/.test(sql)) {
            return { c: openCount };
          }
          return undefined;
        },
      }),
    };
    // Track the resolve UPDATE so we can flip the open count to 0 after retry.
    const origPrepare = env.DB.prepare.bind(env.DB);
    env.DB.prepare = (sql) => {
      const stmt = origPrepare(sql);
      const origRun = stmt.run.bind(stmt);
      stmt.run = async () => {
        if (/SET resolved_at = \?1, last_attempt_at = \?1 WHERE id = \?2/.test(sql)) {
          resolvedId = stmt._params[1];
          openCount = 0;
        }
        return origRun();
      };
      return stmt;
    };

    const report = await runScheduledChecks(env, {
      fetchImpl: makeFetch(),
      now: NOW,
      mirrorUploadImpl: async () => ({ ok: true }),
    });
    assert.equal(resolvedId, 42, 'the retryable row should have been resolved');
    assert.equal(report.checks.mirror_failures.retry.resolved, 1);
    assert.equal(report.checks.mirror_failures.open, 0);
    assert.ok(!report.flags.includes('STUCK_MIRRORS'), 'self-healed mirror must not flag STUCK_MIRRORS');
  });
});

describe('maybeAlert', () => {
  it('no-ops (console.warn) when ALERT_WEBHOOK_URL is unset', async () => {
    const r = await maybeAlert({}, { flags: ['DRIFT'] }, { fetchImpl: makeFetch() });
    assert.equal(r.sent, false);
    assert.equal(r.reason, 'no_webhook');
  });

  it('POSTs the report when webhook is set', async () => {
    let posted = null;
    const fetchImpl = makeFetch({
      webhookUrl: 'https://hooks.example/abc',
      webhook: async (url, opts) => { posted = JSON.parse(opts.body); return { ok: true, status: 200 }; },
    });
    const r = await maybeAlert({ ALERT_WEBHOOK_URL: 'https://hooks.example/abc' }, { flags: ['LOW_FUNDING'], healthy: false }, { fetchImpl });
    assert.equal(r.sent, true);
    assert.ok(posted.text.includes('LOW_FUNDING'));
  });

  it('never throws when the webhook fetch fails', async () => {
    const fetchImpl = makeFetch({
      webhookUrl: 'https://hooks.example/abc',
      webhook: async () => { throw new Error('webhook down'); },
    });
    const r = await maybeAlert({ ALERT_WEBHOOK_URL: 'https://hooks.example/abc' }, { flags: ['DRIFT'] }, { fetchImpl });
    assert.equal(r.sent, false);
    assert.match(r.error, /webhook down/);
  });
});

describe('runScheduledChecks — resilience', () => {
  it('does not throw and still persists when readiness fails (no signing key)', async () => {
    const env = { DB: makeDB() }; // no APP_SIGNING_KEY
    const report = await runScheduledChecks(env, { fetchImpl: makeFetch(), now: NOW });
    assert.ok(report.flags.includes('NOT_READY'));
    assert.equal(report.healthy, false);
    assert.equal(env.DB._inserted.length, 1);
  });

  it('skipPersist/skipCleanup options short-circuit those side effects', async () => {
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB() };
    const report = await runScheduledChecks(env, { fetchImpl: makeFetch(), now: NOW, skipPersist: true, skipCleanup: true });
    assert.equal(env.DB._inserted.length, 0, 'persist skipped');
    assert.equal(report.checks.cleanup, undefined, 'cleanup skipped');
  });
});
