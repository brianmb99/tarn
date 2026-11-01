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
import {
  DEFAULT_LAG_WINDOW_MS,
  DEFAULT_DRIFT_WINDOW_MS,
} from '../../api/src/observability/drift.js';
import { getAddress } from '../../api/src/ans104.js';

const NOW = 1_700_000_000_000;
const MIN = 60 * 1000;
const DAY = 24 * 60 * MIN;

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
  const queries = [];
  return {
    _inserted: inserted,
    _queries: queries,
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
        // retry leg is a no-op unless a test overrides it. Drift key lookups
        // also use .all(); `_queries` records every one of them.
        async all() {
          queries.push({ sql: this._sql, params: [...this._params] });
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

// Operability config a fully-set-up deployment carries (tarn#68): missing any
// of these is itself an unhealthy condition, so "nominal" envs include them.
const OPERABILITY_ENV = {
  ALERT_WEBHOOK_URL: 'https://hooks.example/tarn',
  HEARTBEAT_URL: 'https://hc.example/ping/tarn',
  TURBO_MIN_BALANCE_WINC: '1000000',
};

describe('runScheduledChecks — healthy path', () => {
  it('produces a healthy report when everything is nominal and persists it', async () => {
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB(), ...OPERABILITY_ENV };
    const report = await runScheduledChecks(env, { fetchImpl: makeFetch(), now: NOW });

    assert.equal(report.healthy, true, JSON.stringify(report.flags));
    assert.deepEqual(report.flags, []);
    assert.equal(report.checks.readiness.ok, true);
    assert.equal(report.checks.drift.healthy, true);
    assert.equal(report.checks.drift.lagWindowMs, DEFAULT_LAG_WINDOW_MS);
    assert.equal(report.checks.drift.windowMs, DEFAULT_DRIFT_WINDOW_MS);
    assert.equal(report.checks.funding.low_funding, false);
    // Persisted exactly one row, marked healthy=1.
    assert.equal(env.DB._inserted.length, 1);
    assert.equal(env.DB._inserted[0].healthy, 1);
  });
});

describe('runScheduledChecks — operability config + heartbeat (tarn#68)', () => {
  it('flags ALERTING_UNCONFIGURED / HEARTBEAT_UNCONFIGURED / FUNDING_FLOOR_UNSET when the vars are missing', async () => {
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB() };
    const report = await runScheduledChecks(env, { fetchImpl: makeFetch(), now: NOW });

    assert.ok(report.flags.includes('ALERTING_UNCONFIGURED'), JSON.stringify(report.flags));
    assert.ok(report.flags.includes('HEARTBEAT_UNCONFIGURED'), JSON.stringify(report.flags));
    assert.ok(report.flags.includes('FUNDING_FLOOR_UNSET'), JSON.stringify(report.flags));
    assert.equal(report.healthy, false);
    assert.equal(report.checks.config.alert_webhook_configured, false);
    assert.equal(report.checks.config.heartbeat_configured, false);
    assert.equal(report.checks.config.funding_floor_configured, false);
  });

  it('pings the heartbeat URL on a healthy tick (dead-man switch fires on silence, not on failure)', async () => {
    const fetchImpl = makeFetch();
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB(), ...OPERABILITY_ENV };
    const report = await runScheduledChecks(env, { fetchImpl, now: NOW });

    assert.equal(report.healthy, true);
    const heartbeatCalls = fetchImpl.calls.filter(c => c.url === OPERABILITY_ENV.HEARTBEAT_URL);
    assert.equal(heartbeatCalls.length, 1, 'exactly one heartbeat ping per tick');
  });

  it('pings the heartbeat on UNHEALTHY ticks too — the cron being alive is what the heartbeat reports', async () => {
    // Break readiness (Turbo price down) so the report is unhealthy.
    const fetchImpl = makeFetch({ price: () => ({ ok: false, status: 503, json: async () => ({}) }) });
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB(), ...OPERABILITY_ENV };
    const report = await runScheduledChecks(env, { fetchImpl, now: NOW });

    assert.equal(report.healthy, false);
    const heartbeatCalls = fetchImpl.calls.filter(c => c.url === OPERABILITY_ENV.HEARTBEAT_URL);
    assert.equal(heartbeatCalls.length, 1, 'heartbeat still pings when unhealthy');
  });

  it('a heartbeat ping failure never breaks the cron', async () => {
    const fetchImpl = makeFetch();
    const inner = fetchImpl;
    const failing = async (url, opts) => {
      if (url === OPERABILITY_ENV.HEARTBEAT_URL) throw new Error('heartbeat host down');
      return inner(url, opts);
    };
    failing.calls = inner.calls;
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB(), ...OPERABILITY_ENV };
    const report = await runScheduledChecks(env, { fetchImpl: failing, now: NOW });
    assert.equal(report.healthy, true, 'report unaffected by heartbeat failure');
    assert.equal(env.DB._inserted.length, 1, 'report still persisted');
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

// ---- windowed key-drift helpers ----

function emptyPage() {
  return {
    ok: true,
    status: 200,
    json: async () => ({ data: { transactions: { pageInfo: { hasNextPage: false }, edges: [] } } }),
  };
}

function gqlPage(edges, hasNextPage) {
  return {
    ok: true,
    status: 200,
    json: async () => ({ data: { transactions: { pageInfo: { hasNextPage }, edges } } }),
  };
}

function gqlType(opts) {
  const body = JSON.parse(opts.body);
  return body.variables.tags.find((t) => t.name === 'Type')?.values?.[0];
}

function gqlEdge(id, timestampSec, { owner, tags } = {}) {
  const node = {
    id,
    block: timestampSec == null ? null : { timestamp: timestampSec, height: 1 },
    tags: tags || [],
  };
  if (owner) node.owner = { address: owner };
  return { cursor: `c-${id}`, node };
}

const IN_WINDOW_TS = Math.floor((NOW - 2 * DAY) / 1000);
const OLD_TS = Math.floor((NOW - 30 * DAY) / 1000);

function inQueries(db) {
  return db._queries.filter((q) => / IN \(/.test(q.sql));
}

describe('runScheduledChecks — windowed key drift', () => {
  it('does not flag DRIFT when D1 already knows the settled txid', async () => {
    const fetchImpl = makeFetch({
      graphql: async (url, opts) => {
        if (gqlType(opts) !== 'cred') return emptyPage();
        return gqlPage([gqlEdge('txid-known', IN_WINDOW_TS)], false);
      },
    });
    const env = {
      APP_SIGNING_KEY: FAKE_SIGNING_KEY,
      DB: makeDB({
        all: (sql, params) => {
          if (/FROM entries WHERE txid IN/.test(sql)) return { results: params.map((k) => ({ k })) };
          return undefined;
        },
      }),
    };
    const report = await runScheduledChecks(env, { fetchImpl, now: NOW });
    const cred = report.checks.drift.namespaces.find((n) => n.ns === 'cred');
    assert.equal(cred.drift, false);
    assert.equal(cred.checked, 1);
    assert.equal(cred.missing, 0);
    assert.ok(!report.flags.includes('DRIFT'));
    assert.equal(inQueries(env.DB).length, 1);
    assert.deepEqual(inQueries(env.DB)[0].params, ['txid-known']);
  });

  it('flags DRIFT with missingSample when D1 has no row for a settled txid', async () => {
    const fetchImpl = makeFetch({
      graphql: async (url, opts) => {
        if (gqlType(opts) !== 'cred') return emptyPage();
        return gqlPage([gqlEdge('txid-missing', IN_WINDOW_TS)], false);
      },
    });
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB() };
    const report = await runScheduledChecks(env, { fetchImpl, now: NOW });
    const cred = report.checks.drift.namespaces.find((n) => n.ns === 'cred');
    assert.equal(cred.drift, true);
    assert.equal(cred.missing, 1);
    assert.deepEqual(cred.missingSample, ['txid-missing']);
    assert.ok(report.flags.includes('DRIFT'));
    assert.deepEqual(report.checks.drift.drifted, ['cred']);
  });

  it('does not flag DRIFT for hundreds of old cred edges D1 has never seen', async () => {
    // Production shape: Arweave still has the historical cred records and D1
    // does not. They are older than the window, so they are not drift and
    // they are not looked up.
    const edges = Array.from({ length: 600 }, (_, i) => gqlEdge(`hist-${i}`, OLD_TS));
    const fetchImpl = makeFetch({
      graphql: async (url, opts) => (gqlType(opts) === 'cred' ? gqlPage(edges, false) : emptyPage()),
    });
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB() };
    const report = await runScheduledChecks(env, { fetchImpl, now: NOW });
    const cred = report.checks.drift.namespaces.find((n) => n.ns === 'cred');
    assert.equal(cred.outsideWindow, 600);
    assert.equal(cred.checked, 0);
    assert.equal(cred.missing, 0);
    assert.equal(cred.drift, false);
    assert.equal(inQueries(env.DB).length, 0);
    assert.ok(!report.flags.includes('DRIFT'));
  });

  it('stops paging once a page ends older than the window, and does not treat that history as drift', async () => {
    const calls = {};
    const fetchImpl = makeFetch({
      graphql: async (url, opts) => {
        const type = gqlType(opts);
        calls[type] = (calls[type] || 0) + 1;
        if (type !== 'cred') return emptyPage();
        // Page 1 is still inside the window, so a second page is required.
        // Page 2's last edge is older than the window and hasNextPage is still
        // true — paging must stop anyway. A third call would be a bug.
        if (calls[type] === 1) {
          const edges = Array.from({ length: 100 }, (_, i) => gqlEdge(`recent-${i}`, IN_WINDOW_TS));
          return gqlPage(edges, true);
        }
        const edges = Array.from({ length: 100 }, (_, i) => gqlEdge(`ancient-${i}`, OLD_TS));
        return gqlPage(edges, true);
      },
    });
    // The in-window page is known to D1, so the only way this flags DRIFT is if
    // the older page is checked too. Those ancient ids must not be queried.
    const env = {
      APP_SIGNING_KEY: FAKE_SIGNING_KEY,
      DB: makeDB({
        all: (sql, params) => (/ IN \(/.test(sql) ? { results: params.map((k) => ({ k })) } : undefined),
      }),
    };
    const report = await runScheduledChecks(env, { fetchImpl, now: NOW });
    assert.equal(calls.cred, 2, 'second page is older than the window; no third GraphQL call');
    const cred = report.checks.drift.namespaces.find((n) => n.ns === 'cred');
    assert.equal(cred.truncated, false);
    assert.equal(cred.outsideWindow, 100);
    assert.equal(cred.checked, 100);
    assert.equal(cred.drift, false);
    assert.ok(!report.flags.includes('DRIFT'));
    // The ancient ids were not looked up.
    const lookedUp = inQueries(env.DB).flatMap((q) => q.params);
    assert.ok(lookedUp.includes('recent-0'));
    assert.ok(!lookedUp.includes('ancient-0'));
  });

  it('reports truncated:true when maxPages is exhausted while the last edge is still inside the window, without flagging DRIFT', async () => {
    const calls = {};
    const fetchImpl = makeFetch({
      graphql: async (url, opts) => {
        const body = JSON.parse(opts.body);
        assert.equal(body.variables.first, 100);
        assert.match(body.query, /sort:HEIGHT_DESC/);
        assert.match(body.query, /owner\{address\}/);
        assert.match(body.query, /tags\{name value\}/);
        const type = gqlType(opts);
        calls[type] = (calls[type] || 0) + 1;
        if (type !== 'passkey-reg') return emptyPage();
        const page = calls[type];
        const edges = Array.from({ length: 100 }, (_, i) => gqlEdge(`pk-${page}-${i}`, IN_WINDOW_TS));
        return gqlPage(edges, true);
      },
    });
    const env = {
      APP_SIGNING_KEY: FAKE_SIGNING_KEY,
      DB: makeDB({
        all: (sql, params) => (/ IN \(/.test(sql) ? { results: params.map((k) => ({ k })) } : undefined),
      }),
    };
    const report = await runScheduledChecks(env, { fetchImpl, now: NOW });
    assert.equal(calls['passkey-reg'], 5, 'stops at maxPages');
    const pk = report.checks.drift.namespaces.find((n) => n.ns === 'passkey-reg');
    assert.equal(pk.truncated, true);
    assert.equal(pk.checked, 500);
    assert.equal(pk.drift, false, 'truncation alone is not drift');
    assert.ok(!report.flags.includes('DRIFT'));
    // 500 keys → 5 chunks of 100.
    const pkQueries = inQueries(env.DB).filter((q) => /FROM entries WHERE txid IN/.test(q.sql));
    assert.equal(pkQueries.length, 5);
    for (const q of pkQueries) assert.equal(q.params.length, 100);
  });

  it('skips a foreign owner and flags the same record when the owner is Tarn in mixed case', async () => {
    const signing = getAddress(FAKE_SIGNING_KEY);
    const foreign = 'did:pkh:eip155:1:0x' + 'ab'.repeat(20);
    assert.equal(foreign.toLowerCase().endsWith(signing.toLowerCase()), false);
    const mixedHex = signing.slice(2).split('').map((c, i) => (i % 2 ? c.toUpperCase() : c)).join('');
    const tarnOwner = `did:pkh:eip155:1:0x${mixedHex}`;

    const foreignFetch = makeFetch({
      graphql: async (url, opts) => {
        if (gqlType(opts) !== 'cred') return emptyPage();
        return gqlPage([gqlEdge('foreign-tx', IN_WINDOW_TS, { owner: foreign })], false);
      },
    });
    const foreignReport = await runScheduledChecks(
      { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB() },
      { fetchImpl: foreignFetch, now: NOW },
    );
    const foreignCred = foreignReport.checks.drift.namespaces.find((n) => n.ns === 'cred');
    assert.equal(foreignCred.foreign, 1);
    assert.equal(foreignCred.drift, false);
    assert.equal(foreignCred.missing, 0);
    assert.ok(!foreignReport.flags.includes('DRIFT'));

    const tarnFetch = makeFetch({
      graphql: async (url, opts) => {
        if (gqlType(opts) !== 'cred') return emptyPage();
        return gqlPage([gqlEdge('tarn-tx', IN_WINDOW_TS, { owner: tarnOwner })], false);
      },
    });
    const tarnReport = await runScheduledChecks(
      { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB() },
      { fetchImpl: tarnFetch, now: NOW },
    );
    const tarnCred = tarnReport.checks.drift.namespaces.find((n) => n.ns === 'cred');
    assert.equal(tarnCred.foreign, 0);
    assert.equal(tarnCred.drift, true);
    assert.equal(tarnCred.missing, 1);
    assert.deepEqual(tarnCred.missingSample, ['tarn-tx']);
    assert.ok(tarnReport.flags.includes('DRIFT'));
  });

  it('looks up app-reg by the Lk tag in apps.app_id, and share/entry namespaces in their own tables', async () => {
    const byType = {
      cred: gqlEdge('cred-tx', IN_WINDOW_TS),
      'app-reg': gqlEdge('app-reg-txid-ignored', IN_WINDOW_TS, { tags: [{ name: 'Lk', value: 'app_1' }] }),
      'passkey-reg': gqlEdge('pk-tx', IN_WINDOW_TS),
      'app-config': gqlEdge('cfg-tx', IN_WINDOW_TS),
      'connection-request-v1': gqlEdge('inbox-tx', IN_WINDOW_TS),
      'connection-accept-v1': gqlEdge('accept-tx', IN_WINDOW_TS),
      'share-log-v1': gqlEdge('log-tx', IN_WINDOW_TS),
    };
    const fetchImpl = makeFetch({
      graphql: async (url, opts) => gqlPage([byType[gqlType(opts)]], false),
    });
    const env = {
      APP_SIGNING_KEY: FAKE_SIGNING_KEY,
      DB: makeDB({
        all: (sql, params) => {
          // apps.app_id does not know app_1. Every txid lookup hits.
          if (/FROM apps WHERE app_id IN/.test(sql)) return { results: [] };
          if (/ IN \(/.test(sql)) return { results: params.map((k) => ({ k })) };
          return undefined;
        },
      }),
    };
    const report = await runScheduledChecks(env, { fetchImpl, now: NOW });
    const queries = inQueries(env.DB);
    const sqlOf = (table, column) => queries.find((q) => q.sql === `SELECT ${column} AS k FROM ${table} WHERE ${column} IN (?1)`);
    assert.deepEqual(sqlOf('entries', 'txid')?.params, ['cred-tx']);
    assert.deepEqual(queries.filter((q) => q.sql.startsWith('SELECT txid AS k FROM entries')).map((q) => q.params[0]), ['cred-tx', 'pk-tx', 'cfg-tx']);
    const appQuery = sqlOf('apps', 'app_id');
    assert.ok(appQuery, 'app-reg must query apps.app_id');
    assert.deepEqual(appQuery.params, ['app_1']);
    assert.ok(!appQuery.params.includes('app-reg-txid-ignored'));
    assert.deepEqual(queries.filter((q) => /FROM share_inbox /.test(q.sql)).map((q) => q.params[0]), ['inbox-tx', 'accept-tx']);
    assert.deepEqual(sqlOf('share_log', 'txid')?.params, ['log-tx']);

    const appReg = report.checks.drift.namespaces.find((n) => n.ns === 'app-reg');
    assert.equal(appReg.drift, true);
    assert.deepEqual(appReg.missingSample, ['app_1']);
    assert.deepEqual(report.checks.drift.drifted, ['app-reg']);
    for (const ns of ['cred', 'passkey-reg', 'app-config', 'share-inbox', 'share-inbox-accept', 'share-log']) {
      const row = report.checks.drift.namespaces.find((n) => n.ns === ns);
      assert.equal(row.drift, false, ns);
      assert.equal(row.missing, 0, ns);
    }
  });

  it('chunks IN lookups at 100 bound parameters (250 keys → 3 queries)', async () => {
    const edges = Array.from({ length: 250 }, (_, i) => gqlEdge(`k${i}`, IN_WINDOW_TS));
    const fetchImpl = makeFetch({
      graphql: async (url, opts) => (gqlType(opts) === 'cred' ? gqlPage(edges, false) : emptyPage()),
    });
    const env = { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB() };
    const report = await runScheduledChecks(env, { fetchImpl, now: NOW });
    const queries = inQueries(env.DB);
    assert.equal(queries.length, 3);
    assert.deepEqual(queries.map((q) => q.params.length), [100, 100, 50]);
    for (const q of queries) {
      assert.ok(q.params.length <= 100);
      assert.equal((q.sql.match(/\?/g) || []).length, q.params.length);
      assert.match(q.sql, /^SELECT txid AS k FROM entries WHERE txid IN \(/);
    }
    assert.equal(queries[0].params[0], 'k0');
    assert.equal(queries[2].params[49], 'k249');
    const cred = report.checks.drift.namespaces.find((n) => n.ns === 'cred');
    assert.equal(cred.checked, 250);
    assert.equal(cred.missing, 250);
  });

  it('records a D1 lookup error as incomplete and does not flag DRIFT', async () => {
    const fetchImpl = makeFetch({
      graphql: async (url, opts) => (gqlType(opts) === 'cred' ? gqlPage([gqlEdge('txid-1', IN_WINDOW_TS)], false) : emptyPage()),
    });
    const env = {
      APP_SIGNING_KEY: FAKE_SIGNING_KEY,
      DB: makeDB({
        all: (sql) => {
          if (/ IN \(/.test(sql)) throw new Error('d1 boom');
          return undefined;
        },
      }),
    };
    const report = await runScheduledChecks(env, { fetchImpl, now: NOW });
    const cred = report.checks.drift.namespaces.find((n) => n.ns === 'cred');
    assert.ok(cred, 'namespace result should still be recorded');
    assert.equal(cred.incomplete, true);
    assert.equal(cred.drift, false);
    assert.match(cred.reason, /comparison skipped \(gql=ok, d1=d1 boom\)/);
    assert.equal(report.checks.drift.healthy, true);
    assert.ok(!report.flags.includes('DRIFT'));
  });

  it('DRIFT_WINDOW_MS overrides how far back a settled edge is checked', async () => {
    const threeDays = Math.floor((NOW - 3 * DAY) / 1000);
    const fetchImpl = () => makeFetch({
      graphql: async (url, opts) => (gqlType(opts) === 'cred' ? gqlPage([gqlEdge('aged', threeDays)], false) : emptyPage()),
    });

    const widened = await runScheduledChecks(
      { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB(), DRIFT_WINDOW_MS: String(14 * DAY) },
      { fetchImpl: fetchImpl(), now: NOW },
    );
    assert.equal(widened.checks.drift.windowMs, 14 * DAY);
    assert.equal(widened.checks.drift.lagWindowMs, DEFAULT_LAG_WINDOW_MS);
    const wideCred = widened.checks.drift.namespaces.find((n) => n.ns === 'cred');
    assert.equal(wideCred.checked, 1);
    assert.equal(wideCred.drift, true);

    const narrowed = await runScheduledChecks(
      { APP_SIGNING_KEY: FAKE_SIGNING_KEY, DB: makeDB(), DRIFT_WINDOW_MS: String(1 * DAY) },
      { fetchImpl: fetchImpl(), now: NOW },
    );
    assert.equal(narrowed.checks.drift.windowMs, 1 * DAY);
    const narrowCred = narrowed.checks.drift.namespaces.find((n) => n.ns === 'cred');
    assert.equal(narrowCred.checked, 0);
    assert.equal(narrowCred.outsideWindow, 1);
    assert.equal(narrowCred.drift, false);
    assert.ok(!narrowed.flags.includes('DRIFT'));
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
