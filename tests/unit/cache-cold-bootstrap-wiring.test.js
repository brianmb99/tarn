// CI-runnable guard for the worker cold-bootstrap read path (tarn#61).
//
// The "rebuildable-from-Arweave" property and the cold-bootstrap read path
// (routes/entries.js → cache.js refreshCache → arweave.js
// searchEntriesByLookupKey → upsertEntries → getResolvedEntries, plus the
// lazy gateway blob hydration handleEntryById → fetchBlobFromGateway →
// persistBlob) were previously only proven by the operator-only, destructive,
// mainnet tests/test-rebuild-from-arweave.mjs (excluded from test:unit). A
// regression in the REAL GraphQL request shape / response parse / D1 upsert /
// resolution / gateway-fetch wiring was therefore not caught automatically.
//
// This test drives those REAL functions (not re-mocked logic) by intercepting
// globalThis.fetch (Arweave GraphQL + gateway bodies) and backing env.DB with
// an in-memory D1 shim that honours the SQL the production code actually issues.
//
// SCOPE / TRUTH NOTES (verified against the source, 2026-06-07):
//   * refreshCache() calls searchEntriesByLookupKey(), which issues a SINGLE
//     GraphQL query (first:10, sort:HEIGHT_DESC, NO cursor pagination loop).
//     The #61 issue text mentions "pages GraphQL" for the cold-bootstrap read
//     path — that is NOT what the list/refreshCache path does today. The
//     multi-page GraphQL pagination loop lives in the rebuild TOOL
//     (tools/rebuild-from-arweave.mjs gqlPage), exercised by the companion
//     test rebuild-cli-mock-multipage.test.js. We assert the real single-query
//     behaviour here and document the discrepancy rather than fake a loop.
//   * refreshCache() does METADATA-ONLY bootstrap — it does NOT fetch blob
//     bodies from the gateway. Bodies are hydrated lazily by handleEntryById /
//     the ?eid= / ?since= fast paths via fetchBlobFromGateway → persistBlob.
//     We cover that real gateway-fetch wiring in its own block below.
//
// Run: node --import tsx --test tests/unit/cache-cold-bootstrap-wiring.test.js
//   or via the umbrella: npm run test:unit

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import { refreshCache, getResolvedEntries } from '../../api/src/cache.js';
import { searchEntriesByLookupKey } from '../../api/src/arweave.js';
import { handleEntries, handleEntryById } from '../../api/src/routes/entries.js';

const ARWEAVE_GRAPHQL = 'https://arweave.net/graphql';
const APP = 'bookish';
const TYPE = 'entry';
const DLK = 'a'.repeat(64); // valid 64-char hex data_lookup_key

const originalFetch = globalThis.fetch;
function restoreFetch() { globalThis.fetch = originalFetch; }

// ============ IN-MEMORY D1 SHIM ============
//
// Backs the exact SQL the production cache layer issues. Not a generic SQL
// engine — it pattern-matches the specific statements in cache.js so the test
// exercises the real call sequence (bootstrap probe → upsert batch → resolve).
function makeD1() {
  const entries = new Map();   // txid -> row
  const cacheMeta = new Map(); // key -> {value, updated_at}
  const log = { upsertBatches: 0, upsertedTxids: [], blobPersists: 0 };

  // Real D1: prepare() returns a statement; .bind() returns a NEW bound
  // statement (so upsertEntries can build N independent bound stmts from one
  // prepared stmt and hand them to batch()). The mock mirrors that — bind()
  // returns a fresh object snapshotting its own args, never mutating a shared
  // one. (Getting this wrong silently collapsed a batch to its last row.)
  function bindFactory(sql, boundArgs = null) {
    const args = boundArgs ?? [];
    const api = {
      bind(...a) { return bindFactory(sql, a); },
      async first() {
        if (/FROM cache_meta WHERE key = \?1/.test(sql)) {
          return cacheMeta.has(args[0]) ? { 1: 1 } : null;
        }
        if (/SELECT \* FROM entries WHERE txid = \?1/.test(sql)) {
          return entries.get(args[0]) ?? null;
        }
        return null;
      },
      async run() {
        if (/INSERT INTO cache_meta/.test(sql)) {
          // ON CONFLICT(key) DO NOTHING
          if (!cacheMeta.has(args[0])) cacheMeta.set(args[0], { value: args[1], updated_at: args[2] });
          return { success: true };
        }
        if (/UPDATE entries SET blob_data = \?1 WHERE txid = \?2/.test(sql)) {
          const row = entries.get(args[1]);
          if (row) row.blob_data = args[0];
          log.blobPersists += 1;
          return { success: true };
        }
        return { success: true };
      },
      async all() {
        if (/FROM entries WHERE app = \?1 AND type = \?2 AND lookup_key = \?3/.test(sql)) {
          const [app, type, lk] = args;
          const results = [...entries.values()].filter(
            (r) => r.app === app && r.type === type && r.lookup_key === lk,
          );
          return { results };
        }
        return { results: [] };
      },
      // upsertEntries builds a bound statement and passes it to db.batch();
      // expose the captured insert so batch() can apply it.
      __apply() {
        if (/INSERT INTO entries/.test(sql)) {
          const [txid, app, type, wallet_addr, lookup_key, eid, prev_txid,
            is_tombstone, tombstone_ref, block_timestamp, tags_json, cached_at, blob_data] = args;
          const existing = entries.get(txid);
          if (existing) {
            // ON CONFLICT(txid) DO UPDATE SET block_timestamp = COALESCE(...), cached_at = ...
            existing.block_timestamp = block_timestamp ?? existing.block_timestamp;
            existing.cached_at = cached_at;
          } else {
            entries.set(txid, {
              txid, app, type, wallet_addr, lookup_key, eid, prev_txid,
              is_tombstone, tombstone_ref, block_timestamp, tags_json, cached_at,
              blob_data: blob_data ?? null,
            });
            log.upsertedTxids.push(txid);
          }
        }
      },
    };
    return api;
  }

  return {
    _entries: entries,
    _cacheMeta: cacheMeta,
    _log: log,
    prepare(sql) { return bindFactory(sql); },
    async batch(stmts) {
      log.upsertBatches += 1;
      for (const s of stmts) s.__apply();
      return stmts.map(() => ({ results: [] }));
    },
  };
}

// A KV that always allows the read (rate-limit fail-open shape).
function makeAllowingKV() {
  return { async get() { return null; }, async put() {} };
}

// Build an Arweave GraphQL edge in the wire shape searchEntriesByLookupKey
// parses: { node: { id, tags:[{name,value}], block:{timestamp,height} } }.
function edge(id, { eid = null, prev = null, op = null, ref = null, ts = 1700000000 } = {}) {
  const tags = [
    { name: 'App', value: APP },
    { name: 'Type', value: TYPE },
    { name: 'Lk', value: DLK },
  ];
  if (eid) tags.push({ name: 'Eid', value: eid });
  if (prev) tags.push({ name: 'Prev', value: prev });
  if (op) tags.push({ name: 'Op', value: op });
  if (ref) tags.push({ name: 'Ref', value: ref });
  return { cursor: id, node: { id, tags, block: ts ? { timestamp: ts, height: 1 } : null } };
}

// Intercept fetch: route GraphQL to a fixture, gateway GETs to a body map.
// Records every GraphQL request body so we can assert the REAL query shape.
function interceptFetch({ graphqlEdges = [], graphqlError = null, bodies = {} } = {}) {
  const calls = { graphql: [], gateway: [] };
  globalThis.fetch = async (url, opts = {}) => {
    const u = String(url);
    if (u === ARWEAVE_GRAPHQL) {
      calls.graphql.push(JSON.parse(opts.body));
      if (graphqlError) {
        return { ok: false, status: 500, async text() { return 'boom'; }, async json() { return {}; } };
      }
      return {
        ok: true,
        status: 200,
        async json() {
          return { data: { transactions: { edges: graphqlEdges } } };
        },
      };
    }
    // Gateway body fetch — path is <gateway>/<txid>
    const txid = u.split('/').pop();
    calls.gateway.push(txid);
    const body = bodies[txid];
    if (body == null) {
      return { ok: false, status: 404, async arrayBuffer() { return new ArrayBuffer(0); } };
    }
    const bytes = typeof body === 'string' ? new TextEncoder().encode(body) : body;
    return { ok: true, status: 200, async arrayBuffer() { return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength); } };
  };
  return calls;
}

const ctx = { waitUntil() {} };

describe('tarn#61 — cold-bootstrap GraphQL→D1 wiring (refreshCache / arweave.js)', () => {
  afterEach(restoreFetch);

  it('searchEntriesByLookupKey issues the real single-query GraphQL request (App+Type+Lk filter, first:10, no cursor)', async () => {
    const calls = interceptFetch({ graphqlEdges: [edge('tx-1', { eid: 'e1' })] });
    const { edges, error } = await searchEntriesByLookupKey(DLK, { app: APP, type: TYPE });
    assert.equal(error, null);
    assert.equal(edges.length, 1);
    assert.equal(edges[0].node.id, 'tx-1');

    // Verify the ACTUAL wire request, not a re-mock: exactly one GraphQL POST,
    // carrying the App/Type/Lk tag filter and first:10 (this path does NOT
    // paginate — there is no `after` variable in the query).
    assert.equal(calls.graphql.length, 1);
    const req = calls.graphql[0];
    assert.equal(req.variables.first, 10);
    assert.equal(req.variables.after, undefined, 'cold-bootstrap query is single-shot; no cursor variable');
    const filters = Object.fromEntries(req.variables.tags.map((t) => [t.name, t.values[0]]));
    assert.deepEqual(filters, { App: APP, Type: TYPE, Lk: DLK });
    assert.match(req.query, /sort:HEIGHT_DESC/);
  });

  it('cold (dlk,app,type) read triggers refreshCache: GraphQL → upsert D1 → set bootstrap marker', async () => {
    const db = makeD1();
    const calls = interceptFetch({ graphqlEdges: [edge('tx-a', { eid: 'e1' }), edge('tx-b', { eid: 'e2' })] });
    const env = { DB: db };

    const r1 = await refreshCache(env, ctx, APP, TYPE, DLK);
    assert.equal(r1.bootstrapped, true);
    assert.equal(calls.graphql.length, 1, 'one GraphQL query on cold read');
    assert.equal(db._log.upsertBatches, 1, 'one D1 upsert batch');
    assert.equal(db._entries.size, 2, 'both edges upserted into D1');
    assert.ok(db._cacheMeta.size === 1, 'bootstrap marker set after success');

    // Second read for the same tuple must NOT re-query Arweave — the marker
    // makes D1 authoritative. This proves the one-shot semantics.
    const r2 = await refreshCache(env, ctx, APP, TYPE, DLK);
    assert.equal(r2.bootstrapped, true);
    assert.equal(calls.graphql.length, 1, 'warm read does not re-query GraphQL');
    assert.equal(db._log.upsertBatches, 1, 'warm read does not re-upsert');
  });

  it('a transient GraphQL error does NOT latch the bootstrap marker (re-queries next time)', async () => {
    const db = makeD1();
    const calls = interceptFetch({ graphqlError: true });
    const env = { DB: db };

    const r = await refreshCache(env, ctx, APP, TYPE, DLK);
    assert.equal(r.bootstrapped, false, 'error path reports not-bootstrapped');
    assert.equal(db._cacheMeta.size, 0, 'no marker set on GraphQL failure');

    // Recover: next call succeeds and now sets the marker + upserts.
    restoreFetch();
    interceptFetch({ graphqlEdges: [edge('tx-x', { eid: 'e1' })] });
    const r2 = await refreshCache(env, ctx, APP, TYPE, DLK);
    assert.equal(r2.bootstrapped, true);
    assert.equal(db._entries.size, 1);
    assert.equal(db._cacheMeta.size, 1);
  });
});

describe('tarn#61 — full handleEntries cold-bootstrap reconstruction (latest-wins, tombstone, dedup)', () => {
  afterEach(restoreFetch);

  function urlList(extra = '') {
    return new URL(`https://api.tarn.dev/api/v1/entries?app=${APP}&type=${TYPE}&key=${DLK}${extra}`);
  }
  const cors = {};
  const request = { headers: { get() { return null; } } };

  it('reconstructs live set on cold read: tombstone excluded, superseded (Prev-chain) excluded', async () => {
    const db = makeD1();
    // e1: created (tx1) then updated (tx2 Prev=tx1)         → live = tx2
    // e2: created (tx3) then tombstoned (tx4 Op=tombstone Ref=tx3) → none live
    // e3: created (tx5)                                     → live = tx5
    const edges = [
      edge('tx1', { eid: 'e1' }),
      edge('tx2', { eid: 'e1', prev: 'tx1' }),
      edge('tx3', { eid: 'e2' }),
      edge('tx4', { eid: 'e2', op: 'tombstone', ref: 'tx3' }),
      edge('tx5', { eid: 'e3' }),
    ];
    const calls = interceptFetch({ graphqlEdges: edges });
    const env = { DB: db, RATE_KV: makeAllowingKV() };

    const res = await handleEntries(urlList(), env, ctx, cors, request);
    assert.equal(res.status, 200);
    const body = await res.json();

    // Cold read paged the (single) GraphQL query and upserted all 5 edges.
    assert.equal(calls.graphql.length, 1);
    assert.equal(db._entries.size, 5);

    const liveTxids = body.entries.map((e) => e.txid).sort();
    assert.deepEqual(liveTxids, ['tx2', 'tx5'], 'tx2 (latest of e1) + tx5 (e3); tombstoned e2 and superseded tx1 excluded');
    // List response is metadata-only (no inline blob bytes) — verify the
    // documented contract holds through the real route.
    assert.ok(body.entries.every((e) => !('data' in e)), 'list endpoint stays metadata-only');
  });

  it('latest-wins across multiple updates to the same Eid', async () => {
    const db = makeD1();
    const edges = [
      edge('txA', { eid: 'e1', ts: 1700000000 }),
      edge('txB', { eid: 'e1', prev: 'txA', ts: 1700000100 }),
      edge('txC', { eid: 'e1', prev: 'txB', ts: 1700000200 }),
    ];
    interceptFetch({ graphqlEdges: edges });
    const env = { DB: db, RATE_KV: makeAllowingKV() };

    const res = await handleEntries(urlList(), env, ctx, cors, request);
    const body = await res.json();
    assert.equal(body.entries.length, 1);
    assert.equal(body.entries[0].txid, 'txC', 'newest in the Prev-chain wins');
  });

  it('empty Arweave history → empty live set (no entries, marker still set)', async () => {
    const db = makeD1();
    interceptFetch({ graphqlEdges: [] });
    const env = { DB: db, RATE_KV: makeAllowingKV() };
    const res = await handleEntries(urlList(), env, ctx, cors, request);
    const body = await res.json();
    assert.equal(res.status, 200);
    assert.deepEqual(body.entries, []);
    assert.equal(db._cacheMeta.size, 1, 'empty-but-successful bootstrap still latches the marker');
  });
});

describe('tarn#61 — lazy gateway blob hydration (handleEntryById → fetchBlobFromGateway → persistBlob)', () => {
  afterEach(restoreFetch);

  const cors = {};
  const request = { headers: { get() { return null; } } };

  it('on D1 blob miss, fetches body from the gateway and write-through persists it', async () => {
    const db = makeD1();
    // Seed an entry row with NO blob_data (post-cold-bootstrap state: metadata
    // imported, body not yet hydrated).
    db._entries.set('txid-1', {
      txid: 'txid-1', app: APP, type: TYPE, wallet_addr: null, lookup_key: DLK,
      eid: 'e1', prev_txid: null, is_tombstone: 0, tombstone_ref: null,
      block_timestamp: 1700000000, tags_json: JSON.stringify([{ name: 'Eid', value: 'e1' }]),
      cached_at: Date.now(), blob_data: null,
    });
    const PLAINTEXT = 'encrypted-blob-bytes';
    const calls = interceptFetch({ bodies: { 'txid-1': PLAINTEXT } });
    const env = { DB: db, RATE_KV: makeAllowingKV() };

    const url = new URL(`https://api.tarn.dev/api/v1/entries/txid-1?key=${DLK}`);
    const res = await handleEntryById('txid-1', url, env, ctx, cors, request);
    assert.equal(res.status, 200);
    const body = await res.json();

    // Real gateway wiring: the route fetched the body and returned it base64.
    assert.ok(calls.gateway.includes('txid-1'), 'gateway was hit for the missing blob');
    const decoded = atob(body.data);
    assert.equal(decoded, PLAINTEXT, 'gateway body round-trips through base64');
    // Write-through: D1 row now carries the bytes, and persistBlob ran once.
    assert.equal(db._log.blobPersists, 1);
    assert.ok(db._entries.get('txid-1').blob_data != null, 'blob persisted to D1');
  });

  it('a tombstone row is never gateway-fetched (no body to hydrate)', async () => {
    const db = makeD1();
    db._entries.set('tomb-1', {
      txid: 'tomb-1', app: APP, type: TYPE, wallet_addr: null, lookup_key: DLK,
      eid: 'e2', prev_txid: null, is_tombstone: 1, tombstone_ref: 'orig',
      block_timestamp: 1700000000, tags_json: '[]', cached_at: Date.now(), blob_data: null,
    });
    const calls = interceptFetch({ bodies: {} });
    const env = { DB: db, RATE_KV: makeAllowingKV() };
    const url = new URL(`https://api.tarn.dev/api/v1/entries/tomb-1?key=${DLK}`);
    const res = await handleEntryById('tomb-1', url, env, ctx, cors, request);
    assert.equal(res.status, 200);
    assert.equal(calls.gateway.length, 0, 'tombstones are not hydrated from the gateway');
  });
});
