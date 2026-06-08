// Large-collection scale / pagination tests (tarn#62, ties to the 25,000-entry
// cap and the #51 partial-list work).
//
// Two layers, both deterministic and CI-runnable (no live services):
//
//   1. SERVER cache layer — getResolvedEntries() over thousands of mocked D1
//      rows. Asserts cursor-based pagination walks the WHOLE set exactly once,
//      every live row appears on exactly one page, nothing is dropped or
//      duplicated, and `total` is stable across pages. Pure + fast (no crypto).
//
//   2. CLIENT getEntries() — paginates the metadata list (limit=500, up to 50
//      pages = the 25,000 hard cap) then fetches every blob. Drives the REAL
//      page-accumulation loop and the #51 partial-list semantics:
//        (a) a 1,200-entry / 3-page collection round-trips with all 1,200
//            records decrypted and NONE silently dropped;
//        (b) the 50-page × 500 safety cap is exactly 25,000 — a 51st page is
//            never requested even if the server keeps saying hasMore;
//        (c) a transient blob-fetch failure surfaces as TarnPartialListError
//            (carrying the successes + the failed txids) rather than silently
//            shrinking the list (#51).
//
// Run: node --import tsx --test tests/unit/large-collection-scale.test.js
//   or via the umbrella: npm run test:unit

import '../indexeddb-shim.mjs';
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import { getResolvedEntries, resolveEntries } from '../../api/src/cache.js';
import { TarnClient, TarnPartialListError } from '../../client/src/tarn.js';

// ============ LAYER 1: server getResolvedEntries pagination ============

// Minimal D1 shim whose entries SELECT returns a fixed row array (the handler
// filters by app/type/lookup_key, which we pre-satisfy by tagging every row).
function makeRowsDb(rows) {
  return {
    prepare(sql) {
      let args = [];
      return {
        bind(...a) { args = a; return this; },
        async all() {
          if (/FROM entries WHERE app = \?1 AND type = \?2 AND lookup_key = \?3/.test(sql)) {
            const [app, type, lk] = args;
            return { results: rows.filter((r) => r.app === app && r.type === type && r.lookup_key === lk) };
          }
          return { results: [] };
        },
      };
    },
  };
}

function row(i) {
  return {
    txid: `tx${String(i).padStart(6, '0')}`,
    app: 'bookish', type: 'entry', wallet_addr: null, lookup_key: 'k',
    eid: `e${i}`, prev_txid: null, is_tombstone: 0, tombstone_ref: null,
    block_timestamp: 1700000000 + i, tags_json: '[]', cached_at: 1700000000000 + i,
  };
}

describe('tarn#62 scale — server getResolvedEntries pagination over thousands of rows', () => {
  it('walks 5,000 live rows across pages with no drops and no duplicates', async () => {
    const N = 5000;
    const rows = Array.from({ length: N }, (_, i) => row(i));
    const db = makeRowsDb(rows);

    const seen = new Set();
    let cursor = null;
    let pages = 0;
    let totalSeen = 0;
    const LIMIT = 500;
    // Loop until a short page (fewer than LIMIT) signals the end.
    for (;;) {
      const { entries, total } = await getResolvedEntries(db, 'bookish', 'entry', 'k', { limit: LIMIT, cursor });
      assert.equal(total, N, 'total must reflect the full live set on every page');
      for (const e of entries) {
        assert.ok(!seen.has(e.txid), `duplicate txid across pages: ${e.txid}`);
        seen.add(e.txid);
      }
      totalSeen += entries.length;
      pages += 1;
      if (entries.length < LIMIT) break;
      cursor = entries[entries.length - 1].txid;
      assert.ok(pages <= N / LIMIT + 2, 'pagination did not terminate');
    }

    assert.equal(totalSeen, N, 'every live row surfaced exactly once across pages');
    assert.equal(seen.size, N, 'no row dropped, no row duplicated');
    // N is an exact multiple of LIMIT, so the final full page (#10) cannot
    // signal completion on its own — the consumer fetches one more page (#11)
    // which comes back empty and terminates. This mirrors the real client's
    // hasMore loop (getEntries breaks only on a short/empty page).
    assert.equal(pages, N / LIMIT + 1, `expected ${N / LIMIT + 1} pages (10 full + 1 empty terminator)`);
  });

  it('resolution scales: 3,000 rows where half are superseded + 500 tombstoned yields the right live count', async () => {
    // 3,000 Eids. For the first 1,500 we write an update (Prev-chain) so the
    // original is superseded. For 500 of those Eids we ALSO tombstone the head.
    const rows = [];
    let i = 0;
    const liveExpected = new Set();
    for (let e = 0; e < 3000; e++) {
      const baseTx = `base${e}`;
      rows.push({ ...row(i++), txid: baseTx, eid: `E${e}` });
      if (e < 1500) {
        const headTx = `head${e}`;
        rows.push({ ...row(i++), txid: headTx, eid: `E${e}`, prev_txid: baseTx });
        if (e < 500) {
          // tombstone the head → Eid has no live row
          rows.push({ ...row(i++), txid: `tomb${e}`, eid: `E${e}`, is_tombstone: 1, tombstone_ref: headTx });
        } else {
          liveExpected.add(headTx);
        }
      } else {
        liveExpected.add(baseTx);
      }
    }
    // Expected live = (1500 updated, of which 500 tombstoned → 1000) + 1500 untouched = 2500.
    const live = resolveEntries(rows);
    assert.equal(live.length, 2500, `expected 2500 live, got ${live.length}`);
    const liveTxids = new Set(live.map((r) => r.txid));
    assert.equal(liveTxids.size, 2500, 'no duplicate live rows');
    for (const tx of liveExpected) {
      assert.ok(liveTxids.has(tx), `expected live txid missing: ${tx}`);
    }
  });
});

// ============ LAYER 2: client getEntries pagination + #51 partial-list ============

const APP = 'bookish';
const PASSWORD = 'scale-test-pass-2026';
const originalFetch = globalThis.fetch;
function restoreFetch() { globalThis.fetch = originalFetch; }

function fakeJwt(label = 'jwt') {
  const b64url = (s) => btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const header = b64url('{"alg":"none"}');
  const payload = b64url(JSON.stringify({ sub: label, exp: Math.floor(Date.now() / 1000) + 3600 }));
  return `${header}.${payload}.`;
}
function uniqueDlk() {
  return Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
}
function bytesToBase64(bytes) { return btoa(String.fromCharCode(...bytes)); }

// Register a client and capture ONE real ciphertext for a known payload, so we
// can replay it across many entries (the client's own DEK decrypts it).
async function setUpClient(capturedPayload) {
  const dlk = uniqueDlk();
  let q = [
    { status: 201, body: JSON.stringify({ data_lookup_key: dlk }) },
    { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
    { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
  ];
  globalThis.fetch = async () => {
    const next = q.shift();
    return { status: next.status, headers: { get: () => null }, text: async () => next.body, json: async () => JSON.parse(next.body) };
  };
  const client = new TarnClient('https://api.tarn.dev', APP);
  await client.register(`scale-${Date.now()}-${Math.random().toString(16).slice(2)}@example.com`, PASSWORD, { recoveryAcknowledged: true });

  // Capture one ciphertext via a real createEntry.
  let capturedBody = null;
  globalThis.fetch = async (url, opts) => {
    capturedBody = opts.body; // X-Arweave-Tags carry the eid; body is the ciphertext bytes
    return { status: 200, headers: { get: () => null }, text: async () => JSON.stringify({ id: 'tx-cap' }), json: async () => ({ id: 'tx-cap' }) };
  };
  await client.createEntry('books', capturedPayload, [{ name: 'Eid', value: 'eid-cap' }]);
  return { client, dlk, capturedBody };
}

// A fetch ROUTER for the list + per-blob endpoints. `pages` is an array of
// { entries, hasMore }; list calls consume them in order. Blob GETs return the
// captured body for ANY txid. Tracks how many list pages were requested.
function routeListAndBlobs({ pages, capturedBody, blobOverrides = {} }) {
  let pageIdx = 0;
  const stats = { listCalls: 0, blobCalls: 0, requestedTxids: [] };
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.includes('/api/v1/entries/')) {
      // per-blob fetch
      const txid = u.split('/api/v1/entries/')[1].split('?')[0];
      stats.blobCalls += 1;
      stats.requestedTxids.push(txid);
      const override = blobOverrides[txid];
      if (override) return override();
      const bodyJson = JSON.stringify({ txid, data: bytesToBase64(capturedBody) });
      return { status: 200, headers: { get: () => null }, text: async () => bodyJson, json: async () => JSON.parse(bodyJson) };
    }
    if (u.includes('/api/v1/entries?')) {
      stats.listCalls += 1;
      const page = pages[Math.min(pageIdx, pages.length - 1)];
      pageIdx += 1;
      const body = JSON.stringify({
        entries: page.entries,
        pagination: {
          count: page.entries.length,
          hasMore: page.hasMore,
          cursor: page.hasMore ? (page.entries[page.entries.length - 1]?.txid ?? null) : null,
        },
      });
      return { status: 200, headers: { get: () => null }, text: async () => body, json: async () => JSON.parse(body) };
    }
    throw new Error(`router: unexpected ${u}`);
  };
  return stats;
}

// capturedBody arrives as a JSON.stringify'd byte object/array on the wire shim
// (createEntry sends raw bytes via fetch body). Normalize to a Uint8Array.
function normalizeCaptured(capturedBody) {
  if (capturedBody instanceof Uint8Array) return capturedBody;
  if (typeof capturedBody === 'string') {
    // The client posts the ciphertext as the raw request body string of bytes.
    return new TextEncoder().encode(capturedBody);
  }
  return new Uint8Array(capturedBody);
}

describe('tarn#62 scale — client getEntries pagination + #51 partial-list', () => {
  afterEach(restoreFetch);

  it('1,200 entries across 3 pages: all decrypted, none silently dropped', async () => {
    const payload = { id: 'scaled', title: 'big', n: 42 };
    const { client, capturedBody } = await setUpClient(payload);
    const cap = normalizeCaptured(capturedBody);

    // Build 3 pages of metadata: 500 + 500 + 200 = 1,200.
    function meta(i) {
      return { txid: `tx${i}`, app: APP, type: 'books', eid: `e${i}`, tags: [{ name: 'Eid', value: `e${i}` }], confirmed: true, cachedAt: i };
    }
    const all = Array.from({ length: 1200 }, (_, i) => meta(i));
    const pages = [
      { entries: all.slice(0, 500), hasMore: true },
      { entries: all.slice(500, 1000), hasMore: true },
      { entries: all.slice(1000, 1200), hasMore: false },
    ];
    const stats = routeListAndBlobs({ pages, capturedBody: cap });

    const entries = await client.getEntries('books');
    assert.equal(entries.length, 1200, `expected all 1,200 records, got ${entries.length}`);
    // Every record decrypted to the captured payload.
    assert.ok(entries.every((e) => e.data.id === 'scaled'), 'all records decrypt to the captured payload');
    // Exactly 3 list pages and one blob fetch per distinct txid.
    assert.equal(stats.listCalls, 3, 'paginated through exactly 3 pages');
    assert.equal(new Set(stats.requestedTxids).size, 1200, 'one blob fetch per distinct txid');
    // No txid dropped.
    assert.equal(new Set(entries.map((e) => e.txid)).size, 1200);
  });

  it('25,000-entry hard cap: never requests a 51st page even if the server keeps saying hasMore', async () => {
    const payload = { id: 'capped' };
    const { client, capturedBody } = await setUpClient(payload);
    const cap = normalizeCaptured(capturedBody);

    // Every page reports hasMore:true forever. The client must stop at 50 pages.
    // To keep the test light we use SMALL pages (5 entries) but assert the PAGE
    // COUNT cap (50) — that is the load-bearing safety valve; the 500/page limit
    // is server-enforced. 50 pages × 5 = 250 blob fetches (cheap).
    let counter = 0;
    const router = {
      listCalls: 0, blobCalls: 0,
    };
    globalThis.fetch = async (url) => {
      const u = String(url);
      if (u.includes('/api/v1/entries/')) {
        router.blobCalls += 1;
        const txid = u.split('/api/v1/entries/')[1].split('?')[0];
        const body = JSON.stringify({ txid, data: bytesToBase64(cap) });
        return { status: 200, headers: { get: () => null }, text: async () => body, json: async () => JSON.parse(body) };
      }
      router.listCalls += 1;
      const entries = Array.from({ length: 5 }, () => {
        const i = counter++;
        return { txid: `tx${i}`, app: APP, type: 'books', eid: `e${i}`, tags: [{ name: 'Eid', value: `e${i}` }], confirmed: true, cachedAt: i };
      });
      const body = JSON.stringify({
        entries,
        pagination: { count: 5, hasMore: true, cursor: entries[entries.length - 1].txid }, // ALWAYS hasMore
      });
      return { status: 200, headers: { get: () => null }, text: async () => body, json: async () => JSON.parse(body) };
    };

    const entries = await client.getEntries('books');
    assert.equal(router.listCalls, 50, `must stop at the 50-page cap, requested ${router.listCalls} pages`);
    assert.equal(entries.length, 250, '50 pages × 5 entries = 250 (cap reached, loop terminated)');
  });

  it('#51: a transient blob-fetch failure throws TarnPartialListError (not a silently-short list)', async () => {
    const payload = { id: 'partial' };
    const { client, capturedBody } = await setUpClient(payload);
    const cap = normalizeCaptured(capturedBody);

    function meta(i) {
      return { txid: `tx${i}`, app: APP, type: 'books', eid: `e${i}`, tags: [{ name: 'Eid', value: `e${i}` }], confirmed: true, cachedAt: i };
    }
    const all = Array.from({ length: 30 }, (_, i) => meta(i));
    const pages = [{ entries: all, hasMore: false }];

    // Make tx7 and tx19 fail with a transient 503 (exhausts retry → strict throw).
    const failing = new Set(['tx7', 'tx19']);
    const blobOverrides = {};
    for (const tx of failing) {
      blobOverrides[tx] = () => ({ status: 503, headers: { get: () => null }, text: async () => 'boom', json: async () => null, body: { cancel: async () => {} } });
    }
    routeListAndBlobs({ pages, capturedBody: cap, blobOverrides });

    let caught;
    try {
      await client.getEntries('books');
    } catch (err) {
      caught = err;
    }
    assert.ok(caught instanceof TarnPartialListError, `expected TarnPartialListError, got ${caught?.name}: ${caught?.message}`);
    // The 28 good records are carried, and BOTH failing txids are reported —
    // nothing silently dropped.
    assert.equal(caught.entries.length, 28, 'successful records carried on the error');
    assert.deepEqual([...caught.failedTxids].sort(), ['tx19', 'tx7'], 'both transient failures surfaced');
  });
});
