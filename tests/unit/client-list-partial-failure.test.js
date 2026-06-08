// Unit tests for tarn#51 — list() must NOT silently drop records when a
// per-entry blob fetch fails for a TRANSIENT reason (rate limit / 5xx /
// network) as opposed to the entry being genuinely absent (404).
//
// Before this change:
//   - #fetchBlob wrapped the per-entry GET in try/catch and returned `null`
//     on ANY error (including a TarnRateLimitError).
//   - getEntries fanned out blob fetches via Promise.allSettled and a `null`
//     was treated as "entry absent", so a mid-list rate limit collapsed to a
//     missing record and list() returned a partial library that LOOKED
//     complete — the typed rate-limit error was defeated on the highest
//     -volume read path.
//
// After (tarn#51):
//   - #fetchBlob has a strict mode (used by getEntries) that throws on a
//     transient failure and returns null only on a genuine 404 / malformed
//     200.
//   - getEntries aggregates transient failures and throws TarnPartialListError
//     carrying the records that DID succeed + the txids that failed + the
//     underlying cause (with retryAfterSeconds hoisted from a rate limit).
//
// These tests assert: a list where one blob fetch 429s does NOT return as if
// that record were absent — it throws the typed partial-list error; a real
// 404 still skips (absent); a fully-successful list still returns everything.
//
// Run: node --import tsx --test tests/unit/client-list-partial-failure.test.js

import '../indexeddb-shim.mjs';
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  TarnClient,
  TarnRateLimitError,
  TarnPartialListError,
} from '../../client/src/tarn.js';

const APP = 'bookish';
const PASSWORD = 'list-partial-pass-2026';

const originalFetch = globalThis.fetch;

function fakeJwt(label = 'jwt') {
  const b64url = (s) => btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const header = b64url('{"alg":"none"}');
  const payload = b64url(JSON.stringify({ sub: label, exp: Math.floor(Date.now() / 1000) + 3600 }));
  return `${header}.${payload}.`;
}

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function uniqueDlk() {
  return Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
}

function restoreFetch() {
  globalThis.fetch = originalFetch;
}

// Queue-based mock for the register + write phase (deterministic order).
function mockQueue(responses) {
  const q = responses.slice();
  const calls = [];
  globalThis.fetch = async (url, opts) => {
    calls.push({ url, method: opts?.method || 'GET', body: opts?.body, headers: opts?.headers || {} });
    const next = q.shift();
    if (!next) throw new Error(`mockQueue: no response queued for ${url}`);
    return {
      status: next.status,
      headers: { get: () => null },
      text: async () => next.body ?? '',
      json: async () => { try { return JSON.parse(next.body ?? ''); } catch { return null; } },
    };
  };
  return calls;
}

// URL-routing mock for the LIST phase, where getEntries fans out concurrent
// per-entry blob GETs and arrival order is non-deterministic. `routes` maps a
// substring matcher → response descriptor. A descriptor may be a Response-like
// object {status, body, headers} or an Error to throw (network failure).
function mockRouter(routes) {
  const seen = [];
  globalThis.fetch = async (url, opts) => {
    seen.push(url);
    for (const [needle, descOrFn] of routes) {
      if (url.includes(needle)) {
        const desc = typeof descOrFn === 'function' ? descOrFn(url) : descOrFn;
        if (desc instanceof Error) throw desc;
        const headers = desc.headers || {};
        return {
          status: desc.status,
          headers: { get: (h) => headers[h] ?? null },
          text: async () => desc.body ?? '',
          json: async () => { try { return JSON.parse(desc.body ?? ''); } catch { return null; } },
        };
      }
    }
    throw new Error(`mockRouter: no route for ${url}`);
  };
  return seen;
}

// Register a client and capture real ciphertext for `count` entries by writing
// them through createEntry. We then replay that ciphertext through the per
// -entry blob endpoint under DIFFERENT txids so the blob cache (keyed by the
// created txid) misses and the LIST path must go to the network — which is
// exactly where the transient-failure handling lives.
async function setUpWithBlobs(count) {
  const dlk = uniqueDlk();
  mockQueue([
    { status: 201, body: JSON.stringify({ data_lookup_key: dlk }) },
    { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
    { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
  ]);
  const client = new TarnClient('https://api.tarn.dev', APP);
  await client.register(`list-${Date.now()}-${Math.random().toString(16).slice(2)}@example.com`, PASSWORD, {
    recoveryAcknowledged: true,
  });

  const blobs = [];
  for (let i = 0; i < count; i++) {
    const createdTx = `created-${Math.random().toString(16).slice(2, 12)}`;
    const calls = mockQueue([{ status: 200, body: JSON.stringify({ id: createdTx }) }]);
    const eid = `eid-${i}-${Math.random().toString(16).slice(2, 8)}`;
    await client.createEntry('books', { id: `b${i}`, title: `Book ${i}` }, [{ name: 'Eid', value: eid }]);
    // The write body is the encrypted blob; tags come from the X-Arweave-Tags
    // header. We re-serve these under a fresh listTx so the cache misses.
    const listTx = `list-${Math.random().toString(16).slice(2, 12)}`;
    blobs.push({
      listTx,
      eid,
      ciphertextBase64: bytesToBase64(calls[0].body),
      tags: JSON.parse(calls[0].headers['X-Arweave-Tags']),
      bookId: `b${i}`,
    });
  }
  return { client, dlk, blobs };
}

// Build the LIST metadata-only response getEntries() expects from the
// `/api/v1/entries?...&limit=500` page.
function listPage(blobs) {
  return {
    status: 200,
    body: JSON.stringify({
      entries: blobs.map((b) => ({ txid: b.listTx, tags: b.tags })),
      pagination: { hasMore: false },
    }),
  };
}

describe('tarn#51 — getEntries surfaces transient blob-fetch failures', () => {
  afterEach(restoreFetch);

  it('throws TarnPartialListError (not a partial silent result) when one blob 429s', async () => {
    const { client, blobs } = await setUpWithBlobs(3);
    const [ok1, rl, ok2] = blobs;

    mockRouter([
      // The list metadata page (no per-entry txid in the path).
      [`/api/v1/entries?app=`, listPage(blobs)],
      // Per-entry blob fetches, routed by txid in the path.
      [`/api/v1/entries/${ok1.listTx}`, { status: 200, body: JSON.stringify({ data: ok1.ciphertextBase64 }) }],
      [`/api/v1/entries/${ok2.listTx}`, { status: 200, body: JSON.stringify({ data: ok2.ciphertextBase64 }) }],
      // The middle blob is rate-limited — the regression case. Pre-fix this
      // collapsed to null → "absent" and list() returned only 2 records.
      [`/api/v1/entries/${rl.listTx}`, {
        status: 429,
        body: JSON.stringify({ error: 'rate-limited', retry_after: 120 }),
        headers: { 'Retry-After': '120' },
      }],
    ]);

    let caught;
    try {
      await client.getEntries('books');
    } catch (err) {
      caught = err;
    }

    assert.ok(caught, 'getEntries must NOT return — a transient failure makes the list incomplete');
    assert.ok(
      caught instanceof TarnPartialListError,
      `expected TarnPartialListError, got ${caught?.name}: ${caught?.message}`,
    );
    // The failed record is named, not silently dropped.
    assert.deepEqual(caught.failedTxids, [rl.listTx]);
    // The records that DID fetch are carried for best-effort UX.
    assert.equal(caught.entries.length, 2);
    assert.deepEqual(caught.entries.map((e) => e.data.id).sort(), ['b0', 'b2']);
    // Rate-limit advice is hoisted so a caller can schedule a retry.
    assert.equal(caught.retryAfterSeconds, 120);
    assert.ok(caught.cause instanceof TarnRateLimitError, 'cause is the underlying rate-limit error');
  });

  it('throws TarnPartialListError when a blob fetch fails with a network error', async () => {
    const { client, blobs } = await setUpWithBlobs(2);
    const [ok1, netFail] = blobs;

    mockRouter([
      [`/api/v1/entries?app=`, listPage(blobs)],
      [`/api/v1/entries/${ok1.listTx}`, { status: 200, body: JSON.stringify({ data: ok1.ciphertextBase64 }) }],
      // fetch() throws a TypeError — the shape of a browser network failure.
      // The SDK retry layer exhausts then rethrows; strict #fetchBlob must
      // propagate it rather than swallow to null.
      [`/api/v1/entries/${netFail.listTx}`, new TypeError('Failed to fetch')],
    ]);

    await assert.rejects(
      () => client.getEntries('books'),
      (err) => {
        assert.ok(err instanceof TarnPartialListError, `got ${err?.name}`);
        assert.deepEqual(err.failedTxids, [netFail.listTx]);
        assert.equal(err.entries.length, 1);
        assert.equal(err.retryAfterSeconds, null); // not a rate limit
        return true;
      },
    );
  });

  it('a genuine 404 is treated as absent (skipped), not a transient failure', async () => {
    const { client, blobs } = await setUpWithBlobs(2);
    const [ok1, gone] = blobs;

    mockRouter([
      [`/api/v1/entries?app=`, listPage(blobs)],
      [`/api/v1/entries/${ok1.listTx}`, { status: 200, body: JSON.stringify({ data: ok1.ciphertextBase64 }) }],
      // 404 = the entry really isn't there. This must NOT throw — it's the
      // legitimate absent case (consistent with prior behavior for not-found).
      [`/api/v1/entries/${gone.listTx}`, { status: 404, body: JSON.stringify({ error: 'not_found' }) }],
    ]);

    const entries = await client.getEntries('books');
    assert.equal(entries.length, 1, '404 record is skipped as absent, the rest returns');
    assert.equal(entries[0].data.id, 'b0');
  });

  it('a fully-successful list returns every record (no false positives)', async () => {
    const { client, blobs } = await setUpWithBlobs(3);

    mockRouter([
      [`/api/v1/entries?app=`, listPage(blobs)],
      ...blobs.map((b) => [
        `/api/v1/entries/${b.listTx}`,
        { status: 200, body: JSON.stringify({ data: b.ciphertextBase64 }) },
      ]),
    ]);

    const entries = await client.getEntries('books');
    assert.equal(entries.length, 3);
    assert.deepEqual(entries.map((e) => e.data.id).sort(), ['b0', 'b1', 'b2']);
  });
});
