// Unit tests for the ciphertext blob cache.
//
// Background: Arweave txids are content hashes, so blobs are immutable
// forever. Before this cache, every list() refetched every blob — turning
// a 200-record library into a 201-hit burst against the 300/hr IP rate
// limit. The cache makes warm reads cost zero blob network round trips.
//
// These tests verify:
//   - A second getEntries() over the same set of entries issues zero
//     per-blob fetches (the metadata-list call still happens — that's #2
//     in the proposal, not addressed here).
//   - createEntry pre-populates the cache so a same-device read after
//     write skips the network on the blob path.
//   - The cache stores ciphertext (not plaintext) — verified by reading
//     the cached bytes directly and confirming the TARN magic prefix.
//
// Run: node --test tests/unit/client-blob-cache.test.js

import '../indexeddb-shim.mjs';
import { describe, it, afterEach, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient } from '../../client/src/tarn.js';
import { hasTarnBlobMagic } from '../../client/src/crypto.js';
import { getCachedBlob } from '../../client/src/blob-cache.js';

const APP = 'bookish';
const EMAIL = 'blob-cache@example.com';
const PASSWORD = 'blob-cache-pass-2026';

const originalFetch = globalThis.fetch;
let fetchCalls = [];
let fetchResponses = [];

function mockFetch(responses) {
  fetchCalls = [];
  fetchResponses = responses.slice();
  globalThis.fetch = async (url, opts) => {
    fetchCalls.push({
      url,
      method: opts?.method || 'GET',
      body: opts?.body,
      headers: opts?.headers || {},
    });
    const next = fetchResponses.shift();
    if (!next) throw new Error(`mockFetch: no response queued for ${url}`);
    return {
      status: next.status,
      headers: { get: () => null },
      text: async () => next.body ?? '',
      json: async () => {
        try { return JSON.parse(next.body ?? ''); } catch { return null; }
      },
    };
  };
}

function restoreFetch() {
  globalThis.fetch = originalFetch;
  fetchCalls = [];
  fetchResponses = [];
}

function fakeJwt(label = 'jwt') {
  const b64url = (s) => btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const header = b64url('{"alg":"none"}');
  const payload = b64url(JSON.stringify({ sub: label, exp: Math.floor(Date.now() / 1000) + 3600 }));
  return `${header}.${payload}.`;
}

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

// Each test gets a unique dlk so cached blobs don't bleed between tests.
function uniqueDlk() {
  return Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
}

describe('Blob cache — write-side pre-populate', () => {
  afterEach(restoreFetch);

  it('createEntry stores the ciphertext under the resulting txid', async () => {
    const dlk = uniqueDlk();
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: dlk }) },
      { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
    ]);

    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register(EMAIL, PASSWORD, { recoveryAcknowledged: true });

    const txid = `tx-cache-${Date.now()}`;
    mockFetch([{ status: 200, body: JSON.stringify({ id: txid }) }]);
    await client.createEntry('books', { id: 'b1', title: 'cached on write' });

    const cached = await getCachedBlob(APP, dlk, txid);
    assert.ok(cached instanceof Uint8Array, 'cache must contain the just-written blob');
    assert.equal(
      hasTarnBlobMagic(cached),
      true,
      'cached bytes must be ciphertext (TARN magic prefix), not plaintext',
    );
  });
});

describe('Blob cache — warm-read elimination', () => {
  afterEach(restoreFetch);

  it('second getEntries with the same txids issues zero per-blob fetches', async () => {
    const dlk = uniqueDlk();
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: dlk }) },
      { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
    ]);

    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register(EMAIL, PASSWORD, { recoveryAcknowledged: true });

    // Write three entries. createEntry pre-populates the cache, but we also
    // want to exercise the read-path cache, so we deliberately invalidate
    // the cache by writing to txids that DON'T exist in our cache and then
    // serving them through getEntries. Simpler approach: write the entries,
    // then call getEntries — the per-blob fetches should hit the cache and
    // not the network.
    const writeTxids = [];
    for (let i = 0; i < 3; i++) {
      const tx = `tx-warm-${i}-${Date.now()}`;
      mockFetch([{ status: 200, body: JSON.stringify({ id: tx }) }]);
      await client.createEntry('books', { id: `b${i}`, title: `Book ${i}` });
      writeTxids.push(tx);
    }

    // Snapshot what tags the writes used so we can replay them in the
    // metadata response (the tags carry Enc/Gen which the read path needs).
    const writeCalls = [];
    for (let i = 0; i < 3; i++) {
      // We can't recover write tags from this scope (mockFetch resets each
      // call). Instead, do a single warm-write + read with all three.
    }

    // Reset and do the read sequence. We need real tags in the metadata
    // response, so write each entry fresh and capture the tags this time.
    restoreFetch();
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: uniqueDlk() }) },
      { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg2') }) },
    ]);
    const client2 = new TarnClient('https://api.tarn.dev', APP);
    await client2.register(`warm-${Date.now()}@example.com`, PASSWORD, { recoveryAcknowledged: true });

    // Capture write tags + bytes for three writes.
    const captured = [];
    for (let i = 0; i < 3; i++) {
      const tx = `tx-w${i}-${Date.now()}`;
      mockFetch([{ status: 200, body: JSON.stringify({ id: tx }) }]);
      await client2.createEntry('books', { id: `b${i}`, title: `Book ${i}` });
      const writeCall = fetchCalls[0];
      captured.push({
        txid: tx,
        tags: JSON.parse(writeCall.headers['X-Arweave-Tags']),
        body: writeCall.body,
      });
    }

    // Now perform getEntries. The metadata-list call still happens; the
    // per-blob fetches should be served by the cache because createEntry
    // pre-populated it.
    mockFetch([
      {
        status: 200,
        body: JSON.stringify({
          entries: captured.map(c => ({ txid: c.txid, tags: c.tags })),
          pagination: { hasMore: false },
        }),
      },
    ]);

    const got = await client2.getEntries('books');
    assert.equal(got.length, 3, 'should decrypt all three entries');

    // Exactly ONE request: the metadata-list call. Zero per-blob fetches.
    assert.equal(
      fetchCalls.length,
      1,
      `expected 1 request (metadata only), got ${fetchCalls.length}: ${fetchCalls.map(c => c.url).join(', ')}`,
    );
  });

  it('cache miss falls back to per-blob fetch (cold path still works)', async () => {
    const dlk = uniqueDlk();
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: dlk }) },
      { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register(`cold-${Date.now()}@example.com`, PASSWORD, { recoveryAcknowledged: true });

    // Write one entry to capture real ciphertext + tags.
    const txid = `tx-cold-${Date.now()}`;
    mockFetch([{ status: 200, body: JSON.stringify({ id: txid }) }]);
    await client.createEntry('books', { id: 'b1', title: 'cold' });
    const writeCall = fetchCalls[0];
    const writeTags = JSON.parse(writeCall.headers['X-Arweave-Tags']);
    const writeBytes = writeCall.body;

    // Pretend we're a fresh device that never wrote this entry: serve it
    // back through getEntries, with the per-blob fetch returning the same
    // ciphertext. The metadata call has a different txid that ISN'T in the
    // cache, so the SDK must fall back to the network.
    const coldTxid = `tx-not-cached-${Date.now()}`;
    mockFetch([
      {
        status: 200,
        body: JSON.stringify({
          entries: [{ txid: coldTxid, tags: writeTags }],
          pagination: { hasMore: false },
        }),
      },
      {
        status: 200,
        body: JSON.stringify({
          txid: coldTxid,
          data: bytesToBase64(writeBytes),
          tags: writeTags,
        }),
      },
    ]);
    const got = await client.getEntries('books');
    assert.equal(got.length, 1, 'cold-path decrypt still works');
    assert.equal(fetchCalls.length, 2, 'cold path issues metadata + per-blob fetch');
  });
});
