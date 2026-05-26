// Unit tests for the delta-sync read path.
//
// Background: before this change, every multi-device sync required pulling
// the full live set + re-fetching every blob. The delta endpoint lets a
// client poll with a cursor and get only what changed since — including a
// clean `{ eid, deleted: true }` signal for entries that have been
// tombstoned on another device.
//
// These tests verify:
//   - First sync (no cursor) processes all events and decrypts entries.
//   - Cursor persists across calls (mocked IDB) so the second sync skips
//     entries it already saw.
//   - A `deleted: true` event surfaces as an Eid in the `deleted` array,
//     no protocol-level tombstone vocabulary leaks to the caller.
//   - Server pagination is handled internally — caller sees one aggregated
//     result regardless of how many pages the server returned.
//   - Inline blobs from the delta response populate the blob cache so a
//     follow-up #fetchBlob is satisfied from IDB.
//
// Run: node --test tests/unit/client-delta-sync.test.js

import '../indexeddb-shim.mjs';
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient } from '../../client/src/tarn.js';
import { getCachedBlob } from '../../client/src/blob-cache.js';
import { getCursor } from '../../client/src/sync-cursor.js';

const APP = 'bookish';
const PASSWORD = 'delta-sync-pass-2026';

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

function pushFetch(responses) {
  fetchResponses.push(...responses);
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

function uniqueDlk() {
  return Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
}

// Set up a registered client and capture one written ciphertext we can replay
// through the delta endpoint. Returns { client, dlk, captured }.
async function setUp({ collectionType, payloads }) {
  const dlk = uniqueDlk();
  mockFetch([
    { status: 201, body: JSON.stringify({ data_lookup_key: dlk }) },
    { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
    { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
  ]);
  const client = new TarnClient('https://api.tarn.dev', APP);
  await client.register(`delta-${Date.now()}@example.com`, PASSWORD, { recoveryAcknowledged: true });

  const captured = [];
  for (const payload of payloads) {
    const tx = `tx-${Math.random().toString(16).slice(2, 12)}`;
    mockFetch([{ status: 200, body: JSON.stringify({ id: tx }) }]);
    const eid = `eid-${Math.random().toString(16).slice(2, 12)}`;
    await client.createEntry(collectionType, payload, [{ name: 'Eid', value: eid }]);
    captured.push({
      txid: tx,
      eid,
      payload,
      body: fetchCalls[0].body,
      tags: JSON.parse(fetchCalls[0].headers['X-Arweave-Tags']),
    });
  }
  return { client, dlk, captured };
}

describe('getEntriesSince — basic delta flow', () => {
  afterEach(restoreFetch);

  it('first sync returns all events and persists a cursor', async () => {
    const { client, dlk, captured } = await setUp({
      collectionType: 'books',
      payloads: [
        { id: 'b1', title: 'first' },
        { id: 'b2', title: 'second' },
      ],
    });

    const nextCursor = `${Date.now()}:${captured[1].txid}`;
    mockFetch([
      {
        status: 200,
        body: JSON.stringify({
          entries: captured.map((c) => ({
            eid: c.eid,
            txid: c.txid,
            tags: c.tags,
            data: bytesToBase64(c.body),
          })),
          pagination: { cursor: nextCursor, hasMore: false },
        }),
      },
    ]);

    const delta = await client.getEntriesSince('books');
    assert.equal(delta.entries.length, 2);
    assert.equal(delta.deleted.length, 0);
    assert.deepEqual(delta.entries.map((e) => e.data.id).sort(), ['b1', 'b2']);

    // Cursor persisted in IDB for the next call.
    const persisted = await getCursor(APP, dlk, 'books');
    assert.equal(persisted, nextCursor);

    // Inline blobs landed in the blob cache.
    for (const c of captured) {
      const cached = await getCachedBlob(APP, dlk, c.txid);
      assert.ok(cached instanceof Uint8Array, `blob for ${c.txid} should be cached`);
    }
  });

  it('subsequent sync uses the persisted cursor', async () => {
    const { client, dlk, captured } = await setUp({
      collectionType: 'books',
      payloads: [{ id: 'b1', title: 'only' }],
    });

    const firstCursor = `1000:${captured[0].txid}`;
    mockFetch([
      {
        status: 200,
        body: JSON.stringify({
          entries: [{
            eid: captured[0].eid,
            txid: captured[0].txid,
            tags: captured[0].tags,
            data: bytesToBase64(captured[0].body),
          }],
          pagination: { cursor: firstCursor, hasMore: false },
        }),
      },
    ]);
    await client.getEntriesSince('books');

    // Second call: server has no new events.
    const sameCursor = firstCursor;
    mockFetch([
      {
        status: 200,
        body: JSON.stringify({
          entries: [],
          pagination: { cursor: sameCursor, hasMore: false },
        }),
      },
    ]);
    const delta2 = await client.getEntriesSince('books');
    assert.equal(delta2.entries.length, 0, 'no new entries on warm poll');
    assert.equal(delta2.deleted.length, 0);

    // The request URL must carry the cursor from the first sync.
    assert.equal(fetchCalls.length, 1);
    const requestUrl = fetchCalls[0].url;
    assert.ok(
      requestUrl.includes(`since=${encodeURIComponent(firstCursor)}`),
      `second sync URL should carry the persisted cursor: ${requestUrl}`,
    );

    // Cursor doesn't move when the server reports no progress.
    const persisted = await getCursor(APP, dlk, 'books');
    assert.equal(persisted, sameCursor);
  });
});

describe('getEntriesSince — deletion events', () => {
  afterEach(restoreFetch);

  it('surfaces deleted Eids via the deleted array (no tombstone vocabulary)', async () => {
    const { client } = await setUp({ collectionType: 'books', payloads: [] });

    const cursor = `9999:tx-final`;
    mockFetch([
      {
        status: 200,
        body: JSON.stringify({
          entries: [
            { eid: 'eid-deleted-1', deleted: true },
            { eid: 'eid-deleted-2', deleted: true },
          ],
          pagination: { cursor, hasMore: false },
        }),
      },
    ]);

    const delta = await client.getEntriesSince('books');
    assert.equal(delta.entries.length, 0);
    assert.deepEqual(delta.deleted.sort(), ['eid-deleted-1', 'eid-deleted-2']);
  });

  it('mixes entry and deletion events in a single delta', async () => {
    const { client, captured } = await setUp({
      collectionType: 'books',
      payloads: [{ id: 'b1', title: 'lives' }],
    });

    const cursor = `5000:tx-last`;
    mockFetch([
      {
        status: 200,
        body: JSON.stringify({
          entries: [
            {
              eid: captured[0].eid,
              txid: captured[0].txid,
              tags: captured[0].tags,
              data: bytesToBase64(captured[0].body),
            },
            { eid: 'eid-gone', deleted: true },
          ],
          pagination: { cursor, hasMore: false },
        }),
      },
    ]);

    const delta = await client.getEntriesSince('books');
    assert.equal(delta.entries.length, 1);
    assert.equal(delta.entries[0].data.id, 'b1');
    assert.deepEqual(delta.deleted, ['eid-gone']);
  });
});

describe('getEntriesSince — internal pagination', () => {
  afterEach(restoreFetch);

  it('drains multiple pages internally and returns one aggregated result', async () => {
    const { client, dlk, captured } = await setUp({
      collectionType: 'books',
      payloads: [
        { id: 'b1', title: 'page1' },
        { id: 'b2', title: 'page2' },
      ],
    });

    const cursor1 = `100:${captured[0].txid}`;
    const cursor2 = `200:${captured[1].txid}`;
    mockFetch([
      // Page 1: one entry, hasMore: true
      {
        status: 200,
        body: JSON.stringify({
          entries: [{
            eid: captured[0].eid,
            txid: captured[0].txid,
            tags: captured[0].tags,
            data: bytesToBase64(captured[0].body),
          }],
          pagination: { cursor: cursor1, hasMore: true },
        }),
      },
      // Page 2: second entry, hasMore: false
      {
        status: 200,
        body: JSON.stringify({
          entries: [{
            eid: captured[1].eid,
            txid: captured[1].txid,
            tags: captured[1].tags,
            data: bytesToBase64(captured[1].body),
          }],
          pagination: { cursor: cursor2, hasMore: false },
        }),
      },
    ]);

    const delta = await client.getEntriesSince('books');
    assert.equal(delta.entries.length, 2, 'both pages aggregated into one result');
    assert.equal(fetchCalls.length, 2, 'SDK made both page requests');
    // Second request must use the cursor returned by the first.
    assert.ok(
      fetchCalls[1].url.includes(`since=${encodeURIComponent(cursor1)}`),
      'page 2 must use the cursor from page 1',
    );
    // Final cursor persisted matches page 2.
    const persisted = await getCursor(APP, dlk, 'books');
    assert.equal(persisted, cursor2);
  });
});
