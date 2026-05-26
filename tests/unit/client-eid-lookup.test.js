// Unit tests for the Eid-narrowed read path (issue: delete fan-out).
//
// Before this change, Collection.delete/update/get on a single primaryKey
// caused the SDK to fetch ALL entries in the collection + decrypt each one
// just to find the target's txid. This triggered the 300 reads/hr IP rate
// limit on users with non-trivial collection sizes.
//
// The new path: SDK derives the Eid locally (Eid = hash(appId, collection,
// primaryKey)) and asks the API for the single live entry by Eid. The API
// inlines the blob (≤1 row), so the whole operation is one round trip.
//
// These tests verify:
//   - TarnClient.getEntryByEid issues exactly one request with &eid= in
//     the URL, parses the inline base64 blob, and returns the decrypted
//     record.
//   - The request count does NOT scale with collection size.
//   - Collection.delete is idempotent — null lookup returns without
//     issuing a delete request.
//   - Collection.delete issues exactly one Eid lookup + one delete write
//     when the record exists.
//
// Run: node --test tests/unit/client-eid-lookup.test.js

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient } from '../../client/src/tarn.js';
import { Collection } from '../../client/src/collections/collection.js';
import { deriveEid } from '../../client/src/collections/eid.js';
import { defineSchema } from '../../client/src/schema/index.js';

const APP = 'bookish';
const EMAIL = 'eid-lookup@example.com';
const PASSWORD = 'eid-lookup-pass-2026';

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
    if (next instanceof Error) throw next;
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

describe('TarnClient.getEntryByEid — Eid-narrowed read path', () => {
  afterEach(restoreFetch);

  it('decrypts the inline blob returned by the ?eid= filter', async () => {
    // Register, then capture the bytes the client writes for a known payload.
    // That blob — encrypted with this client's own keys — is what we'll feed
    // back through the Eid lookup.
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
    ]);

    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register(EMAIL, PASSWORD, { recoveryAcknowledged: true });

    const payload = { id: 'book-1', title: 'Eid lookup proof' };
    mockFetch([{ status: 200, body: JSON.stringify({ id: 'tx-eid-1' }) }]);
    await client.createEntry('books', payload);
    const writeCall = fetchCalls[0];
    const blobBytes = writeCall.body;
    const writeTags = JSON.parse(writeCall.headers['X-Arweave-Tags']);

    // Serve the same blob back via the ?eid= lookup.
    mockFetch([
      {
        status: 200,
        body: JSON.stringify({
          entries: [{
            txid: 'tx-eid-1',
            data: bytesToBase64(blobBytes),
            tags: writeTags,
          }],
          pagination: { count: 1, hasMore: false, cursor: null },
        }),
      },
    ]);

    const got = await client.getEntryByEid('books', 'deadbeef-eid');
    assert.ok(got, 'getEntryByEid should return an entry');
    assert.equal(got.txid, 'tx-eid-1');
    assert.deepEqual(got.data, payload);

    // Exactly one fetch — no list, no per-txid blob round trip.
    assert.equal(fetchCalls.length, 1, 'should issue exactly one request');
    assert.ok(
      fetchCalls[0].url.includes('eid=deadbeef-eid'),
      `URL should carry eid filter: ${fetchCalls[0].url}`,
    );
    assert.ok(
      fetchCalls[0].url.includes('type=books'),
      `URL should carry type filter: ${fetchCalls[0].url}`,
    );
  });

  it('returns null when the API reports no live entry for the Eid', async () => {
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
    ]);

    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register(EMAIL, PASSWORD, { recoveryAcknowledged: true });

    mockFetch([
      {
        status: 200,
        body: JSON.stringify({
          entries: [],
          pagination: { count: 0, hasMore: false, cursor: null },
        }),
      },
    ]);

    const got = await client.getEntryByEid('books', 'no-such-eid');
    assert.equal(got, null);
    assert.equal(fetchCalls.length, 1, 'still exactly one request even on miss');
  });
});

describe('Collection.delete — idempotency and call shape', () => {
  afterEach(restoreFetch);

  it('returns silently when no live entry exists (idempotent)', async () => {
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register(EMAIL, PASSWORD, { recoveryAcknowledged: true });

    const schema = defineSchema({
      appId: APP,
      version: 1,
      collections: {
        books: {
          primaryKey: 'id',
          fields: { id: { type: 'string', required: true } },
        },
      },
    });
    const collection = new Collection({
      client,
      appId: APP,
      name: 'books',
      def: schema.collections.books,
      schemaVersion: schema.version,
    });

    // Eid lookup: 0 results.
    mockFetch([
      {
        status: 200,
        body: JSON.stringify({
          entries: [],
          pagination: { count: 0, hasMore: false, cursor: null },
        }),
      },
    ]);

    await collection.delete('missing-book'); // must not throw

    // Single Eid lookup, no delete write issued.
    assert.equal(fetchCalls.length, 1, 'exactly one request — the lookup');
    assert.ok(fetchCalls[0].url.includes('eid='), 'must be an Eid lookup');
    assert.equal(fetchCalls[0].method, 'GET');
  });

  it('issues exactly one Eid lookup + one delete when the record exists', async () => {
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register(EMAIL, PASSWORD, { recoveryAcknowledged: true });

    // Write a real blob so the lookup returns something decryptable.
    mockFetch([{ status: 200, body: JSON.stringify({ id: 'tx-del-1' }) }]);
    await client.createEntry('books', { id: 'doomed', title: 'goodbye' });
    const blobBytes = fetchCalls[0].body;
    const writeTags = JSON.parse(fetchCalls[0].headers['X-Arweave-Tags']);

    const eid = await deriveEid(APP, 'books', 'doomed');
    const schema = defineSchema({
      appId: APP,
      version: 1,
      collections: {
        books: {
          primaryKey: 'id',
          fields: {
            id: { type: 'string', required: true },
            title: { type: 'string' },
          },
        },
      },
    });
    const collection = new Collection({
      client,
      appId: APP,
      name: 'books',
      def: schema.collections.books,
      schemaVersion: schema.version,
    });

    mockFetch([
      // Eid lookup hit.
      {
        status: 200,
        body: JSON.stringify({
          entries: [{
            txid: 'tx-del-1',
            data: bytesToBase64(blobBytes),
            tags: writeTags,
          }],
          pagination: { count: 1, hasMore: false, cursor: null },
        }),
      },
      // Delete write.
      { status: 200, body: JSON.stringify({ id: 'tx-tomb-1' }) },
    ]);

    await collection.delete('doomed');

    assert.equal(fetchCalls.length, 2, 'exactly: 1 Eid lookup + 1 delete write');
    assert.ok(fetchCalls[0].url.includes(`eid=${encodeURIComponent(eid)}`));
    assert.equal(fetchCalls[1].method, 'DELETE');
  });
});
