// Unit tests for caller-supplied idempotency key on Collection.create
// (bookish#225 / seam S-2).
//
// The API already honors X-Idempotency-Key with a 24h dedup TTL, but the SDK
// previously minted a FRESH random key on every createEntry call — so a caller
// that retried the same logical write (e.g. an offline-replay path re-running a
// queued op after a crash, or a requeue after a lost response) sent a DIFFERENT
// key each time, defeating dedup → a second remote entry.
//
// The fix threads an OPTIONAL, backward-compatible `opts.idempotencyKey`
// through Collection.create → ITarnClient.createEntry → the POST header. When
// provided, the SAME key is sent verbatim on every attempt, so the API dedups.
// When omitted, behavior is unchanged: a fresh per-call key.
//
// These tests assert against the actual X-Idempotency-Key header on the wire
// (mocked global fetch), end-to-end through both layers — same harness as
// client-eid-lookup.test.js.
//
// Run: node --test tests/unit/client-create-idempotency-key.test.js

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient } from '../../client/src/tarn.js';
import { Collection } from '../../client/src/collections/collection.js';
import { defineSchema } from '../../client/src/schema/index.js';

const APP = 'bookish';
const EMAIL = 'create-idem@example.com';
const PASSWORD = 'create-idem-pass-2026';

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

function makeSchema() {
  return defineSchema({
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
}

async function registerClient() {
  mockFetch([
    { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
    { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
    { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
  ]);
  const client = new TarnClient('https://api.tarn.dev', APP);
  await client.register(EMAIL, PASSWORD, { recoveryAcknowledged: true });
  return client;
}

function makeCollection(client, schema) {
  return new Collection({
    client,
    appId: APP,
    name: 'books',
    def: schema.collections.books,
    schemaVersion: schema.version,
  });
}

describe('Collection.create — caller-supplied idempotency key (seam S-2)', () => {
  afterEach(restoreFetch);

  it('forwards opts.idempotencyKey verbatim as X-Idempotency-Key', async () => {
    const client = await registerClient();
    const collection = makeCollection(client, makeSchema());

    mockFetch([{ status: 200, body: JSON.stringify({ id: 'tx-1' }) }]);
    await collection.create({ id: 'book-1', title: 'Stable key' }, { idempotencyKey: 'books:book-1' });

    assert.equal(fetchCalls.length, 1);
    assert.equal(fetchCalls[0].headers['X-Idempotency-Key'], 'books:book-1');
  });

  it('sends the SAME key on a replay of the same create (would dedup server-side)', async () => {
    // The double-write scenario at the SDK seam: the same logical create is
    // attempted twice (e.g. offline replay after a crash between create() and
    // removeOp(), or a requeue after a lost response). Because the caller
    // supplies a STABLE key tied to the record's identity, both POSTs carry
    // the same X-Idempotency-Key — the API's 24h dedup collapses the duplicate.
    const client = await registerClient();
    const collection = makeCollection(client, makeSchema());
    const key = 'books:book-stable';

    // First attempt (initial optimistic create).
    mockFetch([{ status: 200, body: JSON.stringify({ id: 'tx-1' }) }]);
    await collection.create({ id: 'book-stable', title: 'v1' }, { idempotencyKey: key });
    const firstKey = fetchCalls[0].headers['X-Idempotency-Key'];

    // Second attempt (replay of the SAME op — same record identity → same key).
    mockFetch([{ status: 200, body: JSON.stringify({ id: 'tx-1' }) }]);
    await collection.create({ id: 'book-stable', title: 'v1' }, { idempotencyKey: key });
    const secondKey = fetchCalls[0].headers['X-Idempotency-Key'];

    assert.equal(firstKey, key);
    assert.equal(secondKey, key);
    assert.equal(firstKey, secondKey, 'replay must reuse the same key so the API dedups');
  });

  it('mints a fresh key when opts is omitted (unchanged default behavior)', async () => {
    const client = await registerClient();
    const collection = makeCollection(client, makeSchema());

    mockFetch([{ status: 200, body: JSON.stringify({ id: 'tx-1' }) }]);
    await collection.create({ id: 'book-a', title: 'A' });
    const keyA = fetchCalls[0].headers['X-Idempotency-Key'];

    mockFetch([{ status: 200, body: JSON.stringify({ id: 'tx-2' }) }]);
    await collection.create({ id: 'book-b', title: 'B' });
    const keyB = fetchCalls[0].headers['X-Idempotency-Key'];

    // A key is always present (the API contract still wants one), but with no
    // caller key the SDK generates a fresh one per call — so two distinct
    // creates get distinct keys.
    assert.ok(keyA, 'a key is still sent by default');
    assert.ok(keyB, 'a key is still sent by default');
    assert.notEqual(keyA, keyB, 'omitted opts → fresh per-call key, as before');
  });

  it('ignores a falsy/empty idempotencyKey and falls back to a generated one', async () => {
    const client = await registerClient();
    const collection = makeCollection(client, makeSchema());

    mockFetch([{ status: 200, body: JSON.stringify({ id: 'tx-1' }) }]);
    await collection.create({ id: 'book-c', title: 'C' }, { idempotencyKey: '' });

    const key = fetchCalls[0].headers['X-Idempotency-Key'];
    assert.ok(key && key.length > 0, 'empty key must not reach the wire as the header');
    assert.notEqual(key, '');
  });
});
