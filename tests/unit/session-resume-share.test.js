// Gap D verification: per-content CEK fallback works after session resume.
//
// Scenario being covered:
//   - User registers, app creates a record. The legacy client caches the
//     CEK (shareKey) keyed by txid in #shareKeyCache.
//   - serializeSession persists the user's DEK chain.
//   - On a fresh page load, resumeSession produces a NEW client with an
//     empty share-key cache.
//   - When the app calls share() (= getShareKey under the hood), the SDK
//     must hit #recoverShareKey: fetch the blob, AES-KW-unwrap the in-blob
//     CEK slot using the resumed DEK, and produce the same shareKey that
//     was originally cached.
//
// This is the single most important property for any Tarn-built PWA:
// pre-reload writes must remain shareable after the user returns to the
// page and resumes their session, without re-authenticating.
//
// Run: node --test tests/unit/session-resume-share.test.js

import '../indexeddb-shim.mjs';
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient } from '../../client/src/tarn.js';
import { hasTarnBlobMagic } from '../../client/src/crypto.js';

const APP = 'bookish';
const EMAIL = 'gap-d@example.com';
const PASSWORD = 'gap-d-pass-2026';

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

describe('Gap D — share-key cold-path recovery after session resume', () => {
  afterEach(restoreFetch);

  it('a freshly-resumed client recovers the shareKey from the blob via DEK unwrap', async () => {
    // ============ Phase 1: register + write entry on client A ============
    mockFetch([
      // register + auth
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
      // createEntry
      { status: 200, body: JSON.stringify({ id: 'tx-gap-d' }) },
    ]);

    const clientA = new TarnClient('https://api.tarn.dev', APP);
    await clientA.register(EMAIL, PASSWORD, { recoveryAcknowledged: true, emailRecoveryKit: false });
    await clientA.createEntry('entry', { title: 'Mountains of the Mind' });

    // Capture the v3 blob the client wrote — that's what the cold-path must
    // be able to unwrap without the in-memory shareKey cache.
    const writeCall = fetchCalls.find(c =>
      c.url.endsWith('/api/v1/entries') && c.method === 'POST'
    );
    assert.ok(writeCall, 'createEntry should have posted a blob');
    const blobBytes = writeCall.body;
    assert.equal(hasTarnBlobMagic(blobBytes), true, 'blob must be v3 (TARN-prefixed)');
    const writeTags = JSON.parse(writeCall.headers['X-Arweave-Tags']);

    // Capture the cached shareKey on the original client. This is what the
    // resumed client MUST reproduce via the cold path.
    const txid = 'tx-gap-d';
    const originalShareKey = await clientA.getShareKey(txid);
    assert.ok(originalShareKey, 'sanity: hot-path getShareKey on original client returns a shareKey');
    assert.match(originalShareKey, /^[A-Za-z0-9_-]+$/, 'shareKey is base64url');

    // ============ Phase 2: serialize, simulate page reload, resume ============
    const blob = await clientA.serializeSession();
    assert.ok(typeof blob === 'string' && blob.length > 0, 'session serializes to a non-empty string');

    // resumeSession reads from IndexedDB (the wrapping key). The shim is
    // process-global, so the resumed client uses the same wrapping key the
    // serialize call wrote with.
    const clientB = await TarnClient.resumeSession('https://api.tarn.dev', APP, blob);
    assert.ok(clientB, 'resumeSession returned a client');
    assert.equal(clientB.isLoggedIn(), true, 'resumed client is logged in');

    // ============ Phase 3: cold-path getShareKey on the fresh client ============
    // The resumed client's #shareKeyCache is empty by construction. Calling
    // getShareKey must hit #recoverShareKey, which:
    //   1. fetches GET /api/v1/entries/{txid}
    //   2. slices the wrapped CEK from the blob
    //   3. AES-KW-unwraps with the resumed DEK
    //   4. base64url-encodes the raw CEK bytes
    // The result must equal the shareKey we captured pre-reload.
    pushFetch([
      // GET /api/v1/entries/{txid}: the blob fetch
      {
        status: 200,
        body: JSON.stringify({
          txid,
          data: bytesToBase64(blobBytes),
          tags: writeTags,
        }),
      },
    ]);

    const recoveredShareKey = await clientB.getShareKey(txid);
    assert.equal(
      recoveredShareKey,
      originalShareKey,
      'cold-path-recovered shareKey must equal the original',
    );

    // Verify we actually used the cold path — there should have been a GET
    // for the blob during the recovery call.
    const blobFetchCall = fetchCalls.find(c =>
      c.url.endsWith(`/api/v1/entries/${txid}`) && c.method === 'GET'
    );
    assert.ok(blobFetchCall, 'cold path should have fetched the blob via GET /api/v1/entries/{txid}');
  });

  it('cold path returns null for an unknown txid (non-existent blob)', async () => {
    // Belt and suspenders: confirm the cold path fails gracefully (returns
    // null) rather than throwing when the blob simply doesn't exist. Apps
    // surface this as "shareKey unavailable" — Collection.share() turns it
    // into a clear usage error.
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'e'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
    ]);

    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register('gap-d-2@example.com', 'pw', { recoveryAcknowledged: true, emailRecoveryKit: false });

    // Unknown txid — fetch returns 404.
    pushFetch([
      { status: 404, body: JSON.stringify({ error: 'not found' }) },
    ]);
    const result = await client.getShareKey('tx-does-not-exist');
    assert.equal(result, null, 'cold path returns null for missing blob');
  });
});
