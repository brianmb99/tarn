// Unit tests for tarn#60 — the metadata-read path now requires a user-role
// session JWT whose account matches the requested data_lookup_key.
//
// Before this change, knowing a dlk was sufficient to enumerate an account's
// encrypted metadata via GET /api/v1/entries?key=<dlk>. The dlk is no longer a
// read bearer-token: an unauthenticated party that learns one can no longer
// list the account's rows. These tests pin the enforcement model:
//
//   - GET /api/v1/entries (list / ?since= / ?eid=):
//       * no/invalid JWT          → 401
//       * app-role JWT            → 403 (platform credential, not a session)
//       * user JWT, wrong account → 403
//       * user JWT, matching dlk  → 200 (reaches the cache layer)
//   - GET /api/v1/entries/:txid:
//       * with ?key= and no JWT          → 401
//       * with ?key= and wrong-account   → 403
//       * with ?key= and matching JWT    → 200
//       * WITHOUT ?key= (txid-only)      → 200 even with no JWT (the body is
//         encrypted and a txid is non-enumerable; this path stays public so
//         recovery / advanced reads keep working).
//
// Zero-knowledge is unaffected — the server still never sees plaintext; this
// only governs WHO may pull a given account's encrypted rows.
//
// JWTs here omit the `sid` claim on purpose so requireAuth takes the stateless
// "pre-7.5 grandfather" branch and never touches a sessions table — keeping
// these tests focused on the route's auth gate.
//
// Run: node --import tsx --test tests/unit/entries-auth-required.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { handleEntries, handleEntryById } from '../../api/src/routes/entries.js';
import { signJWT } from '../../api/src/auth.js';

const JWT_SECRET = btoa('entries-auth-required-test-secret');
const OTHER_SECRET = btoa('a-different-signing-secret-entirely');

const DLK = 'a'.repeat(64);       // the account being read
const OTHER_DLK = 'b'.repeat(64); // a different account
const TXID = 'txid-under-test';

const ctx = { waitUntil() {} };
const cors = {};

// Bearer-header request whose token we control.
function requestWithToken(token) {
  return {
    headers: {
      get(name) {
        return name === 'Authorization' && token ? `Bearer ${token}` : null;
      },
    },
  };
}
function requestNoAuth() {
  return { headers: { get() { return null; } } };
}

async function userJwt(dlk, secret = JWT_SECRET) {
  return signJWT({ sub: dlk, role: 'user' }, secret);
}
async function appJwt(appId, secret = JWT_SECRET) {
  return signJWT({ sub: appId, role: 'app' }, secret);
}

// DB shim: bootstrap marker already set (no GraphQL), entries SELECT empty.
// Enough for handleEntries to complete with an empty 200 once auth passes.
function listEnv() {
  return {
    JWT_SECRET,
    RATE_KV: { async get() { return null; }, async put() {} },
    DB: {
      prepare(sql) {
        return {
          bind() { return this; },
          async all() { return { results: [] }; },
          async first() {
            if (sql.includes('cache_meta')) return { 1: 1 };
            return null;
          },
          async run() { return { success: true }; },
        };
      },
      async batch() { return []; },
    },
  };
}

// DB shim for handleEntryById: getEntryByTxid returns a single seeded row
// owned by `ownerDlk`, already carrying blob bytes so no gateway fetch runs.
function byTxidEnv(ownerDlk = DLK) {
  const row = {
    txid: TXID, app: 'bookish', type: 'entry', lookup_key: ownerDlk,
    eid: 'e1', is_tombstone: 0, tombstone_ref: null, block_timestamp: 1700000000,
    tags_json: '[]', cached_at: Date.now(),
    blob_data: new Uint8Array([1, 2, 3]),
  };
  return {
    JWT_SECRET,
    RATE_KV: { async get() { return null; }, async put() {} },
    DB: {
      prepare(sql) {
        return {
          bind() { return this; },
          async first() {
            if (/FROM entries WHERE txid/.test(sql)) return row;
            return null;
          },
          async all() { return { results: [] }; },
          async run() { return { success: true }; },
        };
      },
      async batch() { return []; },
    },
  };
}

function urlList(key) {
  return new URL(`https://api.tarn.dev/api/v1/entries?app=bookish&type=entry&key=${key}`);
}
function urlByTxid(key) {
  const base = `https://api.tarn.dev/api/v1/entries/${TXID}`;
  return new URL(key ? `${base}?key=${key}` : base);
}

describe('GET /api/v1/entries — requires matching user-role JWT (tarn#60)', () => {
  it('401 when no Authorization header is present', async () => {
    const res = await handleEntries(urlList(DLK), listEnv(), ctx, cors, requestNoAuth());
    assert.equal(res.status, 401);
    assert.match((await res.json()).error, /Unauthorized/);
  });

  it('401 when the JWT is signed with the wrong secret (invalid signature)', async () => {
    const badToken = await userJwt(DLK, OTHER_SECRET);
    const res = await handleEntries(urlList(DLK), listEnv(), ctx, cors, requestWithToken(badToken));
    assert.equal(res.status, 401);
  });

  it('401 on a structurally-broken bearer token', async () => {
    const res = await handleEntries(urlList(DLK), listEnv(), ctx, cors, requestWithToken('not.a.jwt'));
    assert.equal(res.status, 401);
  });

  it('403 when the JWT is an app-role token (platform credential, not a session)', async () => {
    // App tokens carry the app_id as `sub`; even if it somehow equalled the
    // dlk, role !== "user" must reject. Use the dlk as the app_id to prove the
    // role check (not just the account-match) is doing the work.
    const token = await appJwt(DLK);
    const res = await handleEntries(urlList(DLK), listEnv(), ctx, cors, requestWithToken(token));
    assert.equal(res.status, 403);
    assert.match((await res.json()).error, /Forbidden/);
  });

  it('403 when a valid user JWT is for a DIFFERENT account', async () => {
    const token = await userJwt(OTHER_DLK);
    const res = await handleEntries(urlList(DLK), listEnv(), ctx, cors, requestWithToken(token));
    assert.equal(res.status, 403);
    assert.match((await res.json()).error, /Forbidden/);
  });

  it('200 when the user JWT matches the requested account', async () => {
    const token = await userJwt(DLK);
    const res = await handleEntries(urlList(DLK), listEnv(), ctx, cors, requestWithToken(token));
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.deepEqual(body.entries, []);
  });

  it('still 400s a malformed key BEFORE the auth check (fast-fail preserved)', async () => {
    // No auth + malformed key → 400 (format gate), not 401. Proves ordering:
    // the cheap regex runs first and reveals nothing pre-auth.
    const res = await handleEntries(urlList('deadbeef'), listEnv(), ctx, cors, requestNoAuth());
    assert.equal(res.status, 400);
  });
});

describe('GET /api/v1/entries/:txid — auth scoping (tarn#60)', () => {
  it('401 when ?key= is supplied but no JWT', async () => {
    const res = await handleEntryById(TXID, urlByTxid(DLK), byTxidEnv(), ctx, cors, requestNoAuth());
    assert.equal(res.status, 401);
  });

  it('403 when ?key= is supplied with a different-account JWT', async () => {
    const token = await userJwt(OTHER_DLK);
    const res = await handleEntryById(TXID, urlByTxid(DLK), byTxidEnv(), ctx, cors, requestWithToken(token));
    assert.equal(res.status, 403);
  });

  it('200 when ?key= matches the JWT account', async () => {
    const token = await userJwt(DLK);
    const res = await handleEntryById(TXID, urlByTxid(DLK), byTxidEnv(), ctx, cors, requestWithToken(token));
    assert.equal(res.status, 200);
  });

  it('200 on the txid-only path (no ?key=) even with NO JWT — stays public by design', async () => {
    const res = await handleEntryById(TXID, urlByTxid(null), byTxidEnv(), ctx, cors, requestNoAuth());
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.txid, TXID);
  });
});
