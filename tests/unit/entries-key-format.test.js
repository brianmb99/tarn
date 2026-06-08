// Unit tests for tarn#60 — `key` (data_lookup_key) format validation on the
// unauthenticated GET /api/v1/entries metadata-read path.
//
// The dlk is always a 64-char lowercase hex string (SHA-256-shaped; see
// TARN_PROTOCOL.md). Rejecting anything else up front is non-breaking for
// every legitimate client and shrinks the unauthenticated enumeration surface
// (a prober can't spend our rate-limit KV keyspace on arbitrary strings, and
// malformed keys fail fast before any DB / cache fan-out). Mirrors the
// existing validation on GET /api/v1/lookup.
//
// Run: node --import tsx --test tests/unit/entries-key-format.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { handleEntries } from '../../api/src/routes/entries.js';
import { signJWT } from '../../api/src/auth.js';

// A DB / KV that throws if touched — proves the format check short-circuits
// BEFORE any rate-limit or cache work for a malformed key.
const explodingEnv = {
  get DB() { throw new Error('DB must not be touched for a malformed key'); },
  get RATE_KV() { throw new Error('RATE_KV must not be touched for a malformed key'); },
};

const ctx = { waitUntil() {} };
const cors = {};
// The format-rejection cases (malformed key) must 400 BEFORE the auth check —
// the regex runs first by design — so a request with no Authorization header
// still proves the fast-fail property.
const request = { headers: { get() { return null; } } };

// tarn#60 — once a key passes the format gate the route requires a user-role
// JWT matching that account. The "valid key passes the gate" case below needs
// one. We omit `sid` so requireAuth takes the stateless grandfather branch and
// never touches a sessions table.
const JWT_SECRET = btoa('entries-key-format-test-secret');
async function authedRequestFor(dlk) {
  const jwt = await signJWT({ sub: dlk, role: 'user' }, JWT_SECRET);
  return {
    headers: {
      get(name) {
        return name === 'Authorization' ? `Bearer ${jwt}` : null;
      },
    },
  };
}

function urlFor(key) {
  return new URL(`https://api.tarn.dev/api/v1/entries?app=bookish&type=entry&key=${key}`);
}

async function bodyOf(res) {
  return await res.json();
}

const VALID_DLK = 'a'.repeat(64);

describe('handleEntries — key format validation (tarn#60)', () => {
  it('rejects a too-short key with 400 before touching DB/KV', async () => {
    const res = await handleEntries(urlFor('deadbeef'), explodingEnv, ctx, cors, request);
    assert.equal(res.status, 400);
    const body = await bodyOf(res);
    assert.match(body.error, /Invalid key format/);
  });

  it('rejects an uppercase-hex key (dlks are lowercase)', async () => {
    const res = await handleEntries(urlFor('A'.repeat(64)), explodingEnv, ctx, cors, request);
    assert.equal(res.status, 400);
  });

  it('rejects a 64-char non-hex key', async () => {
    const res = await handleEntries(urlFor('z'.repeat(64)), explodingEnv, ctx, cors, request);
    assert.equal(res.status, 400);
  });

  it('rejects a key with a path/regex-injection attempt', async () => {
    const res = await handleEntries(
      urlFor(encodeURIComponent("'; DROP TABLE entries;--")), explodingEnv, ctx, cors, request,
    );
    assert.equal(res.status, 400);
  });

  it('still 400s on missing key (existing behavior preserved)', async () => {
    const url = new URL('https://api.tarn.dev/api/v1/entries?app=bookish&type=entry');
    const res = await handleEntries(url, explodingEnv, ctx, cors, request);
    assert.equal(res.status, 400);
    const body = await bodyOf(res);
    assert.match(body.error, /Missing required params/);
  });

  it('a well-formed 64-char hex key PASSES the format gate (proceeds to rate-limit)', async () => {
    // For a valid key the handler must move PAST validation (and the tarn#60
    // auth check) into the rate-limit check. We detect that by handing it a
    // RATE_KV that records a get — if validation or auth had rejected the
    // request, RATE_KV would never be read. The request carries a matching
    // user-role JWT so the account-match check passes.
    const request = await authedRequestFor(VALID_DLK);
    let kvTouched = false;
    const env = {
      JWT_SECRET,
      RATE_KV: {
        async get() { kvTouched = true; return null; },
        async put() {},
      },
      // refreshCache + getResolvedEntries will run after the rate-limit check.
      // Return a truthy row for the bootstrap-marker SELECT so refreshCache
      // short-circuits (no Arweave GraphQL call), and an empty result set for
      // the entries SELECT so the handler completes with an empty list.
      DB: {
        prepare(sql) {
          return {
            bind() { return this; },
            async all() { return { results: [] }; },
            async first() {
              // cache_meta bootstrap probe → pretend it's already bootstrapped.
              if (sql.includes('cache_meta')) return { 1: 1 };
              return null;
            },
            async run() { return { success: true }; },
          };
        },
        async batch() { return []; },
      },
    };
    const res = await handleEntries(urlFor(VALID_DLK), env, ctx, cors, request);
    assert.ok(kvTouched, 'a valid key must reach the rate-limit check (format gate passed)');
    // 200 (empty list) is the happy path; the point is it was NOT a 400 reject.
    assert.notEqual(res.status, 400, 'valid key must not be rejected by the format gate');
  });
});
