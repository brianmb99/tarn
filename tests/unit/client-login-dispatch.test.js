// Unit tests for TarnClient login KDF dispatch (issue #9).
// Tests that login() tries Argon2id (v2) first and falls back to PBKDF2 (v1)
// when the v2 credential_lookup_key 404s.
//
// Uses real KDFs (Argon2id + PBKDF2) — each test is ~1–2s. Mocks fetch so no
// network or D1 dependency.
//
// Run: node --test tests/unit/client-login-dispatch.test.js

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient } from '../../client/src/tarn.js';
import {
  deriveAllKeys,
  exportPublicKey,
  wrapDataKeyEnvelope,
  KDF_V1_PBKDF2,
  KDF_V2_ARGON2ID,
} from '../../client/src/crypto.js';

const APP = 'bookish';
const EMAIL = 'dispatch-test@example.com';
const PASSWORD = 'correct-horse-battery-staple-2026';

const originalFetch = globalThis.fetch;
let fetchCalls = [];
let fetchResponses = [];

function mockFetch(responses) {
  fetchCalls = [];
  fetchResponses = responses.slice();
  globalThis.fetch = async (url, opts) => {
    fetchCalls.push({ url, method: opts?.method || 'GET', body: opts?.body });
    const next = fetchResponses.shift();
    if (!next) throw new Error(`mockFetch: no response queued for ${url}`);
    if (next instanceof Error) throw next;
    return {
      status: next.status,
      headers: { get: (n) => next.headers?.[n.toLowerCase()] ?? null },
      text: async () => next.body ?? '',
    };
  };
}

function restoreFetch() {
  globalThis.fetch = originalFetch;
  fetchCalls = [];
  fetchResponses = [];
}

// Build a canned /auth/challenge response that matches what the API would
// return for an account registered under the given KDF version.
async function buildChallengeResponse(kdfVersion) {
  const keys = await deriveAllKeys(EMAIL, PASSWORD, APP, kdfVersion);
  const wrappedDataKey = await wrapDataKeyEnvelope(
    keys.credentialEncryptionKey.gcmKey,
    keys.credentialEncryptionKey.kwKey,
    kdfVersion,
  );
  return {
    keys,
    body: JSON.stringify({
      nonce: 'a'.repeat(64),
      data_lookup_key: 'd'.repeat(64),
      wrapped_data_key: wrappedDataKey,
    }),
  };
}

function challengeCalls() {
  return fetchCalls.filter(c => c.url.endsWith('/auth/challenge'));
}

describe('TarnClient.login — KDF dispatch', () => {
  afterEach(restoreFetch);

  it('Argon2id account: succeeds on first /auth/challenge (no fallback)', async () => {
    const v2 = await buildChallengeResponse(KDF_V2_ARGON2ID);

    mockFetch([
      // First /auth/challenge — Argon2id-derived credential_lookup_key, 200.
      { status: 200, body: v2.body },
      // /auth/verify — issues JWT.
      { status: 200, body: JSON.stringify({ jwt: 'fake.jwt.token' }) },
    ]);

    const client = new TarnClient('https://api.tarn.dev', APP);
    const result = await client.login(EMAIL, PASSWORD);

    assert.equal(result.dataLookupKey, 'd'.repeat(64));
    assert.equal(challengeCalls().length, 1, 'should NOT call /auth/challenge twice when v2 succeeds');
    // Sanity: the credential_lookup_key sent matches the Argon2id-derived one.
    const body = JSON.parse(challengeCalls()[0].body);
    assert.equal(body.credential_lookup_key, v2.keys.credentialLookupKey);
  });

  it('PBKDF2-only account: v2 → 404 → fall back to v1 → succeeds', async () => {
    const v1 = await buildChallengeResponse(KDF_V1_PBKDF2);

    mockFetch([
      // First /auth/challenge with Argon2id key — 404.
      { status: 404, body: JSON.stringify({ error: 'Unknown credential_lookup_key' }) },
      // Second /auth/challenge with PBKDF2 key — 200.
      { status: 200, body: v1.body },
      // /auth/verify — issues JWT.
      { status: 200, body: JSON.stringify({ jwt: 'fake.jwt.token' }) },
    ]);

    const client = new TarnClient('https://api.tarn.dev', APP);
    const result = await client.login(EMAIL, PASSWORD);

    assert.equal(result.dataLookupKey, 'd'.repeat(64));
    const calls = challengeCalls();
    assert.equal(calls.length, 2, 'should call /auth/challenge twice (v2 then v1)');

    const v2Body = JSON.parse(calls[0].body);
    const v1Body = JSON.parse(calls[1].body);
    const v2Keys = await deriveAllKeys(EMAIL, PASSWORD, APP, KDF_V2_ARGON2ID);
    assert.equal(v2Body.credential_lookup_key, v2Keys.credentialLookupKey);
    assert.equal(v1Body.credential_lookup_key, v1.keys.credentialLookupKey);
    assert.notEqual(v2Body.credential_lookup_key, v1Body.credential_lookup_key);
  });

  it('non-existent account: both KDFs 404 → throws "Account not found"', async () => {
    mockFetch([
      { status: 404, body: JSON.stringify({ error: 'Unknown credential_lookup_key' }) },
      { status: 404, body: JSON.stringify({ error: 'Unknown credential_lookup_key' }) },
    ]);

    const client = new TarnClient('https://api.tarn.dev', APP);
    await assert.rejects(
      () => client.login(EMAIL, PASSWORD),
      /Account not found/,
    );
    assert.equal(challengeCalls().length, 2, 'should try both KDFs before giving up');
  });

  it('register uses Argon2id (KDF v2) and produces a v3 envelope with a single-entry DEK chain (issue #11)', async () => {
    mockFetch([
      // /auth/register — 201 success.
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      // /auth/challenge — fresh nonce.
      { status: 200, body: JSON.stringify({ nonce: 'b'.repeat(64) }) },
      // /auth/verify — issues JWT.
      { status: 200, body: JSON.stringify({ jwt: 'fake.jwt.token' }) },
    ]);

    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register(EMAIL, PASSWORD);

    const registerCall = fetchCalls.find(c => c.url.endsWith('/auth/register'));
    assert.ok(registerCall, 'register should hit /auth/register');
    const body = JSON.parse(registerCall.body);

    // wrapped_data_key should be a v3 JSON envelope (chain) for new accounts.
    assert.equal(body.wrapped_data_key[0], '{', 'register should send a JSON envelope');
    const env = JSON.parse(body.wrapped_data_key);
    assert.equal(env.v, 3);
    assert.equal(env.kdf, 'argon2id');
    assert.ok(Array.isArray(env.dek_chain));
    assert.equal(env.dek_chain.length, 1);
    assert.equal(env.dek_chain[0].gen, 1);
    assert.equal(typeof env.dek_chain[0].wrapped, 'string');

    // credential_lookup_key should match the Argon2id-derived one.
    const v2Keys = await deriveAllKeys(EMAIL, PASSWORD, APP, KDF_V2_ARGON2ID);
    assert.equal(body.credential_lookup_key, v2Keys.credentialLookupKey);
  });
});
