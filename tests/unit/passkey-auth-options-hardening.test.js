// Unit tests for tarn#59 — hardening of the public passkey
// authentication-options endpoint.
//
// Covers the three properties the fix must hold WITHOUT breaking the live
// discoverable sign-in flow Bookish depends on:
//
//   1. No full-table dump: the discoverable flow (no credential_id) no longer
//      returns a top-level `allow_credentials` array, and leaves
//      `options.allowCredentials` empty (the standard usernameless shape).
//   2. PRF still works: the per-credential salts the client needs are still
//      carried in `options.extensions.prf.evalByCredential` (load-bearing for
//      Bookish — verified against the live bundle, which reads the salt from
//      there and never from `allow_credentials`).
//   3. Rate-limited: the endpoint enforces a per-IP hourly cap and returns 429
//      once the cap is hit.
//
// Also checks the account-identified (credential_id supplied) flow still
// narrows `options.allowCredentials` to the named credential.
//
// Run: node --import tsx --test tests/unit/passkey-auth-options-hardening.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { handlePasskeyAuthOptions } from '../../api/src/routes/passkeys.js';

// ============ Mocks ============

// Minimal D1 mock: supports the two SELECTs handlePasskeyAuthOptions issues
// (all-credentials for the discoverable flow, single-credential for the
// account-identified flow) plus the challenge INSERT. Salts are valid
// base64url so base64UrlToBytes() in the handler succeeds.
function mockDB(rows) {
  const inserted = [];
  return {
    _inserted: inserted,
    prepare(sql) {
      const params = [];
      return {
        bind(...args) { params.push(...args); return this; },
        async all() {
          if (sql.includes('WHERE credential_id = ?1')) {
            const id = params[0];
            return { results: rows.filter(r => r.credential_id === id) };
          }
          if (sql.includes('FROM passkey_credentials')) {
            return { results: rows.slice() };
          }
          throw new Error(`mockDB: unsupported all() SQL: ${sql}`);
        },
        async run() {
          if (sql.startsWith('INSERT INTO webauthn_challenges')) {
            inserted.push(params);
            return { success: true };
          }
          throw new Error(`mockDB: unsupported run() SQL: ${sql}`);
        },
      };
    },
  };
}

function mockKV() {
  const store = new Map();
  return {
    _store: store,
    async get(key) { return store.has(key) ? store.get(key) : null; },
    async put(key, value) { store.set(key, value); },
  };
}

function mockRequest({ origin = 'https://getbookish.app', ip = '203.0.113.7', body = {} } = {}) {
  return {
    headers: {
      get(name) {
        if (name === 'Origin') return origin;
        if (name === 'CF-Connecting-IP') return ip;
        return null;
      },
    },
    async json() { return body; },
  };
}

const ctx = { waitUntil() {} };

// Two valid base64url 32-byte salts.
const SALT_A = 'A'.repeat(43); // 43 base64url chars ≈ 32 bytes
const SALT_B = 'B'.repeat(43);

function credRows() {
  return [
    { credential_id: 'credAAAA', prf_salt: SALT_A },
    { credential_id: 'credBBBB', prf_salt: SALT_B },
  ];
}

async function readJson(response) {
  return await response.json();
}

// ============ Discoverable flow ============

describe('handlePasskeyAuthOptions — discoverable flow (tarn#59)', () => {
  it('does NOT return a top-level allow_credentials array', async () => {
    const env = { DB: mockDB(credRows()), RATE_KV: mockKV() };
    const res = await handlePasskeyAuthOptions(mockRequest(), env, ctx, {});
    assert.equal(res.status, 200);
    const json = await readJson(res);
    assert.equal(
      'allow_credentials' in json, false,
      'discoverable response must not echo a top-level allow_credentials dump',
    );
    assert.ok(json.options, 'options present');
    assert.equal(json.rp_id, 'getbookish.app');
  });

  it('leaves options.allowCredentials empty (standard discoverable shape)', async () => {
    const env = { DB: mockDB(credRows()), RATE_KV: mockKV() };
    const res = await handlePasskeyAuthOptions(mockRequest(), env, ctx, {});
    const json = await readJson(res);
    const allow = json.options.allowCredentials;
    // simplewebauthn returns [] (not undefined) when handed an empty array.
    assert.deepEqual(allow, [], 'allowCredentials must be empty for the discoverable flow');
  });

  it('STILL carries every per-credential salt in extensions.prf.evalByCredential', async () => {
    // This is the load-bearing residual: Bookish reads the salt from here.
    const env = { DB: mockDB(credRows()), RATE_KV: mockKV() };
    const res = await handlePasskeyAuthOptions(mockRequest(), env, ctx, {});
    const json = await readJson(res);
    const ebc = json.options.extensions?.prf?.evalByCredential;
    assert.ok(ebc, 'evalByCredential must be present');
    assert.deepEqual(
      Object.keys(ebc).sort(), ['credAAAA', 'credBBBB'],
      'evalByCredential must enumerate the RP credentials so the client can pick the right salt',
    );
    assert.ok(ebc.credAAAA.first, 'each entry carries a PRF salt under .first');
  });

  it('persists exactly one authenticate challenge row', async () => {
    const env = { DB: mockDB(credRows()), RATE_KV: mockKV() };
    await handlePasskeyAuthOptions(mockRequest(), env, ctx, {});
    assert.equal(env.DB._inserted.length, 1, 'one challenge row inserted');
    // INSERT params: (challenge, 'authenticate', issuedAt, expiresAt)
    assert.equal(env.DB._inserted[0][1], 'authenticate');
  });
});

// ============ Account-identified flow ============

describe('handlePasskeyAuthOptions — credential_id supplied', () => {
  it('narrows options.allowCredentials to the named credential', async () => {
    const env = { DB: mockDB(credRows()), RATE_KV: mockKV() };
    const res = await handlePasskeyAuthOptions(
      mockRequest({ body: { credential_id: 'credAAAA' } }), env, ctx, {},
    );
    const json = await readJson(res);
    assert.equal(json.options.allowCredentials.length, 1);
    assert.equal(json.options.allowCredentials[0].id, 'credAAAA');
    // And only that credential's salt is in the PRF map.
    assert.deepEqual(Object.keys(json.options.extensions.prf.evalByCredential), ['credAAAA']);
    // Still no top-level dump.
    assert.equal('allow_credentials' in json, false);
  });
});

// ============ Rate limiting ============

describe('handlePasskeyAuthOptions — rate limiting (tarn#59)', () => {
  it('returns 429 once the per-IP hourly cap is exceeded', async () => {
    const env = { DB: mockDB(credRows()), RATE_KV: mockKV() };
    const req = () => mockRequest({ ip: '198.51.100.9' });

    // The cap is 60/hr. Drive 60 allowed calls, then assert the 61st is 429.
    let lastStatus = 0;
    for (let i = 0; i < 60; i++) {
      const res = await handlePasskeyAuthOptions(req(), env, ctx, {});
      lastStatus = res.status;
      assert.equal(lastStatus, 200, `call ${i + 1} should be allowed`);
    }
    const blocked = await handlePasskeyAuthOptions(req(), env, ctx, {});
    assert.equal(blocked.status, 429, 'call past the cap must be rate-limited');
    const body = await readJson(blocked);
    assert.match(body.error || '', /rate limit/i);
  });

  it('buckets per-IP under a passkey-authopts:* key (isolated from other limiters)', async () => {
    const env = { DB: mockDB(credRows()), RATE_KV: mockKV() };
    await handlePasskeyAuthOptions(mockRequest({ ip: '192.0.2.50' }), env, ctx, {});
    const keys = Array.from(env.RATE_KV._store.keys());
    assert.equal(keys.length, 1);
    assert.ok(keys[0].startsWith('passkey-authopts:'), `unexpected bucket key ${keys[0]}`);
    // IP must be hashed, not stored raw.
    assert.ok(!keys[0].includes('192.0.2.50'), 'raw IP must not appear in the bucket key');
  });

  it('two IPs get independent buckets', async () => {
    const env = { DB: mockDB(credRows()), RATE_KV: mockKV() };
    await handlePasskeyAuthOptions(mockRequest({ ip: '203.0.113.1' }), env, ctx, {});
    await handlePasskeyAuthOptions(mockRequest({ ip: '203.0.113.2' }), env, ctx, {});
    assert.equal(env.RATE_KV._store.size, 2, 'distinct IPs → distinct buckets');
  });
});

// ============ Origin gate (unchanged) ============

describe('handlePasskeyAuthOptions — origin gate', () => {
  it('rejects a disallowed origin with 400 before any DB work', async () => {
    const env = { DB: mockDB(credRows()), RATE_KV: mockKV() };
    const res = await handlePasskeyAuthOptions(
      mockRequest({ origin: 'https://evil.example' }), env, ctx, {},
    );
    assert.equal(res.status, 400);
    assert.equal(env.DB._inserted.length, 0, 'no challenge row on rejected origin');
  });
});
