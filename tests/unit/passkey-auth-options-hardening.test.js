// Unit tests for tarn#59 — hardening of the public passkey
// authentication-options endpoint.
//
// FULL CLOSE (tarn#59): the per-credential enumeration is eliminated. The PRF
// salt is now an app-wide CONSTANT, so the discoverable (usernameless) flow
// returns ONE salt via `options.extensions.prf.eval.first` and NO
// per-credential `evalByCredential` map — and runs NO credential-table SELECT
// at all on the unauthenticated call.
//
// Covers the properties the fix must hold WITHOUT breaking the live
// discoverable sign-in flow Bookish depends on:
//
//   1. No full-table dump AND no full-table SELECT: the discoverable flow
//      (no credential_id) leaves `options.allowCredentials` empty (the
//      standard usernameless shape), returns no top-level `allow_credentials`,
//      and never issues a `SELECT ... FROM passkey_credentials`.
//   2. PRF still works via a SINGLE constant salt: the salt rides in
//      `options.extensions.prf.eval.first`; there is NO `evalByCredential`
//      map. The same constant is returned to every caller.
//   3. Rate-limited: the endpoint enforces a per-IP hourly cap and returns 429
//      once the cap is hit.
//
// Also checks the account-identified (credential_id supplied) flow still
// narrows `options.allowCredentials` to the named credential, using the same
// constant salt and still without a table read.
//
// Run: node --import tsx --test tests/unit/passkey-auth-options-hardening.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { handlePasskeyAuthOptions } from '../../api/src/routes/passkeys.js';

// ============ Mocks ============

// Minimal D1 mock. tarn#59 full close: handlePasskeyAuthOptions issues NO
// SELECT against passkey_credentials anymore — only the challenge INSERT. The
// mock records every prepared SQL string so a test can assert the absence of
// the full-table SELECT; any `all()` call is treated as a hard failure (the
// handler must not read the credential table on this public endpoint).
function mockDB() {
  const inserted = [];
  const preparedSql = [];
  return {
    _inserted: inserted,
    _preparedSql: preparedSql,
    prepare(sql) {
      preparedSql.push(sql);
      const params = [];
      return {
        bind(...args) { params.push(...args); return this; },
        async all() {
          throw new Error(
            `mockDB: handlePasskeyAuthOptions must not SELECT from the credential table (tarn#59); got: ${sql}`,
          );
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

async function readJson(response) {
  return await response.json();
}

// ============ Discoverable flow ============

describe('handlePasskeyAuthOptions — discoverable flow (tarn#59 full close)', () => {
  it('does NOT return a top-level allow_credentials array', async () => {
    const env = { DB: mockDB(), RATE_KV: mockKV() };
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
    const env = { DB: mockDB(), RATE_KV: mockKV() };
    const res = await handlePasskeyAuthOptions(mockRequest(), env, ctx, {});
    const json = await readJson(res);
    const allow = json.options.allowCredentials;
    // simplewebauthn returns [] (not undefined) when handed an empty array.
    assert.deepEqual(allow, [], 'allowCredentials must be empty for the discoverable flow');
  });

  it('returns a SINGLE constant salt via extensions.prf.eval.first and NO evalByCredential map', async () => {
    const env = { DB: mockDB(), RATE_KV: mockKV() };
    const res = await handlePasskeyAuthOptions(mockRequest(), env, ctx, {});
    const json = await readJson(res);
    const prf = json.options.extensions?.prf;
    assert.ok(prf, 'prf extension must be present');
    assert.ok(prf.eval, 'prf.eval must be present');
    assert.ok(prf.eval.first, 'prf.eval.first (the constant salt) must be present');
    assert.equal(
      'evalByCredential' in prf, false,
      'tarn#59 full close: there must be NO per-credential evalByCredential map',
    );
  });

  it('the same constant salt is returned to two independent callers', async () => {
    const a = await readJson(await handlePasskeyAuthOptions(
      mockRequest({ ip: '203.0.113.20' }), { DB: mockDB(), RATE_KV: mockKV() }, ctx, {},
    ));
    const b = await readJson(await handlePasskeyAuthOptions(
      mockRequest({ ip: '203.0.113.21' }), { DB: mockDB(), RATE_KV: mockKV() }, ctx, {},
    ));
    // simplewebauthn serializes the Uint8Array salt to a base64url string.
    assert.equal(
      JSON.stringify(a.options.extensions.prf.eval.first),
      JSON.stringify(b.options.extensions.prf.eval.first),
      'the PRF salt must be a fixed app-wide constant across calls',
    );
  });

  it('does NOT issue any SELECT against passkey_credentials (no enumeration)', async () => {
    const env = { DB: mockDB(), RATE_KV: mockKV() };
    await handlePasskeyAuthOptions(mockRequest(), env, ctx, {});
    const selects = env.DB._preparedSql.filter(s => /SELECT/i.test(s) && /passkey_credentials/i.test(s));
    assert.equal(selects.length, 0, 'the discoverable flow must not SELECT the credential table');
  });

  it('persists exactly one authenticate challenge row', async () => {
    const env = { DB: mockDB(), RATE_KV: mockKV() };
    await handlePasskeyAuthOptions(mockRequest(), env, ctx, {});
    assert.equal(env.DB._inserted.length, 1, 'one challenge row inserted');
    // INSERT params: (challenge, 'authenticate', issuedAt, expiresAt)
    assert.equal(env.DB._inserted[0][1], 'authenticate');
  });
});

// ============ Account-identified flow ============

describe('handlePasskeyAuthOptions — credential_id supplied (tarn#59 full close)', () => {
  it('narrows options.allowCredentials to the named credential, no table read', async () => {
    const env = { DB: mockDB(), RATE_KV: mockKV() };
    const res = await handlePasskeyAuthOptions(
      mockRequest({ body: { credential_id: 'credAAAA' } }), env, ctx, {},
    );
    const json = await readJson(res);
    assert.equal(json.options.allowCredentials.length, 1);
    assert.equal(json.options.allowCredentials[0].id, 'credAAAA');
    // Single constant salt, still no per-credential map.
    assert.ok(json.options.extensions.prf.eval.first, 'constant salt present');
    assert.equal('evalByCredential' in json.options.extensions.prf, false);
    // Still no top-level dump, and no credential-table SELECT.
    assert.equal('allow_credentials' in json, false);
    const selects = env.DB._preparedSql.filter(s => /SELECT/i.test(s) && /passkey_credentials/i.test(s));
    assert.equal(selects.length, 0, 'the account-identified flow must not SELECT the credential table');
  });
});

// ============ Rate limiting ============

describe('handlePasskeyAuthOptions — rate limiting (tarn#59)', () => {
  it('returns 429 once the per-IP hourly cap is exceeded', async () => {
    const env = { DB: mockDB(), RATE_KV: mockKV() };
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
    const env = { DB: mockDB(), RATE_KV: mockKV() };
    await handlePasskeyAuthOptions(mockRequest({ ip: '192.0.2.50' }), env, ctx, {});
    const keys = Array.from(env.RATE_KV._store.keys());
    assert.equal(keys.length, 1);
    assert.ok(keys[0].startsWith('passkey-authopts:'), `unexpected bucket key ${keys[0]}`);
    // IP must be hashed, not stored raw.
    assert.ok(!keys[0].includes('192.0.2.50'), 'raw IP must not appear in the bucket key');
  });

  it('two IPs get independent buckets', async () => {
    const env = { DB: mockDB(), RATE_KV: mockKV() };
    await handlePasskeyAuthOptions(mockRequest({ ip: '203.0.113.1' }), env, ctx, {});
    await handlePasskeyAuthOptions(mockRequest({ ip: '203.0.113.2' }), env, ctx, {});
    assert.equal(env.RATE_KV._store.size, 2, 'distinct IPs → distinct buckets');
  });
});

// ============ Origin gate (unchanged) ============

describe('handlePasskeyAuthOptions — origin gate', () => {
  it('rejects a disallowed origin with 400 before any DB work', async () => {
    const env = { DB: mockDB(), RATE_KV: mockKV() };
    const res = await handlePasskeyAuthOptions(
      mockRequest({ origin: 'https://evil.example' }), env, ctx, {},
    );
    assert.equal(res.status, 400);
    assert.equal(env.DB._inserted.length, 0, 'no challenge row on rejected origin');
  });
});
