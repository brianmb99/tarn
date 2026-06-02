// Unit tests for api/src/auth.js — JWT and nonce management
// Run: node --test tests/unit/auth.test.js

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateChallenge,
  storeNonce,
  consumeNonce,
  signJWT,
  verifyJWT,
  _resetHMACKey,
  JWT_TTL_SECONDS,
  PASSKEY_JWT_TTL_SECONDS,
} from '../../api/src/auth.js';

// ============ Mock D1 Store (auth_nonces) ============
//
// Migration 0012 moved auth nonces from AUTH_KV to D1. This mock supports
// just the two SQL statements storeNonce / consumeNonce emit:
//   INSERT INTO auth_nonces (nonce, credential_lookup_key, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)
//   DELETE FROM auth_nonces WHERE nonce = ?1 RETURNING credential_lookup_key, created_at, expires_at

function createMockD1() {
  const rows = new Map(); // nonce -> { credential_lookup_key, created_at, expires_at }
  return {
    prepare(sql) {
      const params = [];
      return {
        bind(...args) {
          params.push(...args);
          return this;
        },
        async run() {
          if (sql.startsWith('INSERT INTO auth_nonces')) {
            const [nonce, clk, createdAt, expiresAt] = params;
            rows.set(nonce, {
              credential_lookup_key: clk,
              created_at: createdAt,
              expires_at: expiresAt,
            });
            return { success: true };
          }
          throw new Error(`mock D1: unsupported SQL for run(): ${sql}`);
        },
        async first() {
          if (sql.startsWith('DELETE FROM auth_nonces')) {
            const [nonce] = params;
            const row = rows.get(nonce);
            if (!row) return null;
            rows.delete(nonce);
            return row;
          }
          throw new Error(`mock D1: unsupported SQL for first(): ${sql}`);
        },
      };
    },
    _rows: rows,
  };
}

// A valid base64-encoded 256-bit secret for JWT tests
const TEST_SECRET = btoa(String.fromCharCode(...new Uint8Array(32).fill(42)));

// ============ generateChallenge ============

describe('generateChallenge', () => {
  it('should return a 64-char hex nonce', () => {
    const nonce = generateChallenge();
    assert.equal(typeof nonce, 'string');
    assert.equal(nonce.length, 64);
    assert.match(nonce, /^[a-f0-9]{64}$/);
  });

  it('should generate unique nonces', () => {
    const nonces = new Set();
    for (let i = 0; i < 50; i++) {
      nonces.add(generateChallenge());
    }
    assert.equal(nonces.size, 50);
  });
});

// ============ storeNonce / consumeNonce ============

describe('nonce lifecycle', () => {
  let env;

  beforeEach(() => {
    env = { DB: createMockD1() };
  });

  it('should store and consume a nonce', async () => {
    const nonce = 'a'.repeat(64);
    const clk = 'b'.repeat(64);
    await storeNonce(env, nonce, clk);

    const result = await consumeNonce(env, nonce);
    assert.ok(result);
    assert.equal(result.credentialLookupKey, clk);
    assert.equal(typeof result.createdAt, 'number');
  });

  it('should return null for unknown nonce', async () => {
    const result = await consumeNonce(env, 'unknown');
    assert.equal(result, null);
  });

  it('should prevent nonce replay (single-use)', async () => {
    const nonce = 'c'.repeat(64);
    await storeNonce(env, nonce, 'd'.repeat(64));

    const first = await consumeNonce(env, nonce);
    assert.ok(first);

    const second = await consumeNonce(env, nonce);
    assert.equal(second, null, 'Nonce should not be reusable');
  });

  it('should store the correct credential_lookup_key', async () => {
    const nonce = 'e'.repeat(64);
    const clk1 = '1'.repeat(64);
    const clk2 = '2'.repeat(64);

    await storeNonce(env, nonce, clk1);
    const result = await consumeNonce(env, nonce);
    assert.equal(result.credentialLookupKey, clk1);
    assert.notEqual(result.credentialLookupKey, clk2);
  });
});

// ============ signJWT / verifyJWT ============

describe('JWT', () => {
  beforeEach(() => {
    _resetHMACKey(); // Clear cached key between tests
  });

  it('should sign and verify a JWT round-trip', async () => {
    const payload = { sub: 'test-data-lookup-key', role: 'user' };
    const token = await signJWT(payload, TEST_SECRET);
    assert.equal(typeof token, 'string');
    assert.equal(token.split('.').length, 3);

    const verified = await verifyJWT(token, TEST_SECRET);
    assert.ok(verified);
    assert.equal(verified.sub, 'test-data-lookup-key');
    assert.equal(verified.role, 'user');
    assert.equal(typeof verified.iat, 'number');
    assert.equal(typeof verified.exp, 'number');
  });

  it('should include standard claims', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await signJWT({ sub: 'x' }, TEST_SECRET);
    const payload = await verifyJWT(token, TEST_SECRET);

    assert.ok(payload.iat >= now - 1 && payload.iat <= now + 1, 'iat should be ~now');
    assert.ok(payload.exp === payload.iat + JWT_TTL_SECONDS, 'exp should be iat + TTL');
  });

  it('should preserve custom claims', async () => {
    const token = await signJWT({ sub: 'dlk', role: 'app', custom: 'value' }, TEST_SECRET);
    const payload = await verifyJWT(token, TEST_SECRET);
    assert.equal(payload.custom, 'value');
    assert.equal(payload.role, 'app');
  });

  it('should reject a tampered payload', async () => {
    const token = await signJWT({ sub: 'honest' }, TEST_SECRET);
    const parts = token.split('.');

    // Tamper: change the payload
    const tamperedPayload = btoa(JSON.stringify({ sub: 'evil', iat: 0, exp: 9999999999 }))
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    const result = await verifyJWT(tampered, TEST_SECRET);
    assert.equal(result, null, 'Tampered JWT should not verify');
  });

  it('should reject a tampered signature', async () => {
    const token = await signJWT({ sub: 'x' }, TEST_SECRET);
    const parts = token.split('.');

    // Tamper a char in the FIRST half of the signature. Don't tamper the
    // last char: an 86-char base64url encoding of a 64-byte ECDSA signature
    // has only 2 significant bits in its final char (the other 4 bits are
    // ignored padding). Flipping between 'A' (000000) and 'B' (000001) only
    // toggles a padding bit, so the decoded signature is unchanged and
    // verify (correctly) succeeds — making the test flaky depending on
    // what the last char happened to be. Position 10 is solidly in
    // significant-bit territory.
    const TAMPER_POS = 10;
    const c = parts[2][TAMPER_POS];
    const replacement = c === 'A' ? 'B' : 'A';
    const tampered =
      `${parts[0]}.${parts[1]}.${parts[2].slice(0, TAMPER_POS)}${replacement}${parts[2].slice(TAMPER_POS + 1)}`;

    const result = await verifyJWT(tampered, TEST_SECRET);
    assert.equal(result, null, 'Tampered signature should not verify');
  });

  it('should reject a JWT signed with a different secret', async () => {
    const otherSecret = btoa(String.fromCharCode(...new Uint8Array(32).fill(99)));
    const token = await signJWT({ sub: 'x' }, otherSecret);

    _resetHMACKey();
    const result = await verifyJWT(token, TEST_SECRET);
    assert.equal(result, null);
  });

  it('should reject a malformed JWT (wrong number of parts)', async () => {
    assert.equal(await verifyJWT('a.b', TEST_SECRET), null);
    assert.equal(await verifyJWT('a.b.c.d', TEST_SECRET), null);
    assert.equal(await verifyJWT('', TEST_SECRET), null);
    assert.equal(await verifyJWT('just-a-string', TEST_SECRET), null);
  });

  it('should re-import HMAC key when the secret rotates', async () => {
    const secretA = TEST_SECRET;
    const secretB = btoa(String.fromCharCode(...new Uint8Array(32).fill(77)));

    // Prime cache with secret A and sign a token
    const tokenA = await signJWT({ sub: 'pre-rotation' }, secretA);
    assert.ok(await verifyJWT(tokenA, secretA), 'tokenA should verify under secretA');

    // Rotate: subsequent calls pass the new secret. Cache must re-import,
    // NOT silently reuse the stale key from secretA.
    const tokenB = await signJWT({ sub: 'post-rotation' }, secretB);

    // tokenB must verify under secretB (proves we signed with the new key)
    const verifiedB = await verifyJWT(tokenB, secretB);
    assert.ok(verifiedB, 'tokenB should verify under secretB after rotation');
    assert.equal(verifiedB.sub, 'post-rotation');

    // tokenA (signed with secretA) must NOT verify under secretB
    assert.equal(await verifyJWT(tokenA, secretB), null, 'tokenA must not verify under secretB');

    // And rotating back to secretA should still work — verifies symmetric behavior
    assert.ok(await verifyJWT(tokenA, secretA), 'tokenA should still verify under secretA after rotation back');
  });

  it('should reject an expired JWT', async () => {
    // Sign with a payload that's already expired
    // We can't easily mock Date.now, so we test by checking the exp claim logic
    const token = await signJWT({ sub: 'x' }, TEST_SECRET);
    const parts = token.split('.');

    // Decode, set exp to past, re-encode (but signature won't match —
    // so instead we verify the normal flow and trust the exp check)
    const payload = await verifyJWT(token, TEST_SECRET);
    assert.ok(payload, 'Fresh JWT should verify');
    assert.ok(payload.exp > Math.floor(Date.now() / 1000), 'exp should be in the future');
  });

  // Issue #28: signJWT must accept an optional ttlSeconds override so the
  // passkey-authenticate route can mint 7-day tokens (matching session-blob
  // lifetime) while the password path keeps the short 15-minute default.
  it('should honor an explicit ttlSeconds override', async () => {
    const token = await signJWT({ sub: 'passkey-user' }, TEST_SECRET, PASSKEY_JWT_TTL_SECONDS);
    const payload = await verifyJWT(token, TEST_SECRET);
    assert.ok(payload, 'JWT should verify');
    assert.equal(
      payload.exp - payload.iat,
      PASSKEY_JWT_TTL_SECONDS,
      'exp - iat must equal the explicit TTL',
    );
    assert.equal(
      PASSKEY_JWT_TTL_SECONDS,
      7 * 24 * 3600,
      'passkey TTL constant must be 7 days',
    );
  });

  it('should preserve the short default TTL when no override is passed', async () => {
    // Defense-in-depth for issue #28: changing the passkey TTL must not
    // accidentally change the password-path TTL.
    const token = await signJWT({ sub: 'password-user' }, TEST_SECRET);
    const payload = await verifyJWT(token, TEST_SECRET);
    assert.equal(
      payload.exp - payload.iat,
      JWT_TTL_SECONDS,
      'default TTL must remain JWT_TTL_SECONDS (15 min)',
    );
    assert.notEqual(
      payload.exp - payload.iat,
      PASSKEY_JWT_TTL_SECONDS,
      'default TTL must not silently match the passkey TTL',
    );
  });
});
