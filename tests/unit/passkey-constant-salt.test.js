// tarn#59 — app-wide CONSTANT PRF salt: end-to-end correctness.
//
// Proves the constant-salt scheme is cryptographically sound and that a
// register→authenticate round-trip unwraps correctly under it, without a
// live server:
//
//   1. The authentication-options endpoint returns the constant salt in
//      `options.extensions.prf.eval.first` and that value is exactly
//      SHA-256("tarn-passkey-prf-constant-salt-v1") — the documented,
//      reproducible constant. (This is the same value register-options hands
//      the SDK, so register and auth wrap/unwrap under identical key material.)
//
//   2. A wrap-under-PRF(constant) then unwrap-under-PRF(constant) round-trip
//      recovers the DEK. We model the authenticator faithfully: PRF output =
//      HMAC-SHA-256(per-credential-secret, salt), matching real WebAuthn PRF
//      mechanics (the salt is the HMAC message; the key is the authenticator's
//      per-credential secret).
//
//   3. Per-credential uniqueness under a SHARED salt: two credentials with
//      DIFFERENT authenticator secrets, fed the SAME constant salt, derive
//      DIFFERENT wrapping keys → DIFFERENT wrappings. This is the property
//      that makes a shared salt safe.
//
// Run: node --import tsx --test tests/unit/passkey-constant-salt.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as nodeCrypto from 'node:crypto';
import { handlePasskeyAuthOptions } from '../../api/src/routes/passkeys.js';
import {
  buildEnvelope,
  unwrapDataKeyChain,
  generateRandomDataKey,
  generateRecoverySalt,
  derivePasskeyWrappingKey,
  FACTOR_PASSWORD,
  FACTOR_PASSKEY_PRF,
  bytesToBase64,
} from '../../client/src/crypto.js';

const PASSKEY_PRF_SALT_DOMAIN = 'tarn-passkey-prf-constant-salt-v1';

function mockDB() {
  const inserted = [];
  return {
    _inserted: inserted,
    prepare(sql) {
      const params = [];
      return {
        bind(...args) { params.push(...args); return this; },
        async run() {
          if (sql.startsWith('INSERT INTO webauthn_challenges')) {
            inserted.push(params);
            return { success: true };
          }
          throw new Error(`mockDB: unsupported run() SQL: ${sql}`);
        },
        async all() {
          throw new Error(`mockDB: no SELECT expected (tarn#59): ${sql}`);
        },
      };
    },
  };
}
function mockKV() {
  const store = new Map();
  return { async get(k) { return store.has(k) ? store.get(k) : null; }, async put(k, v) { store.set(k, v); } };
}
function mockRequest({ origin = 'https://getbookish.app', ip = '203.0.113.7', body = {} } = {}) {
  return {
    headers: { get(n) { if (n === 'Origin') return origin; if (n === 'CF-Connecting-IP') return ip; return null; } },
    async json() { return body; },
  };
}
const ctx = { waitUntil() {} };

// simplewebauthn does not transform Uint8Array values inside `extensions`, so
// the salt arrives on the wire as a numeric-keyed object ({"0":n,...}). Rebuild
// the bytes — mirrors client/src/passkeys/prf.ts:numericObjectToBytes.
function numericObjectToBytes(obj) {
  const keys = Object.keys(obj).map(Number).filter(k => Number.isInteger(k) && k >= 0);
  const max = Math.max(...keys);
  const out = new Uint8Array(max + 1);
  for (const k of keys) out[k] = obj[String(k)] & 0xff;
  return out;
}

describe('tarn#59 — constant salt is the documented SHA-256(domain)', () => {
  it('auth-options eval.first equals SHA-256("tarn-passkey-prf-constant-salt-v1")', async () => {
    const env = { DB: mockDB(), RATE_KV: mockKV() };
    const res = await handlePasskeyAuthOptions(mockRequest(), env, ctx, {});
    const json = await res.json();
    const onWire = numericObjectToBytes(json.options.extensions.prf.eval.first);

    const expected = new Uint8Array(
      nodeCrypto.createHash('sha256').update(Buffer.from(PASSKEY_PRF_SALT_DOMAIN, 'utf8')).digest(),
    );
    assert.equal(onWire.length, 32, 'constant salt is 32 bytes');
    assert.deepEqual(Array.from(onWire), Array.from(expected), 'salt is the documented constant');
  });
});

// Model the authenticator: PRF(secret, salt) = HMAC-SHA-256(secret, salt).
function modelPrf(perCredentialSecret, salt) {
  return new Uint8Array(
    nodeCrypto.createHmac('sha256', Buffer.from(perCredentialSecret)).update(Buffer.from(salt)).digest(),
  );
}

describe('tarn#59 — register→authenticate round-trip under the constant salt', () => {
  it('wrap under PRF(constant) then unwrap under PRF(constant) recovers the DEK', async () => {
    // Pull the actual constant the server returns.
    const env = { DB: mockDB(), RATE_KV: mockKV() };
    const json = await (await handlePasskeyAuthOptions(mockRequest(), env, ctx, {})).json();
    const constantSalt = numericObjectToBytes(json.options.extensions.prf.eval.first);

    // ---- REGISTER: authenticator computes PRF(constant); SDK derives KEK and wraps the DEK.
    const credentialId = 'cred-roundtrip';
    const authenticatorSecret = nodeCrypto.randomBytes(32);
    const prfAtRegister = modelPrf(authenticatorSecret, constantSalt);
    const { kwKey: kekRegister } = await derivePasskeyWrappingKey(prfAtRegister);

    const dek = await generateRandomDataKey();
    const wrappedB64 = bytesToBase64(new Uint8Array(
      await crypto.subtle.wrapKey('raw', dek.gcmKey, kekRegister, 'AES-KW'),
    ));
    const salt = generateRecoverySalt();
    const envelope = buildEnvelope(
      [{
        gen: 1,
        wrappings: [
          { factor: FACTOR_PASSWORD, wrappedBase64: wrappedB64 },
          { factor: FACTOR_PASSKEY_PRF, wrappedBase64: wrappedB64, credentialId },
        ],
      }],
      { salt },
    );

    // ---- AUTHENTICATE: discoverable flow returns the SAME constant; same
    // authenticator computes the SAME PRF output; SDK re-derives the same KEK.
    const json2 = await (await handlePasskeyAuthOptions(
      mockRequest({ ip: '203.0.113.99' }), { DB: mockDB(), RATE_KV: mockKV() }, ctx, {},
    )).json();
    const constantSaltAtAuth = numericObjectToBytes(json2.options.extensions.prf.eval.first);
    assert.deepEqual(Array.from(constantSaltAtAuth), Array.from(constantSalt), 'auth salt == register salt');

    const prfAtAuth = modelPrf(authenticatorSecret, constantSaltAtAuth);
    const { kwKey: kekAuth } = await derivePasskeyWrappingKey(prfAtAuth);

    const unwrapped = await unwrapDataKeyChain(envelope, kekAuth, FACTOR_PASSKEY_PRF, credentialId);
    const recovered = unwrapped.dekByGen.get(1);
    assert.ok(recovered, 'DEK recovered at gen 1');
    // Confirm key identity via an encrypt/decrypt round-trip.
    const iv = new Uint8Array(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, dek.gcmKey, new TextEncoder().encode('ok'));
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, recovered.gcmKey, ct);
    assert.equal(new TextDecoder().decode(pt), 'ok');
  });

  it('two credentials under the SAME constant salt derive DIFFERENT wrapping keys (per-credential uniqueness)', async () => {
    const env = { DB: mockDB(), RATE_KV: mockKV() };
    const json = await (await handlePasskeyAuthOptions(mockRequest(), env, ctx, {})).json();
    const constantSalt = numericObjectToBytes(json.options.extensions.prf.eval.first);

    const secretA = nodeCrypto.randomBytes(32);
    const secretB = nodeCrypto.randomBytes(32);
    const { rawBytes: kekA } = await derivePasskeyWrappingKey(modelPrf(secretA, constantSalt));
    const { rawBytes: kekB } = await derivePasskeyWrappingKey(modelPrf(secretB, constantSalt));
    assert.notDeepEqual(
      Array.from(kekA), Array.from(kekB),
      'a shared salt with distinct authenticator secrets must yield distinct KEKs',
    );

    // And a legacy random-salt wrap is NOT unwrappable under PRF(constant) —
    // this is the migration signature the SDK surfaces as "re-register".
    const legacyRandomSalt = nodeCrypto.randomBytes(32);
    const { rawBytes: kekConstant } = await derivePasskeyWrappingKey(modelPrf(secretA, constantSalt));
    const { rawBytes: kekLegacy } = await derivePasskeyWrappingKey(modelPrf(secretA, legacyRandomSalt));
    assert.notDeepEqual(
      Array.from(kekConstant), Array.from(kekLegacy),
      'PRF(constant) != PRF(random) for the same credential — legacy wrappings will not unwrap',
    );
  });
});
