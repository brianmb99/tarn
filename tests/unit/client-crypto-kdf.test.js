// Unit tests for client/src/crypto.js — master_key derivation (Argon2id) and
// the deriveAllKeys convenience.
//
// Note: the legacy KDF (PBKDF2) and legacy envelope shapes (v1 bare-base64,
// v2 single-key, v3 single-factor chain) were removed in the single-envelope
// cleanup. The remaining envelope shape (v1 multi-factor) is exercised by
// tests/unit/client-crypto-cek.test.js.
//
// Run: node --test tests/unit/client-crypto-kdf.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveMasterKey,
  deriveAllKeys,
  parseWrappedDataKey,
} from '../../client/src/crypto.js';

const TEST_EMAIL = 'argon-test@example.com';
const TEST_PASSWORD = 'correct-horse-battery-staple-2026';
const TEST_APP = 'bookish';

// ============ deriveMasterKey ============

describe('deriveMasterKey', () => {
  it('produces a 32-byte key via Argon2id', async () => {
    const key = await deriveMasterKey(TEST_EMAIL, TEST_PASSWORD);
    assert.ok(key instanceof Uint8Array);
    assert.equal(key.length, 32);
  });

  it('is deterministic — same inputs produce the same key', async () => {
    const a = await deriveMasterKey(TEST_EMAIL, TEST_PASSWORD);
    const b = await deriveMasterKey(TEST_EMAIL, TEST_PASSWORD);
    assert.deepEqual(Array.from(a), Array.from(b));
  });

  it('different passwords produce different keys', async () => {
    const a = await deriveMasterKey(TEST_EMAIL, 'pwA');
    const b = await deriveMasterKey(TEST_EMAIL, 'pwB');
    assert.notDeepEqual(Array.from(a), Array.from(b));
  });

  it('different emails produce different keys', async () => {
    const a = await deriveMasterKey('a@example.com', TEST_PASSWORD);
    const b = await deriveMasterKey('b@example.com', TEST_PASSWORD);
    assert.notDeepEqual(Array.from(a), Array.from(b));
  });

  it('rejects missing email/password', async () => {
    await assert.rejects(() => deriveMasterKey('', TEST_PASSWORD), /required/);
    await assert.rejects(() => deriveMasterKey(TEST_EMAIL, ''), /required/);
  });
});

// ============ deriveAllKeys ============

describe('deriveAllKeys', () => {
  it('returns all expected fields', async () => {
    const k = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP);
    assert.ok(k.masterKey instanceof Uint8Array);
    assert.ok(typeof k.credentialLookupKey === 'string');
    assert.match(k.credentialLookupKey, /^[a-f0-9]{64}$/);
    assert.ok(k.credentialEncryptionKey.gcmKey instanceof CryptoKey);
    assert.ok(k.credentialEncryptionKey.kwKey instanceof CryptoKey);
    assert.ok(k.signingKeyPair.privateKey instanceof CryptoKey);
    assert.ok(k.signingKeyPair.publicKey instanceof CryptoKey);
    assert.ok(k.sharingKeyPair.privateKey instanceof Uint8Array);
    assert.ok(k.sharingKeyPair.publicKey instanceof Uint8Array);
  });

  it('different appIds produce different credential_lookup_keys (per-app isolation)', async () => {
    const a = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, 'app-a');
    const b = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, 'app-b');
    assert.notEqual(a.credentialLookupKey, b.credentialLookupKey);
  });

  it('rejects missing appId', async () => {
    await assert.rejects(
      () => deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, ''),
      /appId is required/,
    );
  });
});

// ============ parseWrappedDataKey input validation ============

describe('parseWrappedDataKey input validation', () => {
  it('rejects empty/non-string input', () => {
    assert.throws(() => parseWrappedDataKey(''), /non-empty/);
    assert.throws(() => parseWrappedDataKey(null), /non-empty/);
  });

  it('rejects non-JSON input (legacy v1 bare-base64 is no longer accepted)', () => {
    assert.throws(
      () => parseWrappedDataKey('aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGRsbA=='),
      /must be a JSON envelope/,
    );
  });

  it('rejects malformed JSON', () => {
    assert.throws(() => parseWrappedDataKey('{not json'), /not valid JSON/);
  });

  it('rejects pre-cleanup envelope versions (2/3/4)', () => {
    for (const v of [2, 3, 4]) {
      assert.throws(
        () => parseWrappedDataKey(JSON.stringify({ v, kdf: 'argon2id' })),
        /unsupported envelope/,
      );
    }
  });

  it('rejects unknown KDFs', () => {
    assert.throws(
      () => parseWrappedDataKey(JSON.stringify({ v: 1, kdf: 'pbkdf2' })),
      /unsupported envelope/,
    );
  });
});
