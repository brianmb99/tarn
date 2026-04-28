// Unit tests for client/src/crypto.js — KDF dispatch, master_key derivation,
// and the wrapped_data_key envelope (issue #9).
// Run: node --test tests/unit/client-crypto-kdf.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveMasterKey,
  deriveAllKeys,
  wrapDataKey,
  wrapDataKeyEnvelope,
  unwrapDataKey,
  unwrapDataKeyEnvelope,
  parseWrappedDataKey,
  KDF_V1_PBKDF2,
  KDF_V2_ARGON2ID,
  KDF_DEFAULT,
} from '../../client/src/crypto.js';

const TEST_EMAIL = 'argon-test@example.com';
const TEST_PASSWORD = 'correct-horse-battery-staple-2026';
const TEST_APP = 'bookish';

// ============ deriveMasterKey ============

describe('deriveMasterKey', () => {
  it('defaults to KDF_V2_ARGON2ID', () => {
    assert.equal(KDF_DEFAULT, KDF_V2_ARGON2ID);
  });

  it('produces a 32-byte key with PBKDF2 (v1)', async () => {
    const key = await deriveMasterKey(TEST_EMAIL, TEST_PASSWORD, KDF_V1_PBKDF2);
    assert.ok(key instanceof Uint8Array);
    assert.equal(key.length, 32);
  });

  it('produces a 32-byte key with Argon2id (v2)', async () => {
    const key = await deriveMasterKey(TEST_EMAIL, TEST_PASSWORD, KDF_V2_ARGON2ID);
    assert.ok(key instanceof Uint8Array);
    assert.equal(key.length, 32);
  });

  it('PBKDF2 and Argon2id produce DIFFERENT master keys for the same email+password', async () => {
    const v1 = await deriveMasterKey(TEST_EMAIL, TEST_PASSWORD, KDF_V1_PBKDF2);
    const v2 = await deriveMasterKey(TEST_EMAIL, TEST_PASSWORD, KDF_V2_ARGON2ID);
    assert.notDeepEqual(Array.from(v1), Array.from(v2));
  });

  it('is deterministic — same inputs produce the same key (Argon2id)', async () => {
    const a = await deriveMasterKey(TEST_EMAIL, TEST_PASSWORD, KDF_V2_ARGON2ID);
    const b = await deriveMasterKey(TEST_EMAIL, TEST_PASSWORD, KDF_V2_ARGON2ID);
    assert.deepEqual(Array.from(a), Array.from(b));
  });

  it('is deterministic — same inputs produce the same key (PBKDF2)', async () => {
    const a = await deriveMasterKey(TEST_EMAIL, TEST_PASSWORD, KDF_V1_PBKDF2);
    const b = await deriveMasterKey(TEST_EMAIL, TEST_PASSWORD, KDF_V1_PBKDF2);
    assert.deepEqual(Array.from(a), Array.from(b));
  });

  it('rejects unknown KDF versions', async () => {
    await assert.rejects(
      () => deriveMasterKey(TEST_EMAIL, TEST_PASSWORD, 99),
      /Unknown KDF version/,
    );
  });

  it('rejects missing email/password', async () => {
    await assert.rejects(() => deriveMasterKey('', TEST_PASSWORD), /required/);
    await assert.rejects(() => deriveMasterKey(TEST_EMAIL, ''), /required/);
  });
});

// ============ deriveAllKeys ============

describe('deriveAllKeys', () => {
  it('returns the kdfVersion that was used', async () => {
    const v1 = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V1_PBKDF2);
    const v2 = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V2_ARGON2ID);
    assert.equal(v1.kdfVersion, KDF_V1_PBKDF2);
    assert.equal(v2.kdfVersion, KDF_V2_ARGON2ID);
  });

  it('produces DIFFERENT credential_lookup_keys under different KDFs', async () => {
    const v1 = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V1_PBKDF2);
    const v2 = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V2_ARGON2ID);
    assert.notEqual(v1.credentialLookupKey, v2.credentialLookupKey);
  });

  it('defaults to Argon2id when kdfVersion omitted', async () => {
    const omitted = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP);
    const v2 = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V2_ARGON2ID);
    assert.equal(omitted.credentialLookupKey, v2.credentialLookupKey);
    assert.equal(omitted.kdfVersion, KDF_V2_ARGON2ID);
  });
});

// ============ wrapped_data_key envelope ============

describe('wrapped_data_key envelope', () => {
  it('v1 produces a bare base64 string (legacy compatible)', async () => {
    const k = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V1_PBKDF2);
    const wire = await wrapDataKeyEnvelope(
      k.credentialEncryptionKey.gcmKey,
      k.credentialEncryptionKey.kwKey,
      KDF_V1_PBKDF2,
    );
    assert.equal(typeof wire, 'string');
    assert.notEqual(wire[0], '{');
    // 40 bytes (32 key + 8 AES-KW overhead) base64-encoded ≈ 56 chars.
    assert.match(wire, /^[A-Za-z0-9+/=]+$/);
  });

  it('v2 produces a JSON envelope with KDF metadata', async () => {
    const k = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V2_ARGON2ID);
    const wire = await wrapDataKeyEnvelope(
      k.credentialEncryptionKey.gcmKey,
      k.credentialEncryptionKey.kwKey,
      KDF_V2_ARGON2ID,
    );
    assert.equal(wire[0], '{');
    const parsed = JSON.parse(wire);
    assert.equal(parsed.v, 2);
    assert.equal(parsed.kdf, 'argon2id');
    assert.equal(parsed.kdf_params.m_kib, 65536);
    assert.equal(parsed.kdf_params.t, 3);
    assert.equal(parsed.kdf_params.p, 1);
    assert.equal(typeof parsed.wrapped, 'string');
  });

  it('v1 wire value is byte-identical to wrapDataKey() output (back-compat)', async () => {
    const k = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V1_PBKDF2);
    const bare = await wrapDataKey(k.credentialEncryptionKey.gcmKey, k.credentialEncryptionKey.kwKey);
    const envelope = await wrapDataKeyEnvelope(
      k.credentialEncryptionKey.gcmKey,
      k.credentialEncryptionKey.kwKey,
      KDF_V1_PBKDF2,
    );
    assert.equal(envelope, bare);
  });

  it('parseWrappedDataKey detects legacy bare-base64 as v1', () => {
    const parsed = parseWrappedDataKey('aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGRsbA==');
    assert.equal(parsed.kdfVersion, KDF_V1_PBKDF2);
    assert.equal(parsed.kdfParams, null);
  });

  it('parseWrappedDataKey detects JSON envelope as v2', () => {
    const wire = JSON.stringify({
      v: 2,
      kdf: 'argon2id',
      kdf_params: { m_kib: 65536, t: 3, p: 1 },
      wrapped: 'AAAA',
    });
    const parsed = parseWrappedDataKey(wire);
    assert.equal(parsed.kdfVersion, KDF_V2_ARGON2ID);
    assert.equal(parsed.wrappedBase64, 'AAAA');
    assert.deepEqual(parsed.kdfParams, { m_kib: 65536, t: 3, p: 1 });
  });

  it('parseWrappedDataKey rejects malformed envelopes', () => {
    assert.throws(() => parseWrappedDataKey('{not json'), /not valid JSON/);
    assert.throws(
      () => parseWrappedDataKey(JSON.stringify({ v: 99, kdf: 'unknown', wrapped: 'AAAA' })),
      /Unsupported wrapped_data_key envelope/,
    );
  });

  it('parseWrappedDataKey rejects empty/non-string', () => {
    assert.throws(() => parseWrappedDataKey(''), /non-empty/);
    assert.throws(() => parseWrappedDataKey(null), /non-empty/);
  });

  it('round-trip: v1 wrap → unwrap recovers a usable AES-GCM key', async () => {
    const k = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V1_PBKDF2);
    const wire = await wrapDataKeyEnvelope(
      k.credentialEncryptionKey.gcmKey,
      k.credentialEncryptionKey.kwKey,
      KDF_V1_PBKDF2,
    );
    const unwrapped = await unwrapDataKeyEnvelope(wire, k.credentialEncryptionKey.kwKey);
    assert.equal(unwrapped.kdfVersion, KDF_V1_PBKDF2);

    // Verify the unwrapped key is functional.
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, unwrapped.dataKey, new TextEncoder().encode('hello'));
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, unwrapped.dataKey, ct);
    assert.equal(new TextDecoder().decode(pt), 'hello');
  });

  it('round-trip: v2 wrap → unwrap recovers a usable AES-GCM key', async () => {
    const k = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V2_ARGON2ID);
    const wire = await wrapDataKeyEnvelope(
      k.credentialEncryptionKey.gcmKey,
      k.credentialEncryptionKey.kwKey,
      KDF_V2_ARGON2ID,
    );
    const unwrapped = await unwrapDataKeyEnvelope(wire, k.credentialEncryptionKey.kwKey);
    assert.equal(unwrapped.kdfVersion, KDF_V2_ARGON2ID);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, unwrapped.dataKey, new TextEncoder().encode('hello'));
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, unwrapped.dataKey, ct);
    assert.equal(new TextDecoder().decode(pt), 'hello');
  });

  it('legacy decrypt: v1 wire format unwraps via the legacy unwrapDataKey()', async () => {
    // Emulates a pre-Argon2id account: bare base64 string was sent during
    // registration and is now stored on the API. New client must still unwrap.
    const k = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V1_PBKDF2);
    const bare = await wrapDataKey(k.credentialEncryptionKey.gcmKey, k.credentialEncryptionKey.kwKey);

    // unwrapDataKey is the existing primitive used pre-issue; ensure it still works.
    const dataKey = await unwrapDataKey(bare, k.credentialEncryptionKey.kwKey);
    assert.ok(dataKey instanceof CryptoKey);

    // And via the new envelope-aware path:
    const envelopeUnwrapped = await unwrapDataKeyEnvelope(bare, k.credentialEncryptionKey.kwKey);
    assert.equal(envelopeUnwrapped.kdfVersion, KDF_V1_PBKDF2);
  });
});
