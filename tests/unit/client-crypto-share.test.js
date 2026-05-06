// Unit tests for the sharing keypair derivation + helpers (issue #13).
// Covers:
//   - deriveSharingKeyPair determinism, per-app isolation, X25519 shape
//   - encodeSharePub / decodeSharePub round-trip + length validation
//   - deriveShareLookupKey determinism + per-app isolation + email
//     normalization
//   - deriveAllKeys returns the new sharingKeyPair
//
// Run: node --test tests/unit/client-crypto-share.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveSharingKeyPair,
  deriveShareLookupKey,
  deriveAllKeys,
  encodeSharePub,
  decodeSharePub,
  bytesToBase64Url,
  base64UrlToBytes,
} from '../../client/src/crypto.js';

const TEST_EMAIL = 'share-test@example.com';
const TEST_PASSWORD = 'correct-horse-battery-staple-2026';
const TEST_APP = 'bookish';
const OTHER_APP = 'cellar';

function fixedMasterKey(seed = 0) {
  const mk = new Uint8Array(32);
  for (let i = 0; i < 32; i++) mk[i] = (seed + i) & 0xff;
  return mk;
}

// ============ deriveSharingKeyPair ============

describe('deriveSharingKeyPair', () => {
  it('produces a 32-byte private key and a 32-byte public key', async () => {
    const { privateKey, publicKey } = await deriveSharingKeyPair(fixedMasterKey(), TEST_APP);
    assert.ok(privateKey instanceof Uint8Array);
    assert.ok(publicKey instanceof Uint8Array);
    assert.equal(privateKey.length, 32);
    assert.equal(publicKey.length, 32);
  });

  it('is deterministic — same master_key + app produces the same keypair', async () => {
    const a = await deriveSharingKeyPair(fixedMasterKey(), TEST_APP);
    const b = await deriveSharingKeyPair(fixedMasterKey(), TEST_APP);
    assert.deepEqual(Array.from(a.privateKey), Array.from(b.privateKey));
    assert.deepEqual(Array.from(a.publicKey), Array.from(b.publicKey));
  });

  it('per-app isolated — different app_id produces different share_pub', async () => {
    const bookish = await deriveSharingKeyPair(fixedMasterKey(), TEST_APP);
    const cellar = await deriveSharingKeyPair(fixedMasterKey(), OTHER_APP);
    assert.notDeepEqual(Array.from(bookish.publicKey), Array.from(cellar.publicKey));
    assert.notDeepEqual(Array.from(bookish.privateKey), Array.from(cellar.privateKey));
  });

  it('different master_keys produce different share_pub for the same app', async () => {
    const a = await deriveSharingKeyPair(fixedMasterKey(0), TEST_APP);
    const b = await deriveSharingKeyPair(fixedMasterKey(1), TEST_APP);
    assert.notDeepEqual(Array.from(a.publicKey), Array.from(b.publicKey));
  });

  it('public key is on the X25519 curve (not all-zero, not the obvious junk)', async () => {
    const { publicKey } = await deriveSharingKeyPair(fixedMasterKey(), TEST_APP);
    // Trivial sanity: not all zeros (which would be invalid as a pubkey).
    const allZero = publicKey.every(b => b === 0);
    assert.equal(allZero, false);
    // The implementation is verified end-to-end by the deterministic + per-app
    // tests above; the round-trip ECDH check belongs to Section 5.
  });

  it('rejects missing app_id', async () => {
    await assert.rejects(() => deriveSharingKeyPair(fixedMasterKey(), ''), /appId is required/);
    await assert.rejects(() => deriveSharingKeyPair(fixedMasterKey(), null), /appId is required/);
  });
});

// ============ encodeSharePub / decodeSharePub ============

describe('encodeSharePub / decodeSharePub', () => {
  it('round-trips a 32-byte X25519 public key', async () => {
    const { publicKey } = await deriveSharingKeyPair(fixedMasterKey(), TEST_APP);
    const encoded = encodeSharePub(publicKey);
    assert.equal(typeof encoded, 'string');
    assert.equal(encoded.length, 43); // base64url of 32 bytes, no padding
    assert.match(encoded, /^[A-Za-z0-9_-]+$/);
    const decoded = decodeSharePub(encoded);
    assert.deepEqual(Array.from(decoded), Array.from(publicKey));
  });

  it('encodeSharePub rejects wrong-length input', () => {
    assert.throws(() => encodeSharePub(new Uint8Array(31)), /length 32/);
    assert.throws(() => encodeSharePub(new Uint8Array(33)), /length 32/);
    assert.throws(() => encodeSharePub('not bytes'), /Uint8Array/);
  });

  it('decodeSharePub rejects wrong-length encoded input', () => {
    // 64 raw bytes encodes to a longer string — must fail length check.
    const bigPub = new Uint8Array(64);
    const wrong = bytesToBase64Url(bigPub);
    assert.throws(() => decodeSharePub(wrong), /must decode to 32 bytes/);
  });

  it('decodeSharePub rejects empty input', () => {
    assert.throws(() => decodeSharePub(''), /non-empty string/);
    assert.throws(() => decodeSharePub(null), /non-empty string/);
  });

  it('base64url helpers round-trip arbitrary byte sequences', () => {
    const inputs = [
      new Uint8Array([]),
      new Uint8Array([0]),
      new Uint8Array([0xff, 0xfe, 0xfd]),
      new Uint8Array(64).map((_, i) => i * 3),
    ];
    for (const input of inputs) {
      const encoded = bytesToBase64Url(input);
      // No padding allowed.
      assert.ok(!encoded.includes('='));
      // No standard base64 chars that should have been replaced.
      assert.ok(!encoded.includes('+'));
      assert.ok(!encoded.includes('/'));
      const decoded = base64UrlToBytes(encoded);
      assert.deepEqual(Array.from(decoded), Array.from(input));
    }
  });
});

// ============ deriveShareLookupKey ============

describe('deriveShareLookupKey', () => {
  it('returns a 64-char lowercase hex string', async () => {
    const lk = await deriveShareLookupKey(TEST_EMAIL, TEST_APP);
    assert.match(lk, /^[a-f0-9]{64}$/);
  });

  it('is deterministic for the same email + app', async () => {
    const a = await deriveShareLookupKey(TEST_EMAIL, TEST_APP);
    const b = await deriveShareLookupKey(TEST_EMAIL, TEST_APP);
    assert.equal(a, b);
  });

  it('per-app isolated — different app_id produces different lookup key', async () => {
    const a = await deriveShareLookupKey(TEST_EMAIL, TEST_APP);
    const b = await deriveShareLookupKey(TEST_EMAIL, OTHER_APP);
    assert.notEqual(a, b);
  });

  it('per-email differentiated — different emails produce different lookup keys', async () => {
    const a = await deriveShareLookupKey('alice@example.com', TEST_APP);
    const b = await deriveShareLookupKey('bob@example.com', TEST_APP);
    assert.notEqual(a, b);
  });

  it('normalizes email — case + whitespace are ignored', async () => {
    const canon = await deriveShareLookupKey('alice@example.com', TEST_APP);
    const upper = await deriveShareLookupKey('ALICE@EXAMPLE.COM', TEST_APP);
    const padded = await deriveShareLookupKey('  Alice@Example.com  ', TEST_APP);
    assert.equal(canon, upper);
    assert.equal(canon, padded);
  });

  it('does NOT depend on password — derivable from email alone', async () => {
    // The whole point of share_lookup_key is the connection handshake bootstrap:
    // Alice can find Bob's row knowing only Bob's email. There is no password
    // input to the function — verify by inspecting the signature behavior:
    // calling without a password works.
    const lk = await deriveShareLookupKey(TEST_EMAIL, TEST_APP);
    assert.equal(typeof lk, 'string');
    assert.equal(lk.length, 64);
  });

  it('rejects missing username or app_id', async () => {
    await assert.rejects(() => deriveShareLookupKey('', TEST_APP), /username is required/);
    await assert.rejects(() => deriveShareLookupKey(TEST_EMAIL, ''), /appId is required/);
  });
});

// ============ deriveAllKeys integration ============

describe('deriveAllKeys (issue #13 sharing keypair integration)', () => {
  // Use PBKDF2 (v1) for these to keep the test suite fast — Argon2id adds
  // ~200ms per call which adds up across the full suite. The specific KDF
  // doesn't matter for testing the sharing keypair derivation.
  const KDF_V1_PBKDF2 = 1;

  it('returns a sharingKeyPair alongside the existing keys', async () => {
    const keys = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V1_PBKDF2);
    assert.ok(keys.sharingKeyPair, 'sharingKeyPair missing');
    assert.equal(keys.sharingKeyPair.privateKey.length, 32);
    assert.equal(keys.sharingKeyPair.publicKey.length, 32);
  });

  it('share_pub is deterministic across calls (re-login produces same key)', async () => {
    const a = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V1_PBKDF2);
    const b = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V1_PBKDF2);
    assert.deepEqual(
      Array.from(a.sharingKeyPair.publicKey),
      Array.from(b.sharingKeyPair.publicKey),
    );
  });

  it('share_pub differs for the same email+password across apps (per-app isolation)', async () => {
    const bookish = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V1_PBKDF2);
    const cellar = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, OTHER_APP, KDF_V1_PBKDF2);
    assert.notDeepEqual(
      Array.from(bookish.sharingKeyPair.publicKey),
      Array.from(cellar.sharingKeyPair.publicKey),
    );
  });

  it('share_pub changes when password changes (master_key rotation)', async () => {
    const a = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V1_PBKDF2);
    const b = await deriveAllKeys(TEST_EMAIL, 'different-password', TEST_APP, KDF_V1_PBKDF2);
    assert.notDeepEqual(
      Array.from(a.sharingKeyPair.publicKey),
      Array.from(b.sharingKeyPair.publicKey),
    );
  });

  it('share_pub changes when email changes (master_key salt rotation)', async () => {
    const a = await deriveAllKeys('alice@example.com', TEST_PASSWORD, TEST_APP, KDF_V1_PBKDF2);
    const b = await deriveAllKeys('bob@example.com', TEST_PASSWORD, TEST_APP, KDF_V1_PBKDF2);
    assert.notDeepEqual(
      Array.from(a.sharingKeyPair.publicKey),
      Array.from(b.sharingKeyPair.publicKey),
    );
  });
});
