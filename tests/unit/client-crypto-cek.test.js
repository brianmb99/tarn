// Unit tests for issue #11 — per-content CEK pattern, random DEK at
// registration, and forward-secret DEK chain rotation.
// Run: node --test tests/unit/client-crypto-cek.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveAllKeys,
  generateRandomDataKey,
  wrapDataKey,
  wrapDataKeyChainEnvelope,
  unwrapDataKeyChain,
  parseWrappedDataKey,
  buildV3Envelope,
  encryptWithCEK,
  decryptWithCEK,
  decryptBlobWithSharedCEK,
  hasTarnBlobMagic,
  encrypt,
  TARN_BLOB_MAGIC,
  bytesToBase64Url,
  KDF_V2_ARGON2ID,
} from '../../client/src/crypto.js';

const TEST_EMAIL = 'cek-test@example.com';
const TEST_PASSWORD = 'correct-horse-battery-staple-2026';
const TEST_APP = 'bookish';

// ============ Magic prefix ============

describe('TARN_BLOB_MAGIC', () => {
  it('is the documented 5-byte prefix "TARN" || 0x02', () => {
    assert.equal(TARN_BLOB_MAGIC.length, 5);
    assert.deepEqual(Array.from(TARN_BLOB_MAGIC), [0x54, 0x41, 0x52, 0x4e, 0x02]);
  });

  it('hasTarnBlobMagic detects new-format blobs', () => {
    const newBlob = new Uint8Array([0x54, 0x41, 0x52, 0x4e, 0x02, 0xff, 0xff]);
    assert.equal(hasTarnBlobMagic(newBlob), true);
  });

  it('hasTarnBlobMagic rejects legacy blobs (random IV start)', () => {
    const legacy = new Uint8Array(13).fill(0xab);
    assert.equal(hasTarnBlobMagic(legacy), false);
  });

  it('hasTarnBlobMagic rejects too-short input', () => {
    assert.equal(hasTarnBlobMagic(new Uint8Array(0)), false);
    assert.equal(hasTarnBlobMagic(new Uint8Array([0x54, 0x41, 0x52, 0x4e])), false);
  });

  it('hasTarnBlobMagic rejects non-Uint8Array', () => {
    assert.equal(hasTarnBlobMagic(null), false);
    assert.equal(hasTarnBlobMagic('TARN\x02'), false);
  });
});

// ============ generateRandomDataKey ============

describe('generateRandomDataKey', () => {
  it('returns 32 random bytes plus AES-GCM and AES-KW handles', async () => {
    const dek = await generateRandomDataKey();
    assert.ok(dek.gcmKey instanceof CryptoKey);
    assert.ok(dek.kwKey instanceof CryptoKey);
    assert.equal(dek.gcmKey.algorithm.name, 'AES-GCM');
    assert.equal(dek.kwKey.algorithm.name, 'AES-KW');
    assert.equal(dek.rawBytes.length, 32);
  });

  it('two calls produce different DEKs with overwhelming probability', async () => {
    const a = await generateRandomDataKey();
    const b = await generateRandomDataKey();
    assert.notDeepEqual(Array.from(a.rawBytes), Array.from(b.rawBytes));
  });
});

// ============ v3 envelope (DEK chain) ============

describe('v3 envelope', () => {
  it('buildV3Envelope produces well-formed JSON with sorted gens', () => {
    const wire = buildV3Envelope([
      { gen: 2, wrappedBase64: 'BBBB' },
      { gen: 1, wrappedBase64: 'AAAA' },
    ]);
    const parsed = JSON.parse(wire);
    assert.equal(parsed.v, 3);
    assert.equal(parsed.kdf, 'argon2id');
    assert.deepEqual(parsed.kdf_params, { m_kib: 65536, t: 3, p: 1 });
    assert.deepEqual(parsed.dek_chain, [
      { gen: 1, wrapped: 'AAAA' },
      { gen: 2, wrapped: 'BBBB' },
    ]);
  });

  it('parseWrappedDataKey accepts v3 envelopes', () => {
    const wire = JSON.stringify({
      v: 3,
      kdf: 'argon2id',
      kdf_params: { m_kib: 65536, t: 3, p: 1 },
      dek_chain: [
        { gen: 1, wrapped: 'AAAA' },
        { gen: 2, wrapped: 'BBBB' },
      ],
    });
    const parsed = parseWrappedDataKey(wire);
    assert.equal(parsed.kdfVersion, KDF_V2_ARGON2ID);
    assert.equal(parsed.envelopeVersion, 3);
    assert.equal(parsed.dekChain.length, 2);
    // v3 envelopes are normalized to the v4-shaped multi-factor chain with a
    // single synthetic `password` wrapping per entry (issue #12).
    assert.deepEqual(parsed.dekChain[0], {
      gen: 1, wrappings: [{ factor: 'password', wrappedBase64: 'AAAA' }],
    });
    assert.deepEqual(parsed.dekChain[1], {
      gen: 2, wrappings: [{ factor: 'password', wrappedBase64: 'BBBB' }],
    });
    // wrappedBase64 returns the highest-gen entry's password wrapping as a convenience
    assert.equal(parsed.wrappedBase64, 'BBBB');
  });

  it('parseWrappedDataKey normalizes v1 (bare base64) to a one-entry chain', () => {
    const parsed = parseWrappedDataKey('aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGRsbA==');
    assert.equal(parsed.envelopeVersion, 1);
    assert.equal(parsed.dekChain.length, 1);
    assert.equal(parsed.dekChain[0].gen, 1);
  });

  it('parseWrappedDataKey normalizes v2 to a one-entry chain', () => {
    const wire = JSON.stringify({
      v: 2, kdf: 'argon2id',
      kdf_params: { m_kib: 65536, t: 3, p: 1 },
      wrapped: 'CCCC',
    });
    const parsed = parseWrappedDataKey(wire);
    assert.equal(parsed.envelopeVersion, 2);
    assert.equal(parsed.dekChain.length, 1);
    assert.deepEqual(parsed.dekChain[0], {
      gen: 1, wrappings: [{ factor: 'password', wrappedBase64: 'CCCC' }],
    });
  });

  it('parseWrappedDataKey rejects v3 with empty chain', () => {
    const wire = JSON.stringify({ v: 3, kdf: 'argon2id', dek_chain: [] });
    assert.throws(() => parseWrappedDataKey(wire), /non-empty dek_chain/);
  });

  it('parseWrappedDataKey rejects v3 with duplicate gens', () => {
    const wire = JSON.stringify({
      v: 3, kdf: 'argon2id',
      dek_chain: [
        { gen: 1, wrapped: 'AAAA' },
        { gen: 1, wrapped: 'BBBB' },
      ],
    });
    assert.throws(() => parseWrappedDataKey(wire), /duplicate gen/);
  });

  it('parseWrappedDataKey rejects v3 with malformed entries', () => {
    const cases = [
      JSON.stringify({ v: 3, kdf: 'argon2id', dek_chain: [{ gen: 0, wrapped: 'A' }] }),
      JSON.stringify({ v: 3, kdf: 'argon2id', dek_chain: [{ gen: 'one', wrapped: 'A' }] }),
      JSON.stringify({ v: 3, kdf: 'argon2id', dek_chain: [{ gen: 1 }] }),
    ];
    for (const wire of cases) {
      assert.throws(() => parseWrappedDataKey(wire), /malformed/);
    }
  });
});

// ============ wrapDataKeyChainEnvelope round-trip ============

describe('wrapDataKeyChainEnvelope <-> unwrapDataKeyChain', () => {
  it('round-trips a single-gen chain', async () => {
    const k = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V2_ARGON2ID);
    const dek = await generateRandomDataKey();

    const wire = await wrapDataKeyChainEnvelope(
      [{ gen: 1, key: dek.gcmKey }],
      k.credentialEncryptionKey.kwKey,
    );

    const parsed = JSON.parse(wire);
    assert.equal(parsed.v, 3);
    assert.equal(parsed.dek_chain.length, 1);

    const unwrapped = await unwrapDataKeyChain(wire, k.credentialEncryptionKey.kwKey);
    assert.equal(unwrapped.envelopeVersion, 3);
    assert.equal(unwrapped.currentGen, 1);
    assert.equal(unwrapped.dekByGen.size, 1);
    assert.ok(unwrapped.dekByGen.get(1).gcmKey instanceof CryptoKey);
    assert.ok(unwrapped.dekByGen.get(1).kwKey instanceof CryptoKey);
  });

  it('round-trips a multi-gen chain (forward-secret rotation simulation)', async () => {
    const k = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V2_ARGON2ID);
    const dek1 = await generateRandomDataKey();
    const dek2 = await generateRandomDataKey();
    const dek3 = await generateRandomDataKey();

    const wire = await wrapDataKeyChainEnvelope(
      [
        { gen: 1, key: dek1.gcmKey },
        { gen: 2, key: dek2.gcmKey },
        { gen: 3, key: dek3.gcmKey },
      ],
      k.credentialEncryptionKey.kwKey,
    );

    const unwrapped = await unwrapDataKeyChain(wire, k.credentialEncryptionKey.kwKey);
    assert.equal(unwrapped.currentGen, 3);
    assert.equal(unwrapped.dekByGen.size, 3);

    // Each DEK round-trips: encrypt with the original, decrypt with the
    // unwrapped — confirms gens map to the right bytes.
    for (const gen of [1, 2, 3]) {
      const original = [dek1, dek2, dek3][gen - 1];
      const recovered = unwrapped.dekByGen.get(gen);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, original.gcmKey, new TextEncoder().encode(`gen-${gen}-secret`));
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, recovered.gcmKey, ct);
      assert.equal(new TextDecoder().decode(pt), `gen-${gen}-secret`);
    }
  });

  it('rejects empty chain', async () => {
    const k = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V2_ARGON2ID);
    await assert.rejects(
      () => wrapDataKeyChainEnvelope([], k.credentialEncryptionKey.kwKey),
      /non-empty/,
    );
  });

  it('a fresh random DEK is NOT equal to the credential_encryption_key (no self-wrapping)', async () => {
    // The pre-issue-#11 quirk was DEK := credential_encryption_key. With a
    // random DEK, the two key bytes diverge — verify this by encrypting with
    // the wrapping key and confirming the unwrapped DEK can't decrypt it.
    const k = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP, KDF_V2_ARGON2ID);
    const dek = await generateRandomDataKey();

    const wire = await wrapDataKeyChainEnvelope(
      [{ gen: 1, key: dek.gcmKey }],
      k.credentialEncryptionKey.kwKey,
    );
    const unwrapped = await unwrapDataKeyChain(wire, k.credentialEncryptionKey.kwKey);
    const recovered = unwrapped.dekByGen.get(1).gcmKey;

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      k.credentialEncryptionKey.gcmKey,
      new TextEncoder().encode('encrypted-with-credential-encryption-key'),
    );
    // Decryption with the random DEK should FAIL — different keys.
    await assert.rejects(
      () => crypto.subtle.decrypt({ name: 'AES-GCM', iv }, recovered, ct),
    );
  });
});

// ============ Per-content CEK round-trip ============

describe('encryptWithCEK <-> decryptWithCEK', () => {
  it('round-trips a payload through the new format', async () => {
    const dek = await generateRandomDataKey();
    const payload = { hello: 'world', n: 42, list: [1, 2, 3] };

    const { blob, shareKey } = await encryptWithCEK(dek.kwKey, payload);

    // Layout sanity: starts with magic, total len matches spec
    assert.equal(hasTarnBlobMagic(blob), true);
    // 5 (magic) + 40 (wrapped_CEK) + 12 (iv) + 16 (tag) = 73 fixed overhead
    const expectedMin = 73;
    assert.ok(blob.length >= expectedMin);

    // shareKey is base64url, ~43 chars for 32 raw bytes (no padding)
    assert.equal(typeof shareKey, 'string');
    assert.ok(shareKey.length >= 42 && shareKey.length <= 44);

    const recovered = await decryptWithCEK(dek.kwKey, blob);
    assert.deepEqual(recovered, payload);
  });

  it('two encryptions of the same payload produce different CEKs and ciphertexts', async () => {
    const dek = await generateRandomDataKey();
    const a = await encryptWithCEK(dek.kwKey, { x: 1 });
    const b = await encryptWithCEK(dek.kwKey, { x: 1 });
    assert.notDeepEqual(Array.from(a.blob), Array.from(b.blob));
    // The wrapped_CEK portion (bytes 5..44) must differ — proves CEK rotation
    // per blob, not just IV reuse.
    assert.notDeepEqual(Array.from(a.blob.slice(5, 45)), Array.from(b.blob.slice(5, 45)));
    // shareKeys must also differ (each is a fresh random CEK).
    assert.notEqual(a.shareKey, b.shareKey);
  });

  it('decrypting a CEK blob with the wrong DEK fails', async () => {
    const dek1 = await generateRandomDataKey();
    const dek2 = await generateRandomDataKey();
    const { blob } = await encryptWithCEK(dek1.kwKey, { secret: true });
    await assert.rejects(() => decryptWithCEK(dek2.kwKey, blob));
  });

  it('decryptWithCEK rejects a blob without the magic prefix', async () => {
    const dek = await generateRandomDataKey();
    const legacy = await encrypt(dek.gcmKey, { x: 1 }); // legacy format, no magic
    await assert.rejects(() => decryptWithCEK(dek.kwKey, legacy), /magic prefix/);
  });

  it('decryptWithCEK rejects a too-short blob', async () => {
    const dek = await generateRandomDataKey();
    const tooShort = new Uint8Array([0x54, 0x41, 0x52, 0x4e, 0x02]); // magic only
    await assert.rejects(() => decryptWithCEK(dek.kwKey, tooShort), /too short/);
  });

  it('mixed-generation read: each blob decrypts under its own gen DEK', async () => {
    // Simulates the post-rotation read path. Each blob was written under a
    // different gen; we hold the chain and dispatch on a (synthetic) gen tag.
    const dek1 = await generateRandomDataKey();
    const dek2 = await generateRandomDataKey();
    const dek3 = await generateRandomDataKey();
    const chain = new Map([[1, dek1], [2, dek2], [3, dek3]]);

    const blobs = [
      { gen: 1, blob: (await encryptWithCEK(dek1.kwKey, { from: 'gen-1' })).blob },
      { gen: 2, blob: (await encryptWithCEK(dek2.kwKey, { from: 'gen-2' })).blob },
      { gen: 3, blob: (await encryptWithCEK(dek3.kwKey, { from: 'gen-3' })).blob },
    ];

    for (const { gen, blob } of blobs) {
      const dek = chain.get(gen);
      const recovered = await decryptWithCEK(dek.kwKey, blob);
      assert.equal(recovered.from, `gen-${gen}`);
    }
  });
});

// ============ decryptBlobWithSharedCEK (recipient path) ============

describe('decryptBlobWithSharedCEK', () => {
  it('round-trips a payload using the shareKey directly (no DEK)', async () => {
    const dek = await generateRandomDataKey();
    const payload = { friend: 'shared', count: 7 };
    const { blob, shareKey } = await encryptWithCEK(dek.kwKey, payload);

    // Recipient does NOT have the writer's DEK — only the shareKey from
    // the share-log. They should still recover the plaintext.
    const recovered = await decryptBlobWithSharedCEK(blob, shareKey);
    assert.deepEqual(recovered, payload);
  });

  it('rejects a blob without the magic prefix', async () => {
    const fakeShareKey = bytesToBase64Url(new Uint8Array(32));
    const legacy = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]); // no magic
    await assert.rejects(
      () => decryptBlobWithSharedCEK(legacy, fakeShareKey),
      /magic prefix/,
    );
  });

  it('rejects a wrong-sized shareKey', async () => {
    const dek = await generateRandomDataKey();
    const { blob } = await encryptWithCEK(dek.kwKey, { x: 1 });
    const tooShort = bytesToBase64Url(new Uint8Array(16));
    await assert.rejects(
      () => decryptBlobWithSharedCEK(blob, tooShort),
      /must be 32 raw bytes/,
    );
  });

  it('rejects decryption with the wrong shareKey', async () => {
    const dek = await generateRandomDataKey();
    const { blob } = await encryptWithCEK(dek.kwKey, { x: 1 });
    const wrongKey = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    await assert.rejects(() => decryptBlobWithSharedCEK(blob, wrongKey));
  });
});
