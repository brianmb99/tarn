// Unit tests for the per-content CEK pattern, random DEK at registration,
// forward-secret DEK chain rotation, and the v1 multi-factor envelope.
// Run: node --test tests/unit/client-crypto-cek.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveAllKeys,
  deriveRecoveryKey,
  generateRandomDataKey,
  generateRecoverySalt,
  wrapDataKey,
  wrapDataKeyChainEnvelope,
  unwrapDataKeyChain,
  parseWrappedDataKey,
  buildEnvelope,
  encryptWithCEK,
  decryptWithCEK,
  decryptBlobWithSharedCEK,
  hasTarnBlobMagic,
  encrypt,
  TARN_BLOB_MAGIC,
  bytesToBase64Url,
  FACTOR_PASSWORD,
  FACTOR_RECOVERY_PHRASE,
} from '../../client/src/crypto.js';

const TEST_EMAIL = 'cek-test@example.com';
const TEST_PASSWORD = 'correct-horse-battery-staple-2026';
const TEST_APP = 'bookish';
const TEST_PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Helpers — every test that builds an envelope needs both factors + a salt.

async function makeFactors() {
  const keys = await deriveAllKeys(TEST_EMAIL, TEST_PASSWORD, TEST_APP);
  const salt = generateRecoverySalt();
  const recoveryKEK = await deriveRecoveryKey(TEST_PHRASE, salt);
  return { keys, salt, recoveryKEK };
}

function bothFactors(passwordKwKey, recoveryKwKey) {
  return [
    { name: FACTOR_PASSWORD,        wrappingKey: passwordKwKey },
    { name: FACTOR_RECOVERY_PHRASE, wrappingKey: recoveryKwKey },
  ];
}

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

  it('hasTarnBlobMagic rejects non-magic blobs', () => {
    const random = new Uint8Array(13).fill(0xab);
    assert.equal(hasTarnBlobMagic(random), false);
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

// ============ v1 envelope (multi-factor DEK chain) ============

describe('v1 envelope', () => {
  it('buildEnvelope produces well-formed JSON with sorted gens and required recovery block', async () => {
    const { salt } = await makeFactors();
    const wire = buildEnvelope(
      [
        { gen: 2, wrappings: [{ factor: FACTOR_PASSWORD, wrappedBase64: 'BBBB' }] },
        { gen: 1, wrappings: [{ factor: FACTOR_PASSWORD, wrappedBase64: 'AAAA' }] },
      ],
      { salt },
    );
    const parsed = JSON.parse(wire);
    assert.equal(parsed.v, 1);
    assert.equal(parsed.kdf, 'argon2id');
    assert.deepEqual(parsed.kdf_params, { m_kib: 65536, t: 3, p: 1 });
    assert.equal(parsed.dek_chain.length, 2);
    assert.equal(parsed.dek_chain[0].gen, 1);
    assert.equal(parsed.dek_chain[1].gen, 2);
    assert.ok(parsed.recovery, 'recovery block must be present');
    assert.equal(parsed.recovery.kdf, 'argon2id');
  });

  it('parseWrappedDataKey accepts a v1 envelope and surfaces the password wrapping', () => {
    const wire = JSON.stringify({
      v: 1,
      kdf: 'argon2id',
      kdf_params: { m_kib: 65536, t: 3, p: 1 },
      recovery: {
        kdf: 'argon2id',
        kdf_params: { m_kib: 65536, t: 3, p: 1 },
        salt: 'AAAAAAAAAAAAAAAAAAAAAA==',
      },
      dek_chain: [
        { gen: 1, wrappings: [{ factor: 'password', wrapped: 'AAAA' }, { factor: 'recovery_phrase', wrapped: 'AAAA-rec' }] },
        { gen: 2, wrappings: [{ factor: 'password', wrapped: 'BBBB' }, { factor: 'recovery_phrase', wrapped: 'BBBB-rec' }] },
      ],
    });
    const parsed = parseWrappedDataKey(wire);
    assert.equal(parsed.envelopeVersion, 1);
    assert.equal(parsed.dekChain.length, 2);
    assert.equal(parsed.dekChain[0].wrappings.length, 2);
    // wrappedBase64 returns the highest-gen entry's password wrapping as a convenience
    assert.equal(parsed.wrappedBase64, 'BBBB');
    assert.ok(parsed.recovery, 'parsed.recovery is required');
  });

  it('parseWrappedDataKey rejects bare base64 (legacy v1 single-key)', () => {
    assert.throws(
      () => parseWrappedDataKey('aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGRsbA=='),
      /must be a JSON envelope/,
    );
  });

  it('parseWrappedDataKey rejects pre-cleanup envelopes (v=2/v=3/v=4)', () => {
    for (const v of [2, 3, 4]) {
      const wire = JSON.stringify({ v, kdf: 'argon2id', dek_chain: [] });
      assert.throws(() => parseWrappedDataKey(wire), /unsupported envelope/);
    }
  });

  it('parseWrappedDataKey rejects an envelope missing the recovery block', () => {
    const wire = JSON.stringify({
      v: 1,
      kdf: 'argon2id',
      kdf_params: { m_kib: 65536, t: 3, p: 1 },
      dek_chain: [{ gen: 1, wrappings: [{ factor: 'password', wrapped: 'AAAA' }] }],
    });
    assert.throws(() => parseWrappedDataKey(wire), /missing required recovery block/);
  });

  it('parseWrappedDataKey rejects an envelope with no password wrapping at the current gen', () => {
    const wire = JSON.stringify({
      v: 1,
      kdf: 'argon2id',
      kdf_params: { m_kib: 65536, t: 3, p: 1 },
      recovery: {
        kdf: 'argon2id',
        kdf_params: { m_kib: 65536, t: 3, p: 1 },
        salt: 'AAAAAAAAAAAAAAAAAAAAAA==',
      },
      dek_chain: [{ gen: 1, wrappings: [{ factor: 'recovery_phrase', wrapped: 'X' }] }],
    });
    assert.throws(() => parseWrappedDataKey(wire), /missing the password wrapping/);
  });

  it('parseWrappedDataKey rejects an empty chain', () => {
    const wire = JSON.stringify({
      v: 1, kdf: 'argon2id',
      recovery: { kdf: 'argon2id', kdf_params: { m_kib: 65536, t: 3, p: 1 }, salt: 'AAAAAAAAAAAAAAAAAAAAAA==' },
      dek_chain: [],
    });
    assert.throws(() => parseWrappedDataKey(wire), /non-empty dek_chain/);
  });

  it('parseWrappedDataKey rejects duplicate gens', () => {
    const wire = JSON.stringify({
      v: 1, kdf: 'argon2id',
      recovery: { kdf: 'argon2id', kdf_params: { m_kib: 65536, t: 3, p: 1 }, salt: 'AAAAAAAAAAAAAAAAAAAAAA==' },
      dek_chain: [
        { gen: 1, wrappings: [{ factor: 'password', wrapped: 'A' }] },
        { gen: 1, wrappings: [{ factor: 'password', wrapped: 'B' }] },
      ],
    });
    assert.throws(() => parseWrappedDataKey(wire), /duplicate gen/);
  });
});

// ============ wrapDataKeyChainEnvelope round-trip ============

describe('wrapDataKeyChainEnvelope <-> unwrapDataKeyChain', () => {
  it('round-trips a single-gen chain via the password factor', async () => {
    const { keys, salt, recoveryKEK } = await makeFactors();
    const dek = await generateRandomDataKey();

    const wire = await wrapDataKeyChainEnvelope(
      [{ gen: 1, key: dek.gcmKey }],
      bothFactors(keys.credentialEncryptionKey.kwKey, recoveryKEK.kwKey),
      { salt },
    );

    const parsed = JSON.parse(wire);
    assert.equal(parsed.v, 1);
    assert.equal(parsed.dek_chain.length, 1);
    assert.equal(parsed.dek_chain[0].wrappings.length, 2, 'both factors present');

    const unwrapped = await unwrapDataKeyChain(wire, keys.credentialEncryptionKey.kwKey);
    assert.equal(unwrapped.envelopeVersion, 1);
    assert.equal(unwrapped.currentGen, 1);
    assert.equal(unwrapped.dekByGen.size, 1);
    assert.ok(unwrapped.dekByGen.get(1).gcmKey instanceof CryptoKey);
    assert.ok(unwrapped.dekByGen.get(1).kwKey instanceof CryptoKey);
  });

  it('round-trips a multi-gen chain (forward-secret rotation simulation)', async () => {
    const { keys, salt, recoveryKEK } = await makeFactors();
    const dek1 = await generateRandomDataKey();
    const dek2 = await generateRandomDataKey();
    const dek3 = await generateRandomDataKey();

    const wire = await wrapDataKeyChainEnvelope(
      [
        { gen: 1, key: dek1.gcmKey },
        { gen: 2, key: dek2.gcmKey },
        { gen: 3, key: dek3.gcmKey },
      ],
      bothFactors(keys.credentialEncryptionKey.kwKey, recoveryKEK.kwKey),
      { salt },
    );

    const unwrapped = await unwrapDataKeyChain(wire, keys.credentialEncryptionKey.kwKey);
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

  it('round-trips via the recovery factor (parallel access path)', async () => {
    const { keys, salt, recoveryKEK } = await makeFactors();
    const dek = await generateRandomDataKey();

    const wire = await wrapDataKeyChainEnvelope(
      [{ gen: 1, key: dek.gcmKey }],
      bothFactors(keys.credentialEncryptionKey.kwKey, recoveryKEK.kwKey),
      { salt },
    );

    // Same envelope, different factor. Must produce the same DEK bytes.
    const unwrappedByPwd = await unwrapDataKeyChain(wire, keys.credentialEncryptionKey.kwKey, FACTOR_PASSWORD);
    const unwrappedByRec = await unwrapDataKeyChain(wire, recoveryKEK.kwKey, FACTOR_RECOVERY_PHRASE);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      unwrappedByPwd.dekByGen.get(1).gcmKey,
      new TextEncoder().encode('shared-payload'),
    );
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, unwrappedByRec.dekByGen.get(1).gcmKey, ct);
    assert.equal(new TextDecoder().decode(pt), 'shared-payload');
  });

  it('rejects empty chain', async () => {
    const { keys, salt, recoveryKEK } = await makeFactors();
    await assert.rejects(
      () => wrapDataKeyChainEnvelope([], bothFactors(keys.credentialEncryptionKey.kwKey, recoveryKEK.kwKey), { salt }),
      /non-empty/,
    );
  });

  it('a fresh random DEK is NOT equal to the credential_encryption_key', async () => {
    const { keys, salt, recoveryKEK } = await makeFactors();
    const dek = await generateRandomDataKey();
    const wire = await wrapDataKeyChainEnvelope(
      [{ gen: 1, key: dek.gcmKey }],
      bothFactors(keys.credentialEncryptionKey.kwKey, recoveryKEK.kwKey),
      { salt },
    );
    const unwrapped = await unwrapDataKeyChain(wire, keys.credentialEncryptionKey.kwKey);
    const recovered = unwrapped.dekByGen.get(1).gcmKey;

    // Encrypt under the credential_encryption_key; the recovered DEK must NOT
    // be able to decrypt — that would prove self-wrapping.
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      keys.credentialEncryptionKey.gcmKey,
      new TextEncoder().encode('encrypted-with-credential-encryption-key'),
    );
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
    const noMagic = await encrypt(dek.gcmKey, { x: 1 }); // direct AES-GCM, no magic
    await assert.rejects(() => decryptWithCEK(dek.kwKey, noMagic), /magic prefix/);
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
    const noMagic = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]); // no magic
    await assert.rejects(
      () => decryptBlobWithSharedCEK(noMagic, fakeShareKey),
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
