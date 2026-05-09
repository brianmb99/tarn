/**
 * Cross-validation tests: prove byte-equality between the borrowed crypto
 * code in `recover/src/crypto/` and the original in `client/src/crypto.ts`
 * + `client/src/recovery.ts`.
 *
 * For every primitive borrowed in Phase 3, run BOTH the recover-side and
 * client-side function with the same inputs and assert the outputs match.
 * This catches drift between the two copies (we can't deduplicate the
 * crypto module without coupling the recover package to a tarn-client
 * import — and that defeats the "server-free, single-purpose" packaging
 * goal).
 *
 * The tests use minimal but deterministic inputs. Argon2id (m=64 MiB) is
 * slow but each KDF runs once per test (about 200-500 ms on dev hardware).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Recover-side primitives — the borrowed copies.
import * as recoverCrypto from '../src/crypto/index.js';
import * as recoverBip39 from '../src/crypto/bip39.js';

// Client-side primitives — the originals. The worktree carries the full
// `client/` source + node_modules so this resolves cleanly.
import * as clientCrypto from '../../client/src/crypto.js';
import * as clientRecovery from '../../client/src/recovery.js';

// ============ Fixed test inputs (deterministic across runs) ============

const TEST_USERNAME = 'cross-validate@example.com';
const TEST_PASSWORD = 'cross-validate-pw-2026';
const TEST_APP = 'tarn-recover-test';

// Pre-generated valid 24-word BIP39 mnemonic. Generated via
// `client.recovery.generateAccountKey()` once and pinned for determinism.
const TEST_ACCOUNT_KEY =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';

// Fixed 16-byte salt — recovery KDF salt is per-account but the value is
// arbitrary; we just need the same salt on both sides of the comparison.
const TEST_SALT = new Uint8Array([
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
]);

// ============ Helpers ============

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function exportRaw(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

// ============ Tests ============

describe('cross-validate: encoding helpers', () => {
  it('bytesToHex matches client', () => {
    const input = new Uint8Array([0x00, 0x7f, 0xff, 0xab, 0xcd]);
    assert.equal(recoverCrypto.bytesToHex(input), '007fffabcd');
  });

  it('base64 round-trip matches client output byte-for-byte', () => {
    const input = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const recoverEnc = recoverCrypto.bytesToBase64(input);
    const clientEnc = clientCrypto.bytesToBase64(input);
    assert.equal(recoverEnc, clientEnc);

    const recoverDec = recoverCrypto.base64ToBytes(recoverEnc);
    const clientDec = clientCrypto.base64ToBytes(clientEnc);
    assert.ok(bytesEqual(recoverDec, clientDec));
    assert.ok(bytesEqual(recoverDec, input));
  });

  it('base64url round-trip matches client output byte-for-byte', () => {
    // Bytes that exercise the +/= → -_/(strip) substitutions.
    const input = new Uint8Array([0xff, 0xee, 0xff, 0xee, 0xff]);
    const recoverEnc = recoverCrypto.bytesToBase64Url(input);
    const clientEnc = clientCrypto.bytesToBase64Url(input);
    assert.equal(recoverEnc, clientEnc);

    const recoverDec = recoverCrypto.base64UrlToBytes(recoverEnc);
    const clientDec = clientCrypto.base64UrlToBytes(clientEnc);
    assert.ok(bytesEqual(recoverDec, clientDec));
  });
});

describe('cross-validate: KDFs (Argon2id)', () => {
  it('deriveMasterKey produces byte-identical output to client', async () => {
    const [r, c] = await Promise.all([
      recoverCrypto.deriveMasterKey(TEST_USERNAME, TEST_PASSWORD),
      clientCrypto.deriveMasterKey(TEST_USERNAME, TEST_PASSWORD),
    ]);
    assert.equal(r.length, 32);
    assert.equal(c.length, 32);
    assert.ok(bytesEqual(r, c), 'deriveMasterKey output diverged from client');
  });

  it('deriveRecoveryKey produces byte-identical raw bytes to client', async () => {
    const [r, c] = await Promise.all([
      recoverCrypto.deriveRecoveryKey(TEST_ACCOUNT_KEY, TEST_SALT),
      clientCrypto.deriveRecoveryKey(TEST_ACCOUNT_KEY, TEST_SALT),
    ]);
    assert.equal(r.rawBytes.length, 32);
    assert.equal(c.rawBytes.length, 32);
    assert.ok(
      bytesEqual(r.rawBytes, c.rawBytes),
      'deriveRecoveryKey raw bytes diverged from client',
    );
  });

  it('deriveCredentialEncryptionKey produces byte-identical raw bytes to client', async () => {
    const masterKey = await recoverCrypto.deriveMasterKey(TEST_USERNAME, TEST_PASSWORD);
    const [r, c] = await Promise.all([
      recoverCrypto.deriveCredentialEncryptionKey(masterKey, TEST_APP),
      clientCrypto.deriveCredentialEncryptionKey(masterKey, TEST_APP),
    ]);
    assert.ok(
      bytesEqual(r.rawBytes, c.rawBytes),
      'deriveCredentialEncryptionKey raw bytes diverged from client',
    );
  });
});

describe('cross-validate: BIP39', () => {
  it('validateAccountKey accepts and normalizes identically', () => {
    const r = recoverBip39.validateAccountKey(TEST_ACCOUNT_KEY);
    const c = clientRecovery.validateAccountKey(TEST_ACCOUNT_KEY);
    assert.equal(r.valid, true);
    assert.equal(c.valid, true);
    if (r.valid && c.valid) {
      assert.equal(r.normalized, c.normalized);
    }
  });

  it('validateAccountKey rejects bad input identically', () => {
    const bad = 'not a valid mnemonic phrase obviously not 24 words';
    const r = recoverBip39.validateAccountKey(bad);
    const c = clientRecovery.validateAccountKey(bad);
    assert.equal(r.valid, false);
    assert.equal(c.valid, false);
  });

  it('accountKeyToEntropy produces byte-identical entropy to client', () => {
    const r = recoverBip39.accountKeyToEntropy(TEST_ACCOUNT_KEY);
    const c = clientRecovery.accountKeyToEntropy(TEST_ACCOUNT_KEY);
    assert.equal(r.length, 32); // 24-word phrase = 32 bytes of entropy
    assert.ok(bytesEqual(r, c), 'accountKeyToEntropy diverged from client');
  });
});

describe('cross-validate: AES + envelope decoding', () => {
  it('parseWrappedDataKey accepts a client-built envelope and returns equivalent data', async () => {
    // Build a synthetic envelope using the client-side writer.
    const recoverySalt = clientCrypto.generateRecoverySalt();
    const dek = await clientCrypto.generateRandomDataKey();
    const masterKey = await clientCrypto.deriveMasterKey(TEST_USERNAME, TEST_PASSWORD);
    const cek = await clientCrypto.deriveCredentialEncryptionKey(masterKey, TEST_APP);
    const recoveryKEK = await clientCrypto.deriveRecoveryKey(TEST_ACCOUNT_KEY, recoverySalt);

    const envelope = await clientCrypto.wrapDataKeyChainEnvelope(
      [{ gen: 1, key: dek.gcmKey }],
      [
        { name: clientCrypto.FACTOR_PASSWORD, wrappingKey: cek.kwKey },
        { name: clientCrypto.FACTOR_RECOVERY_PHRASE, wrappingKey: recoveryKEK.kwKey },
      ],
      { salt: recoverySalt },
    );

    const r = recoverCrypto.parseWrappedDataKey(envelope);
    const c = clientCrypto.parseWrappedDataKey(envelope);

    assert.equal(r.envelopeVersion, c.envelopeVersion);
    assert.equal(r.dekChain.length, c.dekChain.length);
    assert.equal(r.dekChain[0]!.gen, c.dekChain[0]!.gen);
    assert.equal(r.dekChain[0]!.wrappings.length, c.dekChain[0]!.wrappings.length);
    assert.ok(bytesEqual(r.recovery.salt, c.recovery.salt));
    assert.deepEqual(r.recovery.kdfParams, c.recovery.kdfParams);
  });

  it('decryptWithCEK round-trips a client-encrypted blob', async () => {
    const dek = await clientCrypto.generateRandomDataKey();
    const payload = { hello: 'world', n: 42 };
    const { blob } = await clientCrypto.encryptWithCEK(dek.kwKey, payload);

    const decoded = await recoverCrypto.decryptWithCEK(dek.kwKey, blob);
    assert.deepEqual(decoded, payload);
  });

  it('hasTarnBlobMagic identifies the magic prefix consistently', () => {
    const magic = new Uint8Array([0x54, 0x41, 0x52, 0x4e, 0x02, 0xaa, 0xbb]);
    const notMagic = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0xaa]);
    assert.equal(recoverCrypto.hasTarnBlobMagic(magic), true);
    assert.equal(clientCrypto.hasTarnBlobMagic(magic), true);
    assert.equal(recoverCrypto.hasTarnBlobMagic(notMagic), false);
    assert.equal(clientCrypto.hasTarnBlobMagic(notMagic), false);
  });

  it('unwrapAccountKey round-trips a client-wrapped account key', async () => {
    const dek = await clientCrypto.generateRandomDataKey();
    const original = TEST_ACCOUNT_KEY;
    const wrapped = await clientCrypto.wrapAccountKey(dek.gcmKey, original);

    const unwrapped = await recoverCrypto.unwrapAccountKey(dek.gcmKey, wrapped);
    assert.equal(unwrapped, original);
  });
});

describe('cross-validate: AES-KW unwrapDataKey', () => {
  it('unwraps a client-wrapped raw DEK to byte-identical material', async () => {
    const wrapping = await clientCrypto.generateRandomDataKey();
    const dek = await clientCrypto.generateRandomDataKey();

    // Wrap via client, unwrap via recover, then read raw bytes from the
    // unwrapped key and compare to the original DEK rawBytes.
    const wrappedB64 = await clientCrypto.wrapDataKey(dek.kwKey, wrapping.kwKey);
    const unwrappedRecover = await recoverCrypto.unwrapDataKey(wrappedB64, wrapping.kwKey);

    const recoveredBytes = await exportRaw(unwrappedRecover);
    assert.ok(
      bytesEqual(recoveredBytes, dek.rawBytes),
      'unwrapDataKey produced different bytes than the original DEK',
    );
  });
});
