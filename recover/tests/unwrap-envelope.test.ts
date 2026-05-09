/**
 * End-to-end Phase 3 tests: synthesize a v1 envelope using the client-side
 * writer, then unwrap via the recover-side pipeline. The DEK that comes
 * out should byte-equal the DEK that went in, via either factor.
 *
 * This is the real "did Phase 3 work?" test — round-trip through both
 * factors, plus a multi-gen chain to mirror a credentials-rotated account.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  parseEnvelope,
  derivePasswordKEK,
  deriveRecoveryKEK,
  unwrapDekChain,
} from '../src/decrypt/index.js';

import {
  decryptWithCEK,
  FACTOR_PASSWORD,
  FACTOR_RECOVERY_PHRASE,
} from '../src/crypto/index.js';

// Client-side writer (used to build the synthetic envelopes the recover
// code is supposed to consume).
import * as clientCrypto from '../../client/src/crypto.js';

const TEST_USERNAME = 'phase3-roundtrip@example.com';
const TEST_PASSWORD = 'phase3-roundtrip-pw-2026';
const TEST_APP = 'tarn-recover-test';
const TEST_ACCOUNT_KEY =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';

async function exportRaw(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Build a v1 envelope with N gen entries, each wrapped under both
 * password + recovery_phrase factors. Returns:
 *   - the wire envelope string
 *   - the per-gen DEK raw bytes (so tests can assert byte-equality after
 *     unwrap)
 *   - the recovery salt (needed by the recover-side `deriveRecoveryKEK`)
 */
async function buildSyntheticEnvelope(genCount: number): Promise<{
  envelope: string;
  recoverySalt: Uint8Array;
  dekRawByGen: Map<number, Uint8Array>;
}> {
  const recoverySalt = clientCrypto.generateRecoverySalt();
  const masterKey = await clientCrypto.deriveMasterKey(TEST_USERNAME, TEST_PASSWORD);
  const cek = await clientCrypto.deriveCredentialEncryptionKey(masterKey, TEST_APP);
  const recoveryKEK = await clientCrypto.deriveRecoveryKey(TEST_ACCOUNT_KEY, recoverySalt);

  const dekRawByGen = new Map<number, Uint8Array>();
  const chain: { gen: number; key: CryptoKey }[] = [];
  for (let gen = 1; gen <= genCount; gen++) {
    const dek = await clientCrypto.generateRandomDataKey();
    dekRawByGen.set(gen, dek.rawBytes);
    chain.push({ gen, key: dek.gcmKey });
  }

  const envelope = await clientCrypto.wrapDataKeyChainEnvelope(
    chain,
    [
      { name: clientCrypto.FACTOR_PASSWORD, wrappingKey: cek.kwKey },
      { name: clientCrypto.FACTOR_RECOVERY_PHRASE, wrappingKey: recoveryKEK.kwKey },
    ],
    { salt: recoverySalt },
  );
  return { envelope, recoverySalt, dekRawByGen };
}

describe('unwrap pipeline: round-trip via password factor', () => {
  it('single-gen envelope unwraps to byte-identical DEK', async () => {
    const { envelope, dekRawByGen } = await buildSyntheticEnvelope(1);

    const kek = await derivePasswordKEK({
      username: TEST_USERNAME,
      password: TEST_PASSWORD,
      appId: TEST_APP,
    });

    const result = await unwrapDekChain({
      envelope,
      kek,
      factor: FACTOR_PASSWORD,
    });

    assert.equal(result.currentGen, 1);
    assert.equal(result.dekByGen.size, 1);
    const recoveredBytes = await exportRaw(result.dekByGen.get(1)!.gcmKey);
    assert.ok(
      bytesEqual(recoveredBytes, dekRawByGen.get(1)!),
      'password-factor unwrap produced different DEK bytes',
    );
  });
});

describe('unwrap pipeline: round-trip via recovery_phrase factor', () => {
  it('single-gen envelope unwraps to byte-identical DEK', async () => {
    const { envelope, dekRawByGen } = await buildSyntheticEnvelope(1);

    const parsed = parseEnvelope(envelope);
    const kek = await deriveRecoveryKEK({
      accountKey: TEST_ACCOUNT_KEY,
      recoverySalt: parsed.recovery.salt,
      kdfParams: parsed.recovery.kdfParams,
    });

    const result = await unwrapDekChain({
      envelope,
      kek,
      factor: FACTOR_RECOVERY_PHRASE,
    });

    assert.equal(result.currentGen, 1);
    const recoveredBytes = await exportRaw(result.dekByGen.get(1)!.gcmKey);
    assert.ok(
      bytesEqual(recoveredBytes, dekRawByGen.get(1)!),
      'recovery-factor unwrap produced different DEK bytes',
    );
  });
});

describe('unwrap pipeline: same envelope, both factors produce same DEK', () => {
  it('password and recovery_phrase factors recover identical DEK chain', async () => {
    const { envelope, dekRawByGen } = await buildSyntheticEnvelope(1);

    const passwordKEK = await derivePasswordKEK({
      username: TEST_USERNAME,
      password: TEST_PASSWORD,
      appId: TEST_APP,
    });
    const parsed = parseEnvelope(envelope);
    const recoveryKEK = await deriveRecoveryKEK({
      accountKey: TEST_ACCOUNT_KEY,
      recoverySalt: parsed.recovery.salt,
      kdfParams: parsed.recovery.kdfParams,
    });

    const [pwResult, recResult] = await Promise.all([
      unwrapDekChain({ envelope, kek: passwordKEK, factor: FACTOR_PASSWORD }),
      unwrapDekChain({ envelope, kek: recoveryKEK, factor: FACTOR_RECOVERY_PHRASE }),
    ]);

    const pwBytes = await exportRaw(pwResult.dekByGen.get(1)!.gcmKey);
    const recBytes = await exportRaw(recResult.dekByGen.get(1)!.gcmKey);
    assert.ok(bytesEqual(pwBytes, recBytes));
    assert.ok(bytesEqual(pwBytes, dekRawByGen.get(1)!));
  });
});

describe('unwrap pipeline: multi-gen chain', () => {
  it('three-gen envelope yields all three DEKs in the map', async () => {
    const { envelope, dekRawByGen } = await buildSyntheticEnvelope(3);

    const parsed = parseEnvelope(envelope);
    const kek = await deriveRecoveryKEK({
      accountKey: TEST_ACCOUNT_KEY,
      recoverySalt: parsed.recovery.salt,
      kdfParams: parsed.recovery.kdfParams,
    });

    const result = await unwrapDekChain({
      envelope,
      kek,
      factor: FACTOR_RECOVERY_PHRASE,
    });

    assert.equal(result.currentGen, 3);
    assert.equal(result.dekByGen.size, 3);
    for (const gen of [1, 2, 3]) {
      const got = await exportRaw(result.dekByGen.get(gen)!.gcmKey);
      assert.ok(
        bytesEqual(got, dekRawByGen.get(gen)!),
        `gen ${gen} DEK bytes did not match expected`,
      );
    }
  });
});

describe('unwrap pipeline: end-to-end through decryptWithCEK', () => {
  it('unwrapped DEK can decrypt a per-content-CEK blob', async () => {
    const { envelope, dekRawByGen } = await buildSyntheticEnvelope(1);

    // Encrypt a payload using the original gen-1 DEK (writer side).
    const dekKw = await crypto.subtle.importKey(
      'raw',
      dekRawByGen.get(1)! as unknown as ArrayBuffer,
      'AES-KW',
      true,
      ['wrapKey', 'unwrapKey'],
    );
    const payload = { schema: 'tarn-test-v1', body: 'hello recover' };
    const { blob } = await clientCrypto.encryptWithCEK(dekKw, payload);

    // Now go through the recover pipeline.
    const parsed = parseEnvelope(envelope);
    const kek = await deriveRecoveryKEK({
      accountKey: TEST_ACCOUNT_KEY,
      recoverySalt: parsed.recovery.salt,
      kdfParams: parsed.recovery.kdfParams,
    });
    const { dekByGen, currentGen } = await unwrapDekChain({
      envelope,
      kek,
      factor: FACTOR_RECOVERY_PHRASE,
    });

    const recoveredPayload = await decryptWithCEK(
      dekByGen.get(currentGen)!.kwKey,
      blob,
    );
    assert.deepEqual(recoveredPayload, payload);
  });
});

describe('unwrap pipeline: input validation', () => {
  it('rejects unsupported factor', async () => {
    const { envelope } = await buildSyntheticEnvelope(1);
    const kek = await derivePasswordKEK({
      username: TEST_USERNAME,
      password: TEST_PASSWORD,
      appId: TEST_APP,
    });
    await assert.rejects(
      // Cast through `unknown` — the type system blocks this at compile
      // time (good!) but the runtime guard must still fire.
      () => unwrapDekChain({ envelope, kek, factor: 'passkey_prf' as unknown as 'password' }),
      /unsupported factor/,
    );
  });

  it('rejects empty envelope string', async () => {
    const kek = await derivePasswordKEK({
      username: TEST_USERNAME,
      password: TEST_PASSWORD,
      appId: TEST_APP,
    });
    await assert.rejects(
      () => unwrapDekChain({ envelope: '', kek, factor: FACTOR_PASSWORD }),
      /non-empty string/,
    );
  });

  it('derivePasswordKEK rejects empty inputs', async () => {
    await assert.rejects(
      () => derivePasswordKEK({ username: '', password: 'x', appId: 'a' }),
      /username/,
    );
    await assert.rejects(
      () => derivePasswordKEK({ username: 'u', password: '', appId: 'a' }),
      /password/,
    );
    await assert.rejects(
      () => derivePasswordKEK({ username: 'u', password: 'p', appId: '' }),
      /appId/,
    );
  });

  it('deriveRecoveryKEK rejects bad salt', async () => {
    await assert.rejects(
      () => deriveRecoveryKEK({
        accountKey: TEST_ACCOUNT_KEY,
        recoverySalt: 'not bytes' as unknown as Uint8Array,
      }),
      /Uint8Array/,
    );
  });
});
