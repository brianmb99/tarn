#!/usr/bin/env node
/**
 * Fixture generator for the @tarn/recover forward-compat suite.
 *
 * # READ THIS BEFORE RUNNING
 *
 * This script generates fixture files in `recover/fixtures/envelope-vN/`.
 * Each fixture file is a frozen artifact: **once committed, never modified
 * or regenerated**. Re-running this script with the same inputs produces
 * different envelopes (random salts, IVs, DEK bytes) — the fixture vault
 * captures one specific run, and the test suite validates that
 * `@tarn/recover` can still decrypt that specific run on every future
 * release.
 *
 * Use this script when:
 *   - You ship a new envelope version (write generator code for vN, then
 *     emit fixtures for the new shapes alongside existing files).
 *   - You ship a new fixture variant for an existing version (a new
 *     edge case worth pinning).
 *
 * Do NOT use this script to "refresh" or "regenerate" existing fixture
 * files. The contract enforcement is meaningful only because the bytes
 * are stable.
 *
 * # What gets emitted
 *
 * For each fixture, a JSON file containing:
 *   - `name`: human-readable label.
 *   - `description`: what scenario this covers.
 *   - `version`: envelope version (1 today).
 *   - `inputs`: deterministic credentials used at generation time.
 *   - `wrappedDataKey`: the wire envelope (the JSON string published as
 *     `wrapped_data_key` in the credential blob).
 *   - `wrappedAccountKey` (Model B only): the AAD'd `wrapped_account_key`
 *     ciphertext.
 *   - `expected.dekRawByGen`: per-gen DEK raw bytes (hex). The recover
 *     pipeline must produce these byte-for-byte after unwrap.
 *   - `expected.contentBlob`: a per-content-CEK blob encrypted under
 *     gen-1 DEK (hex), plus the expected plaintext after `decryptWithCEK`.
 *
 * After generating new fixtures, also append their hash to
 * `recover/fixtures/manifest.json` (the meta-test compares manifest
 * entries to filesystem hashes).
 */

import { mkdir, writeFile, readFile, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

import * as clientCrypto from '../../client/src/crypto.js';

const here = fileURLToPath(new URL('.', import.meta.url));
const fixturesRoot = resolve(here, '..', 'fixtures');
const v1Dir = resolve(fixturesRoot, 'envelope-v1');

await mkdir(v1Dir, { recursive: true });

// ============ Deterministic test credentials ============
//
// These are NOT real user credentials. They are public, fixed, and used
// only by the fixture suite. They appear in committed fixture files.
//
// Account key is a valid 24-word BIP39 mnemonic (the standard
// "abandon ... art" test vector).

const TEST_USERNAME = 'phase6-fixture@example.com';
const TEST_PASSWORD = 'phase6-fixture-pw-DO-NOT-REUSE';
const TEST_APP = 'tarn-recover-fixture-app';
const TEST_ACCOUNT_KEY =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';

// ============ Helpers ============

function bytesToHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

async function exportRaw(key) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

/**
 * Build a v1 envelope with `genCount` chain entries, each wrapped under
 * password + recovery_phrase. Returns the wire envelope plus the per-gen
 * DEK raw bytes (so the fixture can pin them).
 */
async function buildEnvelope({ genCount }) {
  const recoverySalt = clientCrypto.generateRecoverySalt();
  const masterKey = await clientCrypto.deriveMasterKey(TEST_USERNAME, TEST_PASSWORD);
  const cek = await clientCrypto.deriveCredentialEncryptionKey(masterKey, TEST_APP);
  const recoveryKEK = await clientCrypto.deriveRecoveryKey(TEST_ACCOUNT_KEY, recoverySalt);

  const dekRawByGen = {};
  const dekHandlesByGen = new Map();
  const chain = [];
  for (let gen = 1; gen <= genCount; gen++) {
    const dek = await clientCrypto.generateRandomDataKey();
    dekRawByGen[String(gen)] = bytesToHex(dek.rawBytes);
    dekHandlesByGen.set(gen, dek);
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
  return { envelope, dekRawByGen, dekHandlesByGen };
}

/**
 * Encrypt a plaintext under gen-1's DEK using `encryptWithCEK` (the same
 * code path the live SDK uses for collection content). Returns the blob
 * bytes (hex) and the plaintext for round-trip pinning.
 */
async function buildContentBlob({ dekHandlesByGen, plaintext }) {
  const dekGen1 = dekHandlesByGen.get(1);
  if (!dekGen1) throw new Error('content blob requires at least gen 1');
  // encryptWithCEK takes an AES-KW handle (it AES-KW-wraps the per-blob CEK
  // under the DEK). Use the kwKey side of the pair.
  const dekKw = await crypto.subtle.importKey(
    'raw',
    dekGen1.rawBytes,
    'AES-KW',
    true,
    ['wrapKey', 'unwrapKey'],
  );
  const { blob } = await clientCrypto.encryptWithCEK(dekKw, plaintext);
  return { blobHex: bytesToHex(blob), plaintext };
}

/**
 * Build a Model B-style `wrapped_account_key`: the user's account-key
 * string AES-GCM-encrypted under gen-1's DEK with the fixed AAD.
 */
async function buildWrappedAccountKey({ dekHandlesByGen, accountKey }) {
  const dekGen1 = dekHandlesByGen.get(1);
  if (!dekGen1) throw new Error('Model B wrap requires gen 1 DEK');
  return await clientCrypto.wrapAccountKey(dekGen1.gcmKey, accountKey);
}

async function emitFixture(filename, fixture) {
  const path = join(v1Dir, filename);
  if (existsSync(path)) {
    console.log(`[skip] ${filename} already exists — fixture vault is immutable.`);
    return;
  }
  await writeFile(path, JSON.stringify(fixture, null, 2) + '\n', 'utf8');
  console.log(`[emit] ${filename}`);
}

// ============ Fixture: single-gen Model A ============
{
  const { envelope, dekRawByGen, dekHandlesByGen } = await buildEnvelope({ genCount: 1 });
  const content = await buildContentBlob({
    dekHandlesByGen,
    plaintext: { item: 'fixture-single-gen-A', n: 1, note: 'frozen 2026-05-08' },
  });
  await emitFixture('single-gen-model-a.json', {
    name: 'envelope-v1 single-gen Model A',
    description:
      'Account just registered: one DEK gen, password + recovery_phrase wrappings, ' +
      'no wrapped_account_key on the credential blob (Model A).',
    version: 1,
    model: 'A',
    inputs: {
      username: TEST_USERNAME,
      password: TEST_PASSWORD,
      appId: TEST_APP,
      accountKey: TEST_ACCOUNT_KEY,
    },
    wrappedDataKey: envelope,
    expected: {
      currentGen: 1,
      totalGens: 1,
      dekRawByGen,
      contentBlob: { hex: content.blobHex, plaintext: content.plaintext },
    },
  });
}

// ============ Fixture: single-gen Model B ============
{
  const { envelope, dekRawByGen, dekHandlesByGen } = await buildEnvelope({ genCount: 1 });
  const wak = await buildWrappedAccountKey({
    dekHandlesByGen,
    accountKey: TEST_ACCOUNT_KEY,
  });
  const content = await buildContentBlob({
    dekHandlesByGen,
    plaintext: { item: 'fixture-single-gen-B', n: 2, note: 'Model B retains wrapped_account_key' },
  });
  await emitFixture('single-gen-model-b.json', {
    name: 'envelope-v1 single-gen Model B',
    description:
      'Account that opted into server-side account-key storage (Model B): same ' +
      'envelope shape as A plus a wrapped_account_key ciphertext under the gen-1 DEK ' +
      '(AAD: tarn-wrapped-account-key-v1).',
    version: 1,
    model: 'B',
    inputs: {
      username: TEST_USERNAME,
      password: TEST_PASSWORD,
      appId: TEST_APP,
      accountKey: TEST_ACCOUNT_KEY,
    },
    wrappedDataKey: envelope,
    wrappedAccountKey: wak,
    expected: {
      currentGen: 1,
      totalGens: 1,
      dekRawByGen,
      contentBlob: { hex: content.blobHex, plaintext: content.plaintext },
      // The unwrapped wrapped_account_key MUST equal TEST_ACCOUNT_KEY exactly.
      unwrappedAccountKey: TEST_ACCOUNT_KEY,
    },
  });
}

// ============ Fixture: multi-gen Model A (3 gens) ============
{
  const { envelope, dekRawByGen, dekHandlesByGen } = await buildEnvelope({ genCount: 3 });
  const content = await buildContentBlob({
    dekHandlesByGen,
    plaintext: {
      item: 'fixture-multi-gen-A',
      n: 3,
      note: 'simulates an account through 2 changeCredentials runs',
    },
  });
  await emitFixture('multi-gen-model-a.json', {
    name: 'envelope-v1 multi-gen Model A (3 gens)',
    description:
      'Account that has been through changeCredentials twice — three DEK ' +
      'generations, every gen wrapped under both factors. Content is encrypted ' +
      'under gen-1 (oldest gen still reachable).',
    version: 1,
    model: 'A',
    inputs: {
      username: TEST_USERNAME,
      password: TEST_PASSWORD,
      appId: TEST_APP,
      accountKey: TEST_ACCOUNT_KEY,
    },
    wrappedDataKey: envelope,
    expected: {
      currentGen: 3,
      totalGens: 3,
      dekRawByGen,
      contentBlob: { hex: content.blobHex, plaintext: content.plaintext },
    },
  });
}

// ============ Fixture: multi-gen Model B (2 gens) ============
{
  const { envelope, dekRawByGen, dekHandlesByGen } = await buildEnvelope({ genCount: 2 });
  const wak = await buildWrappedAccountKey({
    dekHandlesByGen,
    accountKey: TEST_ACCOUNT_KEY,
  });
  const content = await buildContentBlob({
    dekHandlesByGen,
    plaintext: { item: 'fixture-multi-gen-B', n: 4, note: 'Model B + multi-gen' },
  });
  await emitFixture('multi-gen-model-b.json', {
    name: 'envelope-v1 multi-gen Model B (2 gens)',
    description:
      'Account with two DEK gens AND server-side account-key storage. Exercises ' +
      'the full multi-gen + wrapped_account_key combination.',
    version: 1,
    model: 'B',
    inputs: {
      username: TEST_USERNAME,
      password: TEST_PASSWORD,
      appId: TEST_APP,
      accountKey: TEST_ACCOUNT_KEY,
    },
    wrappedDataKey: envelope,
    wrappedAccountKey: wak,
    expected: {
      currentGen: 2,
      totalGens: 2,
      dekRawByGen,
      contentBlob: { hex: content.blobHex, plaintext: content.plaintext },
      unwrappedAccountKey: TEST_ACCOUNT_KEY,
    },
  });
}

// ============ Manifest update ============
//
// Compute SHA-256 of every fixture JSON file under fixtures/ and write the
// manifest. The fixture-vault meta-test reads this file and re-hashes the
// filesystem; any drift (added file not in manifest, modified file, or
// missing file) fails the test.

const manifestPath = join(fixturesRoot, 'manifest.json');
const fixtureFiles = [];
async function collectFixtures(dir, relPrefix) {
  const { readdir } = await import('node:fs/promises');
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      await collectFixtures(full, rel);
    } else if (entry.name.endsWith('.json') && entry.name !== 'manifest.json') {
      const bytes = await readFile(full);
      const hash = createHash('sha256').update(bytes).digest('hex');
      fixtureFiles.push({ path: rel, sha256: hash, sizeBytes: bytes.length });
    }
  }
}
await collectFixtures(fixturesRoot, '');
fixtureFiles.sort((a, b) => a.path.localeCompare(b.path));

const manifest = {
  comment:
    'Hash manifest for the @tarn/recover fixture vault. Fixtures are immutable: ' +
    'this manifest grows monotonically. The meta-test (recover/tests/fixture-vault.test.ts) ' +
    'fails if any tracked file is missing, modified, or if a new file is present that is ' +
    'not in the manifest. To add fixtures: run scripts/generate-fixtures.mjs (which appends), ' +
    'commit the new files plus the regenerated manifest.',
  generatedBy: basename(import.meta.url),
  fixtures: fixtureFiles,
};
await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
console.log(`[manifest] wrote ${fixtureFiles.length} entries to ${manifestPath}`);

await stat(manifestPath); // sanity-check
console.log('done.');
