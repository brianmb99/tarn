/**
 * Forward-compatibility test suite — runs every fixture in
 * `recover/fixtures/envelope-vN/` through the full `@tarn/recover`
 * pipeline and asserts byte-for-byte equality on the recovered DEKs and
 * plaintext.
 *
 * **This test must pass on every release of `@tarn/recover@vN` for all `N`
 * going forward.** Adding a new envelope version means adding new fixture
 * files alongside the old ones; the old fixture rows here keep running
 * forever. See `recover/fixtures/README.md` for the contract narrative.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  parseWrappedDataKey,
  unwrapDataKeyChain,
  readEnvelopeVersion,
} from '../src/crypto/envelope/index.js';
import {
  decryptWithCEK,
  unwrapAccountKey,
  FACTOR_PASSWORD,
  FACTOR_RECOVERY_PHRASE,
} from '../src/crypto/index.js';
import {
  derivePasswordKEK,
  deriveRecoveryKEK,
} from '../src/decrypt/derive-keys.js';

const here = fileURLToPath(new URL('.', import.meta.url));
const fixturesRoot = resolve(here, '..', 'fixtures');

type Fixture = {
  name: string;
  description: string;
  version: number;
  model: 'A' | 'B';
  inputs: {
    username: string;
    password: string;
    appId: string;
    accountKey: string;
  };
  wrappedDataKey: string;
  wrappedAccountKey?: string;
  expected: {
    currentGen: number;
    totalGens: number;
    dekRawByGen: Record<string, string>; // hex
    contentBlob: { hex: string; plaintext: unknown };
    unwrappedAccountKey?: string;
  };
};

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`hex string must have even length, got ${hex.length}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function exportRaw(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

/** Walk fixtures/ and collect every `envelope-vN/*.json` file. */
function discoverFixtures(): { version: number; path: string; fixture: Fixture }[] {
  const out: { version: number; path: string; fixture: Fixture }[] = [];
  for (const entry of readdirSync(fixturesRoot)) {
    if (!entry.startsWith('envelope-v')) continue;
    const versionDir = join(fixturesRoot, entry);
    const st = statSync(versionDir);
    if (!st.isDirectory()) continue;
    const versionMatch = entry.match(/^envelope-v(\d+)$/);
    if (!versionMatch || !versionMatch[1]) {
      throw new Error(`fixture directory has malformed name: ${entry}`);
    }
    const version = Number.parseInt(versionMatch[1], 10);
    for (const file of readdirSync(versionDir)) {
      if (!file.endsWith('.json')) continue;
      const full = join(versionDir, file);
      const fixture = JSON.parse(readFileSync(full, 'utf8')) as Fixture;
      out.push({ version, path: full, fixture });
    }
  }
  // Stable ordering — version asc, then filename asc.
  out.sort((a, b) => {
    if (a.version !== b.version) return a.version - b.version;
    return a.path.localeCompare(b.path);
  });
  return out;
}

const fixtures = discoverFixtures();

if (fixtures.length === 0) {
  // Loud failure: a contract that has no enforcement is no contract at all.
  throw new Error(
    `forward-compat: no fixtures found under ${fixturesRoot}/envelope-v*/. ` +
    `The forward-compat contract requires at least one fixture per supported ` +
    `envelope version (see recover/fixtures/README.md).`,
  );
}

describe('forward-compat: envelope dispatch + decoder pipeline', () => {
  for (const { version, fixture } of fixtures) {
    describe(fixture.name, () => {
      it('dispatch routes to the correct decoder version', () => {
        const observed = readEnvelopeVersion(fixture.wrappedDataKey);
        assert.equal(observed, version, `envelope v field mismatch`);
        assert.equal(observed, fixture.version, `fixture.version mismatch`);
      });

      it('parses without error and exposes expected shape', () => {
        const parsed = parseWrappedDataKey(fixture.wrappedDataKey);
        assert.equal(parsed.envelopeVersion, version);
        assert.equal(parsed.dekChain.length, fixture.expected.totalGens);
        assert.equal(
          parsed.dekChain[parsed.dekChain.length - 1]!.gen,
          fixture.expected.currentGen,
        );
      });

      it('unwraps via password factor → byte-equal DEK chain', async () => {
        const kek = await derivePasswordKEK({
          username: fixture.inputs.username,
          password: fixture.inputs.password,
          appId: fixture.inputs.appId,
        });
        const result = await unwrapDataKeyChain(
          fixture.wrappedDataKey,
          kek,
          FACTOR_PASSWORD,
        );
        assert.equal(result.currentGen, fixture.expected.currentGen);
        assert.equal(result.dekByGen.size, fixture.expected.totalGens);
        for (const [genStr, expectedHex] of Object.entries(fixture.expected.dekRawByGen)) {
          const gen = Number.parseInt(genStr, 10);
          const handle = result.dekByGen.get(gen);
          assert.ok(handle, `gen ${gen} missing from unwrapped chain`);
          const observed = await exportRaw(handle.gcmKey);
          assert.ok(
            bytesEqual(observed, hexToBytes(expectedHex)),
            `gen ${gen} DEK bytes did not match expected fixture value`,
          );
        }
      });

      it('unwraps via recovery_phrase factor → byte-equal DEK chain', async () => {
        const parsed = parseWrappedDataKey(fixture.wrappedDataKey);
        const kek = await deriveRecoveryKEK({
          accountKey: fixture.inputs.accountKey,
          recoverySalt: parsed.recovery.salt,
          kdfParams: parsed.recovery.kdfParams,
        });
        const result = await unwrapDataKeyChain(
          fixture.wrappedDataKey,
          kek,
          FACTOR_RECOVERY_PHRASE,
        );
        assert.equal(result.currentGen, fixture.expected.currentGen);
        for (const [genStr, expectedHex] of Object.entries(fixture.expected.dekRawByGen)) {
          const gen = Number.parseInt(genStr, 10);
          const handle = result.dekByGen.get(gen);
          assert.ok(handle, `gen ${gen} missing from unwrapped chain`);
          const observed = await exportRaw(handle.gcmKey);
          assert.ok(
            bytesEqual(observed, hexToBytes(expectedHex)),
            `gen ${gen} DEK bytes did not match expected fixture value`,
          );
        }
      });

      it('content blob round-trips to the expected plaintext', async () => {
        const kek = await derivePasswordKEK({
          username: fixture.inputs.username,
          password: fixture.inputs.password,
          appId: fixture.inputs.appId,
        });
        const result = await unwrapDataKeyChain(
          fixture.wrappedDataKey,
          kek,
          FACTOR_PASSWORD,
        );
        const dekGen1 = result.dekByGen.get(1);
        assert.ok(dekGen1, 'fixture must have a gen 1 DEK to decrypt the content blob');
        const blobBytes = hexToBytes(fixture.expected.contentBlob.hex);
        const plaintext = await decryptWithCEK(dekGen1.kwKey, blobBytes);
        assert.deepEqual(plaintext, fixture.expected.contentBlob.plaintext);
      });

      if (fixture.model === 'B') {
        it('Model B: wrapped_account_key unwraps to original account key', async () => {
          assert.ok(fixture.wrappedAccountKey, 'Model B fixture must carry wrappedAccountKey');
          assert.ok(
            fixture.expected.unwrappedAccountKey,
            'Model B fixture must pin expected unwrappedAccountKey',
          );
          const kek = await derivePasswordKEK({
            username: fixture.inputs.username,
            password: fixture.inputs.password,
            appId: fixture.inputs.appId,
          });
          const result = await unwrapDataKeyChain(
            fixture.wrappedDataKey,
            kek,
            FACTOR_PASSWORD,
          );
          const dekGen1 = result.dekByGen.get(1);
          assert.ok(dekGen1, 'gen 1 DEK required to unwrap wrapped_account_key');
          const phrase = await unwrapAccountKey(dekGen1.gcmKey, fixture.wrappedAccountKey);
          assert.equal(
            phrase,
            fixture.expected.unwrappedAccountKey,
            'wrapped_account_key did not decrypt to expected phrase',
          );
        });
      }
    });
  }
});
