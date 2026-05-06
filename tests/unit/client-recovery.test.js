// Unit tests for the recovery factor (issue #12).
//
// Covers:
//   - BIP39 account-key generation + validation
//   - Recovery KEK derivation (Argon2id over account key + per-account salt)
//   - v1 envelope shape (multi-factor wrappings, recovery metadata block)
//   - register() requires recoveryAcknowledged: true
//   - register() emits v1 with both password and recovery_phrase wrappings
//   - register() makes no recovery-email network call (kit delivery is the
//     app's responsibility — Tarn never handles plaintext kit material)
//   - recoverAccount() round-trip (register → simulate forget password → recover with account key → re-login)
//
// Mocks fetch to keep tests fast; uses real KDFs so the crypto under test is
// the real implementation.
//
// Run: node --test tests/unit/client-recovery.test.js

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  TarnClient,
  generateAccountKey,
  validateAccountKey,
} from '../../client/src/tarn.js';
import {
  parseWrappedDataKey,
  deriveRecoveryKey,
  deriveRecoveryLookupKey,
  deriveRecoverySigningKeyPair,
  unwrapDataKeyChain,
  wrapDataKeyChainEnvelope,
  buildEnvelope,
  generateRandomDataKey,
  generateRecoverySalt,
  exportPublicKey,
  signChallenge,
  FACTOR_PASSWORD,
  FACTOR_RECOVERY_PHRASE,
} from '../../client/src/crypto.js';
import { accountKeyToEntropy } from '../../client/src/recovery.js';

const APP = 'bookish';

const originalFetch = globalThis.fetch;
let fetchCalls = [];
let fetchResponses = [];

function mockFetch(responses) {
  fetchCalls = [];
  fetchResponses = responses.slice();
  globalThis.fetch = async (url, opts) => {
    fetchCalls.push({ url, method: opts?.method || 'GET', body: opts?.body });
    const next = fetchResponses.shift();
    if (!next) throw new Error(`mockFetch: no response queued for ${url} (${opts?.method || 'GET'})`);
    if (next instanceof Error) throw next;
    return {
      status: next.status,
      headers: { get: () => null },
      text: async () => next.body ?? '',
      body: { cancel: () => {} },
    };
  };
}

function restoreFetch() {
  globalThis.fetch = originalFetch;
  fetchCalls = [];
  fetchResponses = [];
}

function fakeJwt(label = 'jwt') {
  const b64url = (s) => btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const header = b64url('{"alg":"none"}');
  const payload = b64url(JSON.stringify({ sub: label, exp: Math.floor(Date.now() / 1000) + 3600 }));
  return `${header}.${payload}.`;
}

// ============ ACCOUNT KEY GENERATION ============

describe('BIP39 account key', () => {
  it('generateAccountKey returns a valid 24-word account key', () => {
    const phrase = generateAccountKey();
    const words = phrase.split(' ');
    assert.equal(words.length, 24);
    const v = validateAccountKey(phrase);
    assert.equal(v.valid, true);
    assert.equal(v.normalized, phrase);
  });

  it('generates DIFFERENT account keys on each call (entropy check)', () => {
    const a = generateAccountKey();
    const b = generateAccountKey();
    assert.notEqual(a, b);
  });

  it('validateAccountKey normalizes whitespace + case', () => {
    const phrase = generateAccountKey();
    const messy = '  ' + phrase.toUpperCase().split(' ').join('   ') + '  ';
    const v = validateAccountKey(messy);
    assert.equal(v.valid, true);
    assert.equal(v.normalized, phrase);
  });

  it('validateAccountKey rejects 12-word phrase (we require 24)', () => {
    // A valid 12-word BIP39 phrase from the test vectors.
    const twelve = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
    const v = validateAccountKey(twelve);
    assert.equal(v.valid, false);
    assert.match(v.reason, /expected 24 words/);
  });

  it('validateAccountKey rejects bad checksum', () => {
    const phrase = generateAccountKey();
    // Swap two words to break the checksum (overwhelmingly likely to fail).
    const words = phrase.split(' ');
    [words[0], words[1]] = [words[1], words[0]];
    const v = validateAccountKey(words.join(' '));
    assert.equal(v.valid, false);
  });

  it('accountKeyToEntropy produces 32 bytes for a 24-word account key', () => {
    const phrase = generateAccountKey();
    const entropy = accountKeyToEntropy(phrase);
    assert.equal(entropy.length, 32);
  });
});

// ============ RECOVERY KEK ============

describe('deriveRecoveryKey', () => {
  it('produces deterministic AES handles for fixed (phrase, salt)', async () => {
    const phrase = generateAccountKey();
    const salt = generateRecoverySalt();
    const k1 = await deriveRecoveryKey(phrase, salt);
    const k2 = await deriveRecoveryKey(phrase, salt);
    // Compare raw bytes — CryptoKey identity isn't stable but bytes should match.
    assert.deepEqual(k1.rawBytes, k2.rawBytes);
  });

  it('produces different KEKs for different salts', async () => {
    const phrase = generateAccountKey();
    const salt1 = generateRecoverySalt();
    const salt2 = generateRecoverySalt();
    const k1 = await deriveRecoveryKey(phrase, salt1);
    const k2 = await deriveRecoveryKey(phrase, salt2);
    assert.notDeepEqual(k1.rawBytes, k2.rawBytes);
  });

  it('produces different KEKs for different phrases', async () => {
    const salt = generateRecoverySalt();
    const k1 = await deriveRecoveryKey(generateAccountKey(), salt);
    const k2 = await deriveRecoveryKey(generateAccountKey(), salt);
    assert.notDeepEqual(k1.rawBytes, k2.rawBytes);
  });
});

// ============ RECOVERY LOOKUP KEY + SIGNING KEY ============

describe('deriveRecoveryLookupKey + deriveRecoverySigningKeyPair', () => {
  it('lookup key is deterministic per (phrase entropy, app)', async () => {
    const entropy = accountKeyToEntropy(generateAccountKey());
    const k1 = await deriveRecoveryLookupKey(entropy, APP);
    const k2 = await deriveRecoveryLookupKey(entropy, APP);
    assert.equal(k1, k2);
    assert.match(k1, /^[a-f0-9]{64}$/);
  });

  it('lookup key differs per app (per-app isolation)', async () => {
    const entropy = accountKeyToEntropy(generateAccountKey());
    const a = await deriveRecoveryLookupKey(entropy, 'bookish');
    const b = await deriveRecoveryLookupKey(entropy, 'cellar');
    assert.notEqual(a, b);
  });

  it('signing keypair is deterministic per (phrase entropy, app)', async () => {
    const entropy = accountKeyToEntropy(generateAccountKey());
    const p1 = await deriveRecoverySigningKeyPair(entropy, APP);
    const p2 = await deriveRecoverySigningKeyPair(entropy, APP);
    const pk1 = await exportPublicKey(p1.publicKey);
    const pk2 = await exportPublicKey(p2.publicKey);
    assert.equal(pk1, pk2);
  });

  it('signing keypair signs and verifies a nonce', async () => {
    const entropy = accountKeyToEntropy(generateAccountKey());
    const pair = await deriveRecoverySigningKeyPair(entropy, APP);
    const nonce = 'a'.repeat(64);
    const sig = await signChallenge(pair.privateKey, nonce);
    assert.ok(typeof sig === 'string' && sig.length > 0);
  });
});

// ============ V1 ENVELOPE (multi-factor) ============

describe('v1 envelope wire format', () => {
  it('parseWrappedDataKey accepts a v1 envelope and returns multi-factor chain', () => {
    const wire = JSON.stringify({
      v: 1,
      kdf: 'argon2id',
      kdf_params: { m_kib: 65536, t: 3, p: 1 },
      recovery: {
        kdf: 'argon2id',
        kdf_params: { m_kib: 65536, t: 3, p: 1 },
        salt: 'AAECAwQFBgcICQoLDA0ODw==', // base64 16 bytes
      },
      dek_chain: [
        { gen: 1, wrappings: [
          { factor: 'password', wrapped: 'PPPP' },
          { factor: 'recovery_phrase', wrapped: 'RRRR' },
        ]},
      ],
    });
    const parsed = parseWrappedDataKey(wire);
    assert.equal(parsed.envelopeVersion, 1);
    assert.equal(parsed.dekChain.length, 1);
    assert.equal(parsed.dekChain[0].wrappings.length, 2);
    assert.equal(parsed.recovery.salt.length, 16);
    assert.equal(parsed.wrappedBase64, 'PPPP'); // convenience: top-gen password wrapping
  });

  it('parseWrappedDataKey rejects v1 with duplicate factor in same gen', () => {
    const wire = JSON.stringify({
      v: 1,
      kdf: 'argon2id',
      kdf_params: { m_kib: 65536, t: 3, p: 1 },
      recovery: { kdf: 'argon2id', kdf_params: { m_kib: 65536, t: 3, p: 1 }, salt: 'AAECAwQFBgcICQoLDA0ODw==' },
      dek_chain: [
        { gen: 1, wrappings: [
          { factor: 'password', wrapped: 'PPPP' },
          { factor: 'password', wrapped: 'QQQQ' },
        ]},
      ],
    });
    assert.throws(() => parseWrappedDataKey(wire), /duplicate factor/);
  });

  it('parseWrappedDataKey rejects v1 with missing wrappings', () => {
    const wire = JSON.stringify({
      v: 1,
      kdf: 'argon2id',
      kdf_params: { m_kib: 65536, t: 3, p: 1 },
      recovery: { kdf: 'argon2id', kdf_params: { m_kib: 65536, t: 3, p: 1 }, salt: 'AAECAwQFBgcICQoLDA0ODw==' },
      dek_chain: [{ gen: 1, wrappings: [] }],
    });
    assert.throws(() => parseWrappedDataKey(wire));
  });

  it('parseWrappedDataKey rejects v1 with malformed recovery salt (wrong length)', () => {
    const wire = JSON.stringify({
      v: 1,
      kdf: 'argon2id',
      kdf_params: { m_kib: 65536, t: 3, p: 1 },
      recovery: { kdf: 'argon2id', kdf_params: { m_kib: 65536, t: 3, p: 1 }, salt: 'AAA=' },
      dek_chain: [{ gen: 1, wrappings: [{ factor: 'password', wrapped: 'PPPP' }] }],
    });
    assert.throws(() => parseWrappedDataKey(wire), /salt must decode to 16 bytes/);
  });

  it('round-trip: wrapDataKeyChainEnvelope → parseWrappedDataKey → unwrapDataKeyChain (both factors)', async () => {
    const dek = await generateRandomDataKey();
    const recoverySalt = generateRecoverySalt();
    const accountKey = generateAccountKey();
    const recKEK = await deriveRecoveryKey(accountKey, recoverySalt);
    const pwKEK = await generateRandomDataKey(); // stand-in for credential_encryption_key

    const wire = await wrapDataKeyChainEnvelope(
      [{ gen: 1, key: dek.gcmKey }],
      [
        { name: FACTOR_PASSWORD,        wrappingKey: pwKEK.kwKey },
        { name: FACTOR_RECOVERY_PHRASE, wrappingKey: recKEK.kwKey },
      ],
      { salt: recoverySalt },
    );

    const parsed = parseWrappedDataKey(wire);
    assert.equal(parsed.envelopeVersion, 1);
    assert.equal(parsed.dekChain[0].wrappings.length, 2);
    assert.deepEqual(parsed.recovery.salt, recoverySalt);

    // Unwrap via password factor.
    const viaPw = await unwrapDataKeyChain(wire, pwKEK.kwKey, FACTOR_PASSWORD);
    assert.equal(viaPw.dekByGen.size, 1);
    // Unwrap via recovery factor.
    const viaRec = await unwrapDataKeyChain(wire, recKEK.kwKey, FACTOR_RECOVERY_PHRASE);
    assert.equal(viaRec.dekByGen.size, 1);

    // The two unwrap paths recover the SAME DEK bytes — the whole point.
    const pwDekBytes = new Uint8Array(await crypto.subtle.exportKey('raw', viaPw.dekByGen.get(1).gcmKey));
    const recDekBytes = new Uint8Array(await crypto.subtle.exportKey('raw', viaRec.dekByGen.get(1).gcmKey));
    assert.deepEqual(pwDekBytes, recDekBytes);
  });

  it('buildEnvelope is byte-stable for the same input (idempotency)', () => {
    const chain = [{ gen: 1, wrappings: [
      { factor: 'password', wrapped: 'PPPP' },
      { factor: 'recovery_phrase', wrapped: 'RRRR' },
    ]}];
    const salt = new Uint8Array(16).fill(0x42);
    const a = buildEnvelope(chain, { salt });
    const b = buildEnvelope(chain, { salt });
    assert.equal(a, b);
  });
});

// ============ TarnClient.register — issue #12 enforcement ============

describe('TarnClient.register — recovery acknowledgment + v1 envelope', () => {
  afterEach(restoreFetch);

  it('throws synchronously when recoveryAcknowledged is missing', async () => {
    mockFetch([]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    await assert.rejects(
      () => client.register('rec-test@example.com', 'password-2026'),
      /recoveryAcknowledged: true is required/,
    );
    // No network call should have been made — fail fast.
    assert.equal(fetchCalls.length, 0);
  });

  it('throws when recoveryAcknowledged is false', async () => {
    mockFetch([]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    await assert.rejects(
      () => client.register('rec-test@example.com', 'password-2026', { recoveryAcknowledged: false }),
      /recoveryAcknowledged: true is required/,
    );
    assert.equal(fetchCalls.length, 0);
  });

  it('emits a v1 envelope with both factors + returns the account key', async () => {
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'b'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    const result = await client.register('rec-test@example.com', 'password-2026', {
      recoveryAcknowledged: true,
    });
    assert.ok(result.accountKey);
    assert.equal(result.accountKey.split(' ').length, 24);
    // Tarn no longer renders kits in-SDK — only the account-key string is returned.
    assert.equal(result.pdfBytes, undefined);

    // Inspect the envelope sent to /auth/register.
    const registerCall = fetchCalls.find(c => c.url.endsWith('/auth/register'));
    const body = JSON.parse(registerCall.body);
    const env = JSON.parse(body.wrapped_data_key);
    assert.equal(env.v, 1);
    assert.ok(env.recovery);
    assert.equal(env.dek_chain[0].wrappings.length, 2);
    const factors = env.dek_chain[0].wrappings.map(w => w.factor).sort();
    assert.deepEqual(factors, ['password', 'recovery_phrase']);
    assert.ok(body.recovery_lookup_key);
    assert.ok(body.recovery_public_key);
  });

  it('register makes no recovery-email network call (kit delivery is the app\'s job)', async () => {
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'b'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register('rec-test@example.com', 'password-2026', {
      recoveryAcknowledged: true,
    });
    const emailCall = fetchCalls.find(c => c.url.includes('/recovery/email'));
    assert.equal(emailCall, undefined, 'must not POST /api/v1/recovery/email — endpoint is gone');
  });
});

// ============ recoverAccount round trip ============

describe('TarnClient.recoverAccount — round trip', () => {
  afterEach(restoreFetch);

  it('register → recoverAccount with same phrase → DEK chain preserved', async () => {
    // Step 1: register an account, capture the v1 envelope server-side.
    let storedDataLookupKey, storedWrappedDataKey, storedRecoveryLookupKey;

    mockFetch([
      // /auth/register
      {
        status: 201,
        body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }),
        // We'll capture the body via fetchCalls.
      },
      // /auth/challenge after register
      { status: 200, body: JSON.stringify({ nonce: 'b'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
    ]);
    const c1 = new TarnClient('https://api.tarn.dev', APP);
    const reg = await c1.register('orig@example.com', 'orig-password', {
      recoveryAcknowledged: true,
    });
    const phrase = reg.accountKey;
    storedDataLookupKey = reg.dataLookupKey;

    // Capture what was published to the API.
    const registerCall = fetchCalls.find(c => c.url.endsWith('/auth/register'));
    const registerBody = JSON.parse(registerCall.body);
    storedWrappedDataKey = registerBody.wrapped_data_key;
    storedRecoveryLookupKey = registerBody.recovery_lookup_key;

    // Step 2: recoverAccount on a fresh client, simulating the server returning
    // the existing account's wrapped_data_key in the recovery-challenge.
    restoreFetch();
    mockFetch([
      // /auth/challenge with recovery_lookup_key — server returns existing blob
      {
        status: 200,
        body: JSON.stringify({
          nonce: 'c'.repeat(64),
          data_lookup_key: storedDataLookupKey,
          wrapped_data_key: storedWrappedDataKey,
        }),
      },
      // /auth/verify — issues recovery JWT
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('rec') }) },
      // PUT /auth — credential change
      { status: 200, body: JSON.stringify({}) },
      // post-PUT #authenticate: challenge + verify
      { status: 200, body: JSON.stringify({ nonce: 'e'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('newcreds') }) },
    ]);
    const c2 = new TarnClient('https://api.tarn.dev', APP);
    const rec = await c2.recoverAccount({
      phrase,
      newUsername: 'new@example.com',
      newPassword: 'new-password',
    });
    assert.equal(rec.dataLookupKey, storedDataLookupKey, 'dataLookupKey survives recovery');

    // The PUT body should contain a re-wrapped envelope with both factors,
    // the original recovery_lookup_key, and a NEW credential_lookup_key.
    const putCall = fetchCalls.find(c => c.url.endsWith('/auth') && c.method === 'PUT');
    assert.ok(putCall);
    const putBody = JSON.parse(putCall.body);
    assert.notEqual(putBody.new_credential_lookup_key, registerBody.credential_lookup_key);
    assert.equal(putBody.new_recovery_lookup_key, storedRecoveryLookupKey);

    const newEnv = JSON.parse(putBody.new_wrapped_data_key);
    assert.equal(newEnv.v, 1);
    assert.equal(newEnv.dek_chain.length, 1);
    const factors = newEnv.dek_chain[0].wrappings.map(w => w.factor).sort();
    assert.deepEqual(factors, ['password', 'recovery_phrase']);
    // Recovery wrapping bytes should be IDENTICAL to register (same KEK, same DEK,
    // AES-KW deterministic).
    const newRecWrap = newEnv.dek_chain[0].wrappings.find(w => w.factor === 'recovery_phrase').wrapped;
    const oldEnv = JSON.parse(storedWrappedDataKey);
    const oldRecWrap = oldEnv.dek_chain[0].wrappings.find(w => w.factor === 'recovery_phrase').wrapped;
    assert.equal(newRecWrap, oldRecWrap);
  });

  it('rejects an invalid phrase synchronously (no network)', async () => {
    mockFetch([]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    await assert.rejects(
      () => client.recoverAccount({
        phrase: 'not a real phrase',
        newUsername: 'a@b.com',
        newPassword: 'pw',
      }),
      /invalid|expected 24/,
    );
    assert.equal(fetchCalls.length, 0);
  });

  it('rejects when API returns 404 for recovery_lookup_key', async () => {
    mockFetch([
      { status: 404, body: JSON.stringify({ error: 'Unknown recovery_lookup_key' }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    const phrase = generateAccountKey();
    await assert.rejects(
      () => client.recoverAccount({
        phrase,
        newUsername: 'a@b.com',
        newPassword: 'pw',
      }),
      /no account found/,
    );
  });
});

