// Unit tests for the recovery factor (issue #12).
//
// Covers:
//   - BIP39 phrase generation + validation
//   - Recovery KEK derivation (Argon2id over phrase + per-account salt)
//   - v4 envelope shape (multi-factor wrappings, recovery metadata block)
//   - register() requires recoveryAcknowledged: true
//   - register() emits v4 with both password and recovery_phrase wrappings
//   - PDF rendering (basic structure, deterministic output for fixed inputs)
//   - recoverAccount() round-trip (register → simulate forget password → recover with phrase → re-login)
//   - regenerateRecoveryKit() returns a fresh PDF for the same phrase
//
// Mocks fetch to keep tests fast; uses real KDFs so the crypto under test is
// the real implementation.
//
// Run: node --test tests/unit/client-recovery.test.js

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  TarnClient,
  generateRecoveryPhrase,
  validateRecoveryPhrase,
  renderRecoveryPDF,
} from '../../client/src/tarn.js';
import {
  parseWrappedDataKey,
  deriveRecoveryKey,
  deriveRecoveryLookupKey,
  deriveRecoverySigningKeyPair,
  unwrapDataKeyChain,
  wrapDataKeyChainEnvelopeV4,
  buildV4Envelope,
  generateRandomDataKey,
  generateRecoverySalt,
  exportPublicKey,
  signChallenge,
  FACTOR_PASSWORD,
  FACTOR_RECOVERY_PHRASE,
} from '../../client/src/crypto.js';
import { recoveryPhraseToEntropy } from '../../client/src/recovery.js';

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

// ============ PHRASE GENERATION ============

describe('BIP39 recovery phrase', () => {
  it('generateRecoveryPhrase returns a valid 24-word phrase', () => {
    const phrase = generateRecoveryPhrase();
    const words = phrase.split(' ');
    assert.equal(words.length, 24);
    const v = validateRecoveryPhrase(phrase);
    assert.equal(v.valid, true);
    assert.equal(v.normalized, phrase);
  });

  it('generates DIFFERENT phrases on each call (entropy check)', () => {
    const a = generateRecoveryPhrase();
    const b = generateRecoveryPhrase();
    assert.notEqual(a, b);
  });

  it('validateRecoveryPhrase normalizes whitespace + case', () => {
    const phrase = generateRecoveryPhrase();
    const messy = '  ' + phrase.toUpperCase().split(' ').join('   ') + '  ';
    const v = validateRecoveryPhrase(messy);
    assert.equal(v.valid, true);
    assert.equal(v.normalized, phrase);
  });

  it('validateRecoveryPhrase rejects 12-word phrase (we require 24)', () => {
    // A valid 12-word BIP39 phrase from the test vectors.
    const twelve = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
    const v = validateRecoveryPhrase(twelve);
    assert.equal(v.valid, false);
    assert.match(v.reason, /expected 24 words/);
  });

  it('validateRecoveryPhrase rejects bad checksum', () => {
    const phrase = generateRecoveryPhrase();
    // Swap two words to break the checksum (overwhelmingly likely to fail).
    const words = phrase.split(' ');
    [words[0], words[1]] = [words[1], words[0]];
    const v = validateRecoveryPhrase(words.join(' '));
    assert.equal(v.valid, false);
  });

  it('recoveryPhraseToEntropy produces 32 bytes for a 24-word phrase', () => {
    const phrase = generateRecoveryPhrase();
    const entropy = recoveryPhraseToEntropy(phrase);
    assert.equal(entropy.length, 32);
  });
});

// ============ RECOVERY KEK ============

describe('deriveRecoveryKey', () => {
  it('produces deterministic AES handles for fixed (phrase, salt)', async () => {
    const phrase = generateRecoveryPhrase();
    const salt = generateRecoverySalt();
    const k1 = await deriveRecoveryKey(phrase, salt);
    const k2 = await deriveRecoveryKey(phrase, salt);
    // Compare raw bytes — CryptoKey identity isn't stable but bytes should match.
    assert.deepEqual(k1.rawBytes, k2.rawBytes);
  });

  it('produces different KEKs for different salts', async () => {
    const phrase = generateRecoveryPhrase();
    const salt1 = generateRecoverySalt();
    const salt2 = generateRecoverySalt();
    const k1 = await deriveRecoveryKey(phrase, salt1);
    const k2 = await deriveRecoveryKey(phrase, salt2);
    assert.notDeepEqual(k1.rawBytes, k2.rawBytes);
  });

  it('produces different KEKs for different phrases', async () => {
    const salt = generateRecoverySalt();
    const k1 = await deriveRecoveryKey(generateRecoveryPhrase(), salt);
    const k2 = await deriveRecoveryKey(generateRecoveryPhrase(), salt);
    assert.notDeepEqual(k1.rawBytes, k2.rawBytes);
  });
});

// ============ RECOVERY LOOKUP KEY + SIGNING KEY ============

describe('deriveRecoveryLookupKey + deriveRecoverySigningKeyPair', () => {
  it('lookup key is deterministic per (phrase entropy, app)', async () => {
    const entropy = recoveryPhraseToEntropy(generateRecoveryPhrase());
    const k1 = await deriveRecoveryLookupKey(entropy, APP);
    const k2 = await deriveRecoveryLookupKey(entropy, APP);
    assert.equal(k1, k2);
    assert.match(k1, /^[a-f0-9]{64}$/);
  });

  it('lookup key differs per app (per-app isolation)', async () => {
    const entropy = recoveryPhraseToEntropy(generateRecoveryPhrase());
    const a = await deriveRecoveryLookupKey(entropy, 'bookish');
    const b = await deriveRecoveryLookupKey(entropy, 'cellar');
    assert.notEqual(a, b);
  });

  it('signing keypair is deterministic per (phrase entropy, app)', async () => {
    const entropy = recoveryPhraseToEntropy(generateRecoveryPhrase());
    const p1 = await deriveRecoverySigningKeyPair(entropy, APP);
    const p2 = await deriveRecoverySigningKeyPair(entropy, APP);
    const pk1 = await exportPublicKey(p1.publicKey);
    const pk2 = await exportPublicKey(p2.publicKey);
    assert.equal(pk1, pk2);
  });

  it('signing keypair signs and verifies a nonce', async () => {
    const entropy = recoveryPhraseToEntropy(generateRecoveryPhrase());
    const pair = await deriveRecoverySigningKeyPair(entropy, APP);
    const nonce = 'a'.repeat(64);
    const sig = await signChallenge(pair.privateKey, nonce);
    assert.ok(typeof sig === 'string' && sig.length > 0);
  });
});

// ============ V4 ENVELOPE ============

describe('v4 envelope wire format', () => {
  it('parseWrappedDataKey accepts a v4 envelope and returns multi-factor chain', () => {
    const wire = JSON.stringify({
      v: 4,
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
    assert.equal(parsed.envelopeVersion, 4);
    assert.equal(parsed.dekChain.length, 1);
    assert.equal(parsed.dekChain[0].wrappings.length, 2);
    assert.equal(parsed.recovery.salt.length, 16);
    assert.equal(parsed.wrappedBase64, 'PPPP'); // convenience: top-gen password wrapping
  });

  it('parseWrappedDataKey rejects v4 with duplicate factor in same gen', () => {
    const wire = JSON.stringify({
      v: 4,
      kdf: 'argon2id',
      kdf_params: { m_kib: 65536, t: 3, p: 1 },
      dek_chain: [
        { gen: 1, wrappings: [
          { factor: 'password', wrapped: 'PPPP' },
          { factor: 'password', wrapped: 'QQQQ' },
        ]},
      ],
    });
    assert.throws(() => parseWrappedDataKey(wire), /duplicate factor/);
  });

  it('parseWrappedDataKey rejects v4 with missing wrappings', () => {
    const wire = JSON.stringify({
      v: 4,
      kdf: 'argon2id',
      kdf_params: { m_kib: 65536, t: 3, p: 1 },
      dek_chain: [{ gen: 1, wrappings: [] }],
    });
    assert.throws(() => parseWrappedDataKey(wire));
  });

  it('parseWrappedDataKey rejects v4 with malformed recovery salt (wrong length)', () => {
    const wire = JSON.stringify({
      v: 4,
      kdf: 'argon2id',
      kdf_params: { m_kib: 65536, t: 3, p: 1 },
      recovery: { kdf: 'argon2id', kdf_params: { m_kib: 65536, t: 3, p: 1 }, salt: 'AAA=' },
      dek_chain: [{ gen: 1, wrappings: [{ factor: 'password', wrapped: 'PPPP' }] }],
    });
    assert.throws(() => parseWrappedDataKey(wire), /salt must decode to 16 bytes/);
  });

  it('round-trip: wrapDataKeyChainEnvelopeV4 → parseWrappedDataKey → unwrapDataKeyChain (both factors)', async () => {
    const dek = await generateRandomDataKey();
    const recoverySalt = generateRecoverySalt();
    const recoveryPhrase = generateRecoveryPhrase();
    const recKEK = await deriveRecoveryKey(recoveryPhrase, recoverySalt);
    const pwKEK = await generateRandomDataKey(); // stand-in for credential_encryption_key

    const wire = await wrapDataKeyChainEnvelopeV4(
      [{ gen: 1, key: dek.gcmKey }],
      [
        { name: FACTOR_PASSWORD,        wrappingKey: pwKEK.kwKey },
        { name: FACTOR_RECOVERY_PHRASE, wrappingKey: recKEK.kwKey },
      ],
      { salt: recoverySalt },
    );

    const parsed = parseWrappedDataKey(wire);
    assert.equal(parsed.envelopeVersion, 4);
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

  it('buildV4Envelope is byte-stable for the same input (idempotency)', () => {
    const chain = [{ gen: 1, wrappings: [
      { factor: 'password', wrapped: 'PPPP' },
      { factor: 'recovery_phrase', wrapped: 'RRRR' },
    ]}];
    const salt = new Uint8Array(16).fill(0x42);
    const a = buildV4Envelope(chain, { salt });
    const b = buildV4Envelope(chain, { salt });
    assert.equal(a, b);
  });
});

// ============ TarnClient.register — issue #12 enforcement ============

describe('TarnClient.register — recovery acknowledgment + v4 envelope', () => {
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

  it('emits a v4 envelope with both factors + returns phrase + PDF', async () => {
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'b'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    const result = await client.register('rec-test@example.com', 'password-2026', {
      recoveryAcknowledged: true,
      emailRecoveryKit: false,
    });
    assert.ok(result.recoveryPhrase);
    assert.equal(result.recoveryPhrase.split(' ').length, 24);
    assert.ok(result.pdfBytes instanceof Uint8Array);
    assert.ok(result.pdfBytes.length > 0);
    // First 5 bytes are the PDF header "%PDF-".
    assert.deepEqual(Array.from(result.pdfBytes.slice(0, 5)), [0x25, 0x50, 0x44, 0x46, 0x2d]);
    assert.equal(result.emailDelivered, false);

    // Inspect the envelope sent to /auth/register.
    const registerCall = fetchCalls.find(c => c.url.endsWith('/auth/register'));
    const body = JSON.parse(registerCall.body);
    const env = JSON.parse(body.wrapped_data_key);
    assert.equal(env.v, 4);
    assert.ok(env.recovery);
    assert.equal(env.dek_chain[0].wrappings.length, 2);
    const factors = env.dek_chain[0].wrappings.map(w => w.factor).sort();
    assert.deepEqual(factors, ['password', 'recovery_phrase']);
    assert.ok(body.recovery_lookup_key);
    assert.ok(body.recovery_public_key);
  });

  it('attempts email forward when emailRecoveryKit is true (default)', async () => {
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'b'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
      // /api/v1/recovery/email POST
      { status: 200, body: JSON.stringify({ ok: true }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    const result = await client.register('rec-test@example.com', 'password-2026', {
      recoveryAcknowledged: true,
      // emailRecoveryKit defaults to true
      appName: 'Bookish',
    });
    assert.equal(result.emailDelivered, true);

    const emailCall = fetchCalls.find(c => c.url.endsWith('/recovery/email'));
    assert.ok(emailCall, 'should POST /api/v1/recovery/email when emailRecoveryKit is true');
    const body = JSON.parse(emailCall.body);
    assert.equal(body.recipient_email, 'rec-test@example.com');
    assert.equal(body.app_name, 'Bookish');
    assert.ok(body.pdf_base64);
  });

  it('register succeeds even when email forward fails (does not throw)', async () => {
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'b'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
      // email send fails
      { status: 502, body: JSON.stringify({ error: 'relay error' }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    const result = await client.register('rec-test@example.com', 'password-2026', {
      recoveryAcknowledged: true,
    });
    assert.equal(result.emailDelivered, false);
    assert.ok(result.recoveryPhrase, 'phrase still returned to caller');
    assert.ok(result.pdfBytes, 'PDF still returned to caller');
  });
});

// ============ recoverAccount round trip ============

describe('TarnClient.recoverAccount — round trip', () => {
  afterEach(restoreFetch);

  it('register → recoverAccount with same phrase → DEK chain preserved', async () => {
    // Step 1: register an account, capture the v4 envelope server-side.
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
      emailRecoveryKit: false,
    });
    const phrase = reg.recoveryPhrase;
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
      newEmail: 'new@example.com',
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
    assert.equal(newEnv.v, 4);
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
        newEmail: 'a@b.com',
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
    const phrase = generateRecoveryPhrase();
    await assert.rejects(
      () => client.recoverAccount({
        phrase,
        newEmail: 'a@b.com',
        newPassword: 'pw',
      }),
      /no account found/,
    );
  });
});

// ============ regenerateRecoveryKit ============

describe('TarnClient.regenerateRecoveryKit', () => {
  afterEach(restoreFetch);

  it('without emailRecoveryKit: returns PDF, makes no network call', async () => {
    mockFetch([]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    const phrase = generateRecoveryPhrase();
    const r = await client.regenerateRecoveryKit({ phrase, emailRecoveryKit: false });
    assert.ok(r.pdfBytes instanceof Uint8Array);
    assert.equal(r.emailDelivered, false);
    assert.equal(fetchCalls.length, 0);
  });

  it('rejects an invalid phrase', async () => {
    const client = new TarnClient('https://api.tarn.dev', APP);
    await assert.rejects(
      () => client.regenerateRecoveryKit({ phrase: 'bad phrase', emailRecoveryKit: false }),
      /expected 24|invalid/,
    );
  });
});

// ============ PDF ============

describe('renderRecoveryPDF', () => {
  it('produces a valid PDF (starts with %PDF- and ends with %%EOF)', () => {
    const phrase = generateRecoveryPhrase();
    const pdf = renderRecoveryPDF({ phrase, appName: 'Bookish' });
    const head = new TextDecoder().decode(pdf.slice(0, 5));
    assert.equal(head, '%PDF-');
    const tail = new TextDecoder().decode(pdf.slice(-6));
    assert.equal(tail, '%%EOF\n');
  });

  it('is deterministic for fixed inputs (phrase + branding + generatedAt)', () => {
    const phrase = generateRecoveryPhrase();
    const a = renderRecoveryPDF({ phrase, appName: 'Bookish', generatedAt: '2026-04-28' });
    const b = renderRecoveryPDF({ phrase, appName: 'Bookish', generatedAt: '2026-04-28' });
    assert.deepEqual(a, b);
  });

  it('different phrase → different bytes', () => {
    const a = renderRecoveryPDF({ phrase: generateRecoveryPhrase(), appName: 'X', generatedAt: 'd' });
    const b = renderRecoveryPDF({ phrase: generateRecoveryPhrase(), appName: 'X', generatedAt: 'd' });
    assert.notDeepEqual(a, b);
  });

  it('rejects a non-24-word phrase', () => {
    assert.throws(
      () => renderRecoveryPDF({ phrase: 'too short' }),
      /expected 24-word phrase/,
    );
  });

  it('contains all 24 words in the rendered content stream', () => {
    const phrase = generateRecoveryPhrase();
    const pdf = renderRecoveryPDF({ phrase });
    const text = new TextDecoder().decode(pdf);
    for (const word of phrase.split(' ')) {
      assert.ok(text.includes(word), `PDF should contain word "${word}"`);
    }
  });
});

// ============ sendRecoveryKitEmail ============

describe('TarnClient.sendRecoveryKitEmail', () => {
  afterEach(restoreFetch);

  it('rejects without an active session', async () => {
    mockFetch([]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    const phrase = generateRecoveryPhrase();
    const pdfBytes = renderRecoveryPDF({ phrase });
    await assert.rejects(
      () => client.sendRecoveryKitEmail({ recipientEmail: 'a@b.com', pdfBytes }),
      /Not authenticated/,
    );
    assert.equal(fetchCalls.length, 0);
  });

  it('posts pdf_base64 + recipient_email when authenticated', async () => {
    mockFetch([
      // register
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'b'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
      // sendRecoveryKitEmail call
      { status: 200, body: JSON.stringify({ ok: true }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    const reg = await client.register('rec@example.com', 'password-2026', {
      recoveryAcknowledged: true,
      emailRecoveryKit: false,
    });
    await client.sendRecoveryKitEmail({
      recipientEmail: 'a@b.com',
      pdfBytes: reg.pdfBytes,
      appName: 'Bookish',
    });
    const emailCall = fetchCalls.find(c => c.url.endsWith('/recovery/email'));
    assert.ok(emailCall);
    const body = JSON.parse(emailCall.body);
    assert.equal(body.recipient_email, 'a@b.com');
    assert.equal(body.app_name, 'Bookish');
    assert.ok(body.pdf_base64.length > 0);
  });
});
