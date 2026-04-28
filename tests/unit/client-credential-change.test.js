// Unit tests for TarnClient credential change — forward-secret DEK rotation
// behavior introduced in issue #11.
//
// Uses real KDFs (Argon2id) but mocks fetch so no network or D1 dependency.
// Each Argon2id derivation is ~150-200ms; tests are coarse-grained to keep
// the suite under a few seconds total.
//
// Run: node --test tests/unit/client-credential-change.test.js

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient } from '../../client/src/tarn.js';
import {
  deriveAllKeys,
  unwrapDataKeyChain,
  parseWrappedDataKey,
  KDF_V2_ARGON2ID,
} from '../../client/src/crypto.js';

const APP = 'bookish';
const OLD_EMAIL = 'rotation-old@example.com';
const OLD_PASSWORD = 'old-password-2026';
const NEW_EMAIL = 'rotation-new@example.com';
const NEW_PASSWORD = 'new-password-2026';

const originalFetch = globalThis.fetch;
let fetchCalls = [];
let fetchResponses = [];

function mockFetch(responses) {
  fetchCalls = [];
  fetchResponses = responses.slice();
  globalThis.fetch = async (url, opts) => {
    fetchCalls.push({ url, method: opts?.method || 'GET', body: opts?.body });
    const next = fetchResponses.shift();
    if (!next) throw new Error(`mockFetch: no response queued for ${url}`);
    if (next instanceof Error) throw next;
    return {
      status: next.status,
      headers: { get: () => null },
      text: async () => next.body ?? '',
    };
  };
}

function restoreFetch() {
  globalThis.fetch = originalFetch;
  fetchCalls = [];
  fetchResponses = [];
}

// Build a JWT that #requireAuth() will accept as valid (decodable payload,
// far-future exp). Avoids triggering an extra challenge/verify round trip
// before each authenticated call — keeps mockFetch ordering matched to the
// flow under test.
function fakeJwt(label = 'jwt') {
  const b64url = (s) => btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const header = b64url('{"alg":"none"}');
  const payload = b64url(JSON.stringify({ sub: label, exp: Math.floor(Date.now() / 1000) + 3600 }));
  return `${header}.${payload}.`;
}

describe('TarnClient.changeCredentials — forward-secret DEK rotation (issue #11)', () => {
  afterEach(restoreFetch);

  it('appends a new DEK at gen N+1; previous gen stays in the chain', async () => {
    mockFetch([
      // register → 201
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      // post-register #authenticate(): challenge + verify
      { status: 200, body: JSON.stringify({ nonce: 'b'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('1') }) },
      // changeCredentials PUT → 200
      { status: 200, body: JSON.stringify({}) },
      // post-change #authenticate(): challenge + verify
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('2') }) },
    ]);

    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register(OLD_EMAIL, OLD_PASSWORD);

    // Snapshot the wrapped_data_key sent at registration so we can compare gen 1.
    const registerCall = fetchCalls.find(c => c.url.endsWith('/auth/register'));
    const registerBody = JSON.parse(registerCall.body);
    const registeredEnvelope = JSON.parse(registerBody.wrapped_data_key);
    assert.equal(registeredEnvelope.v, 3);
    assert.equal(registeredEnvelope.dek_chain.length, 1);
    assert.equal(registeredEnvelope.dek_chain[0].gen, 1);
    const gen1WrappedAtRegister = registeredEnvelope.dek_chain[0].wrapped;

    await client.changeCredentials(NEW_EMAIL, NEW_PASSWORD);

    const putCall = fetchCalls.find(c => c.url.endsWith('/auth') && c.method === 'PUT');
    assert.ok(putCall, 'changeCredentials should send PUT /api/v1/auth');
    const putBody = JSON.parse(putCall.body);

    // New envelope is v3 with TWO entries — gen 1 (re-wrapped) + gen 2 (fresh).
    const newEnvelope = JSON.parse(putBody.new_wrapped_data_key);
    assert.equal(newEnvelope.v, 3);
    assert.equal(newEnvelope.kdf, 'argon2id');
    assert.equal(newEnvelope.dek_chain.length, 2);
    assert.deepEqual(newEnvelope.dek_chain.map(e => e.gen), [1, 2]);

    // Gen 1's wrapped bytes MUST differ from registration: it's now wrapped
    // under the NEW credential_encryption_key. (Same DEK bytes inside, but
    // AES-KW is deterministic per (key, plaintext) — different KEK → different
    // ciphertext.)
    assert.notEqual(newEnvelope.dek_chain[0].wrapped, gen1WrappedAtRegister);

    // Gen 2's wrapped bytes are a fresh DEK — definitely not equal to gen 1.
    assert.notEqual(newEnvelope.dek_chain[1].wrapped, newEnvelope.dek_chain[0].wrapped);

    // The new envelope MUST be unwrappable with the NEW credential_encryption_key.
    const newKeys = await deriveAllKeys(NEW_EMAIL, NEW_PASSWORD, APP, KDF_V2_ARGON2ID);
    const unwrapped = await unwrapDataKeyChain(
      putBody.new_wrapped_data_key,
      newKeys.credentialEncryptionKey.kwKey,
    );
    assert.equal(unwrapped.dekByGen.size, 2);
    assert.equal(unwrapped.currentGen, 2);
    assert.ok(unwrapped.dekByGen.get(1));
    assert.ok(unwrapped.dekByGen.get(2));
  });

  it('preserves gen 1 DEK bytes across a credential change', async () => {
    // The whole point of the chain: existing data (encrypted under gen 1)
    // must stay decryptable with the new credentials. We verify by
    // round-tripping a payload encrypted with gen 1 before the change and
    // decrypting after the change with the unwrapped gen-1 DEK.
    mockFetch([
      // register
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'b'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('1') }) },
      // changeCredentials
      { status: 200, body: JSON.stringify({}) },
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('2') }) },
    ]);

    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register(OLD_EMAIL, OLD_PASSWORD);

    // Capture the gen 1 DEK as wrapped under the OLD credential_encryption_key.
    const registerCall = fetchCalls.find(c => c.url.endsWith('/auth/register'));
    const oldEnvelope = JSON.parse(JSON.parse(registerCall.body).wrapped_data_key);
    const oldKeys = await deriveAllKeys(OLD_EMAIL, OLD_PASSWORD, APP, KDF_V2_ARGON2ID);
    const oldUnwrapped = await unwrapDataKeyChain(
      JSON.stringify(oldEnvelope),
      oldKeys.credentialEncryptionKey.kwKey,
    );
    const gen1KeyOld = oldUnwrapped.dekByGen.get(1).gcmKey;

    // Encrypt a payload with the old gen 1 DEK.
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const original = new TextEncoder().encode('legacy-blob-payload');
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, gen1KeyOld, original)
    );

    // Run credential change.
    await client.changeCredentials(NEW_EMAIL, NEW_PASSWORD);

    // Now grab the new envelope, unwrap with NEW credentials, recover gen 1.
    const putCall = fetchCalls.find(c => c.url.endsWith('/auth') && c.method === 'PUT');
    const newWdk = JSON.parse(putCall.body).new_wrapped_data_key;
    const newKeys = await deriveAllKeys(NEW_EMAIL, NEW_PASSWORD, APP, KDF_V2_ARGON2ID);
    const newUnwrapped = await unwrapDataKeyChain(newWdk, newKeys.credentialEncryptionKey.kwKey);
    const gen1KeyNew = newUnwrapped.dekByGen.get(1).gcmKey;

    // Decrypt the OLD ciphertext with the gen-1 key recovered from NEW envelope.
    const recovered = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, gen1KeyNew, ciphertext);
    assert.equal(new TextDecoder().decode(recovered), 'legacy-blob-payload');
  });

  it('three credential changes produce gens 1..4, all readable from the latest envelope', async () => {
    const responses = [
      // register
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('register') }) },
    ];
    // Three credential changes — each is PUT + challenge + verify.
    for (let i = 0; i < 3; i++) {
      responses.push({ status: 200, body: JSON.stringify({}) });
      responses.push({ status: 200, body: JSON.stringify({ nonce: String.fromCharCode(98 + i).repeat(64) }) });
      responses.push({ status: 200, body: JSON.stringify({ jwt: fakeJwt(`change-${i}`) }) });
    }
    mockFetch(responses);

    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register(OLD_EMAIL, OLD_PASSWORD);

    await client.changeCredentials('e1@x.com', 'p1');
    await client.changeCredentials('e2@x.com', 'p2');
    await client.changeCredentials('e3@x.com', 'p3');

    const putCalls = fetchCalls.filter(c => c.url.endsWith('/auth') && c.method === 'PUT');
    assert.equal(putCalls.length, 3);

    // The final envelope is the most recent PUT body.
    const finalEnvelope = JSON.parse(JSON.parse(putCalls[2].body).new_wrapped_data_key);
    assert.equal(finalEnvelope.v, 3);
    assert.deepEqual(finalEnvelope.dek_chain.map(e => e.gen), [1, 2, 3, 4]);

    // Final envelope unwraps with the final credentials and exposes 4 DEKs.
    const finalKeys = await deriveAllKeys('e3@x.com', 'p3', APP, KDF_V2_ARGON2ID);
    const finalUnwrapped = await unwrapDataKeyChain(
      JSON.stringify(finalEnvelope),
      finalKeys.credentialEncryptionKey.kwKey,
    );
    assert.equal(finalUnwrapped.dekByGen.size, 4);
    assert.equal(finalUnwrapped.currentGen, 4);
  });

  it('parseWrappedDataKey handles the rotated envelope shape', async () => {
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'b'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('register') }) },
      { status: 200, body: JSON.stringify({}) },
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('change') }) },
    ]);

    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register(OLD_EMAIL, OLD_PASSWORD);
    await client.changeCredentials(NEW_EMAIL, NEW_PASSWORD);

    const putCall = fetchCalls.find(c => c.url.endsWith('/auth') && c.method === 'PUT');
    const newWdk = JSON.parse(putCall.body).new_wrapped_data_key;
    const parsed = parseWrappedDataKey(newWdk);
    assert.equal(parsed.envelopeVersion, 3);
    assert.equal(parsed.kdfVersion, KDF_V2_ARGON2ID);
    assert.equal(parsed.dekChain.length, 2);
  });
});
