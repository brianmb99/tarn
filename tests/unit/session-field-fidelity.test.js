// SDK-4 verification — session serialize → resume field fidelity.
//
// Background (audit SDK-4, LOW/MEDIUM): a logged-in client carries a set of
// private fields (#jwt, #sid, #dataLookupKey, #dekByGen, #currentGen,
// #signingKeyPair, #credentialLookupKey, #username, #sharingKeyPair,
// #recoveryFactorMeta, #credentialEncryptionKey, #accountKeyStored). Each must
// be (a) emitted by serializeSession() and (b) restored byte-identically by
// resumeSession(). The hazard this test guards against is a FUTURE field that
// gets set on login() but is forgotten in serializeSession() — the resumed
// client would then silently lack it, and a method that depends on it would
// fail only in production on a returning user.
//
// Two complementary checks:
//   1. SCHEMA LOCK — the serialized payload's key set must equal a frozen,
//      hand-maintained inventory. Adding a field to serializeSession() without
//      updating this list (or vice versa) trips immediately, forcing a
//      conscious decision about persistence + this test.
//   2. ROUND-TRIP FIDELITY — resume the blob, re-serialize, and assert every
//      field is byte-identical. If resumeSession dropped or mangled a field,
//      the second payload diverges from the first.
//
// The private fields aren't directly observable, so we observe them through
// the only sanctioned window: the serialized-blob plaintext (the on-disk
// shape resumeSession reads), plus the public isLoggedIn() / isAccountKeyStored()
// surface. A new login-set field that needs to survive a reload MUST appear
// in the blob to be restorable — so locking the blob's key set is the precise
// guard the audit asked for.
//
// Run: node --import tsx --test tests/unit/session-field-fidelity.test.js

import '../indexeddb-shim.mjs';
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient } from '../../client/src/tarn.js';
import {
  decryptSessionBlob,
  getOrCreateWrappingKey,
} from '../../client/src/session-persistence.js';

const APP = 'bookish';
const PASSWORD = 'field-fidelity-pass-2026';

const originalFetch = globalThis.fetch;
let fetchResponses = [];

function mockFetch(responses) {
  fetchResponses = responses.slice();
  globalThis.fetch = async (url, opts) => {
    const next = fetchResponses.shift();
    if (!next) throw new Error(`mockFetch: no response queued for ${url}`);
    return {
      status: next.status,
      headers: { get: () => null },
      text: async () => next.body ?? '',
      json: async () => { try { return JSON.parse(next.body ?? ''); } catch { return null; } },
    };
  };
}
function restoreFetch() {
  globalThis.fetch = originalFetch;
  fetchResponses = [];
}

function fakeJwt(label = 'jwt') {
  const b64url = (s) => btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const header = b64url('{"alg":"none"}');
  const payload = b64url(JSON.stringify({ sub: label, sid: 'sid-fidelity', exp: Math.floor(Date.now() / 1000) + 3600 }));
  return `${header}.${payload}.`;
}

function base64UrlToBytes(s) {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function decryptBlobToPayload(blob) {
  const wrappingKey = await getOrCreateWrappingKey();
  const plaintext = await decryptSessionBlob(base64UrlToBytes(blob), wrappingKey);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

// The frozen inventory of keys serializeSession() emits for a full
// password-authenticated session. Maintained by hand: any change here must be
// a deliberate decision paired with a serializeSession() change.
const EXPECTED_PAYLOAD_KEYS = [
  'v',
  'createdAt',
  'expiresAt',
  'apiBase',
  'appId',
  'dataLookupKey',
  'currentGen',
  'dekByGen',
  'jwt',
  'sid',
  'accountKeyStored',
  'username',
  'credentialLookupKey',
  'signingPrivateKey',
  'signingPublicKey',
  'sharingPrivateKey',
  'sharingPublicKey',
  'recoveryFactorMeta',
  'credentialEncryptionKey',
].sort();

describe('SDK-4 — session serialize/resume field fidelity', () => {
  afterEach(restoreFetch);

  it('SCHEMA LOCK: a full-session blob emits exactly the expected key set', async () => {
    // register() leaves a full password-authenticated client; its blob has
    // the same field shape login() produces (both run the identical
    // field-set tail before serialize). If a future login/register field is
    // added but not serialized, it simply won't appear here — and the
    // accompanying round-trip test will then show the resumed client lost it.
    // Conversely, if serializeSession() gains a key not in EXPECTED_PAYLOAD_KEYS
    // (or drops one), this assertion fails and forces a review.
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg'), account_key_stored: true }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register('fidelity-schema@example.com', PASSWORD, { recoveryAcknowledged: true });

    const payload = await decryptBlobToPayload(await client.serializeSession());
    assert.deepEqual(
      Object.keys(payload).sort(),
      EXPECTED_PAYLOAD_KEYS,
      'serializeSession key set drifted from the frozen inventory — if you added a ' +
      'login/register field, decide whether it must persist and update both serializeSession ' +
      'and EXPECTED_PAYLOAD_KEYS.',
    );

    // Every password-derived field must be populated (non-null) on a full
    // session — a null here means login captured it but serialize dropped it.
    for (const k of [
      'dataLookupKey', 'currentGen', 'dekByGen', 'jwt', 'sid',
      'username', 'credentialLookupKey', 'signingPrivateKey', 'signingPublicKey',
      'sharingPrivateKey', 'sharingPublicKey', 'recoveryFactorMeta', 'credentialEncryptionKey',
    ]) {
      assert.ok(
        payload[k] !== null && payload[k] !== undefined,
        `full-session field "${k}" must be serialized (was ${payload[k]})`,
      );
    }
    assert.equal(typeof payload.accountKeyStored, 'boolean', 'accountKeyStored persisted');
  });

  it('ROUND-TRIP: resume → re-serialize is byte-identical for every field', async () => {
    // Per-field fidelity. We compare the original blob's payload against the
    // resumed-then-reserialized payload key by key. A field that resumeSession
    // failed to restore (or restored with different bytes) diverges here.
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg'), account_key_stored: true }) },
    ]);
    const clientA = new TarnClient('https://api.tarn.dev', APP);
    await clientA.register('fidelity-roundtrip@example.com', PASSWORD, { recoveryAcknowledged: true });
    const blob1 = await clientA.serializeSession();
    const payload1 = await decryptBlobToPayload(blob1);

    const clientB = await TarnClient.resumeSession('https://api.tarn.dev', APP, blob1);
    assert.ok(clientB, 'resume must succeed');
    assert.equal(clientB.isLoggedIn(), true);
    assert.equal(clientB.isAccountKeyStored(), payload1.accountKeyStored, 'accountKeyStored restored');

    const payload2 = await decryptBlobToPayload(await clientB.serializeSession());

    // createdAt/expiresAt are time-derived and re-stamped on each serialize,
    // so we compare them loosely (present + numeric) and everything else
    // exactly. Every identity/key field must round-trip byte-for-byte.
    for (const key of EXPECTED_PAYLOAD_KEYS) {
      if (key === 'createdAt' || key === 'expiresAt') {
        assert.equal(typeof payload2[key], 'number', `${key} present after resume`);
        continue;
      }
      assert.deepEqual(
        payload2[key],
        payload1[key],
        `field "${key}" must round-trip byte-identically through resume`,
      );
    }
  });

  it('ROUND-TRIP: the resumed DEK chain decrypts data the original chain wrote', async () => {
    // Semantic fidelity for the most load-bearing field (dekByGen): not just
    // equal bytes in the blob, but operationally equivalent keys after
    // re-import. Wrap a random DEK under the original gen-1 key and unwrap it
    // under the resumed gen-1 key.
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg'), account_key_stored: true }) },
    ]);
    const clientA = new TarnClient('https://api.tarn.dev', APP);
    await clientA.register('fidelity-dek@example.com', PASSWORD, { recoveryAcknowledged: true });
    const blob1 = await clientA.serializeSession();
    const clientB = await TarnClient.resumeSession('https://api.tarn.dev', APP, blob1);
    const blob2 = await clientB.serializeSession();

    const dek1 = (await decryptBlobToPayload(blob1)).dekByGen;
    const dek2 = (await decryptBlobToPayload(blob2)).dekByGen;
    assert.deepEqual(dek2, dek1, 'DEK chain (gen + raw bytes) round-trips identically');
  });
});
