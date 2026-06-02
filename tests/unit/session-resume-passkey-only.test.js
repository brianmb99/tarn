// Issue #27 verification — passkey-only sessions survive the lifecycle
// methods (isLoggedIn / serializeSession / resumeSession) cleanly.
//
// Background: authenticateWithPasskey() leaves the client with
//   - #jwt populated
//   - #dekByGen populated (chain unwrapped via the passkey PRF KEK)
//   - #signingKeyPair = null  (no master_key derived)
//   - #credentialLookupKey = null
//   - #username = null
//   - #sharingKeyPair = null
//   - #credentialEncryptionKey = null
// Before this fix, the three lifecycle methods all rejected that state:
//   isLoggedIn returned false (consumer apps thought user not logged in),
//   serializeSession threw "client is not authenticated" (session never
//   persisted, so the user must re-tap on every reload), and
//   resumeSession refused any blob lacking the password-derived fields.
//
// Strategy: produce a passkey-only client state by registering a real
// password client, serializing, stripping the password-derived fields
// from the in-blob payload, and reserializing. The result is byte-
// equivalent to what authenticateWithPasskey() would leave + persist on
// a fresh client (same field set, same null pattern).
//
// We also verify:
//   - the existing full-session round-trip (#25 coverage) still works,
//     i.e., this fix is additive
//   - password-side operations on a passkey-only session throw a clear
//     "requires a password-authenticated session" error
//
// Run: node --import tsx --test tests/unit/session-resume-passkey-only.test.js

import '../indexeddb-shim.mjs';
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient } from '../../client/src/tarn.js';
import {
  encryptSessionBlob,
  decryptSessionBlob,
  getOrCreateWrappingKey,
} from '../../client/src/session-persistence.js';

const APP = 'bookish';
const PASSWORD = 'passkey-only-pass-2026';

const originalFetch = globalThis.fetch;
let fetchCalls = [];
let fetchResponses = [];

function mockFetch(responses) {
  fetchCalls = [];
  fetchResponses = responses.slice();
  globalThis.fetch = async (url, opts) => {
    fetchCalls.push({
      url,
      method: opts?.method || 'GET',
      body: opts?.body,
      headers: opts?.headers || {},
    });
    const next = fetchResponses.shift();
    if (!next) throw new Error(`mockFetch: no response queued for ${url}`);
    if (next instanceof Error) throw next;
    return {
      status: next.status,
      headers: { get: () => null },
      text: async () => next.body ?? '',
      json: async () => {
        try { return JSON.parse(next.body ?? ''); } catch { return null; }
      },
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

function bytesToBase64Url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
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

async function reencryptPayload(payload) {
  const wrappingKey = await getOrCreateWrappingKey();
  const pt = new TextEncoder().encode(JSON.stringify(payload));
  const ct = await encryptSessionBlob(pt, wrappingKey);
  return bytesToBase64Url(ct);
}

async function registerClient(email) {
  mockFetch([
    { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
    { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
    { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg'), account_key_stored: true }) },
  ]);
  const client = new TarnClient('https://api.tarn.dev', APP);
  await client.register(email, PASSWORD, { recoveryAcknowledged: true });
  return client;
}

// Strip the password-derived fields from a full-session blob to simulate
// what authenticateWithPasskey() + serializeSession() would have written
// on a fresh passkey-only client. The result is the on-disk shape we
// expect resumeSession() to accept post-fix.
async function toPasskeyOnlyBlob(fullBlob) {
  const payload = await decryptBlobToPayload(fullBlob);
  payload.username = null;
  payload.credentialLookupKey = null;
  payload.signingPrivateKey = null;
  payload.signingPublicKey = null;
  payload.sharingPrivateKey = null;
  payload.sharingPublicKey = null;
  payload.credentialEncryptionKey = null;
  payload.recoveryFactorMeta = null;
  // The JWT must remain (it's the auth context for passkey-only sessions).
  assert.equal(typeof payload.jwt, 'string', 'sanity: full blob carries a JWT');
  return await reencryptPayload(payload);
}

describe('Issue #27 — isLoggedIn() accepts JWT-only sessions', () => {
  afterEach(restoreFetch);

  it('returns true after resume from a passkey-only blob', async () => {
    const clientA = await registerClient('issue27-isloggedin@example.com');
    const fullBlob = await clientA.serializeSession();
    const passkeyOnlyBlob = await toPasskeyOnlyBlob(fullBlob);

    const clientB = await TarnClient.resumeSession('https://api.tarn.dev', APP, passkeyOnlyBlob);
    assert.ok(clientB, 'resumeSession accepted the passkey-only blob');
    assert.equal(clientB.isLoggedIn(), true, 'passkey-only resumed client must be logged in');
  });

  it('returns false for a freshly-constructed client (no DEK chain)', async () => {
    const client = new TarnClient('https://api.tarn.dev', APP);
    assert.equal(client.isLoggedIn(), false);
  });

  it('full password session (signing keys + DEK chain) is also logged-in (no regression)', async () => {
    const client = await registerClient('issue27-fullsession@example.com');
    assert.equal(client.isLoggedIn(), true);
  });
});

describe('Issue #27 — serializeSession() accepts passkey-only state', () => {
  afterEach(restoreFetch);

  it('round-trip: passkey-only resume → reserialize emits a parseable v3 blob without password-derived fields', async () => {
    const clientA = await registerClient('issue27-serialize@example.com');
    const passkeyOnlyBlob = await toPasskeyOnlyBlob(await clientA.serializeSession());
    const clientB = await TarnClient.resumeSession('https://api.tarn.dev', APP, passkeyOnlyBlob);
    assert.ok(clientB, 'passkey-only resume must succeed');

    // The resumed passkey-only client must be able to serialize itself
    // again — that's what the schema-first wrapper's #persistSession()
    // path does on every mutating call.
    const reBlob = await clientB.serializeSession();
    const rePayload = await decryptBlobToPayload(reBlob);

    assert.equal(rePayload.v, 3, 'schema stays on v3 (no version bump)');
    // Required (non-password) fields populate.
    assert.equal(typeof rePayload.jwt, 'string', 'JWT round-trips');
    assert.equal(typeof rePayload.dataLookupKey, 'string', 'dataLookupKey round-trips');
    assert.equal(typeof rePayload.currentGen, 'number', 'currentGen round-trips');
    assert.ok(Array.isArray(rePayload.dekByGen) && rePayload.dekByGen.length > 0, 'DEK chain round-trips');
    // Password-derived fields stay null (passkey-only session has none).
    assert.equal(rePayload.username, null, 'username must be null on passkey-only session');
    assert.equal(rePayload.credentialLookupKey, null);
    assert.equal(rePayload.signingPrivateKey, null);
    assert.equal(rePayload.signingPublicKey, null);
    assert.equal(rePayload.sharingPrivateKey, null);
    assert.equal(rePayload.sharingPublicKey, null);
    assert.equal(rePayload.credentialEncryptionKey, null);
    assert.equal(rePayload.recoveryFactorMeta, null);
  });

  it('throws when the DEK chain is empty (truly unauthenticated client)', async () => {
    const client = new TarnClient('https://api.tarn.dev', APP);
    await assert.rejects(
      () => client.serializeSession(),
      /not authenticated/,
    );
  });
});

describe('Issue #27 — resumeSession() accepts passkey-only blobs', () => {
  afterEach(restoreFetch);

  it('accepts a blob with the password-derived fields nulled out', async () => {
    const clientA = await registerClient('issue27-resume@example.com');
    const passkeyOnlyBlob = await toPasskeyOnlyBlob(await clientA.serializeSession());

    const clientB = await TarnClient.resumeSession('https://api.tarn.dev', APP, passkeyOnlyBlob);
    assert.ok(clientB, 'resumeSession must accept the passkey-only blob');
    assert.equal(clientB.isLoggedIn(), true);
  });

  it('refuses a blob that lacks BOTH signing keys and a JWT (degenerate shape)', async () => {
    // The minimal "logged-in" criterion is "DEK chain + (signing keys OR
    // JWT)". A blob with neither cannot perform any authenticated call
    // and must fail the resume hard so apps fall back to login UI.
    const clientA = await registerClient('issue27-resume-degenerate@example.com');
    const payload = await decryptBlobToPayload(await clientA.serializeSession());
    payload.signingPrivateKey = null;
    payload.signingPublicKey = null;
    payload.jwt = null;
    const broken = await reencryptPayload(payload);
    const clientB = await TarnClient.resumeSession('https://api.tarn.dev', APP, broken);
    assert.equal(clientB, null, 'no signing keys and no JWT must reject the resume');
  });

  it('passkey-only resumed client has #signingKeyPair, #username, #credentialLookupKey, #sharingKeyPair left null', async () => {
    // We observe these indirectly: re-serializing and inspecting the
    // payload. The previous test confirmed the resume succeeds; this one
    // confirms the resume DID NOT accidentally synthesize fake values
    // into the password-derived slots.
    const clientA = await registerClient('issue27-resume-nulls@example.com');
    const passkeyOnlyBlob = await toPasskeyOnlyBlob(await clientA.serializeSession());
    const clientB = await TarnClient.resumeSession('https://api.tarn.dev', APP, passkeyOnlyBlob);
    assert.ok(clientB);

    const rePayload = await decryptBlobToPayload(await clientB.serializeSession());
    assert.equal(rePayload.signingPrivateKey, null);
    assert.equal(rePayload.signingPublicKey, null);
    assert.equal(rePayload.username, null);
    assert.equal(rePayload.credentialLookupKey, null);
    assert.equal(rePayload.sharingPrivateKey, null);
    assert.equal(rePayload.sharingPublicKey, null);
  });
});

describe('Issue #27 — full-session round-trip unchanged (no regression)', () => {
  afterEach(restoreFetch);

  it('password sign-in → serialize → resume restores ALL fields and produces a byte-equivalent blob', async () => {
    // This mirrors the #25 round-trip test but explicitly asserts every
    // password-derived field round-trips. The whole point of issue #27
    // is that the relaxation is additive — full sessions stay byte-for-
    // byte identical across serialize/resume/reserialize.
    const clientA = await registerClient('issue27-full-roundtrip@example.com');
    const blob1 = await clientA.serializeSession();
    const payload1 = await decryptBlobToPayload(blob1);

    const clientB = await TarnClient.resumeSession('https://api.tarn.dev', APP, blob1);
    assert.ok(clientB);
    assert.equal(clientB.isLoggedIn(), true);

    const blob2 = await clientB.serializeSession();
    const payload2 = await decryptBlobToPayload(blob2);

    // Stable fields must round-trip byte-identically.
    assert.equal(payload2.v, payload1.v);
    assert.equal(payload2.dataLookupKey, payload1.dataLookupKey);
    assert.equal(payload2.currentGen, payload1.currentGen);
    assert.equal(payload2.username, payload1.username);
    assert.equal(payload2.credentialLookupKey, payload1.credentialLookupKey);
    assert.equal(payload2.signingPrivateKey, payload1.signingPrivateKey);
    assert.equal(payload2.signingPublicKey, payload1.signingPublicKey);
    assert.equal(payload2.sharingPrivateKey, payload1.sharingPrivateKey);
    assert.equal(payload2.sharingPublicKey, payload1.sharingPublicKey);
    assert.equal(payload2.credentialEncryptionKey, payload1.credentialEncryptionKey);
    assert.equal(payload2.jwt, payload1.jwt);
    assert.equal(payload2.accountKeyStored, payload1.accountKeyStored);
    // DEK chain matches gen-for-gen.
    assert.equal(payload2.dekByGen.length, payload1.dekByGen.length);
    for (let i = 0; i < payload1.dekByGen.length; i++) {
      assert.equal(payload2.dekByGen[i].gen, payload1.dekByGen[i].gen);
      assert.equal(payload2.dekByGen[i].rawBytes, payload1.dekByGen[i].rawBytes);
    }
  });
});

describe('Issue #27 — password-side operations on a passkey-only session', () => {
  afterEach(restoreFetch);

  async function passkeyOnlyClient(label) {
    const clientA = await registerClient(label);
    const passkeyOnlyBlob = await toPasskeyOnlyBlob(await clientA.serializeSession());
    const clientB = await TarnClient.resumeSession('https://api.tarn.dev', APP, passkeyOnlyBlob);
    assert.ok(clientB, 'sanity: passkey-only resume must succeed');
    return clientB;
  }

  it('changeCredentials throws a clear "requires password-authenticated session" error', async () => {
    const client = await passkeyOnlyClient('issue27-change-creds@example.com');
    await assert.rejects(
      () => client.changeCredentials('new@example.com', 'new-pass-2026', { acceptRecoveryGap: true }),
      /requires a password-authenticated session/,
    );
  });

  it('viewAccountKey throws a clear "requires password-authenticated session" error', async () => {
    const client = await passkeyOnlyClient('issue27-view-key@example.com');
    await assert.rejects(
      () => client.viewAccountKey({ password: 'doesnt-matter-2026' }),
      /requires a password-authenticated session/,
    );
  });

  it('rotateAccountKey throws a clear "requires password-authenticated session" error', async () => {
    const client = await passkeyOnlyClient('issue27-rotate@example.com');
    await assert.rejects(
      () => client.rotateAccountKey({ password: 'doesnt-matter-2026' }),
      /requires a password-authenticated session/,
    );
  });

  it('sendConnectionRequest throws a clear "requires password-authenticated session" error', async () => {
    const client = await passkeyOnlyClient('issue27-send-conn@example.com');
    await assert.rejects(
      () => client.sendConnectionRequest('peer@example.com'),
      /requires a password-authenticated session/,
    );
  });

  it('createInviteToken throws a clear "requires password-authenticated session" error', async () => {
    const client = await passkeyOnlyClient('issue27-invite@example.com');
    await assert.rejects(
      () => client.createInviteToken({ label: 'test' }),
      /requires a password-authenticated session/,
    );
  });

  it('listIncomingRequests throws a clear "requires password-authenticated session" error', async () => {
    const client = await passkeyOnlyClient('issue27-incoming@example.com');
    await assert.rejects(
      () => client.listIncomingRequests(),
      /requires a password-authenticated session/,
    );
  });
});
