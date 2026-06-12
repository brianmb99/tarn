// tarn#73 — envelope-carried sharing identity.
//
// The sharing identity (X25519 pair seed + dedicated P-256 share-signing
// keypair) is random at registration and rides inside the credential
// envelope, encrypted under a DEK gen. Any factor that unwraps the DEK
// hydrates it — which is what makes passkey sessions cryptographically
// complete for the sharing layer. These tests pin:
//
//   1. crypto round-trip (encryptSharingKeys / decryptSharingKeys)
//   2. register() emits the blob + a share_pub DECOUPLED from the password
//   3. parseWrappedDataKey / buildEnvelope preserve the blob verbatim
//   4. login() hydrates both keypairs from the envelope
//   5. login() on a pre-#73 envelope throws TarnSharingKeysMissingError;
//      the migration flag yields a legacy-derived session instead
//   6. changeCredentials() keeps the identity STABLE (same share_pub, no
//      §13.5 rotation) for migrated accounts
//   7. changeCredentials() on an unmigrated account mints the identity —
//      the migration path
//
// Run: node --import tsx --test tests/unit/sharing-keys-envelope.test.js

import '../indexeddb-shim.mjs';
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient, TarnSharingKeysMissingError } from '../../client/src/tarn.js';
import {
  deriveAllKeys,
  deriveRecoveryKey,
  generateRecoverySalt,
  generateRandomDataKey,
  generateSharingKeyPair,
  generateShareSigningKeyPair,
  encryptSharingKeys,
  decryptSharingKeys,
  parseWrappedDataKey,
  buildEnvelope,
  wrapDataKeyChainEnvelope,
  encodeSharePub,
  FACTOR_PASSWORD,
  FACTOR_RECOVERY_PHRASE,
} from '../../client/src/crypto.js';
import { generateAccountKey, accountKeyToEntropy } from '../../client/src/recovery.js';
import {
  decryptSessionBlob,
  getOrCreateWrappingKey,
} from '../../client/src/session-persistence.js';

const APP = 'bookish';
const PASSWORD = 'sharing-keys-pass-2026';

// ---- fetch mock with request capture ----
const originalFetch = globalThis.fetch;
let fetchResponses = [];
let fetchCalls = [];

function mockFetch(responses) {
  fetchResponses = responses.slice();
  fetchCalls = [];
  globalThis.fetch = async (url, opts) => {
    let parsedBody = null;
    try { parsedBody = JSON.parse(opts?.body ?? ''); } catch { /* non-JSON */ }
    fetchCalls.push({ url: String(url), method: opts?.method ?? 'GET', body: parsedBody });
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
  fetchCalls = [];
}

function fakeJwt(label = 'jwt') {
  const b64url = (s) => btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const header = b64url('{"alg":"none"}');
  const payload = b64url(JSON.stringify({ sub: label, sid: 'sid-73', exp: Math.floor(Date.now() / 1000) + 3600 }));
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
async function blobPayload(blob) {
  const wrappingKey = await getOrCreateWrappingKey();
  const plaintext = await decryptSessionBlob(base64UrlToBytes(blob), wrappingKey);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

/** Register a fresh client; returns { client, registerBody }. */
async function registerClient(username) {
  mockFetch([
    { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
    { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
    { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg'), account_key_stored: true }) },
  ]);
  const client = new TarnClient('https://api.tarn.dev', APP);
  await client.register(username, PASSWORD, { recoveryAcknowledged: true });
  const registerBody = fetchCalls.find(c => c.url.endsWith('/auth/register')).body;
  return { client, registerBody };
}

/** Build a PRE-#73 envelope (no sharing_keys) for the given credentials. */
async function buildLegacyAccount(username) {
  const keys = await deriveAllKeys(username, PASSWORD, APP);
  const phrase = generateAccountKey();
  const recoverySalt = generateRecoverySalt();
  const recoveryKEK = await deriveRecoveryKey(phrase, recoverySalt);
  const dek = await generateRandomDataKey();
  const envelope = await wrapDataKeyChainEnvelope(
    [{ gen: 1, key: dek.gcmKey }],
    [
      { name: FACTOR_PASSWORD, wrappingKey: keys.credentialEncryptionKey.kwKey },
      { name: FACTOR_RECOVERY_PHRASE, wrappingKey: recoveryKEK.kwKey },
    ],
    { salt: recoverySalt },
  );
  return { keys, envelope };
}

describe('tarn#73 — envelope-carried sharing identity', () => {
  afterEach(restoreFetch);

  it('encryptSharingKeys / decryptSharingKeys round-trips the identity', async () => {
    const dek = await generateRandomDataKey();
    const sharingKeyPair = generateSharingKeyPair();
    const shareSigningKeyPair = await generateShareSigningKeyPair();

    const blob = await encryptSharingKeys({ sharingKeyPair, shareSigningKeyPair }, dek.gcmKey, 1);
    assert.equal(blob.v, 1);
    assert.equal(blob.gen, 1);

    const out = await decryptSharingKeys(blob, dek.gcmKey);
    assert.deepEqual(out.sharingKeyPair.publicKey, sharingKeyPair.publicKey);
    assert.deepEqual(out.sharingKeyPair.privateKey, sharingKeyPair.privateKey);
    // The signing pair survives as a functional sign/verify pair.
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' }, out.shareSigningKeyPair.privateKey, new Uint8Array([1, 2, 3]),
    );
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, shareSigningKeyPair.publicKey, sig, new Uint8Array([1, 2, 3]),
    );
    assert.equal(ok, true);
  });

  it('decryptSharingKeys fails closed on a wrong DEK', async () => {
    const dek = await generateRandomDataKey();
    const wrongDek = await generateRandomDataKey();
    const blob = await encryptSharingKeys(
      { sharingKeyPair: generateSharingKeyPair(), shareSigningKeyPair: await generateShareSigningKeyPair() },
      dek.gcmKey, 1,
    );
    await assert.rejects(() => decryptSharingKeys(blob, wrongDek.gcmKey));
  });

  it('register() emits sharing_keys and a share_pub decoupled from the password', async () => {
    const username = 'sk73-register@example.com';
    const { registerBody } = await registerClient(username);

    const parsed = parseWrappedDataKey(registerBody.wrapped_data_key);
    assert.ok(parsed.sharingKeys, 'envelope must carry sharing_keys');
    assert.equal(parsed.sharingKeys.gen, 1);

    // The published share_pub must be the RANDOM identity from the blob —
    // not the legacy password-derived keypair.
    const keys = await deriveAllKeys(username, PASSWORD, APP);
    const legacySharePub = encodeSharePub(keys.sharingKeyPair.publicKey);
    assert.notEqual(registerBody.share_pub, legacySharePub);

    // And it must MATCH the blob contents (unwrap via the password factor).
    const { unwrapDataKeyChain } = await import('../../client/src/crypto.js');
    const unwrapped = await unwrapDataKeyChain(registerBody.wrapped_data_key, keys.credentialEncryptionKey.kwKey);
    const identity = await decryptSharingKeys(parsed.sharingKeys, unwrapped.dekByGen.get(1).gcmKey);
    assert.equal(registerBody.share_pub, encodeSharePub(identity.sharingKeyPair.publicKey));
  });

  it('parseWrappedDataKey + buildEnvelope preserve the blob verbatim', async () => {
    const { registerBody } = await registerClient('sk73-passthrough@example.com');
    const parsed = parseWrappedDataKey(registerBody.wrapped_data_key);

    const rebuilt = buildEnvelope(
      parsed.dekChain.map(e => ({
        gen: e.gen,
        wrappings: e.wrappings.map(w => ({
          factor: w.factor,
          wrappedBase64: w.wrappedBase64,
          ...(w.credentialId ? { credentialId: w.credentialId } : {}),
        })),
      })),
      { salt: parsed.recovery.salt, kdfParams: parsed.recovery.kdfParams },
      parsed.sharingKeys,
    );
    const reparsed = parseWrappedDataKey(rebuilt);
    assert.deepEqual(reparsed.sharingKeys, parsed.sharingKeys);
  });

  it('login() hydrates both sharing keypairs from the envelope', async () => {
    const username = 'sk73-login@example.com';
    const { registerBody } = await registerClient(username);
    restoreFetch();

    mockFetch([
      { status: 200, body: JSON.stringify({
        nonce: 'b'.repeat(64),
        data_lookup_key: 'd'.repeat(64),
        wrapped_data_key: registerBody.wrapped_data_key,
        envelope_generation: 1,
      }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('login'), account_key_stored: true }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.login(username, PASSWORD);

    const payload = await blobPayload(await client.serializeSession());
    assert.equal(typeof payload.shareSigningPrivateKey, 'string', 'share-signing key hydrated');
    assert.equal(typeof payload.sharingPrivateKey, 'string', 'sharing key hydrated');
    assert.ok(payload.sharingKeysBlob, 'blob snapshot captured');
    // The hydrated sharing key is the ENVELOPE one, not password-derived.
    const keys = await deriveAllKeys(username, PASSWORD, APP);
    const legacyPrivB64 = btoa(String.fromCharCode(...keys.sharingKeyPair.privateKey));
    assert.notEqual(payload.sharingPrivateKey, legacyPrivB64);
  });

  it('login() throws TarnSharingKeysMissingError on a pre-#73 envelope', async () => {
    const username = 'sk73-legacy@example.com';
    const { envelope } = await buildLegacyAccount(username);

    mockFetch([
      { status: 200, body: JSON.stringify({
        nonce: 'c'.repeat(64),
        data_lookup_key: 'd'.repeat(64),
        wrapped_data_key: envelope,
        envelope_generation: 1,
      }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('legacy'), account_key_stored: false }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    await assert.rejects(
      () => client.login(username, PASSWORD),
      (err) => err instanceof TarnSharingKeysMissingError,
    );
  });

  it('login({ allowUnmigratedSharing }) yields a legacy-derived migration session', async () => {
    const username = 'sk73-migration-session@example.com';
    const { keys, envelope } = await buildLegacyAccount(username);

    mockFetch([
      { status: 200, body: JSON.stringify({
        nonce: 'e'.repeat(64),
        data_lookup_key: 'd'.repeat(64),
        wrapped_data_key: envelope,
        envelope_generation: 1,
      }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('mig'), account_key_stored: false }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.login(username, PASSWORD, { allowUnmigratedSharing: true });

    const payload = await blobPayload(await client.serializeSession());
    // Legacy derived X25519 present (needed for the §13.5 announce)...
    const legacyPrivB64 = btoa(String.fromCharCode(...keys.sharingKeyPair.privateKey));
    assert.equal(payload.sharingPrivateKey, legacyPrivB64);
    // ...but no share-signing key — new-style sharing stays unavailable.
    assert.equal(payload.shareSigningPrivateKey, null);
    assert.equal(payload.sharingKeysBlob, null);
  });

  it('changeCredentials() keeps the sharing identity stable for migrated accounts', async () => {
    const username = 'sk73-stable@example.com';
    const { client, registerBody } = await registerClient(username);
    const originalSharePub = registerBody.share_pub;
    restoreFetch();

    mockFetch([
      // PUT /api/v1/auth
      { status: 200, body: JSON.stringify({ ok: true }) },
      // re-auth: challenge + verify
      { status: 200, body: JSON.stringify({ nonce: 'f'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('cc'), account_key_stored: true }) },
    ]);
    await client.changeCredentials(username, 'new-password-sk73-2026', { acceptRecoveryGap: true });

    const put = fetchCalls.find(c => c.method === 'PUT' && c.url.endsWith('/api/v1/auth'));
    assert.ok(put, 'credential change PUT issued');
    assert.equal(put.body.new_share_pub, originalSharePub, 'share_pub unchanged — identity stable');
    const newParsed = parseWrappedDataKey(put.body.new_wrapped_data_key);
    assert.ok(newParsed.sharingKeys, 'new envelope still carries sharing_keys');
    // Stable identity → no §13.5 traffic: only the 3 queued calls happened.
    assert.equal(fetchCalls.length, 3, 'no rotation announce / snapshot fetches');
  });

  it('changeCredentials() mints the identity for unmigrated accounts (migration path)', async () => {
    const username = 'sk73-migrate@example.com';
    const { keys, envelope } = await buildLegacyAccount(username);

    mockFetch([
      { status: 200, body: JSON.stringify({
        nonce: '1'.repeat(64),
        data_lookup_key: 'd'.repeat(64),
        wrapped_data_key: envelope,
        envelope_generation: 1,
      }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('mig2'), account_key_stored: false }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.login(username, PASSWORD, { allowUnmigratedSharing: true });
    restoreFetch();

    mockFetch([
      { status: 200, body: JSON.stringify({ ok: true }) },
      { status: 200, body: JSON.stringify({ nonce: '2'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('mig3'), account_key_stored: false }) },
    ]);
    // Same credentials — the no-op credential change that IS the migration.
    // skipRotationAnnounce keeps the mocked surface small (the announce
    // machinery is integration-tested); the identity mint is what's pinned.
    await client.changeCredentials(username, PASSWORD, {
      acceptRecoveryGap: true,
      skipRotationAnnounce: true,
    });

    const put = fetchCalls.find(c => c.method === 'PUT' && c.url.endsWith('/api/v1/auth'));
    const legacySharePub = encodeSharePub(keys.sharingKeyPair.publicKey);
    assert.notEqual(put.body.new_share_pub, legacySharePub, 'identity minted — not the legacy derived one');
    const newParsed = parseWrappedDataKey(put.body.new_wrapped_data_key);
    assert.ok(newParsed.sharingKeys, 'migrated envelope carries sharing_keys');

    // Post-migration the session is fully capable: share-signing key set.
    const payload = await blobPayload(await client.serializeSession());
    assert.equal(typeof payload.shareSigningPrivateKey, 'string');
    assert.ok(payload.sharingKeysBlob);
  });
});
