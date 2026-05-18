// Issue #25 verification — credentialEncryptionKey round-trips through
// the session blob, and pre-fix v3 blobs without the field still resume
// cleanly (back-compat).
//
// Why this matters: #rebuildEnvelopeWithExtraPasskey (passkey add) and
// #rebuildEnvelopeWithoutPasskey (passkey remove) both read
// #credentialEncryptionKey to re-wrap each gen's DEK under the password
// factor. Before this fix, the field was deliberately omitted from the
// session blob, so any passkey add/remove on a resumed-session client
// failed with "missing client state" — and resumed sessions are the
// dominant returning-user path.
//
// Strategy: the private #credentialEncryptionKey field isn't directly
// observable from JS, so we observe it indirectly by decrypting the
// session-blob plaintext (the SDK exports it as `credentialEncryptionKey`
// — a base64 string). Forward path → field present. Resume + reserialize
// → field round-trips byte-identical. Back-compat → strip the field from
// a real blob and confirm resume still succeeds (and its reserialized
// blob omits the field, since #credentialEncryptionKey stays null).
//
// Run: node --import tsx --test tests/unit/session-resume-cek.test.js

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
const PASSWORD = 'cek-resume-pass-2026';

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
    { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
  ]);
  const client = new TarnClient('https://api.tarn.dev', APP);
  await client.register(email, PASSWORD, { recoveryAcknowledged: true });
  return client;
}

describe('Issue #25 — credentialEncryptionKey persists across session resume', () => {
  afterEach(restoreFetch);

  it('forward path: serialized payload contains a base64 credentialEncryptionKey field', async () => {
    // Locks the on-disk schema. Any future change that drops the field
    // (or renames it) trips this immediately.
    const client = await registerClient('cek-schema@example.com');
    const blob = await client.serializeSession();
    const payload = await decryptBlobToPayload(blob);

    assert.equal(payload.v, 3, 'still on schema v3 (back-compat strategy)');
    assert.equal(
      typeof payload.credentialEncryptionKey, 'string',
      'credentialEncryptionKey must be present as a base64 string',
    );
    // 32 raw bytes → 44 base64 chars (with padding) — sanity-check the size.
    assert.ok(
      payload.credentialEncryptionKey.length >= 40 && payload.credentialEncryptionKey.length <= 48,
      `credentialEncryptionKey base64 length looks wrong: ${payload.credentialEncryptionKey.length}`,
    );
  });

  it('round-trip: resume → re-serialize yields the same CEK bytes (rehydration is byte-identical)', async () => {
    // The only externally-observable check on the resumed
    // #credentialEncryptionKey is whether the resumed client serializes
    // back the same field. If rehydration silently dropped the field or
    // imported the wrong bytes, the second blob's plaintext would diverge.
    const clientA = await registerClient('cek-roundtrip@example.com');
    const blob1 = await clientA.serializeSession();
    const payload1 = await decryptBlobToPayload(blob1);

    const clientB = await TarnClient.resumeSession('https://api.tarn.dev', APP, blob1);
    assert.ok(clientB, 'resumeSession returned a client');
    assert.equal(clientB.isLoggedIn(), true, 'resumed client is logged in');

    const blob2 = await clientB.serializeSession();
    const payload2 = await decryptBlobToPayload(blob2);

    assert.equal(
      payload2.credentialEncryptionKey,
      payload1.credentialEncryptionKey,
      'resumed client must re-serialize the same credentialEncryptionKey bytes',
    );
  });

  it('round-trip: the resumed CEK actually unwraps a DEK wrapped by the original CEK', async () => {
    // End-to-end semantic check: the kwKey on the resumed client must be
    // operationally equivalent to the original. We extract both CEKs from
    // their respective blob payloads, import them as AES-KW keys, and
    // confirm wrap-with-original / unwrap-with-resumed round-trips a
    // random DEK byte-for-byte. This is the exact operation
    // #rebuildEnvelopeWithExtraPasskey performs.
    const clientA = await registerClient('cek-unwrap@example.com');
    const blob1 = await clientA.serializeSession();
    const clientB = await TarnClient.resumeSession('https://api.tarn.dev', APP, blob1);
    assert.ok(clientB);
    const blob2 = await clientB.serializeSession();

    const cek1b64 = (await decryptBlobToPayload(blob1)).credentialEncryptionKey;
    const cek2b64 = (await decryptBlobToPayload(blob2)).credentialEncryptionKey;
    const cek1Bytes = Uint8Array.from(atob(cek1b64), c => c.charCodeAt(0));
    const cek2Bytes = Uint8Array.from(atob(cek2b64), c => c.charCodeAt(0));

    const cekA = await crypto.subtle.importKey(
      'raw', cek1Bytes, 'AES-KW', false, ['wrapKey', 'unwrapKey'],
    );
    const cekB = await crypto.subtle.importKey(
      'raw', cek2Bytes, 'AES-KW', false, ['wrapKey', 'unwrapKey'],
    );

    const dekRaw = crypto.getRandomValues(new Uint8Array(32));
    const dek = await crypto.subtle.importKey(
      'raw', dekRaw, 'AES-KW', true, ['wrapKey', 'unwrapKey'],
    );

    const wrapped = new Uint8Array(
      await crypto.subtle.wrapKey('raw', dek, cekA, 'AES-KW'),
    );
    const unwrapped = await crypto.subtle.unwrapKey(
      'raw', wrapped, cekB, 'AES-KW',
      'AES-KW', true, ['wrapKey', 'unwrapKey'],
    );
    const unwrappedRaw = new Uint8Array(await crypto.subtle.exportKey('raw', unwrapped));
    assert.deepEqual(unwrappedRaw, dekRaw, 'resumed CEK must unwrap what the original CEK wrapped');
  });

  it('back-compat: a pre-fix v3 blob (no credentialEncryptionKey field) resumes cleanly with #credentialEncryptionKey === null', async () => {
    // Simulate a real-world stale blob: the user signed in before this
    // fix landed, IndexedDB holds a v3 blob without the new field. The
    // fix must not require those users to re-auth on read/CRUD; only
    // passkey add/remove should fail with a clear error.
    const clientA = await registerClient('cek-backcompat@example.com');
    const realBlob = await clientA.serializeSession();

    const payload = await decryptBlobToPayload(realBlob);
    assert.ok(
      typeof payload.credentialEncryptionKey === 'string',
      'sanity: forward path emitted the field',
    );
    delete payload.credentialEncryptionKey;
    const staleBlob = await reencryptPayload(payload);

    const clientB = await TarnClient.resumeSession('https://api.tarn.dev', APP, staleBlob);
    assert.ok(clientB, 'pre-fix blob must resume cleanly (back-compat)');
    assert.equal(clientB.isLoggedIn(), true, 'resumed client is logged in');

    // The resumed client must round-trip its (still-null) CEK by emitting
    // a blob with credentialEncryptionKey === null. If the field were
    // populated (e.g., from some other source), serialize would emit a
    // string and we'd miss the regression.
    const reBlob = await clientB.serializeSession();
    const rePayload = await decryptBlobToPayload(reBlob);
    assert.equal(
      rePayload.credentialEncryptionKey,
      null,
      'a back-compat-resumed client must re-serialize with credentialEncryptionKey: null',
    );
  });

  it('back-compat: pre-fix blob with credentialEncryptionKey field absent (undefined) is treated the same as null', async () => {
    // Belt and suspenders: confirm the resume path tolerates the field
    // being absent (undefined after JSON.parse) — that's the on-disk
    // shape for blobs serialized before the fix landed.
    const clientA = await registerClient('cek-undefined@example.com');
    const realBlob = await clientA.serializeSession();
    const payload = await decryptBlobToPayload(realBlob);
    // Explicit `undefined` is dropped by JSON.stringify, so this models
    // the actual on-disk shape.
    payload.credentialEncryptionKey = undefined;
    const staleBlob = await reencryptPayload(payload);

    const clientB = await TarnClient.resumeSession('https://api.tarn.dev', APP, staleBlob);
    assert.ok(clientB, 'undefined CEK field must not block resume');
    assert.equal(clientB.isLoggedIn(), true);
  });
});
