// Sliding session-blob expiry: 90-day idle window, 365-day absolute cap
// from the last interactive sign-in, passkey-only blobs capped at JWT exp,
// and the schema wrapper re-persisting on resume so daily use slides the
// idle deadline.
//
// Run: node --import tsx --test tests/unit/session-sliding-expiry.test.js

import '../indexeddb-shim.mjs';
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  TarnClient,
  SESSION_IDLE_SECONDS,
  SESSION_ABSOLUTE_MAX_SECONDS,
} from '../../client/src/tarn.js';
import {
  TarnClient as SchemaTarnClient,
  defineSchema,
  TarnStorage,
} from '../../client/src/index.js';
import {
  encryptSessionBlob,
  decryptSessionBlob,
  getOrCreateWrappingKey,
} from '../../client/src/session-persistence.js';

const APP = 'bookish';
const API = 'https://api.tarn.dev';
const PASSWORD = 'sliding-expiry-pass-2026';
const DAY = 24 * 60 * 60;

const originalFetch = globalThis.fetch;
const originalWarn = console.warn;

function fakeJwt(exp) {
  const b64url = (s) => btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const header = b64url('{"alg":"none"}');
  const payload = b64url(JSON.stringify({
    sub: 'sliding',
    sid: 'sid-sliding',
    exp,
  }));
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

function mockRegister() {
  const now = Math.floor(Date.now() / 1000);
  globalThis.fetch = async (url) => {
    const u = String(url);
    const body = u.includes('/auth/register')
      ? { data_lookup_key: 'd'.repeat(64) }
      : u.includes('/auth/challenge')
        ? { nonce: 'a'.repeat(64) }
        : { jwt: fakeJwt(now + 3600), account_key_stored: true };
    const status = u.includes('/auth/register') ? 201 : 200;
    return {
      status,
      headers: { get: () => null },
      text: async () => JSON.stringify(body),
      json: async () => body,
    };
  };
}

async function registeredClient(email) {
  mockRegister();
  const client = new TarnClient(API, APP);
  await client.register(email, PASSWORD, { recoveryAcknowledged: true });
  return client;
}

const schema = defineSchema({
  appId: APP,
  version: 1,
  collections: {
    books: {
      primaryKey: 'bookId',
      fields: { bookId: 'string', title: 'string' },
    },
  },
});

describe('sliding session expiry', () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
    console.warn = originalWarn;
  });

  it('a fresh blob expires about 90 days out and records authenticatedAt', async () => {
    const before = Math.floor(Date.now() / 1000);
    const client = await registeredClient('slide-fresh@example.com');
    const payload = await decryptBlobToPayload(await client.serializeSession());
    const after = Math.floor(Date.now() / 1000);

    assert.equal(payload.v, 3);
    assert.ok(payload.authenticatedAt >= before && payload.authenticatedAt <= after);
    const idleDeadline = payload.authenticatedAt + SESSION_IDLE_SECONDS;
    assert.ok(
      Math.abs(payload.expiresAt - idleDeadline) <= 2,
      `expiresAt ${payload.expiresAt} should be ~${idleDeadline}`,
    );
    assert.ok(payload.expiresAt <= payload.authenticatedAt + SESSION_ABSOLUTE_MAX_SECONDS);
    assert.equal(SESSION_IDLE_SECONDS, 90 * DAY);
    assert.equal(SESSION_ABSOLUTE_MAX_SECONDS, 365 * DAY);
  });

  it('re-serialize after resume extends a short expiry, but not past the absolute cap', async () => {
    const clientA = await registeredClient('slide-extend@example.com');
    const payload = await decryptBlobToPayload(await clientA.serializeSession());
    const now = Math.floor(Date.now() / 1000);

    // Shorten the idle deadline so a resume + re-serialize has room to slide,
    // and backdate the interactive sign-in so the absolute cap is the tighter bound.
    payload.authenticatedAt = now - 300 * DAY;
    payload.expiresAt = now + DAY;
    const resumed = await TarnClient.resumeSession(API, APP, await reencryptPayload(payload));
    assert.ok(resumed, 'blob inside both windows must resume');

    const again = await decryptBlobToPayload(await resumed.serializeSession());
    const cap = payload.authenticatedAt + SESSION_ABSOLUTE_MAX_SECONDS;
    assert.equal(again.authenticatedAt, payload.authenticatedAt, 'resume keeps the original sign-in time');
    assert.ok(Math.abs(again.expiresAt - cap) <= 2, `expiresAt should sit on the absolute cap, got delta ${again.expiresAt - cap}`);
    assert.ok(again.expiresAt < now + SESSION_IDLE_SECONDS, 'absolute cap wins over the idle window');
    assert.ok(again.expiresAt > payload.expiresAt, 'expiry still moved forward from the shortened blob');
  });

  it('resume at the absolute cap returns null even when expiresAt is still in the future', async () => {
    const clientA = await registeredClient('slide-cap@example.com');
    const payload = await decryptBlobToPayload(await clientA.serializeSession());
    const now = Math.floor(Date.now() / 1000);
    payload.authenticatedAt = now - SESSION_ABSOLUTE_MAX_SECONDS;
    payload.expiresAt = now + SESSION_IDLE_SECONDS;
    const blob = await reencryptPayload(payload);

    assert.equal(
      await TarnClient.resumeSession(API, APP, blob, { _nowSeconds: now }),
      null,
      'now == authenticatedAt + 365d must not resume',
    );

    payload.authenticatedAt = now - SESSION_ABSOLUTE_MAX_SECONDS + 5;
    const ok = await TarnClient.resumeSession(API, APP, await reencryptPayload(payload), { _nowSeconds: now });
    assert.ok(ok, 'one second inside the absolute cap still resumes');
  });

  it('an older blob without authenticatedAt falls back to createdAt', async () => {
    const clientA = await registeredClient('slide-legacy@example.com');
    const payload = await decryptBlobToPayload(await clientA.serializeSession());
    const now = Math.floor(Date.now() / 1000);
    delete payload.authenticatedAt;
    payload.createdAt = now - 10 * DAY;
    payload.expiresAt = now + DAY;

    const resumed = await TarnClient.resumeSession(API, APP, await reencryptPayload(payload));
    assert.ok(resumed, 'pre-authenticatedAt blob still resumes');
    const again = await decryptBlobToPayload(await resumed.serializeSession());
    assert.equal(again.authenticatedAt, payload.createdAt);

    payload.createdAt = now - SESSION_ABSOLUTE_MAX_SECONDS;
    payload.expiresAt = now + DAY;
    assert.equal(
      await TarnClient.resumeSession(API, APP, await reencryptPayload(payload)),
      null,
      'fallback createdAt is also subject to the absolute cap',
    );
  });

  it('a passkey-only blob is capped at the JWT exp', async () => {
    const clientA = await registeredClient('slide-passkey@example.com');
    const payload = await decryptBlobToPayload(await clientA.serializeSession());
    const now = Math.floor(Date.now() / 1000);
    const exp = now + 3 * DAY;
    payload.jwt = fakeJwt(exp);
    payload.username = null;
    payload.credentialLookupKey = null;
    payload.signingPrivateKey = null;
    payload.signingPublicKey = null;
    payload.sharingPrivateKey = null;
    payload.sharingPublicKey = null;
    payload.credentialEncryptionKey = null;
    payload.recoveryFactorMeta = null;
    payload.expiresAt = now + SESSION_IDLE_SECONDS;

    const resumed = await TarnClient.resumeSession(API, APP, await reencryptPayload(payload));
    assert.ok(resumed, 'passkey-only blob resumes');
    const again = await decryptBlobToPayload(await resumed.serializeSession());
    assert.equal(again.signingPrivateKey, null);
    assert.equal(again.expiresAt, exp, 'passkey-only expiresAt is the JWT exp, not the 90-day idle deadline');
  });

  it('silent JWT refresh does not move authenticatedAt', async () => {
    const clientA = await registeredClient('slide-silent@example.com');
    const payload = await decryptBlobToPayload(await clientA.serializeSession());
    const stamped = payload.authenticatedAt;
    payload.jwt = fakeJwt(Math.floor(Date.now() / 1000) - 3600);
    payload.expiresAt = Math.floor(Date.now() / 1000) + SESSION_IDLE_SECONDS;
    const client = await TarnClient.resumeSession(API, APP, await reencryptPayload(payload));
    assert.ok(client);

    globalThis.fetch = async (url) => {
      const u = String(url);
      const body = u.includes('/auth/challenge')
        ? { nonce: 'b'.repeat(64) }
        : u.includes('/auth/verify')
          ? { jwt: fakeJwt(Math.floor(Date.now() / 1000) + 900), account_key_stored: true }
          : { sessions: [] };
      return {
        status: 200,
        headers: { get: () => null },
        text: async () => JSON.stringify(body),
        json: async () => body,
      };
    };
    await client.listSessions();
    const again = await decryptBlobToPayload(await client.serializeSession());
    assert.equal(again.authenticatedAt, stamped);
  });

  it('the schema wrapper re-persists after a successful resume', async () => {
    const clientA = await registeredClient('slide-wrapper@example.com');
    const blob = await clientA.serializeSession();
    const before = await decryptBlobToPayload(blob);
    before.expiresAt = Math.floor(Date.now() / 1000) + DAY;
    const short = await reencryptPayload(before);

    const storage = TarnStorage.memory();
    await storage.write(short);
    globalThis.fetch = originalFetch;

    const wrapped = await SchemaTarnClient.create({
      apiBase: API,
      appId: APP,
      schema,
      storage,
    });
    assert.equal(wrapped.isLoggedIn(), true);
    const stored = await storage.read();
    assert.ok(stored && stored !== short, 'resume writes a new blob');
    const after = await decryptBlobToPayload(stored);
    assert.ok(after.expiresAt > before.expiresAt, 'stored expiry slid forward');
    assert.equal(after.authenticatedAt, before.authenticatedAt);
  });

  it('a persist failure on resume is non-fatal', async () => {
    const clientA = await registeredClient('slide-persist-fail@example.com');
    const blob = await clientA.serializeSession();
    const storage = {
      async read() { return blob; },
      async write() { throw new Error('disk full'); },
      async clear() {},
    };
    const warns = [];
    console.warn = (...args) => { warns.push(args.map(String).join(' ')); };
    globalThis.fetch = originalFetch;

    const wrapped = await SchemaTarnClient.create({
      apiBase: API,
      appId: APP,
      schema,
      storage,
    });
    assert.equal(wrapped.isLoggedIn(), true);
    assert.match(warns.join('\n'), /persist session failed/);
  });

  it('the test underlying factory does not re-persist', async () => {
    let serializes = 0;
    const storage = TarnStorage.memory();
    await storage.write('leave-me');
    await SchemaTarnClient.create({
      apiBase: API,
      appId: APP,
      schema,
      storage,
      underlying: () => ({
        serializeSession: async () => { serializes++; return 'nope'; },
      }),
    });
    assert.equal(serializes, 0);
    assert.equal(await storage.read(), 'leave-me');
  });
});
