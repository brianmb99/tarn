// A silent JWT refresh that sent require_previous_sid and gets
// 401 { error: 'session_not_found' } must sign the device out.
// A 200 (older server that ignores the flag, or a reused sid) keeps the
// JWT. Interactive login/register never send the flag.
//
// Run: node --import tsx --test tests/unit/session-remote-signout.test.js

import '../indexeddb-shim.mjs';
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient, TarnNotAuthenticatedError, SESSION_IDLE_SECONDS } from '../../client/src/tarn.js';
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
const PASSWORD = 'remote-signout-pass-2026';

const originalFetch = globalThis.fetch;

function b64url(s) {
  return btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function fakeJwt(exp, sid = 'sid-device') {
  return `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify({ sub: 'remote', sid, exp }))}.`;
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
function respond(status, body) {
  return {
    status,
    headers: { get: () => null },
    text: async () => JSON.stringify(body),
    json: async () => body,
  };
}

async function registeredClient(email, sid = 'sid-device') {
  const exp = Math.floor(Date.now() / 1000) + 3600;
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.includes('/auth/register')) return respond(201, { data_lookup_key: 'd'.repeat(64) });
    if (u.includes('/auth/challenge')) return respond(200, { nonce: 'a'.repeat(64) });
    return respond(200, { jwt: fakeJwt(exp, sid), account_key_stored: true });
  };
  const client = new TarnClient(API, APP);
  await client.register(email, PASSWORD, { recoveryAcknowledged: true });
  return client;
}

// Resume a password session whose JWT is already expired, so the next
// authenticated call takes the silent-refresh path and sends previous_sid.
async function expiredSession(email, sid = 'sid-device') {
  const client = await registeredClient(email, sid);
  const payload = await decryptBlobToPayload(await client.serializeSession());
  const blob = await client.serializeSession();
  payload.jwt = fakeJwt(Math.floor(Date.now() / 1000) - 120, sid);
  payload.sid = sid;
  payload.expiresAt = Math.floor(Date.now() / 1000) + SESSION_IDLE_SECONDS;
  const stale = await reencryptPayload(payload);
  const resumed = await TarnClient.resumeSession(API, APP, stale);
  assert.ok(resumed, 'sanity: expired JWT still resumes');
  return { client: resumed, blob: stale, originalBlob: blob };
}

function refreshMock(verifyResponse) {
  const calls = { verifyBodies: [] };
  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    if (u.includes('/auth/challenge')) return respond(200, { nonce: 'c'.repeat(64) });
    if (u.includes('/auth/verify')) {
      const body = JSON.parse(opts.body);
      calls.verifyBodies.push(body);
      return verifyResponse;
    }
    return respond(200, { sessions: [] });
  };
  return calls;
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

describe('remote sign-out on require_previous_sid', () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('401 session_not_found signs the device out, clears the blob, calls the handler, and throws TarnNotAuthenticatedError', async () => {
    const { client, blob } = await expiredSession('remote-not-found@example.com', 'sid-revoked');
    let handlerCalls = 0;
    client.setRemoteSignOutHandler(() => { handlerCalls += 1; });
    const calls = refreshMock(respond(401, { error: 'session_not_found' }));

    await assert.rejects(
      () => client.listSessions(),
      (err) => {
        assert.ok(err instanceof TarnNotAuthenticatedError);
        assert.match(err.message, /signed out from another device/);
        return true;
      },
    );
    assert.equal(calls.verifyBodies.length, 1);
    assert.equal(calls.verifyBodies[0].previous_sid, 'sid-revoked');
    assert.equal(calls.verifyBodies[0].require_previous_sid, true);
    assert.equal(client.isLoggedIn(), false);
    assert.equal(client._testJwt(), null, 'no JWT is kept');
    assert.equal(handlerCalls, 1);

    // A follow-up call must not mint yet another session.
    await assert.rejects(() => client.listSessions(), TarnNotAuthenticatedError);
    assert.equal(calls.verifyBodies.length, 1);

    assert.equal(
      await TarnClient.resumeSession(API, APP, blob),
      null,
      'clearSession wiped the wrapping key, so the persisted blob is unreadable',
    );
  });

  it('a 200 from an older server keeps the minted JWT', async () => {
    const { client, blob } = await expiredSession('remote-old-server@example.com', 'sid-old-server');
    let handlerCalls = 0;
    client.setRemoteSignOutHandler(() => { handlerCalls += 1; });
    const minted = fakeJwt(Math.floor(Date.now() / 1000) + 900, 'sid-replacement');
    const calls = refreshMock(respond(200, { jwt: minted, account_key_stored: true }));
    await client.listSessions();
    assert.equal(calls.verifyBodies[0].previous_sid, 'sid-old-server');
    assert.equal(calls.verifyBodies[0].require_previous_sid, true);
    assert.equal(client.isLoggedIn(), true);
    assert.equal(client._testJwt(), minted);
    assert.equal(handlerCalls, 0);
    assert.ok(await TarnClient.resumeSession(API, APP, blob), 'wrapping key was not cleared');
  });

  it('any other non-200 stays a verify failure and does not sign out', async () => {
    const { client, blob } = await expiredSession('remote-other-401@example.com', 'sid-other');
    let handlerCalls = 0;
    client.setRemoteSignOutHandler(() => { handlerCalls += 1; });
    refreshMock(respond(401, { error: 'Invalid signature' }));
    await assert.rejects(
      () => client.listSessions(),
      (err) => {
        assert.equal(err instanceof TarnNotAuthenticatedError, false);
        assert.match(err.message, /Verify failed: Invalid signature/);
        return true;
      },
    );
    assert.equal(client.isLoggedIn(), true);
    assert.equal(handlerCalls, 0);
    assert.ok(await TarnClient.resumeSession(API, APP, blob));
  });

  it('login sends previous_sid but never require_previous_sid', async () => {
    let registerBody;
    globalThis.fetch = async (url, opts) => {
      const u = String(url);
      if (u.includes('/auth/register')) {
        registerBody = JSON.parse(opts.body);
        return respond(201, { data_lookup_key: 'd'.repeat(64) });
      }
      if (u.includes('/auth/challenge')) return respond(200, { nonce: 'a'.repeat(64) });
      return respond(200, {
        jwt: fakeJwt(Math.floor(Date.now() / 1000) + 3600, 'sid-before-login'),
        account_key_stored: true,
      });
    };
    const email = 'remote-login@example.com';
    const client = new TarnClient(API, APP);
    await client.register(email, PASSWORD, { recoveryAcknowledged: true });
    assert.ok(registerBody?.wrapped_data_key);

    let verifyBody;
    const minted = fakeJwt(Math.floor(Date.now() / 1000) + 900, 'sid-after-login');
    globalThis.fetch = async (url, opts) => {
      const u = String(url);
      if (u.includes('/auth/challenge')) {
        return respond(200, {
          nonce: 'b'.repeat(64),
          data_lookup_key: 'd'.repeat(64),
          wrapped_data_key: registerBody.wrapped_data_key,
          envelope_generation: 1,
        });
      }
      verifyBody = JSON.parse(opts.body);
      return respond(200, {
        jwt: minted,
        account_key_stored: true,
      });
    };
    const result = await client.login(email, PASSWORD);
    assert.equal(result.dataLookupKey, 'd'.repeat(64));
    assert.equal(verifyBody.previous_sid, 'sid-before-login');
    assert.equal(Object.hasOwn(verifyBody, 'require_previous_sid'), false);
    assert.equal(client.isLoggedIn(), true);
    assert.equal(client._testJwt(), minted);
    assert.equal(typeof await client.serializeSession(), 'string');
  });

  it('register does not send the flag and stays logged in', async () => {
    let verifyBody;
    globalThis.fetch = async (url, opts) => {
      const u = String(url);
      if (u.includes('/auth/register')) return respond(201, { data_lookup_key: 'd'.repeat(64) });
      if (u.includes('/auth/challenge')) return respond(200, { nonce: 'a'.repeat(64) });
      verifyBody = JSON.parse(opts.body);
      return respond(200, {
        jwt: fakeJwt(Math.floor(Date.now() / 1000) + 3600, 'sid-reg'),
        account_key_stored: false,
      });
    };
    const client = new TarnClient(API, APP);
    await client.register('remote-register@example.com', PASSWORD, { recoveryAcknowledged: true });
    assert.equal(Object.hasOwn(verifyBody, 'require_previous_sid'), false);
    assert.equal(Object.hasOwn(verifyBody, 'previous_sid'), false);
    assert.equal(client.isLoggedIn(), true);
    assert.ok(client._testJwt());
  });

  it('the schema wrapper clears its storage adapter on remote sign-out', async () => {
    const { blob } = await expiredSession('remote-wrapper@example.com', 'sid-wrapped');
    const storage = TarnStorage.memory();
    await storage.write(blob);
    globalThis.fetch = originalFetch;

    const wrapped = await SchemaTarnClient.create({
      apiBase: API,
      appId: APP,
      schema,
      storage,
    });
    assert.equal(wrapped.isLoggedIn(), true);
    assert.ok(await storage.read(), 'resume re-persisted a blob');

    const calls = refreshMock(respond(401, { error: 'session_not_found' }));
    await assert.rejects(
      () => wrapped.session.listDevices(),
      (err) => {
        assert.ok(err instanceof TarnNotAuthenticatedError);
        assert.match(err.message, /signed out from another device/);
        return true;
      },
    );
    assert.equal(calls.verifyBodies[0].previous_sid, 'sid-wrapped');
    assert.equal(calls.verifyBodies[0].require_previous_sid, true);
    assert.equal(wrapped.isLoggedIn(), false);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(await storage.read(), null, 'storage adapter blob cleared via #onLogout');
  });
});
