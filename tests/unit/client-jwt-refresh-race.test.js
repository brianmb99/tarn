// SDK-2 verification — concurrent JWT refresh is serialized.
//
// Background (audit SDK-2, MEDIUM): #requireAuth() refreshes an expired JWT
// by nulling #jwt and calling #authenticate() (challenge + verify). Before
// this fix there was no guard, so two authenticated operations that both
// observed the expired JWT each kicked off their own challenge/verify round
// trip. The API's per-nonce check made the loser's verify fail (a confusing
// transient error mid-operation) rather than corrupt state, but the duplicate
// round trip and spurious error were still wrong.
//
// The fix is a single in-flight #jwtRefreshPromise: the first caller starts
// the refresh, every concurrent caller awaits the same promise, and the slot
// clears when it settles. This test proves that two (and three) concurrent
// expired-JWT operations trigger exactly ONE challenge round trip.
//
// Strategy: build a logged-in client, then resume it from a session blob whose
// JWT has been rewritten to an already-expired token (so #requireAuth takes
// the refresh path). A gated mock fetch holds the challenge response open
// until both callers have entered #requireAuth, guaranteeing the race window
// the guard must close.
//
// Run: node --import tsx --test tests/unit/client-jwt-refresh-race.test.js

import '../indexeddb-shim.mjs';
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient, TarnNotAuthenticatedError } from '../../client/src/tarn.js';
import {
  encryptSessionBlob,
  decryptSessionBlob,
  getOrCreateWrappingKey,
} from '../../client/src/session-persistence.js';

const APP = 'bookish';
const PASSWORD = 'jwt-refresh-race-pass-2026';

const originalFetch = globalThis.fetch;

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

function fakeJwt(expSecondsFromNow) {
  const b64url = (s) => btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const header = b64url('{"alg":"none"}');
  const payload = b64url(JSON.stringify({
    sub: 'race',
    sid: 'sid-race',
    exp: Math.floor(Date.now() / 1000) + expSecondsFromNow,
  }));
  return `${header}.${payload}.`;
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

// Register a real password client (so signing keys + credentialLookupKey are
// populated), then resume it from a blob whose JWT is already expired. The
// resumed client has everything #requireAuth needs to take the refresh path.
async function expiredJwtClient(email) {
  // Simple non-gated mock for the register round trip.
  globalThis.fetch = async (url) => ({
    status: String(url).includes('/auth/register') ? 201 : 200,
    headers: { get: () => null },
    text: async () => JSON.stringify({
      data_lookup_key: 'd'.repeat(64),
      nonce: 'a'.repeat(64),
      jwt: fakeJwt(3600),
    }),
    json: async () => ({
      data_lookup_key: 'd'.repeat(64),
      nonce: 'a'.repeat(64),
      jwt: fakeJwt(3600),
    }),
  });
  const reg = new TarnClient('https://api.tarn.dev', APP);
  await reg.register(email, PASSWORD, { recoveryAcknowledged: true });
  const blob = await reg.serializeSession();

  // Rewrite the JWT to an expired one (exp in the past). Bump expiresAt so the
  // blob itself still resumes — we only want the *JWT* stale, not the session.
  const payload = await decryptBlobToPayload(blob);
  payload.jwt = fakeJwt(-3600);
  payload.expiresAt = Math.floor(Date.now() / 1000) + 7 * 24 * 3600;
  const staleBlob = await reencryptPayload(payload);

  const client = await TarnClient.resumeSession('https://api.tarn.dev', APP, staleBlob);
  assert.ok(client, 'sanity: resume with expired JWT must succeed');
  return client;
}

// A gated mock fetch: the FIRST challenge response is held until `release()`
// is called, so both concurrent callers are forced to enter #requireAuth
// before the refresh can complete. Everything else resolves immediately.
function gatedMockFetch() {
  const calls = { challenge: 0, verify: 0, other: 0 };
  let releaseFirstChallenge;
  const firstChallengeGate = new Promise((res) => { releaseFirstChallenge = res; });

  globalThis.fetch = async (url, opts) => {
    const u = String(url);
    const respond = (obj) => ({
      status: 200,
      headers: { get: () => null },
      text: async () => JSON.stringify(obj),
      json: async () => obj,
    });

    if (u.includes('/auth/challenge')) {
      calls.challenge += 1;
      if (calls.challenge === 1) {
        // Hold the first challenge open until the test releases it.
        await firstChallengeGate;
      }
      return respond({ nonce: 'b'.repeat(64), data_lookup_key: 'd'.repeat(64) });
    }
    if (u.includes('/auth/verify')) {
      calls.verify += 1;
      return respond({ jwt: fakeJwt(3600), account_key_stored: true });
    }
    calls.other += 1;
    return respond({ sessions: [] });
  };

  return { calls, release: () => releaseFirstChallenge() };
}

function restoreFetch() {
  globalThis.fetch = originalFetch;
}

describe('SDK-2 — concurrent JWT refresh is serialized', () => {
  afterEach(restoreFetch);

  it('two concurrent expired-JWT operations trigger exactly one refresh', async () => {
    const client = await expiredJwtClient('jwt-race-2@example.com');
    const gate = gatedMockFetch();

    // Fire two authenticated calls concurrently. Both see the expired JWT in
    // #requireAuth; the guard must collapse them onto one challenge/verify.
    const p1 = client.listSessions();
    const p2 = client.listSessions();

    // Give both microtasks a chance to reach #requireAuth and register their
    // await on the single in-flight promise before we let the refresh finish.
    await new Promise((r) => setTimeout(r, 20));
    gate.release();

    const [r1, r2] = await Promise.all([p1, p2]);
    assert.deepEqual(r1, []);
    assert.deepEqual(r2, []);

    assert.equal(gate.calls.challenge, 1, 'exactly one challenge round trip for two concurrent callers');
    assert.equal(gate.calls.verify, 1, 'exactly one verify round trip');
  });

  it('three concurrent expired-JWT operations still trigger exactly one refresh', async () => {
    const client = await expiredJwtClient('jwt-race-3@example.com');
    const gate = gatedMockFetch();

    const ps = [client.listSessions(), client.listSessions(), client.listSessions()];
    await new Promise((r) => setTimeout(r, 20));
    gate.release();
    await Promise.all(ps);

    assert.equal(gate.calls.challenge, 1, 'one challenge for three concurrent callers');
    assert.equal(gate.calls.verify, 1, 'one verify for three concurrent callers');
  });

  it('a subsequent refresh after the first settles starts a fresh challenge (slot cleared)', async () => {
    // Proves the #jwtRefreshPromise slot is released on settle: a second
    // expired-JWT episode must be able to start its own refresh, not be
    // wedged behind a stale promise.
    const client = await expiredJwtClient('jwt-race-seq@example.com');
    const gate = gatedMockFetch();

    const first = client.listSessions();
    await new Promise((r) => setTimeout(r, 20));
    gate.release();
    await first;
    assert.equal(gate.calls.challenge, 1, 'first episode: one challenge');

    // The verify above issued a fresh (valid) JWT, so to force a SECOND
    // refresh we re-expire the in-memory JWT by serializing → expiring →
    // resuming into a new client that reuses the same gate counters.
    const payload = await decryptBlobToPayload(await client.serializeSession());
    payload.jwt = fakeJwt(-3600);
    payload.expiresAt = Math.floor(Date.now() / 1000) + 7 * 24 * 3600;
    const reBlob = await reencryptPayload(payload);
    const client2 = await TarnClient.resumeSession('https://api.tarn.dev', APP, reBlob);

    // Reinstall the gate but pre-release it so the second refresh runs through.
    const gate2 = gatedMockFetch();
    gate2.release();
    await client2.listSessions();
    assert.equal(gate2.calls.challenge, 1, 'second episode starts its own challenge (slot was cleared)');
  });
});

describe('SDK-9 — TarnNotAuthenticatedError', () => {
  afterEach(restoreFetch);

  it('is a proper typed Error, exported from the public surface', async () => {
    const e = new TarnNotAuthenticatedError('nope');
    assert.ok(e instanceof Error);
    assert.ok(e instanceof TarnNotAuthenticatedError);
    assert.equal(e.name, 'TarnNotAuthenticatedError');
    assert.equal(e.message, 'nope');

    const mod = await import('../../client/src/index.js');
    assert.equal(mod.TarnNotAuthenticatedError, TarnNotAuthenticatedError, 're-exported from index');
  });

  it('#requireAuth throws TarnNotAuthenticatedError on a never-logged-in client', async () => {
    globalThis.fetch = async () => { throw new Error('no network expected'); };
    const fresh = new TarnClient('https://api.tarn.dev', APP);
    await assert.rejects(
      () => fresh.listSessions(),
      (err) => err instanceof TarnNotAuthenticatedError && /call register\(\) or login\(\)/.test(err.message),
    );
  });

  it('#requireAuth throws TarnNotAuthenticatedError when JWT is expired with no signing keys', async () => {
    // Build a passkey-only-shaped client (no signing keys, no
    // credentialLookupKey) whose JWT is expired. #requireAuth can't refresh
    // and must surface the typed error rather than a generic one.
    const reg = await expiredJwtClient('sdk9-expired@example.com');
    const payload = await decryptBlobToPayload(await reg.serializeSession());
    payload.jwt = fakeJwt(-3600);
    payload.signingPrivateKey = null;
    payload.signingPublicKey = null;
    payload.credentialLookupKey = null;
    payload.expiresAt = Math.floor(Date.now() / 1000) + 7 * 24 * 3600;
    const blob = await reencryptPayload(payload);
    const client = await TarnClient.resumeSession('https://api.tarn.dev', APP, blob);
    assert.ok(client, 'sanity: resume succeeded (passkey-only shape with expired JWT)');

    globalThis.fetch = async () => { throw new Error('no network expected'); };
    await assert.rejects(
      () => client.listSessions(),
      (err) => err instanceof TarnNotAuthenticatedError && /no signing keys available/.test(err.message),
    );
  });
});
