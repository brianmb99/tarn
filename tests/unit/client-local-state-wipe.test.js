// Unit tests for the per-account local-state wipe on logout (issue #71).
//
// Background: `session.clear()` used to forget only the wrapped session
// blob; the SDK's per-account IndexedDB stores survived logout:
//   - tarn-sync-cursors (keyed `${appId}:${dlk}:${type}`) — a stale cursor
//     after the app wipes its own cache makes the next delta sync silently
//     skip history ("missing data" after re-login; real production incident
//     2026-06-11).
//   - tarn-blob-cache (keyed `${appId}:${dlk}:${txid}`) — the previous
//     account's ciphertext lingered on shared devices.
//
// These tests verify:
//   - clearSession() wipes BOTH stores for the current (appId, dlk) only;
//     other accounts' / apps' entries survive the prefix wipe.
//   - deleteAccount() wipes too (runs before the dlk field is nulled).
//   - changeCredentials() does NOT wipe — the dlk is stable across
//     credential rotation, so the cursor stays valid and wiping would only
//     force a needless full resync.
//   - A broken cache store never breaks logout: clearSession() resolves
//     even when opening the cache DBs fails.
//
// Run: node --test tests/unit/client-local-state-wipe.test.js

import '../indexeddb-shim.mjs';
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient } from '../../client/src/tarn.js';
import { getCursor, setCursor } from '../../client/src/sync-cursor.js';
import { getCachedBlob, setCachedBlob } from '../../client/src/blob-cache.js';

const APP = 'bookish';
const OTHER_APP = 'otherapp';
const EMAIL = 'local-state-wipe@example.com';
const PASSWORD = 'wipe-test-pass-2026';

const originalFetch = globalThis.fetch;
let fetchResponses = [];

function mockFetch(responses) {
  fetchResponses = responses.slice();
  globalThis.fetch = async (url) => {
    const next = fetchResponses.shift();
    if (!next) throw new Error(`mockFetch: no response queued for ${url}`);
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
  fetchResponses = [];
}

// Decodable JWT with far-future exp so #requireAuth() accepts it without an
// extra challenge/verify round trip (same pattern as the other unit tests).
function fakeJwt(label = 'jwt') {
  const b64url = (s) => btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const header = b64url('{"alg":"none"}');
  const payload = b64url(JSON.stringify({ sub: label, exp: Math.floor(Date.now() / 1000) + 3600 }));
  return `${header}.${payload}.`;
}

// Each test gets unique dlks so state doesn't bleed between tests.
function uniqueDlk() {
  return Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
}

function registerResponses(dlk, label) {
  return [
    { status: 201, body: JSON.stringify({ data_lookup_key: dlk }) },
    { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
    { status: 200, body: JSON.stringify({ jwt: fakeJwt(label) }) },
  ];
}

async function registeredClient(dlk, label = 'reg') {
  mockFetch(registerResponses(dlk, label));
  const client = new TarnClient('https://api.tarn.dev', APP);
  await client.register(`${label}-${EMAIL}`, PASSWORD, { recoveryAcknowledged: true });
  return client;
}

// Seed both stores for (appId, dlk) plus foreign scopes that must survive.
async function seedStores(dlk, foreignDlk) {
  await setCursor(APP, dlk, 'books', 'cursor-mine-books');
  await setCursor(APP, dlk, 'notes', 'cursor-mine-notes');
  await setCachedBlob(APP, dlk, 'tx-mine', new Uint8Array([1, 2, 3]));
  // Same app, different account (dlk) — must survive.
  await setCursor(APP, foreignDlk, 'books', 'cursor-other-account');
  await setCachedBlob(APP, foreignDlk, 'tx-other', new Uint8Array([4, 5, 6]));
  // Different app, same dlk — must survive.
  await setCursor(OTHER_APP, dlk, 'books', 'cursor-other-app');
}

async function assertForeignScopesSurvive(dlk, foreignDlk) {
  assert.equal(
    await getCursor(APP, foreignDlk, 'books'),
    'cursor-other-account',
    'another account\'s cursor must survive the prefix wipe',
  );
  assert.ok(
    (await getCachedBlob(APP, foreignDlk, 'tx-other')) instanceof Uint8Array,
    'another account\'s cached blob must survive the prefix wipe',
  );
  assert.equal(
    await getCursor(OTHER_APP, dlk, 'books'),
    'cursor-other-app',
    'another app\'s cursor must survive the prefix wipe',
  );
}

describe('Issue #71 — clearSession() wipes per-account local state', () => {
  afterEach(restoreFetch);

  it('removes cursors + cached blobs for the current (appId, dlk) only', async () => {
    const dlk = uniqueDlk();
    const foreignDlk = uniqueDlk();
    const client = await registeredClient(dlk, 'wipe');
    await seedStores(dlk, foreignDlk);

    await client.clearSession();

    assert.equal(await getCursor(APP, dlk, 'books'), null, 'books cursor must be wiped');
    assert.equal(await getCursor(APP, dlk, 'notes'), null, 'notes cursor must be wiped (all types)');
    assert.equal(await getCachedBlob(APP, dlk, 'tx-mine'), null, 'cached blob must be wiped');
    await assertForeignScopesSurvive(dlk, foreignDlk);
  });

  it('is a no-op on a client that never logged in (no dlk)', async () => {
    const dlk = uniqueDlk();
    await setCursor(APP, dlk, 'books', 'cursor-untouched');

    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.clearSession(); // must not throw

    assert.equal(
      await getCursor(APP, dlk, 'books'),
      'cursor-untouched',
      'no scope to wipe — existing cursors must be untouched',
    );
  });

  it('a broken cache store does not break logout (clearSession resolves)', async () => {
    const dlk = uniqueDlk();
    const client = await registeredClient(dlk, 'broken');

    // Poison opens of the two cache DBs only; tarn-session (wrapping key)
    // passes through to the real shim so the rest of clearSession works.
    const realIDB = globalThis.indexedDB;
    globalThis.indexedDB = {
      open(name, version) {
        if (name === 'tarn-sync-cursors' || name === 'tarn-blob-cache') {
          const req = {
            onupgradeneeded: null, onsuccess: null, onerror: null,
            result: null, error: new Error('synthetic IndexedDB failure'),
          };
          queueMicrotask(() => req.onerror?.({ target: req }));
          return req;
        }
        return realIDB.open(name, version);
      },
    };
    try {
      await assert.doesNotReject(
        () => client.clearSession(),
        'wipe failure must never break logout',
      );
    } finally {
      globalThis.indexedDB = realIDB;
    }
  });
});

describe('Issue #71 — deleteAccount() wipes per-account local state', () => {
  afterEach(restoreFetch);

  it('removes cursors + cached blobs for the deleted account only', async () => {
    const dlk = uniqueDlk();
    const foreignDlk = uniqueDlk();
    const client = await registeredClient(dlk, 'del');
    await seedStores(dlk, foreignDlk);

    // deleteAccount: DELETE /api/v1/auth → 200 (jwt from register is still
    // fresh, so no extra challenge/verify round trip).
    mockFetch([{ status: 200, body: JSON.stringify({}) }]);
    await client.deleteAccount();

    assert.equal(await getCursor(APP, dlk, 'books'), null, 'cursor must be wiped on account deletion');
    assert.equal(await getCachedBlob(APP, dlk, 'tx-mine'), null, 'cached blob must be wiped on account deletion');
    await assertForeignScopesSurvive(dlk, foreignDlk);
  });
});

describe('Issue #71 — changeCredentials() does NOT wipe (dlk is stable)', () => {
  afterEach(restoreFetch);

  it('cursors + cached blobs survive a credential rotation', async () => {
    const dlk = uniqueDlk();
    const client = await registeredClient(dlk, 'rot');
    await setCursor(APP, dlk, 'books', 'cursor-survives-rotation');
    await setCachedBlob(APP, dlk, 'tx-keep', new Uint8Array([7, 8, 9]));

    // changeCredentials: PUT /api/v1/auth → 200, then re-auth challenge +
    // verify (same mock shape as client-credential-change.test.js).
    mockFetch([
      { status: 200, body: JSON.stringify({}) },
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('rot2') }) },
    ]);
    await client.changeCredentials('rotated@example.com', 'rotated-pass-2026', {
      acceptRecoveryGap: true,
      skipRotationAnnounce: true,
    });

    // The dlk did not change, the server-issued cursor is still valid, and
    // the cached ciphertext is still decryptable via the re-wrapped DEK
    // chain — wiping here would only force a needless full resync.
    assert.equal(
      await getCursor(APP, dlk, 'books'),
      'cursor-survives-rotation',
      'cursor must survive changeCredentials',
    );
    assert.ok(
      (await getCachedBlob(APP, dlk, 'tx-keep')) instanceof Uint8Array,
      'cached blob must survive changeCredentials',
    );
  });
});
