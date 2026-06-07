// Tarn #32 Phase 2 — passkey-vs-password session symmetry.
//
// The Tarn passkey contract (see `client/README.md` "Passkey session
// capabilities" + `docs/SDK_ARCHITECTURE.md`) says:
//
//   Initial auth step differs. Everything downstream — "you're
//   authenticated, here's your data" — should be identical, EXCEPT for a
//   small, documented set of operations that genuinely require the
//   master_key-derived state that passkey sessions don't carry.
//
// Symmetric ops (entry CRUD, list, isLoggedIn, serializeSession,
// resumeSession) MUST work identically across auth methods. Asymmetric
// ops (share-log writes/read, connection handshake, credential rotation,
// account-key ops) MUST reject passkey-only sessions with a typed
// `TarnPasskeyOnlyError` rather than crash on a null-deref.
//
// Phase 1 of this audit found a live HIGH-severity null-deref in
// `#hydrateOutboundState` that crashed `Collection.share()` /
// `shareContent` / `unshareContent` / `snapshotShareLog` /
// `removeConnection` / `revokeContentFromConnections` on passkey-only
// sessions. Phase 2 (this commit) adds typed guards + tests.
//
// Strategy follows `session-resume-passkey-only.test.js` (issue #27): build
// a passkey-only session by registering with password, serializing,
// stripping the master_key-derived fields from the blob, and resuming —
// the resulting client has the exact field-state shape that
// `authenticateWithPasskey()` would leave on a fresh client.
//
// Run: node --import tsx --test tests/unit/passkey-session-symmetry.test.js

import '../indexeddb-shim.mjs';
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient, TarnPasskeyOnlyError } from '../../client/src/tarn.js';
import { Collection } from '../../client/src/collections/index.js';
import {
  encryptSessionBlob,
  decryptSessionBlob,
  getOrCreateWrappingKey,
} from '../../client/src/session-persistence.js';

const APP = 'bookish';
const PASSWORD = 'symmetry-test-pass-2026';

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

// Strip master_key-derived fields to simulate `authenticateWithPasskey()`
// — byte-equivalent to what a passkey-only client persists.
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
  return await reencryptPayload(payload);
}

async function passkeyOnlyClient(label) {
  const passkeyOnlyBlob = await toPasskeyOnlyBlob(await (await registerClient(label)).serializeSession());
  const client = await TarnClient.resumeSession('https://api.tarn.dev', APP, passkeyOnlyBlob);
  assert.ok(client, 'sanity: passkey-only resume must succeed');
  return client;
}

// A connection object with the minimum fields the share-log surface needs.
// The actual share_pub bytes are unimportant for these tests — the guards
// fire before any cryptographic work touches them.
const FAKE_CONNECTION = {
  share_pub: bytesToBase64Url(new Uint8Array(32).fill(7)),
  signing_pub: bytesToBase64Url(new Uint8Array(65).fill(4)),
};

// ============ ASYMMETRIC OPS — must reject passkey-only sessions ============

describe('Tarn #32 — share-log writes reject passkey-only sessions', () => {
  afterEach(restoreFetch);

  it('shareContent throws TarnPasskeyOnlyError on a passkey-only session', async () => {
    const client = await passkeyOnlyClient('symmetry-share@example.com');
    let thrown = null;
    try {
      await client.shareContent(FAKE_CONNECTION, 'book:1', 'tx-fake', bytesToBase64Url(new Uint8Array(32).fill(1)));
    } catch (err) {
      thrown = err;
    }
    assert.ok(thrown, 'shareContent must throw on a passkey-only session');
    assert.ok(
      thrown instanceof TarnPasskeyOnlyError,
      `must be TarnPasskeyOnlyError, got ${thrown?.constructor?.name}: ${thrown?.message}`,
    );
    assert.equal(thrown.name, 'TarnPasskeyOnlyError');
    assert.match(thrown.message, /password-authenticated session/);
  });

  it('updateShareContent throws TarnPasskeyOnlyError on a passkey-only session', async () => {
    const client = await passkeyOnlyClient('symmetry-update@example.com');
    await assert.rejects(
      () => client.updateShareContent(FAKE_CONNECTION, 'book:1', 'tx-new'),
      (err) => err instanceof TarnPasskeyOnlyError && /password-authenticated session/.test(err.message),
    );
  });

  it('unshareContent throws TarnPasskeyOnlyError on a passkey-only session', async () => {
    const client = await passkeyOnlyClient('symmetry-unshare@example.com');
    await assert.rejects(
      () => client.unshareContent(FAKE_CONNECTION, 'book:1'),
      (err) => err instanceof TarnPasskeyOnlyError,
    );
  });

  it('snapshotShareLog throws TarnPasskeyOnlyError on a passkey-only session', async () => {
    const client = await passkeyOnlyClient('symmetry-snapshot@example.com');
    await assert.rejects(
      () => client.snapshotShareLog(FAKE_CONNECTION),
      (err) => err instanceof TarnPasskeyOnlyError,
    );
  });

  it('snapshotShareLog with explicit state still throws TarnPasskeyOnlyError on a passkey-only session', async () => {
    // Without the public-entry guard, passing an explicit `state` would
    // bypass `#hydrateOutboundState` and the throw would only surface
    // inside `_publishShareLogEntry`. The public guard makes the surface
    // uniform regardless of which internal path runs.
    const client = await passkeyOnlyClient('symmetry-snapshot-explicit@example.com');
    await assert.rejects(
      () => client.snapshotShareLog(FAKE_CONNECTION, { 'book:1': { tx_id: 'tx-1', cek: 'cek-1' } }),
      (err) => err instanceof TarnPasskeyOnlyError,
    );
  });

  it('removeConnection throws TarnPasskeyOnlyError on a passkey-only session', async () => {
    const client = await passkeyOnlyClient('symmetry-remove@example.com');
    await assert.rejects(
      () => client.removeConnection(FAKE_CONNECTION),
      (err) => err instanceof TarnPasskeyOnlyError,
    );
  });

  it('removeConnection(notify: true) throws TarnPasskeyOnlyError on a passkey-only session', async () => {
    const client = await passkeyOnlyClient('symmetry-remove-notify@example.com');
    await assert.rejects(
      () => client.removeConnection(FAKE_CONNECTION, { notify: true }),
      (err) => err instanceof TarnPasskeyOnlyError,
    );
  });

  it('revokeContentFromConnections throws TarnPasskeyOnlyError on a passkey-only session', async () => {
    const client = await passkeyOnlyClient('symmetry-revoke@example.com');
    await assert.rejects(
      () => client.revokeContentFromConnections('book:1'),
      (err) => err instanceof TarnPasskeyOnlyError,
    );
  });
});

describe('Tarn #32 — share-log reads reject passkey-only sessions', () => {
  afterEach(restoreFetch);

  it('readShareLog throws TarnPasskeyOnlyError on a passkey-only session', async () => {
    const client = await passkeyOnlyClient('symmetry-readlog@example.com');
    let thrown = null;
    try {
      await client.readShareLog(FAKE_CONNECTION);
    } catch (err) {
      thrown = err;
    }
    assert.ok(thrown, 'readShareLog must throw');
    assert.ok(
      thrown instanceof TarnPasskeyOnlyError,
      `must be TarnPasskeyOnlyError, got ${thrown?.constructor?.name}: ${thrown?.message}`,
    );
    assert.match(thrown.message, /password-authenticated session/);
  });
});

describe('Tarn #32 — Collection.share()/unshare() propagate TarnPasskeyOnlyError', () => {
  afterEach(restoreFetch);

  // Collection.share() does a `getEntryByEid` lookup first, then calls
  // shareContent. To exercise the share-path guard end-to-end we build a
  // Collection over a synthetic ITarnClient that returns a fake entry from
  // getEntryByEid and delegates shareContent to the real TarnClient (which
  // is in passkey-only state). The typed error must propagate up through
  // the Collection layer unchanged.
  function makeFakeITarnClient(realClient) {
    return {
      isLoggedIn: () => true,
      async getEntries() { return []; },
      async getEntryByEid() {
        // Return a synthetic entry so Collection.share gets past #findCurrent.
        return { txid: 'tx-existing', data: { bookId: 'b1', title: 'A' }, tags: [] };
      },
      async getEntriesSince() { return { entries: [], deleted: [] }; },
      async getShareKey() { return bytesToBase64Url(new Uint8Array(32).fill(2)); },
      async fetchBlob() { return new Uint8Array(0); },
      async decryptSharedBlob() { return {}; },
      async createEntry() { return { txid: 'tx-new', shareKey: 'sk' }; },
      async batchCreate() { return []; },
      async updateEntry() { return { txid: 'tx-up', shareKey: 'sk' }; },
      async deleteEntry() { return { txid: 'tx-del' }; },
      async listConnections() { return []; },
      async isMuted() { return false; },
      // Delegate sharing ops to the real client — guards fire here.
      async shareContent(connection, contentId, txid, shareKey) {
        return await realClient.shareContent(connection, contentId, txid, shareKey);
      },
      async unshareContent(connection, contentId) {
        return await realClient.unshareContent(connection, contentId);
      },
      async readShareLog(connection, opts) {
        return await realClient.readShareLog(connection, opts);
      },
    };
  }

  const SHAREABLE_DEF = {
    primaryKey: 'bookId',
    fields: {
      bookId: 'string',
      title: 'string',
    },
    shareable: true,
  };

  it('Collection.share() on passkey-only session throws TarnPasskeyOnlyError', async () => {
    const realClient = await passkeyOnlyClient('symmetry-coll-share@example.com');
    const fake = makeFakeITarnClient(realClient);
    const books = new Collection({
      client: fake, appId: APP, name: 'books', def: SHAREABLE_DEF, schemaVersion: 4,
    });
    await assert.rejects(
      () => books.share(FAKE_CONNECTION, 'b1'),
      (err) => err instanceof TarnPasskeyOnlyError,
    );
  });

  it('Collection.unshare() on passkey-only session throws TarnPasskeyOnlyError', async () => {
    const realClient = await passkeyOnlyClient('symmetry-coll-unshare@example.com');
    const fake = makeFakeITarnClient(realClient);
    const books = new Collection({
      client: fake, appId: APP, name: 'books', def: SHAREABLE_DEF, schemaVersion: 4,
    });
    await assert.rejects(
      () => books.unshare(FAKE_CONNECTION, 'b1'),
      (err) => err instanceof TarnPasskeyOnlyError,
    );
  });
});

// ============ SYMMETRIC OPS — must work identically across auth methods ============

describe('Tarn #32 — session lifecycle is symmetric across auth methods', () => {
  afterEach(restoreFetch);

  it('isLoggedIn() returns true after a passkey-only resume (regression for #27)', async () => {
    const client = await passkeyOnlyClient('symmetry-isloggedin@example.com');
    assert.equal(client.isLoggedIn(), true, 'passkey-only resumed client must report logged in');
  });

  it('serializeSession round-trips on a passkey-only session', async () => {
    const client = await passkeyOnlyClient('symmetry-serialize@example.com');
    const blob = await client.serializeSession();
    assert.equal(typeof blob, 'string');
    assert.ok(blob.length > 0, 'passkey-only session must produce a non-empty blob');
    // And the blob must be re-resumable.
    const resumed = await TarnClient.resumeSession('https://api.tarn.dev', APP, blob);
    assert.ok(resumed, 'passkey-only blob must round-trip through resume');
    assert.equal(resumed.isLoggedIn(), true);
  });

  it('TarnPasskeyOnlyError is NOT thrown by symmetric ops on a password session (no over-rejection)', async () => {
    // Sanity: the guard only fires on passkey-only state. A real
    // password-authenticated client must NOT see TarnPasskeyOnlyError when
    // it tries to use the share-log surface. We assert this indirectly:
    // a password-authenticated client has both #signingKeyPair and
    // #sharingKeyPair populated; any error from share-log calls on it is
    // either a network/protocol error or some other class — never
    // TarnPasskeyOnlyError.
    const passwordClient = await registerClient('symmetry-no-overreject@example.com');
    restoreFetch();
    // Stub all further fetches to a clean failure so we can be sure the
    // error class we see is NOT the passkey-only one.
    globalThis.fetch = async () => { throw new Error('network down'); };
    let caught = null;
    try {
      await passwordClient.shareContent(FAKE_CONNECTION, 'book:1', 'tx-fake', bytesToBase64Url(new Uint8Array(32).fill(1)));
    } catch (err) {
      caught = err;
    }
    assert.ok(caught, 'sanity: with network down, shareContent must throw something');
    assert.ok(
      !(caught instanceof TarnPasskeyOnlyError),
      `password session must NOT throw TarnPasskeyOnlyError, got ${caught?.constructor?.name}: ${caught?.message}`,
    );
  });
});

// ============ SDK-10 — changeCredentials passkey-capability errors ============

// Strip ONLY recoveryFactorMeta from a full-session blob. This produces the
// narrow state SDK-10 targets: signing keys + username + credentialLookupKey
// all present (so the upfront passkey-only guard passes), but no
// recovery-factor metadata — the deeper branch that previously threw a generic
// "missing recovery-factor metadata (corrupt session?)" Error.
async function noRecoveryMetaBlob(fullBlob) {
  const payload = await decryptBlobToPayload(fullBlob);
  payload.recoveryFactorMeta = null;
  return await reencryptPayload(payload);
}

describe('SDK-10 — changeCredentials rejects under-provisioned sessions with TarnPasskeyOnlyError', () => {
  afterEach(restoreFetch);

  it('passkey-only session: changeCredentials throws TarnPasskeyOnlyError (upfront guard)', async () => {
    const client = await passkeyOnlyClient('sdk10-passkey-only@example.com');
    let thrown = null;
    try {
      await client.changeCredentials('new@example.com', 'new-password-2026', {
        acceptRecoveryGap: true, skipRotationAnnounce: true,
      });
    } catch (err) {
      thrown = err;
    }
    assert.ok(thrown, 'changeCredentials must throw on a passkey-only session');
    assert.ok(
      thrown instanceof TarnPasskeyOnlyError,
      `must be TarnPasskeyOnlyError, got ${thrown?.constructor?.name}: ${thrown?.message}`,
    );
    assert.equal(thrown.name, 'TarnPasskeyOnlyError');
    assert.match(thrown.message, /password-authenticated session/);
  });

  it('session missing recovery-factor metadata: throws TarnPasskeyOnlyError, not a generic Error', async () => {
    // SDK-10 core case: signing keys + username + credentialLookupKey present
    // (upfront guard passes) but recoveryFactorMeta absent. Before the fix this
    // threw `new Error('...missing recovery-factor metadata (corrupt session?)')`.
    const fullBlob = await (await registerClient('sdk10-no-recmeta@example.com')).serializeSession();
    const blob = await noRecoveryMetaBlob(fullBlob);
    const client = await TarnClient.resumeSession('https://api.tarn.dev', APP, blob);
    assert.ok(client, 'sanity: resume with null recoveryFactorMeta must succeed');

    let thrown = null;
    try {
      // phrase supplied so we get PAST the "must supply phrase" check and reach
      // the recovery-factor-metadata branch specifically.
      await client.changeCredentials('new2@example.com', 'new-password-2026', {
        phrase: 'word '.repeat(24).trim(), skipRotationAnnounce: true,
      });
    } catch (err) {
      thrown = err;
    }
    assert.ok(thrown, 'changeCredentials must throw when recovery-factor metadata is missing');
    assert.ok(
      thrown instanceof TarnPasskeyOnlyError,
      `must be TarnPasskeyOnlyError (SDK-10), got ${thrown?.constructor?.name}: ${thrown?.message}`,
    );
    assert.equal(thrown.name, 'TarnPasskeyOnlyError');
    assert.match(thrown.message, /password-authenticated session/);
    assert.doesNotMatch(thrown.message, /corrupt session/, 'old indirect message must be gone');
  });
});

// ============ TarnPasskeyOnlyError shape ============

describe('Tarn #32 — TarnPasskeyOnlyError is a proper typed error', () => {
  it('is an instance of Error', () => {
    const e = new TarnPasskeyOnlyError('hello');
    assert.ok(e instanceof Error);
    assert.ok(e instanceof TarnPasskeyOnlyError);
  });

  it('has name=TarnPasskeyOnlyError', () => {
    const e = new TarnPasskeyOnlyError('hello');
    assert.equal(e.name, 'TarnPasskeyOnlyError');
  });

  it('preserves the message it was constructed with', () => {
    const e = new TarnPasskeyOnlyError('custom message goes here');
    assert.equal(e.message, 'custom message goes here');
  });

  it('is re-exported from the SDK public surface (../../client/src/index.ts)', async () => {
    const mod = await import('../../client/src/index.js');
    assert.ok(typeof mod.TarnPasskeyOnlyError === 'function', 'must be exported from index');
    assert.equal(mod.TarnPasskeyOnlyError, TarnPasskeyOnlyError, 'must be the same class as the one in tarn.ts');
  });
});
