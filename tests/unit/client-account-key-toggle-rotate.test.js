// Unit tests for Phase 4 — account-key storage toggle (enable/disable)
// and rotation orchestration in TarnClient.
//
// Covers:
//   - enableKeyStorage: validates phrase, runs step-up, computes the wrap,
//     PUTs with JWT + step-up token, updates isAccountKeyStored()
//   - enableKeyStorage: rejects invalid phrase synchronously
//   - enableKeyStorage: pin-check rejects a valid-but-unrelated phrase
//     before any network call
//   - enableKeyStorage: surfaces step-up auth failure (wrong password)
//   - disableKeyStorage: runs step-up, DELETEs with both auth headers,
//     updates isAccountKeyStored()
//   - disableKeyStorage: maps already-disabled response to
//     `{ stored: false, alreadyDisabled: true }`
//   - rotateAccountKey: re-derives password keys, generates a fresh phrase,
//     wraps the chain under {existing password KEK, new recovery KEK},
//     submits to /account/rotate-account-key, updates cached recovery state
//   - rotateAccountKey: rejects on wrong password without touching the API
//   - rotateAccountKey: forwards 409 conflicts as descriptive errors
//   - rotateAccountKey: updates the cached recovery_lookup_key so a
//     subsequent enableKeyStorage uses the new pin value
//
// Run: node --test tests/unit/client-account-key-toggle-rotate.test.js

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  TarnClient,
  AccountKeyPinningError,
  generateAccountKey,
} from '../../client/src/tarn.js';

const APP = 'bookish';

const originalFetch = globalThis.fetch;
let fetchCalls = [];
let fetchResponses = [];

function mockFetch(responses) {
  fetchCalls = [];
  fetchResponses = responses.slice();
  globalThis.fetch = async (url, opts) => {
    fetchCalls.push({ url, method: opts?.method || 'GET', body: opts?.body, headers: opts?.headers });
    const next = fetchResponses.shift();
    if (!next) throw new Error(`mockFetch: no response queued for ${url} (${opts?.method || 'GET'})`);
    if (next instanceof Error) throw next;
    return {
      status: next.status,
      headers: { get: () => null },
      text: async () => next.body ?? '',
      body: { cancel: () => {} },
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

// Boilerplate: stand up a registered Model B client. Returns the client +
// the captured registration body so tests can read derived values
// (recovery_lookup_key, the original wrap, etc.) without re-deriving them.
async function registerModelB(opts = {}) {
  mockFetch([
    { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
    { status: 200, body: JSON.stringify({ nonce: 'b'.repeat(64) }) },
    { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg'), account_key_stored: true }) },
  ]);
  const client = new TarnClient('https://api.tarn.dev', APP);
  const reg = await client.register(
    opts.username || 'u@x.com',
    opts.password || 'pw-2026',
    { recoveryAcknowledged: true },
  );
  const registerCall = fetchCalls.find(c => c.url.endsWith('/auth/register'));
  const registerBody = JSON.parse(registerCall.body);
  return { client, registerBody, accountKey: reg.accountKey };
}

// ============ enableKeyStorage ============

describe('TarnClient.enableKeyStorage', () => {
  afterEach(restoreFetch);

  it('rejects an invalid phrase synchronously (no network call)', async () => {
    const { client } = await registerModelB();
    restoreFetch();
    mockFetch([]); // assert no fetches by leaving the queue empty
    await assert.rejects(
      () => client.enableKeyStorage({ password: 'pw-2026', accountKey: 'not a real phrase' }),
      /invalid account key/,
    );
    assert.equal(fetchCalls.length, 0);
  });

  it('rejects when phrase derives a different recovery_lookup_key (pin check)', async () => {
    const { client } = await registerModelB();
    // Generate a DIFFERENT valid 24-word phrase. With overwhelming probability
    // it derives a different recovery_lookup_key than the one cached on the
    // client from registration → pin-check should fire.
    const otherPhrase = generateAccountKey();
    restoreFetch();
    mockFetch([]); // no fetches expected — pin check fails before step-up
    await assert.rejects(
      () => client.enableKeyStorage({ password: 'pw-2026', accountKey: otherPhrase }),
      AccountKeyPinningError,
    );
    assert.equal(fetchCalls.length, 0);
  });

  it('full happy path: validate → step-up → PUT → update isStored()', async () => {
    const { client, accountKey } = await registerModelB();
    restoreFetch();
    mockFetch([
      // /auth/challenge for step-up
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64), data_lookup_key: 'd'.repeat(64) }) },
      // /auth/step-up
      { status: 200, body: JSON.stringify({ step_up_token: 'tok-enable', expires_at: Date.now() + 60000, scope: 'account_key_fetch' }) },
      // PUT /account/account-key
      { status: 200, body: JSON.stringify({ stored: true }) },
    ]);

    const out = await client.enableKeyStorage({ password: 'pw-2026', accountKey });
    assert.deepEqual(out, { stored: true });
    assert.equal(client.isAccountKeyStored(), true);

    const putCall = fetchCalls.find(c => c.url.endsWith('/account/account-key') && c.method === 'PUT');
    assert.ok(putCall, 'must call PUT /account/account-key');
    assert.equal(putCall.headers['X-Step-Up-Token'], 'tok-enable');
    assert.match(putCall.headers['Authorization'], /^Bearer /);
    const putBody = JSON.parse(putCall.body);
    assert.ok(putBody.wrapped_account_key, 'must include wrapped_account_key in body');
    assert.match(putBody.wrapped_account_key, /^[A-Za-z0-9+/=]+$/);
    assert.ok(putBody.wrapped_account_key.length >= 100);
  });

  it('surfaces step-up 401 as a wrong-password error (no state mutation)', async () => {
    // Register Model A so isStored() starts as false; a failed enable
    // must NOT flip it to true.
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'b'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg'), account_key_stored: false }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    const reg = await client.register('a@x.com', 'right-pw', {
      recoveryAcknowledged: true,
      storeAccountKey: false,
    });
    assert.equal(client.isAccountKeyStored(), false);

    restoreFetch();
    mockFetch([
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64), data_lookup_key: 'd'.repeat(64) }) },
      { status: 401, body: JSON.stringify({ error: 'Invalid signature' }) },
    ]);
    await assert.rejects(
      () => client.enableKeyStorage({ password: 'wrong-pw', accountKey: reg.accountKey }),
      /step-up auth failed/,
    );
    // Still Model A — the failed enable must not have toggled the cached flag.
    assert.equal(client.isAccountKeyStored(), false);
  });
});

// ============ disableKeyStorage ============

describe('TarnClient.disableKeyStorage', () => {
  afterEach(restoreFetch);

  it('full happy path: step-up → DELETE → update isStored()', async () => {
    const { client } = await registerModelB();
    restoreFetch();
    mockFetch([
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64), data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ step_up_token: 'tok-disable', expires_at: Date.now() + 60000, scope: 'account_key_fetch' }) },
      { status: 200, body: JSON.stringify({ stored: false }) },
    ]);
    const out = await client.disableKeyStorage({ password: 'pw-2026' });
    assert.deepEqual(out, { stored: false });
    assert.equal(client.isAccountKeyStored(), false);

    const del = fetchCalls.find(c => c.url.endsWith('/account/account-key') && c.method === 'DELETE');
    assert.ok(del, 'must call DELETE /account/account-key');
    assert.equal(del.headers['X-Step-Up-Token'], 'tok-disable');
    assert.match(del.headers['Authorization'], /^Bearer /);
  });

  it('maps the already_disabled response to alreadyDisabled: true', async () => {
    const { client } = await registerModelB();
    restoreFetch();
    mockFetch([
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64), data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ step_up_token: 'tok-x', expires_at: Date.now() + 60000, scope: 'account_key_fetch' }) },
      { status: 200, body: JSON.stringify({ stored: false, already_disabled: true }) },
    ]);
    const out = await client.disableKeyStorage({ password: 'pw-2026' });
    assert.equal(out.stored, false);
    assert.equal(out.alreadyDisabled, true);
    assert.equal(client.isAccountKeyStored(), false);
  });

  it('rejects without changing local state on step-up failure', async () => {
    const { client } = await registerModelB();
    restoreFetch();
    mockFetch([
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64), data_lookup_key: 'd'.repeat(64) }) },
      { status: 401, body: JSON.stringify({ error: 'Invalid signature' }) },
    ]);
    await assert.rejects(
      () => client.disableKeyStorage({ password: 'wrong-pw' }),
      /step-up auth failed/,
    );
    // State unchanged from the post-register Model B value.
    assert.equal(client.isAccountKeyStored(), true);
  });
});

// ============ rotateAccountKey ============

describe('TarnClient.rotateAccountKey', () => {
  afterEach(restoreFetch);

  it('returns a fresh 24-word account key on success', async () => {
    const { client, accountKey: oldKey } = await registerModelB();
    restoreFetch();
    mockFetch([
      // /auth/challenge for step-up (Phase 4.1 — rotate now requires step-up)
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64), data_lookup_key: 'd'.repeat(64) }) },
      // /auth/step-up
      { status: 200, body: JSON.stringify({ step_up_token: 'tok-rotate', expires_at: Date.now() + 60000, scope: 'account_key_fetch' }) },
      // POST /account/rotate-account-key
      { status: 200, body: JSON.stringify({ rotated: true }) },
    ]);
    const out = await client.rotateAccountKey({ password: 'pw-2026' });
    assert.ok(out.accountKey);
    assert.notEqual(out.accountKey, oldKey, 'rotation must produce a different key');
    assert.equal(out.accountKey.split(' ').length, 24);

    // Step-up must be invoked before rotate (Phase 4.1).
    const stepUpCall = fetchCalls.find(c => c.url.endsWith('/auth/step-up'));
    assert.ok(stepUpCall, 'must call /auth/step-up before rotating');
    const stepUpBody = JSON.parse(stepUpCall.body);
    assert.equal(stepUpBody.scope, 'account_key_fetch', 'step-up must use account_key_fetch scope');

    const rotateCall = fetchCalls.find(c => c.url.endsWith('/account/rotate-account-key'));
    assert.ok(rotateCall, 'must call /account/rotate-account-key');
    assert.equal(rotateCall.method, 'POST');
    assert.match(rotateCall.headers['Authorization'], /^Bearer /);
    assert.equal(rotateCall.headers['X-Step-Up-Token'], 'tok-rotate', 'rotate must carry the step-up token');
    const rotateBody = JSON.parse(rotateCall.body);
    assert.ok(rotateBody.new_envelope, 'must include new_envelope');
    assert.match(rotateBody.new_recovery_lookup_key, /^[a-f0-9]{64}$/);
    assert.ok(rotateBody.new_recovery_public_key, 'must include new_recovery_public_key');
    // Model B → wrapped_account_key present.
    assert.ok(rotateBody.new_wrapped_account_key, 'Model B rotation must include new_wrapped_account_key');
  });

  it('omits new_wrapped_account_key on a Model A account', async () => {
    // Register Model A so isAccountKeyStored() === false.
    mockFetch([
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ nonce: 'b'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg'), account_key_stored: false }) },
    ]);
    const client = new TarnClient('https://api.tarn.dev', APP);
    await client.register('a@x.com', 'pw-modelA', {
      recoveryAcknowledged: true,
      storeAccountKey: false,
    });
    assert.equal(client.isAccountKeyStored(), false);

    restoreFetch();
    mockFetch([
      // step-up challenge + token
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64), data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ step_up_token: 'tok-rotate-A', expires_at: Date.now() + 60000, scope: 'account_key_fetch' }) },
      // rotate POST
      { status: 200, body: JSON.stringify({ rotated: true }) },
    ]);
    const out = await client.rotateAccountKey({ password: 'pw-modelA' });
    assert.ok(out.accountKey);
    const rotateCall = fetchCalls.find(c => c.url.endsWith('/account/rotate-account-key'));
    const rotateBody = JSON.parse(rotateCall.body);
    assert.equal(rotateBody.new_wrapped_account_key, null, 'Model A rotation must NOT carry a wrap');
    assert.equal(rotateCall.headers['X-Step-Up-Token'], 'tok-rotate-A', 'Model A rotation also requires step-up');
  });

  it('rejects on wrong password without touching the API', async () => {
    const { client } = await registerModelB();
    restoreFetch();
    mockFetch([]); // no fetches expected — local credential mismatch tripwire fires first
    await assert.rejects(
      () => client.rotateAccountKey({ password: 'wrong-pw' }),
      /wrong password/,
    );
    assert.equal(fetchCalls.length, 0);
  });

  it('forwards 409 conflict as a descriptive error', async () => {
    const { client } = await registerModelB();
    restoreFetch();
    mockFetch([
      // step-up succeeds; conflict surfaces from the rotate POST itself
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64), data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ step_up_token: 'tok', expires_at: Date.now() + 60000, scope: 'account_key_fetch' }) },
      { status: 409, body: JSON.stringify({ error: 'new_recovery_lookup_key already in use' }) },
    ]);
    await assert.rejects(
      () => client.rotateAccountKey({ password: 'pw-2026' }),
      /conflict/,
    );
  });

  it('updates cached recovery state so a subsequent enableKeyStorage uses the new pin', async () => {
    // Rotate, then call enableKeyStorage with the OLD phrase — should fail
    // pin-check because the cached recovery_lookup_key was updated.
    const { client, accountKey: oldKey } = await registerModelB();
    restoreFetch();
    mockFetch([
      // step-up + rotate
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64), data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ step_up_token: 'tok', expires_at: Date.now() + 60000, scope: 'account_key_fetch' }) },
      { status: 200, body: JSON.stringify({ rotated: true }) },
    ]);
    const { accountKey: newKey } = await client.rotateAccountKey({ password: 'pw-2026' });
    assert.notEqual(newKey, oldKey);

    restoreFetch();
    mockFetch([]); // pin check should fail before any network call
    await assert.rejects(
      () => client.enableKeyStorage({ password: 'pw-2026', accountKey: oldKey }),
      AccountKeyPinningError,
    );
    assert.equal(fetchCalls.length, 0);

    // The NEW key should pass the pin check (then proceed to step-up which we
    // don't bother queuing for this assertion — just verify the pin path
    // doesn't fire on the new key).
    restoreFetch();
    mockFetch([
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64), data_lookup_key: 'd'.repeat(64) }) },
      { status: 200, body: JSON.stringify({ step_up_token: 'tok', expires_at: Date.now() + 60000, scope: 'account_key_fetch' }) },
      { status: 200, body: JSON.stringify({ stored: true }) },
    ]);
    const out = await client.enableKeyStorage({ password: 'pw-2026', accountKey: newKey });
    assert.deepEqual(out, { stored: true });
  });
});
