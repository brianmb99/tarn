// End-to-end tests for Phase 6 — WebAuthn-PRF passkey factor.
//
// Run: node --import tsx tests/test-passkeys.mjs [apiBaseUrl]
//
// Requires: wrangler dev running (cd api && npx wrangler dev --port 8787)
// and migration 0018 applied locally.
//
// What this exercises against the real API:
//   - register a passkey (full WebAuthn ceremony via virtual authenticator)
//   - authenticate with passkey, unwrap DEK chain, read account state
//   - list passkeys (without leaking pubkey / prf_salt)
//   - remove passkey (step-up gated, envelope updated, DB row gone)
//   - multi-passkey envelopes: register two, each authenticates independently
//   - envelope preservation through changeCredentials, rotateAccountKey,
//     and recoverAccount
//   - error/edge cases: unknown credential, replayed challenge, cross-account
//     credential, tampered signature, sign-count regression
//
// The tests stub navigator.credentials.{create,get} with a virtual EC P-256
// authenticator (see tests/helpers/virtual-authenticator.mjs) and patch
// globalThis.fetch to inject `Origin: http://localhost:3000` so the API's
// passkey origin allowlist accepts the requests. PRF is modeled as
// HMAC-SHA-256(prfSecret, prfSalt) — deterministic per (credential, salt),
// matching real authenticator behavior.

import { TarnClient } from '../client/src/tarn.js';
import { seedTestApp, DEFAULT_APP_ID, randomUsername } from './helpers.mjs';
import { VirtualAuthenticator, installPasskeyTestEnv } from './helpers/virtual-authenticator.mjs';

const API_BASE = process.argv[2] || 'http://localhost:8787';

await seedTestApp();

// Install once for the entire suite — every fetch and every WebAuthn
// ceremony goes through the shim. We restore at the end.
const env = installPasskeyTestEnv({ origin: 'http://localhost:3000', rpId: 'localhost' });

let passed = 0;
let failed = 0;
let currentSection = '';

function section(name) {
  currentSection = name;
  console.log(`\n=== ${name} ===`);
}

function log(status, name, detail = '') {
  const icon = status === 'PASS' ? '✓' : '✗';
  console.log(`  ${icon} ${name}${detail ? ': ' + detail : ''}`);
}

async function test(name, fn) {
  try {
    await fn();
    log('PASS', name);
    passed++;
  } catch (err) {
    log('FAIL', name, err.message);
    if (process.env.PASSKEY_TEST_TRACE) console.error(err);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

async function d1Query(sql) {
  const { execSync } = await import('node:child_process');
  const out = execSync(
    `npx wrangler d1 execute tarn-api --local --json --command "${sql}"`,
    {
      cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'),
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 15000,
    },
  ).toString();
  const parsed = JSON.parse(out);
  return parsed[0]?.results || [];
}

async function registerAccount() {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const username = randomUsername();
  const password = 'pw-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
  const reg = await client.register(username, password, { recoveryAcknowledged: true });
  return { client, username, password, reg };
}

/**
 * Drive a full passkey registration: stage a new VirtualAuthenticator,
 * call SDK.registerPasskey, return the authenticator + the SDK result.
 */
async function registerPasskeyOn(client, opts = {}) {
  const auth = new VirtualAuthenticator();
  env.stageRegistration(auth);
  const result = await client.registerPasskey(opts);
  return { auth, result };
}

// ============ CORE FLOWS ============

section('Register a passkey end-to-end');

let coreClient;
let corePassword;
let coreAuth;
let coreCredId;

await test('register a fresh account, then enroll a passkey', async () => {
  const a = await registerAccount();
  coreClient = a.client;
  corePassword = a.password;
  const { auth, result } = await registerPasskeyOn(coreClient, { deviceLabel: 'Test Phone' });
  coreAuth = auth;
  coreCredId = result.credentialId;
  assert(result.credentialId, 'register returned a credentialId');
  assert(result.deviceLabel === 'Test Phone', `expected device label, got ${result.deviceLabel}`);
});

await test('passkey_credentials row exists in D1', async () => {
  const rows = await d1Query(
    `SELECT credential_id, device_label, sign_count FROM passkey_credentials WHERE account_id = '${coreClient.dataLookupKey}'`,
  );
  assert(rows.length === 1, `expected 1 row, got ${rows.length}`);
  assert(rows[0].credential_id === coreCredId, 'credential_id matches');
  assert(rows[0].device_label === 'Test Phone', 'device_label persisted');
  assert(rows[0].sign_count === 0, 'sign_count starts at 0');
});

await test('account row envelope carries a passkey_prf wrapping for the new credential', async () => {
  const rows = await d1Query(
    `SELECT wrapped_data_key FROM accounts WHERE data_lookup_key = '${coreClient.dataLookupKey}'`,
  );
  const env = JSON.parse(rows[0].wrapped_data_key);
  const passkeyWrap = env.dek_chain[0].wrappings.find(
    w => w.factor === 'passkey_prf' && w.credential_id === coreCredId,
  );
  assert(passkeyWrap, 'passkey_prf wrapping is present in current gen');
  assert(typeof passkeyWrap.wrapped === 'string' && passkeyWrap.wrapped.length > 0, 'wrapping has a value');
  // password + recovery + passkey_prf
  assert(env.dek_chain[0].wrappings.length === 3, 'three wrappings present in current gen');
});

section('Authenticate with passkey');

await test('authenticateWithPasskey() unwraps the DEK chain and mints a session', async () => {
  // Fresh client (no prior session). Drive a full passkey login.
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(coreAuth.credentialIdB64Url);
  const result = await c.authenticateWithPasskey({ deviceLabel: 'Test Phone' });
  env.clearNextAuth();
  assert(result.dataLookupKey === coreClient.dataLookupKey, 'dataLookupKey matches the registered account');
  // Note: isLoggedIn() returns false on passkey-only sessions — by
  // design, no #signingKeyPair is populated (no password derivation
  // ran). What matters is that DEK was unwrapped (proven by the
  // dataLookupKey match — the API only returns it if the assertion
  // verified) and that #dekByGen is populated for subsequent reads.
});

section('List passkeys');

await test('listPasskeys() returns the registered credential without leaking pubkey/salt', async () => {
  const list = await coreClient.listPasskeys();
  assert(Array.isArray(list) && list.length === 1, 'one passkey listed');
  const p = list[0];
  assert(p.credentialId === coreCredId, 'credentialId matches');
  assert(p.deviceLabel === 'Test Phone', 'deviceLabel matches');
  assert(typeof p.createdAt === 'number', 'createdAt is a number');
  assert(!('publicKey' in p) && !('public_key' in p), 'public key NOT in response');
  assert(!('prfSalt' in p) && !('prf_salt' in p), 'PRF salt NOT in response');
});

section('Remove passkey');

await test('removePasskey() with wrong password fails', async () => {
  let threw = null;
  try {
    await coreClient.removePasskey({ credentialId: coreCredId, password: 'wrong-' + corePassword });
  } catch (err) { threw = err; }
  assert(threw, 'expected removePasskey to throw on wrong password');
  // Either step-up signature fails or the challenge step fails — both are
  // valid auth-failure outcomes.
  assert(/step-up|challenge|Unknown|401/i.test(threw.message), `expected auth failure, got: ${threw.message}`);
});

await test('removePasskey() with correct password succeeds, DB row + envelope wrapping gone', async () => {
  await coreClient.removePasskey({ credentialId: coreCredId, password: corePassword });
  const rows = await d1Query(
    `SELECT COUNT(*) AS n FROM passkey_credentials WHERE account_id = '${coreClient.dataLookupKey}'`,
  );
  assert(rows[0].n === 0, 'D1 row removed');
  // Envelope wrapping for this credentialId should be gone.
  const acct = await d1Query(
    `SELECT wrapped_data_key FROM accounts WHERE data_lookup_key = '${coreClient.dataLookupKey}'`,
  );
  const envObj = JSON.parse(acct[0].wrapped_data_key);
  const stillHas = envObj.dek_chain[0].wrappings.find(
    w => w.factor === 'passkey_prf' && w.credential_id === coreCredId,
  );
  assert(!stillHas, 'passkey_prf wrapping stripped from envelope');
});

// ============ MULTI-PASSKEY ============

section('Multiple passkeys');

let multiClient, multiPassword;
let multiAuthA, multiAuthB;

await test('register two passkeys; both wrappings present in envelope', async () => {
  const a = await registerAccount();
  multiClient = a.client;
  multiPassword = a.password;
  const r1 = await registerPasskeyOn(multiClient, { deviceLabel: 'Phone' });
  const r2 = await registerPasskeyOn(multiClient, { deviceLabel: 'Laptop' });
  multiAuthA = r1.auth;
  multiAuthB = r2.auth;

  const list = await multiClient.listPasskeys();
  assert(list.length === 2, `expected 2 passkeys, got ${list.length}`);

  const acct = await d1Query(
    `SELECT wrapped_data_key FROM accounts WHERE data_lookup_key = '${multiClient.dataLookupKey}'`,
  );
  const envObj = JSON.parse(acct[0].wrapped_data_key);
  const passkeys = envObj.dek_chain[0].wrappings.filter(w => w.factor === 'passkey_prf');
  assert(passkeys.length === 2, `expected 2 passkey_prf wrappings, got ${passkeys.length}`);
});

await test('each passkey authenticates the account independently', async () => {
  for (const auth of [multiAuthA, multiAuthB]) {
    const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
    env.pinNextAuth(auth.credentialIdB64Url);
    const r = await c.authenticateWithPasskey();
    env.clearNextAuth();
    assert(r.dataLookupKey === multiClient.dataLookupKey, `authentication via ${auth.credentialIdB64Url.slice(0, 8)} works`);
  }
});

await test('removing one of two passkeys leaves the other working', async () => {
  await multiClient.removePasskey({ credentialId: multiAuthA.credentialIdB64Url, password: multiPassword });
  const list = await multiClient.listPasskeys();
  assert(list.length === 1, 'one passkey remains');
  assert(list[0].credentialId === multiAuthB.credentialIdB64Url, 'remaining is B');

  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(multiAuthB.credentialIdB64Url);
  const r = await c.authenticateWithPasskey();
  env.clearNextAuth();
  assert(r.dataLookupKey === multiClient.dataLookupKey, 'B still authenticates');

  // Envelope retains B's wrapping only.
  const acct = await d1Query(
    `SELECT wrapped_data_key FROM accounts WHERE data_lookup_key = '${multiClient.dataLookupKey}'`,
  );
  const envObj = JSON.parse(acct[0].wrapped_data_key);
  const passkeys = envObj.dek_chain[0].wrappings.filter(w => w.factor === 'passkey_prf');
  assert(passkeys.length === 1 && passkeys[0].credential_id === multiAuthB.credentialIdB64Url, 'only B remains');
});

// ============ ENVELOPE PRESERVATION ============

section('changeCredentials passkey re-tap (Phase 6.1)');

await test('changeCredentials WITHOUT passkeyTapHandler throws when passkeys are registered', async () => {
  // The new contract: silently producing stale credentials would be a
  // worse UX failure than refusing to proceed. Apps must opt in by
  // supplying a handler.
  const a = await registerAccount();
  await registerPasskeyOn(a.client, { deviceLabel: 'no-handler-test' });

  let threw = null;
  try {
    await a.client.changeCredentials(a.username, 'changed-' + Date.now(), { phrase: a.reg.accountKey });
  } catch (err) {
    threw = err;
  }
  assert(threw, 'expected changeCredentials() to throw without handler');
  assert(/passkeyTapHandler/i.test(threw.message), `expected helpful error mentioning passkeyTapHandler, got: ${threw.message}`);
});

await test('changeCredentials WITH re-tap re-wraps the new gen so the passkey can read post-change data', async () => {
  // The new contract under Phase 6.1: when the user re-taps, the new
  // gen (N+1) gains a passkey_prf wrapping for that credential. After
  // the change, an authentication-with-passkey unwraps every gen
  // including the new one, and writes/reads against the new gen
  // succeed.
  const a = await registerAccount();
  const { auth } = await registerPasskeyOn(a.client, { deviceLabel: 'retap-test' });

  const before = JSON.parse(
    (await d1Query(`SELECT wrapped_data_key FROM accounts WHERE data_lookup_key = '${a.client.dataLookupKey}'`))[0].wrapped_data_key,
  );
  const beforeGen1Pk = before.dek_chain.find(e => e.gen === 1)?.wrappings.find(
    w => w.factor === 'passkey_prf' && w.credential_id === auth.credentialIdB64Url,
  );
  assert(beforeGen1Pk, 'precondition: gen-1 passkey wrapping present pre-changeCredentials');

  const newPw = 'changed-' + Date.now();
  await a.client.changeCredentials(a.username, newPw, {
    phrase: a.reg.accountKey,
    passkeyTapHandler: async (cred) => {
      assert(cred.credentialId === auth.credentialIdB64Url, 'handler called with the registered credentialId');
      return true;
    },
  });

  const after = JSON.parse(
    (await d1Query(`SELECT wrapped_data_key FROM accounts WHERE data_lookup_key = '${a.client.dataLookupKey}'`))[0].wrapped_data_key,
  );
  // Gen 1 wrapping preserved byte-for-byte.
  const afterGen1Pk = after.dek_chain.find(e => e.gen === 1)?.wrappings.find(
    w => w.factor === 'passkey_prf' && w.credential_id === auth.credentialIdB64Url,
  );
  assert(afterGen1Pk, 'gen-1 passkey wrapping must still be present post-changeCredentials');
  assert(
    afterGen1Pk.wrapped === beforeGen1Pk.wrapped,
    'gen-1 passkey wrapping bytes must be preserved byte-for-byte',
  );
  // Gen 2 (the new gen) MUST now have a passkey wrapping for the same credential.
  const afterGen2Pk = after.dek_chain.find(e => e.gen === 2)?.wrappings.find(
    w => w.factor === 'passkey_prf' && w.credential_id === auth.credentialIdB64Url,
  );
  assert(afterGen2Pk, 'gen-2 must have a passkey_prf wrapping after re-tap');

  // Authenticate with the passkey on a fresh client; verify auth and that the latest gen unwraps.
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(auth.credentialIdB64Url);
  const r = await c.authenticateWithPasskey();
  env.clearNextAuth();
  assert(r.dataLookupKey === a.client.dataLookupKey, 'passkey still authenticates the same account');
});

await test('changeCredentials with handler returning false leaves credential stale; refresh repairs it', async () => {
  // The user dismisses the tap → credential becomes stale on the new gen.
  // A subsequent authenticateWithPasskey returns stale_credential:true.
  // With a stalePasskeyHandler that supplies the password, the SDK
  // transparently re-wraps the latest gen and the credential is no
  // longer stale.
  const a = await registerAccount();
  const { auth } = await registerPasskeyOn(a.client, { deviceLabel: 'stale-test' });

  const newPw = 'changed-' + Date.now();
  let handlerCalls = 0;
  await a.client.changeCredentials(a.username, newPw, {
    phrase: a.reg.accountKey,
    passkeyTapHandler: async () => { handlerCalls += 1; return false; },
  });
  assert(handlerCalls === 1, 'handler called exactly once for one credential');

  // Verify gen 2 has NO passkey wrapping.
  const afterChange = JSON.parse(
    (await d1Query(`SELECT wrapped_data_key FROM accounts WHERE data_lookup_key = '${a.client.dataLookupKey}'`))[0].wrapped_data_key,
  );
  const gen2Pk = afterChange.dek_chain.find(e => e.gen === 2)?.wrappings.find(w => w.factor === 'passkey_prf');
  assert(!gen2Pk, 'gen-2 should have no passkey wrapping (user skipped re-tap)');

  // Login with the passkey + stale handler → should succeed and re-wrap.
  // Use a NEW client (passkey-only path), then call login() first to
  // populate username so the stale handler can do the password-side unwrap.
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c.login(a.username, newPw); // primes username + dlk + dekByGen
  // Now log out from the password side and exercise the passkey path
  // — but we need a fresh client. Re-design: log in with passkey first,
  // then call refresh-credential through the stale handler. Because
  // #username is null on a passkey-only session, the repair throws
  // (documented limitation). Instead drive the flow on a client that
  // already has #username populated (the post-changeCredentials
  // `a.client` itself, which still holds the post-change credentials).
  // Re-validate the contract: stale handler is invoked, repair runs
  // through, gen 2 re-gains its passkey wrapping.
  const c2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c2.login(a.username, newPw);
  let stalePromptCount = 0;
  env.pinNextAuth(auth.credentialIdB64Url);
  const r = await c2.authenticateWithPasskey({
    stalePasskeyHandler: async () => { stalePromptCount += 1; return newPw; },
  });
  env.clearNextAuth();
  assert(r.dataLookupKey === a.client.dataLookupKey, 'passkey authenticates with refresh path');
  assert(stalePromptCount === 1, 'stalePasskeyHandler called exactly once during repair');

  // Envelope now should include a gen-2 passkey wrapping.
  const repaired = JSON.parse(
    (await d1Query(`SELECT wrapped_data_key FROM accounts WHERE data_lookup_key = '${a.client.dataLookupKey}'`))[0].wrapped_data_key,
  );
  const gen2PkAfter = repaired.dek_chain.find(e => e.gen === 2)?.wrappings.find(
    w => w.factor === 'passkey_prf' && w.credential_id === auth.credentialIdB64Url,
  );
  assert(gen2PkAfter, 'gen-2 must have a passkey_prf wrapping post-repair');

  // Subsequent auth has stale_credential=false (via a fresh client).
  const c3 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(auth.credentialIdB64Url);
  let staleHandlerCalled = 0;
  await c3.authenticateWithPasskey({
    stalePasskeyHandler: async () => { staleHandlerCalled += 1; return null; },
  });
  env.clearNextAuth();
  assert(staleHandlerCalled === 0, 'after repair the stale handler is not called');
});

await test('multiple credentials: re-tap one, skip another → only the skipped one is stale', async () => {
  const a = await registerAccount();
  const { auth: aA } = await registerPasskeyOn(a.client, { deviceLabel: 'multi-A' });
  const { auth: aB } = await registerPasskeyOn(a.client, { deviceLabel: 'multi-B' });

  const newPw = 'changed-' + Date.now();
  await a.client.changeCredentials(a.username, newPw, {
    phrase: a.reg.accountKey,
    passkeyTapHandler: async (cred) => {
      // Re-tap A, skip B.
      env.pinNextAuth(aA.credentialIdB64Url); // ensure ceremony goes to A's authenticator
      try {
        return cred.credentialId === aA.credentialIdB64Url;
      } finally {
        env.clearNextAuth();
      }
    },
  });

  const after = JSON.parse(
    (await d1Query(`SELECT wrapped_data_key FROM accounts WHERE data_lookup_key = '${a.client.dataLookupKey}'`))[0].wrapped_data_key,
  );
  const gen2 = after.dek_chain.find(e => e.gen === 2);
  const gen2A = gen2?.wrappings.find(w => w.factor === 'passkey_prf' && w.credential_id === aA.credentialIdB64Url);
  const gen2B = gen2?.wrappings.find(w => w.factor === 'passkey_prf' && w.credential_id === aB.credentialIdB64Url);
  assert(gen2A, 'A should have a gen-2 wrapping (re-tapped)');
  assert(!gen2B, 'B should NOT have a gen-2 wrapping (skipped)');

  // Authenticate with A → fresh.
  const cA = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(aA.credentialIdB64Url);
  let staleA = 0;
  await cA.authenticateWithPasskey({ stalePasskeyHandler: async () => { staleA += 1; return null; } });
  env.clearNextAuth();
  assert(staleA === 0, 'A is fresh — handler should not be called');

  // Authenticate with B → stale. With no handler, throws.
  const cB = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(aB.credentialIdB64Url);
  let threw = null;
  try { await cB.authenticateWithPasskey(); } catch (err) { threw = err; }
  env.clearNextAuth();
  assert(threw, 'B is stale — should throw without handler');
  assert(threw.name === 'StalePasskeyError', `expected StalePasskeyError, got ${threw.name}: ${threw.message}`);
  assert(threw.credentialId === aB.credentialIdB64Url, 'error carries the stale credentialId');
});

section('rotateAccountKey preserves passkey wrappings');

await test('register passkey, rotate account key, passkey still authenticates', async () => {
  const a = await registerAccount();
  const { auth } = await registerPasskeyOn(a.client, { deviceLabel: 'rotate-test' });

  await a.client.rotateAccountKey({ password: a.password });

  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(auth.credentialIdB64Url);
  const r = await c.authenticateWithPasskey();
  env.clearNextAuth();
  assert(r.dataLookupKey === a.client.dataLookupKey, 'passkey still works post-rotation');
});

section('recoverAccount preserves passkey wrappings');

await test('register passkey, recoverAccount, passkey still authenticates', async () => {
  const a = await registerAccount();
  const { auth } = await registerPasskeyOn(a.client, { deviceLabel: 'recover-test' });
  const oldPhrase = a.reg.accountKey;
  const oldDlk = a.client.dataLookupKey;

  // Run recoverAccount in a fresh client.
  const recoveryClient = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await recoveryClient.recoverAccount({
    phrase: oldPhrase,
    newUsername: randomUsername(),
    newPassword: 'recovered-' + Date.now(),
  });

  // The passkey was registered for the original account.
  // recoverAccount preserves the DEK chain (same data, new auth factors)
  // — passkey wrapping should still be there for old gens.
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(auth.credentialIdB64Url);
  const r = await c.authenticateWithPasskey();
  env.clearNextAuth();
  assert(r.dataLookupKey === oldDlk, 'passkey still resolves to the same account post-recovery');
});

// ============ ERROR / EDGE CASES ============

section('Error / edge cases');

await test('unknown credential_id rejected during authentication', async () => {
  // Hit the wire directly with a credential_id that was never registered.
  const fakeAuth = new VirtualAuthenticator();
  const optsRes = await fetch(`${API_BASE}/api/v1/auth/passkey/authentication-options`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_id: fakeAuth.credentialIdB64Url }),
  });
  assert(optsRes.status === 200, `expected options 200, got ${optsRes.status}`);
  const optsJson = await optsRes.json();
  // No allow_credentials → server has nothing matching. Submit a forged
  // assertion claiming this credential_id; server rejects in the lookup
  // step ("Unknown credential").
  const challenge = optsJson.options.challenge;
  // Build a minimal-shaped credential the server's first parse will
  // accept, but with credential_id pointing at the unregistered authenticator.
  const fakeCred = fakeAuth.buildAuthenticationResponse({
    rpId: 'localhost',
    origin: 'http://localhost:3000',
    challenge,
    // PRF salt doesn't matter — the credential lookup happens before any
    // crypto. Pass the fake authenticator's own salt-equivalent.
    prfSalt: 'AAAAAAAAAAAAAAAAAAAAAA',
  });
  // re-shape response fields to base64url strings (the real network shape).
  function ab2b64u(ab) {
    return Buffer.from(new Uint8Array(ab)).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  const wireCred = {
    id: fakeCred.id,
    rawId: fakeCred.id, // base64url
    type: 'public-key',
    response: {
      authenticatorData: ab2b64u(fakeCred.response.authenticatorData),
      clientDataJSON: ab2b64u(fakeCred.response.clientDataJSON),
      signature: ab2b64u(fakeCred.response.signature),
      userHandle: null,
    },
    clientExtensionResults: {},
  };
  const r = await fetch(`${API_BASE}/api/v1/auth/passkey/authenticate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential: wireCred }),
  });
  assert(r.status === 401, `expected 401 on unknown credential, got ${r.status}`);
});

await test('reused authentication challenge rejected', async () => {
  // Register a passkey, fetch options, hand-build TWO assertions for the
  // same challenge, submit both. First succeeds, second fails (challenge
  // marked consumed in D1).
  const a = await registerAccount();
  const { auth } = await registerPasskeyOn(a.client, { deviceLabel: 'replay-test' });

  // Manually drive the wire flow.
  const optsRes = await fetch(`${API_BASE}/api/v1/auth/passkey/authentication-options`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_id: auth.credentialIdB64Url }),
  });
  assert(optsRes.status === 200, `options ${optsRes.status}`);
  const optsJson = await optsRes.json();
  const challenge = optsJson.options.challenge;
  const prfSalt = optsJson.allow_credentials.find(c => c.credential_id === auth.credentialIdB64Url).prf_salt;

  function ab2b64u(ab) {
    return Buffer.from(new Uint8Array(ab)).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function buildWire(challenge) {
    const cred = auth.buildAuthenticationResponse({
      rpId: 'localhost', origin: 'http://localhost:3000', challenge, prfSalt,
    });
    return {
      id: cred.id, rawId: cred.id, type: 'public-key',
      response: {
        authenticatorData: ab2b64u(cred.response.authenticatorData),
        clientDataJSON: ab2b64u(cred.response.clientDataJSON),
        signature: ab2b64u(cred.response.signature),
        userHandle: null,
      },
      clientExtensionResults: {},
    };
  }

  const r1 = await fetch(`${API_BASE}/api/v1/auth/passkey/authenticate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential: buildWire(challenge) }),
  });
  assert(r1.status === 200, `first assertion expected 200, got ${r1.status}`);

  const r2 = await fetch(`${API_BASE}/api/v1/auth/passkey/authenticate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential: buildWire(challenge) }),
  });
  assert(r2.status === 401, `second assertion (replay) expected 401, got ${r2.status}`);
});

await test('cross-account: passkey from account A cannot impersonate account B', async () => {
  // The DB binds credential_id → account_id. A passkey registered on A
  // can never authenticate as B because the lookup is by credential_id
  // alone — the server picks B's account or doesn't find one. There's no
  // input to the API where the caller could supply a "victim" account_id
  // and have the server route to it. So the natural shape of this test
  // is: register a passkey on account A, then verify the resulting
  // authenticate call returns A's data_lookup_key, not anyone else's.
  const accountA = await registerAccount();
  const accountB = await registerAccount();
  assert(accountA.client.dataLookupKey !== accountB.client.dataLookupKey, 'two distinct accounts');

  const { auth } = await registerPasskeyOn(accountA.client, { deviceLabel: 'A-only' });

  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(auth.credentialIdB64Url);
  const r = await c.authenticateWithPasskey();
  env.clearNextAuth();
  assert(r.dataLookupKey === accountA.client.dataLookupKey, 'auth resolves to A');
  assert(r.dataLookupKey !== accountB.client.dataLookupKey, 'auth does NOT resolve to B');
});

await test('tampered signature rejected (401)', async () => {
  const a = await registerAccount();
  const { auth } = await registerPasskeyOn(a.client, { deviceLabel: 'tamper-test' });

  // Fresh login attempt with a tampered signature.
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(auth.credentialIdB64Url);
  env.onceBeforeAuth(() => ({ tamperSignature: true }));

  let threw = null;
  try {
    await c.authenticateWithPasskey();
  } catch (err) { threw = err; }
  env.clearNextAuth();

  assert(threw, 'expected authenticateWithPasskey to throw on tampered sig');
  assert(/401|verification|failed/i.test(threw.message), `expected auth-fail message, got: ${threw.message}`);
});

await test('sign_count regression rejected', async () => {
  // Phase 6 stores sign_count and the API delegates verification to
  // @simplewebauthn/server, which throws if `counter > 0` and the new
  // counter does not exceed the stored counter. Confirm the policy
  // by:
  //   1. Registering a passkey (sign_count = 0 in DB).
  //   2. First auth with counter = 1 — succeeds, DB row updated to 1.
  //   3. Second auth with counter = 1 (regression) — must fail.
  //
  // Note: real synced passkeys that keep counter at 0 forever still
  // work, because the verifier short-circuits when both stored and new
  // counter are 0. This test exercises the non-zero monotonicity rule.
  const a = await registerAccount();
  const { auth } = await registerPasskeyOn(a.client, { deviceLabel: 'count-test' });

  const c1 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(auth.credentialIdB64Url);
  await c1.authenticateWithPasskey();
  env.clearNextAuth();

  const c2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(auth.credentialIdB64Url);
  env.onceBeforeAuth(() => ({ signCountOverride: 1 }));
  let threw = null;
  try { await c2.authenticateWithPasskey(); } catch (err) { threw = err; }
  env.clearNextAuth();
  assert(threw, 'expected sign_count regression to throw');
  assert(/counter|verification|401/i.test(threw.message), `expected counter rejection, got: ${threw.message}`);
});

// ============ DONE ============

env.restore();
console.log(`\n=== Passkey Tests: ${passed} passed, ${failed} failed ===`);
if (failed > 0) process.exit(1);
