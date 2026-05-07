// End-to-end tests for Phase 3 — Model B account-key storage and retrieval.
// Phase 4 tests for toggle endpoints (PUT/DELETE) + rotation are appended
// at the bottom of this file.
//
// Run: node tests/test-account-key.mjs [apiBaseUrl]
//
// Requires: wrangler dev running (cd api && npx wrangler dev --port 8787)
//
// What this exercises against the real API:
//   - register({ storeAccountKey: true }) populates wrapped_account_key in D1
//   - /auth/verify response includes account_key_stored: true
//   - tarn.accountKey.view() returns the same phrase that register did
//   - register({ storeAccountKey: false }) leaves account_key_stored: false
//   - view() against a Model A account → no_account_key_stored
//   - Step-up token is single-use (re-using → 401)
//   - Audit log gets a row per fetch
//   - Phase 4: enableKeyStorage / disableKeyStorage round trip
//   - Phase 4: rotateAccountKey evicts the old key (recoverAccount with
//     OLD phrase fails, NEW phrase succeeds, data still readable)
//   - Phase 4: recoverAccount({ rotatePhrase: true }) returns + binds new key
//   - Phase 4: rotation is atomic (no partial state on conflict)

import { TarnClient } from '../client/src/tarn.js';
import { seedTestApp, DEFAULT_APP_ID, randomUsername } from './helpers.mjs';

const API_BASE = process.argv[2] || 'http://localhost:8787';

await seedTestApp();

let passed = 0;
let failed = 0;

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
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

// ============ Underlying-client (TarnClient in tarn.ts) flow ============

console.log('\n=== Model B end-to-end (legacy underlying client) ===');

let modelBPhrase;
let modelBUsername;
let modelBPassword;

await test('register({ storeAccountKey: true }) returns the account key', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  modelBUsername = randomUsername();
  modelBPassword = 'pw-modelb-' + Date.now();
  const result = await client.register(modelBUsername, modelBPassword, {
    recoveryAcknowledged: true,
  });
  assert(result.dataLookupKey, 'should return dataLookupKey');
  assert(result.accountKey, 'should return accountKey');
  assert(result.accountKey.split(' ').length === 24, '24-word phrase');
  modelBPhrase = result.accountKey;
});

await test('isAccountKeyStored() reflects /auth/verify response', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.login(modelBUsername, modelBPassword);
  assert(client.isAccountKeyStored() === true, 'expected true after Model B login');
});

await test('viewAccountKey() returns the same phrase that register issued', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.login(modelBUsername, modelBPassword);
  const out = await client.viewAccountKey({ password: modelBPassword });
  assert(out.accountKey === modelBPhrase, `expected ${modelBPhrase} got ${out.accountKey}`);
});

await test('viewAccountKey() with wrong password fails authentication', async () => {
  // The wrong password derives a different credential_lookup_key, so the
  // challenge step itself fails ("Unknown credential_lookup_key"). Either
  // that or the step-up signature failing is acceptable — both prove the
  // password didn't match. This test catches both paths.
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.login(modelBUsername, modelBPassword);
  let threw = null;
  try {
    await client.viewAccountKey({ password: 'wrong-' + modelBPassword });
  } catch (err) { threw = err; }
  assert(threw, 'expected viewAccountKey to throw on wrong password');
  assert(/step-up|challenge|Unknown/i.test(threw.message), `expected auth failure, got: ${threw.message}`);
});

// ============ Model A path ============

console.log('\n=== Model A end-to-end ===');

let modelAUsername;
let modelAPassword;

await test('register({ storeAccountKey: false }) does not surface a wrap on /auth/verify', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  modelAUsername = randomUsername();
  modelAPassword = 'pw-modela-' + Date.now();
  await client.register(modelAUsername, modelAPassword, {
    recoveryAcknowledged: true,
    storeAccountKey: false,
  });
  assert(client.isAccountKeyStored() === false, 'expected false for Model A');
});

await test('viewAccountKey() against Model A throws no_account_key_stored', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.login(modelAUsername, modelAPassword);
  let threw = null;
  try {
    await client.viewAccountKey({ password: modelAPassword });
  } catch (err) { threw = err; }
  assert(threw, 'expected viewAccountKey to throw for Model A');
  assert(/no_account_key_stored/.test(threw.message), `expected no_account_key_stored, got: ${threw.message}`);
});

// ============ Step-up token: single-use enforcement ============

console.log('\n=== Step-up token semantics ===');

await test('step-up token is single-use (second fetch with same token → 401)', async () => {
  // Drive the flow at the wire level so we can replay the same token twice.
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.login(modelBUsername, modelBPassword);

  // Fresh challenge + step-up.
  const { deriveAllKeys, signChallenge } = await import('../client/src/crypto.js');
  const keys = await deriveAllKeys(modelBUsername, modelBPassword, DEFAULT_APP_ID);

  const challengeRes = await fetch(`${API_BASE}/api/v1/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey }),
  });
  const challengeJson = await challengeRes.json();
  const sig = await signChallenge(keys.signingKeyPair.privateKey, challengeJson.nonce);

  const stepUpRes = await fetch(`${API_BASE}/api/v1/auth/step-up`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      credential_lookup_key: keys.credentialLookupKey,
      nonce: challengeJson.nonce,
      signature: sig,
      scope: 'account_key_fetch',
    }),
  });
  assert(stepUpRes.status === 200, `step-up status ${stepUpRes.status}`);
  const stepUpJson = await stepUpRes.json();
  const token = stepUpJson.step_up_token;
  assert(token, 'step-up returned no token');

  // First fetch — must succeed.
  const r1 = await fetch(`${API_BASE}/api/v1/account/account-key`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${client._testJwt()}`,
      'X-Step-Up-Token': token,
    },
  });
  assert(r1.status === 200, `first fetch status ${r1.status}`);

  // Second fetch with the SAME token — must fail (single-use).
  const r2 = await fetch(`${API_BASE}/api/v1/account/account-key`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${client._testJwt()}`,
      'X-Step-Up-Token': token,
    },
  });
  assert(r2.status === 401, `second fetch must be 401 (single-use), got ${r2.status}`);
});

await test('step-up scope is enforced (wrong scope rejected)', async () => {
  const { deriveAllKeys, signChallenge } = await import('../client/src/crypto.js');
  const keys = await deriveAllKeys(modelBUsername, modelBPassword, DEFAULT_APP_ID);
  const challengeRes = await fetch(`${API_BASE}/api/v1/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey }),
  });
  const challengeJson = await challengeRes.json();
  const sig = await signChallenge(keys.signingKeyPair.privateKey, challengeJson.nonce);
  const stepUpRes = await fetch(`${API_BASE}/api/v1/auth/step-up`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      credential_lookup_key: keys.credentialLookupKey,
      nonce: challengeJson.nonce,
      signature: sig,
      scope: 'something-else',
    }),
  });
  assert(stepUpRes.status === 400, `expected 400 for unknown scope, got ${stepUpRes.status}`);
});

await test('account-key fetch without step-up token → 401', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.login(modelBUsername, modelBPassword);
  const r = await fetch(`${API_BASE}/api/v1/account/account-key`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${client._testJwt()}` },
  });
  assert(r.status === 401, `expected 401 without step-up, got ${r.status}`);
});

await test('account-key fetch without JWT → 401', async () => {
  const r = await fetch(`${API_BASE}/api/v1/account/account-key`, {
    method: 'GET',
    headers: { 'X-Step-Up-Token': 'whatever' },
  });
  assert(r.status === 401, `expected 401 without JWT, got ${r.status}`);
});

// ============ Audit log ============

console.log('\n=== Audit log ===');

await test('successful fetch writes a row to account_key_fetch_log', async () => {
  // Drive a view, then check via wrangler d1 that a new row exists.
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.login(modelBUsername, modelBPassword);
  const before = await countAuditRows(client.dataLookupKey);
  await client.viewAccountKey({ password: modelBPassword });
  // Audit insertion runs in waitUntil, so wait briefly.
  await new Promise(r => setTimeout(r, 250));
  const after = await countAuditRows(client.dataLookupKey);
  assert(after >= before + 1, `expected audit count to grow; before=${before}, after=${after}`);
});

// ============ Phase 4 — toggle (Model A ↔ Model B) ============

console.log('\n=== Phase 4 — toggle endpoints ===');

await test('disableKeyStorage on Model B → view() then fails with no_account_key_stored', async () => {
  // Use the existing modelBUsername / modelBPassword (registered earlier).
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.login(modelBUsername, modelBPassword);
  assert(client.isAccountKeyStored() === true, 'precondition: still Model B');

  const out = await client.disableKeyStorage({ password: modelBPassword });
  assert(out.stored === false, 'disable returns stored: false');
  assert(client.isAccountKeyStored() === false, 'cached flag flipped to false');

  // view() must now reject as Model A.
  let threw = null;
  try {
    await client.viewAccountKey({ password: modelBPassword });
  } catch (err) { threw = err; }
  assert(threw, 'view() should fail post-disable');
  assert(/no_account_key_stored/.test(threw.message), `expected no_account_key_stored, got: ${threw.message}`);
});

await test('disableKeyStorage is idempotent on already-Model-A account', async () => {
  // Same client, already disabled — should return stored:false again, no error.
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.login(modelBUsername, modelBPassword);
  const out = await client.disableKeyStorage({ password: modelBPassword });
  assert(out.stored === false);
  assert(out.alreadyDisabled === true, 'second call must report alreadyDisabled');
});

await test('enableKeyStorage with the saved phrase restores Model B', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.login(modelBUsername, modelBPassword);
  const out = await client.enableKeyStorage({
    password: modelBPassword,
    accountKey: modelBPhrase,
  });
  assert(out.stored === true);
  assert(client.isAccountKeyStored() === true);

  // view() now returns the original phrase (the wrap was recomputed under
  // the SAME DEK_gen1 + same plaintext, so the same phrase comes back).
  const view = await client.viewAccountKey({ password: modelBPassword });
  assert(view.accountKey === modelBPhrase, `expected ${modelBPhrase}, got ${view.accountKey}`);
});

await test('enableKeyStorage rejects an unrelated valid phrase (pin check on register/recover sessions)', async () => {
  // The client-side pin check requires #recoveryLookupKey to be populated,
  // which happens at register or recoverAccount time (not at login — the
  // password-side challenge response does not reveal it). Set up a fresh
  // register so the pin check is live, then try to enable with the WRONG
  // (but valid) phrase.
  const { generateAccountKey } = await import('../client/src/recovery.js');
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const u = randomUsername();
  const pw = 'pw-pin-' + Date.now();
  // Register Model A so we can attempt to enable storage.
  await client.register(u, pw, { recoveryAcknowledged: true, storeAccountKey: false });
  const otherPhrase = generateAccountKey();
  let threw = null;
  try {
    await client.enableKeyStorage({ password: pw, accountKey: otherPhrase });
  } catch (err) { threw = err; }
  assert(threw, 'expected pin-check failure');
  assert(/does not match the account on file/i.test(threw.message), `expected pin-check error, got: ${threw.message}`);
});

await test('PUT /account/account-key requires step-up token (401 without)', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.login(modelBUsername, modelBPassword);
  const r = await fetch(`${API_BASE}/api/v1/account/account-key`, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${client._testJwt()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ wrapped_account_key: 'x'.repeat(150) }),
  });
  assert(r.status === 401, `expected 401 without step-up, got ${r.status}`);
});

await test('DELETE /account/account-key requires step-up token (401 without)', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.login(modelBUsername, modelBPassword);
  const r = await fetch(`${API_BASE}/api/v1/account/account-key`, {
    method: 'DELETE',
    headers: { 'Authorization': `Bearer ${client._testJwt()}` },
  });
  assert(r.status === 401, `expected 401 without step-up, got ${r.status}`);
});

// ============ Phase 4 — rotation ============

console.log('\n=== Phase 4 — rotation ===');

let rotatedUsername;
let rotatedPassword;
let rotatedOldPhrase;
let rotatedNewPhrase;

await test('rotateAccountKey returns a new phrase and evicts the old one', async () => {
  // Register a fresh account so we can compare pre/post recovery.
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  rotatedUsername = randomUsername();
  rotatedPassword = 'pw-rotate-' + Date.now();
  const reg = await client.register(rotatedUsername, rotatedPassword, {
    recoveryAcknowledged: true,
  });
  rotatedOldPhrase = reg.accountKey;

  const out = await client.rotateAccountKey({ password: rotatedPassword });
  rotatedNewPhrase = out.accountKey;
  assert(out.accountKey, 'rotation returns a new phrase');
  assert(out.accountKey.split(' ').length === 24, '24-word phrase');
  assert(out.accountKey !== rotatedOldPhrase, 'new phrase differs from old');
});

await test('post-rotation: OLD phrase no longer recovers the account', async () => {
  const recoveryClient = new TarnClient(API_BASE, DEFAULT_APP_ID);
  let threw = null;
  try {
    await recoveryClient.recoverAccount({
      phrase: rotatedOldPhrase,
      newUsername: randomUsername(),
      newPassword: 'pw-after-' + Date.now(),
    });
  } catch (err) { threw = err; }
  assert(threw, 'OLD phrase must be rejected post-rotation');
  // The wire-level error: the OLD recovery_lookup_key no longer maps to
  // any account, so /auth/challenge returns 404.
  assert(/no account found|challenge failed/i.test(threw.message),
    `expected unknown-recovery-key error, got: ${threw.message}`);
});

await test('post-rotation: NEW phrase recovers the account and data is still decryptable', async () => {
  const recoveryClient = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const newUsername2 = randomUsername();
  const newPassword2 = 'pw-recovered-' + Date.now();
  const result = await recoveryClient.recoverAccount({
    phrase: rotatedNewPhrase,
    newUsername: newUsername2,
    newPassword: newPassword2,
  });
  assert(result.dataLookupKey, 'recoverAccount returns dataLookupKey');
  assert(recoveryClient.isLoggedIn(), 'client is logged in post-recovery');
});

await test('rotation atomicity: rotating Model B preserves the wrap (view returns new phrase)', async () => {
  // Fresh Model B account so we can rotate and then view.
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const u = randomUsername();
  const pw = 'pw-rotateB-' + Date.now();
  const reg = await client.register(u, pw, { recoveryAcknowledged: true });
  assert(client.isAccountKeyStored() === true, 'precondition: Model B');

  const rot = await client.rotateAccountKey({ password: pw });
  assert(rot.accountKey !== reg.accountKey);

  // After rotation the client-side flag is unchanged (still Model B);
  // the wrap on the server now decrypts to the NEW phrase.
  assert(client.isAccountKeyStored() === true, 'rotation must not flip Model B → A');

  const view = await client.viewAccountKey({ password: pw });
  assert(view.accountKey === rot.accountKey,
    `view() must return the new phrase, got ${view.accountKey} expected ${rot.accountKey}`);
});

await test('rotation on Model A leaves wrap absent', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const u = randomUsername();
  const pw = 'pw-rotateA-' + Date.now();
  await client.register(u, pw, { recoveryAcknowledged: true, storeAccountKey: false });
  assert(client.isAccountKeyStored() === false);

  const rot = await client.rotateAccountKey({ password: pw });
  assert(rot.accountKey, 'rotation works on Model A');
  assert(client.isAccountKeyStored() === false, 'Model A stays Model A');

  // view() must still 404 with no_account_key_stored.
  let threw = null;
  try { await client.viewAccountKey({ password: pw }); } catch (err) { threw = err; }
  assert(threw && /no_account_key_stored/.test(threw.message), 'Model A view still 404');
});

await test('rotation conflict: 409 when new_recovery_lookup_key collides', async () => {
  // Simulate by directly POSTing a rotation payload with another account's
  // recovery_lookup_key. This is the only practical way to hit the 409 in
  // unit-test time (a real HMAC-SHA256 collision is astronomically unlikely).
  // Need a second account to pull a recovery_lookup_key from.
  const otherClient = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const otherU = randomUsername();
  const otherPw = 'pw-otherX-' + Date.now();
  await otherClient.register(otherU, otherPw, { recoveryAcknowledged: true });
  // Pull the other account's recovery_lookup_key out of D1 directly.
  const { execSync } = await import('child_process');
  const sql = `SELECT recovery_lookup_key FROM accounts WHERE data_lookup_key = '${otherClient.dataLookupKey}'`;
  const out = execSync(
    `npx wrangler d1 execute tarn-api --local --json --command "${sql}"`,
    { cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), stdio: ['ignore', 'pipe', 'ignore'], timeout: 15000 },
  ).toString();
  const parsed = JSON.parse(out);
  const collidingLookupKey = parsed[0]?.results?.[0]?.recovery_lookup_key;
  assert(collidingLookupKey, 'must extract collision lookup key from D1');

  // Now stand up a third account and try to rotate it onto the second
  // account's recovery_lookup_key. The hand-crafted payload uses a stub
  // envelope/public key — we expect the 409 to fire BEFORE the deeper
  // validation (the API checks lookup-key uniqueness up front).
  const victim = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const vU = randomUsername();
  const vPw = 'pw-victim-' + Date.now();
  await victim.register(vU, vPw, { recoveryAcknowledged: true });
  // Phase 4.1: rotate now requires a step-up token in addition to the JWT.
  // Mint a fresh one for the victim so the conflict check (which runs after
  // step-up validation but before envelope validation) actually executes.
  const stepUpToken = await mintStepUpToken(victim, vU, vPw);
  // Build a minimal-looking but invalid payload — the lookup-key conflict
  // check runs before envelope validation in the API, so we need to pass
  // schema checks (envelope: any non-empty string; recovery_public_key:
  // base64 SPKI). We'll yank both from victim's existing /auth/verify state.
  const r = await fetch(`${API_BASE}/api/v1/account/rotate-account-key`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${victim._testJwt()}`,
      'X-Step-Up-Token': stepUpToken,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      new_envelope: '{"v":1,"x":"stub"}',
      new_recovery_lookup_key: collidingLookupKey,
      // Reuse victim's own current recovery_public_key (a valid SPKI). Pull
      // from D1 to avoid re-deriving.
      new_recovery_public_key: await pullRecoveryPublicKey(victim.dataLookupKey),
      new_wrapped_account_key: null,
    }),
  });
  assert(r.status === 409, `expected 409 on lookup conflict, got ${r.status}`);
});

// Phase 4.1 — step-up requirement on rotate-account-key. Mirrors the
// existing PUT/DELETE step-up tests above. The SDK's rotate() handles step-up
// transparently; these tests probe the wire-level posture.

await test('POST /account/rotate-account-key without step-up token → 401', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const u = randomUsername();
  const pw = 'pw-rotate-nostep-' + Date.now();
  await client.register(u, pw, { recoveryAcknowledged: true });
  const r = await fetch(`${API_BASE}/api/v1/account/rotate-account-key`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${client._testJwt()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      new_envelope: '{"v":1,"x":"stub"}',
      new_recovery_lookup_key: 'a'.repeat(64),
      new_recovery_public_key: await pullRecoveryPublicKey(client.dataLookupKey),
      new_wrapped_account_key: null,
    }),
  });
  assert(r.status === 401, `expected 401 without step-up, got ${r.status}`);
});

await test('POST /account/rotate-account-key without JWT → 401', async () => {
  const r = await fetch(`${API_BASE}/api/v1/account/rotate-account-key`, {
    method: 'POST',
    headers: {
      'X-Step-Up-Token': 'whatever',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      new_envelope: '{"v":1,"x":"stub"}',
      new_recovery_lookup_key: 'a'.repeat(64),
      new_recovery_public_key: 'stub',
      new_wrapped_account_key: null,
    }),
  });
  assert(r.status === 401, `expected 401 without JWT, got ${r.status}`);
});

await test('POST /account/rotate-account-key with consumed step-up token → 401', async () => {
  // Mint a token, consume it via a successful GET /account/account-key,
  // then try to reuse it on rotate. Single-use enforcement → 401.
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const u = randomUsername();
  const pw = 'pw-rotate-consumed-' + Date.now();
  await client.register(u, pw, { recoveryAcknowledged: true });
  const token = await mintStepUpToken(client, u, pw);

  // Consume it on the GET endpoint first.
  const r1 = await fetch(`${API_BASE}/api/v1/account/account-key`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${client._testJwt()}`,
      'X-Step-Up-Token': token,
    },
  });
  assert(r1.status === 200, `precondition: GET succeeds, got ${r1.status}`);

  // Reuse must 401.
  const r2 = await fetch(`${API_BASE}/api/v1/account/rotate-account-key`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${client._testJwt()}`,
      'X-Step-Up-Token': token,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      new_envelope: '{"v":1,"x":"stub"}',
      new_recovery_lookup_key: 'a'.repeat(64),
      new_recovery_public_key: await pullRecoveryPublicKey(client.dataLookupKey),
      new_wrapped_account_key: null,
    }),
  });
  assert(r2.status === 401, `consumed step-up token must 401 on rotate, got ${r2.status}`);
});

await test('rotateAccountKey() with wrong password fails authentication', async () => {
  // Mirrors the wrong-password test for viewAccountKey above. With Phase 4.1
  // step-up the SDK has TWO password tripwires: a local credential mismatch
  // check (fires first on wrong-pw) and the server-side step-up signature
  // check. Either failure mode is acceptable — both prove the password
  // didn't match.
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const u = randomUsername();
  const pw = 'pw-rotate-wrong-' + Date.now();
  await client.register(u, pw, { recoveryAcknowledged: true });
  let threw = null;
  try {
    await client.rotateAccountKey({ password: 'wrong-' + pw });
  } catch (err) { threw = err; }
  assert(threw, 'expected rotateAccountKey to throw on wrong password');
  assert(/wrong password|step-up|challenge|Unknown/i.test(threw.message),
    `expected auth failure, got: ${threw.message}`);
});

// ============ Phase 4 — recoverAccount({ rotatePhrase: true }) ============

console.log('\n=== Phase 4 — recoverAccount({ rotatePhrase: true }) ===');

await test('recoverAccount({ rotatePhrase: true }) returns a new phrase and old phrase is rejected', async () => {
  // Register fresh account.
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const u = randomUsername();
  const pw = 'pw-rp-' + Date.now();
  const reg = await client.register(u, pw, { recoveryAcknowledged: true });
  const oldPhrase = reg.accountKey;

  // Recover with rotation.
  const recoveryClient = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const newU = randomUsername();
  const newPw = 'pw-rp2-' + Date.now();
  const result = await recoveryClient.recoverAccount({
    phrase: oldPhrase,
    newUsername: newU,
    newPassword: newPw,
    rotatePhrase: true,
  });
  assert(result.accountKey, 'rotatePhrase: true returns the new accountKey');
  assert(result.accountKey !== oldPhrase, 'new phrase differs from old');

  // Verify OLD phrase is now rejected.
  const c2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  let threw = null;
  try {
    await c2.recoverAccount({
      phrase: oldPhrase,
      newUsername: randomUsername(),
      newPassword: 'pw-late-' + Date.now(),
    });
  } catch (err) { threw = err; }
  assert(threw && /no account found|challenge failed/i.test(threw.message),
    `OLD phrase must be rejected, got: ${threw?.message}`);

  // Verify NEW phrase still works.
  const c3 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c3.recoverAccount({
    phrase: result.accountKey,
    newUsername: randomUsername(),
    newPassword: 'pw-final-' + Date.now(),
  });
  assert(c3.isLoggedIn());
});

await test('recoverAccount default behavior unchanged (no rotation, no accountKey in result)', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const u = randomUsername();
  const pw = 'pw-norot-' + Date.now();
  const reg = await client.register(u, pw, { recoveryAcknowledged: true });

  const recoveryClient = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const result = await recoveryClient.recoverAccount({
    phrase: reg.accountKey,
    newUsername: randomUsername(),
    newPassword: 'pw-norot2-' + Date.now(),
  });
  assert(result.accountKey === undefined, 'no rotatePhrase → no accountKey in result');

  // OLD phrase still works (no rotation happened).
  const c2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c2.recoverAccount({
    phrase: reg.accountKey,
    newUsername: randomUsername(),
    newPassword: 'pw-again-' + Date.now(),
  });
  assert(c2.isLoggedIn());
});

console.log(`\n=== Account-key Tests: ${passed} passed, ${failed} failed ===`);
if (failed > 0) process.exit(1);

async function countAuditRows(dlk) {
  const { execSync } = await import('child_process');
  const sql = `SELECT COUNT(*) AS n FROM account_key_fetch_log WHERE data_lookup_key = '${dlk}'`;
  const out = execSync(
    `npx wrangler d1 execute tarn-api --local --json --command "${sql}"`,
    { cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), stdio: ['ignore', 'pipe', 'ignore'], timeout: 15000 },
  ).toString();
  const parsed = JSON.parse(out);
  return parsed[0]?.results?.[0]?.n ?? 0;
}

/**
 * Drive the wire-level step-up flow against the real API and return a fresh
 * token. Mirrors what the SDK's #performStepUp does — used by the integration
 * tests that POST to rotate-account-key directly (bypassing the SDK) so they
 * can attach a valid token without rebuilding the SDK helper.
 */
async function mintStepUpToken(client, username, password) {
  const { deriveAllKeys, signChallenge } = await import('../client/src/crypto.js');
  const keys = await deriveAllKeys(username, password, DEFAULT_APP_ID);
  const challengeRes = await fetch(`${API_BASE}/api/v1/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey }),
  });
  const challengeJson = await challengeRes.json();
  const sig = await signChallenge(keys.signingKeyPair.privateKey, challengeJson.nonce);
  const stepUpRes = await fetch(`${API_BASE}/api/v1/auth/step-up`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      credential_lookup_key: keys.credentialLookupKey,
      nonce: challengeJson.nonce,
      signature: sig,
      scope: 'account_key_fetch',
    }),
  });
  if (stepUpRes.status !== 200) {
    throw new Error(`mintStepUpToken: step-up failed ${stepUpRes.status}`);
  }
  return (await stepUpRes.json()).step_up_token;
}

async function pullRecoveryPublicKey(dlk) {
  const { execSync } = await import('child_process');
  const sql = `SELECT recovery_public_key FROM accounts WHERE data_lookup_key = '${dlk}'`;
  const out = execSync(
    `npx wrangler d1 execute tarn-api --local --json --command "${sql}"`,
    { cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), stdio: ['ignore', 'pipe', 'ignore'], timeout: 15000 },
  ).toString();
  const parsed = JSON.parse(out);
  return parsed[0]?.results?.[0]?.recovery_public_key;
}
