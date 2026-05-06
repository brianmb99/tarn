// End-to-end tests for Phase 3 — Model B account-key storage and retrieval.
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
