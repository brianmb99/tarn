// E2E tests for app identity, rules enforcement, and status endpoint
// Run: node tests/test-apps-e2e.mjs [apiBaseUrl]
// Requires: cd api && npx wrangler dev --port 8787
//
// NOTE: App registration is currently manual (insert into apps table).
// This test seeds the app via wrangler d1 execute before running.

import {
  deriveAllKeys, exportPublicKey, wrapDataKey, signChallenge, encrypt,
} from '../client/src/crypto.js';
import { seedTestApp, DEFAULT_APP_ID } from './helpers.mjs';

const API_BASE = process.argv[2] || 'http://localhost:8787';

// Seed the default test app for user registration
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
    if (process.env.VERBOSE) console.error('    ', err.stack);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function randomEmail() {
  return `app-e2e-${Date.now()}-${Math.random().toString(36).slice(2)}@test.com`;
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function fetchJSON(path, opts = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: res.status, json, text };
}

// ============ SETUP: Register an app via D1 ============

// We'll register an app by generating a key pair and inserting directly into D1
// via the API's own registration flow (treating the app_id as credential_lookup_key
// in the apps table). Since app registration is manual, we insert via a helper.

let appPrivateKey;
let appPublicKeyBase64;
let appJwt;
// Use DEFAULT_APP_ID so the app identity matches user registrations
const APP_ID = DEFAULT_APP_ID;

async function setupApp() {
  // Generate a P-256 key pair for the app
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  appPrivateKey = keyPair.privateKey;
  const der = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  appPublicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(der)));

  // Insert app into D1 via a POST to a test-only seeding approach
  // Since we can't directly write to D1 from outside, we'll register the app
  // by manually inserting via wrangler. But in tests against the live API,
  // we need a different approach.
  //
  // Workaround: We'll use the auth/challenge endpoint to detect if the app exists.
  // If not, we'll need to seed it. For now, let's see if we can use the lookup endpoint.
  //
  // Actually — we can insert app registrations via the API by adding a seed endpoint,
  // OR we can test by having the test runner directly insert via wrangler d1 execute.
  // For CI, the simplest approach is to check if the app exists and skip if not.

  // For this test, we'll check if we have wrangler access to seed the app.
  // If running against a local dev instance, we can shell out.
  console.log(`  Setting up test app: ${APP_ID}`);

  try {
    const { execSync } = await import('child_process');
    const sql = `INSERT OR REPLACE INTO apps (app_id, public_key, created_at) VALUES ('${APP_ID}', '${appPublicKeyBase64}', ${Date.now()})`;
    execSync(
      `cd api && npx wrangler d1 execute tarn-api --local --command "${sql}"`,
      { cwd: process.cwd().replace(/\/tests$/, ''), stdio: 'pipe', timeout: 15000 }
    );
    console.log('  App seeded in D1.\n');
  } catch (err) {
    console.log(`  Could not seed app via wrangler: ${err.message}`);
    console.log('  Skipping app tests.\n');
    return false;
  }
  return true;
}

async function loginApp() {
  // Challenge
  const cRes = await fetchJSON('/api/v1/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: APP_ID }),
  });
  assert(cRes.status === 200, `App challenge failed: ${cRes.status} ${cRes.text}`);

  // Sign nonce
  const nonceBytes = hexToBytes(cRes.json.nonce);
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    appPrivateKey,
    nonceBytes
  );
  const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(sig)));

  // Verify
  const vRes = await fetchJSON('/api/v1/auth/verify', {
    method: 'POST',
    body: JSON.stringify({
      credential_lookup_key: APP_ID,
      nonce: cRes.json.nonce,
      signature: sigBase64,
    }),
  });
  assert(vRes.status === 200, `App verify failed: ${vRes.status} ${vRes.text}`);
  appJwt = vRes.json.jwt;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}

// Helper: register + login a user, return { dlk, jwt, encKey }
async function registerUser() {
  const email = randomEmail();
  const password = 'test-pass';
  const keys = await deriveAllKeys(email, password, DEFAULT_APP_ID);
  const pub = await exportPublicKey(keys.signingKeyPair.publicKey);
  const wdk = await wrapDataKey(keys.credentialEncryptionKey.gcmKey, keys.credentialEncryptionKey.kwKey);

  const regRes = await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey, public_key: pub, wrapped_data_key: wdk, app: DEFAULT_APP_ID }),
  });
  assert(regRes.status === 201, `Register failed: ${regRes.status}`);
  const dlk = regRes.json.data_lookup_key;

  const cRes = await fetchJSON('/api/v1/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey }),
  });
  const sig = await signChallenge(keys.signingKeyPair.privateKey, cRes.json.nonce);
  const vRes = await fetchJSON('/api/v1/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey, nonce: cRes.json.nonce, signature: sig }),
  });

  // Set default rules (unrestricted) — in production, the app sets this
  const { execSync } = await import('child_process');
  try {
    execSync(
      `npx wrangler d1 execute tarn-api --local --command "UPDATE accounts SET rules_json = '[]' WHERE data_lookup_key = '${dlk}'"`,
      { cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), stdio: 'pipe', timeout: 10000 }
    );
  } catch {}

  return { dlk, jwt: vRes.json.jwt, encKey: keys.credentialEncryptionKey.gcmKey };
}

async function createEntry(jwt, dlk, encKey, app, payload) {
  const encrypted = await encrypt(encKey, payload);
  const tags = [
    { name: 'App', value: app }, { name: 'Type', value: 'entry' },
    { name: 'Lk', value: dlk }, { name: 'Enc', value: 'aes-256-gcm' },
    { name: 'V', value: '0.3.0' },
  ];
  const res = await fetch(`${API_BASE}/api/v1/entries`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${jwt}`,
      'X-Arweave-Tags': JSON.stringify(tags),
      'Content-Type': 'application/octet-stream',
    },
    body: encrypted,
  });
  const json = await res.json().catch(() => null);
  assert(res.status === 200, `Create failed: ${res.status} ${JSON.stringify(json)}`);
  return json.id;
}

// ============ TESTS ============

const appReady = await setupApp();

if (appReady) {
  console.log('=== App Authentication ===');

  await test('App challenge-response login', async () => {
    await loginApp();
    assert(appJwt, 'Should get JWT');
  });

  console.log('\n=== Rules Enforcement ===');

  await test('Set max_entries rule, enforce on write', async () => {
    const user = await registerUser();

    // User creates an entry for this app (so app can set rules)
    await createEntry(user.jwt, user.dlk, user.encKey, APP_ID, { book: 'First' });
    await sleep(200);

    // App sets max_entries=2 for this user
    const rulesRes = await fetchJSON(`/api/v1/accounts/${user.dlk}/rules`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${appJwt}` },
      body: JSON.stringify({
        rules: [{ type: 'max_entries', limit: 2, app: APP_ID, entry_type: 'entry' }],
      }),
    });
    assert(rulesRes.status === 200, `Set rules failed: ${rulesRes.status} ${rulesRes.text}`);

    // User creates second entry — should succeed (count is 1, limit is 2)
    await createEntry(user.jwt, user.dlk, user.encKey, APP_ID, { book: 'Second' });
    await sleep(200);

    // User creates third entry — should be DENIED (count is 2, limit is 2)
    const encrypted = await encrypt(user.encKey, { book: 'Third' });
    const tags = [
      { name: 'App', value: APP_ID }, { name: 'Type', value: 'entry' },
      { name: 'Lk', value: user.dlk }, { name: 'Enc', value: 'aes-256-gcm' },
      { name: 'V', value: '0.3.0' },
    ];
    const denyRes = await fetch(`${API_BASE}/api/v1/entries`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${user.jwt}`,
        'X-Arweave-Tags': JSON.stringify(tags),
        'Content-Type': 'application/octet-stream',
      },
      body: encrypted,
    });
    assert(denyRes.status === 403, `Expected 403 for third write, got ${denyRes.status}`);
  });

  await test('Set expires rule, enforce on write', async () => {
    const user = await registerUser();
    await createEntry(user.jwt, user.dlk, user.encKey, APP_ID, { seed: true });
    await sleep(200);

    // Set expiry in the past
    const pastDate = new Date(Date.now() - 3600000).toISOString();
    const rulesRes = await fetchJSON(`/api/v1/accounts/${user.dlk}/rules`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${appJwt}` },
      body: JSON.stringify({
        rules: [{ type: 'expires', at: pastDate }],
      }),
    });
    assert(rulesRes.status === 200, `Set rules failed: ${rulesRes.status}`);

    // Write should be denied
    const encrypted = await encrypt(user.encKey, { expired: true });
    const tags = [
      { name: 'App', value: APP_ID }, { name: 'Type', value: 'entry' },
      { name: 'Lk', value: user.dlk }, { name: 'Enc', value: 'aes-256-gcm' },
      { name: 'V', value: '0.3.0' },
    ];
    const res = await fetch(`${API_BASE}/api/v1/entries`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${user.jwt}`,
        'X-Arweave-Tags': JSON.stringify(tags),
        'Content-Type': 'application/octet-stream',
      },
      body: encrypted,
    });
    assert(res.status === 403, `Expected 403 for expired write, got ${res.status}`);
  });

  await test('Clear rules: previously denied write succeeds', async () => {
    const user = await registerUser();
    await createEntry(user.jwt, user.dlk, user.encKey, APP_ID, { seed: true });
    await sleep(200);

    // Set restrictive rules
    await fetchJSON(`/api/v1/accounts/${user.dlk}/rules`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${appJwt}` },
      body: JSON.stringify({ rules: [{ type: 'max_entries', limit: 1, app: APP_ID, entry_type: 'entry' }] }),
    });

    // Verify write is denied
    const enc1 = await encrypt(user.encKey, { blocked: true });
    const tags = [
      { name: 'App', value: APP_ID }, { name: 'Type', value: 'entry' },
      { name: 'Lk', value: user.dlk }, { name: 'Enc', value: 'aes-256-gcm' },
      { name: 'V', value: '0.3.0' },
    ];
    const deny = await fetch(`${API_BASE}/api/v1/entries`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${user.jwt}`, 'X-Arweave-Tags': JSON.stringify(tags), 'Content-Type': 'application/octet-stream' },
      body: enc1,
    });
    assert(deny.status === 403, `Expected 403, got ${deny.status}`);

    // Clear rules (empty array = unrestricted)
    await fetchJSON(`/api/v1/accounts/${user.dlk}/rules`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${appJwt}` },
      body: JSON.stringify({ rules: [] }),
    });

    // Now write should succeed
    const enc2 = await encrypt(user.encKey, { unblocked: true });
    const allow = await fetch(`${API_BASE}/api/v1/entries`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${user.jwt}`, 'X-Arweave-Tags': JSON.stringify(tags), 'Content-Type': 'application/octet-stream' },
      body: enc2,
    });
    assert(allow.status === 200, `Expected 200 after clearing rules, got ${allow.status}`);
  });

  await test('Non-app JWT cannot set rules', async () => {
    const user = await registerUser();
    const res = await fetchJSON(`/api/v1/accounts/${user.dlk}/rules`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${user.jwt}` },
      body: JSON.stringify({ rules: [] }),
    });
    assert(res.status === 403, `Expected 403, got ${res.status}`);
  });

  console.log('\n=== Status Endpoint ===');

  await test('Status: returns user and entry counts', async () => {
    const user = await registerUser();

    // Challenge + verify for user JWT (need it for status)
    const res = await fetchJSON('/api/v1/status', {
      headers: { 'Authorization': `Bearer ${user.jwt}` },
    });
    assert(res.status === 200, `Status failed: ${res.status} ${res.text}`);
    assert(typeof res.json.users?.total === 'number', 'Should have users.total');
    assert(typeof res.json.entries?.total === 'number', 'Should have entries.total');
    assert(res.json.protocol_version === '0.4.0', 'Should have protocol version');
    assert(res.json.timestamp, 'Should have timestamp');
  });

  await test('Status: app JWT returns app-specific entry count', async () => {
    const res = await fetchJSON('/api/v1/status', {
      headers: { 'Authorization': `Bearer ${appJwt}` },
    });
    assert(res.status === 200, `Status failed: ${res.status}`);
    assert(typeof res.json.entries?.for_app === 'number', 'Should have entries.for_app');
  });

  await test('Status: unauthenticated returns 401', async () => {
    const res = await fetchJSON('/api/v1/status');
    assert(res.status === 401, `Expected 401, got ${res.status}`);
  });
}

// ============ SUMMARY ============

console.log(`\n=== App E2E Results: ${passed} passed, ${failed} failed ===\n`);
process.exit(failed > 0 ? 1 : 0);
