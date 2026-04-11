// Security-focused integration tests — validates fixes for architect review findings
// Run: node tests/test-security.mjs [apiBaseUrl]
// Requires: cd api && npx wrangler dev --port 8787

import {
  deriveAllKeys, exportPublicKey, wrapDataKey, signChallenge, encrypt,
} from '../client/src/crypto.js';
import { seedTestApp, DEFAULT_APP_ID } from './helpers.mjs';

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
    if (process.env.VERBOSE) console.error('    ', err.stack);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function randomEmail() {
  return `sec-${Date.now()}-${Math.random().toString(36).slice(2)}@test.com`;
}

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

// Register a user and get JWT (without setting rules)
async function registerUserNoRules() {
  const email = randomEmail();
  const keys = await deriveAllKeys(email, 'test-pass', DEFAULT_APP_ID);
  const pub = await exportPublicKey(keys.signingKeyPair.publicKey);
  const wdk = await wrapDataKey(keys.credentialEncryptionKey.gcmKey, keys.credentialEncryptionKey.kwKey);

  const regRes = await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey, public_key: pub, wrapped_data_key: wdk, app: DEFAULT_APP_ID }),
  });
  assert(regRes.status === 201, `Register failed: ${regRes.status}`);

  const cRes = await fetchJSON('/api/v1/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey }),
  });
  const sig = await signChallenge(keys.signingKeyPair.privateKey, cRes.json.nonce);
  const vRes = await fetchJSON('/api/v1/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey, nonce: cRes.json.nonce, signature: sig }),
  });

  return { dlk: regRes.json.data_lookup_key, jwt: vRes.json.jwt, encKey: keys.credentialEncryptionKey.gcmKey };
}

// ============ C1: NULL rules = DENY ============

console.log('\n=== C1: NULL rules = DENY (new user without app-set rules) ===');

await test('New user without rules: write is DENIED', async () => {
  const { jwt, dlk, encKey } = await registerUserNoRules();

  const encrypted = await encrypt(encKey, { test: 'should be denied' });
  const tags = [
    { name: 'App', value: DEFAULT_APP_ID }, { name: 'Type', value: 'entry' },
    { name: 'Lk', value: dlk }, { name: 'Enc', value: 'aes-256-gcm' },
    { name: 'V', value: '0.4.0' },
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

  assert(res.status === 403, `Expected 403 for no-rules user, got ${res.status}`);
  const json = await res.json();
  assert(json.detail.includes('No rules set'), `Expected 'No rules set' message, got: ${json.detail}`);
});

await test('User with empty rules array (app set []): write is ALLOWED', async () => {
  const { jwt, dlk, encKey } = await registerUserNoRules();

  // Set empty rules via D1 (simulating app setting rules)
  const { execSync } = await import('child_process');
  execSync(
    `npx wrangler d1 execute tarn-api --local --command "UPDATE accounts SET rules_json = '[]' WHERE data_lookup_key = '${dlk}'"`,
    { cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), stdio: 'pipe', timeout: 10000 }
  );

  const encrypted = await encrypt(encKey, { test: 'should be allowed' });
  const tags = [
    { name: 'App', value: DEFAULT_APP_ID }, { name: 'Type', value: 'entry' },
    { name: 'Lk', value: dlk }, { name: 'Enc', value: 'aes-256-gcm' },
    { name: 'V', value: '0.4.0' },
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

  assert(res.status === 200, `Expected 200 for user with empty rules, got ${res.status}`);
});

// ============ C5: App can set rules for new user (no chicken-and-egg) ============

console.log('\n=== C5: App can set rules for new user (no entries required) ===');

await test('App sets rules for user with zero entries: succeeds', async () => {
  // Seed the test app with a key pair we control
  const appKP = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const appPubDer = await crypto.subtle.exportKey('spki', appKP.publicKey);
  const appPub64 = btoa(String.fromCharCode(...new Uint8Array(appPubDer)));
  const { execSync } = await import('child_process');
  execSync(
    `npx wrangler d1 execute tarn-api --local --command "INSERT OR REPLACE INTO apps (app_id, public_key, created_at) VALUES ('${DEFAULT_APP_ID}', '${appPub64}', ${Date.now()})"`,
    { cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), stdio: 'pipe', timeout: 10000 }
  );

  // Get app JWT
  const cRes = await fetchJSON('/api/v1/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: DEFAULT_APP_ID }),
  });
  const nonceBytes = new Uint8Array(cRes.json.nonce.length / 2);
  for (let i = 0; i < cRes.json.nonce.length; i += 2) nonceBytes[i / 2] = parseInt(cRes.json.nonce.substr(i, 2), 16);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, appKP.privateKey, nonceBytes);
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  const vRes = await fetchJSON('/api/v1/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: DEFAULT_APP_ID, nonce: cRes.json.nonce, signature: sigB64 }),
  });
  const appJwt = vRes.json.jwt;

  // Register a new user (zero entries)
  const { dlk } = await registerUserNoRules();

  // App sets rules for user — should succeed (user.app matches app_id)
  const rulesRes = await fetchJSON(`/api/v1/accounts/${dlk}/rules`, {
    method: 'PUT',
    headers: { 'Authorization': `Bearer ${appJwt}` },
    body: JSON.stringify({ rules: [{ type: 'max_entries', limit: 10 }] }),
  });

  assert(rulesRes.status === 200, `Expected 200, got ${rulesRes.status}: ${rulesRes.text}`);
});

// ============ C4: App tag must match JWT app ============

console.log('\n=== C4: App tag must match JWT app claim ===');

await test('Write with mismatched App tag: DENIED', async () => {
  const { jwt, dlk, encKey } = await registerUserNoRules();

  // Set rules so the user can write
  const { execSync } = await import('child_process');
  execSync(
    `npx wrangler d1 execute tarn-api --local --command "UPDATE accounts SET rules_json = '[]' WHERE data_lookup_key = '${dlk}'"`,
    { cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), stdio: 'pipe', timeout: 10000 }
  );

  const encrypted = await encrypt(encKey, { sneaky: true });
  const tags = [
    { name: 'App', value: 'wrong-app' }, // Doesn't match jwt.app
    { name: 'Type', value: 'entry' },
    { name: 'Lk', value: dlk },
    { name: 'Enc', value: 'aes-256-gcm' },
    { name: 'V', value: '0.4.0' },
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

  assert(res.status === 403, `Expected 403 for wrong App tag, got ${res.status}`);
});

await test('Write with correct App tag: ALLOWED', async () => {
  const { jwt, dlk, encKey } = await registerUserNoRules();

  const { execSync } = await import('child_process');
  execSync(
    `npx wrangler d1 execute tarn-api --local --command "UPDATE accounts SET rules_json = '[]' WHERE data_lookup_key = '${dlk}'"`,
    { cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), stdio: 'pipe', timeout: 10000 }
  );

  const encrypted = await encrypt(encKey, { correct: true });
  const tags = [
    { name: 'App', value: DEFAULT_APP_ID }, // Matches jwt.app
    { name: 'Type', value: 'entry' },
    { name: 'Lk', value: dlk },
    { name: 'Enc', value: 'aes-256-gcm' },
    { name: 'V', value: '0.4.0' },
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

  assert(res.status === 200, `Expected 200 for correct App tag, got ${res.status}`);
});

// ============ C6: Sync ack txids cap ============

console.log('\n=== C6: Sync ack txids array validation ===');

await test('Sync ack with >100 txids: rejected', async () => {
  const { jwt } = await registerUserNoRules();
  const bigArray = Array.from({ length: 101 }, (_, i) => `tx_${i}`);

  const res = await fetchJSON('/api/v1/sync/ack', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${jwt}` },
    body: JSON.stringify({ txids: bigArray }),
  });

  assert(res.status === 400, `Expected 400, got ${res.status}`);
});

// ============ Registration without valid app ============

console.log('\n=== App validation at registration ===');

await test('Register with unregistered app: rejected', async () => {
  const keys = await deriveAllKeys(randomEmail(), 'pass', 'nonexistent-app');
  const pub = await exportPublicKey(keys.signingKeyPair.publicKey);
  const wdk = await wrapDataKey(keys.credentialEncryptionKey.gcmKey, keys.credentialEncryptionKey.kwKey);

  const res = await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({
      credential_lookup_key: keys.credentialLookupKey,
      public_key: pub,
      wrapped_data_key: wdk,
      app: 'nonexistent-app',
    }),
  });

  assert(res.status === 400, `Expected 400 for unregistered app, got ${res.status}`);
  assert(res.json.error.includes('Unregistered'), `Expected 'Unregistered' error, got: ${res.json.error}`);
});

await test('Register without app field: rejected', async () => {
  const keys = await deriveAllKeys(randomEmail(), 'pass', 'dummy');
  const pub = await exportPublicKey(keys.signingKeyPair.publicKey);
  const wdk = await wrapDataKey(keys.credentialEncryptionKey.gcmKey, keys.credentialEncryptionKey.kwKey);

  const res = await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({
      credential_lookup_key: keys.credentialLookupKey,
      public_key: pub,
      wrapped_data_key: wdk,
      // no app field
    }),
  });

  assert(res.status === 400, `Expected 400 for missing app, got ${res.status}`);
});

// ============ SUMMARY ============

console.log(`\n=== Security Results: ${passed} passed, ${failed} failed ===\n`);
process.exit(failed > 0 ? 1 : 0);
