// End-to-end client tests for TarnClient
// Run: node tests/test-client.mjs [apiBaseUrl]
// Requires: wrangler dev running (cd api && npx wrangler dev --port 8787)

import { TarnClient } from '../client/src/tarn.js';
import { deriveAllKeys, exportPublicKey, wrapDataKey } from '../client/src/crypto.js';
import { seedTestApp, DEFAULT_APP_ID } from './helpers.mjs';

const API_BASE = process.argv[2] || 'http://localhost:8787';

// Seed the test app before any tests run
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

function randomEmail() {
  return `test-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
}

// ============ REGISTRATION ============

console.log('\n=== Registration ===');

await test('Register: happy path', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const email = randomEmail();
  const { dataLookupKey } = await client.register(email, 'test-password-123', { recoveryAcknowledged: true, emailRecoveryKit: false });

  assert(dataLookupKey, 'Should return dataLookupKey');
  assert(dataLookupKey.length === 64, 'dataLookupKey should be 64-char hex');
  assert(client.isAuthenticated, 'Should be authenticated after register');
});

await test('Register: duplicate email produces 409', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const email = randomEmail();
  await client.register(email, 'password', { recoveryAcknowledged: true, emailRecoveryKit: false });

  const client2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  try {
    await client2.register(email, 'password', { recoveryAcknowledged: true, emailRecoveryKit: false });
    assert(false, 'Should have thrown');
  } catch (err) {
    assert(err.message.includes('409') || err.message.includes('already'), `Expected 409 error, got: ${err.message}`);
  }
});

// ============ LOGIN ============

console.log('\n=== Login ===');

await test('Login: happy path', async () => {
  const email = randomEmail();
  const password = 'login-test-pass';

  // Register first
  const client1 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const { dataLookupKey } = await client1.register(email, password, { recoveryAcknowledged: true, emailRecoveryKit: false });

  // Login from "another device"
  const client2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const result = await client2.login(email, password);

  assert(result.dataLookupKey === dataLookupKey, 'Login should return same dataLookupKey');
  assert(client2.isAuthenticated, 'Should be authenticated after login');
});

await test('Login: wrong password fails', async () => {
  const email = randomEmail();
  const client1 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client1.register(email, 'correct-password', { recoveryAcknowledged: true, emailRecoveryKit: false });

  const client2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  try {
    await client2.login(email, 'wrong-password');
    assert(false, 'Should have thrown');
  } catch (err) {
    // Wrong password → wrong credential_lookup_key → 404
    assert(err.message.includes('not found') || err.message.includes('404'),
      `Expected 'not found' error, got: ${err.message}`);
  }
});

await test('Login: non-existent account fails', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  try {
    await client.login('nobody@example.com', 'password');
    assert(false, 'Should have thrown');
  } catch (err) {
    assert(err.message.includes('not found') || err.message.includes('404'),
      `Expected 'not found', got: ${err.message}`);
  }
});

// ============ KEY DETERMINISM ============

console.log('\n=== Key Determinism ===');

await test('Same email+password always derives same keys', async () => {
  const email = 'determinism@test.com';
  const password = 'test123';

  const keys1 = await deriveAllKeys(email, password, DEFAULT_APP_ID);
  const keys2 = await deriveAllKeys(email, password, DEFAULT_APP_ID);

  assert(keys1.credentialLookupKey === keys2.credentialLookupKey,
    'credentialLookupKey should be deterministic');

  const pub1 = await exportPublicKey(keys1.signingKeyPair.publicKey);
  const pub2 = await exportPublicKey(keys2.signingKeyPair.publicKey);
  assert(pub1 === pub2, 'Public key should be deterministic');
});

await test('Different emails derive different keys', async () => {
  const keys1 = await deriveAllKeys('alice@test.com', 'same-password', DEFAULT_APP_ID);
  const keys2 = await deriveAllKeys('bob@test.com', 'same-password', DEFAULT_APP_ID);

  assert(keys1.credentialLookupKey !== keys2.credentialLookupKey,
    'Different emails should produce different keys');
});

await test('Wrapped data key self-encryption round-trip', async () => {
  const keys = await deriveAllKeys('wrap-test@test.com', 'password', DEFAULT_APP_ID);

  // Self-encryption at registration
  const wrapped = await wrapDataKey(keys.credentialEncryptionKey.gcmKey, keys.credentialEncryptionKey.kwKey);
  assert(typeof wrapped === 'string', 'Wrapped key should be base64 string');

  // Unwrap should recover the same key
  const { unwrapDataKey: unwrap } = await import('../client/src/crypto.js');
  const unwrapped = await unwrap(wrapped, keys.credentialEncryptionKey.kwKey);
  assert(unwrapped instanceof CryptoKey, 'Unwrapped should be CryptoKey');

  // Verify the unwrapped key works for encryption
  const { encrypt, decrypt } = await import('../client/src/crypto.js');
  const testData = { hello: 'world' };
  const encrypted = await encrypt(unwrapped, testData);
  const decrypted = await decrypt(unwrapped, encrypted);
  assert(decrypted.hello === 'world', 'Unwrapped key should encrypt/decrypt correctly');
});

// ============ CREDENTIAL CHANGE ============

console.log('\n=== Credential Change ===');

await test('Change credentials: new login works, old fails', async () => {
  const oldEmail = randomEmail();
  const oldPassword = 'old-pass';
  const newEmail = randomEmail();
  const newPassword = 'new-pass';

  // Register + login
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const { dataLookupKey } = await client.register(oldEmail, oldPassword, { recoveryAcknowledged: true, emailRecoveryKit: false });

  // Change credentials
  await client.changeCredentials(newEmail, newPassword);
  assert(client.isAuthenticated, 'Should be re-authenticated after credential change');

  // New credentials should work
  const client2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const result = await client2.login(newEmail, newPassword);
  assert(result.dataLookupKey === dataLookupKey, 'data_lookup_key should be preserved');

  // Old credentials should fail
  const client3 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  try {
    await client3.login(oldEmail, oldPassword);
    assert(false, 'Old credentials should fail');
  } catch (err) {
    assert(err.message.includes('not found') || err.message.includes('404'),
      `Expected 'not found', got: ${err.message}`);
  }
});

// ============ ACCOUNT DELETION ============

console.log('\n=== Account Deletion ===');

await test('Delete account: login fails after', async () => {
  const email = randomEmail();
  const password = 'delete-me';

  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.register(email, password, { recoveryAcknowledged: true, emailRecoveryKit: false });
  assert(client.isAuthenticated, 'Should be authenticated');

  await client.deleteAccount();
  assert(!client.isAuthenticated, 'Should not be authenticated after deletion');

  // Login should fail
  const client2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  try {
    await client2.login(email, password);
    assert(false, 'Login should fail after deletion');
  } catch (err) {
    assert(err.message.includes('not found') || err.message.includes('404'),
      `Expected 'not found', got: ${err.message}`);
  }
});

// ============ SUMMARY ============

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
process.exit(failed > 0 ? 1 : 0);
