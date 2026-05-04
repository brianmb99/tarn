// End-to-end client tests for TarnClient
// Run: node tests/test-client.mjs [apiBaseUrl]
// Requires: wrangler dev running (cd api && npx wrangler dev --port 8787)

import './indexeddb-shim.mjs';
import { TarnClient } from '../client/src/tarn.js';
import { deriveAllKeys, exportPublicKey, wrapDataKey } from '../client/src/crypto.js';
import { clearWrappingKey } from '../client/src/session-persistence.js';
import { seedTestApp, DEFAULT_APP_ID, forceAllowRulesForAccount } from './helpers.mjs';

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
  const { dataLookupKey } = await client.register(email, 'test-password-123', { recoveryAcknowledged: true });

  assert(dataLookupKey, 'Should return dataLookupKey');
  assert(dataLookupKey.length === 64, 'dataLookupKey should be 64-char hex');
  assert(client.isAuthenticated, 'Should be authenticated after register');
});

await test('Register: duplicate email produces 409', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const email = randomEmail();
  await client.register(email, 'password', { recoveryAcknowledged: true });

  const client2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  try {
    await client2.register(email, 'password', { recoveryAcknowledged: true });
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
  const { dataLookupKey } = await client1.register(email, password, { recoveryAcknowledged: true });

  // Login from "another device"
  const client2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const result = await client2.login(email, password);

  assert(result.dataLookupKey === dataLookupKey, 'Login should return same dataLookupKey');
  assert(client2.isAuthenticated, 'Should be authenticated after login');
});

await test('Login: wrong password fails', async () => {
  const email = randomEmail();
  const client1 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client1.register(email, 'correct-password', { recoveryAcknowledged: true });

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
  const { dataLookupKey, recoveryPhrase } = await client.register(oldEmail, oldPassword, { recoveryAcknowledged: true });

  // Change credentials. v4 accounts require the phrase (issue #17 follow-up:
  // close the recovery-wrapping gap by default).
  await client.changeCredentials(newEmail, newPassword, { phrase: recoveryPhrase });
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
  await client.register(email, password, { recoveryAcknowledged: true });
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

// ============ SESSION PERSISTENCE (Section 7, issue #19) ============

console.log('\n=== Session Persistence ===');

await test('serializeSession + resumeSession: end-to-end without re-prompting password', async () => {
  // Each test owns the wrapping-key state to avoid cross-test interference.
  await clearWrappingKey();

  const email = randomEmail();
  const password = 'session-persist-1';
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const { dataLookupKey } = await client.register(email, password, { recoveryAcknowledged: true });
  // Allow reads locally without an app JWT — same pattern as test-e2e.
  await forceAllowRulesForAccount(dataLookupKey);

  const blob = await client.serializeSession();
  assert(typeof blob === 'string' && blob.length > 0, 'serializeSession returns a non-empty string');

  // Resume into a fresh client — no password supplied.
  const resumed = await TarnClient.resumeSession(API_BASE, DEFAULT_APP_ID, blob);
  assert(resumed instanceof TarnClient, 'resumeSession should return a TarnClient');
  assert(resumed.isAuthenticated, 'resumed client should be authenticated');
  assert(resumed.dataLookupKey === client.dataLookupKey, 'dataLookupKey should match');

  // Force the JWT to null so the next API call triggers re-auth via the
  // resumed signing key — this proves the signing keypair round-tripped
  // correctly through the persisted PKCS#8 export.
  resumed._testInvalidateJwt();
  const entries = await resumed.getEntries('entry');
  assert(Array.isArray(entries), 'resumed client should fetch entries (re-auth via signing key)');

  await resumed.deleteAccount();
});

await test('resumeSession: tampered blob returns null', async () => {
  await clearWrappingKey();

  const email = randomEmail();
  const password = 'session-persist-tamper';
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.register(email, password, { recoveryAcknowledged: true });

  const blob = await client.serializeSession();
  // Flip one base64url char somewhere past the IV region.
  const idx = Math.floor(blob.length / 2);
  const flipChar = blob[idx] === 'A' ? 'B' : 'A';
  const tampered = blob.slice(0, idx) + flipChar + blob.slice(idx + 1);

  const result = await TarnClient.resumeSession(API_BASE, DEFAULT_APP_ID, tampered);
  assert(result === null, 'tampered blob must resume to null');

  await client.deleteAccount();
});

await test('resumeSession: malformed (non-base64url) blob returns null', async () => {
  await clearWrappingKey();
  // Force the wrapping key to exist so the failure path is JSON, not key.
  const email = randomEmail();
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c.register(email, 'x', { recoveryAcknowledged: true });
  await c.serializeSession();

  // A short random string that decodes to a too-short blob.
  const result = await TarnClient.resumeSession(API_BASE, DEFAULT_APP_ID, 'aaaa');
  assert(result === null, 'short malformed blob must resume to null');

  await c.deleteAccount();
});

await test('resumeSession: schema-mismatch (unknown v) returns null', async () => {
  await clearWrappingKey();
  const email = randomEmail();
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.register(email, 'x', { recoveryAcknowledged: true });

  // Hand-build a blob with an unknown schema version (v: 99) by encrypting
  // under the same wrapping key. v1 (Section 7) and v2 (Section 7.5) are
  // both valid; anything else must reject.
  const { encryptSessionBlob, getOrCreateWrappingKey } = await import('../client/src/session-persistence.js');
  const { bytesToBase64Url } = await import('../client/src/crypto.js');
  const fake = { v: 99, expiresAt: Math.floor(Date.now() / 1000) + 1000 };
  const pt = new TextEncoder().encode(JSON.stringify(fake));
  const key = await getOrCreateWrappingKey();
  const ct = await encryptSessionBlob(pt, key);
  const blob = bytesToBase64Url(ct);

  const result = await TarnClient.resumeSession(API_BASE, DEFAULT_APP_ID, blob);
  assert(result === null, 'unknown schema v must resume to null');

  await client.deleteAccount();
});

await test('resumeSession: missing required field returns null', async () => {
  await clearWrappingKey();
  const email = randomEmail();
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.register(email, 'x', { recoveryAcknowledged: true });

  const { encryptSessionBlob, getOrCreateWrappingKey } = await import('../client/src/session-persistence.js');
  const { bytesToBase64Url } = await import('../client/src/crypto.js');
  const fake = { v: 1, createdAt: 1, expiresAt: Math.floor(Date.now() / 1000) + 1000, apiBase: API_BASE.replace(/\/$/, ''), appId: DEFAULT_APP_ID };
  const pt = new TextEncoder().encode(JSON.stringify(fake));
  const key = await getOrCreateWrappingKey();
  const ct = await encryptSessionBlob(pt, key);
  const blob = bytesToBase64Url(ct);

  const result = await TarnClient.resumeSession(API_BASE, DEFAULT_APP_ID, blob);
  assert(result === null, 'missing required fields must resume to null');

  await client.deleteAccount();
});

await test('resumeSession: wrong appId / apiBase returns null', async () => {
  await clearWrappingKey();
  const email = randomEmail();
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.register(email, 'x', { recoveryAcknowledged: true });
  const blob = await client.serializeSession();

  const wrongApp = await TarnClient.resumeSession(API_BASE, 'some-other-app', blob);
  assert(wrongApp === null, 'wrong appId must resume to null');
  const wrongApi = await TarnClient.resumeSession('http://nope.invalid', DEFAULT_APP_ID, blob);
  assert(wrongApi === null, 'wrong apiBase must resume to null');

  await client.deleteAccount();
});

await test('resumeSession: expired blob (via _nowSeconds) returns null', async () => {
  await clearWrappingKey();
  const email = randomEmail();
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.register(email, 'x', { recoveryAcknowledged: true });
  const blob = await client.serializeSession();

  // Pretend it's 8 days from now — past the 7-day cap baked into expiresAt.
  const future = Math.floor(Date.now() / 1000) + 8 * 24 * 60 * 60;
  const result = await TarnClient.resumeSession(API_BASE, DEFAULT_APP_ID, blob, { _nowSeconds: future });
  assert(result === null, 'expired blob must resume to null');

  // Sanity: fresh _nowSeconds should still resume.
  const freshNow = Math.floor(Date.now() / 1000);
  const ok = await TarnClient.resumeSession(API_BASE, DEFAULT_APP_ID, blob, { _nowSeconds: freshNow });
  assert(ok instanceof TarnClient, 'fresh _nowSeconds should still resume');

  await client.deleteAccount();
});

await test('resumeSession: wrong wrapping key (clearSession between) returns null', async () => {
  await clearWrappingKey();
  const email = randomEmail();
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.register(email, 'x', { recoveryAcknowledged: true });
  const blob = await client.serializeSession();

  // Resume works first.
  const ok = await TarnClient.resumeSession(API_BASE, DEFAULT_APP_ID, blob);
  assert(ok instanceof TarnClient, 'fresh resume should succeed');

  // Now wipe the wrapping key — getOrCreateWrappingKey will mint a new one,
  // and the old blob's auth-tag check will fail under it.
  await client.clearSession();
  const result = await TarnClient.resumeSession(API_BASE, DEFAULT_APP_ID, blob);
  assert(result === null, 'after clearSession the prior blob must resume to null');

  await client.deleteAccount();
});

await test('changeCredentials: prior blob resumes as null; fresh blob after change resumes successfully', async () => {
  await clearWrappingKey();
  const email = randomEmail();
  const password = 'pre-change';
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const { recoveryPhrase } = await client.register(email, password, { recoveryAcknowledged: true });

  const oldBlob = await client.serializeSession();

  await client.changeCredentials(email, 'post-change', { phrase: recoveryPhrase });

  // Old blob is now unreadable on this origin (clearSession side-effect).
  const old = await TarnClient.resumeSession(API_BASE, DEFAULT_APP_ID, oldBlob);
  assert(old === null, 'old blob should resume to null after changeCredentials');

  // A fresh blob emitted post-change should round-trip cleanly.
  const newBlob = await client.serializeSession();
  const resumed = await TarnClient.resumeSession(API_BASE, DEFAULT_APP_ID, newBlob);
  assert(resumed instanceof TarnClient, 'fresh post-change blob should resume');
  assert(resumed.isAuthenticated, 'resumed client should be authenticated');

  await resumed.deleteAccount();
});

// ============ SUMMARY ============

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
process.exit(failed > 0 ? 1 : 0);
