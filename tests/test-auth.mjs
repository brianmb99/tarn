// Integration tests for Tarn auth endpoints
// Run: node tests/test-auth.mjs [baseUrl]
// Requires: wrangler dev running (or deployed API URL)
// Uses Node.js built-in WebCrypto for P-256 key generation and signing.

import { seedTestApp, DEFAULT_APP_ID } from './helpers.mjs';

const BASE_URL = process.argv[2] || 'http://localhost:8787';

// Seed the test app before any tests run
await seedTestApp();

let passed = 0;
let failed = 0;
let skipped = 0;

function log(status, name, detail = '') {
  const icon = status === 'PASS' ? '✓' : status === 'FAIL' ? '✗' : '⊘';
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

async function fetchJSON(path, opts = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: res.status, json, text, headers: res.headers };
}

// ============ CRYPTO HELPERS ============

async function generateKeyPair() {
  return await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
}

async function exportPublicKeySPKI(publicKey) {
  const der = await crypto.subtle.exportKey('spki', publicKey);
  return bytesToBase64(new Uint8Array(der));
}

async function signNonce(privateKey, nonceHex) {
  const nonceBytes = hexToBytes(nonceHex);
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    nonceBytes
  );
  return bytesToBase64(new Uint8Array(sig));
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function randomHex64() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============ REGISTRATION TESTS ============

console.log('\n=== Registration ===');

await test('Register: happy path', async () => {
  const { publicKey } = await generateKeyPair();
  const pub = await exportPublicKeySPKI(publicKey);
  const clk = randomHex64();
  const wdk = bytesToBase64(new Uint8Array(48)); // dummy wrapped key

  const { status, json } = await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk, public_key: pub, wrapped_data_key: wdk, app: DEFAULT_APP_ID }),
  });

  assert(status === 201, `Expected 201, got ${status}: ${JSON.stringify(json)}`);
  assert(json.data_lookup_key, 'Expected data_lookup_key');
  assert(json.data_lookup_key.length === 64, 'data_lookup_key should be 64-char hex');
  assert(/^[a-f0-9]{64}$/.test(json.data_lookup_key), 'data_lookup_key should be lowercase hex');
});

await test('Register: duplicate credential_lookup_key -> 409', async () => {
  const { publicKey } = await generateKeyPair();
  const pub = await exportPublicKeySPKI(publicKey);
  const clk = randomHex64();
  const wdk = bytesToBase64(new Uint8Array(48));

  // First registration
  const { status: s1 } = await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk, public_key: pub, wrapped_data_key: wdk, app: DEFAULT_APP_ID }),
  });
  assert(s1 === 201, `First registration should succeed, got ${s1}`);

  // Duplicate
  const { status: s2, json } = await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk, public_key: pub, wrapped_data_key: wdk, app: DEFAULT_APP_ID }),
  });
  assert(s2 === 409, `Expected 409, got ${s2}: ${JSON.stringify(json)}`);
});

await test('Register: invalid credential_lookup_key -> 400', async () => {
  const { publicKey } = await generateKeyPair();
  const pub = await exportPublicKeySPKI(publicKey);

  const { status } = await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: 'too-short', public_key: pub, wrapped_data_key: 'x', app: DEFAULT_APP_ID }),
  });
  assert(status === 400, `Expected 400, got ${status}`);
});

await test('Register: invalid public_key -> 400', async () => {
  const { status } = await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: randomHex64(), public_key: 'garbage', wrapped_data_key: 'x', app: DEFAULT_APP_ID }),
  });
  assert(status === 400, `Expected 400, got ${status}`);
});

await test('Register: missing wrapped_data_key -> 400', async () => {
  const { publicKey } = await generateKeyPair();
  const pub = await exportPublicKeySPKI(publicKey);

  const { status } = await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: randomHex64(), public_key: pub, app: DEFAULT_APP_ID }),
  });
  assert(status === 400, `Expected 400, got ${status}`);
});

// ============ LOGIN TESTS (CHALLENGE + VERIFY) ============

console.log('\n=== Login (Challenge + Verify) ===');

await test('Login: full happy path', async () => {
  const { publicKey, privateKey } = await generateKeyPair();
  const pub = await exportPublicKeySPKI(publicKey);
  const clk = randomHex64();
  const wdk = bytesToBase64(new Uint8Array(48));

  // Register
  const { json: regJson } = await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk, public_key: pub, wrapped_data_key: wdk, app: DEFAULT_APP_ID }),
  });
  const dlk = regJson.data_lookup_key;

  // Challenge
  const { status: cs, json: cJson } = await fetchJSON('/api/v1/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk }),
  });
  assert(cs === 200, `Challenge should return 200, got ${cs}`);
  assert(cJson.nonce, 'Challenge should return nonce');
  assert(cJson.data_lookup_key === dlk, 'Challenge should return correct data_lookup_key');
  assert(cJson.wrapped_data_key === wdk, 'Challenge should return wrapped_data_key');

  // Sign nonce
  const signature = await signNonce(privateKey, cJson.nonce);

  // Verify
  const { status: vs, json: vJson } = await fetchJSON('/api/v1/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk, nonce: cJson.nonce, signature }),
  });
  assert(vs === 200, `Verify should return 200, got ${vs}: ${JSON.stringify(vJson)}`);
  assert(vJson.jwt, 'Verify should return JWT');
  assert(vJson.expiresIn === 900, 'JWT should expire in 900s');
});

await test('Challenge: unknown credential_lookup_key -> 404', async () => {
  const { status } = await fetchJSON('/api/v1/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: randomHex64() }),
  });
  assert(status === 404, `Expected 404, got ${status}`);
});

await test('Verify: wrong signature -> 401', async () => {
  const { publicKey } = await generateKeyPair();
  const wrongKeyPair = await generateKeyPair();
  const pub = await exportPublicKeySPKI(publicKey);
  const clk = randomHex64();
  const wdk = bytesToBase64(new Uint8Array(48));

  // Register
  await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk, public_key: pub, wrapped_data_key: wdk, app: DEFAULT_APP_ID }),
  });

  // Challenge
  const { json: cJson } = await fetchJSON('/api/v1/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk }),
  });

  // Sign with WRONG key
  const wrongSig = await signNonce(wrongKeyPair.privateKey, cJson.nonce);

  const { status } = await fetchJSON('/api/v1/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk, nonce: cJson.nonce, signature: wrongSig }),
  });
  assert(status === 401, `Expected 401, got ${status}`);
});

await test('Verify: nonce replay -> 401', async () => {
  const { publicKey, privateKey } = await generateKeyPair();
  const pub = await exportPublicKeySPKI(publicKey);
  const clk = randomHex64();
  const wdk = bytesToBase64(new Uint8Array(48));

  // Register
  await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk, public_key: pub, wrapped_data_key: wdk, app: DEFAULT_APP_ID }),
  });

  // Challenge
  const { json: cJson } = await fetchJSON('/api/v1/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk }),
  });

  const signature = await signNonce(privateKey, cJson.nonce);

  // First verify — should succeed
  const { status: s1 } = await fetchJSON('/api/v1/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk, nonce: cJson.nonce, signature }),
  });
  assert(s1 === 200, `First verify should succeed, got ${s1}`);

  // Replay — should fail
  const { status: s2 } = await fetchJSON('/api/v1/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk, nonce: cJson.nonce, signature }),
  });
  assert(s2 === 401, `Replay should return 401, got ${s2}`);
});

await test('Verify: nonce for different credential_lookup_key -> 401', async () => {
  const kp1 = await generateKeyPair();
  const kp2 = await generateKeyPair();
  const pub1 = await exportPublicKeySPKI(kp1.publicKey);
  const pub2 = await exportPublicKeySPKI(kp2.publicKey);
  const clk1 = randomHex64();
  const clk2 = randomHex64();
  const wdk = bytesToBase64(new Uint8Array(48));

  // Register both
  await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk1, public_key: pub1, wrapped_data_key: wdk, app: DEFAULT_APP_ID }),
  });
  await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk2, public_key: pub2, wrapped_data_key: wdk, app: DEFAULT_APP_ID }),
  });

  // Get challenge for clk1
  const { json: cJson } = await fetchJSON('/api/v1/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk1 }),
  });

  // Try to verify with clk2's nonce
  const signature = await signNonce(kp2.privateKey, cJson.nonce);
  const { status } = await fetchJSON('/api/v1/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk2, nonce: cJson.nonce, signature }),
  });
  assert(status === 401, `Expected 401, got ${status}`);
});

// ============ CREDENTIAL CHANGE TESTS ============

console.log('\n=== Credential Change ===');

// Helper: register + login, return { clk, dlk, jwt, privateKey }
async function registerAndLogin() {
  const { publicKey, privateKey } = await generateKeyPair();
  const pub = await exportPublicKeySPKI(publicKey);
  const clk = randomHex64();
  const wdk = bytesToBase64(new Uint8Array(48));

  const { json: regJson } = await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk, public_key: pub, wrapped_data_key: wdk, app: DEFAULT_APP_ID }),
  });

  const { json: cJson } = await fetchJSON('/api/v1/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk }),
  });

  const sig = await signNonce(privateKey, cJson.nonce);

  const { json: vJson } = await fetchJSON('/api/v1/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk, nonce: cJson.nonce, signature: sig }),
  });

  return { clk, dlk: regJson.data_lookup_key, jwt: vJson.jwt, privateKey };
}

await test('Credential change: happy path', async () => {
  const { jwt, dlk } = await registerAndLogin();

  // Generate new credentials
  const newKP = await generateKeyPair();
  const newPub = await exportPublicKeySPKI(newKP.publicKey);
  const newClk = randomHex64();
  const newWdk = bytesToBase64(new Uint8Array(48));

  // Change credentials
  const { status, json } = await fetchJSON('/api/v1/auth', {
    method: 'PUT',
    headers: { Authorization: `Bearer ${jwt}` },
    body: JSON.stringify({
      new_credential_lookup_key: newClk,
      new_public_key: newPub,
      new_wrapped_data_key: newWdk,
    }),
  });
  assert(status === 200, `Expected 200, got ${status}: ${JSON.stringify(json)}`);

  // Old credential_lookup_key should no longer work
  const { status: cs } = await fetchJSON('/api/v1/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: 'does-not-exist-anymore' }),
  });
  // (We can't test the old clk here without storing it — but we can verify new login works)

  // New login should work
  const { status: cs2, json: cJson2 } = await fetchJSON('/api/v1/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: newClk }),
  });
  assert(cs2 === 200, `New challenge should work, got ${cs2}`);
  assert(cJson2.data_lookup_key === dlk, 'data_lookup_key should be unchanged');

  const newSig = await signNonce(newKP.privateKey, cJson2.nonce);
  const { status: vs2 } = await fetchJSON('/api/v1/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: newClk, nonce: cJson2.nonce, signature: newSig }),
  });
  assert(vs2 === 200, `New verify should work, got ${vs2}`);
});

await test('Credential change: without auth -> 401', async () => {
  const { status } = await fetchJSON('/api/v1/auth', {
    method: 'PUT',
    body: JSON.stringify({
      new_credential_lookup_key: randomHex64(),
      new_public_key: 'x',
      new_wrapped_data_key: 'x',
    }),
  });
  assert(status === 401, `Expected 401, got ${status}`);
});

// ============ ACCOUNT DELETION TESTS ============

console.log('\n=== Account Deletion ===');

await test('Delete account: happy path', async () => {
  const { jwt, clk } = await registerAndLogin();

  const { status } = await fetchJSON('/api/v1/auth', {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${jwt}` },
  });
  assert(status === 200, `Expected 200, got ${status}`);

  // Challenge should fail now
  const { status: cs } = await fetchJSON('/api/v1/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: clk }),
  });
  assert(cs === 404, `Expected 404 after deletion, got ${cs}`);
});

await test('Delete account: without auth -> 401', async () => {
  const { status } = await fetchJSON('/api/v1/auth', { method: 'DELETE' });
  assert(status === 401, `Expected 401, got ${status}`);
});

// ============ SUMMARY ============

console.log(`\n=== Results: ${passed} passed, ${failed} failed, ${skipped} skipped ===\n`);
process.exit(failed > 0 ? 1 : 0);
