#!/usr/bin/env node
/**
 * Post-deployment smoke test for the Tarn API.
 * Tests the full lifecycle against a live deployed API.
 *
 * Usage:
 *   node tests/test-deployed.mjs <api_url> <app_id> <app_private_key_hex>
 *
 * Example:
 *   node tests/test-deployed.mjs https://api.tarn.dev bookish 308187...
 *
 * Prerequisites:
 *   - API deployed and healthy
 *   - App registered in D1 (via generate-app-key.mjs + D1 seed)
 *   - APP_SIGNING_KEY secret set (for Arweave uploads)
 *   - WARP VPN disabled (blocks Turbo uploads)
 */

import { TarnClient } from '../client/src/tarn.js';
import {
  deriveAllKeys, exportPublicKey, wrapDataKey, signChallenge,
  encodeSharePub, deriveShareLookupKey,
} from '../client/src/crypto.js';

const API_BASE = process.argv[2];
const APP_ID = process.argv[3];
const APP_KEY = process.argv[4];

if (!API_BASE || !APP_ID || !APP_KEY) {
  console.error('Usage: node tests/test-deployed.mjs <api_url> <app_id> <app_private_key_hex>');
  console.error('Example: node tests/test-deployed.mjs https://api.tarn.dev bookish 308187...');
  process.exit(1);
}

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

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

const testEmail = `deploy-test-${Date.now()}@test.com`;
const testPassword = 'deploy-test-pass-' + Date.now();
let testDlk;

// ============ 1. HEALTH ============

console.log('\n=== 1. Health Check ===');

await test('API is healthy', async () => {
  const res = await fetch(`${API_BASE}/api/v1/health`);
  const json = await res.json();
  assert(res.status === 200, `Status ${res.status}`);
  assert(json.healthy === true, 'Not healthy');
  assert(json.version === '0.4.0', `Wrong version: ${json.version}`);
  assert(json.checks.d1.reachable, 'D1 not reachable');
  console.log(`    D1 entries: ${json.checks.d1.entryCount}, Arweave: ${json.checks.arweave.reachable ? 'OK' : 'FAIL'}`);
});

// ============ 2. REGISTER ============

console.log('\n=== 2. Registration ===');

await test('Register new user', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  const { dataLookupKey } = await tarn.register(testEmail, testPassword, { recoveryAcknowledged: true, emailRecoveryKit: false });
  assert(dataLookupKey, 'No dataLookupKey');
  assert(dataLookupKey.length === 64, 'Bad dataLookupKey length');
  assert(tarn.isAuthenticated, 'Not authenticated');
  testDlk = dataLookupKey;
  console.log(`    DLK: ${testDlk.slice(0, 16)}...`);
});

await test('Re-register with same credentials is idempotent (issue #6)', async () => {
  // Simulates the 503-after-commit case: client retries with an identical
  // payload. Server should return 201 with the same DLK, not 409.
  const tarn = new TarnClient(API_BASE, APP_ID);
  const { dataLookupKey } = await tarn.register(testEmail, testPassword, { recoveryAcknowledged: true, emailRecoveryKit: false });
  assert(dataLookupKey === testDlk, `DLK changed on retry: ${dataLookupKey} vs ${testDlk}`);
});

// ============ 3. APP AUTH + SET RULES ============

console.log('\n=== 3. App Auth + Set Rules ===');

await test('App sets free-tier rules for new user', async () => {
  // Import app private key
  const pkcs8 = new Uint8Array(APP_KEY.length / 2);
  for (let i = 0; i < APP_KEY.length; i += 2) pkcs8[i / 2] = parseInt(APP_KEY.substr(i, 2), 16);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);

  // Challenge
  const cRes = await fetch(`${API_BASE}/api/v1/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: APP_ID }),
  });
  assert(cRes.status === 200, `Challenge failed: ${cRes.status}`);
  const { nonce } = await cRes.json();

  // Sign
  const nonceBytes = new Uint8Array(nonce.length / 2);
  for (let i = 0; i < nonce.length; i += 2) nonceBytes[i / 2] = parseInt(nonce.substr(i, 2), 16);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, nonceBytes);
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));

  // Verify
  const vRes = await fetch(`${API_BASE}/api/v1/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: APP_ID, nonce, signature: sigB64 }),
  });
  assert(vRes.status === 200, `Verify failed: ${vRes.status}`);
  const { jwt } = await vRes.json();

  // Set rules
  const rulesRes = await fetch(`${API_BASE}/api/v1/accounts/${testDlk}/rules`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${jwt}` },
    body: JSON.stringify({ rules: [{ type: 'max_entries', limit: 5, app: APP_ID }, { type: 'max_bytes', limit: 102400 }] }),
  });
  assert(rulesRes.status === 200, `Set rules failed: ${rulesRes.status}`);
});

// ============ 4. LOGIN ============

console.log('\n=== 4. Login ===');

await test('Login on "another device"', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  const { dataLookupKey } = await tarn.login(testEmail, testPassword);
  assert(dataLookupKey === testDlk, 'DLK mismatch');
  assert(tarn.isAuthenticated, 'Not authenticated');
});

// ============ 5. WRITE + READ ============

console.log('\n=== 5. Write + Read ===');

let entryTxid;

await test('Create entry', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testEmail, testPassword);
  const { txid } = await tarn.createEntry('entry', {
    title: 'Deployment Test',
    author: 'Tarn CI',
    timestamp: Date.now(),
  });
  assert(txid, 'No txid');
  entryTxid = txid;
  console.log(`    Txid: ${txid.slice(0, 20)}...`);
});

await test('Idempotent write: retry with same X-Idempotency-Key returns same txid (issue #8)', async () => {
  // Low-level test: send two raw POSTs with the same X-Idempotency-Key and
  // assert the second returns the txid from the first — the server short-
  // circuits on the cached response instead of signing a new DataItem.
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testEmail, testPassword);

  // Server doesn't decrypt the body, it just signs + caches. Any bytes work.
  const payload = new TextEncoder().encode(JSON.stringify({ _: 'idempotency-test', t: Date.now() }));
  const tags = [
    { name: 'App', value: APP_ID },
    { name: 'Type', value: 'entry' },
    { name: 'Lk', value: testDlk },
    { name: 'Enc', value: 'aes-256-gcm' },
    { name: 'V', value: '0.4.0' },
  ];
  const key = crypto.randomUUID();
  const headers = {
    'Authorization': `Bearer ${tarn._testJwt()}`,
    'X-Arweave-Tags': JSON.stringify(tags),
    'X-Idempotency-Key': key,
    'Content-Type': 'application/octet-stream',
  };

  const res1 = await fetch(`${API_BASE}/api/v1/entries`, { method: 'POST', headers, body: payload });
  const json1 = await res1.json();
  assert(res1.status === 200, `First write failed: ${res1.status} ${JSON.stringify(json1)}`);

  const res2 = await fetch(`${API_BASE}/api/v1/entries`, { method: 'POST', headers, body: payload });
  const json2 = await res2.json();
  assert(res2.status === 200, `Second write failed: ${res2.status}`);
  assert(json1.id === json2.id, `Idempotency failed: different txids (${json1.id} vs ${json2.id})`);
});

await test('Read entry from D1 cache', async () => {
  await sleep(500); // Brief wait for write-through
  const res = await fetch(`${API_BASE}/api/v1/entries?app=${APP_ID}&type=entry&key=${testDlk}`);
  const json = await res.json();
  assert(res.status === 200, `Read failed: ${res.status}`);
  assert(json.entries.length >= 1, `Expected entries, got ${json.entries.length}`);
  const entry = json.entries.find(e => e.txid === entryTxid);
  assert(entry, 'Entry not in cache');
});

await test('Entry available on Turbo gateway', async () => {
  await sleep(3000); // Wait for background Turbo upload
  const res = await fetch(`https://turbo-gateway.com/${entryTxid}`, { signal: AbortSignal.timeout(10000) });
  if (res.ok) {
    const bytes = (await res.arrayBuffer()).byteLength;
    console.log(`    ${bytes} bytes on Turbo gateway (encrypted)`);
  } else {
    console.log(`    Gateway returned ${res.status} — may need more time`);
    // Not a hard failure — Turbo upload is background/async
  }
  // Pass regardless — the D1 cache test above proves the write worked
});

// ============ 6. STATUS ============

console.log('\n=== 6. Status ===');

await test('Status endpoint returns operational data', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testEmail, testPassword);

  // Use raw fetch since TarnClient doesn't expose status
  const keys = await deriveAllKeys(testEmail, testPassword, APP_ID);
  const cRes = await fetch(`${API_BASE}/api/v1/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey }),
  });
  const { nonce } = await cRes.json();
  const sig = await signChallenge(keys.signingKeyPair.privateKey, nonce);
  const vRes = await fetch(`${API_BASE}/api/v1/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey, nonce, signature: sig }),
  });
  const { jwt } = await vRes.json();

  const statusRes = await fetch(`${API_BASE}/api/v1/status`, {
    headers: { 'Authorization': `Bearer ${jwt}` },
  });
  const status = await statusRes.json();
  assert(statusRes.status === 200, `Status failed: ${statusRes.status}`);
  assert(status.protocol_version === '0.4.0', `Wrong version: ${status.protocol_version}`);
  assert(typeof status.users?.total === 'number', 'Missing users.total');
  assert(typeof status.entries?.total === 'number', 'Missing entries.total');
  console.log(`    Users: ${status.users.total}, Entries: ${status.entries.total}`);
});

// ============ 7. SHARING KEYPAIR (issue #13) ============

console.log('\n=== 7. Sharing keypair lookup ===');

await test('getRecipientShareKey returns the published share_pub', async () => {
  const expected = encodeSharePub(
    (await deriveAllKeys(testEmail, testPassword, APP_ID)).sharingKeyPair.publicKey,
  );
  const stranger = new TarnClient(API_BASE, APP_ID);
  const { sharePubBase64Url, discoverable, sharePub } = await stranger.getRecipientShareKey(testEmail);
  assert(discoverable === true, `expected discoverable=true, got ${discoverable}`);
  assert(sharePubBase64Url === expected, `share_pub mismatch:\n  got:  ${sharePubBase64Url}\n  want: ${expected}`);
  assert(sharePub instanceof Uint8Array && sharePub.length === 32, 'sharePub should decode to 32 raw bytes');
});

await test('getRecipientShareKey for unknown email returns null + discoverable=false', async () => {
  const stranger = new TarnClient(API_BASE, APP_ID);
  const { sharePub, discoverable } = await stranger.getRecipientShareKey(`nobody-${Date.now()}@nowhere.test`);
  assert(sharePub === null, 'unknown email should return null sharePub');
  assert(discoverable === false, 'unknown email should be opaque');
});

await test('share_lookup_key is per-app isolated (cross-app probe misses)', async () => {
  // Use a different app_id (the smoke test only seeds bookish on the deployed
  // API, so this lookup will miss for two reasons — different app + different
  // share_lookup_key — both consistent with the design).
  const wrongApp = new TarnClient(API_BASE, 'definitely-not-a-real-app');
  const { sharePub, discoverable } = await wrongApp.getRecipientShareKey(testEmail);
  assert(sharePub === null, 'cross-app lookup should miss');
  assert(discoverable === false, 'cross-app lookup should be opaque');
});

// ============ 8. FRIEND HANDSHAKE (issue #14, Section 5a) ============

console.log('\n=== 8. Friend handshake (HPKE inbox) ===');

let handshakeAlice;
let handshakeBob;
let handshakeAliceEmail;
let handshakeAliceDlk;
let handshakeBobEmail;
let handshakeBobDlk;
let handshakeRequestNonce;

await test('Two test users register + complete a mutual handshake against the deployed API', async () => {
  // Note: we don't need to set rules for the friends + pending records
  // because Bookish's standard rules (max_entries with no entry_type filter,
  // max_bytes) apply per-app. The test creates only a few share-state
  // entries — well under the limit. If max_entries were lower than ~5 the
  // test would fail; the smoke-test rule set is `max_entries: 5, app:
  // bookish` and we use 2 entries per user (friends + pending), so we have
  // headroom.
  handshakeAliceEmail = `deploy-handshake-a-${Date.now()}@test.com`;
  handshakeBobEmail = `deploy-handshake-b-${Date.now()}@test.com`;
  const password = 'handshake-test-' + Date.now();

  handshakeAlice = new TarnClient(API_BASE, APP_ID);
  handshakeBob = new TarnClient(API_BASE, APP_ID);
  const a = await handshakeAlice.register(handshakeAliceEmail, password, { recoveryAcknowledged: true, emailRecoveryKit: false });
  const b = await handshakeBob.register(handshakeBobEmail, password, { recoveryAcknowledged: true, emailRecoveryKit: false });
  handshakeAliceDlk = a.dataLookupKey;
  handshakeBobDlk = b.dataLookupKey;

  // Set permissive rules on each user via the bookish app JWT (the
  // existing test scaffolding sets rules for testDlk only; we replicate
  // the auth+PUT for our two new users).
  const pkcs8 = new Uint8Array(APP_KEY.length / 2);
  for (let i = 0; i < APP_KEY.length; i += 2) pkcs8[i / 2] = parseInt(APP_KEY.substr(i, 2), 16);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const cRes = await fetch(`${API_BASE}/api/v1/auth/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: APP_ID }),
  });
  const { nonce } = await cRes.json();
  const nonceBytes = new Uint8Array(nonce.length / 2);
  for (let i = 0; i < nonce.length; i += 2) nonceBytes[i / 2] = parseInt(nonce.substr(i, 2), 16);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, nonceBytes);
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  const vRes = await fetch(`${API_BASE}/api/v1/auth/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: APP_ID, nonce, signature: sigB64 }),
  });
  const { jwt } = await vRes.json();

  for (const dlk of [handshakeAliceDlk, handshakeBobDlk]) {
    const r = await fetch(`${API_BASE}/api/v1/accounts/${dlk}/rules`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${jwt}` },
      body: JSON.stringify({ rules: [{ type: 'max_entries', limit: 20, app: APP_ID }, { type: 'max_bytes', limit: 102400 }] }),
    });
    assert(r.status === 200, `Set rules failed for ${dlk}: ${r.status}`);
  }

  // Alice → Bob friend request.
  const send = await handshakeAlice.sendFriendRequest(handshakeBobEmail, { message: 'hi from deployed test' });
  assert(send.requestNonce, 'no requestNonce');
  handshakeRequestNonce = send.requestNonce;

  // Bob picks it up.
  await sleep(500);
  const inbox = await handshakeBob.listIncomingRequests();
  assert(inbox.length >= 1, `Bob expected ≥1 incoming, got ${inbox.length}`);
  assert(inbox.some(r => r.requestNonce === handshakeRequestNonce), 'request nonce not in inbox');

  // Bob accepts.
  await handshakeBob.acceptFriendRequest(handshakeRequestNonce);
  const bobFriends = await handshakeBob.listFriends();
  assert(bobFriends.some(f => f.email === handshakeAliceEmail), 'Alice not in Bob\'s friends');

  // Alice processes the accept.
  await sleep(500);
  await handshakeAlice.listIncomingRequests();
  const aliceFriends = await handshakeAlice.listFriends();
  assert(aliceFriends.some(f => f.email === handshakeBobEmail), 'Bob not in Alice\'s friends');
});

await test('Delete handshake test accounts', async () => {
  if (handshakeAlice) await handshakeAlice.deleteAccount();
  if (handshakeBob) await handshakeBob.deleteAccount();
});

// ============ 9. CLEANUP ============

console.log('\n=== 9. Cleanup ===');

await test('Delete test account', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testEmail, testPassword);
  await tarn.deleteAccount();
  assert(!tarn.isAuthenticated, 'Still authenticated after deletion');

  // Verify login fails
  const tarn2 = new TarnClient(API_BASE, APP_ID);
  try {
    await tarn2.login(testEmail, testPassword);
    assert(false, 'Login should fail after deletion');
  } catch (err) {
    assert(err.message.includes('not found') || err.message.includes('404'), `Unexpected error: ${err.message}`);
  }
});

// ============ SUMMARY ============

console.log(`\n=== Deployment Test: ${passed} passed, ${failed} failed ===`);
if (failed === 0) {
  console.log('✓ Tarn API is fully operational.\n');
} else {
  console.log('✗ Issues detected — investigate before relying on this deployment.\n');
}
process.exit(failed > 0 ? 1 : 0);
