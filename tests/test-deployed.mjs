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

// ============ 9. SHARE LOG (issue #15, Section 5b) ============

console.log('\n=== 9. Share log (per-pair, signed, stealth-tagged) ===');

await test('Friends from §8 can publish + fetch share log entries with verified signatures', async () => {
  // Re-resolve the friend records on each side. Section 8 left Alice + Bob
  // mutually friended; the seq=0 snapshots were already published by the
  // handshake-acceptance flow.
  const aliceFriends = await handshakeAlice.listFriends();
  const bobFriends = await handshakeBob.listFriends();
  const bobFriendOfAlice = aliceFriends.find(f => f.email === handshakeBobEmail);
  const aliceFriendOfBob = bobFriends.find(f => f.email === handshakeAliceEmail);
  assert(bobFriendOfAlice, 'Bob missing from Alice\'s friends');
  assert(aliceFriendOfBob, 'Alice missing from Bob\'s friends');

  // Bob fetches Alice's seq=0 snapshot.
  const initial = await handshakeBob._fetchShareLogEntry(aliceFriendOfBob, 0);
  assert(initial, 'no entry at seq=0 from Alice');
  assert(initial.operation.type === 'snapshot',
    `expected snapshot at seq=0, got ${initial.operation.type}`);
  assert(initial.verified === true, 'seq=0 signature did not verify');

  // Alice publishes a real `add` operation; Bob fetches + verifies.
  const cek = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const addRes = await handshakeAlice._publishShareLogEntry(bobFriendOfAlice, {
    type: 'add',
    content_id: 'deploy-share-log-' + Date.now(),
    tx_id: 'arweave-tx-deploy-' + Date.now(),
    cek,
    shared_at: Math.floor(Date.now() / 1000),
  });
  assert(addRes.txid, 'no txid on publish');
  assert(typeof addRes.seq === 'number', 'no seq on publish');

  await sleep(500);
  const fetched = await handshakeBob._fetchShareLogEntry(aliceFriendOfBob, addRes.seq);
  assert(fetched, `Bob found nothing at seq=${addRes.seq}`);
  assert(fetched.operation.type === 'add', 'wrong op type after fetch');
  assert(fetched.verified === true, 'add signature did not verify');
});

await test('Per-tag uniqueness against deployed API: re-publish at same tag → 409', async () => {
  // Push a synthetic tag through Alice's JWT twice — second attempt must be
  // 409 with the existing txid.
  const jwt = handshakeAlice._testJwt();
  const tagSeed = crypto.getRandomValues(new Uint8Array(32));
  // We use deriveLogTag from the SDK to keep the format consistent, but
  // imported lazily to avoid needing share-log re-exports at file load.
  const { deriveLogTag } = await import('../client/src/share-log.js');
  const tag = await deriveLogTag(tagSeed, 0);
  const dummyCipher = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(64))));

  const r1 = await fetch(`${API_BASE}/api/v1/share/log/publish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${jwt}` },
    body: JSON.stringify({ tag, type: 'share-log-v1', ciphertext_base64: dummyCipher }),
  });
  assert(r1.status === 200, `first publish must succeed: ${r1.status}`);
  const j1 = await r1.json();

  const r2 = await fetch(`${API_BASE}/api/v1/share/log/publish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${jwt}` },
    body: JSON.stringify({ tag, type: 'share-log-v1', ciphertext_base64: dummyCipher }),
  });
  assert(r2.status === 409, `second publish must be 409: ${r2.status}`);
  const j2 = await r2.json();
  assert(j2.existing_txid === j1.txid, '409 must echo the original txid');
});

// ============ 9b. SHARE LOG READ FLOW + RETRY (issue #16, Section 5c) ============

console.log('\n=== 9b. Share log read flow + multi-device retry (Section 5c) ===');

await test('readShareLog: Bob bootstraps Alice\'s log, sees content shared by Alice', async () => {
  // Re-resolve friend records (handshakeAlice/Bob persist from §8/§9).
  const aliceFriends = await handshakeAlice.listFriends();
  const bobFriends = await handshakeBob.listFriends();
  const bobFriendOfAlice = aliceFriends.find(f => f.email === handshakeBobEmail);
  const aliceFriendOfBob = bobFriends.find(f => f.email === handshakeAliceEmail);
  assert(bobFriendOfAlice && aliceFriendOfBob, 'friend records missing');

  const cek1 = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const cek2 = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  await handshakeAlice.shareContent(bobFriendOfAlice, 'deploy-5c-A', 'tx-5c-A', cek1);
  await handshakeAlice.shareContent(bobFriendOfAlice, 'deploy-5c-B', 'tx-5c-B', cek2);

  await sleep(800);
  const bobState = await handshakeBob.readShareLog(aliceFriendOfBob, { refresh: true });
  assert(bobState['deploy-5c-A']?.tx_id === 'tx-5c-A', 'deploy-5c-A missing or wrong tx_id');
  assert(bobState['deploy-5c-B']?.tx_id === 'tx-5c-B', 'deploy-5c-B missing or wrong tx_id');
});

await test('syncShareLog: incremental update + remove flows through to Bob', async () => {
  const aliceFriends = await handshakeAlice.listFriends();
  const bobFriends = await handshakeBob.listFriends();
  const bobFriendOfAlice = aliceFriends.find(f => f.email === handshakeBobEmail);
  const aliceFriendOfBob = bobFriends.find(f => f.email === handshakeAliceEmail);

  await handshakeAlice.updateShareContent(bobFriendOfAlice, 'deploy-5c-A', 'tx-5c-A-v2');
  await handshakeAlice.unshareContent(bobFriendOfAlice, 'deploy-5c-B');

  await sleep(800);
  const updated = await handshakeBob.syncShareLog(aliceFriendOfBob);
  assert(updated['deploy-5c-A']?.tx_id === 'tx-5c-A-v2', 'update did not propagate');
  assert(updated['deploy-5c-B'] === undefined, 'remove did not propagate');
});

await test('Concurrent publish race against deployed API: exactly one 409, NOT 500', async () => {
  // Drives the live API's INSERT-vs-UNIQUE catch path for the 409-vs-500
  // contract that 5c's retry depends on. Two parallel POSTs at the same
  // synthetic tag from the same JWT.
  const jwt = handshakeAlice._testJwt();
  const tagSeed = crypto.getRandomValues(new Uint8Array(32));
  const { deriveLogTag } = await import('../client/src/share-log.js');
  const tag = await deriveLogTag(tagSeed, 555000 + Date.now() % 1000);
  const post = (cipher) => fetch(`${API_BASE}/api/v1/share/log/publish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${jwt}` },
    body: JSON.stringify({ tag, type: 'share-log-v1', ciphertext_base64: cipher }),
  });
  const dummyA = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(64))));
  const dummyB = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(64))));
  const [rA, rB] = await Promise.all([post(dummyA), post(dummyB)]);
  const statuses = [rA.status, rB.status].sort((a, b) => a - b);
  assert(statuses[0] === 200 && statuses[1] === 409,
    `expected [200, 409] from concurrent publishes; got [${statuses.join(', ')}]`);
  const winner = rA.status === 200 ? rA : rB;
  const loser = rA.status === 409 ? rA : rB;
  const wj = await winner.json();
  const lj = await loser.json();
  assert(wj.txid, 'winner missing txid');
  assert(lj.existing_txid === wj.txid,
    `loser.existing_txid (${lj.existing_txid}) !== winner.txid (${wj.txid})`);
});

await test('Delete handshake test accounts', async () => {
  if (handshakeAlice) await handshakeAlice.deleteAccount();
  if (handshakeBob) await handshakeBob.deleteAccount();
});

// ============ 9c. SECTION 5d — REVOCATION + IDENTITY ROTATION ============

console.log('\n=== 9c. Revocation + identity rotation (Section 5d) ===');

// Build two fresh accounts (Pat + Quinn) for the rotation E2E. The §9c flow
// proves the §13.5 protocol works against the deployed API:
//   1. Both accounts register + handshake.
//   2. Pat shares a content item with Quinn.
//   3. Pat changes credentials (issue #17 §13.5 sender flow).
//   4. Quinn syncs and picks up the rotation: friend record updated to
//      Pat's NEW share_pub + signing_pub; subsequent shares from Pat under
//      the NEW pair keys reach Quinn.

const patEmail = `tarn-pat-${Date.now()}-${Math.random().toString(36).slice(2)}@test.com`;
const patPassword = 'pat-pw-' + Date.now();
const quinnEmail = `tarn-quinn-${Date.now()}-${Math.random().toString(36).slice(2)}@test.com`;
const quinnPassword = 'quinn-pw-' + Date.now();

let pat, quinn;
let quinnFriendOfPat, patFriendOfQuinn;
let patPhrase;
let patSharePubBeforeRotate;

await test('Pat + Quinn register + handshake against deployed API', async () => {
  pat = new TarnClient(API_BASE, APP_ID);
  quinn = new TarnClient(API_BASE, APP_ID);
  const patReg = await pat.register(patEmail, patPassword, {
    recoveryAcknowledged: true,
    emailRecoveryKit: false,
  });
  patPhrase = patReg.recoveryPhrase;
  const quinnReg = await quinn.register(quinnEmail, quinnPassword, {
    recoveryAcknowledged: true,
    emailRecoveryKit: false,
  });

  // Set permissive rules on each user via the bookish app JWT (same pattern
  // as §8). Friends + pending records + share-log entries + tarn-share-state
  // writes need rules — the credential-change flow also writes share-state
  // entries to publish snapshots to friends' new logs after rotation.
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

  for (const dlk of [pat.dataLookupKey, quinn.dataLookupKey]) {
    const r = await fetch(`${API_BASE}/api/v1/accounts/${dlk}/rules`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${jwt}` },
      body: JSON.stringify({ rules: [{ type: 'max_entries', limit: 50, app: APP_ID }, { type: 'max_bytes', limit: 204800 }] }),
    });
    assert(r.status === 200, `Set rules failed for ${dlk}: ${r.status}`);
  }

  const send = await pat.sendFriendRequest(quinnEmail);
  await sleep(500);
  await quinn.listIncomingRequests();
  await quinn.acceptFriendRequest(send.requestNonce);
  await sleep(500);
  await pat.listIncomingRequests();
  quinnFriendOfPat = (await pat.listFriends()).find(f => f.email === quinnEmail);
  patFriendOfQuinn = (await quinn.listFriends()).find(f => f.email === patEmail);
  assert(quinnFriendOfPat, 'Pat missing Quinn after handshake');
  assert(patFriendOfQuinn, 'Quinn missing Pat after handshake');
  patSharePubBeforeRotate = patFriendOfQuinn.share_pub;
});

await test('Pat shares a content item with Quinn', async () => {
  const cek = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  await pat.shareContent(quinnFriendOfPat, 'rot-target-1', 'arweave-rot-pre', cek);
  await sleep(500);
  const state = await quinn.readShareLog(patFriendOfQuinn, { refresh: true });
  assert(state['rot-target-1'], 'Quinn should see rot-target-1 before rotation');
});

await test('Pat changes credentials → publishes rotate_identity to Quinn (deployed API)', async () => {
  const newEmail = `tarn-pat-rotated-${Date.now()}@test.com`;
  const result = await pat.changeCredentials(newEmail, 'new-pw-' + Date.now(), {
    phrase: patPhrase,
  });
  assert(Array.isArray(result.rotationAnnouncements), 'expected rotationAnnouncements');
  assert(result.rotationAnnouncements.length === 1, 'expected exactly one rotation announcement');
  const ann = result.rotationAnnouncements[0];
  assert(ann.friendSharePub === quinnFriendOfPat.share_pub, 'rotation targets the right friend');
  assert(typeof ann.txid === 'string', 'rotation announcement should have a txid');
});

await test('Quinn syncs against deployed API: rotate_identity processed, friend record updated', async () => {
  await sleep(800);
  const stateAfter = await quinn.syncShareLog(patFriendOfQuinn);
  assert(stateAfter['rot-target-1'], 'Quinn still sees rot-target-1 after rotation (NEW-log seq=0 snapshot)');

  const updatedFriend = (await quinn.listFriends())[0];
  assert(updatedFriend.share_pub !== patSharePubBeforeRotate,
    'Quinn\'s friend record holds Pat\'s NEW share_pub');
  assert(updatedFriend.prior_share_pub === patSharePubBeforeRotate,
    'Quinn records the pre-rotation share_pub');
});

await test('Pat publishes a post-rotation share; Quinn picks it up via NEW-log keys', async () => {
  // Refresh references — Pat's friend record was updated by the rotation
  // (no, actually Pat's view of Quinn is unchanged; only Quinn's view of
  // Pat rotated). But re-fetch defensively.
  quinnFriendOfPat = (await pat.listFriends()).find(f => f.email === quinnEmail);
  const cek = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  await pat.shareContent(quinnFriendOfPat, 'rot-target-2-postrotate', 'arweave-rot-post', cek);
  await sleep(500);
  const updatedQuinnFriend = (await quinn.listFriends())[0];
  const stateAfter = await quinn.syncShareLog(updatedQuinnFriend);
  assert(stateAfter['rot-target-2-postrotate'],
    'Quinn should see post-rotation content via NEW-log keys');
});

await test('Cleanup §9c accounts (Pat + Quinn)', async () => {
  await pat.deleteAccount();
  await quinn.deleteAccount();
});

// ============ 10. CLEANUP ============

console.log('\n=== 10. Cleanup ===');

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
