// Integration tests for sharing keypair publication + lookup (issue #13).
//
// Covers:
//   - Register publishes share_pub + share_lookup_key + share_discoverable
//   - getRecipientShareKey returns the published share_pub
//   - Discoverable=false hides share_pub from the lookup endpoint
//   - changeCredentials republishes share_pub + share_lookup_key
//   - Per-app isolation through the live API (different app_id, different
//     share_pub for the same username+password)
//   - Backward compat: pre-#13 accounts (no share fields in register body)
//     show up as discoverable=false in the lookup endpoint
//
// Run: node tests/test-share.mjs [baseUrl]
// Requires: wrangler dev running with the 0009 migration applied.

import { TarnClient } from '../client/src/tarn.js';
import { deriveSharingKeyPair, deriveShareLookupKey, encodeSharePub, deriveAllKeys } from '../client/src/crypto.js';
import { seedTestApp, DEFAULT_APP_ID, randomUsername } from './helpers.mjs';

const BASE_URL = process.argv[2] || 'http://localhost:8787';
const SECONDARY_APP_ID = 'test-app-share2';

await seedTestApp(DEFAULT_APP_ID);
await seedTestApp(SECONDARY_APP_ID);

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

// ============ 1. Register publishes share fields ============

console.log('\n=== 1. Register publishes share fields ===');

const aliceUsername = randomUsername();
const alicePassword = 'pw-' + Date.now();
let aliceClient;
let aliceExpectedSharePub;

await test('register() publishes share_pub by default', async () => {
  aliceClient = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  await aliceClient.register(aliceUsername, alicePassword, {
    recoveryAcknowledged: true,
  });
  // tarn#73 — share_pub is a RANDOM envelope-carried identity, no longer
  // derivable from username+password. Capture the published value via the
  // server lookup, and assert it is NOT the legacy derived value (the
  // decoupling is the point of #73).
  const lookup = await new TarnClient(BASE_URL, DEFAULT_APP_ID).getRecipientShareKey(aliceUsername);
  aliceExpectedSharePub = lookup.sharePubBase64Url;
  assert(aliceExpectedSharePub && aliceExpectedSharePub.length === 43,
    `share_pub length ${aliceExpectedSharePub?.length}`);
  const legacyKeys = await deriveAllKeys(aliceUsername, alicePassword, DEFAULT_APP_ID);
  assert(aliceExpectedSharePub !== encodeSharePub(legacyKeys.sharingKeyPair.publicKey),
    'share_pub must be decoupled from the password-derived keypair (tarn#73)');
});

await test('share_lookup_key is derivable from username + app alone', async () => {
  const lk = await deriveShareLookupKey(aliceUsername, DEFAULT_APP_ID);
  assert(/^[a-f0-9]{64}$/.test(lk), `share_lookup_key shape: ${lk}`);
});

// ============ 2. getRecipientShareKey returns the published share_pub ============

console.log('\n=== 2. Lookup returns share_pub ===');

await test('getRecipientShareKey() returns Alice\'s share_pub by username', async () => {
  const bob = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  const { sharePubBase64Url, discoverable } = await bob.getRecipientShareKey(aliceUsername);
  assert(discoverable === true, `expected discoverable=true, got ${discoverable}`);
  assert(sharePubBase64Url === aliceExpectedSharePub,
    `share_pub mismatch:\n  got:  ${sharePubBase64Url}\n  want: ${aliceExpectedSharePub}`);
});

await test('getRecipientShareKey() returns sharePub as 32 raw bytes', async () => {
  const bob = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  const { sharePub } = await bob.getRecipientShareKey(aliceUsername);
  assert(sharePub instanceof Uint8Array, 'sharePub not a Uint8Array');
  assert(sharePub.length === 32, `sharePub length ${sharePub.length}`);
});

await test('getRecipientShareKey() for unknown username returns null + discoverable=false', async () => {
  const bob = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  const result = await bob.getRecipientShareKey(`unknown-${Date.now()}@nowhere.test`);
  assert(result.sharePub === null, `expected null, got ${result.sharePub}`);
  assert(result.sharePubBase64Url === null, `expected null base64url, got ${result.sharePubBase64Url}`);
  assert(result.discoverable === false, 'expected discoverable=false for unknown username');
});

// ============ 3. Discoverability gate ============

console.log('\n=== 3. Discoverability gate ===');

const carolUsername = randomUsername();
const carolPassword = 'pw-' + Date.now();

await test('register({ shareDiscoverable: false }) hides share_pub from lookup', async () => {
  const carol = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  await carol.register(carolUsername, carolPassword, {
    recoveryAcknowledged: true,
    shareDiscoverable: false,
  });

  const stranger = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  const { sharePub, sharePubBase64Url, discoverable } = await stranger.getRecipientShareKey(carolUsername);
  assert(sharePub === null, 'discoverable=false should hide share_pub');
  assert(sharePubBase64Url === null, 'discoverable=false should hide base64url too');
  assert(discoverable === false, 'discoverable flag should be false');
});

// ============ 4. Per-app isolation ============

console.log('\n=== 4. Per-app isolation ===');

await test('same username+password registered to a different app produces a different share_pub', async () => {
  // Use Alice's username but register against the SECONDARY_APP_ID.
  const altApp = new TarnClient(BASE_URL, SECONDARY_APP_ID);
  await altApp.register(aliceUsername, alicePassword, {
    recoveryAcknowledged: true,
  });

  // Look up via the secondary app's id.
  const lookupClient = new TarnClient(BASE_URL, SECONDARY_APP_ID);
  const { sharePubBase64Url } = await lookupClient.getRecipientShareKey(aliceUsername);
  assert(sharePubBase64Url, 'secondary-app lookup returned no share_pub');
  assert(sharePubBase64Url !== aliceExpectedSharePub,
    `per-app isolation broken: same share_pub across apps (${sharePubBase64Url})`);

  // And verify the primary-app lookup still returns the original — so the
  // secondary registration didn't overwrite anything.
  const primary = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  const primaryRes = await primary.getRecipientShareKey(aliceUsername);
  assert(primaryRes.sharePubBase64Url === aliceExpectedSharePub,
    'primary-app lookup changed unexpectedly after secondary registration');
});

await test('cross-app probe: share_lookup_key from app A does not match account in app B', async () => {
  // Bob registers in DEFAULT_APP_ID; we then derive his share_lookup_key
  // against SECONDARY_APP_ID and confirm the API returns null (the lookup
  // key embeds app_id in HKDF info, so it's not a valid index in the other
  // app).
  const bobUsername = randomUsername();
  const bobPassword = 'pw-' + Date.now();
  const bob = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  await bob.register(bobUsername, bobPassword, {
    recoveryAcknowledged: true,
  });

  const wrongAppLookup = new TarnClient(BASE_URL, SECONDARY_APP_ID);
  const { sharePub, discoverable } = await wrongAppLookup.getRecipientShareKey(bobUsername);
  assert(sharePub === null, 'cross-app lookup should not find Bob');
  assert(discoverable === false, 'cross-app lookup should be opaque');
});

// ============ 5. changeCredentials republishes share_pub ============

console.log('\n=== 5. changeCredentials republishes share_pub ===');

await test('changeCredentials() keeps share_pub STABLE on password change (tarn#73)', async () => {
  // Use a fresh account so we don't disturb Alice's other tests.
  const dUsername = randomUsername();
  const dPassword = 'pw-d-' + Date.now();
  const d = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  const dReg = await d.register(dUsername, dPassword, { recoveryAcknowledged: true });

  const before = await new TarnClient(BASE_URL, DEFAULT_APP_ID).getRecipientShareKey(dUsername);
  assert(before.sharePubBase64Url, 'no initial share_pub');

  const newPassword = dPassword + '-rotated';
  await d.changeCredentials(dUsername, newPassword, { phrase: dReg.accountKey });

  // tarn#73 — the sharing identity is envelope-carried: a password change
  // rewraps ACCESS, it does not change who you are to your friends. Same
  // username => same share_lookup_key, and now also the SAME share_pub.
  const after = await new TarnClient(BASE_URL, DEFAULT_APP_ID).getRecipientShareKey(dUsername);
  assert(after.sharePubBase64Url, 'no share_pub after credential change');
  assert(after.sharePubBase64Url === before.sharePubBase64Url,
    'share_pub must be STABLE across a password change (tarn#73)');
});

await test('changeCredentials() rotates share_lookup_key on username change', async () => {
  const eUsername = randomUsername();
  const ePassword = 'pw-e-' + Date.now();
  const e = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  const eReg = await e.register(eUsername, ePassword, { recoveryAcknowledged: true });

  // Lookup at the OLD username should work.
  const before = await new TarnClient(BASE_URL, DEFAULT_APP_ID).getRecipientShareKey(eUsername);
  assert(before.sharePubBase64Url, 'no share_pub at original username');

  // Change username.
  const newUsername = randomUsername();
  await e.changeCredentials(newUsername, ePassword, { phrase: eReg.accountKey });

  // Lookup at the NEW username should now resolve.
  const newRes = await new TarnClient(BASE_URL, DEFAULT_APP_ID).getRecipientShareKey(newUsername);
  assert(newRes.sharePubBase64Url, 'no share_pub at new username after change');

  // Lookup at the OLD username should now miss (or, more precisely, be opaque
  // null from the API).
  const oldRes = await new TarnClient(BASE_URL, DEFAULT_APP_ID).getRecipientShareKey(eUsername);
  assert(oldRes.sharePubBase64Url === null,
    `lookup at old username should miss after rotation, got ${oldRes.sharePubBase64Url}`);
});

// ============ 6. Backward compat: pre-#13 accounts ============

console.log('\n=== 6. Backward compat ===');

await test('register without share fields is rejected (#30 — share_lookup_key required)', async () => {
  // Pre-#30 this scenario produced a 201 with NULL share_lookup_key on the
  // accounts row. That NULL allowed duplicate (email, app) registrations
  // because the unique-check skipped NULLs. #30 closes the gap by requiring
  // both share_pub and share_lookup_key at the API boundary.
  const fUsername = randomUsername();
  const fPassword = 'pw-f-' + Date.now();
  const keys = await deriveAllKeys(fUsername, fPassword, DEFAULT_APP_ID);
  const der = await crypto.subtle.exportKey('spki', keys.signingKeyPair.publicKey);
  const pubBase64 = btoa(String.fromCharCode(...new Uint8Array(der)));

  const dummyDek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const dekRaw = await crypto.subtle.exportKey('raw', dummyDek);
  const dekKw = await crypto.subtle.importKey('raw', dekRaw, 'AES-KW', true, ['wrapKey']);
  const wrapped = await crypto.subtle.wrapKey('raw', dekKw, keys.credentialEncryptionKey.kwKey, 'AES-KW');
  const wrappedBase64 = btoa(String.fromCharCode(...new Uint8Array(wrapped)));

  const res = await fetch(`${BASE_URL}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      credential_lookup_key: keys.credentialLookupKey,
      public_key: pubBase64,
      wrapped_data_key: wrappedBase64,
      app: DEFAULT_APP_ID,
      // Deliberately no share_* — must now 400.
    }),
  });
  assert(res.status === 400, `register without share fields should now 400, got ${res.status}: ${await res.clone().text()}`);
  const body = await res.json();
  assert(/share_lookup_key is required/.test(body.error || ''),
    `expected "share_lookup_key is required" error, got: ${body.error}`);
});

// ============ SUMMARY ============

console.log(`\n=== Share Tests: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
