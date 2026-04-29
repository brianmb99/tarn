// Integration tests for sharing keypair publication + lookup (issue #13).
//
// Covers:
//   - Register publishes share_pub + share_lookup_key + share_discoverable
//   - getRecipientShareKey returns the published share_pub
//   - Discoverable=false hides share_pub from the lookup endpoint
//   - changeCredentials republishes share_pub + share_lookup_key
//   - Per-app isolation through the live API (different app_id, different
//     share_pub for the same email+password)
//   - Backward compat: pre-#13 accounts (no share fields in register body)
//     show up as discoverable=false in the lookup endpoint
//
// Run: node tests/test-share.mjs [baseUrl]
// Requires: wrangler dev running with the 0009 migration applied.

import { TarnClient } from '../client/src/tarn.js';
import { deriveSharingKeyPair, deriveShareLookupKey, encodeSharePub, deriveAllKeys } from '../client/src/crypto.js';
import { seedTestApp, DEFAULT_APP_ID, randomEmail } from './helpers.mjs';

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

const aliceEmail = randomEmail();
const alicePassword = 'pw-' + Date.now();
let aliceClient;
let aliceExpectedSharePub;

await test('register() publishes share_pub by default', async () => {
  aliceClient = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  await aliceClient.register(aliceEmail, alicePassword, {
    recoveryAcknowledged: true,
    emailRecoveryKit: false,
  });
  // Re-derive offline to assert the published value matches what the SDK
  // computed locally.
  const keys = await deriveAllKeys(aliceEmail, alicePassword, DEFAULT_APP_ID);
  aliceExpectedSharePub = encodeSharePub(keys.sharingKeyPair.publicKey);
  assert(aliceExpectedSharePub.length === 43, `share_pub length ${aliceExpectedSharePub.length}`);
});

await test('share_lookup_key is derivable from email + app alone', async () => {
  const lk = await deriveShareLookupKey(aliceEmail, DEFAULT_APP_ID);
  assert(/^[a-f0-9]{64}$/.test(lk), `share_lookup_key shape: ${lk}`);
});

// ============ 2. getRecipientShareKey returns the published share_pub ============

console.log('\n=== 2. Lookup returns share_pub ===');

await test('getRecipientShareKey() returns Alice\'s share_pub by email', async () => {
  const bob = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  const { sharePubBase64Url, discoverable } = await bob.getRecipientShareKey(aliceEmail);
  assert(discoverable === true, `expected discoverable=true, got ${discoverable}`);
  assert(sharePubBase64Url === aliceExpectedSharePub,
    `share_pub mismatch:\n  got:  ${sharePubBase64Url}\n  want: ${aliceExpectedSharePub}`);
});

await test('getRecipientShareKey() returns sharePub as 32 raw bytes', async () => {
  const bob = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  const { sharePub } = await bob.getRecipientShareKey(aliceEmail);
  assert(sharePub instanceof Uint8Array, 'sharePub not a Uint8Array');
  assert(sharePub.length === 32, `sharePub length ${sharePub.length}`);
});

await test('getRecipientShareKey() for unknown email returns null + discoverable=false', async () => {
  const bob = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  const result = await bob.getRecipientShareKey(`unknown-${Date.now()}@nowhere.test`);
  assert(result.sharePub === null, `expected null, got ${result.sharePub}`);
  assert(result.sharePubBase64Url === null, `expected null base64url, got ${result.sharePubBase64Url}`);
  assert(result.discoverable === false, 'expected discoverable=false for unknown email');
});

// ============ 3. Discoverability gate ============

console.log('\n=== 3. Discoverability gate ===');

const carolEmail = randomEmail();
const carolPassword = 'pw-' + Date.now();

await test('register({ shareDiscoverable: false }) hides share_pub from lookup', async () => {
  const carol = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  await carol.register(carolEmail, carolPassword, {
    recoveryAcknowledged: true,
    emailRecoveryKit: false,
    shareDiscoverable: false,
  });

  const stranger = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  const { sharePub, sharePubBase64Url, discoverable } = await stranger.getRecipientShareKey(carolEmail);
  assert(sharePub === null, 'discoverable=false should hide share_pub');
  assert(sharePubBase64Url === null, 'discoverable=false should hide base64url too');
  assert(discoverable === false, 'discoverable flag should be false');
});

// ============ 4. Per-app isolation ============

console.log('\n=== 4. Per-app isolation ===');

await test('same email+password registered to a different app produces a different share_pub', async () => {
  // Use Alice's email but register against the SECONDARY_APP_ID.
  const altApp = new TarnClient(BASE_URL, SECONDARY_APP_ID);
  await altApp.register(aliceEmail, alicePassword, {
    recoveryAcknowledged: true,
    emailRecoveryKit: false,
  });

  // Look up via the secondary app's id.
  const lookupClient = new TarnClient(BASE_URL, SECONDARY_APP_ID);
  const { sharePubBase64Url } = await lookupClient.getRecipientShareKey(aliceEmail);
  assert(sharePubBase64Url, 'secondary-app lookup returned no share_pub');
  assert(sharePubBase64Url !== aliceExpectedSharePub,
    `per-app isolation broken: same share_pub across apps (${sharePubBase64Url})`);

  // And verify the primary-app lookup still returns the original — so the
  // secondary registration didn't overwrite anything.
  const primary = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  const primaryRes = await primary.getRecipientShareKey(aliceEmail);
  assert(primaryRes.sharePubBase64Url === aliceExpectedSharePub,
    'primary-app lookup changed unexpectedly after secondary registration');
});

await test('cross-app probe: share_lookup_key from app A does not match account in app B', async () => {
  // Bob registers in DEFAULT_APP_ID; we then derive his share_lookup_key
  // against SECONDARY_APP_ID and confirm the API returns null (the lookup
  // key embeds app_id in HKDF info, so it's not a valid index in the other
  // app).
  const bobEmail = randomEmail();
  const bobPassword = 'pw-' + Date.now();
  const bob = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  await bob.register(bobEmail, bobPassword, {
    recoveryAcknowledged: true,
    emailRecoveryKit: false,
  });

  const wrongAppLookup = new TarnClient(BASE_URL, SECONDARY_APP_ID);
  const { sharePub, discoverable } = await wrongAppLookup.getRecipientShareKey(bobEmail);
  assert(sharePub === null, 'cross-app lookup should not find Bob');
  assert(discoverable === false, 'cross-app lookup should be opaque');
});

// ============ 5. changeCredentials republishes share_pub ============

console.log('\n=== 5. changeCredentials republishes share_pub ===');

await test('changeCredentials() rotates share_pub (master_key change)', async () => {
  // Use a fresh account so we don't disturb Alice's other tests.
  const dEmail = randomEmail();
  const dPassword = 'pw-d-' + Date.now();
  const d = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  await d.register(dEmail, dPassword, { recoveryAcknowledged: true, emailRecoveryKit: false });

  const before = await new TarnClient(BASE_URL, DEFAULT_APP_ID).getRecipientShareKey(dEmail);
  assert(before.sharePubBase64Url, 'no initial share_pub');

  const newPassword = dPassword + '-rotated';
  await d.changeCredentials(dEmail, newPassword);

  // Same email => same share_lookup_key, so the lookup still finds the
  // account, but with a fresh share_pub (because master_key changed).
  const after = await new TarnClient(BASE_URL, DEFAULT_APP_ID).getRecipientShareKey(dEmail);
  assert(after.sharePubBase64Url, 'no share_pub after credential change');
  assert(after.sharePubBase64Url !== before.sharePubBase64Url,
    'share_pub should rotate when password changes');

  // Cross-check: re-derive the new share_pub locally and assert match.
  const newKeys = await deriveAllKeys(dEmail, newPassword, DEFAULT_APP_ID);
  const expectedNew = encodeSharePub(newKeys.sharingKeyPair.publicKey);
  assert(after.sharePubBase64Url === expectedNew,
    `share_pub mismatch after change:\n  got:  ${after.sharePubBase64Url}\n  want: ${expectedNew}`);
});

await test('changeCredentials() rotates share_lookup_key on email change', async () => {
  const eEmail = randomEmail();
  const ePassword = 'pw-e-' + Date.now();
  const e = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  await e.register(eEmail, ePassword, { recoveryAcknowledged: true, emailRecoveryKit: false });

  // Lookup at the OLD email should work.
  const before = await new TarnClient(BASE_URL, DEFAULT_APP_ID).getRecipientShareKey(eEmail);
  assert(before.sharePubBase64Url, 'no share_pub at original email');

  // Change email.
  const newEmail = randomEmail();
  await e.changeCredentials(newEmail, ePassword);

  // Lookup at the NEW email should now resolve.
  const newRes = await new TarnClient(BASE_URL, DEFAULT_APP_ID).getRecipientShareKey(newEmail);
  assert(newRes.sharePubBase64Url, 'no share_pub at new email after change');

  // Lookup at the OLD email should now miss (or, more precisely, be opaque
  // null from the API).
  const oldRes = await new TarnClient(BASE_URL, DEFAULT_APP_ID).getRecipientShareKey(eEmail);
  assert(oldRes.sharePubBase64Url === null,
    `lookup at old email should miss after rotation, got ${oldRes.sharePubBase64Url}`);
});

// ============ 6. Backward compat: pre-#13 accounts ============

console.log('\n=== 6. Backward compat ===');

await test('pre-#13 register (no share fields in body) succeeds and lookup returns null', async () => {
  // Hand-construct a register call that omits share_*, simulating an old
  // client that hasn't been updated.
  const fEmail = randomEmail();
  const fPassword = 'pw-f-' + Date.now();
  const keys = await deriveAllKeys(fEmail, fPassword, DEFAULT_APP_ID);
  const der = await crypto.subtle.exportKey('spki', keys.signingKeyPair.publicKey);
  const pubBase64 = btoa(String.fromCharCode(...new Uint8Array(der)));

  // We need a wrapped_data_key — use the v1 single-key envelope (the
  // simplest backward-compat path). The lookup is what we're testing, not
  // login, so any opaque envelope shape works.
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
      // no share_*, no recovery_*
    }),
  });
  assert(res.status === 201, `register without share fields failed: ${res.status} ${await res.text()}`);

  const stranger = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  const { sharePub, sharePubBase64Url, discoverable } = await stranger.getRecipientShareKey(fEmail);
  // No share_lookup_key was published, so this is indistinguishable from an
  // unknown email — the lookup returns null + discoverable=false.
  assert(sharePub === null, `pre-#13 account should look up to null, got ${sharePub}`);
  assert(sharePubBase64Url === null, 'sharePubBase64Url should be null');
  assert(discoverable === false, 'pre-#13 account should be opaque to lookups');
});

// ============ SUMMARY ============

console.log(`\n=== Share Tests: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
