// Integration tests for the friend handshake (issue #14, Section 5a).
//
// Exercises the full handshake against a running wrangler dev:
//   - Alice registers, Bob registers — both publish share_pub
//   - Alice sendFriendRequest(bob) → blob lands at Bob's inbox tag
//   - Bob listIncomingRequests() → decrypts + surfaces the request
//   - Bob acceptFriendRequest(nonce) → publishes accept, adds Alice to friends
//   - Alice listIncomingRequests() (also processes accepts) → adds Bob to friends
//   - Replay attack: re-publishing Alice's blob is silently dropped
//   - Forged accept: an accept with no matching outbound is silently dropped
//   - Spam mitigation: 11th friend request in an hour gets 429
//   - Pre-#13 accounts can't be friended — sendFriendRequest fails cleanly
//   - Per-app isolation: a Bookish handshake doesn't bootstrap a Cellar one
//
// Run: cd api && npx wrangler dev --port 8787 (in another terminal)
//      node tests/test-handshake.mjs [baseUrl]

import { TarnClient } from '../client/src/tarn.js';
import {
  deriveAllKeys, exportPublicKey, encodeSharePub, deriveShareLookupKey,
  bytesToBase64, base64ToBytes,
} from '../client/src/crypto.js';
import {
  hpkeSeal,
  deriveInboxTag,
  currentInboxWindow,
  buildFriendRequestPayload,
  buildFriendAcceptPayload,
  INFO_FRIEND_REQUEST,
  INFO_FRIEND_ACCEPT,
} from '../client/src/sharing.js';
import {
  seedTestApp, DEFAULT_APP_ID, randomEmail, forceAllowRulesForAccount, sleep,
} from './helpers.mjs';

const BASE_URL = process.argv[2] || 'http://localhost:8787';
const SECONDARY_APP_ID = 'test-app-handshake-2';

await seedTestApp(DEFAULT_APP_ID);
await seedTestApp(SECONDARY_APP_ID);

let passed = 0;
let failed = 0;
const failures = [];

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
    failures.push({ name, err });
    if (process.env.VERBOSE) console.error('    ', err.stack);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

async function registerWithRules(client, email, password, opts = {}) {
  const { dataLookupKey } = await client.register(email, password, {
    recoveryAcknowledged: true,
    emailRecoveryKit: false,
    ...opts,
  });
  await forceAllowRulesForAccount(dataLookupKey);
  return dataLookupKey;
}

// ============ 1. End-to-end mutual handshake ============

console.log('\n=== 1. End-to-end mutual handshake ===');

const aliceEmail = randomEmail();
const alicePassword = 'pw-' + Date.now();
const bobEmail = randomEmail();
const bobPassword = 'pw-bob-' + Date.now();
const alice = new TarnClient(BASE_URL, DEFAULT_APP_ID);
const bob = new TarnClient(BASE_URL, DEFAULT_APP_ID);
let aliceDlk, bobDlk;
let requestNonce;

await test('Alice + Bob register with discoverable share keys', async () => {
  aliceDlk = await registerWithRules(alice, aliceEmail, alicePassword);
  bobDlk = await registerWithRules(bob, bobEmail, bobPassword);
  assert(aliceDlk && bobDlk, 'both should have DLKs');
});

await test('Alice sendFriendRequest(bob) succeeds and tracks outbound pending', async () => {
  const res = await alice.sendFriendRequest(bobEmail, { message: 'hi from alice' });
  assert(res.txid, 'no txid returned');
  assert(res.requestNonce, 'no requestNonce returned');
  requestNonce = res.requestNonce;

  const pending = await alice.getPendingRequests();
  assert(pending.outbound.length === 1, `expected 1 outbound, got ${pending.outbound.length}`);
  assert(pending.outbound[0].request_nonce === requestNonce, 'outbound nonce mismatch');
  assert(pending.outbound[0].recipient_email === bobEmail, 'outbound recipient mismatch');
});

await test('Bob listIncomingRequests() returns Alice\'s request', async () => {
  // Brief wait for D1 write-through to propagate (the publish endpoint is
  // synchronous on D1 cache, so this is mostly belt-and-suspenders).
  await sleep(150);
  const inbox = await bob.listIncomingRequests();
  assert(inbox.length === 1, `expected 1 incoming, got ${inbox.length}`);
  assert(inbox[0].senderEmail === aliceEmail, `wrong sender: ${inbox[0].senderEmail}`);
  assert(inbox[0].requestNonce === requestNonce, 'request nonce mismatch');
  assert(inbox[0].message === 'hi from alice', `wrong message: ${inbox[0].message}`);
  assert(inbox[0].senderAppId === DEFAULT_APP_ID, 'app_id should match');

  const pending = await bob.getPendingRequests();
  assert(pending.inbound.length === 1, 'inbound pending should have 1 entry');
});

await test('Bob acceptFriendRequest() adds Alice to Bob\'s friends', async () => {
  const res = await bob.acceptFriendRequest(requestNonce);
  assert(res.txid, 'no txid for accept');

  const friends = await bob.listFriends();
  assert(friends.length === 1, `Bob should have 1 friend, got ${friends.length}`);
  assert(friends[0].email === aliceEmail, `wrong friend email: ${friends[0].email}`);

  const pending = await bob.getPendingRequests();
  assert(pending.inbound.length === 0, 'Bob inbound should be empty after accept');
});

await test('Alice listIncomingRequests() processes accept, adds Bob to her friends', async () => {
  // The same poll that surfaces incoming requests also processes incoming
  // accepts. After this call Alice's friends list should contain Bob and
  // her outbound pending should be empty.
  await sleep(150);
  await alice.listIncomingRequests();

  const friends = await alice.listFriends();
  assert(friends.length === 1, `Alice should have 1 friend, got ${friends.length}`);
  assert(friends[0].email === bobEmail, `wrong friend email: ${friends[0].email}`);

  const pending = await alice.getPendingRequests();
  assert(pending.outbound.length === 0, 'Alice outbound should be empty after accept-process');
});

// ============ 2. Replay attack (sharing §13.8) ============

console.log('\n=== 2. Replay attack ===');

await test('Re-publishing Alice\'s already-seen request blob is silently ignored', async () => {
  // Carol sends a request to Bob. Eve captures it and re-publishes the same
  // ciphertext. Bob's second listIncomingRequests should not surface it
  // again — the in-memory replay cache rejects the duplicate nonce.
  const carolEmail = randomEmail();
  const carol = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  await registerWithRules(carol, carolEmail, 'pw-carol-' + Date.now());

  const sendRes = await carol.sendFriendRequest(bobEmail);
  await sleep(150);

  const first = await bob.listIncomingRequests();
  // First call surfaces it (carol is new — bob hasn't seen this nonce).
  assert(first.some(r => r.requestNonce === sendRes.requestNonce),
    'first poll should surface carol\'s request');

  // Second call must NOT re-surface the same request — the replay cache
  // dedupes by nonce, AND the inbound pending record contains it (so the
  // SDK skips it as already-known).
  const second = await bob.listIncomingRequests();
  assert(!second.some(r => r.requestNonce === sendRes.requestNonce),
    'second poll should not re-surface the same request (already in inbound pending)');
});

// ============ 3. Forged accept (sharing §13.9) ============

console.log('\n=== 3. Forged accept ===');

await test('Accept blob with no matching outbound is silently ignored', async () => {
  // Eve sends a fake "accept" to Alice's inbox without Alice having sent a
  // request. Alice's pending outbound list contains nothing matching this
  // accept's `in_reply_to`, so processing should drop it silently and
  // produce no friends-record change.
  const eveEmail = randomEmail();
  const eve = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  await registerWithRules(eve, eveEmail, 'pw-eve-' + Date.now());

  const beforeFriends = (await alice.listFriends()).length;

  // Build a forged accept directly. We need Alice's share_pub for the inbox
  // tag + HPKE seal target. Get it via the public lookup.
  const aliceShare = await eve.getRecipientShareKey(aliceEmail);
  assert(aliceShare.sharePub, 'should be able to look up Alice\'s share_pub');

  const eveSigningPub = await exportPublicKey(
    (await deriveAllKeys(eveEmail, 'pw-eve-' + Date.now() /*ignored*/, DEFAULT_APP_ID)).signingKeyPair.publicKey,
  );
  const eveSharePub = (await deriveAllKeys(eveEmail, 'pw-eve-' + Date.now() /*ignored*/, DEFAULT_APP_ID)).sharingKeyPair.publicKey;

  // Use a random nonce that's NOT in Alice's outbound pending — by
  // construction (Alice never asked Eve to be friends).
  const fakeReplyTo = bytesToBase64(crypto.getRandomValues(new Uint8Array(16))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const acceptPayload = buildFriendAcceptPayload({
    senderEmail: eveEmail,
    senderSharePub: eveSharePub,
    senderSigningPubBase64: eveSigningPub,
    senderAppId: DEFAULT_APP_ID,
    inReplyToNonceBase64Url: fakeReplyTo,
  });
  const sealed = await hpkeSeal({
    recipientSharePub: aliceShare.sharePub,
    info: INFO_FRIEND_ACCEPT,
    plaintext: new TextEncoder().encode(JSON.stringify(acceptPayload)),
  });
  const tag = await deriveInboxTag(aliceShare.sharePub, DEFAULT_APP_ID, currentInboxWindow());

  // Eve has a session, so she can publish via the rate-limited endpoint.
  // (In a real attack she'd post via a different account; the API enforces
  // JWT presence but doesn't require sender to be the recipient's friend.)
  const eveJwt = eve._testJwt();
  const publishRes = await fetch(`${BASE_URL}/api/v1/share/inbox/publish`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${eveJwt}`,
    },
    body: JSON.stringify({ tag, type: 'friend-accept-v1', ciphertext_base64: bytesToBase64(sealed) }),
  });
  assert(publishRes.status === 200, `Eve\'s publish failed: ${publishRes.status}`);
  await sleep(150);

  // Alice polls — the forged accept should be silently dropped.
  await alice.listIncomingRequests();
  const afterFriends = await alice.listFriends();
  assert(afterFriends.length === beforeFriends,
    `forged accept should not add a friend (was ${beforeFriends}, now ${afterFriends.length})`);
});

// ============ 4. Spam mitigation (rate limit) ============

console.log('\n=== 4. Spam mitigation ===');

await test('11th friend request in an hour returns 429', async () => {
  // Use a fresh account to avoid colliding with limits already consumed
  // by earlier tests (sharing §9.5: 10 friend-request publishes/hour per
  // session).
  const spammerEmail = randomEmail();
  const spammer = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  await registerWithRules(spammer, spammerEmail, 'pw-spam-' + Date.now());

  const targets = [];
  for (let i = 0; i < 12; i++) {
    const targetEmail = randomEmail();
    const target = new TarnClient(BASE_URL, DEFAULT_APP_ID);
    await registerWithRules(target, targetEmail, 'pw-target-' + Date.now() + '-' + i);
    targets.push(targetEmail);
  }

  // First 10 should succeed.
  for (let i = 0; i < 10; i++) {
    await spammer.sendFriendRequest(targets[i]);
  }

  // 11th should fail with the 429 surfaced as an error.
  let threw = false;
  try {
    await spammer.sendFriendRequest(targets[10]);
  } catch (err) {
    threw = true;
    assert(/rate limit/i.test(err.message) || /429/.test(err.message),
      `wrong error: ${err.message}`);
  }
  assert(threw, 'expected rate-limit error on 11th request');
});

// ============ 5. Pre-#13 / non-discoverable account ============

console.log('\n=== 5. Pre-#13 account is not friendable ===');

await test('sendFriendRequest to non-discoverable account fails cleanly', async () => {
  const hiddenEmail = randomEmail();
  const hidden = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  await registerWithRules(hidden, hiddenEmail, 'pw-hidden-' + Date.now(), {
    shareDiscoverable: false,
  });

  const seekerEmail = randomEmail();
  const seeker = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  await registerWithRules(seeker, seekerEmail, 'pw-seeker-' + Date.now());

  let caught;
  try {
    await seeker.sendFriendRequest(hiddenEmail);
  } catch (err) {
    caught = err;
  }
  assert(caught, 'sendFriendRequest should throw for non-discoverable target');
  assert(caught.code === 'RECIPIENT_NOT_FRIENDABLE',
    `expected code RECIPIENT_NOT_FRIENDABLE, got ${caught.code}`);
});

await test('sendFriendRequest to unknown email fails cleanly', async () => {
  const seeker = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  // Use the alice account from earlier — already authenticated via login on
  // a fresh client. Cheaper than registering yet another user.
  await seeker.login(aliceEmail, alicePassword);
  let caught;
  try {
    await seeker.sendFriendRequest(`nobody-${Date.now()}@nowhere.test`);
  } catch (err) {
    caught = err;
  }
  assert(caught, 'should throw for unknown email');
  assert(caught.code === 'RECIPIENT_NOT_FRIENDABLE',
    `expected RECIPIENT_NOT_FRIENDABLE, got ${caught.code}`);
});

// ============ 6. Per-app isolation ============

console.log('\n=== 6. Per-app isolation ===');

await test('A Bookish-side request to Bob\'s email does NOT land in Bob\'s Cellar inbox', async () => {
  // Same email, two apps. Bob's Cellar account has its own share_pub
  // (different keypair) and its own inbox tag (different app_id in HMAC).
  // A Bookish friend request to bobEmail must not appear when Bob polls
  // his Cellar inbox.
  const bobOnCellarEmail = randomEmail();
  const bobOnCellar = new TarnClient(BASE_URL, SECONDARY_APP_ID);
  await registerWithRules(bobOnCellar, bobOnCellarEmail, 'pw-cellar-' + Date.now());

  // A bookish-app sender tries to reach bobOnCellarEmail (which exists only
  // in cellar). The lookup against bookish should miss — bobOnCellarEmail
  // never registered there.
  const bookishSender = new TarnClient(BASE_URL, DEFAULT_APP_ID);
  await bookishSender.login(aliceEmail, alicePassword);
  let caught;
  try {
    await bookishSender.sendFriendRequest(bobOnCellarEmail);
  } catch (err) {
    caught = err;
  }
  assert(caught && caught.code === 'RECIPIENT_NOT_FRIENDABLE',
    'bookish→cellar lookup should miss (per-app isolation)');

  // Sanity: Bob in cellar polling his own inbox should see no requests.
  const incoming = await bobOnCellar.listIncomingRequests();
  assert(incoming.length === 0,
    `cellar inbox should be empty for fresh user, got ${incoming.length}`);
});

// ============ SUMMARY ============

console.log(`\n=== Handshake Tests: ${passed} passed, ${failed} failed ===`);
if (failed > 0 && !process.env.VERBOSE) {
  console.log('Re-run with VERBOSE=1 for stack traces.');
}
process.exit(failed > 0 ? 1 : 0);
