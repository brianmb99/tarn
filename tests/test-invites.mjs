// Integration tests for invite tokens (Section 8, issue #22).
// Run: node tests/test-invites.mjs [apiBaseUrl]
// Requires: wrangler dev running (cd api && npx wrangler dev --port 8787)
//
// Walks the 12 acceptance-criterion cases from issue #22 against a live API.

import './indexeddb-shim.mjs';
import { TarnClient } from '../client/src/tarn.js';
import { clearWrappingKey } from '../client/src/session-persistence.js';
import {
  seedTestApp,
  backdateInviteExpiresAt,
  DEFAULT_APP_ID,
  randomEmail,
  forceAllowRulesForAccount,
  sleep,
} from './helpers.mjs';

const API_BASE = process.argv[2] || 'http://localhost:8787';
const INVITE_APP_ID = 'invites-test-app';
const INVITE_URL_TEMPLATE = 'https://example.test/invite/{token_id}';

await seedTestApp(DEFAULT_APP_ID);
await seedTestApp(INVITE_APP_ID, { inviteUrlTemplate: INVITE_URL_TEMPLATE });

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

async function registerWithRules(client, email, password) {
  const { dataLookupKey } = await client.register(email, password, {
    recoveryAcknowledged: true,
    emailRecoveryKit: false,
  });
  await forceAllowRulesForAccount(dataLookupKey);
  return dataLookupKey;
}

async function resetState() {
  await clearWrappingKey();
}

// ============ 1. App invite-template GET (happy path + 404) ============

console.log('\n=== Section 8 — invite tokens ===');

await test('1. GET /api/v1/apps/:app/invite-template returns the seeded template', async () => {
  const res = await fetch(`${API_BASE}/api/v1/apps/${INVITE_APP_ID}/invite-template`);
  assert(res.status === 200, `expected 200, got ${res.status}`);
  const body = await res.json();
  assert(body.invite_url_template === INVITE_URL_TEMPLATE,
    `wrong template: ${body.invite_url_template}`);
});

await test('2. GET /api/v1/apps/:app/invite-template 404 for unregistered app', async () => {
  const res = await fetch(`${API_BASE}/api/v1/apps/no-such-app-${Date.now()}/invite-template`);
  assert(res.status === 404, `expected 404, got ${res.status}`);
});

// ============ 2. Happy path: createInviteToken → preview → redeem → auto-accept ============

await test('3. happy path: invite → preview → redeem → auto-accept (both connected)', async () => {
  await resetState();
  const inviter = new TarnClient(API_BASE, INVITE_APP_ID);
  const inviterEmail = randomEmail();
  await registerWithRules(inviter, inviterEmail, 'pw-' + Date.now());

  const created = await inviter.createInviteToken({ display_name: 'Maya', expiry_days: 7 });
  assert(typeof created.token_id === 'string', 'token_id must be string');
  assert(created.token_id.length === 43, `token_id must be 43 chars, got ${created.token_id.length}`);
  assert(created.invite_url.includes(created.token_id), 'invite_url must include token_id');
  assert(created.invite_url.includes('#'), 'invite_url must carry payload_key in fragment');
  const fragment = created.invite_url.split('#')[1];
  assert(fragment.length > 0, 'fragment must be non-empty');
  assert(typeof created.expires_at === 'number', 'expires_at must be a number');

  // Recipient registers AFTER the invite link was created — simulating the
  // "register and click link" flow.
  await resetState();
  const recipient = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(recipient, randomEmail(), 'pw-' + Date.now());

  // Preview — unauthenticated path. Use a fresh fetch to confirm.
  const previewRes = await fetch(`${API_BASE}/api/v1/invite/${created.token_id}`);
  assert(previewRes.status === 200, `preview status ${previewRes.status}`);
  const previewBody = await previewRes.json();
  assert(previewBody.app_id === INVITE_APP_ID, 'preview app_id mismatch');

  // Recipient client decrypts the preview via the SDK helper.
  const recipientPreview = await recipient.previewInviteToken(created.token_id, fragment);
  assert(recipientPreview != null, 'previewInviteToken should return non-null on active invite');
  assert(recipientPreview.inviter_display_name === 'Maya', 'display_name should round-trip');
  assert(typeof recipientPreview.inviter_share_pub_fingerprint === 'string', 'fingerprint must be present');
  assert(/^[0-9a-f:]+$/.test(recipientPreview.inviter_share_pub_fingerprint), 'fingerprint must be hex+colons');

  // Redeem.
  const redeemed = await recipient.redeemInviteToken(created.token_id, fragment);
  assert(typeof redeemed.requestNonce === 'string', 'redeem must return requestNonce');

  // Inviter polls. Auto-accept should kick in: the invite token matches an
  // entry in tarn-issued-invites-v1, so the request never surfaces to the user.
  await sleep(150);
  const surfaced = await inviter.listIncomingRequests();
  assert(!surfaced.some(s => s.requestNonce === redeemed.requestNonce),
    `auto-accept should remove the request from surfaced list (saw ${surfaced.length} entries)`);

  // Both sides see each other in connections.
  const inviterConnections = await inviter.listConnections();
  assert(inviterConnections.length === 1, `inviter should have 1 connection, got ${inviterConnections.length}`);
  assert(inviterConnections[0].label === 'Maya', `inviter label should seed from display_name, got ${inviterConnections[0].label}`);

  await sleep(150);
  await recipient.listIncomingRequests();
  const recipientConnections = await recipient.listConnections();
  assert(recipientConnections.length === 1, `recipient should have 1 connection, got ${recipientConnections.length}`);
  // Pre-existing entries default to label: null on the recipient side (they
  // didn't pass a label through redeemInviteToken's pipeline).
  assert(recipientConnections[0].label === null, `recipient label should be null by default, got ${recipientConnections[0].label}`);
});

// ============ 3. Expired invite ============

await test('4. expired invite returns 410 on redeem', async () => {
  await resetState();
  const inviter = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(inviter, randomEmail(), 'pw-' + Date.now());
  const invite = await inviter.createInviteToken({ display_name: 'X', expiry_days: 7 });

  // Backdate via direct DB mutation.
  await backdateInviteExpiresAt(invite.token_id, 1000);

  await resetState();
  const redeemer = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(redeemer, randomEmail(), 'pw-' + Date.now());

  const fragment = invite.invite_url.split('#')[1];
  let caught;
  try { await redeemer.redeemInviteToken(invite.token_id, fragment); }
  catch (e) { caught = e; }
  assert(caught, 'redeem of expired invite should throw');
  assert(caught.code === 'INVITE_EXPIRED', `expected INVITE_EXPIRED, got ${caught.code}`);
});

// ============ 4. Already-used: redeem twice ============

await test('5. redeeming an already-used invite returns 409', async () => {
  await resetState();
  const inviter = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(inviter, randomEmail(), 'pw-' + Date.now());
  const invite = await inviter.createInviteToken({ display_name: 'Y' });
  const fragment = invite.invite_url.split('#')[1];

  await resetState();
  const r1 = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(r1, randomEmail(), 'pw-' + Date.now());
  const first = await r1.redeemInviteToken(invite.token_id, fragment);
  assert(first.requestNonce, 'first redeem should succeed');

  await resetState();
  const r2 = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(r2, randomEmail(), 'pw-' + Date.now());
  let caught;
  try { await r2.redeemInviteToken(invite.token_id, fragment); }
  catch (e) { caught = e; }
  assert(caught, 'second redeem should throw');
  assert(caught.code === 'INVITE_ALREADY_USED', `expected INVITE_ALREADY_USED, got ${caught.code}`);
});

// ============ 5. Two-redeemer race (server-side atomicity) ============

await test('6. two concurrent redeems: exactly one wins', async () => {
  await resetState();
  const inviter = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(inviter, randomEmail(), 'pw-' + Date.now());
  const invite = await inviter.createInviteToken({ display_name: 'Race' });
  const fragment = invite.invite_url.split('#')[1];

  await resetState();
  const a = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(a, randomEmail(), 'pw-' + Date.now());
  await resetState();
  const b = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(b, randomEmail(), 'pw-' + Date.now());

  const [resA, resB] = await Promise.allSettled([
    a.redeemInviteToken(invite.token_id, fragment),
    b.redeemInviteToken(invite.token_id, fragment),
  ]);
  const wins = [resA, resB].filter(r => r.status === 'fulfilled');
  const losses = [resA, resB].filter(r => r.status === 'rejected');
  assert(wins.length === 1, `exactly one redeem should succeed, got ${wins.length}`);
  assert(losses.length === 1, `exactly one redeem should fail, got ${losses.length}`);
  assert(losses[0].reason?.code === 'INVITE_ALREADY_USED',
    `loser should see INVITE_ALREADY_USED, got ${losses[0].reason?.code}`);
});

// ============ 6. Inviter offline at redemption ============

await test('7. inviter offline at redemption: connection still forms when they poll', async () => {
  await resetState();
  const inviter = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(inviter, randomEmail(), 'pw-' + Date.now());
  const invite = await inviter.createInviteToken({ display_name: 'Offline' });
  const fragment = invite.invite_url.split('#')[1];

  // Recipient redeems while inviter is "offline" (i.e., not calling listIncomingRequests).
  await resetState();
  const recipient = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(recipient, randomEmail(), 'pw-' + Date.now());
  const redeemed = await recipient.redeemInviteToken(invite.token_id, fragment);

  // Inviter has zero connections at this point.
  const before = await inviter.listConnections();
  assert(before.length === 0, `inviter should have 0 connections before polling, got ${before.length}`);

  // Now inviter comes online — listIncomingRequests should auto-accept.
  await sleep(150);
  await inviter.listIncomingRequests();
  const after = await inviter.listConnections();
  assert(after.length === 1, `inviter should have 1 connection after polling, got ${after.length}`);
  assert(after[0].label === 'Offline', `label should seed from display_name, got ${after[0].label}`);

  // And the request must NOT be in the surfaced list on subsequent polls.
  const second = await inviter.listIncomingRequests();
  assert(!second.some(s => s.requestNonce === redeemed.requestNonce),
    'auto-accepted request must not re-surface');
});

// ============ 7. Recipient signs up after clicking link ============

await test('8. recipient signs up AFTER createInviteToken returns the URL', async () => {
  await resetState();
  const inviter = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(inviter, randomEmail(), 'pw-' + Date.now());
  const invite = await inviter.createInviteToken({ display_name: 'Late' });

  // Time passes (no-op) — recipient just now signs up.
  await resetState();
  const recipient = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(recipient, randomEmail(), 'pw-' + Date.now());

  const fragment = invite.invite_url.split('#')[1];
  const redeemed = await recipient.redeemInviteToken(invite.token_id, fragment);
  assert(redeemed.requestNonce, 'redeem must succeed for a recipient who signed up after the URL was built');
});

// ============ 8. listIssuedInvites + revokeIssuedInvite ============

await test('9. listIssuedInvites returns the entry; revokeIssuedInvite removes it; subsequent redeem 404', async () => {
  await resetState();
  const inviter = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(inviter, randomEmail(), 'pw-' + Date.now());
  const invite = await inviter.createInviteToken({ display_name: 'ToRevoke' });

  const issued = await inviter.listIssuedInvites();
  assert(issued.some(i => i.token_id === invite.token_id), 'createInviteToken should populate listIssuedInvites');

  const revoked = await inviter.revokeIssuedInvite(invite.token_id);
  assert(revoked.revoked === true, `revokeIssuedInvite should report server-side delete success, got ${revoked.revoked}`);

  const after = await inviter.listIssuedInvites();
  assert(!after.some(i => i.token_id === invite.token_id), 'revokeIssuedInvite must drop the local entry');

  await resetState();
  const r = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(r, randomEmail(), 'pw-' + Date.now());
  const fragment = invite.invite_url.split('#')[1];
  let caught;
  try { await r.redeemInviteToken(invite.token_id, fragment); }
  catch (e) { caught = e; }
  assert(caught, 'redeem of revoked invite should throw');
  assert(caught.code === 'INVITE_NOT_FOUND', `expected INVITE_NOT_FOUND, got ${caught.code}`);
});

// ============ 9. Connection.label flows through ============

await test('10. Connection.label flows through opts.label → listConnections → setConnectionLabel', async () => {
  await resetState();
  const alice = new TarnClient(API_BASE, INVITE_APP_ID);
  const aliceEmail = randomEmail();
  await registerWithRules(alice, aliceEmail, 'pw-' + Date.now());

  await resetState();
  const bob = new TarnClient(API_BASE, INVITE_APP_ID);
  const bobEmail = randomEmail();
  await registerWithRules(bob, bobEmail, 'pw-' + Date.now());

  const sendRes = await alice.sendConnectionRequest(bobEmail);
  await sleep(150);
  const inbox = await bob.listIncomingRequests();
  const r = inbox.find(x => x.requestNonce === sendRes.requestNonce);
  assert(r, 'Bob should see Alice’s request');

  await bob.acceptConnectionRequest(sendRes.requestNonce, { label: 'Friend Alice' });
  const bobConnections = await bob.listConnections();
  assert(bobConnections.length === 1, `Bob should have 1 connection, got ${bobConnections.length}`);
  assert(bobConnections[0].label === 'Friend Alice', `label should be persisted, got ${bobConnections[0].label}`);

  // Update via setConnectionLabel.
  const upd = await bob.setConnectionLabel(bobConnections[0], 'Best friend Alice');
  assert(upd.updated === true, 'setConnectionLabel should report updated: true');
  assert(upd.label === 'Best friend Alice', 'setConnectionLabel should normalize + return new label');

  const refreshed = await bob.listConnections();
  assert(refreshed[0].label === 'Best friend Alice', 'listConnections should return updated label');

  // Idempotent set with the same value → updated: false, no write.
  const noop = await bob.setConnectionLabel(refreshed[0], 'Best friend Alice');
  assert(noop.updated === false, 'setting the same label twice must report updated: false');
});

// ============ 11. payload_key never appears in HTTP bodies ============

await test('11. createInviteToken does not include the payload_key in any HTTP body', async () => {
  await resetState();
  const inviter = new TarnClient(API_BASE, INVITE_APP_ID);
  await registerWithRules(inviter, randomEmail(), 'pw-' + Date.now());

  const captured = [];
  const originalFetch = global.fetch;
  global.fetch = async (url, init) => {
    if (typeof init?.body === 'string') captured.push({ url: String(url), body: init.body });
    return originalFetch(url, init);
  };
  try {
    const res = await inviter.createInviteToken({ display_name: 'Quiet' });
    const fragment = res.invite_url.split('#')[1];
    // The fragment IS the payload_key (base64url). Assert it's in the URL but
    // not in any HTTP body that went over the wire.
    for (const c of captured) {
      assert(!c.body.includes(fragment), `outbound body to ${c.url} contained the payload_key`);
    }
  } finally {
    global.fetch = originalFetch;
  }
});

// ============ 12. App invite_url_template GET happy path + 404 (already covered above) ============

// (already tested as cases 1 and 2.)

// ============ Summary ============

console.log(`\n${passed}/${passed + failed} passed${failed ? ` — ${failed} failed` : ''}\n`);
if (failed) {
  process.exit(1);
}
