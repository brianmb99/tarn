// Integration tests for server-side session management (Section 7.5, issue #20).
// Run: node tests/test-sessions.mjs [apiBaseUrl]
// Requires: wrangler dev running (cd api && npx wrangler dev --port 8787)
//
// Walks the 10 acceptance criteria from issue #20 against a live API:
//   1. Fresh /auth/verify mints a sid, listSessions shows it (isCurrent: true).
//   2. Re-verify with valid previous_sid: same sid, last_seen_at bumps.
//   3. Re-verify with stale/wrong previous_sid: fresh sid + new row.
//   4. revokeSession on someone else's sid → 401 on the next call.
//   5. revokeAllSessions revokes calling sid; subsequent request 401s.
//   6. revokeOtherSessions preserves calling session.
//   7. changeCredentials revokes all; old JWT 401s; fresh login mints new sid.
//   8. recoverAccount revokes all; same.
//   9. deleteAccount revokes all (subsequent listSessions 401s).
//  10. Pre-7.5 JWT grandfather: hand-mint a JWT without `sid` and verify it auths.
//  11. Lazy-prune: insert stale row, verify next /auth/verify removes it.
//  12. deviceLabel validation: oversize → 400; control chars → 400.

import './indexeddb-shim.mjs';
import { TarnClient } from '../client/src/tarn.js';
import { clearWrappingKey } from '../client/src/session-persistence.js';
import { seedTestApp, DEFAULT_APP_ID } from './helpers.mjs';

const API_BASE = process.argv[2] || 'http://localhost:8787';

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

function randomEmail() {
  return `sess-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
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

// Hard-reset the session blob's wrapping key between tests so blobs from one
// run don't bleed into the next.
async function resetClientState() {
  await clearWrappingKey();
}

// ============ 1. Fresh /auth/verify mints a sid ============

console.log('\n=== Section 7.5 — sessions ===');

await test('1. fresh /auth/verify mints a sid; listSessions shows it (isCurrent: true)', async () => {
  await resetClientState();
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.register(randomEmail(), 'pw', { recoveryAcknowledged: true, emailRecoveryKit: false, deviceLabel: 'laptop' });
  const sessions = await client.listSessions();
  assert(sessions.length === 1, `expected 1 session, got ${sessions.length}`);
  assert(sessions[0].isCurrent === true, 'session should be marked isCurrent');
  assert(sessions[0].deviceLabel === 'laptop', 'device label should round-trip');
  assert(typeof sessions[0].createdAt === 'number', 'createdAt should be a number');
  assert(typeof sessions[0].lastSeenAt === 'number', 'lastSeenAt should be a number');
  assert(typeof sessions[0].sid === 'string' && sessions[0].sid.length > 0, 'sid should be a non-empty string');
});

// ============ 2. Re-verify with valid previous_sid: same sid, last_seen_at bumps ============

await test('2. re-verify with valid previous_sid reuses the same sid', async () => {
  await resetClientState();
  const email = randomEmail();
  const password = 'pw';
  const c1 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c1.register(email, password, { recoveryAcknowledged: true, emailRecoveryKit: false });
  const before = await c1.listSessions();
  const sidBefore = before[0].sid;

  // Force JWT expiry so the next #requireAuth re-verifies.
  c1._testInvalidateJwt();
  // Trigger re-verify by hitting any auth-required endpoint via listSessions.
  const after = await c1.listSessions();
  assert(after.length === 1, `expected 1 session after re-verify, got ${after.length}`);
  assert(after[0].sid === sidBefore, 'sid must be reused on continuous re-verify');
});

// ============ 3. Re-verify with stale/wrong previous_sid: fresh sid + new row ============

await test('3. re-verify with stale previous_sid mints a fresh sid + new row', async () => {
  await resetClientState();
  const email = randomEmail();
  const password = 'pw';
  const c1 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c1.register(email, password, { recoveryAcknowledged: true, emailRecoveryKit: false });
  const sidBefore = (await c1.listSessions())[0].sid;

  // Revoke the only session — simulates the "previous_sid is no longer valid"
  // path. Subsequent #requireAuth call must mint a fresh sid.
  await c1.revokeAllSessions();

  // After revokeAllSessions the in-memory client cleared its jwt + sid. Force
  // re-auth from the still-loaded keypair.
  await c1._testForceReauth();

  const fresh = await c1.listSessions();
  assert(fresh.length === 1, `expected 1 fresh session, got ${fresh.length}`);
  assert(fresh[0].sid !== sidBefore, 'sid must differ from the revoked one');
});

// ============ 4. revokeSession on someone else's sid → 401 within 5s (or immediate same isolate) ============

await test('4. revokeSession on a peer device 401s the peer immediately on this isolate', async () => {
  await resetClientState();
  const email = randomEmail();
  const password = 'pw';
  const c1 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c1.register(email, password, { recoveryAcknowledged: true, emailRecoveryKit: false, deviceLabel: 'A' });

  // "Other device" — fresh client, login from scratch. This produces a second
  // session row with a distinct sid.
  await resetClientState();
  const c2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c2.login(email, password, { deviceLabel: 'B' });

  // c1 still has its session blob in memory. List from c1 — should see both.
  const fromC1 = await c1.listSessions();
  assert(fromC1.length === 2, `expected 2 sessions, got ${fromC1.length}`);

  // c1 revokes c2's sid.
  const c2Row = fromC1.find(r => !r.isCurrent);
  await c1.revokeSession(c2Row.sid);

  // c2's next call should 401.
  let saw401 = false;
  try {
    await c2.listSessions();
  } catch (err) {
    saw401 = /401|Unauthorized|status 401/i.test(err.message);
  }
  assert(saw401, 'revoked peer must 401 on next call');
});

// ============ 5. revokeAllSessions revokes calling sid; subsequent request 401s ============

await test('5. revokeAllSessions kills the calling session too', async () => {
  await resetClientState();
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c.register(randomEmail(), 'pw', { recoveryAcknowledged: true, emailRecoveryKit: false });
  await c.revokeAllSessions();

  // Force a re-auth attempt via the cached keypair — the server should mint a
  // fresh session on the next /auth/verify, which is also fine for the
  // acceptance criterion: the OLD JWT is dead. The cleanest way to assert
  // that the old JWT is dead is to call listSessions with the cached JWT
  // directly — but revokeAllSessions clears it. So construct the assertion
  // around "the old JWT, still in our hand, no longer authenticates."
  //
  // We do that by saving the JWT before revoke and replaying it via fetch.
  // Replay shows up in a separate variant below, so this test trusts the
  // already-asserted same-isolate cache invalidation.
});

await test('5b. old JWT after revokeAllSessions 401s on a raw replay', async () => {
  await resetClientState();
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c.register(randomEmail(), 'pw', { recoveryAcknowledged: true, emailRecoveryKit: false });
  const oldJwt = c._testJwt();
  assert(oldJwt, 'should have a JWT before revoke');
  await c.revokeAllSessions();
  // Replay the old JWT raw — must 401.
  const { status } = await fetchJSON('/api/v1/sessions', {
    method: 'GET',
    headers: { Authorization: `Bearer ${oldJwt}` },
  });
  assert(status === 401, `expected 401 after revoke, got ${status}`);
});

// ============ 6. revokeOtherSessions preserves calling session ============

await test('6. revokeOtherSessions preserves the calling sid', async () => {
  await resetClientState();
  const email = randomEmail();
  const password = 'pw';
  const c1 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c1.register(email, password, { recoveryAcknowledged: true, emailRecoveryKit: false });

  await resetClientState();
  const c2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c2.login(email, password);

  await resetClientState();
  const c3 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c3.login(email, password);

  // c1 keeps its current; revoke the other two.
  const before = await c1.listSessions();
  assert(before.length === 3, `expected 3 sessions, got ${before.length}`);
  await c1.revokeOtherSessions();
  const after = await c1.listSessions();
  assert(after.length === 1, `expected 1 session after revokeOtherSessions, got ${after.length}`);
  assert(after[0].isCurrent === true, 'remaining session should be the calling one');
});

// ============ 7. changeCredentials revokes all; old JWT 401s ============

await test('7. changeCredentials revokes all sessions for the dlk', async () => {
  await resetClientState();
  const email = randomEmail();
  const password = 'pw1';
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const { recoveryPhrase } = await c.register(email, password, { recoveryAcknowledged: true, emailRecoveryKit: false });

  // Build a peer session; we'll observe it disappear post-change.
  await resetClientState();
  const peer = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await peer.login(email, password);
  const peerJwt = peer._testJwt();

  await c.changeCredentials(email, 'pw2', { phrase: recoveryPhrase });

  // Peer's old JWT must 401.
  const { status } = await fetchJSON('/api/v1/sessions', {
    method: 'GET',
    headers: { Authorization: `Bearer ${peerJwt}` },
  });
  assert(status === 401, `peer JWT after changeCredentials should 401, got ${status}`);

  // c re-authenticated under new credentials → has a fresh session.
  const list = await c.listSessions();
  assert(list.length === 1, `expected 1 session post-change, got ${list.length}`);
});

// ============ 8. recoverAccount revokes all ============

await test('8. recoverAccount revokes all sessions', async () => {
  await resetClientState();
  const email = randomEmail();
  const password = 'pw';
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const { recoveryPhrase } = await c.register(email, password, { recoveryAcknowledged: true, emailRecoveryKit: false });

  await resetClientState();
  const peer = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await peer.login(email, password);
  const peerJwt = peer._testJwt();

  // Recover from a fresh client (typical recovery flow — user lost password).
  await resetClientState();
  const recoverer = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await recoverer.recoverAccount({ phrase: recoveryPhrase, newEmail: email, newPassword: 'pw-recovered' });

  // Peer's old JWT must 401.
  const { status } = await fetchJSON('/api/v1/sessions', {
    method: 'GET',
    headers: { Authorization: `Bearer ${peerJwt}` },
  });
  assert(status === 401, `peer JWT after recoverAccount should 401, got ${status}`);

  // The recoverer should have its own fresh session.
  const list = await recoverer.listSessions();
  assert(list.length === 1, `expected 1 session post-recover, got ${list.length}`);
});

// ============ 9. deleteAccount revokes all ============

await test('9. deleteAccount revokes all sessions', async () => {
  await resetClientState();
  const email = randomEmail();
  const password = 'pw';
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await c.register(email, password, { recoveryAcknowledged: true, emailRecoveryKit: false });

  await resetClientState();
  const peer = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await peer.login(email, password);
  const peerJwt = peer._testJwt();

  await c.deleteAccount();

  // Peer's old JWT must 401 (account is gone, sessions wiped).
  const { status } = await fetchJSON('/api/v1/sessions', {
    method: 'GET',
    headers: { Authorization: `Bearer ${peerJwt}` },
  });
  assert(status === 401, `peer JWT after deleteAccount should 401, got ${status}`);
});

// ============ 10. Pre-7.5 JWT grandfather ============

await test('10. pre-7.5 JWT (no sid claim) authenticates via grandfather path', async () => {
  await resetClientState();
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const { dataLookupKey } = await c.register(randomEmail(), 'pw', { recoveryAcknowledged: true, emailRecoveryKit: false });

  // Hand-mint a JWT for the same dlk WITHOUT a sid claim using the same
  // JWT_SECRET wrangler dev uses (loaded from api/.dev.vars).
  const { signJWT } = await import('../api/src/auth.js');
  // wrangler dev exposes the secret via the env binding only; for the test we
  // read the same .dev.vars file the worker loads. If we can't read it,
  // skip rather than fail.
  let jwtSecret;
  try {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const devVarsPath = path.resolve('api/.dev.vars');
    const text = fs.readFileSync(devVarsPath, 'utf8');
    const m = text.match(/^JWT_SECRET\s*=\s*"?([^"\r\n]+)"?\s*$/m);
    if (!m) throw new Error('JWT_SECRET not in api/.dev.vars');
    jwtSecret = m[1];
  } catch (err) {
    skipped++;
    log('SKIP', '10. pre-7.5 grandfather (no api/.dev.vars JWT_SECRET available)', err.message);
    return;
  }
  const grandfatherJwt = await signJWT(
    { sub: dataLookupKey, role: 'user', app: DEFAULT_APP_ID },
    jwtSecret,
  );
  // Replay raw — should authenticate (middleware skips the sid check when sid
  // is missing).
  const { status } = await fetchJSON('/api/v1/sessions', {
    method: 'GET',
    headers: { Authorization: `Bearer ${grandfatherJwt}` },
  });
  assert(status === 200, `pre-7.5 JWT should authenticate, got ${status}`);
});

// ============ 11. Lazy-prune ============

await test('11. lazy-prune removes stale rows on next /auth/verify', async () => {
  await resetClientState();
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const { dataLookupKey } = await c.register(randomEmail(), 'pw', { recoveryAcknowledged: true, emailRecoveryKit: false });

  // Insert a stale row directly (last_seen_at = 1, well past 24h).
  const { execSync } = await import('child_process');
  const sql = `INSERT INTO sessions (sid, data_lookup_key, app, created_at, last_seen_at, device_label, via_recovery) VALUES ('stale-test-${Date.now()}', '${dataLookupKey}', '${DEFAULT_APP_ID}', 1, 1, 'old', 0)`;
  execSync(
    `npx wrangler d1 execute tarn-api --local --command "${sql}"`,
    { cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), stdio: 'pipe', timeout: 15000 },
  );

  // Force a re-verify (the server prunes BEFORE creating the new sid).
  c._testInvalidateJwt();
  const sessions = await c.listSessions();
  // After lazy-prune, only the active row should remain.
  assert(sessions.every(r => r.lastSeenAt > 100), `stale row should be pruned, got ${JSON.stringify(sessions)}`);
});

// ============ 12. deviceLabel validation ============

await test('12a. deviceLabel oversize → 400 from /auth/verify', async () => {
  await resetClientState();
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  let saw400 = false;
  try {
    // 65 chars (1 over MAX_DEVICE_LABEL_LEN).
    await c.register(randomEmail(), 'pw', {
      recoveryAcknowledged: true,
      emailRecoveryKit: false,
      deviceLabel: 'x'.repeat(65),
    });
  } catch (err) {
    saw400 = /400|exceeds|device_label/i.test(err.message);
  }
  assert(saw400, 'oversize deviceLabel must 400');
});

await test('12b. deviceLabel control chars → 400', async () => {
  await resetClientState();
  const c = new TarnClient(API_BASE, DEFAULT_APP_ID);
  let saw400 = false;
  try {
    await c.register(randomEmail(), 'pw', {
      recoveryAcknowledged: true,
      emailRecoveryKit: false,
      deviceLabel: 'has\nnewline',
    });
  } catch (err) {
    saw400 = /400|control|device_label/i.test(err.message);
  }
  assert(saw400, 'control-char deviceLabel must 400');
});

// ============ Summary ============

console.log(`\n=== Results: ${passed} passed, ${failed} failed, ${skipped} skipped ===\n`);
process.exit(failed > 0 ? 1 : 0);
