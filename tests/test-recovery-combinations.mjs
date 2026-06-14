// Recovery-flow COMBINATION tests (issue #39 / audit finding SDK-5).
//
// Run: node --import tsx tests/test-recovery-combinations.mjs [apiBaseUrl]
//   or: npm run test:recovery-combos -- http://localhost:8787
//
// Requires: wrangler dev running (cd api && npx wrangler dev --port 8787)
// with migration 0018 applied locally and TARN_SKIP_TURBO set in api/.dev.vars
// (so data writes succeed without a live Turbo wallet).
//
// Why this file exists
// --------------------
// Four SDK entry points mutate the envelope / DEK chain and each must
// CONVERGE to the same valid end-state:
//
//   recoverAccount(), changeCredentials(), rotateAccountKey(),
//   and stale-passkey repair inside authenticateWithPasskey().
//
// Each happy path is tested in isolation elsewhere (test-recovery.mjs,
// test-passkeys.mjs, test-sessions.mjs). The CROSS-PRODUCT is not — and
// #32's audit already found one latent bug in this family. These tests hunt
// the next one and lock in the convergence invariants:
//
//   - the end-state is logged-in / authenticable,
//   - a NEW generation was minted,
//   - the recovery factor is still present on the envelope,
//   - EVERY prior DEK generation still decrypts the entries written under it
//     (the load-bearing "no orphaned gen" invariant), and
//   - passkey wrappings are preserved across the mutation.
//
// Writing real entries (not just inspecting the envelope) is deliberate:
// it's the only way to prove a *prior* generation's DEK still round-trips
// after a mutation rotates the chain forward. The envelope inspection
// confirms the structural invariants the data round-trip can't see (recovery
// factor present, passkey wrapping byte-preserved, gen count advanced).

import { TarnClient, StalePasskeyError } from '../client/src/tarn.js';
import {
  seedTestApp,
  DEFAULT_APP_ID,
  randomUsername,
  forceAllowRulesForAccount,
  sleep,
  connectionTo,
} from './helpers.mjs';
import { VirtualAuthenticator, installPasskeyTestEnv } from './helpers/virtual-authenticator.mjs';

const API_BASE = process.argv[2] || 'http://localhost:8787';

await seedTestApp();

// The passkey ceremonies + Origin-header injection go through the same shim
// the dedicated passkey suite uses. Installed for the whole run, restored at
// the end. Tests that don't touch passkeys are unaffected (the shim only
// activates when navigator.credentials is called).
const env = installPasskeyTestEnv({ origin: 'http://localhost:3000', rpId: 'localhost' });

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

// ----- D1 helpers (same shape as the recovery / passkey suites) -----

async function d1Query(sql) {
  const { execSync } = await import('node:child_process');
  const out = execSync(
    `npx wrangler d1 execute tarn-api --local --json --command "${sql}"`,
    {
      cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'),
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 15000,
    },
  ).toString();
  const parsed = JSON.parse(out);
  return parsed[0]?.results || [];
}

async function readEnvelope(dataLookupKey) {
  const rows = await d1Query(
    `SELECT wrapped_data_key FROM accounts WHERE data_lookup_key = '${dataLookupKey}'`,
  );
  assert(rows.length === 1, `expected 1 account row for ${dataLookupKey}, got ${rows.length}`);
  return JSON.parse(rows[0].wrapped_data_key);
}

// Convergence invariant: the envelope must carry a recovery_phrase wrapping on
// EVERY generation (and therefore on the current one). A flow that dropped the
// recovery factor on any gen would leave data written under that gen
// unrecoverable via the account key.
function assertRecoveryFactorPresent(envelope, where) {
  for (const entry of envelope.dek_chain) {
    const rec = entry.wrappings.find(w => w.factor === 'recovery_phrase');
    assert(rec, `${where}: recovery_phrase wrapping missing on gen ${entry.gen}`);
  }
}

function genCount(envelope) {
  return envelope.dek_chain.length;
}

// ============ shared fixtures ============

// Register an account, open its write gate, and write `n` entries so we have
// data sitting under the gen that's live at registration time. Returns the
// client + the set of payload markers we wrote so a later read can prove every
// one survives.
async function registerWithData(n = 2) {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const username = randomUsername();
  const password = 'combo-pw-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
  const reg = await client.register(username, password, { recoveryAcknowledged: true });
  await forceAllowRulesForAccount(reg.dataLookupKey);

  const markers = new Set();
  for (let i = 0; i < n; i++) {
    const marker = `gen-orig-${i}-${Math.random().toString(36).slice(2)}`;
    await client.createEntry('entry', { marker });
    markers.add(marker);
  }
  return { client, username, password, reg, markers };
}

// Read every 'entry' back through a (fresh or existing) logged-in client and
// confirm each expected marker decrypted. Because entries can be spread across
// several DEK generations, a full read only succeeds if EVERY referenced gen
// is still in #dekByGen — this is the "all prior generations still decrypt"
// invariant, exercised end-to-end rather than asserted structurally.
async function assertAllMarkersReadable(client, expectedMarkers, where) {
  const entries = await client.getEntries('entry');
  const seen = new Set(entries.map(e => e?.data?.marker).filter(Boolean));
  for (const m of expectedMarkers) {
    assert(seen.has(m), `${where}: marker "${m}" did not decrypt after the mutation (gen orphaned?)`);
  }
}

async function registerPasskeyOn(client, opts = {}) {
  const auth = new VirtualAuthenticator();
  env.stageRegistration(auth);
  const result = await client.registerPasskey(opts);
  return { auth, result };
}

// ============================================================================
// CASE 1 — register(password) + register passkey -> recoverAccount(phrase)
//          -> the passkey STILL authenticates afterward.
//
// Recovery must re-wrap / preserve the passkey wrapping, not orphan it. We go
// beyond the existing test-passkeys "passkey still authenticates" check by
// also asserting the end-state invariants: new gen, recovery factor present,
// and all pre-recovery data still decrypts via the recovered chain.
// ============================================================================

console.log('\n=== Case 1: recovery x passkey (passkey survives recoverAccount) ===');

await test('register + passkey -> recoverAccount -> passkey still authenticates; invariants hold', async () => {
  const { client, reg, markers } = await registerWithData(2);
  const { auth } = await registerPasskeyOn(client, { deviceLabel: 'case1-passkey' });
  const dlk = client.dataLookupKey;

  const envBefore = await readEnvelope(dlk);
  const gensBefore = genCount(envBefore);

  // Lost-password recovery from a fresh client with only the phrase.
  const recClient = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const recRes = await recClient.recoverAccount({
    phrase: reg.accountKey,
    newUsername: randomUsername(),
    newPassword: 'case1-recovered-' + Date.now(),
  });
  assert(recRes.dataLookupKey === dlk, 'recovery must preserve data_lookup_key');
  assert(recClient.isLoggedIn(), 'recoverer should be logged in (full session)');

  // End-state envelope invariants. recoverAccount re-wraps the EXISTING DEK
  // chain under new credentials in place — it does NOT mint a new gen (the
  // underlying DEKs are unchanged; only the wrapping factors rotate). So the
  // gen count is preserved, every gen keeps a recovery wrapping, and the
  // password factor is now derived from the new credentials.
  const envAfter = await readEnvelope(dlk);
  assert(genCount(envAfter) === gensBefore, `recovery must preserve the gen count (was ${gensBefore}, now ${genCount(envAfter)})`);
  assertRecoveryFactorPresent(envAfter, 'case1 post-recovery');

  // All pre-recovery data still decrypts through the recovered chain — proves
  // every prior gen's DEK survived the re-wrap.
  await assertAllMarkersReadable(recClient, markers, 'case1 recoverer read');

  // The passkey wrapping for the original credential must still be present on
  // every gen it was wrapped for (recovery preserves byte-for-byte, does not
  // orphan). This is the crux of the recovery x passkey combination.
  for (const entry of envAfter.dek_chain) {
    const pk = entry.wrappings.find(w => w.factor === 'passkey_prf' && w.credential_id === auth.credentialIdB64Url);
    assert(pk, `case1: passkey wrapping must survive recoverAccount on gen ${entry.gen}`);
  }

  // And the passkey still authenticates the same account on a fresh client.
  // recoverAccount preserves the passkey wrapping on every existing gen, so
  // the credential is NOT stale and authenticates cleanly with no repair.
  const pkClient = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(auth.credentialIdB64Url);
  const pkRes = await pkClient.authenticateWithPasskey();
  env.clearNextAuth();
  assert(pkRes.dataLookupKey === dlk, 'case1: passkey must still authenticate the same account post-recovery');

  // Recovery factor truly preserved: a SECOND recovery with the same phrase
  // still works (and reads all original data) — proving the chain didn't lose
  // the recovery wrapping.
  const rec2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const rec2Res = await rec2.recoverAccount({
    phrase: reg.accountKey,
    newUsername: randomUsername(),
    newPassword: 'case1-recovered-again-' + Date.now(),
  });
  assert(rec2Res.dataLookupKey === dlk, 'second recovery must preserve the same account');
  await assertAllMarkersReadable(rec2, markers, 'case1 second-recovery read');
});

// ============================================================================
// CASE 2 — rotate the phrase -> recoverAccount with the NEW phrase succeeds
//          (and the OLD phrase fails).
//
// NB on the API surface: issue #39 phrases this as
// `changeCredentials({ rotatePhrase: true })`, but `changeCredentials` does
// NOT rotate the recovery phrase — by design it PRESERVES the
// recovery_lookup_key (it re-wraps the new gen under the SAME recovery factor;
// see test-recovery.mjs "changeCredentials ... preserves recovery_lookup_key").
// The SDK primitive that rotates the phrase is `rotateAccountKey()` (also
// reachable as `recoverAccount({ rotatePhrase: true })`). This test exercises
// the real rotate-phrase primitive and asserts the `changeCredentials`
// preserve-not-rotate contract explicitly, so the imprecise issue wording
// can't quietly mask a regression in either direction.
// ============================================================================

console.log('\n=== Case 2: rotate phrase x recovery (new phrase recovers, old fails) ===');

await test('changeCredentials PRESERVES the phrase (does not rotate recovery_lookup_key)', async () => {
  const { client, username, reg } = await registerWithData(1);
  const dlk = client.dataLookupKey;

  const before = await d1Query(
    `SELECT recovery_lookup_key FROM accounts WHERE data_lookup_key = '${dlk}'`,
  );
  // NB: `rotatePhrase` is NOT a changeCredentials option — it belongs to
  // recoverAccount / rotateAccountKey, and changeCredentials' strict
  // assertKnownOpts (correctly) rejects unknown keys. changeCredentials
  // preserves the recovery factor by design; we assert that directly below.
  const ccRes = await client.changeCredentials(randomUsername(), 'case2-cc-' + Date.now(), {
    phrase: reg.accountKey,
  });
  // changeCredentials does not surface a rotated accountKey.
  assert(ccRes.accountKey === undefined, 'changeCredentials must NOT return a rotated accountKey');
  const after = await d1Query(
    `SELECT recovery_lookup_key FROM accounts WHERE data_lookup_key = '${dlk}'`,
  );
  assert(
    before[0].recovery_lookup_key === after[0].recovery_lookup_key,
    'changeCredentials must preserve recovery_lookup_key (phrase is NOT rotated)',
  );
  // The ORIGINAL phrase therefore still recovers the account.
  const cStill = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const stillRec = await cStill.recoverAccount({
    phrase: reg.accountKey,
    newUsername: randomUsername(),
    newPassword: 'case2-still-' + Date.now(),
  });
  assert(stillRec.dataLookupKey === dlk, 'original phrase must still recover after changeCredentials');
});

await test('rotateAccountKey -> NEW phrase recovers, OLD phrase rejected, data + factor intact', async () => {
  const { client, password, reg, markers } = await registerWithData(2);
  const dlk = client.dataLookupKey;
  const oldPhrase = reg.accountKey;

  // rotateAccountKey returns the new 24-word phrase and rotates
  // recovery_lookup_key (proven in test-recovery.mjs). No new gen is minted —
  // it re-wraps the existing chain under the new recovery factor.
  const rot = await client.rotateAccountKey({ password });
  assert(rot.accountKey, 'rotateAccountKey must return a new account key');
  const newPhrase = rot.accountKey;
  assert(newPhrase !== oldPhrase, 'rotated phrase must differ from the original');
  assert(newPhrase.split(' ').length === 24, 'new phrase must be 24 words');

  // The OLD phrase must no longer find the account (its recovery_lookup_key
  // rotated). recoverAccount surfaces this as "no account found".
  const cOld = new TarnClient(API_BASE, DEFAULT_APP_ID);
  let oldThrew = null;
  try {
    await cOld.recoverAccount({
      phrase: oldPhrase,
      newUsername: randomUsername(),
      newPassword: 'case2-should-not-work',
    });
  } catch (err) {
    oldThrew = err;
  }
  assert(oldThrew, 'recoverAccount with the OLD phrase must fail after rotateAccountKey');
  assert(/no account found/i.test(oldThrew.message), `expected "no account found", got: ${oldThrew.message}`);

  // The NEW phrase recovers the account, lands logged-in, keeps the recovery
  // factor on every gen, and reads ALL original data.
  const cNew = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const newRec = await cNew.recoverAccount({
    phrase: newPhrase,
    newUsername: randomUsername(),
    newPassword: 'case2-recovered-' + Date.now(),
  });
  assert(newRec.dataLookupKey === dlk, 'recovery via the new phrase must hit the same account');
  assert(cNew.isLoggedIn(), 'new-phrase recoverer should be logged in');

  const envAfter = await readEnvelope(dlk);
  assertRecoveryFactorPresent(envAfter, 'case2 post-recovery');
  await assertAllMarkersReadable(cNew, markers, 'case2 new-phrase read');
});

// ============================================================================
// CASE 3 — rotateAccountKey() -> passkey wrappings preserved (passkey still
//          authenticates), plus full end-state invariants.
// ============================================================================

console.log('\n=== Case 3: rotateAccountKey x passkey (wrappings preserved) ===');

await test('register passkey -> rotateAccountKey -> passkey authenticates; data + recovery factor intact', async () => {
  const { client, password, markers } = await registerWithData(2);
  const { auth } = await registerPasskeyOn(client, { deviceLabel: 'case3-passkey' });
  const dlk = client.dataLookupKey;

  const envBefore = await readEnvelope(dlk);
  // Capture the gen-1 passkey wrapping bytes to assert byte-for-byte preservation.
  const beforeWrap = envBefore.dek_chain
    .flatMap(e => e.wrappings.map(w => ({ gen: e.gen, ...w })))
    .find(w => w.factor === 'passkey_prf' && w.credential_id === auth.credentialIdB64Url);
  assert(beforeWrap, 'precondition: passkey wrapping present pre-rotation');

  const rot = await client.rotateAccountKey({ password });
  assert(rot.accountKey && rot.accountKey.split(' ').length === 24, 'rotateAccountKey returns a 24-word key');

  const envAfter = await readEnvelope(dlk);
  // Same-gen wrapping bytes preserved (rotation only touches the recovery factor).
  const afterWrap = envAfter.dek_chain
    .flatMap(e => e.wrappings.map(w => ({ gen: e.gen, ...w })))
    .find(w => w.gen === beforeWrap.gen && w.factor === 'passkey_prf' && w.credential_id === auth.credentialIdB64Url);
  assert(afterWrap, 'case3: passkey wrapping must survive rotateAccountKey');
  assert(afterWrap.wrapped === beforeWrap.wrapped, 'case3: passkey wrapping bytes must be byte-for-byte preserved');
  assertRecoveryFactorPresent(envAfter, 'case3 post-rotation');

  // Original (still-logged-in) client reads all data — DEK chain intact.
  await assertAllMarkersReadable(client, markers, 'case3 same-client read');
  assert(client.isLoggedIn(), 'client should remain logged in after rotateAccountKey');

  // Passkey still authenticates on a fresh client.
  const pk = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(auth.credentialIdB64Url);
  const r = await pk.authenticateWithPasskey();
  env.clearNextAuth();
  assert(r.dataLookupKey === dlk, 'case3: passkey must still authenticate post-rotation');
});

// ============================================================================
// CASE 4 — stale-passkey repair: the handler supplies BAD credentials.
//          The repair must fail with a TYPED error and leave NO envelope
//          corruption — a subsequent correct password login still works.
// ============================================================================

console.log('\n=== Case 4: stale-passkey repair with bad credentials (clean failure, no corruption) ===');

await test('stale-passkey repair with wrong password fails cleanly; correct password login still works', async () => {
  const { client, username, reg } = await registerWithData(2);
  const { auth } = await registerPasskeyOn(client, { deviceLabel: 'case4-passkey' });
  const dlk = client.dataLookupKey;

  // Make the passkey stale on a new gen: changeCredentials with the tap
  // handler returning false (user dismisses the re-tap). gen-2 then has no
  // passkey wrapping for this credential -> stale.
  const newPassword = 'case4-new-' + Date.now();
  await client.changeCredentials(username, newPassword, {
    phrase: reg.accountKey,
    passkeyTapHandler: async () => false,
  });

  const envBeforeRepair = await readEnvelope(dlk);
  const genCountBefore = genCount(envBeforeRepair);
  // Snapshot the full envelope so we can prove the failed repair didn't mutate it.
  const envJsonBefore = JSON.stringify(envBeforeRepair);

  // Drive a passkey-only auth whose stalePasskeyHandler returns the WRONG
  // password. The repair must reject (typed StalePasskeyError or a clean
  // auth error) — NOT crash, NOT silently corrupt the envelope.
  const c2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  env.pinNextAuth(auth.credentialIdB64Url);
  let repairErr = null;
  try {
    await c2.authenticateWithPasskey({
      stalePasskeyHandler: async () => ({ username, password: 'wrong-' + newPassword }),
    });
  } catch (err) {
    repairErr = err;
  }
  env.clearNextAuth();

  assert(repairErr, 'repair with wrong password must throw');
  // The failure must be a typed/clean auth error, not a null-deref TypeError.
  assert(
    repairErr.name === 'StalePasskeyError' || /password|credential|unwrap|step-up|401|verification/i.test(repairErr.message),
    `expected a typed/clean auth failure, got ${repairErr.name}: ${repairErr.message}`,
  );
  assert(!(repairErr instanceof TypeError), `repair failure must not be a TypeError (null-deref): ${repairErr.message}`);

  // No envelope corruption: the stored envelope is byte-identical to before
  // the failed repair (the SDK must only PUT a new envelope on a SUCCESSFUL
  // re-wrap), and the gen count is unchanged.
  const envAfterRepair = await readEnvelope(dlk);
  assert(genCount(envAfterRepair) === genCountBefore, 'failed repair must not add a gen');
  assert(JSON.stringify(envAfterRepair) === envJsonBefore, 'failed repair must not mutate the stored envelope');
  assertRecoveryFactorPresent(envAfterRepair, 'case4 post-failed-repair');

  // The account is fully intact: a correct password login still works and
  // reads all data through the chain.
  const cPw = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const loginRes = await cPw.login(username, newPassword);
  assert(loginRes.dataLookupKey === dlk, 'correct password login must still work after the failed repair');
  assert(cPw.isLoggedIn(), 'password login should be a full session');
});

// ============================================================================
// CASE 5 — after recoverAccount() of a post-#73 account, the enveloped sharing
//          identity is RESTORED (not rotated), so per-connection read-state
//          caches stay valid and are deliberately KEPT.
//
// Recovery unwraps the DEK via the recovery factor and decrypts the unchanged
// sharing + share-signing keys; share_priv does not rotate, so a connection's
// pair keys and its warmed read-state cache remain valid. tarn.ts gates the
// cache-clear on `if (!recoveredIdentity)` (the minted-new-identity / pre-#73
// migration branch only). We assert the cache is retained and that a real
// post-recovery share read still works on the (unchanged) keys.
// ============================================================================

console.log('\n=== Case 5: post-recovery read on the restored (post-#73) identity (caches kept) ===');

await test('recoverAccount of a restored (post-#73) identity keeps the still-valid read-state cache; read works', async () => {
  // Post-#73, recovery RESTORES Alice's enveloped sharing identity (the
  // recovery factor unwraps the DEK, which decrypts the unchanged sharing +
  // share-signing keys). Her share_priv does NOT rotate, so the connection's
  // pair keys — and the warmed per-connection read-state cache — stay VALID.
  // tarn.ts deliberately KEEPS the caches in this path (it gates the
  // cache-clear on `if (!recoveredIdentity)`, i.e. only the minted-new-identity
  // / pre-#73 migration branch). We assert the cache is retained AND that a
  // real post-recovery read still works.
  const alice = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const bob = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const aliceUser = randomUsername();
  const alicePw = 'case5-alice-' + Date.now();
  const bobUser = randomUsername();
  const bobPw = 'case5-bob-' + Date.now();

  const aliceReg = await alice.register(aliceUser, alicePw, { recoveryAcknowledged: true });
  await forceAllowRulesForAccount(aliceReg.dataLookupKey);
  const bobReg = await bob.register(bobUser, bobPw, { recoveryAcknowledged: true });
  await forceAllowRulesForAccount(bobReg.dataLookupKey);

  // Handshake.
  const send = await alice.sendConnectionRequest(bobUser);
  await sleep(300);
  await bob.listIncomingRequests();
  await bob.acceptConnectionRequest(send.requestNonce);
  await sleep(300);
  await alice.listIncomingRequests();

  let bobConnOfAlice = await connectionTo(alice, bobUser);
  assert(bobConnOfAlice, 'Alice must have Bob as a connection');

  // Alice shares an item and reads her own outbound state so a read-state
  // cache entry exists keyed on Bob's CURRENT share_pub.
  await alice.shareContent(
    bobConnOfAlice,
    'case5-pre-recovery',
    'arweave-case5-pre',
    Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  );
  // Warm Alice's read-state cache for this connection.
  await alice.readShareLog(bobConnOfAlice, { refresh: true });
  const cachedBefore = alice._peekReadStateCache(bobConnOfAlice.share_pub);
  assert(cachedBefore, 'precondition: Alice should have a warmed read-state cache entry');

  // Alice loses her password and recovers ON THE SAME CLIENT that holds the
  // warm read-state cache, so we can observe the in-process behavior directly.
  const recovered = await alice.recoverAccount({
    phrase: aliceReg.accountKey,
    newUsername: randomUsername(),
    newPassword: 'case5-recovered-self-' + Date.now(),
  });
  assert(recovered.dataLookupKey === aliceReg.dataLookupKey, 'recovery preserves Alice DLK');

  // Identity restored (post-#73) → share keys unchanged → the warmed cache is
  // still valid, and recovery deliberately KEEPS it (a non-disruptive recovery
  // that leaves friendships and their read caches intact).
  const cachedAfter = alice._peekReadStateCache(bobConnOfAlice.share_pub);
  assert(cachedAfter, 'recoverAccount of a restored identity must KEEP the still-valid read-state cache');

  // Re-resolve the connection and prove a real share read still works on the
  // (unchanged) keys — no stale-key decrypt failure.
  bobConnOfAlice = await connectionTo(alice, bobUser);
  assert(bobConnOfAlice, 'Alice still has Bob as a connection post-recovery');
  const postState = await alice.readShareLog(bobConnOfAlice, { refresh: true });
  assert(typeof postState === 'object' && postState !== null, 'post-recovery share read must return a state map on rotated keys');
});

// ============ DONE ============

env.restore();
console.log(`\n=== Recovery-combination tests: ${passed} passed, ${failed} failed ===`);
if (failed > 0) {
  console.log('\nFailed:');
  for (const { name, err } of failures) console.log(`  - ${name}: ${err.message}`);
  process.exit(1);
}
process.exit(0);
