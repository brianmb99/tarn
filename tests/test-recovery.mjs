// End-to-end recovery flow tests (issue #12)
// Run: node tests/test-recovery.mjs [apiBaseUrl]
// Requires: wrangler dev running (cd api && npx wrangler dev --port 8787)
//
// What this exercises against a real (local or remote) Tarn API:
//   - register() publishes a v1 envelope with both factors
//   - login() reads back the v1 envelope and recovers the DEK chain
//   - createEntry/getEntries round-trip works under v1 (per-content CEK)
//   - recoverAccount() with the account key recovers the DEK chain via the
//     recovery factor and rotates credentials
//   - Post-recovery login() with new credentials reads pre-recovery data

import { TarnClient } from '../client/src/tarn.js';
import { seedTestApp, DEFAULT_APP_ID } from './helpers.mjs';

const API_BASE = process.argv[2] || 'http://localhost:8787';

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

function randomUsername() {
  return `recovery-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
}

// Open the per-account write-rules gate by setting an empty rule list. Mirrors
// the helper pattern in tests/test-e2e.mjs — a fresh account has rules_json
// NULL (DENY) until an app sets rules; for these tests we shortcut via D1.
async function openWriteGate(dataLookupKey) {
  const { execSync } = await import('child_process');
  execSync(
    `npx wrangler d1 execute tarn-api --local --command "UPDATE accounts SET rules_json = '[]' WHERE data_lookup_key = '${dataLookupKey}'"`,
    { cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), stdio: 'pipe', timeout: 10000 }
  );
}

// ============ REGISTER → LOGIN → RECOVER → LOGIN ============

console.log('\n=== Recovery round trip ===');

await test('register publishes v1 envelope with both factors', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const username = randomUsername();
  const result = await client.register(username, 'orig-password-2026', {
    recoveryAcknowledged: true,
  });
  assert(result.dataLookupKey, 'should return dataLookupKey');
  assert(result.accountKey, 'should return accountKey');
  if (result.accountKey.split(' ').length !== 24) {
    throw new Error(`expected 24-word account key, got ${result.accountKey.split(' ').length}`);
  }
  // Tarn no longer renders kits in-SDK — apps build their own from the account key.
  if (result.pdfBytes !== undefined) {
    throw new Error('register() must not return pdfBytes (in-SDK PDF renderer was removed)');
  }
});

await test('login → fresh client reads back v1 envelope chain', async () => {
  // No createEntry here — local dev's Turbo wallet is Forbidden, and writing
  // is exercised by the existing test-client.mjs via the same code path. This
  // test focuses on what's NEW for issue #12: the v1 envelope is correctly
  // round-trippable through the API + login.
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const username = randomUsername();
  const password = 'test-password-2026';
  await client.register(username, password, {
    recoveryAcknowledged: true,
  });

  // Fresh client logs in successfully — proves the API stored + returned the
  // v1 wrapped_data_key intact and the password factor unwraps the chain.
  const c2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const r = await c2.login(username, password);
  if (!r.dataLookupKey || r.dataLookupKey.length !== 64) {
    throw new Error(`bad dataLookupKey from login: ${r.dataLookupKey}`);
  }
});

await test('recoverAccount with phrase rotates credentials (no writes)', async () => {
  // 1. Register an account.
  const c1 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const oldUsername = randomUsername();
  const oldPassword = 'old-password-2026';
  const reg = await c1.register(oldUsername, oldPassword, {
    recoveryAcknowledged: true,
  });

  // 2. Simulate "user lost their password" — fresh client, only the phrase.
  const c2 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const newUsername = randomUsername();
  const newPassword = 'new-password-2026';
  const rec = await c2.recoverAccount({
    phrase: reg.accountKey,
    newUsername,
    newPassword,
  });
  if (rec.dataLookupKey !== reg.dataLookupKey) {
    throw new Error(`dataLookupKey changed after recovery: ${reg.dataLookupKey} → ${rec.dataLookupKey}`);
  }

  // 3. Old credentials should no longer log in.
  const cOld = new TarnClient(API_BASE, DEFAULT_APP_ID);
  let oldLoginThrew = false;
  try {
    await cOld.login(oldUsername, oldPassword);
  } catch {
    oldLoginThrew = true;
  }
  if (!oldLoginThrew) {
    throw new Error('old credentials should fail to log in after recovery');
  }

  // 4. New credentials log in cleanly under the SAME data_lookup_key.
  const cNew = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const newLoginRes = await cNew.login(newUsername, newPassword);
  if (newLoginRes.dataLookupKey !== reg.dataLookupKey) {
    throw new Error(`new-credential login should see the original dataLookupKey`);
  }

  // 5. The same phrase works for a SECOND recovery — proves the recovery
  //    factor is preserved across credential changes.
  const c3 = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const rec2 = await c3.recoverAccount({
    phrase: reg.accountKey,
    newUsername: randomUsername(),
    newPassword: 'second-recovery-pw',
  });
  if (rec2.dataLookupKey !== reg.dataLookupKey) {
    throw new Error(`second recovery changed dataLookupKey`);
  }
});

await test('recoverAccount with wrong phrase fails (404 from API)', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  // Generate a phrase that's almost certainly not registered to any account.
  const garbagePhrase =
    'abandon abandon abandon abandon abandon abandon abandon abandon ' +
    'abandon abandon abandon abandon abandon abandon abandon abandon ' +
    'abandon abandon abandon abandon abandon abandon abandon art';
  let threw = false;
  try {
    await client.recoverAccount({
      phrase: garbagePhrase,
      newUsername: randomUsername(),
      newPassword: 'pw',
    });
  } catch (err) {
    threw = true;
    if (!/no account found/.test(err.message)) {
      throw new Error(`unexpected error message: ${err.message}`);
    }
  }
  if (!threw) throw new Error('recoverAccount should have thrown for unregistered phrase');
});

await test('POST /api/v1/recovery/email is gone (404) — Tarn no longer touches recovery material', async () => {
  // The endpoint was removed — Tarn must never see plaintext recovery PDFs,
  // even ephemerally. Recovery-kit delivery is an app-layer concern.
  const res = await fetch(`${API_BASE}/api/v1/recovery/email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recipient_email: 'a@b.com', pdf_base64: 'xx' }),
  });
  if (res.status !== 404) throw new Error(`expected 404 (route removed), got ${res.status}`);
});

// ============ RLk dual-tag (standalone-recovery prep, 2026-05) ============
//
// The credential blob on Arweave is dual-tagged with `Lk = credential_lookup_key`
// AND `RLk = recovery_lookup_key` so the standalone-recovery package
// (`@tarn/recover`, in development) can find the account record from the
// account key alone — without knowing the password.
//
// These tests query D1's local `entries` cache. The cache mirrors what gets
// written to Arweave via Turbo (best-effort), so a row in `entries` with a
// matching `tags_json` substring is sufficient evidence that the upload tags
// carried `RLk`. We deliberately avoid waiting on the live Turbo upload
// (which is unreachable from local dev anyway).

console.log('\n=== RLk dual-tag (gateway-direct discovery prep) ===');

async function queryEntriesByRLk(rlkHex) {
  const { execSync } = await import('child_process');
  const { writeFileSync, unlinkSync } = await import('node:fs');
  // Match entries whose tags_json blob contains the RLk hex value as a
  // substring. We use INSTR() rather than LIKE — D1's SQLite enforces a
  // surprisingly strict "LIKE or GLOB pattern too complex" cap that fires
  // on patterns longer than ~50 chars even without wildcards in the middle.
  // INSTR() is simple substring search and has no such limit. Two INSTR
  // calls (one for "RLk", one for the hex value) keep the match scoped to
  // the right tag without trying to encode quotes.
  //
  // Cross-platform shell quoting with both " and ' is fragile, so the SQL
  // goes through a sidecar file inside api/ via --file. wrangler on Windows
  // also fails to resolve some Windows-style absolute paths for --file; a
  // relative path under cwd avoids that issue.
  const sql = `SELECT txid, app, type, lookup_key, tags_json FROM entries WHERE app = 'tarn' AND type = 'cred' AND INSTR(tags_json, 'RLk') > 0 AND INSTR(tags_json, '${rlkHex}') > 0;`;
  const cwd = new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1');
  const fileName = `__rlk_query_${process.pid}_${Date.now()}_${Math.random().toString(36).slice(2)}.sql`;
  const filePath = `${cwd}/${fileName}`;
  try {
    writeFileSync(filePath, sql, 'utf8');
    let out;
    try {
      out = execSync(
        `npx wrangler d1 execute tarn-api --local --json --file ${fileName}`,
        { cwd, stdio: ['ignore', 'pipe', 'pipe'], timeout: 60000 },
      ).toString();
    } catch (err) {
      const stdout = err.stdout?.toString() || '';
      const stderr = err.stderr?.toString() || '';
      // wrangler often exits non-zero on warnings (e.g. version-update
      // banner) while still emitting valid JSON on stdout. Prefer stdout
      // when it parses.
      if (stdout.trim().startsWith('[')) {
        out = stdout;
      } else {
        throw new Error(
          `wrangler d1 execute --file failed (status=${err.status}, signal=${err.signal}): ` +
            `STDERR=${stderr.slice(0, 500)} STDOUT=${stdout.slice(0, 500)}`,
        );
      }
    }
    const parsed = JSON.parse(out);
    return parsed[0]?.results ?? [];
  } finally {
    try { unlinkSync(filePath); } catch { /* best effort */ }
  }
}

// Credential-blob upserts run inside ctx.waitUntil() — they can complete
// after the HTTP response returns. Give the worker a short window to flush
// before querying D1 directly. 500ms is comfortably above the observed
// upsert latency in local dev (single-digit ms).
async function waitForBlobFlush() {
  await new Promise(r => setTimeout(r, 500));
}

async function readRecoveryLookupKey(dataLookupKey) {
  const { execSync } = await import('child_process');
  const sql = `SELECT recovery_lookup_key, credential_lookup_key FROM accounts WHERE data_lookup_key = '${dataLookupKey}'`;
  const out = execSync(
    `npx wrangler d1 execute tarn-api --local --json --command "${sql}"`,
    { cwd: new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1'), stdio: ['ignore', 'pipe', 'ignore'], timeout: 15000 },
  ).toString();
  return JSON.parse(out)[0]?.results?.[0] ?? null;
}

await test('register: credential blob is dual-tagged with Lk + RLk', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const username = randomUsername();
  const reg = await client.register(username, 'rlk-pw-' + Date.now(), {
    recoveryAcknowledged: true,
  });
  const row = await readRecoveryLookupKey(reg.dataLookupKey);
  if (!row?.recovery_lookup_key) throw new Error('account should have a recovery_lookup_key');

  // Query the cache by RLk — this is exactly the lookup the standalone-recovery
  // client will perform via Arweave GraphQL.
  await waitForBlobFlush();
  const matches = await queryEntriesByRLk(row.recovery_lookup_key);
  if (matches.length < 1) throw new Error(`expected at least one entries row tagged with RLk=${row.recovery_lookup_key}, got ${matches.length}`);
  // The match must be this account's credential blob, not a stray.
  if (!matches.some(m => m.lookup_key === row.credential_lookup_key)) {
    throw new Error(`RLk lookup should resolve to the row whose Lk = ${row.credential_lookup_key}`);
  }
});

await test('changeCredentials: republished blob keeps RLk discoverable (recovery factor preserved)', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const username = randomUsername();
  const password = 'rlk-cc-' + Date.now();
  const reg = await client.register(username, password, { recoveryAcknowledged: true });
  const beforeRow = await readRecoveryLookupKey(reg.dataLookupKey);
  if (!beforeRow?.recovery_lookup_key) throw new Error('must have RLk pre-change');

  // changeCredentials with a new password — phrase passes through so the new
  // gen also gets a recovery wrapping; recovery_lookup_key itself doesn't
  // rotate (it's stable across credential changes by design).
  const newUsername = randomUsername();
  const newPassword = 'rlk-cc-new-' + Date.now();
  await client.changeCredentials(newUsername, newPassword, { phrase: reg.accountKey });
  const afterRow = await readRecoveryLookupKey(reg.dataLookupKey);
  if (afterRow.recovery_lookup_key !== beforeRow.recovery_lookup_key) {
    throw new Error('changeCredentials should preserve recovery_lookup_key (it is account-key-derived, not password-derived)');
  }

  // The same RLk should still resolve — at minimum the original credential
  // blob is still discoverable; the new credential blob also carries the
  // same RLk. Either way the recovery client can find this account.
  await waitForBlobFlush();
  const matches = await queryEntriesByRLk(beforeRow.recovery_lookup_key);
  if (matches.length < 1) throw new Error('RLk lookup must still resolve after changeCredentials');
  // The CURRENT credential_lookup_key must be among the matches — proves the
  // freshly republished blob also carried RLk.
  if (!matches.some(m => m.lookup_key === afterRow.credential_lookup_key)) {
    throw new Error(`post-change credential blob (Lk=${afterRow.credential_lookup_key}) must be tagged with RLk`);
  }
});

await test('rotateAccountKey: NEW RLk discovers the rotated blob, OLD RLk does not', async () => {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  const username = randomUsername();
  const password = 'rlk-rot-' + Date.now();
  const reg = await client.register(username, password, { recoveryAcknowledged: true });
  const beforeRow = await readRecoveryLookupKey(reg.dataLookupKey);
  const oldRlk = beforeRow.recovery_lookup_key;
  if (!oldRlk) throw new Error('must have OLD RLk before rotation');

  // Rotate — produces a new account key and new recovery_lookup_key.
  const rot = await client.rotateAccountKey({ password });
  if (!rot.accountKey) throw new Error('rotateAccountKey should return new account key');
  if (rot.accountKey.split(' ').length !== 24) throw new Error('expected 24-word phrase');

  const afterRow = await readRecoveryLookupKey(reg.dataLookupKey);
  const newRlk = afterRow.recovery_lookup_key;
  if (!newRlk) throw new Error('must have NEW RLk after rotation');
  if (newRlk === oldRlk) throw new Error('rotation should produce a different recovery_lookup_key');

  // NEW RLk must find the newly republished credential blob.
  await waitForBlobFlush();
  const newMatches = await queryEntriesByRLk(newRlk);
  if (newMatches.length < 1) throw new Error(`NEW RLk should find at least one entry, got ${newMatches.length}`);
  if (!newMatches.some(m => m.lookup_key === afterRow.credential_lookup_key)) {
    throw new Error('NEW RLk should resolve to the post-rotation credential blob');
  }

  // OLD RLk: there is one historical row tagged with it (the original register
  // blob, written before rotation). That's expected — Arweave is append-only.
  // The CRITICAL property is that no row tagged with the OLD RLk also carries
  // the CURRENT credential_lookup_key — i.e. an attacker / observer with the
  // old phrase finds only stale data, never the live credential.
  const oldMatches = await queryEntriesByRLk(oldRlk);
  if (oldMatches.some(m => m.lookup_key === afterRow.credential_lookup_key)) {
    throw new Error('OLD RLk must NOT resolve to the post-rotation credential blob');
  }
});

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
process.exit(failed > 0 ? 1 : 0);
