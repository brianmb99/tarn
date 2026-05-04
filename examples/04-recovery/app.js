/**
 * Recovery example — register, capture phrase, simulate password loss,
 * recover account on a fresh client.
 *
 * The recovery phrase is the user's parallel access path to their data,
 * independent of the password. This example:
 *   1. Registers a new account.
 *   2. Captures the phrase + the recovery PDF bytes (writes the PDF to disk).
 *      The kit never leaves the device — Tarn does not deliver it for you;
 *      apps decide how to surface it (download, print, app-specific channel).
 *   3. Writes a record under the original account.
 *   4. Constructs a FRESH client (simulating the user being on a different
 *      device or having forgotten their password) and recovers using the
 *      phrase + new credentials.
 *   5. Lists records on the recovered client — proving the data is still
 *      decryptable under the new credentials.
 */

import { writeFile } from 'node:fs/promises';
import { TarnClient, TarnStorage, defineSchema } from 'tarn-client';

async function maybeGrantLocalRules(apiBase, dlk) {
  if (!/^http:\/\/(localhost|127\.0\.0\.1)/.test(apiBase)) return;
  if (!dlk) return;
  const { execSync } = await import('node:child_process');
  const sql = `UPDATE accounts SET rules_json = '[]' WHERE data_lookup_key = '${dlk}'`;
  execSync(`npx wrangler d1 execute tarn-api --local --command "${sql}"`, {
    cwd: new URL('../../api', import.meta.url),
    stdio: 'pipe',
  });
}

const API_BASE = process.env.TARN_API ?? 'http://localhost:8787';
const APP_ID   = 'bookish';

const schema = defineSchema({
  appId: 'bookish',
  version: 1,
  collections: {
    notes: {
      primaryKey: 'noteId',
      fields: { noteId: 'string', body: 'string' },
    },
  },
});

const email       = `recovery+${Date.now()}@example.com`;
const password    = 'original-password';
const newPassword = 'fresh-password-after-loss';

// ============ Phase 1: register and capture the recovery kit ============

console.log('[phase 1] registering', email);
const tarn1 = await TarnClient.create({
  apiBase: API_BASE,
  appId:   APP_ID,
  schema,
  storage: TarnStorage.memory(),
});

const reg = await tarn1.register(email, password, {
  recoveryAcknowledged: true,
  appName:              'Tarn Example 04',
});

await maybeGrantLocalRules(API_BASE, reg.dataLookupKey);

console.log('  recoveryPhrase: <captured, not logged for safety>');
console.log('  pdfBytes:       Uint8Array of', reg.pdfBytes.length, 'bytes');

// In a real app the PDF goes straight to the user via download / share.
// Here we drop it to disk so you can inspect it.
const pdfPath = './recovery-kit.pdf';
await writeFile(pdfPath, reg.pdfBytes);
console.log('  wrote', pdfPath);

// Capture the phrase only in this process. Apps must NEVER persist the
// phrase to disk or any storage system — the user is the only durable store.
const phrase = reg.recoveryPhrase;

console.log('[phase 1] writing one note');
await tarn1.notes.create({ noteId: 'n1', body: 'this should survive recovery' });

// ============ Phase 2: simulate password loss → recover ============

console.log('\n[phase 2] simulating password loss — constructing FRESH client');
const tarn2 = await TarnClient.create({
  apiBase: API_BASE,
  appId:   APP_ID,
  schema,
  storage: TarnStorage.memory(),
});

console.log('[phase 2] recovering via phrase');
await tarn2.recoverAccount({
  phrase,
  newEmail:    email,        // can be the same email or a different one
  newPassword: newPassword,
});

console.log('[phase 2] reading notes on the recovered client');
const notes = await tarn2.notes.list();
console.log(notes);

// ============ Phase 3: confirm the new password works ============

console.log('\n[phase 3] confirming the new password works on a third client');
const tarn3 = await TarnClient.create({
  apiBase: API_BASE,
  appId:   APP_ID,
  schema,
  storage: TarnStorage.memory(),
});
await tarn3.login(email, newPassword);
console.log('  notes via login:', await tarn3.notes.list());

console.log('\nDone.');
