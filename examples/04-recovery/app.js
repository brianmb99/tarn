/**
 * Recovery example — register, capture phrase, simulate password loss,
 * recover account on a fresh client.
 *
 * The recovery phrase is the user's parallel access path to their data,
 * independent of the password. This example:
 *   1. Registers a new account.
 *   2. Captures the phrase + the recovery PDF bytes (writes the PDF to disk).
 *   3. Skips the email-recovery-kit forwarder via emailRecoveryKit: false —
 *      the local wrangler dev usually doesn't have an email forwarder
 *      configured, and demo'ing the email path on a real account is awkward
 *      anyway. Apps that DO want email forwarding pass emailRecoveryKit: true.
 *   4. Writes a record under the original account.
 *   5. Constructs a FRESH client (simulating the user being on a different
 *      device or having forgotten their password) and recovers using the
 *      phrase + new credentials.
 *   6. Lists records on the recovered client — proving the data is still
 *      decryptable under the new credentials.
 */

import { writeFile } from 'node:fs/promises';
import { TarnClient, TarnStorage, defineSchema } from 'tarn-client';

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
  emailRecoveryKit:     false,    // skip the email forwarder for this example
  appName:              'Tarn Example 04',
});

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
