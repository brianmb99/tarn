/**
 * Sender side of the connection + sharing example.
 *
 * Flow:
 *   1. Register a fresh Tarn account.
 *   2. Create a few notes.
 *   3. Generate a single-use invite token + URL. Print it for the recipient.
 *   4. Poll `tarn.connections.listIncomingRequests()` until the recipient
 *      redeems and the connection auto-accepts.
 *   5. Share-with-all, so the new connection sees every note.
 *
 * The auto-accept happens inside `tarn.connections.listIncomingRequests()`:
 * it processes the inbox, and any inbound connection-request whose token
 * matches an issued invite is auto-accepted as a side effect.
 */

import { TarnClient, TarnStorage } from 'tarn-client';
import { schema } from './schema.js';

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

const email    = `sender+${Date.now()}@example.com`;
const password = 'p@ssw0rd-example-03-sender';

const tarn = await TarnClient.create({
  apiBase: API_BASE,
  appId:   APP_ID,
  schema,
  storage: TarnStorage.memory(),
});

console.log('[sender] registering', email);
const reg = await tarn.register(email, password, {
  recoveryAcknowledged: true,
});

await maybeGrantLocalRules(API_BASE, reg.dataLookupKey);

console.log('[sender] creating notes');
const items = [
  ['n1', 'Project kickoff agenda',   'Goals, owners, milestones, risks.'],
  ['n2', 'Research follow-ups',      'Re-check the share-log seq mechanics under multi-device.'],
  ['n3', 'Travel checklist',         'Passport, charger, adapter, offline maps.'],
];
for (const [noteId, title, body] of items) {
  await tarn.notes.create({ noteId, title, body });
}
console.log('[sender] library:', (await tarn.notes.list()).map((n) => n.title));

console.log('\n[sender] creating invite token');
const invite = await tarn.connections.createInvite({
  label:        'Sender',   // local-only label for the to-be connection
  expiry_days:  1,
});
console.log('  token_id:   ', invite.token_id);
console.log('  invite_url: ', invite.invite_url);

console.log('\n=========================================================');
console.log('Run the recipient with this URL:');
console.log(`  TARN_INVITE_URL='${invite.invite_url}' node recipient.js`);
console.log('=========================================================\n');

console.log('[sender] polling for redemption (Ctrl-C to abort)...');
const start = Date.now();
const TIMEOUT_MS = 5 * 60 * 1000;
let connection = null;

while (Date.now() - start < TIMEOUT_MS) {
  // Trigger the inbox poll. Side effect: if a connection-request matching
  // an issued invite has arrived, auto-accept (the SDK's invite-token flow
  // handles that internally).
  try {
    await tarn.connections.listIncomingRequests();
  } catch (err) {
    console.warn('[sender] poll failed:', err.message);
  }
  const conns = await tarn.connections.list();
  if (conns.length > 0) {
    connection = conns[0];
    break;
  }
  await new Promise((r) => setTimeout(r, 2000));
}

if (!connection) {
  console.error('[sender] timed out waiting for redemption');
  process.exit(1);
}

console.log('[sender] connected to', connection.label ?? connection.email ?? '(no label)');
console.log('[sender] sharing all notes with the new connection');
const result = await tarn.notes.shareWithAll('n1');
console.log('  n1 shareWithAll:', result);
const r2 = await tarn.notes.shareWithAll('n2');
console.log('  n2 shareWithAll:', r2);
const r3 = await tarn.notes.shareWithAll('n3');
console.log('  n3 shareWithAll:', r3);

console.log('\n[sender] done. Recipient can now run listShared.');
