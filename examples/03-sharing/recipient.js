/**
 * Recipient side of the connection + sharing example.
 *
 * Flow:
 *   1. Register a fresh Tarn account (separate from the sender).
 *   2. Parse the invite URL handed off from sender.js.
 *   3. Preview the invite (non-consuming) so the user sees who's inviting.
 *   4. Redeem the invite — sends a connection-request HPKE-sealed back to
 *      the inviter. The sender's poll auto-accepts it.
 *   5. Wait briefly for the connection to materialize on this side, then
 *      list the books the sender has shared.
 *
 * Run with:
 *   TARN_INVITE_URL='<url printed by sender>' node recipient.js
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

const API_BASE   = process.env.TARN_API ?? 'http://localhost:8787';
const APP_ID     = 'bookish';
const INVITE_URL = process.env.TARN_INVITE_URL;

if (!INVITE_URL) {
  console.error('Usage: TARN_INVITE_URL=<url printed by sender.js> node recipient.js');
  process.exit(1);
}

// Parse the URL: token_id is the last path segment, payload_key is the fragment.
function parseInvite(url) {
  // Handle both http(s) URLs and the tarn:invite/... fallback.
  const hashIdx = url.indexOf('#');
  if (hashIdx < 0) throw new Error('invite URL missing # fragment with payload_key');
  const payloadKey = url.slice(hashIdx + 1);
  const beforeHash = url.slice(0, hashIdx);
  const tokenId    = decodeURIComponent(beforeHash.split('/').pop());
  return { tokenId, payloadKey };
}

const { tokenId, payloadKey } = parseInvite(INVITE_URL);

const email    = `recipient+${Date.now()}@example.com`;
const password = 'p@ssw0rd-example-03-recipient';

const tarn = await TarnClient.create({
  apiBase: API_BASE,
  appId:   APP_ID,
  schema,
  storage: TarnStorage.memory(),
});

console.log('[recipient] registering', email);
const reg = await tarn.register(email, password, {
  recoveryAcknowledged: true,
  emailRecoveryKit: false,
});

await maybeGrantLocalRules(API_BASE, reg.dataLookupKey);

console.log('[recipient] previewing invite (non-consuming)');
const preview = await tarn.connections.previewInvite(tokenId, payloadKey);
if (preview) {
  console.log('  invited by:', preview.inviter_display_name || '(no display name)');
  console.log('  expires_at:', new Date(preview.expires_at * 1000).toISOString());
} else {
  console.log('  preview returned null — token may be expired or already used');
}

console.log('[recipient] redeeming invite token');
await tarn.connections.redeemInvite(tokenId, payloadKey);

console.log('[recipient] waiting for the sender to auto-accept and share...');
const start = Date.now();
const TIMEOUT_MS = 5 * 60 * 1000;
let notes = [];
let sender = null;

while (Date.now() - start < TIMEOUT_MS) {
  // Process any inbound accepts the sender published.
  try {
    await tarn.connections.listIncomingRequests();
  } catch (err) {
    console.warn('[recipient] poll failed:', err.message);
  }
  const conns = await tarn.connections.list();
  if (conns.length > 0) {
    sender = conns[0];
    notes = await tarn.notes.listShared(sender);
    if (notes.length > 0) break;
  }
  await new Promise((r) => setTimeout(r, 2000));
}

if (!sender) {
  console.error('[recipient] timed out waiting for the connection to establish');
  process.exit(1);
}

console.log('\n[recipient] sender:', sender.label ?? sender.email ?? '(no label)');
console.log('[recipient] shared notes:');
for (const n of notes) {
  console.log(`  - ${n.title}${n.body ? ' — ' + n.body : ''}`);
}
