// App management endpoints
// PUT /api/v1/accounts/:data_lookup_key/rules — set write rules for a user

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { upsertWriteThrough } from '../cache.js';
import { uploadToArweave } from '../turbo.js';

const PROTOCOL_VERSION = '0.3.0';

/**
 * Set write authorization rules for a user.
 * Requires JWT with role='app'. The app can only set rules for users who have
 * at least one entry tagged with the app's app_id.
 */
export async function handleSetRules(dataLookupKey, request, env, ctx, cors) {
  // Auth
  const auth = await requireAuth(request, env);
  if (!auth) return errorResponse('Unauthorized', 401, cors);

  // Must be an app identity
  if (auth.role !== 'app') {
    return errorResponse('Only app identities can set user rules', 403, cors);
  }

  const appId = auth.data_lookup_key; // For apps, JWT sub = app_id

  // Validate data_lookup_key format
  if (!/^[a-f0-9]{64}$/.test(dataLookupKey)) {
    return errorResponse('Invalid data_lookup_key format', 400, cors);
  }

  // Parse body
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { rules } = body;
  if (!Array.isArray(rules)) {
    return errorResponse('rules must be an array', 400, cors);
  }

  // Verify user account exists
  const account = await env.DB.prepare(
    'SELECT data_lookup_key FROM accounts WHERE data_lookup_key = ?1'
  ).bind(dataLookupKey).first();

  if (!account) {
    return errorResponse('User account not found', 404, cors);
  }

  // Verify user has entries for this app (they're "our" user)
  const hasEntries = await env.DB.prepare(
    'SELECT 1 FROM entries WHERE lookup_key = ?1 AND app = ?2 AND is_tombstone = 0 LIMIT 1'
  ).bind(dataLookupKey, appId).first();

  if (!hasEntries) {
    return errorResponse('User has no entries for this app', 403, cors);
  }

  // Update rules in D1
  const rulesJson = JSON.stringify(rules);
  await env.DB.prepare(
    'UPDATE accounts SET rules_json = ?1 WHERE data_lookup_key = ?2'
  ).bind(rulesJson, dataLookupKey).run();

  // Persist app-config to Arweave (non-blocking)
  const tags = [
    { name: 'App', value: appId },
    { name: 'Type', value: 'app-config' },
    { name: 'Lk', value: dataLookupKey },
    { name: 'V', value: PROTOCOL_VERSION },
  ];

  const configBody = JSON.stringify({
    rules,
    set_by: appId,
    timestamp: new Date().toISOString(),
  });

  ctx.waitUntil((async () => {
    try {
      const signingKey = env.APP_SIGNING_KEY;
      if (!signingKey) {
        console.warn('[tarn-api] APP_SIGNING_KEY not set — skipping app-config upload');
        return;
      }
      const blobBytes = new TextEncoder().encode(configBody);
      const turbo = await uploadToArweave(blobBytes, tags, signingKey);
      if (turbo.ok && turbo.txid) {
        await upsertWriteThrough(env.DB, turbo.txid, tags);
        console.log(`[tarn-api] App-config uploaded: ${turbo.txid}`);
      }
    } catch (err) {
      console.error('[tarn-api] App-config upload error:', err.message);
    }
  })());

  return jsonResponse({ ok: true }, 200, cors);
}
