// App management endpoints
// PUT /api/v1/accounts/:data_lookup_key/rules — set write rules for a user
// PUT /api/v1/apps/:app_id/invite-template — set invite_url_template (Section 8)

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { upsertWriteThrough } from '../cache.js';
import { buildSignedDataItem, uploadSignedDataItem } from '../turbo.js';

import { PROTOCOL_VERSION } from '../constants.js';

const MAX_INVITE_URL_TEMPLATE_LEN = 512;

/**
 * Set write authorization rules for a user.
 * Requires JWT with role='app'. The app can only set rules for users who have
 * at least one entry tagged with the app's app_id.
 */
export async function handleSetRules(dataLookupKey, request, env, ctx, cors) {
  // Auth
  const auth = await requireAuth(request, env, ctx);
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

  // Verify user account exists AND belongs to this app
  const account = await env.DB.prepare(
    'SELECT data_lookup_key, app FROM accounts WHERE data_lookup_key = ?1'
  ).bind(dataLookupKey).first();

  if (!account) {
    return errorResponse('User account not found', 404, cors);
  }

  if (account.app !== appId) {
    return errorResponse('User is not registered for this app', 403, cors);
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
      const { signedDataItem, txid } = await buildSignedDataItem(blobBytes, tags, signingKey);
      await upsertWriteThrough(env.DB, txid, tags);
      console.log(`[tarn-api] App-config cached: ${txid}`);
      const turbo = await uploadSignedDataItem(signedDataItem);
      if (turbo.ok) {
        console.log(`[tarn-api] App-config uploaded to Turbo: ${txid}`);
      }
    } catch (err) {
      console.error('[tarn-api] App-config upload error:', err.message);
    }
  })());

  return jsonResponse({ ok: true }, 200, cors);
}

/**
 * Set invite_url_template for an app (Section 8, issue #22).
 *
 * The caller must authenticate as the app — the JWT's app role is the
 * authorization boundary, and `app_id` in the path must equal the JWT's
 * subject. Empty / null body clears the template; any non-empty value is
 * stored verbatim. The SDK's `createInviteToken` reads this back via the
 * unauthenticated `GET /api/v1/apps/:app_id/invite-template`.
 */
export async function handleSetInviteTemplate(appId, request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'app') {
    return errorResponse('Only app identities can set invite_url_template', 403, cors);
  }
  if (auth.data_lookup_key !== appId) {
    return errorResponse('app_id mismatch', 403, cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const template = body?.invite_url_template;
  if (template != null) {
    if (typeof template !== 'string') {
      return errorResponse('invite_url_template must be a string or null', 400, cors);
    }
    if (template.length > MAX_INVITE_URL_TEMPLATE_LEN) {
      return errorResponse(`invite_url_template exceeds ${MAX_INVITE_URL_TEMPLATE_LEN} chars`, 400, cors);
    }
    if (!template.includes('{token_id}')) {
      return errorResponse('invite_url_template must contain {token_id}', 400, cors);
    }
  }

  const exists = await env.DB.prepare('SELECT 1 FROM apps WHERE app_id = ?1').bind(appId).first();
  if (!exists) {
    return errorResponse('App not found', 404, cors);
  }

  await env.DB.prepare(
    'UPDATE apps SET invite_url_template = ?1 WHERE app_id = ?2'
  ).bind(template ?? null, appId).run();

  return jsonResponse({ ok: true, invite_url_template: template ?? null }, 200, cors);
}
