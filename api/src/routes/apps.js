// App management endpoints
// PUT /api/v1/accounts/:data_lookup_key/rules — set write rules for a user
// PUT /api/v1/apps/:app_id/invite-template — set invite_url_template (Section 8)
// PUT /api/v1/apps/:app_id/schema — publish app schema (SDK redesign step 5)

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { upsertWriteThrough } from '../cache.js';
import { buildSignedDataItem, uploadSignedDataItem } from '../turbo.js';

import { PROTOCOL_VERSION } from '../constants.js';

const MAX_INVITE_URL_TEMPLATE_LEN = 512;

// 64 KB upper bound on the serialized schema. Real-world schemas are well
// under this (Bookish's draft is ~2 KB); the limit just rejects obviously
// malformed input early so we don't upload garbage to Arweave.
const MAX_SCHEMA_BYTES = 64 * 1024;

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

/**
 * Publish an app schema to Arweave (SDK redesign step 5).
 *
 * The caller authenticates as the app — the JWT's `app` role is the
 * authorization boundary, and the path's `app_id` must equal the JWT's
 * subject. The body is `{ version, schema }`:
 *   - `version` is a positive integer matching the schema's declared
 *     `version` field (the SDK enforces this client-side too).
 *   - `schema` is the full schema object as produced by `defineSchema()`,
 *     serialized via JSON. Public — schemas are app-public structure
 *     metadata, not user data.
 *
 * Tarn signs with APP_SIGNING_KEY and writes to Arweave with tags
 * `App=<app_id>, Type='app-schema', V=<version>`. Subsequent reads can
 * find the latest schema via Arweave GraphQL ordering by HEIGHT_DESC for
 * (App, Type='app-schema'), or filter by V for a specific version.
 *
 * Idempotent at the schema-publication level: re-running with the same
 * (app_id, version, schema) is fine — Arweave dedups on bytes-identical
 * uploads via the Turbo gateway. Bumping `version` is how new schemas
 * are released.
 */
export async function handleSetSchema(appId, request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'app') {
    return errorResponse('Only app identities can publish a schema', 403, cors);
  }
  if (auth.data_lookup_key !== appId) {
    return errorResponse('app_id mismatch', 403, cors);
  }

  // The body itself is bounded by the gateway, but we double-check before
  // serializing so we can reject early with a clean error.
  let bodyText;
  try {
    bodyText = await request.text();
  } catch {
    return errorResponse('Failed to read body', 400, cors);
  }
  if (bodyText.length > MAX_SCHEMA_BYTES) {
    return errorResponse(
      `Schema body exceeds ${MAX_SCHEMA_BYTES} bytes (got ${bodyText.length})`,
      413,
      cors,
    );
  }

  let body;
  try {
    body = JSON.parse(bodyText);
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { version, schema } = body || {};
  if (!Number.isInteger(version) || version < 1) {
    return errorResponse('version must be a positive integer', 400, cors);
  }
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
    return errorResponse('schema must be an object', 400, cors);
  }
  if (typeof schema.appId !== 'string' || schema.appId !== appId) {
    return errorResponse('schema.appId must match the URL app_id', 400, cors);
  }
  if (schema.version !== version) {
    return errorResponse('schema.version must match the body version', 400, cors);
  }

  // Verify the app is actually registered.
  const exists = await env.DB.prepare('SELECT 1 FROM apps WHERE app_id = ?1').bind(appId).first();
  if (!exists) {
    return errorResponse('App not found', 404, cors);
  }

  // Build tags + body for the Arweave upload. Schemas are PUBLIC: the body
  // is the verbatim schema JSON, no encryption layer.
  const tags = [
    { name: 'App', value: appId },
    { name: 'Type', value: 'app-schema' },
    { name: 'V', value: String(version) },
    { name: 'Pv', value: PROTOCOL_VERSION },
  ];

  const signingKey = env.APP_SIGNING_KEY;
  if (!signingKey) {
    return errorResponse(
      'APP_SIGNING_KEY not configured — schema publication unavailable',
      503,
      cors,
    );
  }

  // Sign + cache synchronously so the response carries the txid; defer the
  // Turbo upload (network-bound) to ctx.waitUntil so the caller doesn't
  // wait on it. Same pattern as handleSetRules above.
  const blobBytes = new TextEncoder().encode(JSON.stringify(schema));
  let txid;
  try {
    const signed = await buildSignedDataItem(blobBytes, tags, signingKey);
    txid = signed.txid;
    await upsertWriteThrough(env.DB, txid, tags, blobBytes);

    ctx.waitUntil((async () => {
      try {
        const turbo = await uploadSignedDataItem(signed.signedDataItem);
        if (turbo.ok) {
          console.log(`[tarn-api] App-schema uploaded to Turbo: ${appId} v${version} ${txid}`);
        } else {
          console.warn(`[tarn-api] App-schema Turbo upload failed: ${turbo.status}`);
        }
      } catch (err) {
        console.error('[tarn-api] App-schema Turbo upload error:', err.message);
      }
    })());
  } catch (err) {
    console.error('[tarn-api] App-schema sign/cache error:', err.message);
    return errorResponse('Failed to publish schema', 500, cors);
  }

  return jsonResponse({ ok: true, app_id: appId, version, txid }, 200, cors);
}
