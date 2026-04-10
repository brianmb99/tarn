// Auth route handlers: register, challenge, verify, credential change, account deletion
// Implements Tarn Protocol ECDSA P-256 challenge-response auth.

import { jsonResponse, errorResponse } from '../worker.js';
import { generateChallenge, storeNonce, consumeNonce, signJWT } from '../auth.js';
import { importPublicKey, verifySignature, isValidHex64 } from '../crypto.js';
import { requireAuth } from '../middleware/auth.js';
import { buildSignedDataItem, uploadSignedDataItem } from '../turbo.js';
import { upsertWriteThrough } from '../cache.js';

import { PROTOCOL_VERSION } from '../constants.js';

// ============ HELPERS ============

function generateDataLookupKey() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function buildCredentialBlob(dataLookupKey, wrappedDataKey, publicKey, app) {
  return JSON.stringify({ data_lookup_key: dataLookupKey, wrapped_data_key: wrappedDataKey, public_key: publicKey, app });
}

function buildCredentialTags(credentialLookupKey) {
  return [
    { name: 'App', value: 'tarn' },
    { name: 'Type', value: 'cred' },
    { name: 'Lk', value: credentialLookupKey },
    { name: 'V', value: PROTOCOL_VERSION },
  ];
}

/**
 * Persist a credential mapping blob to Arweave (non-blocking).
 * Returns immediately — upload runs in ctx.waitUntil.
 */
function persistCredentialBlob(ctx, env, credentialLookupKey, dataLookupKey, wrappedDataKey, publicKey, app) {
  const blobBody = buildCredentialBlob(dataLookupKey, wrappedDataKey, publicKey, app);
  const tags = buildCredentialTags(credentialLookupKey);

  ctx.waitUntil((async () => {
    try {
      const signingKey = env.APP_SIGNING_KEY;
      if (!signingKey) {
        console.warn('[tarn-api] APP_SIGNING_KEY not set — skipping Arweave upload');
        return;
      }
      const blobBytes = new TextEncoder().encode(blobBody);
      const { signedDataItem, txid } = await buildSignedDataItem(blobBytes, tags, signingKey);
      await upsertWriteThrough(env.DB, txid, tags);
      console.log(`[tarn-api] Credential blob cached: ${txid}`);
      const turbo = await uploadSignedDataItem(signedDataItem);
      if (turbo.ok) {
        console.log(`[tarn-api] Credential blob uploaded to Turbo: ${txid}`);
      } else {
        console.warn(`[tarn-api] Credential blob Turbo upload failed: ${turbo.status} ${turbo.body}`);
      }
    } catch (err) {
      console.error('[tarn-api] Credential blob upload error:', err.message);
    }
  })());
}

// ============ POST /api/v1/auth/register ============

const MAX_REGISTRATIONS_PER_HOUR = 100;

async function checkRegistrationRateLimit(env, request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const data = new TextEncoder().encode(ip + '-tarn-register-salt');
  const hash = await crypto.subtle.digest('SHA-256', data);
  const ipHash = Array.from(new Uint8Array(hash)).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
  const hour = new Date().toISOString().slice(0, 13);
  const key = `register:${ipHash}:${hour}`;
  const count = parseInt(await env.RATE_KV.get(key) || '0');
  if (count >= MAX_REGISTRATIONS_PER_HOUR) {
    return { allowed: false };
  }
  await env.RATE_KV.put(key, String(count + 1), { expirationTtl: 3600 });
  return { allowed: true };
}

export async function handleRegister(request, env, ctx, cors) {
  // IP rate limit
  const { allowed } = await checkRegistrationRateLimit(env, request);
  if (!allowed) {
    return errorResponse('Registration rate limit exceeded', 429, cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { credential_lookup_key, public_key, wrapped_data_key, app } = body;

  // Validate app — must be a registered app
  if (!app || typeof app !== 'string') {
    return errorResponse('app is required', 400, cors);
  }
  const registeredApp = await env.DB.prepare(
    'SELECT 1 FROM apps WHERE app_id = ?1'
  ).bind(app).first();
  if (!registeredApp) {
    return errorResponse('Unregistered app: ' + app, 400, cors);
  }

  // Validate credential_lookup_key
  if (!isValidHex64(credential_lookup_key)) {
    return errorResponse('Invalid credential_lookup_key: must be 64-char lowercase hex', 400, cors);
  }

  // Validate public_key by attempting import
  try {
    await importPublicKey(public_key);
  } catch {
    return errorResponse('Invalid public_key: must be base64-encoded SPKI P-256 public key', 400, cors);
  }

  // Validate wrapped_data_key
  if (!wrapped_data_key || typeof wrapped_data_key !== 'string' || wrapped_data_key.length === 0) {
    return errorResponse('wrapped_data_key is required', 400, cors);
  }

  // Check credential_lookup_key uniqueness
  const existing = await env.DB.prepare(
    'SELECT 1 FROM accounts WHERE credential_lookup_key = ?1'
  ).bind(credential_lookup_key).first();
  if (existing) {
    return errorResponse('credential_lookup_key already in use', 409, cors);
  }

  // Generate unique data_lookup_key
  let data_lookup_key;
  for (let attempt = 0; attempt < 5; attempt++) {
    const candidate = generateDataLookupKey();
    const dlkExists = await env.DB.prepare(
      'SELECT 1 FROM accounts WHERE data_lookup_key = ?1'
    ).bind(candidate).first();
    if (!dlkExists) {
      data_lookup_key = candidate;
      break;
    }
  }
  if (!data_lookup_key) {
    return errorResponse('Failed to generate unique data_lookup_key', 500, cors);
  }

  // Insert account (rules_json NULL = DENY until app sets rules)
  await env.DB.prepare(
    'INSERT INTO accounts (credential_lookup_key, public_key, data_lookup_key, wrapped_data_key, app, rules_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)'
  ).bind(credential_lookup_key, public_key, data_lookup_key, wrapped_data_key, app, Date.now()).run();

  // Persist credential mapping to Arweave (non-blocking)
  persistCredentialBlob(ctx, env, credential_lookup_key, data_lookup_key, wrapped_data_key, public_key, app);

  return jsonResponse({ data_lookup_key }, 201, cors);
}

// ============ POST /api/v1/auth/challenge ============

export async function handleChallenge(request, env, cors) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { credential_lookup_key } = body;
  if (!credential_lookup_key || typeof credential_lookup_key !== 'string') {
    return errorResponse('credential_lookup_key is required', 400, cors);
  }

  // Look up in accounts table first
  const account = await env.DB.prepare(
    'SELECT data_lookup_key, wrapped_data_key FROM accounts WHERE credential_lookup_key = ?1'
  ).bind(credential_lookup_key).first();

  if (account) {
    const nonce = generateChallenge();
    await storeNonce(env, nonce, credential_lookup_key);
    return jsonResponse({
      nonce,
      data_lookup_key: account.data_lookup_key,
      wrapped_data_key: account.wrapped_data_key,
    }, 200, cors);
  }

  // Fall back to apps table
  const app = await env.DB.prepare(
    'SELECT app_id FROM apps WHERE app_id = ?1'
  ).bind(credential_lookup_key).first();

  if (app) {
    const nonce = generateChallenge();
    await storeNonce(env, nonce, credential_lookup_key);
    return jsonResponse({ nonce }, 200, cors);
  }

  return errorResponse('Unknown credential_lookup_key', 404, cors);
}

// ============ POST /api/v1/auth/verify ============

export async function handleVerify(request, env, cors) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { credential_lookup_key, nonce, signature } = body;
  if (!credential_lookup_key || !nonce || !signature) {
    return errorResponse('credential_lookup_key, nonce, and signature are required', 400, cors);
  }

  // Consume nonce (single-use)
  const nonceData = await consumeNonce(env, nonce);
  if (!nonceData) {
    return errorResponse('Invalid or expired nonce', 401, cors);
  }

  // Verify nonce was issued for this credential_lookup_key
  if (nonceData.credentialLookupKey !== credential_lookup_key) {
    return errorResponse('Nonce credential mismatch', 401, cors);
  }

  // Look up public key (accounts first, then apps)
  let publicKeyBase64;
  let jwtPayload;

  const account = await env.DB.prepare(
    'SELECT data_lookup_key, public_key, app FROM accounts WHERE credential_lookup_key = ?1'
  ).bind(credential_lookup_key).first();

  if (account) {
    publicKeyBase64 = account.public_key;
    jwtPayload = { sub: account.data_lookup_key, role: 'user', app: account.app };
  } else {
    const app = await env.DB.prepare(
      'SELECT app_id, public_key FROM apps WHERE app_id = ?1'
    ).bind(credential_lookup_key).first();

    if (app) {
      publicKeyBase64 = app.public_key;
      jwtPayload = { sub: app.app_id, role: 'app' };
    }
  }

  if (!publicKeyBase64) {
    return errorResponse('Account not found', 401, cors);
  }

  // Import public key and verify signature
  let publicKey;
  try {
    publicKey = await importPublicKey(publicKeyBase64);
  } catch {
    return errorResponse('Stored public key is invalid', 500, cors);
  }

  const valid = await verifySignature(publicKey, nonce, signature);
  if (!valid) {
    return errorResponse('Invalid signature', 401, cors);
  }

  // Issue JWT
  const jwt = await signJWT(jwtPayload, env.JWT_SECRET);
  return jsonResponse({ jwt, expiresIn: 900 }, 200, cors);
}

// ============ PUT /api/v1/auth — Credential Change ============

export async function handleCredentialChange(request, env, ctx, cors) {
  const auth = await requireAuth(request, env);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') return errorResponse('Only user accounts can change credentials', 403, cors);

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { new_credential_lookup_key, new_public_key, new_wrapped_data_key } = body;

  // Validate new credential_lookup_key
  if (!isValidHex64(new_credential_lookup_key)) {
    return errorResponse('Invalid new_credential_lookup_key: must be 64-char lowercase hex', 400, cors);
  }

  // Validate new public_key
  try {
    await importPublicKey(new_public_key);
  } catch {
    return errorResponse('Invalid new_public_key: must be base64-encoded SPKI P-256 public key', 400, cors);
  }

  // Validate new wrapped_data_key
  if (!new_wrapped_data_key || typeof new_wrapped_data_key !== 'string' || new_wrapped_data_key.length === 0) {
    return errorResponse('new_wrapped_data_key is required', 400, cors);
  }

  // Check new_credential_lookup_key not already in use
  const conflict = await env.DB.prepare(
    'SELECT 1 FROM accounts WHERE credential_lookup_key = ?1'
  ).bind(new_credential_lookup_key).first();
  if (conflict) {
    return errorResponse('new_credential_lookup_key already in use', 409, cors);
  }

  // Read current account (need rules_json and app to preserve them)
  const current = await env.DB.prepare(
    'SELECT credential_lookup_key, rules_json, app FROM accounts WHERE data_lookup_key = ?1'
  ).bind(auth.data_lookup_key).first();
  if (!current) {
    return errorResponse('Account not found', 404, cors);
  }

  // PK change: delete old row + insert new (SQLite doesn't support UPDATE of PK).
  // NOTE: There is a small race window here. A concurrent handleChallenge using the old
  // credential_lookup_key could receive a nonce, but by the time handleVerify runs, the
  // row is gone and the user gets a 401. This is acceptable — the user simply re-logs in
  // with the new credentials. The probability is very low (requires two devices changing
  // credentials and logging in within the same D1 batch window).
  await env.DB.batch([
    env.DB.prepare('DELETE FROM accounts WHERE credential_lookup_key = ?1').bind(current.credential_lookup_key),
    env.DB.prepare(
      'INSERT INTO accounts (credential_lookup_key, public_key, data_lookup_key, wrapped_data_key, app, rules_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)'
    ).bind(new_credential_lookup_key, new_public_key, auth.data_lookup_key, new_wrapped_data_key, current.app, current.rules_json, Date.now()),
  ]);

  // Persist new credential mapping to Arweave (non-blocking)
  persistCredentialBlob(ctx, env, new_credential_lookup_key, auth.data_lookup_key, new_wrapped_data_key, new_public_key, current.app);

  return jsonResponse({ ok: true }, 200, cors);
}

// ============ DELETE /api/v1/auth — Account Deletion ============

export async function handleDeleteAccount(request, env, ctx, cors) {
  const auth = await requireAuth(request, env);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') return errorResponse('Only user accounts can be deleted', 403, cors);

  // Find current account
  const account = await env.DB.prepare(
    'SELECT credential_lookup_key FROM accounts WHERE data_lookup_key = ?1'
  ).bind(auth.data_lookup_key).first();
  if (!account) {
    return errorResponse('Account not found', 404, cors);
  }

  // Find the credential mapping txid to tombstone
  const credEntry = await env.DB.prepare(
    "SELECT txid FROM entries WHERE lookup_key = ?1 AND type = 'cred' AND is_tombstone = 0 ORDER BY cached_at DESC LIMIT 1"
  ).bind(account.credential_lookup_key).first();

  // Delete account from D1
  await env.DB.prepare('DELETE FROM accounts WHERE data_lookup_key = ?1').bind(auth.data_lookup_key).run();

  // Write tombstone to Arweave (non-blocking)
  if (credEntry?.txid) {
    const tombstoneTags = [
      { name: 'App', value: 'tarn' },
      { name: 'Type', value: 'cred' },
      { name: 'Op', value: 'tombstone' },
      { name: 'Ref', value: credEntry.txid },
      { name: 'Lk', value: account.credential_lookup_key },
      { name: 'V', value: PROTOCOL_VERSION },
    ];

    ctx.waitUntil((async () => {
      try {
        const signingKey = env.APP_SIGNING_KEY;
        if (!signingKey) {
          console.warn('[tarn-api] APP_SIGNING_KEY not set — skipping tombstone upload');
          return;
        }
        const tombstoneBody = new TextEncoder().encode(JSON.stringify({ tombstone: true }));
        const { signedDataItem, txid } = await buildSignedDataItem(tombstoneBody, tombstoneTags, signingKey);
        await upsertWriteThrough(env.DB, txid, tombstoneTags);
        console.log(`[tarn-api] Account tombstone cached: ${txid}`);
        const turbo = await uploadSignedDataItem(signedDataItem);
        if (turbo.ok) {
          console.log(`[tarn-api] Account tombstone uploaded to Turbo: ${txid}`);
        }
      } catch (err) {
        console.error('[tarn-api] Account tombstone upload error:', err.message);
      }
    })());
  }

  return jsonResponse({ ok: true, deleted: true }, 200, cors);
}
