// Account-key Model B retrieval (Phase 3, RECOVERY_PLAN.md).
//
// GET /api/v1/account/account-key
//
// Returns the wrapped account-key ciphertext + everything the client needs
// to derive the recovery_lookup_key for the wrap-pinning check on the
// decrypted plaintext. The wrap is opaque to the server; decryption is
// strictly client-side.
//
// Auth: BOTH a session JWT (Authorization: Bearer …) AND a single-use
// step-up token (X-Step-Up-Token header). Either missing → 401. The session
// proves the caller is logged in to *some* account; the step-up token
// proves a fresh password re-entry on this device. Both bind to the same
// data_lookup_key — we explicitly cross-check.
//
// Audit: every successful fetch writes a row to `account_key_fetch_log`
// (data_lookup_key, fetched_at, ip_hash, user_agent) so the SDK / app
// surface can later render "your account key was last viewed at X".

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { consumeStepUpToken, STEP_UP_SCOPE_ACCOUNT_KEY_FETCH } from './auth.js';

async function hashIp(ip) {
  if (!ip) return null;
  const data = new TextEncoder().encode(ip + '-tarn-account-key-audit-salt');
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .slice(0, 8)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function handleGetAccountKey(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') {
    return errorResponse('Only user accounts can fetch the account key', 403, cors);
  }

  const stepUpToken = request.headers.get('X-Step-Up-Token');
  if (!stepUpToken) {
    return errorResponse('Step-up token required', 401, cors);
  }
  const consumed = await consumeStepUpToken(env, stepUpToken, STEP_UP_SCOPE_ACCOUNT_KEY_FETCH);
  if (!consumed) {
    return errorResponse('Invalid or expired step-up token', 401, cors);
  }
  // The step-up token must belong to the same account as the JWT — defense
  // in depth against a JWT/token cross-binding mismatch (e.g., one user's
  // JWT paired with another user's leaked step-up token).
  if (consumed.data_lookup_key !== auth.data_lookup_key) {
    return errorResponse('Step-up token does not match session', 401, cors);
  }

  const row = await env.DB.prepare(
    `SELECT wrapped_account_key, wrapped_data_key, recovery_lookup_key
       FROM accounts
      WHERE data_lookup_key = ?1`
  ).bind(auth.data_lookup_key).first();
  if (!row) {
    return errorResponse('Account not found', 404, cors);
  }
  if (row.wrapped_account_key == null) {
    // Model A account — no backup stored. The SDK uses this 404 to render
    // the "no backup stored" Settings affordance instead of "view your key".
    return jsonResponse({ error: 'no_account_key_stored' }, 404, cors);
  }

  // Audit log. Best-effort — a D1 hiccup must not block the user from seeing
  // their own account key.
  ctx.waitUntil((async () => {
    try {
      const ip = request.headers.get('CF-Connecting-IP') || null;
      const ipHash = await hashIp(ip);
      const userAgent = (request.headers.get('User-Agent') || '').slice(0, 256) || null;
      await env.DB.prepare(
        'INSERT INTO account_key_fetch_log (data_lookup_key, fetched_at, ip_hash, user_agent) VALUES (?1, ?2, ?3, ?4)'
      ).bind(auth.data_lookup_key, Date.now(), ipHash, userAgent).run();
    } catch (err) {
      console.warn('[tarn-api] account_key_fetch_log insert failed:', err.message);
    }
  })());

  // Return everything the client needs to derive recovery_KEK for the
  // wrap-pinning check after decryption. recovery_salt + kdf_params live
  // inside the wrapped_data_key envelope's `recovery` block — return them
  // top-level here so the client doesn't have to re-parse the envelope just
  // to read them.
  let recoverySalt = null;
  let kdfParams = null;
  try {
    const env_ = JSON.parse(row.wrapped_data_key);
    if (env_ && env_.recovery) {
      recoverySalt = env_.recovery.salt ?? null;
      kdfParams = env_.recovery.kdf_params ?? null;
    }
  } catch {
    // Envelope shape isn't required for the wrap fetch; the client can
    // re-parse from the next /auth/verify if needed.
  }

  return jsonResponse({
    wrapped_account_key: row.wrapped_account_key,
    recovery_salt: recoverySalt,
    kdf_params: kdfParams,
    recovery_lookup_key: row.recovery_lookup_key ?? null,
  }, 200, cors);
}
