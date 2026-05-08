// Account-key Model B retrieval + Phase 4 toggle / rotation endpoints.
//
// GET    /api/v1/account/account-key            — Phase 3, fetch (Model B)
// PUT    /api/v1/account/account-key            — Phase 4, enable storage (Model A → B)
// DELETE /api/v1/account/account-key            — Phase 4, disable storage (Model B → A)
// POST   /api/v1/account/rotate-account-key     — Phase 4, rotate the account key
//
// Common shape:
//   - All four endpoints require BOTH a session JWT (Authorization: Bearer)
//     AND a single-use step-up token (X-Step-Up-Token header). Either missing → 401.
//   - Phase 4.1: rotate-account-key was originally JWT-only (the rationale was
//     that client-side friction — the user just generated a new phrase — was
//     enough). That reasoning is incomplete: client-side friction does nothing
//     against a session-hijack attacker who calls the endpoint directly. A
//     stolen JWT was sufficient to permanently destroy the user's recovery
//     factor. Step-up brings rotate symmetric with view/enable/disable and
//     raises the bar from "any session theft" to "session theft + password
//     phish".
//
// All write endpoints publish a fresh credential blob to Arweave after the
// D1 commit (best-effort in waitUntil) so the "Tarn infra is rebuildable
// from Arweave" property holds. Audit-log rows are written to
// `account_key_fetch_log` (despite the historical name, it now carries
// `op IN ('fetch','enable','disable','rotate')` after migration 0017).

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { consumeStepUpToken, STEP_UP_SCOPE_ACCOUNT_KEY_FETCH, buildCredentialTags } from './auth.js';
import { importPublicKey, isValidHex64 } from '../crypto.js';
import { buildSignedDataItem, uploadSignedDataItem } from '../turbo.js';
import { upsertWriteThrough, markLookupBootstrapped } from '../cache.js';

async function hashIp(ip) {
  if (!ip) return null;
  const data = new TextEncoder().encode(ip + '-tarn-account-key-audit-salt');
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .slice(0, 8)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Best-effort audit-log write. Mirrors the Phase 3 fetch path: any D1
 * hiccup must NOT fail the user-visible operation, so this runs in
 * waitUntil and swallows errors with a console warning.
 */
function writeAudit(ctx, env, request, dataLookupKey, op) {
  ctx.waitUntil((async () => {
    try {
      const ip = request.headers.get('CF-Connecting-IP') || null;
      const ipHash = await hashIp(ip);
      const userAgent = (request.headers.get('User-Agent') || '').slice(0, 256) || null;
      await env.DB.prepare(
        'INSERT INTO account_key_fetch_log (data_lookup_key, fetched_at, ip_hash, user_agent, op) VALUES (?1, ?2, ?3, ?4, ?5)'
      ).bind(dataLookupKey, Date.now(), ipHash, userAgent, op).run();
    } catch (err) {
      console.warn(`[tarn-api] account_key_fetch_log insert failed (op=${op}):`, err.message);
    }
  })());
}

/**
 * Validate a wrapped_account_key field with the same rules as the
 * registration path (Phase 3): base64 string, 100..1024 chars. Used by
 * both the PUT toggle and the rotate endpoint.
 *
 * Returns null when valid, or an error string when not.
 */
function validateWrappedAccountKey(wrap) {
  if (typeof wrap !== 'string') {
    return 'wrapped_account_key must be a string';
  }
  if (wrap.length < 100 || wrap.length > 1024) {
    return 'Invalid wrapped_account_key: implausible length';
  }
  if (!/^[A-Za-z0-9+/=_-]+$/.test(wrap)) {
    return 'Invalid wrapped_account_key: must be base64 / base64url';
  }
  return null;
}

/**
 * Republish the credential mapping blob to Arweave with the current
 * accounts row state. Phase 4 endpoints call this after every successful
 * D1 commit so the Arweave-side rebuild path stays in sync. Best-effort
 * (waitUntil); a Turbo failure does not roll back D1.
 *
 * The shape of the blob mirrors persistCredentialBlob in routes/auth.js
 * but without the optional sharing-fields plumbing (sharing fields are
 * read straight from the row).
 */
function persistCredentialBlobFromRow(ctx, env, row) {
  const blob = {
    data_lookup_key: row.data_lookup_key,
    wrapped_data_key: row.wrapped_data_key,
    public_key: row.public_key,
    app: row.app,
  };
  if (row.recovery_lookup_key) blob.recovery_lookup_key = row.recovery_lookup_key;
  if (row.recovery_public_key) blob.recovery_public_key = row.recovery_public_key;
  if (row.share_pub) blob.share_pub = row.share_pub;
  if (row.share_pub) blob.share_discoverable = row.share_discoverable === 1;
  if (row.share_lookup_key) blob.share_lookup_key = row.share_lookup_key;
  if (row.wrapped_account_key) blob.wrapped_account_key = row.wrapped_account_key;

  // Dual-tag with Lk (credential_lookup_key) + RLk (recovery_lookup_key when
  // present) — see buildCredentialTags in auth.js for rationale.
  const tags = buildCredentialTags(row.credential_lookup_key, row.recovery_lookup_key);

  ctx.waitUntil((async () => {
    try {
      const signingKey = env.APP_SIGNING_KEY;
      if (!signingKey) {
        console.warn('[tarn-api] APP_SIGNING_KEY not set — skipping Arweave republish');
        return;
      }
      const blobBytes = new TextEncoder().encode(JSON.stringify(blob));
      const { signedDataItem, txid } = await buildSignedDataItem(blobBytes, tags, signingKey);
      await upsertWriteThrough(env.DB, txid, tags);
      await markLookupBootstrapped(env.DB, row.credential_lookup_key, 'tarn', 'cred');
      console.log(`[tarn-api] Account-key republish cached: ${txid}`);
      const turbo = await uploadSignedDataItem(signedDataItem);
      if (turbo.ok) {
        console.log(`[tarn-api] Account-key republish uploaded to Turbo: ${txid}`);
      } else {
        console.warn(`[tarn-api] Account-key republish Turbo upload failed: ${turbo.status} ${turbo.body}`);
      }
    } catch (err) {
      console.error('[tarn-api] Account-key republish error:', err.message);
    }
  })());
}

// ============ GET /api/v1/account/account-key (Phase 3) ============

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
    return jsonResponse({ error: 'no_account_key_stored' }, 404, cors);
  }

  writeAudit(ctx, env, request, auth.data_lookup_key, 'fetch');

  let recoverySalt = null;
  let kdfParams = null;
  try {
    const env_ = JSON.parse(row.wrapped_data_key);
    if (env_ && env_.recovery) {
      recoverySalt = env_.recovery.salt ?? null;
      kdfParams = env_.recovery.kdf_params ?? null;
    }
  } catch {
    // Envelope shape isn't required for the wrap fetch.
  }

  return jsonResponse({
    wrapped_account_key: row.wrapped_account_key,
    recovery_salt: recoverySalt,
    kdf_params: kdfParams,
    recovery_lookup_key: row.recovery_lookup_key ?? null,
  }, 200, cors);
}

// ============ PUT /api/v1/account/account-key (Phase 4 — enable storage) ============
//
// Toggle Model A → Model B. The caller must include a fresh step-up token
// (proves the user just re-entered their password — which they need anyway
// to derive the gen-1 DEK that produced the wrap). The wrap is opaque
// ciphertext stored verbatim; decryption is impossible server-side.
//
// If `wrapped_account_key` is already set, this is treated as an overwrite
// (the user re-entered the phrase and computed a fresh wrap). Documented in
// TARN_PROTOCOL.md so apps know calling PUT twice is not an error.

export async function handlePutAccountKey(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') {
    return errorResponse('Only user accounts can enable account-key storage', 403, cors);
  }

  const stepUpToken = request.headers.get('X-Step-Up-Token');
  if (!stepUpToken) {
    return errorResponse('Step-up token required', 401, cors);
  }
  const consumed = await consumeStepUpToken(env, stepUpToken, STEP_UP_SCOPE_ACCOUNT_KEY_FETCH);
  if (!consumed) {
    return errorResponse('Invalid or expired step-up token', 401, cors);
  }
  if (consumed.data_lookup_key !== auth.data_lookup_key) {
    return errorResponse('Step-up token does not match session', 401, cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }
  const { wrapped_account_key } = body || {};
  if (wrapped_account_key == null) {
    return errorResponse('wrapped_account_key is required', 400, cors);
  }
  const wrapErr = validateWrappedAccountKey(wrapped_account_key);
  if (wrapErr) return errorResponse(wrapErr, 400, cors);

  // Update + read back in one shot so we have the full row for the
  // Arweave republish below.
  const update = await env.DB.prepare(
    `UPDATE accounts
        SET wrapped_account_key = ?2
      WHERE data_lookup_key = ?1
      RETURNING credential_lookup_key, public_key, wrapped_data_key, app,
                recovery_lookup_key, recovery_public_key,
                share_pub, share_discoverable, share_lookup_key,
                wrapped_account_key, data_lookup_key`
  ).bind(auth.data_lookup_key, wrapped_account_key).first();
  if (!update) {
    return errorResponse('Account not found', 404, cors);
  }

  writeAudit(ctx, env, request, auth.data_lookup_key, 'enable');
  persistCredentialBlobFromRow(ctx, env, update);

  return jsonResponse({ stored: true }, 200, cors);
}

// ============ DELETE /api/v1/account/account-key (Phase 4 — disable storage) ============
//
// Toggle Model B → Model A. Same auth posture as PUT (JWT + step-up).
// Idempotent: deleting the wrap on an already-Model-A account returns
// 200 OK with `{ stored: false, already_disabled: true }` rather than 404
// — the caller's intent ("ensure no wrap is stored") is satisfied either
// way and an error would force every UI to special-case it.

export async function handleDeleteAccountKey(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') {
    return errorResponse('Only user accounts can disable account-key storage', 403, cors);
  }

  const stepUpToken = request.headers.get('X-Step-Up-Token');
  if (!stepUpToken) {
    return errorResponse('Step-up token required', 401, cors);
  }
  const consumed = await consumeStepUpToken(env, stepUpToken, STEP_UP_SCOPE_ACCOUNT_KEY_FETCH);
  if (!consumed) {
    return errorResponse('Invalid or expired step-up token', 401, cors);
  }
  if (consumed.data_lookup_key !== auth.data_lookup_key) {
    return errorResponse('Step-up token does not match session', 401, cors);
  }

  // Read-then-update so we can short-circuit the idempotent path without a
  // pointless write + Arweave republish.
  const existing = await env.DB.prepare(
    `SELECT wrapped_account_key
       FROM accounts
      WHERE data_lookup_key = ?1`
  ).bind(auth.data_lookup_key).first();
  if (!existing) {
    return errorResponse('Account not found', 404, cors);
  }
  if (existing.wrapped_account_key == null) {
    // Already in Model A — no-op success.
    return jsonResponse({ stored: false, already_disabled: true }, 200, cors);
  }

  const update = await env.DB.prepare(
    `UPDATE accounts
        SET wrapped_account_key = NULL
      WHERE data_lookup_key = ?1
      RETURNING credential_lookup_key, public_key, wrapped_data_key, app,
                recovery_lookup_key, recovery_public_key,
                share_pub, share_discoverable, share_lookup_key,
                wrapped_account_key, data_lookup_key`
  ).bind(auth.data_lookup_key).first();
  if (!update) {
    // Account vanished between the read and the write (delete-account race).
    return errorResponse('Account not found', 404, cors);
  }

  writeAudit(ctx, env, request, auth.data_lookup_key, 'disable');
  persistCredentialBlobFromRow(ctx, env, update);

  return jsonResponse({ stored: false }, 200, cors);
}

// ============ POST /api/v1/account/rotate-account-key (Phase 4) ============
//
// Atomically swap the recovery factor on an account. The caller has
// generated a fresh account key client-side, derived all the dependent
// values (recovery_lookup_key, recovery_public_key, recovery_KEK), and
// re-wrapped every gen of the DEK chain. We just commit the bundle.
//
// Auth posture (Phase 4.1): JWT + step-up token, symmetric with the
// view/enable/disable endpoints. Closes the session-hijack gap that the
// JWT-only posture left open — without step-up, a stolen JWT was enough
// to overwrite the recovery factor with attacker-controlled values and
// permanently brick the user's saved account key.
//
// Atomicity: D1 batch updates wrapped_data_key, recovery_lookup_key,
// recovery_public_key, and wrapped_account_key together. Either all four
// land or none do.
//
// Conflict handling: 409 if the new recovery_lookup_key collides with
// another account (mirrors the changeCredentials path).

export async function handleRotateAccountKey(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') {
    return errorResponse('Only user accounts can rotate the account key', 403, cors);
  }

  const stepUpToken = request.headers.get('X-Step-Up-Token');
  if (!stepUpToken) {
    return errorResponse('Step-up token required', 401, cors);
  }
  const consumed = await consumeStepUpToken(env, stepUpToken, STEP_UP_SCOPE_ACCOUNT_KEY_FETCH);
  if (!consumed) {
    return errorResponse('Invalid or expired step-up token', 401, cors);
  }
  if (consumed.data_lookup_key !== auth.data_lookup_key) {
    return errorResponse('Step-up token does not match session', 401, cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const {
    new_envelope,
    new_recovery_lookup_key,
    new_recovery_public_key,
    new_wrapped_account_key,
  } = body || {};

  if (!new_envelope || typeof new_envelope !== 'string' || new_envelope.length === 0) {
    return errorResponse('new_envelope is required', 400, cors);
  }
  if (!isValidHex64(new_recovery_lookup_key)) {
    return errorResponse('Invalid new_recovery_lookup_key: must be 64-char lowercase hex', 400, cors);
  }
  try {
    await importPublicKey(new_recovery_public_key);
  } catch {
    return errorResponse('Invalid new_recovery_public_key: must be base64-encoded SPKI P-256 public key', 400, cors);
  }
  // new_wrapped_account_key is OPTIONAL: present iff the account is in
  // Model B at rotation time. Null / omitted explicitly leaves the wrap
  // null in D1 (Model A stays Model A).
  if (new_wrapped_account_key != null) {
    const wrapErr = validateWrappedAccountKey(new_wrapped_account_key);
    if (wrapErr) return errorResponse(wrapErr, 400, cors);
  }

  // Read the current row so we can detect "no actual change" + collision
  // with an OTHER account (vs. our own current value, which is a no-op).
  const current = await env.DB.prepare(
    `SELECT credential_lookup_key, public_key, wrapped_data_key, app,
            recovery_lookup_key, recovery_public_key,
            share_pub, share_discoverable, share_lookup_key,
            wrapped_account_key, data_lookup_key
       FROM accounts
      WHERE data_lookup_key = ?1`
  ).bind(auth.data_lookup_key).first();
  if (!current) {
    return errorResponse('Account not found', 404, cors);
  }
  // The caller MUST NOT submit credential_lookup_key as the new recovery
  // lookup (mirrors the register / changeCredentials invariant — the two
  // identifier spaces must stay disjoint per account).
  if (new_recovery_lookup_key === current.credential_lookup_key) {
    return errorResponse('new_recovery_lookup_key must differ from credential_lookup_key', 400, cors);
  }

  // Up-front uniqueness check: the new recovery_lookup_key must not be
  // taken by any OTHER account. (Same value as our own current is fine —
  // it's a no-op rotation, and the UNIQUE constraint on the column allows
  // it because we're rewriting our own row.)
  if (new_recovery_lookup_key !== current.recovery_lookup_key) {
    const conflict = await env.DB.prepare(
      'SELECT 1 FROM accounts WHERE recovery_lookup_key = ?1'
    ).bind(new_recovery_lookup_key).first();
    if (conflict) {
      return errorResponse('new_recovery_lookup_key already in use', 409, cors);
    }
  }

  // D1 batch — single statement update against one row is already atomic;
  // the explicit batch here is to keep the call structurally consistent
  // with multi-row operations elsewhere (e.g. credential change). All four
  // fields land in one statement, so there is no partial-state window.
  let update;
  try {
    update = await env.DB.prepare(
      `UPDATE accounts
          SET wrapped_data_key       = ?2,
              recovery_lookup_key    = ?3,
              recovery_public_key    = ?4,
              wrapped_account_key    = ?5
        WHERE data_lookup_key = ?1
        RETURNING credential_lookup_key, public_key, wrapped_data_key, app,
                  recovery_lookup_key, recovery_public_key,
                  share_pub, share_discoverable, share_lookup_key,
                  wrapped_account_key, data_lookup_key`
    ).bind(
      auth.data_lookup_key,
      new_envelope,
      new_recovery_lookup_key,
      new_recovery_public_key,
      new_wrapped_account_key ?? null,
    ).first();
  } catch (err) {
    // UNIQUE constraint on recovery_lookup_key — another account raced us.
    if (/UNIQUE/i.test(err.message || '')) {
      return errorResponse('new_recovery_lookup_key already in use', 409, cors);
    }
    throw err;
  }
  if (!update) {
    return errorResponse('Account not found', 404, cors);
  }

  writeAudit(ctx, env, request, auth.data_lookup_key, 'rotate');
  persistCredentialBlobFromRow(ctx, env, update);

  return jsonResponse({ rotated: true }, 200, cors);
}
