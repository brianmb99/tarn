// Invite-token endpoints (Section 8, issue #22).
//
// Five routes:
//   POST   /api/v1/invite                              user-role auth
//   GET    /api/v1/invite/:token_id                    unauthenticated
//   POST   /api/v1/invite/redeem/:token_id             user-role auth
//   DELETE /api/v1/invite/:token_id                    user-role auth (inviter only)
//   GET    /api/v1/apps/:app_id/invite-template        unauthenticated
//
// The server stores opaque ciphertext, never the payload key — every privacy
// property in this section is enforced client-side. Atomic single-use is
// enforced by the redeem UPDATE; rate limits follow the existing patterns.

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { checkAndIncrementRateLimit } from '../rate-limit.js';
import {
  validateTokenId,
  validateExpiresAt,
  validatePayload,
  validateFingerprint,
  createInviteRow,
  previewInvite,
  redeemInvite,
  pruneExpiredInvites,
  MAX_PAYLOAD_BYTES,
} from '../invites.js';

const MAX_INVITE_CREATE_PER_HOUR = 10;
const MAX_INVITE_REDEEM_PER_HOUR = 50;
const MAX_INVITE_PREVIEW_PER_HOUR = 100;

function decodeBase64(str) {
  if (typeof str !== 'string' || str.length === 0) return null;
  try {
    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

async function ipHash(request) {
  // Hash the IP so the rate-limit key isn't a raw PII identifier in KV. Same
  // pattern as share-inbox fetch.
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const data = new TextEncoder().encode(ip + '-tarn-invite-preview-salt');
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).slice(0, 8)
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkInviteCreateRateLimit(env, dlk) {
  const hour = new Date().toISOString().slice(0, 13);
  const key = `invite-create:${dlk}:${hour}`;
  const expiresAt = Date.now() + 3600_000;
  try {
    const row = await env.DB.prepare(`
      INSERT INTO write_rate_limits (key, count, expires_at)
      VALUES (?1, 1, ?2)
      ON CONFLICT(key) DO UPDATE SET count = count + 1
      RETURNING count
    `).bind(key, expiresAt).first();
    const count = row?.count ?? 1;
    return { allowed: count <= MAX_INVITE_CREATE_PER_HOUR };
  } catch (err) {
    console.warn('[invites] create rate-limit lookup failed:', err?.message || err);
    return { allowed: true };
  }
}

async function checkInviteRedeemRateLimit(env, dlk) {
  const hour = new Date().toISOString().slice(0, 13);
  const key = `invite-redeem:${dlk}:${hour}`;
  const expiresAt = Date.now() + 3600_000;
  try {
    const row = await env.DB.prepare(`
      INSERT INTO write_rate_limits (key, count, expires_at)
      VALUES (?1, 1, ?2)
      ON CONFLICT(key) DO UPDATE SET count = count + 1
      RETURNING count
    `).bind(key, expiresAt).first();
    const count = row?.count ?? 1;
    return { allowed: count <= MAX_INVITE_REDEEM_PER_HOUR };
  } catch (err) {
    console.warn('[invites] redeem rate-limit lookup failed:', err?.message || err);
    return { allowed: true };
  }
}

// ============ POST /api/v1/invite ============

export async function handleCreateInvite(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') return errorResponse('Only user accounts can create invites', 403, cors);

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { token_id, app_id, payload, expires_at } = body || {};
  if (!validateTokenId(token_id)) {
    return errorResponse('token_id must be 43 chars of base64url', 400, cors);
  }
  if (typeof app_id !== 'string' || app_id.length === 0) {
    return errorResponse('app_id is required', 400, cors);
  }
  // Bind invite to the JWT's app — a user authenticated for app A cannot
  // create an invite scoped to app B.
  if (auth.app && app_id !== auth.app) {
    return errorResponse('app_id must match the authenticated app', 403, cors);
  }

  const payloadBytes = decodeBase64(payload);
  if (!payloadBytes) {
    return errorResponse('payload must be base64', 400, cors);
  }
  if (payloadBytes.byteLength > MAX_PAYLOAD_BYTES) {
    return errorResponse(`payload exceeds ${MAX_PAYLOAD_BYTES} bytes`, 413, cors);
  }
  if (!validatePayload(payloadBytes)) {
    return errorResponse('payload must be 1..4096 bytes', 400, cors);
  }

  const now = Math.floor(Date.now() / 1000);
  if (!validateExpiresAt(now, expires_at)) {
    return errorResponse('expires_at must be in (now, now + 30 days]', 400, cors);
  }

  // Per-inviter create rate limit (D1-atomic, same pattern as share-inbox).
  const limit = await checkInviteCreateRateLimit(env, auth.data_lookup_key);
  if (!limit.allowed) {
    return errorResponse('Invite create rate limit exceeded', 429, { ...cors, 'Retry-After': '3600' });
  }

  try {
    await createInviteRow(env, {
      token_id,
      app_id,
      inviter_dlk: auth.data_lookup_key,
      payload: payloadBytes,
      expires_at,
      now,
    });
  } catch (err) {
    if (err?.code === 'TOKEN_COLLISION') {
      return errorResponse('token_id already exists', 409, cors);
    }
    console.error('[invites] createInviteRow error:', err?.message || err);
    return errorResponse('Failed to create invite', 500, cors);
  }

  return jsonResponse({ token_id, expires_at }, 201, cors);
}

// ============ GET /api/v1/invite/:token_id (unauthenticated) ============

export async function handleGetInvite(request, env, token_id, cors) {
  if (!validateTokenId(token_id)) {
    return errorResponse('Invalid token_id', 400, cors);
  }

  // Per-IP preview rate limit (KV). Fails open per the existing pattern.
  const ipKey = `invite-preview:${await ipHash(request)}:${new Date().toISOString().slice(0, 13)}`;
  const { allowed } = await checkAndIncrementRateLimit(env.RATE_KV, ipKey, MAX_INVITE_PREVIEW_PER_HOUR);
  if (!allowed) {
    return errorResponse('Invite preview rate limit exceeded', 429, { ...cors, 'Retry-After': '3600' });
  }

  const now = Math.floor(Date.now() / 1000);
  const result = await previewInvite(env, token_id, now);
  if (result.status === 'not_found') return errorResponse('Invite not found', 404, cors);
  if (result.status === 'expired') return errorResponse('Invite expired', 410, cors);
  if (result.status === 'used') return errorResponse('Invite already used', 409, cors);

  return jsonResponse({
    app_id: result.app_id,
    payload: bytesToBase64(result.payload),
    issued_at: result.issued_at,
    expires_at: result.expires_at,
  }, 200, cors);
}

// ============ POST /api/v1/invite/redeem/:token_id ============

export async function handleRedeemInvite(request, env, ctx, token_id, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') return errorResponse('Only user accounts can redeem invites', 403, cors);
  if (!validateTokenId(token_id)) {
    return errorResponse('Invalid token_id', 400, cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }
  const fingerprint = body?.redeemer_share_pub_fingerprint;
  if (!validateFingerprint(fingerprint)) {
    return errorResponse('redeemer_share_pub_fingerprint must be hex+colons, 1..32 chars', 400, cors);
  }

  const limit = await checkInviteRedeemRateLimit(env, auth.data_lookup_key);
  if (!limit.allowed) {
    return errorResponse('Invite redeem rate limit exceeded', 429, { ...cors, 'Retry-After': '3600' });
  }

  const now = Math.floor(Date.now() / 1000);
  const result = await redeemInvite(env, { token_id, fingerprint, now });
  if (result.status === 'not_found') return errorResponse('Invite not found', 404, cors);
  if (result.status === 'expired') return errorResponse('Invite expired', 410, cors);
  if (result.status === 'used') return errorResponse('Invite already used', 409, cors);

  // Fire-and-forget cleanup on ~5% of redeems. Same probabilistic pattern as
  // checkWriteRateLimit; cheap because the table is small and the index on
  // expires_at is selective.
  if (Math.random() < 0.05 && ctx && typeof ctx.waitUntil === 'function') {
    ctx.waitUntil(pruneExpiredInvites(env, now));
  }

  return jsonResponse({
    app_id: result.app_id,
    payload: bytesToBase64(result.payload),
    issued_at: result.issued_at,
    expires_at: result.expires_at,
  }, 200, cors);
}

// ============ DELETE /api/v1/invite/:token_id ============

export async function handleRevokeInvite(request, env, ctx, token_id, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') return errorResponse('Only user accounts can revoke invites', 403, cors);
  if (!validateTokenId(token_id)) {
    return errorResponse('Invalid token_id', 400, cors);
  }

  // Scope by inviter_dlk so users can't revoke each other's invites; a 404
  // covers both "not yours" and "doesn't exist" without leaking existence.
  const result = await env.DB.prepare(
    'DELETE FROM invites WHERE token_id = ?1 AND inviter_dlk = ?2'
  ).bind(token_id, auth.data_lookup_key).run();
  const changes = result?.meta?.changes ?? result?.changes ?? 0;
  if (changes === 0) {
    return errorResponse('Invite not found', 404, cors);
  }
  return new Response(null, { status: 204, headers: cors });
}

// ============ GET /api/v1/apps/:app_id/invite-template (unauthenticated) ============

export async function handleGetAppInviteTemplate(request, env, app_id, cors) {
  if (typeof app_id !== 'string' || app_id.length === 0) {
    return errorResponse('Invalid app_id', 400, cors);
  }
  const row = await env.DB.prepare(
    'SELECT invite_url_template FROM apps WHERE app_id = ?1'
  ).bind(app_id).first();
  if (!row) {
    return errorResponse('App not found', 404, cors);
  }
  return jsonResponse({ invite_url_template: row.invite_url_template ?? null }, 200, cors);
}

function bytesToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
