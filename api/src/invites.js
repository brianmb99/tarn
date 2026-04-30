// Invite tokens — server-side helpers (Section 8, issue #22).
//
// Server stores opaque AES-GCM ciphertext keyed on a 256-bit token_id. Atomic
// single-use is enforced by the redeem UPDATE (used_at IS NULL AND expires_at
// > now); the row is mutated, not deleted, so a follow-up SELECT can
// disambiguate 409 vs 410 vs 404 for the loser of a concurrent redeem.
//
// Lazy cleanup follows the auth_nonces / write_rate_limits precedent: expired
// rows are filtered out on read; opportunistic DELETE runs on ~5% of redeems.
// No cron, no separate worker.

export const MAX_PAYLOAD_BYTES = 4096;
export const MAX_EXPIRY_DAYS = 30;
export const DEFAULT_EXPIRY_DAYS = 7;
export const MAX_DISPLAY_NAME_LEN = 64;
export const MAX_FINGERPRINT_LEN = 32;

const SECONDS_PER_DAY = 86400;
const TOKEN_ID_RE = /^[A-Za-z0-9_-]{43}$/;
const FINGERPRINT_RE = /^[0-9a-f:]+$/;

/**
 * `token_id` must be exactly 43 characters of base64url alphabet (no padding).
 * That's the canonical encoding of 32 random bytes.
 *
 * @param {unknown} tokenId
 * @returns {boolean}
 */
export function validateTokenId(tokenId) {
  return typeof tokenId === 'string' && TOKEN_ID_RE.test(tokenId);
}

/**
 * `expires_at` must be strictly in the future and at most 30 days out.
 * Both bounds are seconds — same convention as the rest of the protocol.
 *
 * @param {number} now - unix seconds
 * @param {unknown} expiresAt
 * @returns {boolean}
 */
export function validateExpiresAt(now, expiresAt) {
  if (!Number.isInteger(expiresAt)) return false;
  if (expiresAt <= now) return false;
  if (expiresAt > now + MAX_EXPIRY_DAYS * SECONDS_PER_DAY) return false;
  return true;
}

/**
 * Payload bytes (post-base64-decode) must be in the [1, 4096] range.
 * Empty payloads are rejected up front; the maximum is the wire-side cap from
 * the spec.
 *
 * @param {Uint8Array | null | undefined} bytes
 * @returns {boolean}
 */
export function validatePayload(bytes) {
  if (!(bytes instanceof Uint8Array)) return false;
  return bytes.byteLength >= 1 && bytes.byteLength <= MAX_PAYLOAD_BYTES;
}

/**
 * Fingerprint format is short hex with optional `:` separators
 * (e.g. "a3b9c7" or "a3:b9:c7"). Bounded length so it fits in the
 * `redeemer_share_pub_fingerprint` column without surprise.
 *
 * @param {unknown} fp
 * @returns {boolean}
 */
export function validateFingerprint(fp) {
  if (typeof fp !== 'string') return false;
  if (fp.length === 0 || fp.length > MAX_FINGERPRINT_LEN) return false;
  return FINGERPRINT_RE.test(fp);
}

/**
 * Insert a new invite row. Throws on PRIMARY KEY collision (token_id already
 * exists) so the caller can map to HTTP 409.
 *
 * @param {{ DB: D1Database }} env
 * @param {{
 *   token_id: string,
 *   app_id: string,
 *   inviter_dlk: string,
 *   payload: Uint8Array,
 *   expires_at: number,
 *   now: number,
 * }} args
 */
export async function createInviteRow(env, { token_id, app_id, inviter_dlk, payload, expires_at, now }) {
  try {
    await env.DB.prepare(
      'INSERT INTO invites (token_id, app_id, inviter_dlk, payload, issued_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)'
    ).bind(token_id, app_id, inviter_dlk, payload, now, expires_at).run();
  } catch (err) {
    const msg = err?.message || '';
    if (/UNIQUE|constraint|PRIMARY KEY/i.test(msg)) {
      const e = new Error('token_id already exists');
      e.code = 'TOKEN_COLLISION';
      throw e;
    }
    throw err;
  }
}

/**
 * Read an invite row. Returns the active row's preview-shape when present;
 * otherwise a discriminated `{ status }` so the route can pick the right HTTP
 * code. `used` and `expired` are distinguishable on the API surface (409 vs
 * 410) per the spec.
 *
 * @param {{ DB: D1Database }} env
 * @param {string} token_id
 * @param {number} now - unix seconds
 * @returns {Promise<
 *   | { status: 'active', app_id: string, payload: Uint8Array, issued_at: number, expires_at: number }
 *   | { status: 'expired' | 'used' | 'not_found' }
 * >}
 */
export async function previewInvite(env, token_id, now) {
  const row = await env.DB.prepare(
    'SELECT app_id, payload, issued_at, expires_at, used_at FROM invites WHERE token_id = ?1'
  ).bind(token_id).first();
  if (!row) return { status: 'not_found' };
  if (row.used_at != null) return { status: 'used' };
  if (row.expires_at <= now) return { status: 'expired' };
  const payload = row.payload instanceof Uint8Array
    ? row.payload
    : new Uint8Array(row.payload);
  return {
    status: 'active',
    app_id: row.app_id,
    payload,
    issued_at: row.issued_at,
    expires_at: row.expires_at,
  };
}

/**
 * Atomic single-use redeem. The UPDATE is the only mutation; if it changes
 * 0 rows the caller does a follow-up SELECT to disambiguate.
 *
 * Returns the active row's payload on success, or `{ status }` for the
 * three error modes.
 *
 * @param {{ DB: D1Database }} env
 * @param {{ token_id: string, fingerprint: string, now: number }} args
 * @returns {Promise<
 *   | { status: 'redeemed', app_id: string, payload: Uint8Array, issued_at: number, expires_at: number }
 *   | { status: 'expired' | 'used' | 'not_found' }
 * >}
 */
export async function redeemInvite(env, { token_id, fingerprint, now }) {
  const updated = await env.DB.prepare(
    `UPDATE invites
       SET used_at = ?1, redeemer_share_pub_fingerprint = ?2
     WHERE token_id = ?3 AND used_at IS NULL AND expires_at > ?4
     RETURNING app_id, payload, issued_at, expires_at`
  ).bind(now, fingerprint, token_id, now).first();
  if (updated) {
    const payload = updated.payload instanceof Uint8Array
      ? updated.payload
      : new Uint8Array(updated.payload);
    return {
      status: 'redeemed',
      app_id: updated.app_id,
      payload,
      issued_at: updated.issued_at,
      expires_at: updated.expires_at,
    };
  }
  // Disambiguate the failure mode for the caller. The row may have been
  // redeemed by a concurrent caller, or expired, or never existed.
  const row = await env.DB.prepare(
    'SELECT used_at, expires_at FROM invites WHERE token_id = ?1'
  ).bind(token_id).first();
  if (!row) return { status: 'not_found' };
  if (row.used_at != null) return { status: 'used' };
  if (row.expires_at <= now) return { status: 'expired' };
  // The row exists, isn't used, and isn't expired — but the UPDATE missed.
  // This shouldn't happen under normal operation; treat as not_found so the
  // client retries cleanly.
  return { status: 'not_found' };
}

/**
 * Delete every expired invite. Best-effort — swallowed errors so the calling
 * redeem path always returns success.
 *
 * @param {{ DB: D1Database }} env
 * @param {number} now - unix seconds
 */
export async function pruneExpiredInvites(env, now) {
  try {
    await env.DB.prepare('DELETE FROM invites WHERE expires_at < ?1').bind(now).run();
  } catch (err) {
    console.warn('[invites] pruneExpiredInvites failed:', err?.message || err);
  }
}

/**
 * Snapshot of active issued-but-unredeemed invites for a given inviter. Used
 * by the SDK's revoke flow to enforce server-side ownership before deleting.
 *
 * @param {{ DB: D1Database }} env
 * @param {string} dlk
 * @param {number} now - unix seconds
 */
export async function listIssuedInvitesForUser(env, dlk, now) {
  const rows = await env.DB.prepare(
    'SELECT token_id, app_id, issued_at, expires_at, used_at, redeemer_share_pub_fingerprint FROM invites WHERE inviter_dlk = ?1 AND expires_at > ?2 AND used_at IS NULL'
  ).bind(dlk, now).all();
  return rows.results || [];
}
