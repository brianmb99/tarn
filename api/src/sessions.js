// Server-side session management helpers (Section 7.5, issue #20).
//
// User-role JWTs carry a `sid` claim that maps 1:1 to a row in the `sessions`
// table. The auth middleware verifies the row exists on every authenticated
// request, amortized by a per-isolate 5-second cache. Revocation is just
// DELETE FROM sessions; the cached entry is invalidated on the originating
// isolate immediately, and other isolates serve stale until the 5s TTL elapses.
//
// App-role JWTs are stateless (no sid) and bypass everything in this module.

export const MAX_DEVICE_LABEL_LEN = 64;
const STALE_SESSION_CUTOFF_SECONDS = 24 * 60 * 60; // 24h
const LAST_SEEN_REFRESH_SECONDS = 60;

let SESSION_CACHE_TTL_MS = 5_000;
const _sessionCache = new Map(); // sid -> { active: boolean, cachedAt: number }

/**
 * Validate an optional device_label string. Returns null if absent/valid;
 * otherwise an error message suitable for a 400 response. Rejects non-strings,
 * lengths over MAX_DEVICE_LABEL_LEN, and any control character (codepoint
 * < 0x20). Empty string is treated as "unset" — null on the way in.
 */
export function validateDeviceLabel(label) {
  if (label == null || label === '') return null;
  if (typeof label !== 'string') return 'device_label must be a string';
  if (label.length > MAX_DEVICE_LABEL_LEN) {
    return `device_label exceeds ${MAX_DEVICE_LABEL_LEN} characters`;
  }
  for (let i = 0; i < label.length; i++) {
    if (label.charCodeAt(i) < 0x20) {
      return 'device_label contains control characters';
    }
  }
  return null;
}

/**
 * Lazy-prune sessions for a given data_lookup_key. Deletes rows whose
 * last_seen_at is older than `nowSeconds - 24h`. Called at the start of
 * /auth/verify so an active user's table stays bounded; an inactive user
 * gets a clean slate next time they log in.
 */
export async function pruneStaleSessions(env, dlk, nowSeconds) {
  const cutoff = nowSeconds - STALE_SESSION_CUTOFF_SECONDS;
  await env.DB.prepare(
    'DELETE FROM sessions WHERE data_lookup_key = ?1 AND last_seen_at < ?2'
  ).bind(dlk, cutoff).run();
}

/**
 * Mint a new sid (UUID v4) or reuse an active one for the same dlk if
 * `previousSid` is supplied and still present. Reuse path bumps last_seen_at
 * to keep the row from being lazy-pruned. Insert path creates a new row
 * with created_at = last_seen_at = nowSeconds.
 */
export async function createOrReuseSession(env, { dlk, app, deviceLabel, viaRecovery, previousSid, nowSeconds }) {
  if (previousSid) {
    const existing = await env.DB.prepare(
      'SELECT sid FROM sessions WHERE sid = ?1 AND data_lookup_key = ?2'
    ).bind(previousSid, dlk).first();
    if (existing) {
      await env.DB.prepare(
        'UPDATE sessions SET last_seen_at = ?1 WHERE sid = ?2'
      ).bind(nowSeconds, previousSid).run();
      // Refresh the cache: this isolate just confirmed the row is active.
      _sessionCache.set(previousSid, { active: true, cachedAt: Date.now() });
      return previousSid;
    }
  }

  const sid = crypto.randomUUID();
  await env.DB.prepare(
    'INSERT INTO sessions (sid, data_lookup_key, app, created_at, last_seen_at, device_label, via_recovery) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)'
  ).bind(
    sid,
    dlk,
    app || '',
    nowSeconds,
    nowSeconds,
    deviceLabel || null,
    viaRecovery ? 1 : 0,
  ).run();
  _sessionCache.set(sid, { active: true, cachedAt: Date.now() });
  return sid;
}

/**
 * Delete every session row for a given account. Used by deleteAccount where
 * the account itself is going away.
 *
 * For changeCredentials / recoverAccount, prefer deleteOtherSessionsForAccount
 * — the calling session must survive the request because the SDK still has
 * follow-up work to do under the same JWT (publishing rotate_identity
 * announcements to each connection's outbound log) before it re-authenticates
 * under the new credentials. Killing the calling sid inside the request that
 * triggered the rotation 401s those follow-up writes.
 */
export async function deleteAllSessionsForAccount(env, dlk) {
  // Snapshot the sids first so we can invalidate cache entries on this isolate.
  // The cross-isolate stale window is bounded by SESSION_CACHE_TTL_MS.
  const rows = await env.DB.prepare(
    'SELECT sid FROM sessions WHERE data_lookup_key = ?1'
  ).bind(dlk).all();
  await env.DB.prepare(
    'DELETE FROM sessions WHERE data_lookup_key = ?1'
  ).bind(dlk).run();
  for (const row of rows.results || []) {
    _sessionCache.set(row.sid, { active: false, cachedAt: Date.now() });
  }
}

/**
 * Delete every session row for a given account EXCEPT the supplied sid.
 * Used by changeCredentials / recoverAccount to revoke other devices while
 * keeping the calling session alive for follow-up work (rotate_identity
 * announcements). The SDK's subsequent re-auth under the new credentials
 * mints a fresh sid; the surviving exceptSid eventually expires via lazy
 * prune.
 */
export async function deleteOtherSessionsForAccount(env, dlk, exceptSid) {
  if (!exceptSid) {
    // Defensive: if for some reason we have no calling sid (pre-7.5 grandfather
    // path), fall back to deleting everything — there's no calling session to
    // preserve.
    return deleteAllSessionsForAccount(env, dlk);
  }
  const rows = await env.DB.prepare(
    'SELECT sid FROM sessions WHERE data_lookup_key = ?1 AND sid != ?2'
  ).bind(dlk, exceptSid).all();
  await env.DB.prepare(
    'DELETE FROM sessions WHERE data_lookup_key = ?1 AND sid != ?2'
  ).bind(dlk, exceptSid).run();
  for (const row of rows.results || []) {
    _sessionCache.set(row.sid, { active: false, cachedAt: Date.now() });
  }
}

/**
 * Check whether a sid is active. Hits the per-isolate cache first; on miss
 * (or stale) does a single SELECT and updates the cache. The 5-second TTL
 * caps cross-isolate revocation latency.
 */
export async function isSessionActive(env, sid, nowMs) {
  const cached = _sessionCache.get(sid);
  if (cached && cached.cachedAt > nowMs - SESSION_CACHE_TTL_MS) {
    return cached.active;
  }
  const row = await env.DB.prepare(
    'SELECT sid, last_seen_at FROM sessions WHERE sid = ?1'
  ).bind(sid).first();
  const active = !!row;
  _sessionCache.set(sid, { active, cachedAt: nowMs, lastSeenAt: row?.last_seen_at ?? null });
  return active;
}

/**
 * Mark this sid as freshly used. Bumps last_seen_at if the cached value is
 * older than 60s (or unknown). Runs in ctx.waitUntil so the request returns
 * before the D1 write lands.
 */
export function markSessionSeen(env, ctx, sid, nowSeconds) {
  if (!sid) return;
  const cached = _sessionCache.get(sid);
  // If we have a recent lastSeenAt in cache, throttle. If not, just update —
  // the worst case is ~16 writes/min per active session, which is fine.
  if (cached && typeof cached.lastSeenAt === 'number' &&
      cached.lastSeenAt > nowSeconds - LAST_SEEN_REFRESH_SECONDS) {
    return;
  }
  const update = env.DB.prepare(
    'UPDATE sessions SET last_seen_at = ?1 WHERE sid = ?2'
  ).bind(nowSeconds, sid).run().then(() => {
    // Mirror the new lastSeenAt into the cache so subsequent calls in this
    // isolate honor the 60s throttle.
    const c = _sessionCache.get(sid);
    if (c) {
      c.lastSeenAt = nowSeconds;
    } else {
      _sessionCache.set(sid, { active: true, cachedAt: Date.now(), lastSeenAt: nowSeconds });
    }
  }).catch(() => {});
  if (ctx && typeof ctx.waitUntil === 'function') {
    ctx.waitUntil(update);
  }
}

/**
 * Mark a sid as inactive in the local cache. The revoke endpoints call this
 * so the originating isolate enforces revocation immediately; other isolates
 * catch up within SESSION_CACHE_TTL_MS.
 */
export function invalidateSessionCache(sid) {
  if (!sid) return;
  _sessionCache.set(sid, { active: false, cachedAt: Date.now() });
}

// ============ Test seams ============

export function _setSessionCacheTTLForTesting(ms) {
  SESSION_CACHE_TTL_MS = ms;
}

export function _resetSessionCache() {
  _sessionCache.clear();
}
