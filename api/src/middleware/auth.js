// Auth middleware: extract and verify JWT from Authorization header

import { verifyJWT } from '../auth.js';
import { isSessionActive, markSessionSeen } from '../sessions.js';

/**
 * Verify JWT from Authorization header.
 * Returns { data_lookup_key, role, app, sid } for user tokens,
 * or { data_lookup_key: app_id, role: 'app', app: null, sid: null } for app tokens.
 * Returns null if no token, invalid token, or (Section 7.5) revoked sid.
 *
 * `ctx` is optional but required for the deferred last_seen_at update — pass
 * it from any handler that has it (the worker `fetch` entrypoint).
 */
export async function requireAuth(request, env, ctx) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;

  const token = authHeader.slice(7);
  if (!token) return null;

  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload || !payload.sub) return null;

  const role = payload.role || 'user';
  const sid = payload.sid || null;

  // Section 7.5: stateful check for user-role JWTs that carry a sid claim.
  // App-role JWTs are stateless and skip the check unconditionally. User-role
  // JWTs without a sid are pre-7.5 grandfather — accept until they expire.
  if (role === 'user' && sid) {
    const active = await isSessionActive(env, sid, Date.now());
    if (!active) return null;
    const nowSeconds = Math.floor(Date.now() / 1000);
    markSessionSeen(env, ctx, sid, nowSeconds);
  }

  return {
    data_lookup_key: payload.sub,
    role,
    app: payload.app || null,
    sid,
  };
}
