// Session management endpoints (Section 7.5, issue #20).
//
// All three endpoints are user-role only: app-role JWTs have no sid claim
// and no rows in the sessions table. The data_lookup_key on the JWT is the
// authorization boundary — a user cannot list, see, or revoke sessions for
// another account.

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { invalidateSessionCache, _resetSessionCache } from '../sessions.js';

// GET /api/v1/sessions — list active sessions for the calling user.
export async function handleListSessions(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') return errorResponse('Only user accounts can list sessions', 403, cors);

  const rows = await env.DB.prepare(
    'SELECT sid, created_at, last_seen_at, device_label, via_recovery FROM sessions WHERE data_lookup_key = ?1 ORDER BY last_seen_at DESC'
  ).bind(auth.data_lookup_key).all();

  const callingSid = auth.sid;
  const sessions = (rows.results || []).map(r => ({
    sid: r.sid,
    created_at: r.created_at,
    last_seen_at: r.last_seen_at,
    device_label: r.device_label,
    via_recovery: !!r.via_recovery,
    is_current: callingSid != null && r.sid === callingSid,
  }));

  return jsonResponse({ sessions }, 200, cors);
}

// DELETE /api/v1/sessions/:sid — revoke a single session.
export async function handleRevokeSession(request, env, ctx, sid, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') return errorResponse('Only user accounts can revoke sessions', 403, cors);

  // Scope by data_lookup_key — a 404 covers both "doesn't exist" and "belongs
  // to someone else", so cross-account existence is not leaked.
  const result = await env.DB.prepare(
    'DELETE FROM sessions WHERE sid = ?1 AND data_lookup_key = ?2'
  ).bind(sid, auth.data_lookup_key).run();

  const changes = result?.meta?.changes ?? result?.changes ?? 0;
  if (changes === 0) {
    return errorResponse('Session not found', 404, cors);
  }
  invalidateSessionCache(sid);

  return new Response(null, { status: 204, headers: cors });
}

// DELETE /api/v1/sessions[?except=current] — revoke all (or all-but-current).
export async function handleRevokeAllSessions(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') return errorResponse('Only user accounts can revoke sessions', 403, cors);

  const url = new URL(request.url);
  const exceptCurrent = url.searchParams.get('except') === 'current';

  if (exceptCurrent && auth.sid) {
    await env.DB.prepare(
      'DELETE FROM sessions WHERE data_lookup_key = ?1 AND sid != ?2'
    ).bind(auth.data_lookup_key, auth.sid).run();
  } else {
    await env.DB.prepare(
      'DELETE FROM sessions WHERE data_lookup_key = ?1'
    ).bind(auth.data_lookup_key).run();
  }

  // Simpler than tracking which sids were affected: clear this isolate's
  // entire cache. Other isolates serve stale until the 5s TTL expires.
  _resetSessionCache();

  return new Response(null, { status: 204, headers: cors });
}
