// admin.js — privileged operational endpoints for the CORE observability
// subsystem.
//
// GET /api/v1/admin/health-report
//   Returns the latest persisted health report (written by the hourly cron's
//   scheduled() handler into the health_reports table).
//
// AUTH POSTURE (documented decision):
//   Tarn has no dedicated "admin" JWT role — the only roles are 'user' and
//   'app' (see middleware/auth.js). Rather than invent a new role + key
//   hierarchy for one endpoint, this route reuses the existing APP role auth,
//   matching how every other privileged route authenticates (handleSetRules,
//   handleSetSchema, etc. all gate on `auth.role === 'app'`).
//
//   Optional tightening: if `env.ADMIN_APP_ID` is set, ONLY that app_id may
//   read the report (an app-role JWT whose sub === ADMIN_APP_ID). If it is
//   unset, ANY valid app-role JWT may read it. This keeps the default working
//   without extra config while letting the operator lock the endpoint to a
//   single admin app by setting one secret. No plaintext / user data is in the
//   report, so app-role is an appropriate floor; the ADMIN_APP_ID gate exists
//   so the operator can restrict it further without code changes.

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';

/**
 * GET /api/v1/admin/health-report
 * Returns the most recent row from health_reports.
 */
export async function handleGetHealthReport(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);

  // App role only.
  if (auth.role !== 'app') {
    return errorResponse('Admin endpoints require an app identity', 403, cors);
  }

  // Optional single-app lock.
  if (env.ADMIN_APP_ID && auth.data_lookup_key !== env.ADMIN_APP_ID) {
    return errorResponse('Not authorized for admin endpoints', 403, cors);
  }

  let row;
  try {
    row = await env.DB.prepare(
      'SELECT id, created_at, healthy, report_json FROM health_reports ORDER BY created_at DESC LIMIT 1',
    ).first();
  } catch (err) {
    return errorResponse(`Failed to read health report: ${err.message}`, 500, cors);
  }

  if (!row) {
    // No report yet (cron hasn't run, or table just migrated). 404 so callers
    // can distinguish "no report" from "report says unhealthy".
    return jsonResponse({ error: 'No health report available yet' }, 404, cors);
  }

  let report;
  try {
    report = JSON.parse(row.report_json);
  } catch {
    report = { error: 'report_json corrupt', raw: row.report_json };
  }

  return jsonResponse(
    {
      id: row.id,
      created_at: row.created_at,
      healthy: row.healthy === 1,
      report,
    },
    200,
    cors,
  );
}
