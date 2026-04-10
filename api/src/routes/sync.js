// Sync endpoints: pending tx status and acknowledgment
// Tracks recently uploaded entries per data_lookup_key for client sync.

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { isValidHex64 } from '../crypto.js';

// GET /api/v1/sync/status?key=<data_lookup_key> — no auth required
export async function handleSyncStatus(url, env, cors) {
  const key = url.searchParams.get('key');
  if (!key || !isValidHex64(key)) {
    return errorResponse('Missing or invalid key parameter (64-char hex)', 400, cors);
  }

  const result = await env.DB.prepare(
    `SELECT txid FROM pending_txs
     WHERE data_lookup_key = ?1 AND created_at > datetime('now', '-6 hours')
     ORDER BY created_at DESC`
  ).bind(key).all();

  const txids = (result.results || []).map(r => r.txid);

  return jsonResponse({
    dirty: txids.length > 0,
    pendingTxids: txids,
    count: txids.length,
  }, 200, cors);
}

// POST /api/v1/sync/ack — requires auth
export async function handleSyncAck(request, env, cors) {
  const auth = await requireAuth(request, env);
  if (!auth) return errorResponse('Unauthorized', 401, cors);

  let body;
  try { body = await request.json(); } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { txids } = body;
  if (!Array.isArray(txids) || txids.length === 0) {
    return errorResponse('txids[] required', 400, cors);
  }

  // Delete matching rows for this user
  const placeholders = txids.map(() => '?').join(',');
  const result = await env.DB.prepare(
    `DELETE FROM pending_txs WHERE data_lookup_key = ?1 AND txid IN (${placeholders})`
  ).bind(auth.data_lookup_key, ...txids).run();

  const remaining = await env.DB.prepare(
    `SELECT COUNT(*) as count FROM pending_txs
     WHERE data_lookup_key = ?1 AND created_at > datetime('now', '-6 hours')`
  ).bind(auth.data_lookup_key).first();

  return jsonResponse({
    removed: result.meta?.changes || 0,
    remaining: remaining?.count || 0,
  }, 200, cors);
}
