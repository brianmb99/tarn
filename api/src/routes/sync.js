// Sync endpoints: pending tx status and acknowledgment
// Replaces upload-proxy's KV-based sync state with D1.

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

// GET /api/v1/sync/status?addr=0x... — no auth required
export async function handleSyncStatus(url, env, cors) {
  const addr = url.searchParams.get('addr')?.toLowerCase();
  if (!addr || !ADDRESS_RE.test(addr)) {
    return errorResponse('Missing or invalid addr parameter', 400, cors);
  }

  const result = await env.DB.prepare(
    `SELECT txid FROM pending_txs
     WHERE wallet_addr = ?1 AND created_at > datetime('now', '-6 hours')
     ORDER BY created_at DESC`
  ).bind(addr).all();

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

  // Delete matching rows for this wallet
  const placeholders = txids.map(() => '?').join(',');
  const result = await env.DB.prepare(
    `DELETE FROM pending_txs WHERE wallet_addr = ?1 AND txid IN (${placeholders})`
  ).bind(auth.address.toLowerCase(), ...txids).run();

  const remaining = await env.DB.prepare(
    `SELECT COUNT(*) as count FROM pending_txs
     WHERE wallet_addr = ?1 AND created_at > datetime('now', '-6 hours')`
  ).bind(auth.address.toLowerCase()).first();

  return jsonResponse({
    removed: result.meta?.changes || 0,
    remaining: remaining?.count || 0,
  }, 200, cors);
}
