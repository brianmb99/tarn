// Sync endpoints: pending tx status and acknowledgment
// Tracks recently uploaded entries per data_lookup_key for client sync.

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { isValidHex64 } from '../crypto.js';

const MAX_SYNC_READS_PER_HOUR = 300;

async function checkSyncRateLimit(env, request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const data = new TextEncoder().encode(ip + '-tarn-sync-salt');
  const hash = await crypto.subtle.digest('SHA-256', data);
  const ipHash = Array.from(new Uint8Array(hash)).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
  const hour = new Date().toISOString().slice(0, 13);
  const key = `sync:${ipHash}:${hour}`;
  const count = parseInt(await env.RATE_KV.get(key) || '0');
  if (count >= MAX_SYNC_READS_PER_HOUR) {
    return { allowed: false };
  }
  await env.RATE_KV.put(key, String(count + 1), { expirationTtl: 3600 });
  return { allowed: true };
}

// GET /api/v1/sync/status?key=<data_lookup_key> — no auth required, IP rate-limited
export async function handleSyncStatus(url, env, cors, request) {
  // IP rate limit
  const { allowed } = await checkSyncRateLimit(env, request);
  if (!allowed) {
    return errorResponse('Rate limit exceeded', 429, cors);
  }

  const key = url.searchParams.get('key');
  if (!key || !isValidHex64(key)) {
    return errorResponse('Missing or invalid key parameter (64-char hex)', 400, cors);
  }

  // Opportunistic cleanup: purge rows older than 48 hours
  env.DB.prepare("DELETE FROM pending_txs WHERE created_at < datetime('now', '-48 hours')")
    .run().catch(() => {});

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
export async function handleSyncAck(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);

  let body;
  try { body = await request.json(); } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { txids } = body;
  if (!Array.isArray(txids) || txids.length === 0) {
    return errorResponse('txids[] required', 400, cors);
  }
  if (txids.length > 100) {
    return errorResponse('txids[] max 100 items', 400, cors);
  }
  // Validate all items are non-empty strings
  if (!txids.every(t => typeof t === 'string' && t.length > 0 && t.length < 100)) {
    return errorResponse('txids[] must contain non-empty strings', 400, cors);
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
