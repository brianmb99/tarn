// App status endpoint: operational health, user stats, wallet info
// Requires JWT with role='app'. Returns operational data for the authenticated app.

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { getAddress } from '../ans104.js';
import { PROTOCOL_VERSION } from '../constants.js';
import { fetchTurboBalance } from '../observability/funding.js';

/**
 * GET /api/v1/status
 * Returns operational status for the authenticated app.
 * Requires app JWT or user JWT (app gets more data).
 */
export async function handleStatus(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);

  const isApp = auth.role === 'app';
  const appId = isApp ? auth.data_lookup_key : null; // For apps, JWT sub = app_id

  const status = {};

  // Wallet info (from APP_SIGNING_KEY)
  if (env.APP_SIGNING_KEY) {
    try {
      const address = getAddress(env.APP_SIGNING_KEY);
      status.wallet = { address };

      // Turbo price check (no auth needed — shows cost per byte)
      try {
        const priceRes = await fetch('https://payment.ardrive.io/v1/price/bytes/102400', {
          signal: AbortSignal.timeout(5000),
        });
        if (priceRes.ok) {
          const priceData = await priceRes.json();
          status.wallet.turbo_price_100kb_winc = priceData.winc;
        }
      } catch {}

      // Turbo wallet balance (winc). The runway calculation lives in the
      // scheduled() cron; here we just surface the raw balance so operators
      // can eyeball it from /status. Resilient — fetchTurboBalance never
      // throws and a 404 (wallet never funded) is reported as 0.
      try {
        const bal = await fetchTurboBalance(address);
        if (bal.ok) {
          status.wallet.turbo_balance = bal.winc;
        } else {
          status.wallet.turbo_balance_error = bal.error;
        }
      } catch {}
    } catch {}
  }

  // User counts (from D1 accounts table)
  try {
    const totalUsers = await env.DB.prepare('SELECT COUNT(*) as count FROM accounts').first();
    status.users = { total: totalUsers?.count ?? 0 };

    // Active users (wrote something in last 7 days)
    const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    const activeUsers = await env.DB.prepare(
      'SELECT COUNT(DISTINCT lookup_key) as count FROM entries WHERE cached_at > ?1 AND is_tombstone = 0'
    ).bind(sevenDaysAgo).first();
    status.users.active_7d = activeUsers?.count ?? 0;

    // Active users (last 30 days)
    const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
    const active30 = await env.DB.prepare(
      'SELECT COUNT(DISTINCT lookup_key) as count FROM entries WHERE cached_at > ?1 AND is_tombstone = 0'
    ).bind(thirtyDaysAgo).first();
    status.users.active_30d = active30?.count ?? 0;
  } catch (err) {
    status.users = { error: err.message };
  }

  // Entry counts
  try {
    const totalEntries = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM entries WHERE is_tombstone = 0'
    ).first();
    status.entries = { total: totalEntries?.count ?? 0 };

    // Pending (unconfirmed on Arweave)
    const pending = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM entries WHERE block_timestamp IS NULL AND is_tombstone = 0'
    ).first();
    status.entries.pending = pending?.count ?? 0;

    // If app, filter by app_id
    if (isApp && appId) {
      const appEntries = await env.DB.prepare(
        'SELECT COUNT(*) as count FROM entries WHERE app = ?1 AND is_tombstone = 0'
      ).bind(appId).first();
      status.entries.for_app = appEntries?.count ?? 0;
    }
  } catch (err) {
    status.entries = { error: err.message };
  }

  // App registrations
  try {
    const totalApps = await env.DB.prepare('SELECT COUNT(*) as count FROM apps').first();
    status.apps = { registered: totalApps?.count ?? 0 };
  } catch (err) {
    status.apps = { error: err.message };
  }

  // Pending transactions (sync status)
  try {
    const pendingTxs = await env.DB.prepare('SELECT COUNT(*) as count FROM pending_txs').first();
    status.pending_txs = pendingTxs?.count ?? 0;
  } catch {}

  status.protocol_version = PROTOCOL_VERSION;
  status.timestamp = new Date().toISOString();

  return jsonResponse(status, 200, cors);
}
