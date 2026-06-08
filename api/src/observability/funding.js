// funding.js — Turbo wallet balance + runway estimation for the CORE
// observability subsystem.
//
// The app wallet (APP_SIGNING_KEY, an Ethereum-compatible key) pays Turbo for
// Arweave uploads over the 100 KB free tier. If it runs dry, every >100 KB
// write starts failing with a 402/403 from Turbo and the platform silently
// degrades. The scheduled health check fetches the wallet's Turbo balance and
// flags LOW_FUNDING when the estimated runway falls below a floor.
//
// Turbo bills in "winc" (Winston credits — 1 AR = 1e12 winc, but for our
// purposes winc is just an opaque integer unit; price and balance are both
// quoted in winc so we reason in winc throughout and never need an AR/USD
// conversion). The balance endpoint for an Ethereum-signed account is:
//   GET https://payment.ardrive.io/v1/account/balance/ethereum?address=<addr>
// which returns { winc, controlledWinc, effectiveBalance } (all winc strings).
//
// The split (pure logic vs fetch) mirrors drift.js: `assessRunway` is pure and
// fully unit-tested; `fetchTurboBalance` does the network I/O and is mocked in
// tests via injectable fetch.

export const TURBO_PAYMENT_BASE = 'https://payment.ardrive.io';

// Default runway floor: alert if estimated runway is under 14 days. Two weeks
// is enough lead time for an operator to top up the wallet before writes start
// failing, without being so generous it pages constantly. Configurable via
// env.TURBO_RUNWAY_FLOOR_DAYS.
export const DEFAULT_RUNWAY_FLOOR_DAYS = 14;

// Default absolute-balance floor (winc). Even if recent write volume is zero
// (so the divide-by-volume runway is Infinity), we still want a hard floor so
// a near-empty wallet is flagged before the first large write fails. 0 means
// "no absolute floor; rely on the runway estimate only". Configurable via
// env.TURBO_MIN_BALANCE_WINC.
export const DEFAULT_MIN_BALANCE_WINC = 0;

/**
 * Fetch the Turbo balance (winc) for an Ethereum wallet address. Resilient:
 * never throws; returns { ok:false, error } on any failure so the cron is
 * never broken by a balance lookup.
 *
 * @param {string} address - 0x-prefixed Ethereum address (from getAddress())
 * @param {Object} [opts]
 * @param {typeof fetch} [opts.fetchImpl] - injectable for tests
 * @param {number} [opts.timeoutMs]
 * @returns {Promise<{ok: boolean, winc?: number, raw?: object, error?: string}>}
 */
export async function fetchTurboBalance(address, { fetchImpl = fetch, timeoutMs = 5000 } = {}) {
  if (!address || typeof address !== 'string') {
    return { ok: false, error: 'no_address' };
  }
  const url = `${TURBO_PAYMENT_BASE}/v1/account/balance/ethereum?address=${encodeURIComponent(address)}`;
  try {
    const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) {
      // 404 here means "wallet has never had a Turbo balance" — treat as zero,
      // not as an error (a brand-new wallet legitimately has no account row).
      if (res.status === 404) return { ok: true, winc: 0, raw: { status: 404 } };
      return { ok: false, error: `http_${res.status}` };
    }
    const data = await res.json();
    // Prefer effectiveBalance (controlled minus pending), fall back to winc.
    const wincStr = data?.effectiveBalance ?? data?.winc ?? data?.controlledWinc;
    const winc = Number(wincStr);
    if (!Number.isFinite(winc)) return { ok: false, error: 'unparseable_balance' };
    return { ok: true, winc, raw: data };
  } catch (err) {
    return { ok: false, error: err?.message || 'fetch_failed' };
  }
}

/**
 * Estimate runway and decide whether to flag LOW_FUNDING. Pure.
 *
 * Runway model (deliberately simple, documented):
 *   - `wincPer100kb` is the current Turbo price for a 100 KB upload (already
 *     fetched by /status as turbo_price_100kb_winc). We use it as the unit
 *     cost of one "paid write".
 *   - `recentPaidWrites` is the number of >100 KB-class writes in the recent
 *     window (`windowDays`). We approximate daily burn as
 *     spend_in_window / windowDays, where spend = recentPaidWrites * wincPer100kb.
 *     (Most Tarn writes are <100 KB and FREE on Turbo; only oversized writes
 *     burn balance. We don't have a precise per-write byte ledger in D1, so we
 *     treat each recent write as at most one 100 KB unit — an intentionally
 *     conservative OVER-estimate of burn, which makes runway shorter and the
 *     alert earlier/safer.)
 *   - runwayDays = balanceWinc / dailyBurnWinc. If dailyBurn is 0 (no recent
 *     paid writes, or price unknown), runway is Infinity and we fall back to
 *     the absolute minBalanceWinc floor only.
 *
 * Flags LOW_FUNDING when EITHER:
 *   - runwayDays < runwayFloorDays (and dailyBurn > 0), OR
 *   - balanceWinc <= minBalanceWinc (absolute floor, if configured > 0).
 *
 * @param {Object} args
 * @param {number} args.balanceWinc
 * @param {number|null} args.wincPer100kb   - unit cost; null/0 disables burn calc
 * @param {number} args.recentPaidWrites    - count of writes in window
 * @param {number} args.windowDays
 * @param {number} args.runwayFloorDays
 * @param {number} args.minBalanceWinc
 * @returns {{lowFunding: boolean, runwayDays: number, dailyBurnWinc: number,
 *            reason: string, balanceWinc: number}}
 */
export function assessRunway({
  balanceWinc,
  wincPer100kb = null,
  recentPaidWrites = 0,
  windowDays = 7,
  runwayFloorDays = DEFAULT_RUNWAY_FLOOR_DAYS,
  minBalanceWinc = DEFAULT_MIN_BALANCE_WINC,
}) {
  const safeBalance = Number.isFinite(balanceWinc) ? balanceWinc : 0;
  const unitCost = Number.isFinite(wincPer100kb) && wincPer100kb > 0 ? wincPer100kb : 0;
  const safeWindow = windowDays > 0 ? windowDays : 1;

  const spendInWindow = unitCost * Math.max(0, recentPaidWrites);
  const dailyBurnWinc = spendInWindow / safeWindow;

  const runwayDays = dailyBurnWinc > 0 ? safeBalance / dailyBurnWinc : Infinity;

  const reasons = [];
  let lowFunding = false;

  if (dailyBurnWinc > 0 && runwayDays < runwayFloorDays) {
    lowFunding = true;
    reasons.push(`runway ${runwayDays.toFixed(1)}d < floor ${runwayFloorDays}d`);
  }
  if (minBalanceWinc > 0 && safeBalance <= minBalanceWinc) {
    lowFunding = true;
    reasons.push(`balance ${safeBalance} <= floor ${minBalanceWinc} winc`);
  }

  return {
    lowFunding,
    runwayDays,
    dailyBurnWinc,
    balanceWinc: safeBalance,
    reason: reasons.length ? reasons.join('; ') : `ok (runway=${runwayDays === Infinity ? 'inf' : runwayDays.toFixed(1) + 'd'}, burn=${dailyBurnWinc.toFixed(0)} winc/d)`,
  };
}
