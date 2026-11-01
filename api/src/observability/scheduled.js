// scheduled.js — the CORE observability orchestrator. Driven by the Cloudflare
// Cron Trigger via `scheduled()` in worker.js. One tick:
//
//   1. Readiness — APP_SIGNING_KEY parseable + Turbo reachable (shared with
//      /health).
//   2. Drift — per-namespace check that every Tarn-signed Arweave record which
//      settled inside the recent window is a key D1 already has (drift.js).
//      Counts are not compared: Arweave keeps history, D1 keeps current rows.
//      This does not detect a targeted delete from `accounts` that leaves
//      `entries` intact, or any miss older than the window.
//   3. Funding — Turbo wallet balance + runway (funding.js), flag LOW_FUNDING.
//   4. Cleanup — prune dead aux rows (cleanup.js).
//   5. Mirror failures — self-heal (re-upload) failed background ("waitUntil")
//      Arweave mirror uploads, then surface the still-open count; flag
//      STUCK_MIRRORS when > 0 (mirror-failures.js, issue #47).
//   6. Persist — write the report to health_reports.
//   7. Alert — POST the report to ALERT_WEBHOOK_URL when healthy === false.
//
// All I/O lives here; the pure decision logic lives in drift.js / funding.js /
// cleanup.js so it can be unit-tested without a live gateway or D1. Every leg
// is wrapped so a single failure degrades the report (records an error) rather
// than throwing out of the cron — a thrown cron just retries next hour and we
// lose the cleanup/persist side effects.

import { getAddress } from '../ans104.js';
import {
  TRACKED_NAMESPACES,
  DEFAULT_LAG_WINDOW_MS,
  DEFAULT_DRIFT_WINDOW_MS,
  keyOfForNamespace,
  selectCheckedEdges,
  compareNamespace,
  summarizeDrift,
} from './drift.js';
import {
  fetchTurboBalance,
  assessRunway,
  DEFAULT_RUNWAY_FLOOR_DAYS,
  DEFAULT_MIN_BALANCE_WINC,
} from './funding.js';
import { buildCleanupPlan, runCleanup } from './cleanup.js';
import {
  countOpenMirrorFailures,
  retryMirrorFailures,
  pruneResolvedMirrorFailures,
  DEFAULT_RETRY_BATCH,
} from './mirror-failures.js';

const ARWEAVE_GRAPHQL = 'https://arweave.net/graphql';
const TURBO_PRICE_URL = 'https://payment.ardrive.io/v1/price/bytes/102400';

// How many recent health_reports rows to keep (self-pruning; one tick/hour →
// ~30 days at 24/day). Avoids the table growing unbounded.
const REPORT_RETENTION_ROWS = 1000;

// ============ READINESS (shared with /health) ============

/**
 * Check APP_SIGNING_KEY presence/parseability and a cheap Turbo reachability
 * ping. Returns a structured result; never throws.
 *
 * @param {Object} env
 * @param {Object} [opts] - { fetchImpl } injectable for tests
 */
export async function checkReadiness(env, { fetchImpl = fetch } = {}) {
  const result = {};

  // (a) APP_SIGNING_KEY present and parseable into an address.
  try {
    if (!env.APP_SIGNING_KEY) {
      result.signing_key = { ok: false, error: 'missing' };
    } else {
      const address = getAddress(env.APP_SIGNING_KEY);
      result.signing_key = { ok: typeof address === 'string' && address.startsWith('0x'), address };
    }
  } catch (err) {
    result.signing_key = { ok: false, error: err?.message || 'unparseable' };
  }

  // (b) Cheap Turbo reachability ping — the price endpoint needs no auth and
  // no wallet, so it isolates "is Turbo up" from "does the wallet have funds".
  try {
    const res = await fetchImpl(TURBO_PRICE_URL, { signal: AbortSignal.timeout(5000) });
    result.turbo = { ok: res.ok, statusCode: res.status };
  } catch (err) {
    result.turbo = { ok: false, error: err?.message || 'unreachable' };
  }

  result.ok = !!(result.signing_key?.ok && result.turbo?.ok);
  return result;
}

// ============ ARWEAVE GRAPHQL (recent edges by namespace) ============

/**
 * Page through Arweave GraphQL for one namespace's edges (newest first),
 * including owner and tags so the drift check can keep only Tarn-signed
 * records and, for app-reg, read the Lk key.
 *
 * Stops early once the last edge of a page is older than `windowStartMs` —
 * later pages are history and cannot affect the window. Capped at `maxPages`.
 * If that cap is hit while the last edge is still inside the window (or newer),
 * `truncated` is true. Truncation is reported; it is not drift by itself.
 *
 * Resilient: returns { edges, error, truncated } and never throws.
 */
async function fetchNamespaceEdges(
  { appTag, type },
  { fetchImpl = fetch, maxPages = 5, pageSize = 100, windowStartMs = null } = {},
) {
  const tags = [{ name: 'Type', values: [type] }];
  if (appTag) tags.unshift({ name: 'App', values: [appTag] });

  const q = `query($after:String,$first:Int,$tags:[TagFilter!]){
    transactions(after:$after,first:$first,sort:HEIGHT_DESC,tags:$tags){
      pageInfo{hasNextPage}
      edges{cursor node{id block{timestamp height} owner{address} tags{name value}}}
    }
  }`;

  const all = [];
  let after = null;
  let truncated = false;
  for (let page = 0; page < maxPages; page++) {
    try {
      const res = await fetchImpl(ARWEAVE_GRAPHQL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q, variables: { after, first: pageSize, tags } }),
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) return { edges: all, error: `http_${res.status}`, truncated: false };
      const json = await res.json();
      if (json.errors?.length) return { edges: all, error: json.errors[0].message, truncated: false };
      const txns = json.data?.transactions;
      const edges = txns?.edges || [];
      all.push(...edges);
      if (edges.length === 0 || !txns.pageInfo?.hasNextPage) break;
      const lastTs = edges[edges.length - 1]?.node?.block?.timestamp;
      // HEIGHT_DESC: the last edge is the oldest on this page. Once it is
      // already before the window, every later page is history.
      if (windowStartMs != null && lastTs != null && lastTs * 1000 < windowStartMs) break;
      after = edges[edges.length - 1].cursor;
      if (page === maxPages - 1) truncated = true;
    } catch (err) {
      return { edges: all, error: err?.message || 'graphql_failed', truncated: false };
    }
  }
  return { edges: all, error: null, truncated };
}

// ============ D1 KEY LOOKUP (per namespace) ============

// Fixed map. Table and column are never taken from request or GraphQL input.
// cred / passkey-reg / app-config all land in `entries` via upsertWriteThrough
// (txid = data-item id). share tables store their own txid. app-reg is keyed
// by app_id because a CLI uploader does not write `entries`.
const D1_KEY_SOURCE = {
  cred: { table: 'entries', column: 'txid' },
  'passkey-reg': { table: 'entries', column: 'txid' },
  'app-config': { table: 'entries', column: 'txid' },
  'app-reg': { table: 'apps', column: 'app_id' },
  'share-inbox': { table: 'share_inbox', column: 'txid' },
  'share-inbox-accept': { table: 'share_inbox', column: 'txid' },
  'share-log': { table: 'share_log', column: 'txid' },
};

// D1 rejects a prepared statement with more than 100 bound parameters.
const D1_IN_CHUNK = 100;

/**
 * Which of `keys` already exist in the namespace's D1 table.
 * Runs `SELECT <column> AS k FROM <table> WHERE <column> IN (?1, ...)` in
 * chunks of at most 100. Never throws. No query when `keys` is empty.
 *
 * @param {Object} db
 * @param {string} ns
 * @param {string[]} keys
 * @returns {Promise<{known: Set<string>, error: string|null}>}
 */
async function d1KnownKeys(db, ns, keys) {
  const src = D1_KEY_SOURCE[ns];
  if (!src) return { known: new Set(), error: 'unknown_namespace' };
  if (!keys || keys.length === 0) return { known: new Set(), error: null };
  const known = new Set();
  try {
    for (let i = 0; i < keys.length; i += D1_IN_CHUNK) {
      const chunk = keys.slice(i, i + D1_IN_CHUNK);
      const placeholders = chunk.map((_, idx) => `?${idx + 1}`).join(', ');
      const sql = `SELECT ${src.column} AS k FROM ${src.table} WHERE ${src.column} IN (${placeholders})`;
      const result = await db.prepare(sql).bind(...chunk).all();
      const rows = result?.results;
      if (!Array.isArray(rows)) return { known: new Set(), error: 'd1_failed' };
      for (const row of rows) {
        if (row?.k != null) known.add(row.k);
      }
    }
    return { known, error: null };
  } catch (err) {
    return { known: new Set(), error: err?.message || 'd1_failed' };
  }
}

function skippedComparison(ns, gqlErr, d1Err, truncated = false) {
  return {
    ns,
    drift: false,
    reason: `comparison skipped (gql=${gqlErr || 'ok'}, d1=${d1Err || 'ok'})`,
    checked: 0,
    missing: 0,
    missingSample: [],
    inFlight: 0,
    outsideWindow: 0,
    foreign: 0,
    incomplete: true,
    truncated: !!truncated,
  };
}

// ============ ORCHESTRATOR ============

function num(env, key, fallback) {
  const v = env?.[key];
  if (v == null || v === '') return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

/**
 * Run the full observability sweep and return the report object (also the
 * value persisted to health_reports.report_json). Does NOT throw.
 *
 * @param {Object} env - Worker env (DB, APP_SIGNING_KEY, ALERT_WEBHOOK_URL, tunables)
 * @param {Object} [opts]
 * @param {typeof fetch} [opts.fetchImpl]
 * @param {number} [opts.now] - injectable unix ms for tests
 * @param {boolean} [opts.skipPersist] - skip the health_reports write (tests)
 * @param {boolean} [opts.skipCleanup] - skip the aux-table reap (tests)
 * @returns {Promise<Object>} the report
 */
export async function runScheduledChecks(env, opts = {}) {
  const fetchImpl = opts.fetchImpl || fetch;
  const now = opts.now ?? Date.now();
  const lagWindowMs = num(env, 'DRIFT_LAG_WINDOW_MS', DEFAULT_LAG_WINDOW_MS);
  const windowMs = num(env, 'DRIFT_WINDOW_MS', DEFAULT_DRIFT_WINDOW_MS);
  const runwayFloorDays = num(env, 'TURBO_RUNWAY_FLOOR_DAYS', DEFAULT_RUNWAY_FLOOR_DAYS);
  const minBalanceWinc = num(env, 'TURBO_MIN_BALANCE_WINC', DEFAULT_MIN_BALANCE_WINC);

  const report = {
    generated_at: new Date(now).toISOString(),
    generated_at_ms: now,
    checks: {},
    flags: [],
  };

  // 1. Readiness
  const readiness = await checkReadiness(env, { fetchImpl });
  report.checks.readiness = readiness;
  if (!readiness.ok) report.flags.push('NOT_READY');

  // 2. Drift — a Tarn-signed record that settled inside the window but that
  // D1 has no key for. A GraphQL or D1 failure marks that namespace incomplete
  // (drift: false) rather than paging on a comparison we could not finish.
  // Truncation (hit maxPages while still inside the window) is reported per
  // namespace and is not drift by itself. A delete from `accounts` that leaves
  // `entries` intact, and anything older than the window, are not detected.
  try {
    let ownerAddress = null;
    try {
      if (env.APP_SIGNING_KEY) ownerAddress = getAddress(env.APP_SIGNING_KEY);
    } catch {
      ownerAddress = null;
    }
    const settledCutoffMs = now - lagWindowMs;
    const windowStartMs = settledCutoffMs - windowMs;
    const comparisons = [];
    for (const spec of TRACKED_NAMESPACES) {
      const { edges, error: gqlErr, truncated } = await fetchNamespaceEdges(spec, {
        fetchImpl,
        windowStartMs,
      });
      if (gqlErr) {
        comparisons.push(skippedComparison(spec.ns, gqlErr, null, truncated));
        continue;
      }
      const keyOf = keyOfForNamespace(spec.ns);
      const selected = selectCheckedEdges({
        edges,
        keyOf,
        now,
        lagWindowMs,
        windowMs,
        ownerAddress,
      });
      const d1 = await d1KnownKeys(env.DB, spec.ns, selected.checked);
      if (d1.error) {
        comparisons.push(skippedComparison(spec.ns, null, d1.error, truncated));
        continue;
      }
      comparisons.push({
        ...compareNamespace({
          ns: spec.ns,
          edges,
          knownKeys: d1.known,
          keyOf,
          now,
          lagWindowMs,
          windowMs,
          ownerAddress,
        }),
        truncated: !!truncated,
      });
    }
    const drift = summarizeDrift(comparisons);
    report.checks.drift = { ...drift, lagWindowMs, windowMs };
    if (!drift.healthy) report.flags.push('DRIFT');
  } catch (err) {
    report.checks.drift = { error: err?.message || 'drift_failed', healthy: true };
  }

  // 3. Funding
  try {
    const funding = {};
    if (!env.APP_SIGNING_KEY) {
      funding.error = 'no_signing_key';
    } else {
      const address = getAddress(env.APP_SIGNING_KEY);
      funding.address = address;
      const bal = await fetchTurboBalance(address, { fetchImpl });
      if (!bal.ok) {
        funding.error = bal.error;
      } else {
        funding.balance_winc = bal.winc;

        // Unit cost: current Turbo price for 100 KB.
        let wincPer100kb = null;
        try {
          const priceRes = await fetchImpl(TURBO_PRICE_URL, { signal: AbortSignal.timeout(5000) });
          if (priceRes.ok) {
            const priceData = await priceRes.json();
            wincPer100kb = Number(priceData.winc);
            if (!Number.isFinite(wincPer100kb)) wincPer100kb = null;
          }
        } catch {}
        funding.winc_per_100kb = wincPer100kb;

        // Recent write volume (last 7 days) as the burn proxy. Conservative:
        // counts ALL non-tombstone writes in the window (most are FREE <100 KB,
        // so this over-estimates burn → earlier alert, the safe direction).
        const windowDays = 7;
        let recentPaidWrites = 0;
        try {
          const sevenDaysAgo = now - windowDays * 24 * 60 * 60 * 1000;
          const row = await env.DB.prepare(
            'SELECT COUNT(*) AS c FROM entries WHERE cached_at > ?1 AND is_tombstone = 0',
          ).bind(sevenDaysAgo).first();
          recentPaidWrites = row?.c ?? 0;
        } catch {}
        funding.recent_writes_7d = recentPaidWrites;

        const assessment = assessRunway({
          balanceWinc: bal.winc,
          wincPer100kb,
          recentPaidWrites,
          windowDays,
          runwayFloorDays,
          minBalanceWinc,
        });
        funding.runway_days = assessment.runwayDays === Infinity ? null : assessment.runwayDays;
        funding.daily_burn_winc = assessment.dailyBurnWinc;
        funding.low_funding = assessment.lowFunding;
        funding.reason = assessment.reason;
        if (assessment.lowFunding) report.flags.push('LOW_FUNDING');
      }
    }
    report.checks.funding = funding;
  } catch (err) {
    report.checks.funding = { error: err?.message || 'funding_failed' };
  }

  // 4. Cleanup
  if (!opts.skipCleanup) {
    try {
      const auditRetentionDays = num(env, 'AUDIT_RETENTION_DAYS', undefined);
      const plan = buildCleanupPlan(
        auditRetentionDays !== undefined ? { now, auditRetentionDays } : { now },
      );
      report.checks.cleanup = await runCleanup(env.DB, plan);
    } catch (err) {
      report.checks.cleanup = { error: err?.message || 'cleanup_failed' };
    }
  }

  // 5. Mirror failures (issue #47) — self-heal then surface.
  //
  // SELF-HEAL FIRST: re-upload the unresolved+stored-bytes background-mirror
  // failures (bounded batch), so transient Turbo outages drain automatically
  // and only genuinely stuck mirrors remain. THEN count the still-open failures
  // for the report: STUCK_MIRRORS fires only for what retry could NOT fix this
  // tick, so a flap that healed itself doesn't page. Resolved rows are then
  // reaped on a short retention. Wrapped so a failure degrades the report
  // rather than throwing out of the cron.
  try {
    const mirror = {};
    if (!opts.skipMirrorRetry) {
      const batch = num(env, 'MIRROR_RETRY_BATCH', DEFAULT_RETRY_BATCH);
      mirror.retry = await retryMirrorFailures(env.DB, {
        batch,
        now,
        uploadImpl: opts.mirrorUploadImpl,
      });
      const retentionDays = num(env, 'MIRROR_FAILURE_RETENTION_DAYS', undefined);
      mirror.pruned = await pruneResolvedMirrorFailures(
        env.DB,
        retentionDays !== undefined ? { now, retentionDays } : { now },
      );
    }
    const open = await countOpenMirrorFailures(env.DB);
    mirror.open = open.count;
    if (open.error) mirror.error = open.error;
    report.checks.mirror_failures = mirror;
    if (open.count > 0) report.flags.push('STUCK_MIRRORS');
  } catch (err) {
    report.checks.mirror_failures = { error: err?.message || 'mirror_check_failed' };
  }

  // 6. Operability config (tarn#68). Unattended operation requires a working
  // alert channel, a dead-man heartbeat, and a funding floor — without them
  // every other check here degrades to a logbook nobody reads (an unhealthy
  // report with no webhook is just a console.warn). Their absence is itself
  // an unhealthy condition, surfaced as flags so the operator is nudged until
  // the three vars are set. See docs/OPERATIONS.md for setup.
  const config = {
    alert_webhook_configured: !!env.ALERT_WEBHOOK_URL,
    heartbeat_configured: !!env.HEARTBEAT_URL,
    funding_floor_configured: minBalanceWinc > 0,
  };
  report.checks.config = config;
  if (!config.alert_webhook_configured) report.flags.push('ALERTING_UNCONFIGURED');
  if (!config.heartbeat_configured) report.flags.push('HEARTBEAT_UNCONFIGURED');
  if (!config.funding_floor_configured) report.flags.push('FUNDING_FLOOR_UNSET');

  // Overall verdict: any flag means unhealthy.
  report.healthy = report.flags.length === 0;

  // 5. Persist
  if (!opts.skipPersist) {
    try {
      await persistReport(env.DB, now, report);
    } catch (err) {
      // Persist failure is itself a signal but must not break the cron.
      console.error('[tarn-api][observability] persist failed:', err?.message);
    }
  }

  // 7. Alert webhook (only when unhealthy)
  if (!report.healthy) {
    await maybeAlert(env, report, { fetchImpl });
  }

  // 8. Dead-man heartbeat (tarn#68) — ping on EVERY tick, healthy or not, so
  // the heartbeat monitor (healthchecks.io / UptimeRobot style) alerts on
  // SILENCE: a dead worker, a stopped cron, or a mis-deploy can't report
  // itself, but a missed heartbeat can page. Best-effort; a ping failure must
  // never break the cron.
  if (env.HEARTBEAT_URL) {
    try {
      await fetchImpl(env.HEARTBEAT_URL, { method: 'GET', signal: AbortSignal.timeout(5000) });
    } catch (err) {
      console.error('[tarn-api][observability] heartbeat ping failed:', err?.message);
    }
  }

  return report;
}

/**
 * Write the report to health_reports and prune to REPORT_RETENTION_ROWS.
 */
export async function persistReport(db, now, report) {
  await db
    .prepare('INSERT INTO health_reports (created_at, healthy, report_json) VALUES (?1, ?2, ?3)')
    .bind(now, report.healthy ? 1 : 0, JSON.stringify(report))
    .run();

  // Self-prune: keep the most recent REPORT_RETENTION_ROWS rows.
  try {
    await db
      .prepare(
        'DELETE FROM health_reports WHERE id NOT IN (SELECT id FROM health_reports ORDER BY created_at DESC LIMIT ?1)',
      )
      .bind(REPORT_RETENTION_ROWS)
      .run();
  } catch {
    // Pruning is best-effort; never fail the persist on it.
  }
}

/**
 * POST the report to env.ALERT_WEBHOOK_URL when present. No-op + console.warn
 * if unset. Wrapped in try/catch so a webhook failure never breaks the cron.
 */
export async function maybeAlert(env, report, { fetchImpl = fetch } = {}) {
  if (!env.ALERT_WEBHOOK_URL) {
    console.warn('[tarn-api][observability] unhealthy report but ALERT_WEBHOOK_URL is unset:', report.flags.join(','));
    return { sent: false, reason: 'no_webhook' };
  }
  try {
    const res = await fetchImpl(env.ALERT_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: `[Tarn] health check FAILED: ${report.flags.join(', ')}`,
        report,
      }),
      signal: AbortSignal.timeout(5000),
    });
    return { sent: res.ok, status: res.status };
  } catch (err) {
    console.error('[tarn-api][observability] alert webhook failed:', err?.message);
    return { sent: false, error: err?.message };
  }
}
