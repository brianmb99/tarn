// drift.js — pure D1<->Arweave drift detection for the CORE observability
// subsystem.
//
// The scheduled health check compares, per namespace, what D1 believes it has
// cached against what Arweave's GraphQL indexer reports. The hard part is NOT
// the comparison — it's distinguishing *normal indexing lag* from *true drift*.
//
// Background (docs/ARWEAVE_RECOVERABILITY_AUDIT.md §"Mainnet indexing-latency
// caveat"): arweave.net's L1 GraphQL lags ~15–25 min behind a Turbo upload
// (bundle must confirm → post to L1 → mine → index). So a row that exists in
// D1 (written through at request time) will legitimately be invisible to
// Arweave GraphQL for up to ~25 minutes. If we naively flagged "D1 has N rows,
// Arweave has N-k rows → DRIFT", every recent write would false-positive.
//
// The lag-window model
// --------------------
// We only count Arweave-side activity that is OLDER than `lagWindowMs` when
// comparing against D1's recent-activity timestamp. Equivalently: drift is
// flagged only when D1's *latest settled* activity is meaningfully ahead of
// Arweave's latest indexed activity, AND the gap exceeds the lag window. A
// recent D1 write that Arweave hasn't indexed yet is treated as "in flight",
// not drift.
//
// This module is pure: it takes already-fetched D1 counts/timestamps and
// already-fetched Arweave edge lists (the {node:{id,tags,block:{timestamp}}}
// shape from GraphQL). The scheduled handler does the I/O and hands data here.
// That keeps every branch unit-testable without a live gateway or D1.

import { tagValue, sortEdgesByTimestamp } from '../../../tools/lib/rebuild-core.mjs';

// Default lag window: 30 minutes. The audit observes arweave.net L1 indexing
// at ~15–25 min; 30 min gives a margin above the high end so normal indexing
// never trips the alarm. Configurable via env.DRIFT_LAG_WINDOW_MS.
export const DEFAULT_LAG_WINDOW_MS = 30 * 60 * 1000;

/**
 * The namespaces (Arweave Type tags) the observability sweep tracks. Each
 * entry says which App tag scopes it and which Type tag identifies it. These
 * mirror exactly what the runtime writers emit:
 *   - cred / app-reg / passkey-reg : App=tarn   (auth.js, app-reg.js, passkey-reg.js)
 *   - app-config                   : App=<app_id> (apps.js — per-app, App is NOT 'tarn')
 *   - connection-{request,accept}  : App=tarn-share (share-inbox.js)
 *   - share-log-v1                 : App=tarn-share (share-log.js)
 *
 * `appTag: null` means "the App tag is per-app (the app_id), not a fixed
 * literal" — the caller queries Type only (or per-app) and we don't pin App.
 */
export const TRACKED_NAMESPACES = [
  { ns: 'cred',          appTag: 'tarn',       type: 'cred' },
  { ns: 'app-reg',       appTag: 'tarn',       type: 'app-reg' },
  { ns: 'passkey-reg',   appTag: 'tarn',       type: 'passkey-reg' },
  { ns: 'app-config',    appTag: null,         type: 'app-config' },
  { ns: 'share-inbox',   appTag: 'tarn-share', type: 'connection-request-v1' },
  { ns: 'share-inbox-accept', appTag: 'tarn-share', type: 'connection-accept-v1' },
  { ns: 'share-log',     appTag: 'tarn-share', type: 'share-log-v1' },
];

/**
 * Count Arweave edges whose block.timestamp is at or before `cutoffSeconds`,
 * i.e. edges that have been indexed long enough that we'd EXPECT D1 to also
 * reflect them. Unconfirmed edges (no block) are excluded — they are, by
 * definition, still in the indexing pipeline.
 *
 * @param {Array} edges - GraphQL edges ({node:{block:{timestamp}}}, secs)
 * @param {number} cutoffSeconds - unix seconds; edges newer than this are "in flight"
 * @returns {{settled: number, inFlight: number, latestSettledMs: number|null}}
 */
export function summarizeArweaveEdges(edges, cutoffSeconds) {
  let settled = 0;
  let inFlight = 0;
  let latestSettledMs = null;
  for (const edge of edges || []) {
    const ts = edge?.node?.block?.timestamp;
    if (ts == null) {
      // Unconfirmed / not yet on L1 — pure in-flight.
      inFlight += 1;
      continue;
    }
    if (ts <= cutoffSeconds) {
      settled += 1;
      const ms = ts * 1000;
      if (latestSettledMs == null || ms > latestSettledMs) latestSettledMs = ms;
    } else {
      inFlight += 1;
    }
  }
  return { settled, inFlight, latestSettledMs };
}

/**
 * Compare one namespace's D1 state against its Arweave edges, applying the
 * lag-window model so normal indexing latency is NOT flagged as drift.
 *
 * Decision logic:
 *   - Let `cutoff = now - lagWindowMs`. Arweave edges at/older than cutoff are
 *     "settled" — D1 should have caught up. Newer edges are "in flight".
 *   - We compare D1's count against the count of settled Arweave edges.
 *   - If D1 >= settledArweave: NO drift on count. D1 having MORE than settled
 *     Arweave is expected (D1 also holds the in-flight, not-yet-indexed rows
 *     it wrote through at request time). We never flag "D1 ahead" as drift —
 *     that's exactly the healthy write-through case.
 *   - If D1 < settledArweave: Arweave has confirmed+indexed rows (older than
 *     the lag window) that D1 is MISSING. That is true drift — the cache lost
 *     rows that permanent storage still has (a rebuild candidate). We report
 *     the shortfall.
 *
 * @param {Object} args
 * @param {string} args.ns
 * @param {number} args.d1Count           - rows D1 has for this namespace
 * @param {number|null} args.d1LatestMs   - D1's latest activity (unix ms) or null
 * @param {Array} args.arweaveEdges       - GraphQL edges for this namespace
 * @param {number} args.now               - unix ms (injectable for tests)
 * @param {number} args.lagWindowMs       - lag tolerance
 * @returns {{ns, drift: boolean, reason: string, d1Count, arweaveSettled,
 *            arweaveInFlight, shortfall: number, latestSettledMs: number|null}}
 */
export function compareNamespace({ ns, d1Count, d1LatestMs = null, arweaveEdges, now, lagWindowMs }) {
  const cutoffSeconds = Math.floor((now - lagWindowMs) / 1000);
  const { settled, inFlight, latestSettledMs } = summarizeArweaveEdges(arweaveEdges, cutoffSeconds);

  const shortfall = settled - d1Count;
  let drift = false;
  let reason;

  if (shortfall > 0) {
    // Arweave has settled (indexed, past the lag window) rows that D1 lacks.
    drift = true;
    reason = `d1 missing ${shortfall} settled arweave row(s) (d1=${d1Count}, arweave_settled=${settled})`;
  } else if (d1Count > settled + inFlight) {
    // D1 claims MORE rows than Arweave has indexed at all (settled+inFlight).
    // This is only "drift" if the gap can't be explained by indexing lag.
    // Because in-flight covers the lag window, a D1 surplus beyond
    // settled+inFlight means D1 has rows Arweave has no record of — possible
    // if a write hit D1 but the Turbo upload silently failed. We surface it as
    // an informational (non-fatal) note rather than missing-data drift, since
    // it could also be the GraphQL query being capped (paging). Keep it
    // non-drift to avoid false alarms from pagination caps; the count is in
    // the report for an operator to eyeball.
    drift = false;
    reason = `d1 ahead by ${d1Count - settled - inFlight} (likely in-flight uploads or graphql page cap; d1=${d1Count}, arweave_total=${settled + inFlight})`;
  } else {
    drift = false;
    reason = `ok (d1=${d1Count}, arweave_settled=${settled}, in_flight=${inFlight})`;
  }

  return {
    ns,
    drift,
    reason,
    d1Count,
    arweaveSettled: settled,
    arweaveInFlight: inFlight,
    shortfall: shortfall > 0 ? shortfall : 0,
    latestSettledMs,
    d1LatestMs,
  };
}

/**
 * Latest activity timestamp (unix ms) across a set of edges, ignoring the lag
 * window. Convenience for reports; uses the rebuild-core sort so the tiebreak
 * matches the rest of the system.
 * @param {Array} edges
 * @returns {number|null}
 */
export function latestEdgeMs(edges) {
  if (!edges || edges.length === 0) return null;
  const sorted = sortEdgesByTimestamp(edges);
  const latest = sorted[sorted.length - 1];
  const ts = latest?.node?.block?.timestamp;
  return ts ? ts * 1000 : null;
}

/**
 * Roll up per-namespace comparisons into an overall drift verdict.
 * @param {Array} comparisons - output of compareNamespace per ns
 * @returns {{healthy: boolean, drifted: string[], namespaces: Array}}
 */
export function summarizeDrift(comparisons) {
  const drifted = comparisons.filter((c) => c.drift).map((c) => c.ns);
  return {
    healthy: drifted.length === 0,
    drifted,
    namespaces: comparisons,
  };
}
