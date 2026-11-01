// drift.js — pure D1<->Arweave drift detection for the CORE observability
// subsystem.
//
// Drift means: a Tarn-signed record settled on Arweave recently, but D1 has
// no trace of it. It is a per-record, windowed, key comparison — not a count
// comparison. Arweave keeps every historical record (credential republishes,
// deletion tombstones, test accounts, rows from before a deliberate D1 reset)
// while D1 holds only what Tarn wrote and still has. Comparing "how many
// GraphQL edges" with "how many D1 rows" can never pass in production.
//
// Every Tarn write records its Arweave data-item id before (or regardless of)
// the upload, so D1 should know every recent Tarn-signed record:
//   - cred / passkey-reg / app-config → entries.txid (node.id). Nothing in the
//     API deletes `entries` rows.
//   - share-inbox / share-inbox-accept → share_inbox.txid
//   - share-log → share_log.txid
//   - app-reg → apps.app_id, keyed by the Lk tag. Some app-reg blobs are
//     uploaded by a CLI that does not write `entries`.
//
// Window: an edge is checked only when it has a block timestamp (unix seconds)
// and windowStartMs <= ts*1000 <= settledCutoffMs, where
//   settledCutoffMs = now - lagWindowMs   (DRIFT_LAG_WINDOW_MS, default 30 min)
//   windowStartMs   = settledCutoffMs - windowMs  (DRIFT_WINDOW_MS, default 7 days)
// No block, or newer than the cutoff: in-flight (not checked). Older than
// windowStartMs: history (ignored).
//
// Owner: only Tarn-signed records count. When the signing address is known and
// the edge has node.owner.address, the edge is foreign (skipped) unless that
// address ends with the signing address (arweave.net reports
// "did:pkh:eip155:1:0x…"). Edges with no owner info are kept.
//
// This does NOT detect:
//   - a targeted delete from `accounts` (or passkey_credentials) that leaves
//     the `entries` row intact — the txid is still known;
//   - drift older than the window (deliberate: historical Arweave records are
//     not a cache-miss signal).
//
// This module is pure: no GraphQL and no D1. The scheduled handler fetches
// edges and known keys and hands them here.

import { tagValue, sortEdgesByTimestamp } from '../../../tools/lib/rebuild-core.mjs';

// Default lag window: 30 minutes. arweave.net L1 indexing runs ~15–25 min
// behind a Turbo upload; 30 min sits above that so a record that has not
// settled yet is in-flight, not drift. Configurable via env.DRIFT_LAG_WINDOW_MS.
export const DEFAULT_LAG_WINDOW_MS = 30 * 60 * 1000;

// How far behind the lag cutoff we still look. Older than this is history.
// Configurable via env.DRIFT_WINDOW_MS.
export const DEFAULT_DRIFT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

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
 * literal" — the caller queries Type only and we don't pin App.
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
 * Lookup key for one namespace. cred / passkey-reg / app-config / share-* use
 * the data-item id (GraphQL node.id = D1 txid). app-reg uses the Lk tag
 * (the app_id), because a CLI uploader never writes `entries`.
 * @param {string} ns
 * @returns {(edge: any) => string|null}
 */
export function keyOfForNamespace(ns) {
  if (ns === 'app-reg') return (edge) => tagValue(edge, 'Lk');
  return (edge) => edge?.node?.id ?? null;
}

/**
 * Classify edges into the keys that must be present in D1, plus the edges we
 * deliberately do not check.
 *
 * Each edge lands in exactly one bucket:
 *   - foreign: owner address present, signing address known, and it does not
 *     end with that address (skipped before the window is applied);
 *   - inFlight: no block, or block timestamp newer than settledCutoffMs;
 *   - outsideWindow: block timestamp older than windowStartMs;
 *   - checked: settled inside the window. `checked` is the lookup keys, in
 *     edge order. An edge with no key (app-reg missing Lk) is not checked.
 *
 * @param {Object} args
 * @param {Array} args.edges
 * @param {(edge: any) => string|null} args.keyOf
 * @param {number} args.now - unix ms
 * @param {number} args.lagWindowMs
 * @param {number} args.windowMs
 * @param {string|null} [args.ownerAddress] - Tarn signing address, or null if unknown
 * @returns {{ checked: string[], inFlight: number, outsideWindow: number, foreign: number }}
 */
export function selectCheckedEdges({ edges, keyOf, now, lagWindowMs, windowMs, ownerAddress }) {
  const settledCutoffMs = now - lagWindowMs;
  const windowStartMs = settledCutoffMs - windowMs;
  const signing = typeof ownerAddress === 'string' && ownerAddress.length > 0
    ? ownerAddress.toLowerCase()
    : null;

  const checked = [];
  let inFlight = 0;
  let outsideWindow = 0;
  let foreign = 0;

  for (const edge of edges || []) {
    const addr = edge?.node?.owner?.address;
    if (signing && addr && !String(addr).toLowerCase().endsWith(signing)) {
      foreign += 1;
      continue;
    }
    const ts = edge?.node?.block?.timestamp;
    if (ts == null || ts * 1000 > settledCutoffMs) {
      inFlight += 1;
      continue;
    }
    if (ts * 1000 < windowStartMs) {
      outsideWindow += 1;
      continue;
    }
    const key = keyOf(edge);
    if (key == null || key === '') continue;
    checked.push(key);
  }

  return { checked, inFlight, outsideWindow, foreign };
}

/**
 * Compare one namespace's settled in-window Arweave records against the keys
 * D1 already knows. drift is true only when at least one checked key is missing.
 *
 * @param {Object} args
 * @param {string} args.ns
 * @param {Array} args.edges - GraphQL edges ({node:{id,block,owner,tags}})
 * @param {Iterable<string>} args.knownKeys - keys D1 returned for this namespace
 * @param {(edge: any) => string|null} args.keyOf
 * @param {number} args.now - unix ms
 * @param {number} args.lagWindowMs
 * @param {number} args.windowMs
 * @param {string|null} [args.ownerAddress]
 * @returns {{ns: string, drift: boolean, reason: string, checked: number,
 *            missing: number, missingSample: string[], inFlight: number,
 *            outsideWindow: number, foreign: number}}
 */
export function compareNamespace({ ns, edges, knownKeys, keyOf, now, lagWindowMs, windowMs, ownerAddress }) {
  const selected = selectCheckedEdges({ edges, keyOf, now, lagWindowMs, windowMs, ownerAddress });
  const known = new Set(knownKeys || []);
  const missingKeys = [];
  for (const key of selected.checked) {
    if (!known.has(key)) missingKeys.push(key);
  }
  const missing = missingKeys.length;
  const drift = missing > 0;
  const reason = drift
    ? `d1 missing ${missing} settled in-window record(s) (checked=${selected.checked.length})`
    : `ok (checked=${selected.checked.length}, in_flight=${selected.inFlight}, outside_window=${selected.outsideWindow}, foreign=${selected.foreign})`;

  return {
    ns,
    drift,
    reason,
    checked: selected.checked.length,
    missing,
    missingSample: missingKeys.slice(0, 5),
    inFlight: selected.inFlight,
    outsideWindow: selected.outsideWindow,
    foreign: selected.foreign,
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
