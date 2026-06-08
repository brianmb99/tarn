// Unit tests for api/src/observability/drift.js — the D1<->Arweave drift
// comparison, focused on the hard part: distinguishing normal indexing LAG
// from true DRIFT.
//
// Run: node --test tests/unit/observability-drift.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_LAG_WINDOW_MS,
  summarizeArweaveEdges,
  compareNamespace,
  summarizeDrift,
  latestEdgeMs,
  TRACKED_NAMESPACES,
} from '../../api/src/observability/drift.js';

// A fixed "now" so timestamp math is deterministic.
const NOW = 1_700_000_000_000; // unix ms
const SEC = 1000;
const MIN = 60 * SEC;

// Build a GraphQL-shaped edge with a block timestamp `agoMs` before NOW.
// timestamp is unix SECONDS (matching Arweave). agoMs=null => unconfirmed.
function edge(agoMs, id = Math.random().toString(36).slice(2)) {
  if (agoMs == null) {
    return { node: { id, block: null } };
  }
  return { node: { id, block: { timestamp: Math.floor((NOW - agoMs) / 1000), height: 1 } } };
}

describe('summarizeArweaveEdges', () => {
  it('splits edges into settled vs in-flight at the cutoff', () => {
    const cutoffSeconds = Math.floor((NOW - 30 * MIN) / 1000);
    const edges = [
      edge(60 * MIN), // settled (older than 30m)
      edge(45 * MIN), // settled
      edge(10 * MIN), // in-flight (newer than 30m)
      edge(null),     // unconfirmed -> in-flight
    ];
    const { settled, inFlight } = summarizeArweaveEdges(edges, cutoffSeconds);
    assert.equal(settled, 2);
    assert.equal(inFlight, 2);
  });

  it('tracks the latest settled timestamp in ms', () => {
    const cutoffSeconds = Math.floor((NOW - 30 * MIN) / 1000);
    const edges = [edge(90 * MIN), edge(40 * MIN), edge(35 * MIN)];
    const { latestSettledMs } = summarizeArweaveEdges(edges, cutoffSeconds);
    // latest settled is the 35-min-old one.
    assert.equal(latestSettledMs, Math.floor((NOW - 35 * MIN) / 1000) * 1000);
  });

  it('returns zeros for an empty edge list', () => {
    const r = summarizeArweaveEdges([], 0);
    assert.deepEqual(r, { settled: 0, inFlight: 0, latestSettledMs: null });
  });
});

describe('compareNamespace — lag vs true drift', () => {
  const base = { ns: 'cred', now: NOW, lagWindowMs: DEFAULT_LAG_WINDOW_MS };

  it('does NOT flag drift when D1 trails Arweave only on RECENT (in-flight) writes', () => {
    // Arweave has 3 edges, but 2 are within the lag window (just uploaded).
    // D1 has 1 settled row. The 2 recent ones are still indexing — NOT drift.
    const arweaveEdges = [
      edge(60 * MIN), // settled
      edge(10 * MIN), // in-flight
      edge(5 * MIN),  // in-flight
    ];
    const r = compareNamespace({ ...base, d1Count: 1, arweaveEdges });
    assert.equal(r.drift, false, 'recent-write lag must not be drift');
    assert.equal(r.arweaveSettled, 1);
    assert.equal(r.arweaveInFlight, 2);
    assert.equal(r.shortfall, 0);
  });

  it('FLAGS drift when D1 is missing a SETTLED (past-lag-window) Arweave row', () => {
    // Two edges, BOTH older than the lag window => both settled. D1 has only 1.
    // The missing one has been indexed long enough that D1 should have it.
    const arweaveEdges = [edge(90 * MIN), edge(60 * MIN)];
    const r = compareNamespace({ ...base, d1Count: 1, arweaveEdges });
    assert.equal(r.drift, true, 'a settled row missing from D1 IS drift');
    assert.equal(r.arweaveSettled, 2);
    assert.equal(r.shortfall, 1);
    assert.match(r.reason, /missing 1 settled/);
  });

  it('does NOT flag drift when D1 is exactly caught up to settled', () => {
    const arweaveEdges = [edge(90 * MIN), edge(60 * MIN), edge(5 * MIN)];
    const r = compareNamespace({ ...base, d1Count: 2, arweaveEdges });
    assert.equal(r.drift, false);
    assert.equal(r.arweaveSettled, 2);
    assert.equal(r.shortfall, 0);
  });

  it('does NOT flag drift when D1 is AHEAD (healthy write-through)', () => {
    // D1 wrote 5 rows at request time; Arweave has only indexed 2 settled + 1
    // in-flight. D1 ahead is the normal write-through case, never drift.
    const arweaveEdges = [edge(90 * MIN), edge(60 * MIN), edge(5 * MIN)];
    const r = compareNamespace({ ...base, d1Count: 5, arweaveEdges });
    assert.equal(r.drift, false, 'D1 ahead is healthy, not drift');
    assert.equal(r.shortfall, 0);
    assert.match(r.reason, /ahead/);
  });

  it('respects a custom (shorter) lag window — what was in-flight becomes settled', () => {
    // With a 1-minute lag window, a 10-min-old edge is now "settled".
    const arweaveEdges = [edge(10 * MIN)];
    const drifts = compareNamespace({ ...base, d1Count: 0, arweaveEdges, lagWindowMs: 1 * MIN });
    assert.equal(drifts.drift, true, '10m-old edge is settled under a 1m window');
    // Same edge under the default 30m window is still in-flight => no drift.
    const ok = compareNamespace({ ...base, d1Count: 0, arweaveEdges, lagWindowMs: DEFAULT_LAG_WINDOW_MS });
    assert.equal(ok.drift, false, '10m-old edge is in-flight under the 30m window');
  });

  it('treats a fully-empty namespace (D1=0, Arweave=0) as healthy', () => {
    const r = compareNamespace({ ...base, d1Count: 0, arweaveEdges: [] });
    assert.equal(r.drift, false);
    assert.equal(r.shortfall, 0);
  });
});

describe('summarizeDrift rollup', () => {
  it('is healthy when no namespace drifts', () => {
    const comparisons = [
      { ns: 'cred', drift: false },
      { ns: 'app-reg', drift: false },
    ];
    const s = summarizeDrift(comparisons);
    assert.equal(s.healthy, true);
    assert.deepEqual(s.drifted, []);
  });

  it('reports every drifted namespace and flips healthy=false', () => {
    const comparisons = [
      { ns: 'cred', drift: false },
      { ns: 'passkey-reg', drift: true },
      { ns: 'share-log', drift: true },
    ];
    const s = summarizeDrift(comparisons);
    assert.equal(s.healthy, false);
    assert.deepEqual(s.drifted, ['passkey-reg', 'share-log']);
  });
});

describe('latestEdgeMs', () => {
  it('returns null for empty', () => {
    assert.equal(latestEdgeMs([]), null);
  });
  it('returns the newest block timestamp in ms', () => {
    const edges = [edge(60 * MIN), edge(5 * MIN), edge(30 * MIN)];
    assert.equal(latestEdgeMs(edges), Math.floor((NOW - 5 * MIN) / 1000) * 1000);
  });
});

describe('TRACKED_NAMESPACES sanity', () => {
  it('covers the identity-plane + share namespaces from the recoverability audit', () => {
    const names = TRACKED_NAMESPACES.map((n) => n.ns);
    for (const required of ['cred', 'app-reg', 'passkey-reg', 'app-config', 'share-inbox', 'share-log']) {
      assert.ok(names.includes(required), `missing tracked namespace: ${required}`);
    }
  });
  it('pins App=tarn for identity-plane and App=tarn-share for share namespaces', () => {
    const byNs = Object.fromEntries(TRACKED_NAMESPACES.map((n) => [n.ns, n]));
    assert.equal(byNs.cred.appTag, 'tarn');
    assert.equal(byNs['app-reg'].appTag, 'tarn');
    assert.equal(byNs['passkey-reg'].appTag, 'tarn');
    // app-config is per-app (App=<app_id>), so appTag is null (unpinned).
    assert.equal(byNs['app-config'].appTag, null);
    assert.equal(byNs['share-inbox'].appTag, 'tarn-share');
    assert.equal(byNs['share-log'].appTag, 'tarn-share');
  });
});
