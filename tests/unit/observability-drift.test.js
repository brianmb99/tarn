// Unit tests for api/src/observability/drift.js — per-record, windowed drift.
// A checked record is a Tarn-signed edge that has settled inside the window.
// Drift is "D1 has no key for that record", not "the counts differ".
//
// Run: node --import tsx --test tests/unit/observability-drift.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_LAG_WINDOW_MS,
  DEFAULT_DRIFT_WINDOW_MS,
  selectCheckedEdges,
  compareNamespace,
  summarizeDrift,
  latestEdgeMs,
  keyOfForNamespace,
  TRACKED_NAMESPACES,
} from '../../api/src/observability/drift.js';

// A fixed "now" so timestamp math is deterministic.
const NOW = 1_700_000_000_000; // unix ms
const SEC = 1000;
const MIN = 60 * SEC;
const DAY = 24 * 60 * MIN;

const idOf = (e) => e?.node?.id ?? null;
const lkOf = (e) => e?.node?.tags?.find((t) => t.name === 'Lk')?.value ?? null;

// Build a GraphQL-shaped edge with a block timestamp `agoMs` before NOW.
// timestamp is unix SECONDS (matching Arweave). agoMs=null => unconfirmed.
function edge(agoMs, id = Math.random().toString(36).slice(2), { owner, tags } = {}) {
  const node = { id, tags: tags || [] };
  if (owner) node.owner = { address: owner };
  if (agoMs == null) node.block = null;
  else node.block = { timestamp: Math.floor((NOW - agoMs) / 1000), height: 1 };
  return { node };
}

function compare(overrides = {}) {
  return compareNamespace({
    ns: 'cred',
    now: NOW,
    lagWindowMs: DEFAULT_LAG_WINDOW_MS,
    windowMs: DEFAULT_DRIFT_WINDOW_MS,
    keyOf: idOf,
    knownKeys: new Set(),
    edges: [],
    ...overrides,
  });
}

describe('compareNamespace — settled in-window keys', () => {
  it('does not flag drift when D1 knows the settled txid', () => {
    const edges = [edge(2 * DAY, 'txid-known')];
    const r = compare({ edges, knownKeys: new Set(['txid-known']) });
    assert.equal(r.drift, false);
    assert.equal(r.checked, 1);
    assert.equal(r.missing, 0);
    assert.deepEqual(r.missingSample, []);
    assert.equal(r.inFlight, 0);
    assert.equal(r.outsideWindow, 0);
    assert.equal(r.foreign, 0);
  });

  it('flags drift when D1 does not know a settled in-window txid', () => {
    const edges = [edge(2 * DAY, 'txid-missing')];
    const r = compare({ edges, knownKeys: new Set() });
    assert.equal(r.drift, true);
    assert.equal(r.missing, 1);
    assert.equal(r.checked, 1);
    assert.deepEqual(r.missingSample, ['txid-missing']);
    assert.match(r.reason, /missing 1 settled in-window/);
  });

  it('caps missingSample at the first 5 missing keys', () => {
    const edges = Array.from({ length: 7 }, (_, i) => edge(2 * DAY, `m${i}`));
    const r = compare({ edges });
    assert.equal(r.missing, 7);
    assert.deepEqual(r.missingSample, ['m0', 'm1', 'm2', 'm3', 'm4']);
  });

  it('treats an empty edge list as healthy', () => {
    const r = compare({ edges: [] });
    assert.equal(r.drift, false);
    assert.equal(r.checked, 0);
    assert.equal(r.missing, 0);
  });

  it('includes an edge exactly at either window bound', () => {
    const atCutoff = edge(DEFAULT_LAG_WINDOW_MS, 'at-cutoff');
    const atStart = edge(DEFAULT_LAG_WINDOW_MS + DEFAULT_DRIFT_WINDOW_MS, 'at-start');
    const r = compare({
      edges: [atCutoff, atStart],
      knownKeys: new Set(['at-cutoff', 'at-start']),
    });
    assert.equal(r.drift, false);
    assert.equal(r.checked, 2);
    assert.equal(r.inFlight, 0);
    assert.equal(r.outsideWindow, 0);
  });
});

describe('compareNamespace — history and in-flight are not drift', () => {
  it('ignores many old edges D1 has never seen (the production false positive)', () => {
    // Production has thousands of historical cred records on Arweave and ~100
    // current account rows. Those old edges must not flag DRIFT.
    const edges = Array.from({ length: 600 }, (_, i) => edge(400 * DAY, `old-${i}`));
    const r = compare({ edges, knownKeys: new Set() });
    assert.equal(r.drift, false);
    assert.equal(r.checked, 0);
    assert.equal(r.missing, 0);
    assert.equal(r.outsideWindow, 600);
    assert.deepEqual(r.missingSample, []);
  });

  it('still flags one in-window miss sitting behind a pile of old edges', () => {
    const old = Array.from({ length: 600 }, (_, i) => edge(400 * DAY, `old-${i}`));
    const edges = [...old, edge(2 * DAY, 'recent-miss')];
    const r = compare({ edges });
    assert.equal(r.drift, true);
    assert.equal(r.missing, 1);
    assert.deepEqual(r.missingSample, ['recent-miss']);
    assert.equal(r.outsideWindow, 600);
  });

  it('does not flag in-flight edges (no block, or newer than the lag cutoff)', () => {
    const edges = [
      edge(null, 'unconfirmed'),
      edge(5 * MIN, 'still-indexing'),
    ];
    const r = compare({ edges, knownKeys: new Set() });
    assert.equal(r.drift, false);
    assert.equal(r.checked, 0);
    assert.equal(r.missing, 0);
    assert.equal(r.inFlight, 2);
  });

  it('treats one second newer than the cutoff as in-flight and one second older than the window as history', () => {
    const edges = [
      edge(DEFAULT_LAG_WINDOW_MS - SEC, 'too-new'),
      edge(DEFAULT_LAG_WINDOW_MS + DEFAULT_DRIFT_WINDOW_MS + SEC, 'too-old'),
    ];
    const r = compare({ edges });
    assert.equal(r.drift, false);
    assert.equal(r.inFlight, 1);
    assert.equal(r.outsideWindow, 1);
    assert.equal(r.checked, 0);
  });
});

describe('compareNamespace — owner filter', () => {
  const signing = '0xaf93cBd1270aA26F5672056cEbbFa8Bb3130c4a4';

  it('does not flag a foreign-owner edge D1 has never seen', () => {
    const edges = [edge(2 * DAY, 'someone-else', {
      owner: 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111',
    })];
    const r = compare({ edges, ownerAddress: signing });
    assert.equal(r.drift, false);
    assert.equal(r.foreign, 1);
    assert.equal(r.checked, 0);
    assert.equal(r.missing, 0);
  });

  it('flags the same edge when the owner is Tarn, even with mixed-case hex', () => {
    const edges = [edge(2 * DAY, 'ours', {
      owner: 'did:pkh:eip155:1:0xAF93CbD1270Aa26f5672056CeBBFa8bB3130C4A4',
    })];
    const r = compare({ edges, ownerAddress: signing });
    assert.equal(r.drift, true);
    assert.equal(r.foreign, 0);
    assert.equal(r.missing, 1);
    assert.deepEqual(r.missingSample, ['ours']);
  });

  it('keeps edges that have no owner info', () => {
    const edges = [edge(2 * DAY, 'no-owner')];
    const r = compare({ edges, ownerAddress: signing });
    assert.equal(r.drift, true);
    assert.equal(r.foreign, 0);
    assert.equal(r.missing, 1);
  });

  it('does not filter owners when the signing address is unknown', () => {
    const edges = [edge(2 * DAY, 'foreign-kept', {
      owner: 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111',
    })];
    const r = compare({ edges, ownerAddress: null });
    assert.equal(r.drift, true);
    assert.equal(r.foreign, 0);
  });
});

describe('compareNamespace — app-reg uses the Lk tag', () => {
  it('compares Lk against known app ids and ignores the edge id', () => {
    const edges = [
      edge(2 * DAY, 'txid-not-the-key', { tags: [{ name: 'Lk', value: 'app_known' }] }),
      edge(2 * DAY, 'also-not-the-key', { tags: [{ name: 'Lk', value: 'app_missing' }] }),
    ];
    const r = compare({
      ns: 'app-reg',
      edges,
      keyOf: lkOf,
      knownKeys: new Set(['app_known']),
    });
    assert.equal(r.checked, 2);
    assert.equal(r.missing, 1);
    assert.deepEqual(r.missingSample, ['app_missing']);
    assert.equal(r.drift, true);
    assert.equal(keyOfForNamespace('app-reg')(edges[0]), 'app_known');
    assert.equal(keyOfForNamespace('cred')(edges[0]), 'txid-not-the-key');
  });
});

describe('compareNamespace — windowMs', () => {
  it('a shorter window turns a settled edge into history', () => {
    const edges = [edge(3 * DAY, 'three-days')];
    const inside = compare({ edges, windowMs: DEFAULT_DRIFT_WINDOW_MS });
    assert.equal(inside.drift, true);
    assert.equal(inside.checked, 1);
    const outside = compare({ edges, windowMs: 1 * DAY });
    assert.equal(outside.drift, false);
    assert.equal(outside.checked, 0);
    assert.equal(outside.outsideWindow, 1);
  });
});

describe('selectCheckedEdges', () => {
  it('returns the checked keys in edge order', () => {
    const edges = [edge(2 * DAY, 'a'), edge(5 * MIN, 'b'), edge(2 * DAY, 'c')];
    const sel = selectCheckedEdges({
      edges,
      keyOf: idOf,
      now: NOW,
      lagWindowMs: DEFAULT_LAG_WINDOW_MS,
      windowMs: DEFAULT_DRIFT_WINDOW_MS,
      ownerAddress: null,
    });
    assert.deepEqual(sel.checked, ['a', 'c']);
    assert.equal(sel.inFlight, 1);
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
    assert.equal(s.namespaces, comparisons);
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

describe('defaults', () => {
  it('exports the 30 min lag and the 7 day window', () => {
    assert.equal(DEFAULT_LAG_WINDOW_MS, 30 * MIN);
    assert.equal(DEFAULT_DRIFT_WINDOW_MS, 7 * DAY);
  });
});
