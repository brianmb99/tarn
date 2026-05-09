/**
 * Unit tests for the Eid + Prev-chain + tombstone resolver.
 *
 * Pure-function tests against scripted `BlobRecord[]`. Each test covers a
 * specific server-side semantic in `api/src/cache.js` `resolveEntries`,
 * with comments naming the matching server behavior so future readers can
 * cross-reference.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { resolveContentBlobs } from '../src/reader/resolve.js';
import type { BlobRecord } from '../src/gateway/queries.js';

function blob(args: {
  txid: string;
  height: number;
  eid?: string;
  prev?: string;
  tombstone?: { ref: string };
  extraTags?: Record<string, string>;
}): BlobRecord {
  const tags: { name: string; value: string }[] = [
    { name: 'App', value: 'recover-test' },
    { name: 'Type', value: 'books' },
    { name: 'Lk', value: 'd'.repeat(64) },
  ];
  if (args.eid) tags.push({ name: 'Eid', value: args.eid });
  if (args.prev) tags.push({ name: 'Prev', value: args.prev });
  if (args.tombstone) {
    tags.push({ name: 'Op', value: 'tombstone' });
    tags.push({ name: 'Ref', value: args.tombstone.ref });
  }
  for (const [k, v] of Object.entries(args.extraTags ?? {})) {
    tags.push({ name: k, value: v });
  }
  const tagMap: Record<string, string> = {};
  for (const t of tags) tagMap[t.name] = t.value;
  return {
    txid: args.txid,
    tags,
    tagMap,
    blockTimestamp: 1700000000 + args.height,
    blockHeight: args.height,
    async loadBody() {
      throw new Error('resolver tests should not load bodies');
    },
  };
}

describe('resolveContentBlobs: tombstone semantics', () => {
  it('drops tombstones from the live set', () => {
    const a = blob({ txid: 'a', height: 1 });
    const tomb = blob({ txid: 't', height: 2, tombstone: { ref: 'a' } });
    const { live, tombstoneCount } = resolveContentBlobs([a, tomb]);
    assert.deepEqual(live.map((b) => b.txid), []);
    assert.equal(tombstoneCount, 1);
  });

  it('drops the tombstoned target itself', () => {
    const a = blob({ txid: 'a', height: 1 });
    const b = blob({ txid: 'b', height: 2 });
    const tomb = blob({ txid: 't', height: 3, tombstone: { ref: 'a' } });
    const { live, tombstoneCount } = resolveContentBlobs([a, b, tomb]);
    assert.deepEqual(live.map((x) => x.txid).sort(), ['b']);
    assert.equal(tombstoneCount, 1);
  });

  it('counts each distinct tombstoned record once', () => {
    const a = blob({ txid: 'a', height: 1 });
    const b = blob({ txid: 'b', height: 2 });
    const ta = blob({ txid: 'ta', height: 3, tombstone: { ref: 'a' } });
    const tb = blob({ txid: 'tb', height: 4, tombstone: { ref: 'b' } });
    const { live, tombstoneCount } = resolveContentBlobs([a, b, ta, tb]);
    assert.deepEqual(live, []);
    assert.equal(tombstoneCount, 2);
  });

  it('ignores stray tombstones whose Ref is not in the input', () => {
    const a = blob({ txid: 'a', height: 1 });
    const tStray = blob({ txid: 't', height: 2, tombstone: { ref: 'never-existed' } });
    const { live, tombstoneCount } = resolveContentBlobs([a, tStray]);
    assert.deepEqual(live.map((x) => x.txid), ['a']);
    assert.equal(tombstoneCount, 0);
  });
});

describe('resolveContentBlobs: Prev-chain', () => {
  it('drops superseded versions, keeps only the tip', () => {
    const v1 = blob({ txid: 'v1', height: 1, eid: 'eid-a' });
    const v2 = blob({ txid: 'v2', height: 2, eid: 'eid-a', prev: 'v1' });
    const v3 = blob({ txid: 'v3', height: 3, eid: 'eid-a', prev: 'v2' });
    const { live } = resolveContentBlobs([v1, v2, v3]);
    assert.deepEqual(live.map((b) => b.txid), ['v3']);
  });

  it('handles a tombstone over an updated record', () => {
    const v1 = blob({ txid: 'v1', height: 1, eid: 'eid-a' });
    const v2 = blob({ txid: 'v2', height: 2, eid: 'eid-a', prev: 'v1' });
    const tomb = blob({ txid: 't', height: 3, tombstone: { ref: 'v2' } });
    const { live, tombstoneCount } = resolveContentBlobs([v1, v2, tomb]);
    // v2 is tombstoned (drop), v1 is superseded by v2 (drop).
    assert.deepEqual(live, []);
    assert.equal(tombstoneCount, 1);
  });
});

describe('resolveContentBlobs: Eid dedup', () => {
  it('newest by block_timestamp wins among same-Eid entries', () => {
    // No Prev links — Eid grouping is the only thing that decides.
    const a = blob({ txid: 'a', height: 5, eid: 'eid-x' });
    const b = blob({ txid: 'b', height: 10, eid: 'eid-x' });
    const c = blob({ txid: 'c', height: 7, eid: 'eid-x' });
    const { live } = resolveContentBlobs([a, b, c]);
    assert.deepEqual(live.map((x) => x.txid), ['b']);
  });

  it('keeps no-Eid entries verbatim', () => {
    const a = blob({ txid: 'a', height: 1 });
    const b = blob({ txid: 'b', height: 2 });
    const { live } = resolveContentBlobs([a, b]);
    assert.deepEqual(live.map((x) => x.txid).sort(), ['a', 'b']);
  });

  it('mixes Eid-grouped and no-Eid entries', () => {
    const eA1 = blob({ txid: 'eA1', height: 1, eid: 'A' });
    const eA2 = blob({ txid: 'eA2', height: 2, eid: 'A' });
    const noEid = blob({ txid: 'plain', height: 3 });
    const { live } = resolveContentBlobs([eA1, eA2, noEid]);
    assert.deepEqual(live.map((x) => x.txid).sort(), ['eA2', 'plain']);
  });
});

describe('resolveContentBlobs: combined scenarios', () => {
  it('full lifecycle: create → update → update → tombstone', () => {
    const v1 = blob({ txid: 'v1', height: 1, eid: 'eid-a' });
    const v2 = blob({ txid: 'v2', height: 2, eid: 'eid-a', prev: 'v1' });
    const v3 = blob({ txid: 'v3', height: 3, eid: 'eid-a', prev: 'v2' });
    const tomb = blob({ txid: 't', height: 4, tombstone: { ref: 'v3' } });
    const { live, tombstoneCount } = resolveContentBlobs([v1, v2, v3, tomb]);
    assert.deepEqual(live, []);
    assert.equal(tombstoneCount, 1);
  });

  it('multiple records in one call, mix of live + tombstoned', () => {
    // Record A: created + updated, still live (tip = a2).
    // Record B: created, tombstoned.
    // Record C: created, still live.
    const a1 = blob({ txid: 'a1', height: 1, eid: 'eid-A' });
    const a2 = blob({ txid: 'a2', height: 2, eid: 'eid-A', prev: 'a1' });
    const b1 = blob({ txid: 'b1', height: 3, eid: 'eid-B' });
    const tb = blob({ txid: 'tb', height: 4, tombstone: { ref: 'b1' } });
    const c1 = blob({ txid: 'c1', height: 5, eid: 'eid-C' });
    const { live, tombstoneCount } = resolveContentBlobs([a1, a2, b1, tb, c1]);
    assert.deepEqual(live.map((x) => x.txid).sort(), ['a2', 'c1']);
    assert.equal(tombstoneCount, 1);
  });
});
