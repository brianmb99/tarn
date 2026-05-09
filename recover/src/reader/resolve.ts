/**
 * Eid + Prev-chain + tombstone resolver — client-side port.
 *
 * In the live SDK, `getEntries(type)` lands at the Tarn API which calls
 * `getResolvedEntries` in `api/src/cache.js`. That server-side helper:
 *   1. Collects the set of `tombstone_ref` targets across all rows.
 *   2. Collects the set of `prev_txid` targets (superseded entries).
 *   3. Drops every row that is itself a tombstone, OR that has been
 *      tombstoned, OR that has been superseded.
 *   4. Groups what remains by `Eid` and keeps only the newest per group
 *      (highest `block_timestamp`, with `cached_at` as a tiebreaker).
 *
 * The recover package can't call the API, so this module reproduces the
 * same semantics over a `BlobRecord[]` (Phase 2's `findContentBlobs`
 * output). Inputs:
 *   - `txid`              ← `BlobRecord.txid`
 *   - `is_tombstone`      ← `tagMap['Op'] === 'tombstone'`
 *   - `tombstone_ref`     ← `tagMap['Ref']`
 *   - `prev_txid`         ← `tagMap['Prev']`
 *   - `eid`               ← `tagMap['Eid']`
 *   - `block_timestamp`   ← `BlobRecord.blockTimestamp`
 *
 * Outputs the surviving `BlobRecord[]` plus a `tombstoneCount` for the
 * Reader to expose. Pure function, no I/O.
 *
 * Faithfulness to `api/src/cache.js` `resolveEntries`:
 *   - Tombstone-target set + Prev-set collection: identical.
 *   - Drop-rule order (tombstone-self → tombstoned-target → superseded):
 *     identical.
 *   - Eid grouping with newest-wins: identical. The server falls back on
 *     `cached_at` when block timestamps tie; the recover package uses the
 *     blob's input order (a stable proxy that mirrors the on-chain order
 *     `findContentBlobs` already sorted ascending).
 */

import type { BlobRecord } from '../gateway/queries.js';

/**
 * Collapse a list of content blobs to the live "post-resolver" view.
 *
 * `blobs` is the raw output of {@link import('../gateway/queries.js').findContentBlobs}
 * (sorted ascending by block height). The function is pure: it reads
 * tags + block timestamps and returns a filtered/deduped subset along
 * with a count of distinct logical records that were tombstoned.
 */
export function resolveContentBlobs(blobs: BlobRecord[]): {
  live: BlobRecord[];
  tombstoneCount: number;
} {
  // 1. Collect tombstone targets.
  const tombRefs = new Set<string>();
  for (const b of blobs) {
    if (isTombstone(b) && b.tagMap['Ref']) {
      tombRefs.add(b.tagMap['Ref']);
    }
  }

  // 2. Collect superseded txids (Prev-chain).
  const superseded = new Set<string>();
  for (const b of blobs) {
    const prev = b.tagMap['Prev'];
    if (prev) {
      superseded.add(prev);
    }
  }

  // 3. Filter: exclude tombstones, tombstoned entries, superseded entries.
  const live = blobs.filter((b) => {
    if (isTombstone(b)) return false;
    if (tombRefs.has(b.txid)) return false;
    if (superseded.has(b.txid)) return false;
    return true;
  });

  // 4. Eid dedup: if multiple entries share an Eid, keep only the newest.
  //    (For well-formed data, Prev-chain already handles this. Eid is a
  //    safety net — preserves the server-side behavior.)
  const eidGroups = new Map<string, { blob: BlobRecord; idx: number }[]>();
  const noEid: BlobRecord[] = [];
  live.forEach((b, idx) => {
    const eid = b.tagMap['Eid'];
    if (eid) {
      const list = eidGroups.get(eid) ?? [];
      list.push({ blob: b, idx });
      eidGroups.set(eid, list);
    } else {
      noEid.push(b);
    }
  });

  const deduped: BlobRecord[] = [...noEid];
  for (const [, group] of eidGroups) {
    if (group.length === 1) {
      deduped.push(group[0]!.blob);
      continue;
    }
    // Multiple entries with same Eid — pick the newest. Sort by
    // block_timestamp DESC; tiebreak by input position DESC (since the
    // input is height-ASC, the later position is the newer arrival).
    group.sort((a, b) => {
      const ta = a.blob.blockTimestamp ?? 0;
      const tb = b.blob.blockTimestamp ?? 0;
      if (tb !== ta) return tb - ta;
      return b.idx - a.idx;
    });
    deduped.push(group[0]!.blob);
  }

  // Tombstone count = number of distinct logical records that were
  // tombstoned. We approximate by counting tombstone-Ref entries that
  // matched a real txid in the input (i.e., ignore stray tombstones for
  // entries we never saw). This matches the server semantic in spirit:
  // each tombstone applies to one underlying record.
  const txids = new Set(blobs.map((b) => b.txid));
  let tombstoneCount = 0;
  for (const ref of tombRefs) {
    if (txids.has(ref)) tombstoneCount++;
  }

  return { live: deduped, tombstoneCount };
}

function isTombstone(b: BlobRecord): boolean {
  return b.tagMap['Op'] === 'tombstone';
}
