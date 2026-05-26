// D1 cache layer — upsert, resolution, one-shot Arweave bootstrap.
//
// Invariant: Tarn is the sole write path. Once a (dlk, app, type) tuple has been
// bootstrapped (either by a successful write through Tarn or a one-time GraphQL
// backfill on first read), D1 is authoritative for that tuple's live state.
// We do not periodically re-scan Arweave — there is nothing to reconcile against.
//
// Arweave is consulted only for cold bootstrap: the first read for a (dlk, app,
// type) where Tarn has no record of having processed any writes. This is a rare,
// one-shot operation per tuple (usually zero, since the write path sets the
// bootstrap marker directly).

import { searchEntriesByLookupKey } from './arweave.js';

// ============ TAG HELPERS ============

function tagValue(tags, name) {
  return tags?.find(t => t.name === name)?.value || null;
}

function edgeToRow(edge) {
  const node = edge.node;
  const tags = node.tags || [];
  return {
    txid: node.id,
    app: tagValue(tags, 'App') || '',
    type: tagValue(tags, 'Type') || '',
    wallet_addr: tagValue(tags, 'Addr')?.toLowerCase() || null,
    lookup_key: tagValue(tags, 'Lk') || null,
    eid: tagValue(tags, 'Eid') || null,
    prev_txid: tagValue(tags, 'Prev') || null,
    is_tombstone: tagValue(tags, 'Op') === 'tombstone' ? 1 : 0,
    tombstone_ref: tagValue(tags, 'Ref') || null,
    block_timestamp: node.block?.timestamp || null,
    tags_json: JSON.stringify(tags),
    cached_at: Date.now(),
  };
}

// ============ D1 UPSERT ============

/**
 * Upsert edges into D1. Batches in groups of 100 (D1 limit).
 */
export async function upsertEntries(db, edges) {
  if (edges.length === 0) return;

  const stmt = db.prepare(`
    INSERT INTO entries (txid, app, type, wallet_addr, lookup_key, eid, prev_txid,
                         is_tombstone, tombstone_ref, block_timestamp, tags_json, cached_at)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
    ON CONFLICT(txid) DO UPDATE SET
      block_timestamp = COALESCE(excluded.block_timestamp, entries.block_timestamp),
      cached_at = excluded.cached_at
  `);

  const rows = edges.map(edgeToRow);

  // Batch in groups of 100
  for (let i = 0; i < rows.length; i += 100) {
    const batch = rows.slice(i, i + 100).map(r =>
      stmt.bind(r.txid, r.app, r.type, r.wallet_addr, r.lookup_key, r.eid,
                r.prev_txid, r.is_tombstone, r.tombstone_ref, r.block_timestamp,
                r.tags_json, r.cached_at)
    );
    await db.batch(batch);
  }
}

// ============ RESOLUTION ============

/**
 * Get resolved (live) entries for a data_lookup_key+app+type.
 * Filters tombstones, superseded Prev-chain entries, and Eid duplicates.
 *
 * Deliberately excludes the blob_data column — clients fetch blobs separately
 * via /api/v1/entries/{txid}. With ~200 entries and ~10 MB of cumulative blob
 * data, loading them all into a single Worker invocation pushes us past the
 * 128 MB per-request memory limit and CF returns error 1102 (resource limits
 * exceeded). Metadata-only keeps this query O(rows) in memory regardless of
 * blob size.
 */
export async function getResolvedEntries(db, app, type, dataLookupKey, { limit = 100, cursor = null } = {}) {
  // Fetch all entry metadata for this scope (including tombstones and superseded).
  // blob_data is intentionally omitted — see header comment.
  const all = await db.prepare(
    `SELECT txid, app, type, wallet_addr, lookup_key, eid, prev_txid,
            is_tombstone, tombstone_ref, block_timestamp, tags_json, cached_at
     FROM entries WHERE app = ?1 AND type = ?2 AND lookup_key = ?3`
  ).bind(app, type, dataLookupKey).all();

  const rows = all.results || [];
  const live = resolveEntries(rows);

  // Apply cursor-based pagination (cursor = txid to start after)
  let start = 0;
  if (cursor) {
    const idx = live.findIndex(e => e.txid === cursor);
    if (idx >= 0) start = idx + 1;
  }

  const page = live.slice(start, start + limit);
  return { entries: page, total: live.length };
}

/**
 * Core resolution: tombstone + Prev-chain + Eid filtering.
 * Pure function — no side effects.
 */
export function resolveEntries(rows) {
  // 1. Collect tombstone targets
  const tombRefs = new Set();
  for (const r of rows) {
    if (r.is_tombstone && r.tombstone_ref) {
      tombRefs.add(r.tombstone_ref);
    }
  }

  // 2. Collect superseded txids (Prev-chain)
  const superseded = new Set();
  for (const r of rows) {
    if (r.prev_txid) {
      superseded.add(r.prev_txid);
    }
  }

  // 3. Filter: exclude tombstones, tombstoned entries, superseded entries
  let live = rows.filter(r => {
    if (r.is_tombstone) return false;
    if (tombRefs.has(r.txid)) return false;
    if (superseded.has(r.txid)) return false;
    return true;
  });

  // 4. Eid dedup: if multiple entries share an Eid, keep only the non-superseded one
  //    (For well-formed data, Prev-chain already handles this. Eid is a safety net.)
  const eidGroups = new Map();
  const noEid = [];
  for (const r of live) {
    if (r.eid) {
      if (!eidGroups.has(r.eid)) eidGroups.set(r.eid, []);
      eidGroups.get(r.eid).push(r);
    } else {
      noEid.push(r);
    }
  }

  const deduped = [...noEid];
  for (const [, group] of eidGroups) {
    if (group.length === 1) {
      deduped.push(group[0]);
    } else {
      // Multiple entries with same Eid — pick the newest (highest block_timestamp, or most recent cached_at)
      group.sort((a, b) => (b.block_timestamp || 0) - (a.block_timestamp || 0) || b.cached_at - a.cached_at);
      deduped.push(group[0]);
    }
  }

  return deduped;
}

/**
 * Resolve the delta of live state since a (cached_at, txid) cursor.
 *
 * Filters rows by `(cached_at, txid) > (sinceCachedAt, sinceTxid)`, groups
 * the result by Eid, runs resolution per Eid group, and emits semantic
 * events for each Eid that has any rows in the window:
 *   - Eid has a live row after resolution → { eid, txid, tags, ..., blob }
 *   - Eid has only tombstone(s) / superseded rows → { eid, deleted: true }
 *
 * Page-bounded by `limit`. Returns `nextCursor` = (max(cached_at), max(txid))
 * over the *input* rows (not the events), so the next poll picks up where
 * this one stopped regardless of how the events were grouped. When the
 * window is exhausted without hitting the limit, `nextCursor` is the
 * highest cursor seen and `hasMore` is false; the client just keeps that
 * cursor for the next poll.
 *
 * The wire-level tombstone abstraction stays server-side — clients never
 * see a "tombstone row", just a `deleted: true` event on the Eid. Same
 * way `update` doesn't expose Prev-chain mechanics to callers.
 */
export async function getDeltaEntries(db, app, type, dataLookupKey, since, { limit = 25 } = {}) {
  const sinceCachedAt = since?.cachedAt ?? 0;
  const sinceTxid = since?.txid ?? '';

  // Pull the next page of input rows by composite cursor. Include blob_data —
  // we inline blobs for live events so a single delta call covers metadata
  // and bytes for new entries (the same trade-off as the ?eid= fast path).
  const all = await db.prepare(
    `SELECT txid, app, type, wallet_addr, lookup_key, eid, prev_txid,
            is_tombstone, tombstone_ref, block_timestamp, tags_json, cached_at, blob_data
     FROM entries
     WHERE app = ?1 AND type = ?2 AND lookup_key = ?3
       AND (cached_at > ?4 OR (cached_at = ?4 AND txid > ?5))
     ORDER BY cached_at ASC, txid ASC
     LIMIT ?6`
  ).bind(app, type, dataLookupKey, sinceCachedAt, sinceTxid, limit).all();

  const rows = all.results || [];
  if (rows.length === 0) {
    return {
      events: [],
      nextCursor: since ?? { cachedAt: 0, txid: '' },
      hasMore: false,
    };
  }

  // Group input rows by Eid so we can resolve per-Eid in the window. Rows
  // without an Eid tag (legacy or unscoped writes) fall through as their
  // own "group of one" — same shape, never collapsed across rows.
  const byEid = new Map();
  const orphans = [];
  for (const r of rows) {
    if (r.eid) {
      if (!byEid.has(r.eid)) byEid.set(r.eid, []);
      byEid.get(r.eid).push(r);
    } else {
      orphans.push(r);
    }
  }

  // For each Eid group, run resolution against *all* rows in the group
  // observed within this window. If anything live emerges → emit an entry
  // event for the resolved head. If nothing live emerges (tombstone or
  // everything superseded inside the window) → emit a deleted event.
  //
  // Caveat: a tombstone in this window targeting an entry written in a
  // PRIOR window will only show up here as the tombstone row alone. The
  // resolver sees a single is_tombstone row, yields nothing, and we emit
  // `deleted: true`. That's exactly what the client needs — they have the
  // prior entry locally and need to know it's gone.
  const events = [];
  for (const [eid, group] of byEid) {
    const live = resolveEntries(group);
    if (live.length > 0) {
      const head = live[0];
      events.push({
        eid,
        txid: head.txid,
        tags_json: head.tags_json,
        confirmed: head.block_timestamp != null,
        cached_at: head.cached_at,
        blob_data: head.blob_data,
        is_tombstone: head.is_tombstone,
      });
    } else {
      // Either the group is a single tombstone row, or the resolver
      // collapsed everything (e.g., create + tombstone in same window).
      events.push({ eid, deleted: true });
    }
  }

  // Orphans (no Eid) pass through individually as live events. Don't try
  // to resolve them — without an Eid there's no group to resolve over.
  for (const r of orphans) {
    if (r.is_tombstone) continue; // tombstones need an Eid to be meaningful
    events.push({
      eid: null,
      txid: r.txid,
      tags_json: r.tags_json,
      confirmed: r.block_timestamp != null,
      cached_at: r.cached_at,
      blob_data: r.blob_data,
    });
  }

  // Cursor advances past the last *input* row, not the last event. Critical:
  // grouping by Eid can collapse N rows to 1 event, but we still need to
  // skip past all N rows on the next call.
  const lastRow = rows[rows.length - 1];
  return {
    events,
    nextCursor: { cachedAt: lastRow.cached_at, txid: lastRow.txid },
    hasMore: rows.length === limit,
  };
}

/**
 * Resolve the single live entry for a (app, type, dlk, eid) tuple, including
 * blob bytes. Returns null if no live entry exists.
 *
 * Used by the list endpoint's Eid-filter fast path (delete/update/get on the
 * Collection surface). Including blob_data here is safe because Eid is unique
 * per (app, collection, primaryKey) and resolveEntries collapses any
 * Prev-chain down to one head — at most one row's worth of bytes ever lands
 * in the response.
 */
export async function getResolvedEntryByEid(db, app, type, dataLookupKey, eid) {
  const all = await db.prepare(
    `SELECT txid, app, type, wallet_addr, lookup_key, eid, prev_txid,
            is_tombstone, tombstone_ref, block_timestamp, tags_json, cached_at, blob_data
     FROM entries WHERE app = ?1 AND type = ?2 AND lookup_key = ?3 AND eid = ?4`
  ).bind(app, type, dataLookupKey, eid).all();

  const rows = all.results || [];
  const live = resolveEntries(rows);
  return live[0] || null;
}

// ============ SINGLE ENTRY ============

export async function getEntryByTxid(db, txid) {
  return await db.prepare('SELECT * FROM entries WHERE txid = ?1').bind(txid).first();
}

export async function getEntryByLookupKey(db, lookupKey) {
  // Get the most recent non-tombstone entry for this lookup key
  const all = await db.prepare(
    'SELECT * FROM entries WHERE lookup_key = ?1'
  ).bind(lookupKey).all();

  const rows = all.results || [];
  const live = resolveEntries(rows);
  return live[0] || null;
}

// ============ BOOTSTRAP MARKERS ============

// Bootstrap markers live in the cache_meta table, keyed by scope.
// Presence of a marker means: "Tarn has verified there is nothing on Arweave
// for this scope that isn't in D1 — D1 is authoritative."
const DATA_BOOTSTRAP_KEY = (dlk, app, type) => `bootstrap:data:${dlk}:${app}:${type}`;
const LOOKUP_BOOTSTRAP_KEY = (lookupKey, app, type) => `bootstrap:lookup:${lookupKey}:${app}:${type}`;

async function hasBootstrap(db, key) {
  const row = await db.prepare('SELECT 1 FROM cache_meta WHERE key = ?1').bind(key).first();
  return !!row;
}

async function setBootstrap(db, key) {
  await db.prepare(
    'INSERT INTO cache_meta (key, value, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(key) DO NOTHING'
  ).bind(key, '{}', Date.now()).run();
}

/**
 * Mark a (dlk, app, type) tuple as bootstrapped. Called from the write path
 * after a successful write-through, so the next read for this tuple does not
 * trigger a redundant GraphQL bootstrap.
 */
export async function markDataBootstrapped(db, dataLookupKey, app, type) {
  await setBootstrap(db, DATA_BOOTSTRAP_KEY(dataLookupKey, app, type));
}

/**
 * Mark a (lookupKey, app, type) tuple as bootstrapped for lookup queries.
 * Called after a credential blob is persisted to D1, so subsequent lookups
 * don't re-query Arweave for data we already have.
 */
export async function markLookupBootstrapped(db, lookupKey, app, type) {
  await setBootstrap(db, LOOKUP_BOOTSTRAP_KEY(lookupKey, app, type));
}

/**
 * Ensure the (dlk, app, type) tuple is bootstrapped. If a marker already exists,
 * returns immediately — D1 is authoritative. Otherwise runs a one-time GraphQL
 * query against Arweave to ingest any pre-existing on-chain entry metadata,
 * then sets the marker.
 *
 * Blob bytes are NOT fetched here. They warm into D1 lazily as clients request
 * specific txids via /api/v1/entries/{txid} (handleEntryById fills blob_data
 * from the gateway on miss). This keeps the cold-bootstrap path on the list
 * endpoint cheap and predictable: one GraphQL query + one D1 batch upsert,
 * regardless of how many entries the user has — no chains of sequential
 * gateway fetches that risk tripping CF Worker resource limits.
 */
export async function refreshCache(env, ctx, app, type, dataLookupKey) {
  const cacheKey = DATA_BOOTSTRAP_KEY(dataLookupKey, app, type);

  if (await hasBootstrap(env.DB, cacheKey)) {
    return { bootstrapped: true };
  }

  const { edges, error } = await searchEntriesByLookupKey(dataLookupKey, { app, type });
  if (edges.length > 0) {
    await upsertEntries(env.DB, edges);
  }

  // Only set the marker if GraphQL succeeded — a transient Arweave error should
  // not latch us into a "D1 is authoritative" state for a scope we never queried.
  if (!error) {
    await setBootstrap(env.DB, cacheKey);
  }

  return { bootstrapped: !error };
}

/**
 * Bootstrap variant for lookup-key-addressed entries (credentials, account
 * metadata resolved by a deterministic lookup key rather than by dlk).
 */
export async function refreshLookupCache(env, ctx, app, type, lookupKey) {
  const cacheKey = LOOKUP_BOOTSTRAP_KEY(lookupKey, app, type);

  if (await hasBootstrap(env.DB, cacheKey)) {
    return;
  }

  const { edges, error } = await searchEntriesByLookupKey(lookupKey, { app, type });
  if (edges.length > 0) {
    await upsertEntries(env.DB, edges);
  }

  if (!error) {
    await setBootstrap(env.DB, cacheKey);
  }
}

// ============ BLOB LAZY-LOAD ============

const TURBO_GW = 'https://turbo-gateway.com';
const ARWEAVE_GW = 'https://arweave.net';
const GATEWAY_TIMEOUT_MS = 10_000;

/**
 * Fetch a single entry's encrypted blob from a public Arweave gateway. Tries
 * Turbo first (fast CDN-fronted gateway) then arweave.net L1. Returns the
 * raw bytes or null if both gateways failed (404, timeout, network error).
 *
 * Used by handleEntryById to warm D1's blob_data column on miss. This is the
 * sole runtime path for hydrating blobs from Arweave; refreshCache does
 * metadata-only bootstrap, and clients no longer fetch from gateways
 * directly. For wholesale post-migration backfill, see tools/backfill-blobs.mjs.
 */
export async function fetchBlobFromGateway(txid) {
  for (const gw of [TURBO_GW, ARWEAVE_GW]) {
    try {
      const res = await fetch(`${gw}/${txid}`, { signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS) });
      if (res.ok) return new Uint8Array(await res.arrayBuffer());
    } catch {}
  }
  return null;
}

/**
 * Persist freshly-fetched blob bytes into D1 so subsequent reads for the same
 * txid hit the cache.
 */
export async function persistBlob(db, txid, blobBytes) {
  await db.prepare('UPDATE entries SET blob_data = ?1 WHERE txid = ?2')
    .bind(blobBytes, txid).run();
}

// ============ WRITE-THROUGH ============

/**
 * Insert a newly uploaded entry into D1 immediately (write-through).
 * Includes the encrypted blob data so reads can be served entirely from D1.
 * block_timestamp is NULL — entry is pending/unconfirmed on Arweave.
 * @param {Object} db - D1 database
 * @param {string} txid - DataItem transaction ID
 * @param {Array} tags - Arweave tags
 * @param {Uint8Array|null} blobData - Encrypted blob bytes (null for tombstones/metadata)
 */
export async function upsertWriteThrough(db, txid, tags, blobData = null) {
  const tagValue = (name) => tags.find(t => t.name === name)?.value || null;
  await db.prepare(`
    INSERT INTO entries (txid, app, type, wallet_addr, lookup_key, eid, prev_txid,
                         is_tombstone, tombstone_ref, block_timestamp, tags_json, cached_at, blob_data)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11, ?12)
    ON CONFLICT(txid) DO NOTHING
  `).bind(
    txid,
    tagValue('App') || '',
    tagValue('Type') || '',
    tagValue('Addr')?.toLowerCase() || null,
    tagValue('Lk') || null,
    tagValue('Eid') || null,
    tagValue('Prev') || null,
    tagValue('Op') === 'tombstone' ? 1 : 0,
    tagValue('Ref') || null,
    JSON.stringify(tags),
    Date.now(),
    blobData || null
  ).run();
}

/**
 * Track a pending transaction in D1 for sync status.
 */
export async function trackPendingTx(db, txid, dataLookupKey, app, type) {
  await db.prepare(
    'INSERT OR IGNORE INTO pending_txs (txid, wallet_addr, data_lookup_key, app, type) VALUES (?1, NULL, ?2, ?3, ?4)'
  ).bind(txid, dataLookupKey, app, type).run();
}
