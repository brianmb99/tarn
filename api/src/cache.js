// D1 cache layer — upsert, resolution, stale-while-revalidate
// All entries stored as rows including tombstones and edits.
// Resolution happens at read time.

import { fetchAllPages, searchEntriesByLookupKey } from './arweave.js';

const CACHE_FRESH_MS = 60_000; // 60 seconds

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
 */
export async function getResolvedEntries(db, app, type, dataLookupKey, { limit = 100, cursor = null } = {}) {
  // Fetch all entries for this scope (including tombstones and superseded)
  const all = await db.prepare(
    'SELECT * FROM entries WHERE app = ?1 AND type = ?2 AND lookup_key = ?3'
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

// ============ CACHE FRESHNESS ============

async function getCacheMeta(db, key) {
  const row = await db.prepare('SELECT * FROM cache_meta WHERE key = ?1').bind(key).first();
  if (!row) return null;
  try {
    return { ...JSON.parse(row.value), updated_at: row.updated_at };
  } catch {
    return null;
  }
}

async function setCacheMeta(db, key, value) {
  await db.prepare(
    'INSERT INTO cache_meta (key, value, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3'
  ).bind(key, JSON.stringify(value), Date.now()).run();
}

/**
 * Refresh cache for data entries by data_lookup_key. Stale-while-revalidate pattern.
 * Queries Arweave by Lk tag, upserts into D1.
 */
export async function refreshCache(env, ctx, app, type, dataLookupKey) {
  const cacheKey = `refresh:${dataLookupKey}:${app}:${type}`;
  const meta = await getCacheMeta(env.DB, cacheKey);
  const now = Date.now();

  if (meta && (now - meta.updated_at) < CACHE_FRESH_MS) {
    return { lastRefresh: meta.updated_at, stale: false };
  }

  const doRefreshMeta = async () => {
    // Use lookup key search (Lk tag) for data entries
    const { edges, error } = await searchEntriesByLookupKey(dataLookupKey, { app, type });
    if (edges.length > 0) {
      await upsertEntries(env.DB, edges);
    }
    if (!error) {
      await setCacheMeta(env.DB, cacheKey, { refreshedAt: Date.now() });
    }
  };

  // Blob backfill is opportunistic — it fetches from Arweave gateways which can be
  // slow. Never block the response on it. Running it synchronously on cold cache was
  // causing wall-time timeouts (CF returns edge 503 when a worker exceeds 30s).
  const doBackfill = () => backfillBlobs(env.DB, dataLookupKey, app, type);

  if (meta) {
    // Stale: serve from cache, refresh in background
    ctx.waitUntil(Promise.all([doRefreshMeta(), doBackfill()]));
    return { lastRefresh: meta.updated_at, stale: true };
  }

  // Cold cache: block on GraphQL refresh so the response reflects current index,
  // but run the blob backfill in the background.
  await doRefreshMeta();
  ctx.waitUntil(doBackfill());
  return { lastRefresh: Date.now(), stale: false };
}

/**
 * Refresh cache for lookup-key-addressed entries (credentials, account metadata).
 */
export async function refreshLookupCache(env, ctx, app, type, lookupKey) {
  const cacheKey = `lookup:${lookupKey}:${app}:${type}`;
  const meta = await getCacheMeta(env.DB, cacheKey);
  const now = Date.now();

  if (meta && (now - meta.updated_at) < CACHE_FRESH_MS) {
    return;
  }

  const doRefresh = async () => {
    const { edges, error } = await searchEntriesByLookupKey(lookupKey, { app, type });
    if (edges.length > 0) {
      await upsertEntries(env.DB, edges);
    }
    if (!error) {
      await setCacheMeta(env.DB, cacheKey, { refreshedAt: Date.now() });
    }
  };

  if (meta) {
    ctx.waitUntil(doRefresh());
    return;
  }

  await doRefresh();
}

// ============ BLOB BACKFILL ============

const TURBO_GW = 'https://turbo-gateway.com';
const ARWEAVE_GW = 'https://arweave.net';
const BACKFILL_BATCH_SIZE = 10; // Stay well under Workers subrequest limit

/**
 * Backfill blob_data for entries that don't have it yet.
 * Fetches from Arweave gateways and stores in D1.
 * Limited to BACKFILL_BATCH_SIZE entries per call to avoid subrequest limits.
 */
async function backfillBlobs(db, lookupKey, app, type) {
  const missing = await db.prepare(
    'SELECT txid FROM entries WHERE lookup_key = ?1 AND app = ?2 AND type = ?3 AND blob_data IS NULL AND is_tombstone = 0 LIMIT ?4'
  ).bind(lookupKey, app, type, BACKFILL_BATCH_SIZE).all();

  const txids = (missing.results || []).map(r => r.txid);
  if (txids.length === 0) return;

  console.log(`[tarn-api] Backfilling ${txids.length} blobs for ${lookupKey.slice(0, 12)}...`);

  for (const txid of txids) {
    try {
      // Try Turbo first, then Arweave L1
      let blobData = null;
      for (const gw of [TURBO_GW, ARWEAVE_GW]) {
        try {
          const res = await fetch(`${gw}/${txid}`, { signal: AbortSignal.timeout(10000) });
          if (res.ok) {
            blobData = new Uint8Array(await res.arrayBuffer());
            break;
          }
        } catch {}
      }

      if (blobData) {
        await db.prepare('UPDATE entries SET blob_data = ?1 WHERE txid = ?2')
          .bind(blobData, txid).run();
      }
    } catch (err) {
      console.warn(`[tarn-api] Backfill failed for ${txid}: ${err.message}`);
    }
  }
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
