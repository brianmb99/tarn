// Entry listing and single-entry endpoints (read-only, unauthenticated)

import { jsonResponse, errorResponse } from '../worker.js';
import { getResolvedEntries, getEntryByTxid, refreshCache } from '../cache.js';

export async function handleEntries(url, env, ctx, cors) {
  const app = url.searchParams.get('app');
  const type = url.searchParams.get('type');
  const key = url.searchParams.get('key');

  if (!app || !type || !key) {
    return errorResponse('Missing required params: app, type, key', 400, cors);
  }

  const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10), 500);
  const cursor = url.searchParams.get('cursor') || null;

  // Check cache freshness and refresh if needed
  const cacheStatus = await refreshCache(env, ctx, app, type, key);

  // Resolve live entries (tombstone + Prev-chain + Eid filtering)
  const { entries, total } = await getResolvedEntries(env.DB, app, type, key, { limit, cursor });

  return jsonResponse({
    entries: entries.map(e => ({
      txid: e.txid,
      app: e.app,
      type: e.type,
      eid: e.eid || null,
      tags: e.tags_json ? JSON.parse(e.tags_json) : [],
      confirmed: e.block_timestamp != null,
      cachedAt: e.cached_at,
      gatewayUrl: `https://arweave.net/${e.txid}`,
    })),
    pagination: {
      count: entries.length,
      hasMore: entries.length === limit,
      cursor: entries.length === limit ? entries[entries.length - 1].txid : null,
    },
    cache: {
      lastRefresh: cacheStatus.lastRefresh,
      stale: cacheStatus.stale,
    },
  }, 200, cors);
}

export async function handleEntryById(txid, url, env, ctx, cors) {
  const key = url.searchParams.get('key') || null;

  const entry = await getEntryByTxid(env.DB, txid);
  if (!entry) {
    return errorResponse('Entry not found', 404, cors);
  }

  // If key provided, verify ownership
  if (key && entry.lookup_key && entry.lookup_key !== key) {
    return errorResponse('Entry not found', 404, cors);
  }

  return jsonResponse({
    txid: entry.txid,
    app: entry.app,
    type: entry.type,
    eid: entry.eid || null,
    tags: entry.tags_json ? JSON.parse(entry.tags_json) : [],
    confirmed: entry.block_timestamp != null,
    cachedAt: entry.cached_at,
    gatewayUrl: `https://arweave.net/${entry.txid}`,
  }, 200, cors);
}
