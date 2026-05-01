// Entry listing and single-entry endpoints (read-only, unauthenticated, IP rate-limited)

import { jsonResponse, errorResponse } from '../worker.js';
import { getResolvedEntries, getEntryByTxid, refreshCache } from '../cache.js';
import { checkAndIncrementRateLimit } from '../rate-limit.js';

// Convert blob_data from D1 (ArrayBuffer/Uint8Array) to base64 for JSON transport.
// Only used by the single-entry endpoint (handleEntryById) — the list endpoint
// returns metadata only and clients fetch each blob via /api/v1/entries/{txid}.
function blobToBase64(blob) {
  if (!blob) return null;
  const bytes = blob instanceof Uint8Array ? blob : new Uint8Array(blob);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

const MAX_READS_PER_HOUR = 300;

async function checkReadRateLimit(env, request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const data = new TextEncoder().encode(ip + '-tarn-read-salt');
  const hash = await crypto.subtle.digest('SHA-256', data);
  const ipHash = Array.from(new Uint8Array(hash)).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
  const hour = new Date().toISOString().slice(0, 13);
  const key = `read:${ipHash}:${hour}`;
  const { allowed, count } = await checkAndIncrementRateLimit(env.RATE_KV, key, MAX_READS_PER_HOUR);
  return { allowed, remaining: Math.max(0, MAX_READS_PER_HOUR - count) };
}

export async function handleEntries(url, env, ctx, cors, request) {
  const app = url.searchParams.get('app');
  const type = url.searchParams.get('type');
  const key = url.searchParams.get('key');

  if (!app || !type || !key) {
    return errorResponse('Missing required params: app, type, key', 400, cors);
  }

  // IP rate limit
  const { allowed, remaining } = await checkReadRateLimit(env, request);
  if (!allowed) {
    return errorResponse('Rate limit exceeded', 429, { ...cors, 'Retry-After': '3600' });
  }

  const limit = Math.min(parseInt(url.searchParams.get('limit') || '100', 10), 500);
  const cursor = url.searchParams.get('cursor') || null;

  // One-time Arweave bootstrap for this (dlk, app, type). After the marker is
  // set (here or on first write), subsequent reads skip Arweave entirely.
  await refreshCache(env, ctx, app, type, key);

  // Resolve live entries (tombstone + Prev-chain + Eid filtering)
  const { entries, total } = await getResolvedEntries(env.DB, app, type, key, { limit, cursor });

  // Metadata-only response. Blob bytes are NOT returned here — clients fetch
  // each blob via GET /api/v1/entries/{txid} (or directly from a public Arweave
  // gateway). Returning ~10 MB of inline base64 in a single response was pushing
  // the Worker past the 128 MB per-request memory limit and producing CF
  // error 1102 (resource limits exceeded) for users with ~200+ entries.
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
  }, 200, cors);
}

export async function handleEntryById(txid, url, env, ctx, cors, request) {
  // IP rate limit (shares bucket with list endpoint)
  const { allowed } = await checkReadRateLimit(env, request);
  if (!allowed) {
    return errorResponse('Rate limit exceeded', 429, cors);
  }

  const key = url.searchParams.get('key') || null;

  const entry = await getEntryByTxid(env.DB, txid);
  if (!entry) {
    return errorResponse('Entry not found', 404, cors);
  }

  // If key provided, verify ownership. Without key, returns metadata for any txid.
  // This is intentional: entry tags are public on Arweave (only the blob body is encrypted).
  // Restricting metadata here would be security theater — it's already on-chain.
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
    data: blobToBase64(entry.blob_data),
    gatewayUrl: `https://arweave.net/${entry.txid}`,
  }, 200, cors);
}
