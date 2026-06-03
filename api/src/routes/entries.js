// Entry listing and single-entry endpoints (read-only).
//
// Rate-limit keying:
//   - GET /api/v1/entries — requires `key` (data_lookup_key) in the URL, so
//     we bucket on the account (mirrors the per-account write limit).
//   - GET /api/v1/entries/:txid — `key` is OPTIONAL. When present we still
//     bucket on the account; when absent (txid-only metadata lookup, allowed
//     because tags are public on Arweave) we fall back to per-IP.
//
// Per-IP read limits used to apply uniformly here, which caused noisy-
// neighbor failures on shared NAT (tarn#31). The account-keyed path now
// matches the write path's identity model.

import { jsonResponse, errorResponse } from '../worker.js';
import {
  getResolvedEntries,
  getResolvedEntryByEid,
  getDeltaEntries,
  getEntryByTxid,
  refreshCache,
  fetchBlobFromGateway,
  persistBlob,
} from '../cache.js';
import { checkReadRateLimitByAccount, checkReadRateLimitByIp } from '../rate_limit.js';

// Convert blob_data from D1 (ArrayBuffer/Uint8Array) to base64 for JSON transport.
// Used by handleEntryById, the ?eid= fast path, and the ?since= delta path
// (any response that inlines a single bounded set of blobs). The default
// list endpoint still returns metadata-only — see comment at handleEntries.
function blobToBase64(blob) {
  if (!blob) return null;
  const bytes = blob instanceof Uint8Array ? blob : new Uint8Array(blob);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

// Parse the opaque "<cachedAt>:<txid>" delta cursor. Returns null on any
// malformed value — caller treats null as "start from the beginning."
function parseSinceCursor(raw) {
  if (!raw) return null;
  const idx = raw.indexOf(':');
  if (idx < 0) return null;
  const cachedAt = parseInt(raw.slice(0, idx), 10);
  const txid = raw.slice(idx + 1);
  if (!Number.isFinite(cachedAt) || cachedAt < 0) return null;
  return { cachedAt, txid };
}

function formatSinceCursor(cursor) {
  return `${cursor.cachedAt}:${cursor.txid}`;
}

export async function handleEntries(url, env, ctx, cors, request) {
  const app = url.searchParams.get('app');
  const type = url.searchParams.get('type');
  const key = url.searchParams.get('key');
  const eid = url.searchParams.get('eid');
  const sinceRaw = url.searchParams.get('since');

  if (!app || !type || !key) {
    return errorResponse('Missing required params: app, type, key', 400, cors);
  }

  // Per-account rate limit. `key` is the caller's data_lookup_key — knowing
  // it proves identity for read purposes (the data is encrypted anyway), so
  // we bucket on it directly. See tarn#31 for the migration off per-IP.
  const { allowed } = await checkReadRateLimitByAccount(env, key);
  if (!allowed) {
    return errorResponse('Rate limit exceeded', 429, { ...cors, 'Retry-After': '3600' });
  }

  // Delta-sync fast path: clients poll with the cursor from their last
  // response and get back a small page of semantic events (entry-changed /
  // entry-deleted), with blob bytes inlined for the entry events. Replaces
  // the metadata-list + N-blob-fetch fan-out that warm polls used to do.
  // The "tombstone" abstraction never crosses the wire — deletions surface
  // as { eid, deleted: true } events, same way updates surface as the
  // latest version (Prev-chain hidden).
  if (sinceRaw !== null) {
    await refreshCache(env, ctx, app, type, key);
    const since = parseSinceCursor(sinceRaw);
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '25', 10), 25);
    const { events, nextCursor, hasMore } = await getDeltaEntries(env.DB, app, type, key, since, { limit });

    const wireEntries = [];
    for (const evt of events) {
      if (evt.deleted) {
        wireEntries.push({ eid: evt.eid, deleted: true });
        continue;
      }
      let blobData = evt.blob_data;
      if (!blobData && !evt.is_tombstone) {
        const fetched = await fetchBlobFromGateway(evt.txid);
        if (fetched) {
          blobData = fetched;
          try {
            await persistBlob(env.DB, evt.txid, fetched);
          } catch (err) {
            console.warn(`[tarn-api] persistBlob failed for ${evt.txid}: ${err.message}`);
          }
        }
      }
      wireEntries.push({
        eid: evt.eid,
        txid: evt.txid,
        tags: evt.tags_json ? JSON.parse(evt.tags_json) : [],
        confirmed: evt.confirmed,
        cachedAt: evt.cached_at,
        data: blobToBase64(blobData),
      });
    }

    return jsonResponse({
      entries: wireEntries,
      pagination: {
        cursor: formatSinceCursor(nextCursor),
        hasMore,
      },
    }, 200, cors);
  }

  // Eid-filter fast path: collapses the N+1 read fan-out that the SDK used to
  // do when looking up a single record by primaryKey (it knew the Eid all along
  // but had no narrow read path). At most one live row per (dlk, app, type, eid)
  // after resolution, so we inline blob bytes — saves a follow-up round trip
  // for delete / update / get / share-state lookups.
  if (eid) {
    await refreshCache(env, ctx, app, type, key);
    const entry = await getResolvedEntryByEid(env.DB, app, type, key, eid);
    if (!entry) {
      return jsonResponse({
        entries: [],
        pagination: { count: 0, hasMore: false, cursor: null },
      }, 200, cors);
    }
    let blobData = entry.blob_data;
    if (!blobData && !entry.is_tombstone) {
      const fetched = await fetchBlobFromGateway(entry.txid);
      if (fetched) {
        blobData = fetched;
        try {
          await persistBlob(env.DB, entry.txid, fetched);
        } catch (err) {
          console.warn(`[tarn-api] persistBlob failed for ${entry.txid}: ${err.message}`);
        }
      }
    }
    return jsonResponse({
      entries: [{
        txid: entry.txid,
        app: entry.app,
        type: entry.type,
        eid: entry.eid || null,
        tags: entry.tags_json ? JSON.parse(entry.tags_json) : [],
        confirmed: entry.block_timestamp != null,
        cachedAt: entry.cached_at,
        data: blobToBase64(blobData),
        gatewayUrl: `https://arweave.net/${entry.txid}`,
      }],
      pagination: { count: 1, hasMore: false, cursor: null },
    }, 200, cors);
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
  const key = url.searchParams.get('key') || null;

  // When `key` is supplied this is a normal account-identified read; bucket
  // on the account (mirrors handleEntries above). When it's omitted, we have
  // no account identity — this is the txid-only metadata-lookup case, which
  // we allow because tags are already public on Arweave. That path falls
  // back to per-IP keying since there's nothing else to bucket on.
  const { allowed } = key
    ? await checkReadRateLimitByAccount(env, key)
    : await checkReadRateLimitByIp(env, request);
  if (!allowed) {
    return errorResponse('Rate limit exceeded', 429, { ...cors, 'Retry-After': '3600' });
  }

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

  // Lazy-load blob bytes from a public gateway if D1 is missing them. This
  // happens during the cold-bootstrap window: refreshCache imports metadata
  // for a (dlk, app, type) tuple but does NOT eagerly backfill blobs (doing so
  // synchronously inside the list endpoint risked CF Worker resource limits
  // for users with many entries — see issue notes on error 1102). Tombstones
  // legitimately have no blob, so skip those.
  let blobData = entry.blob_data;
  if (!blobData && !entry.is_tombstone) {
    const fetched = await fetchBlobFromGateway(entry.txid);
    if (fetched) {
      blobData = fetched;
      // Write-through so the next reader hits warm D1. Errors here are
      // non-fatal — we still serve the bytes we just fetched.
      try {
        await persistBlob(env.DB, entry.txid, fetched);
      } catch (err) {
        console.warn(`[tarn-api] persistBlob failed for ${entry.txid}: ${err.message}`);
      }
    }
  }

  return jsonResponse({
    txid: entry.txid,
    app: entry.app,
    type: entry.type,
    eid: entry.eid || null,
    tags: entry.tags_json ? JSON.parse(entry.tags_json) : [],
    confirmed: entry.block_timestamp != null,
    cachedAt: entry.cached_at,
    data: blobToBase64(blobData),
    gatewayUrl: `https://arweave.net/${entry.txid}`,
  }, 200, cors);
}
