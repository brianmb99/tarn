// Entry listing and single-entry endpoints (read-only).
//
// Authentication (tarn#60):
//   - GET /api/v1/entries — requires a user-role session JWT whose account
//     (auth.data_lookup_key) matches the `key` query param. Knowing a dlk is
//     no longer sufficient to read an account's encrypted metadata: the dlk
//     stopped being a read bearer-token. 401 on missing/invalid JWT, 403 when
//     the JWT belongs to a different account.
//   - GET /api/v1/entries/:txid — same requirement when a `key` param is
//     supplied (the SDK's blob-fetch path always supplies the JWT now). The
//     `key`-less variant (txid-only metadata lookup) is still allowed without
//     auth because entry tags are already public on Arweave — the encrypted
//     blob body is the only secret, and that's what this route returns, so the
//     gate there is "do you know the exact content-addressed txid."
//
// Rate-limit keying:
//   - Both routes bucket on the authenticated account (read:<dlk>:<hour>),
//     mirroring the per-account write limit. Because reads now carry a JWT,
//     the bucket identity is the session's account rather than an
//     attacker-supplied dlk. The key-less by-txid path still falls back to
//     per-IP (no account identity to bucket on).
//
// Per-IP read limits used to apply uniformly here, which caused noisy-
// neighbor failures on shared NAT (tarn#31). The account-keyed path now
// matches the write path's identity model.

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
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

  // tarn#60 — `key` is a data_lookup_key, which is always a 64-char lowercase
  // hex string (SHA-256-shaped; see TARN_PROTOCOL.md). Reject anything else up
  // front, before any DB / cache / rate-limit work. This is non-breaking
  // (every legitimate dlk matches) and shrinks the unauthenticated
  // metadata-enumeration surface: a prober can no longer spend our rate-limit
  // KV keyspace on arbitrary attacker-controlled strings, and malformed keys
  // fail fast instead of fanning out into cache lookups. Mirrors the existing
  // validation on GET /api/v1/lookup.
  if (!/^[a-f0-9]{64}$/.test(key)) {
    return errorResponse('Invalid key format: expected 64-char hex', 400, cors);
  }

  // tarn#60 — require a user-role session JWT, and enforce that the JWT's
  // account matches the dlk being read. A dlk is no longer a read
  // bearer-token: an unauthenticated party that learns one can no longer
  // enumerate the account's encrypted metadata. Zero-knowledge is preserved
  // (the server still never sees plaintext); this only gates WHO may pull a
  // given account's encrypted rows.
  //
  // Ordering note: the cheap key-format regex runs first (above) so a
  // malformed key still fails fast with 400 and never touches the JWT
  // verifier / DB / KV. The regex reveals nothing — the key is
  // attacker-supplied — so there's no pre-auth disclosure concern.
  const auth = await requireAuth(request, env, ctx);
  if (!auth) {
    return errorResponse('Unauthorized', 401, cors);
  }
  // App-role JWTs are platform credentials, not account sessions — they have
  // no business reading a user's encrypted metadata, and auth.data_lookup_key
  // is the app_id for them (would never match a real dlk anyway). Require a
  // user-role session.
  if (auth.role !== 'user' || auth.data_lookup_key !== key) {
    return errorResponse('Forbidden', 403, cors);
  }

  // Per-account rate limit, keyed on the authenticated account's dlk (now
  // proven by the JWT rather than asserted by the URL param). Mirrors the
  // per-account write limit. See tarn#31 for the migration off per-IP.
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

  // Resolve live entries (tombstone + Prev-chain + Eid filtering) —
  // page-bounded in SQL (tarn#70); pagination comes from the raw page.
  const { entries, hasMore, nextCursor } = await getResolvedEntries(env.DB, app, type, key, { limit, cursor });

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
      hasMore,
      cursor: nextCursor,
    },
  }, 200, cors);
}

export async function handleEntryById(txid, url, env, ctx, cors, request) {
  const key = url.searchParams.get('key') || null;

  // tarn#60 scoping for the by-txid route.
  //
  // A txid is a 43-char Arweave content hash — it is NOT enumerable from a
  // dlk, so this route is not the metadata-enumeration vector #60 closes
  // (that's the `?key=<dlk>` list path). The body it returns is the AES-GCM
  // encrypted blob; tags are already public on Arweave. We therefore keep two
  // modes:
  //
  //   - `key` supplied → account-identified read. The SDK's authenticated
  //     paths that pass `key` (none today inline it, but the contract is
  //     explicit) must present a matching user-role JWT: 401 missing/invalid,
  //     403 different account. Bucket on the account.
  //   - `key` omitted → txid-only fetch. The SDK's #fetchBlob path attaches
  //     the session JWT (so this is an authenticated read in practice), but
  //     because a txid is content-addressed and non-enumerable, and the body
  //     is encrypted, we do NOT make the JWT mandatory or tie it to a specific
  //     account here. An unauthenticated caller that already knows the exact
  //     txid still gets the encrypted bytes (it can't enumerate them from a
  //     dlk), and falls back to per-IP rate limiting.
  let auth = null;
  if (key) {
    auth = await requireAuth(request, env, ctx);
    if (!auth) return errorResponse('Unauthorized', 401, cors);
    if (auth.role !== 'user' || auth.data_lookup_key !== key) {
      return errorResponse('Forbidden', 403, cors);
    }
  }

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

  // If key provided, verify ownership. Without key, returns the encrypted blob
  // for any txid the caller already knows (txids are content-addressed and
  // non-enumerable; the body is encrypted). Restricting further here would be
  // security theater — the tags are already on-chain.
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
