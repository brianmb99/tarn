// Friend-handshake inbox endpoints (issue #14, Section 5a).
//
// Two endpoints, both scoped by app:
//   POST /api/v1/share/inbox/publish — JWT-gated, rate-limited per session
//     publishes an HPKE-sealed friend_request or friend_accept blob.
//   GET  /api/v1/share/inbox/fetch — public, IP rate-limited, returns
//     all cached blobs for a (app, inbox_tag, blob_type) tuple.
//
// The blob bytes are opaque to the server (HPKE ciphertext); only the
// recipient's share_priv can open them. Tarn signs + uploads to Arweave via
// the existing Turbo path — inbox blobs land permanently on chain so the
// recipient can poll for them on a fresh device. The D1 row is the cache.
//
// Per-tag uniqueness is NOT enforced (unlike the share-log writes coming in
// Section 5b — those use the stealth tag + seq for ordering). Inbox tags are
// shared across all senders in a window, so multiple rows per (tag, type) is
// the normal case.
//
// Rate limits (sharing §9.5):
//   - friend-request-v1: 10 per hour per data_lookup_key
//   - friend-accept-v1:  50 per hour per data_lookup_key
// Exceeded → 429 with Retry-After.

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { buildSignedDataItem, uploadSignedDataItem, TURBO_GATEWAY } from '../turbo.js';

// Per the design doc — kept generous on the accept side because a popular
// user might receive many requests in a burst, each one prompting a 1:1
// accept. Friend requests are the abuse-vector channel (any Bob with
// share_pub_A's email can write to Alice's inbox), so rate-limit hard.
const MAX_FRIEND_REQUESTS_PER_HOUR = 10;
const MAX_FRIEND_ACCEPTS_PER_HOUR = 50;

// Keep blob size small — HPKE-sealed handshake payloads are tens to low
// hundreds of bytes; 8 KiB is a generous cap that catches accidents (someone
// trying to publish a real share-log blob to the wrong endpoint) without
// bothering legitimate handshakes.
const MAX_INBOX_BLOB_BYTES = 8 * 1024;

// IP rate limit on the public fetch endpoint. The fetch is unauthenticated by
// design — a recipient who lost their JWT (e.g., still booting on a fresh
// device) needs to be able to poll their inbox. A recipient polling N=30
// windows × 2 types per call (request + accept) hits ~60 fetches per
// listIncomingRequests; a power user with multiple sessions per hour can
// easily reach ~600. The 1800/hour budget gives enough headroom for those
// patterns while still bounding bulk-enumeration attacks (an attacker who
// somehow learned a victim's share_pub could only sweep ~1800 windows/hour
// per IP — modest cost on top of the publish-rate-limit defense).
const MAX_INBOX_FETCHES_PER_HOUR = 1800;

// Recognized blob types. Anything else is rejected up front.
const VALID_BLOB_TYPES = new Set(['friend-request-v1', 'friend-accept-v1']);

// ============ POST /api/v1/share/inbox/publish ============

export async function handleShareInboxPublish(request, env, ctx, cors) {
  const auth = await requireAuth(request, env);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') {
    return errorResponse('Only user accounts can publish to friend inboxes', 403, cors);
  }
  if (!auth.app) {
    return errorResponse('JWT missing app claim', 403, cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { tag, type, ciphertext_base64 } = body || {};

  if (typeof tag !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(tag)) {
    return errorResponse('Invalid tag: must be 43-char base64url (HMAC-SHA-256 output)', 400, cors);
  }
  if (!VALID_BLOB_TYPES.has(type)) {
    return errorResponse(
      `Invalid type: must be one of ${[...VALID_BLOB_TYPES].join(', ')}`,
      400, cors,
    );
  }
  if (typeof ciphertext_base64 !== 'string' || ciphertext_base64.length === 0) {
    return errorResponse('ciphertext_base64 is required', 400, cors);
  }
  if (ciphertext_base64.length > Math.ceil(MAX_INBOX_BLOB_BYTES * 4 / 3) + 4) {
    return errorResponse('ciphertext_base64 exceeds maximum size', 413, cors);
  }
  let ciphertext;
  try {
    const bin = atob(ciphertext_base64);
    ciphertext = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) ciphertext[i] = bin.charCodeAt(i);
  } catch {
    return errorResponse('ciphertext_base64 is not valid base64', 400, cors);
  }
  if (ciphertext.length === 0) {
    return errorResponse('ciphertext is empty', 400, cors);
  }
  // Minimum sane size: 32 (HPKE enc) + 16 (AEAD tag). Anything below that
  // is malformed.
  if (ciphertext.length < 48) {
    return errorResponse('ciphertext is too short to be an HPKE blob', 400, cors);
  }
  if (ciphertext.length > MAX_INBOX_BLOB_BYTES) {
    return errorResponse(`ciphertext exceeds ${MAX_INBOX_BLOB_BYTES} bytes`, 413, cors);
  }

  // Per-DLK, per-type rate limit. Use the existing write_rate_limits table
  // with a distinct key prefix so it doesn't compete with the data-write
  // budget. Atomic INSERT...ON CONFLICT...RETURNING (same pattern as
  // checkWriteRateLimit) — single query, no TOCTOU.
  const limit = type === 'friend-request-v1'
    ? MAX_FRIEND_REQUESTS_PER_HOUR
    : MAX_FRIEND_ACCEPTS_PER_HOUR;
  const hour = new Date().toISOString().slice(0, 13);
  const rateKey = `share-inbox-${type}:${auth.data_lookup_key}:${hour}`;
  const expiresAt = Date.now() + 3600_000;
  const rateRow = await env.DB.prepare(`
    INSERT INTO write_rate_limits (key, count, expires_at)
    VALUES (?1, 1, ?2)
    ON CONFLICT(key) DO UPDATE SET count = count + 1
    RETURNING count
  `).bind(rateKey, expiresAt).first();
  if ((rateRow?.count ?? 1) > limit) {
    return errorResponse(
      `Inbox publish rate limit exceeded for ${type}`,
      429, { ...cors, 'Retry-After': '3600' },
    );
  }

  // Sign + upload to Arweave + cache in D1. We reuse the existing Turbo path
  // so inbox blobs are permanently archived (a recipient logging in on a
  // fresh device with no D1 cache available can still recover them via
  // gateway fetch — though the standard fetch endpoint here serves the cache).
  //
  // Tags written to Arweave (sharing §6.2):
  //   App=tarn-share, Type=<friend-request-v1|friend-accept-v1>, To=<inbox_tag>
  // The "App" value 'tarn-share' is reserved server-side — distinct from any
  // user-app id so a (mis)matching App tag from a different consumer is
  // unambiguous.
  const arweaveTags = [
    { name: 'App', value: 'tarn-share' },
    { name: 'Type', value: type },
    { name: 'To', value: tag },
    { name: 'AppScope', value: auth.app },
    { name: 'V', value: '0.4.0' },
  ];

  const signingKey = env.APP_SIGNING_KEY;
  if (!signingKey) {
    return errorResponse('Server signing key not configured', 500, cors);
  }

  const { signedDataItem, txid } = await buildSignedDataItem(
    ciphertext, arweaveTags, signingKey,
  );

  // D1 cache write — must succeed before we return success. Same authority
  // model as the existing entries table (write-through).
  try {
    await env.DB.prepare(`
      INSERT INTO share_inbox (txid, app_id, inbox_tag, blob_type, ciphertext, published_at)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6)
      ON CONFLICT(txid) DO NOTHING
    `).bind(txid, auth.app, tag, type, ciphertext, Date.now()).run();
  } catch (err) {
    console.error('[tarn-api] share_inbox D1 write failed:', txid, err.message);
    return errorResponse('Failed to cache inbox blob', 500, cors);
  }

  // Background Turbo upload — if Turbo is unhealthy, the D1 cache still
  // serves the blob to recipients. Failed Turbo uploads will require a
  // manual reconcile; documented separately. (Same model as the credential
  // blob upload in routes/auth.js.)
  ctx.waitUntil((async () => {
    try {
      const turbo = await uploadSignedDataItem(signedDataItem);
      if (!turbo.ok) {
        console.warn(`[tarn-api] share-inbox Turbo upload failed: ${turbo.status} ${turbo.body}`);
      }
    } catch (err) {
      console.error('[tarn-api] share-inbox Turbo upload error:', err.message);
    }
  })());

  return jsonResponse({
    txid,
    gateway: `${TURBO_GATEWAY}/${txid}`,
    status: 'pending',
  }, 200, cors);
}

// ============ GET /api/v1/share/inbox/fetch ============

async function checkInboxFetchRateLimit(env, request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const data = new TextEncoder().encode(ip + '-tarn-inbox-fetch-salt');
  const hash = await crypto.subtle.digest('SHA-256', data);
  const ipHash = Array.from(new Uint8Array(hash)).slice(0, 8)
    .map(b => b.toString(16).padStart(2, '0')).join('');
  const hour = new Date().toISOString().slice(0, 13);
  const key = `share-inbox-fetch:${ipHash}:${hour}`;
  const count = parseInt(await env.RATE_KV.get(key) || '0');
  if (count >= MAX_INBOX_FETCHES_PER_HOUR) return { allowed: false, remaining: 0 };
  await env.RATE_KV.put(key, String(count + 1), { expirationTtl: 3600 });
  return { allowed: true, remaining: MAX_INBOX_FETCHES_PER_HOUR - count - 1 };
}

function blobToBase64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

export async function handleShareInboxFetch(url, request, env, cors) {
  const app = url.searchParams.get('app');
  const tag = url.searchParams.get('tag');
  const type = url.searchParams.get('type');

  if (!app || !tag || !type) {
    return errorResponse('Missing required params: app, tag, type', 400, cors);
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(tag)) {
    return errorResponse('Invalid tag format: expected 43-char base64url', 400, cors);
  }
  if (!VALID_BLOB_TYPES.has(type)) {
    return errorResponse(
      `Invalid type: must be one of ${[...VALID_BLOB_TYPES].join(', ')}`,
      400, cors,
    );
  }

  const { allowed, remaining } = await checkInboxFetchRateLimit(env, request);
  if (!allowed) {
    return errorResponse('Rate limit exceeded', 429, { ...cors, 'Retry-After': '3600' });
  }

  const rows = await env.DB.prepare(
    'SELECT txid, ciphertext, published_at FROM share_inbox '
    + 'WHERE app_id = ?1 AND inbox_tag = ?2 AND blob_type = ?3 '
    + 'ORDER BY published_at ASC LIMIT 200'
  ).bind(app, tag, type).all();

  const items = (rows.results || []).map(r => ({
    txid: r.txid,
    ciphertext_base64: blobToBase64(r.ciphertext),
    published_at: r.published_at,
  }));

  return jsonResponse({ blobs: items }, 200, {
    ...cors, 'X-RateLimit-Remaining': String(remaining),
  });
}
