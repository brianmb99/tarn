// Per-pair share log endpoints (issue #15, Section 5b).
//
// Two endpoints, both scoped by app:
//   POST /api/v1/share/log/publish — JWT-gated, per-tag uniqueness check
//     publishes a stealth-addressed encrypted log entry. Returns 409 with
//     the existing txid if the tag is already taken (sharing §9.1).
//   GET  /api/v1/share/log/fetch — public, IP rate-limited, returns the
//     single blob at a given (app, tag, type). 404 if not found.
//
// The blob bytes are opaque to the server (AES-GCM ciphertext under per-pair
// K_AB); only the recipient can decrypt. Tarn signs + uploads to Arweave via
// the existing Turbo path so the entry is permanent on chain — D1 is the
// cache.
//
// Per the sharing design (§9.1, explicit note): Tarn's uniqueness check is
// per *exact tag value*. There is no per-pair prefix parameter — Tarn has no
// notion of which user-pair a tag belongs to.

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { buildSignedDataItem, uploadSignedDataItem, TURBO_GATEWAY } from '../turbo.js';
import { checkAndIncrementRateLimit } from '../rate-limit.js';
import { mirrorUploadWithTracking } from '../observability/mirror-failures.js';

// Plaintext is signed JSON (~150 bytes for a typical add) up to a snapshot of
// the user's full shared library. The client caps plaintext at 256 KB
// (see share-log.js MAX_LOG_BLOB_PLAINTEXT_BYTES). After AES-GCM (12-byte iv
// + 16-byte tag) the blob is plaintext + 28; we cap server-side at 384 KB
// to leave headroom for protocol-version growth without round-tripping a
// constant.
const MAX_LOG_BLOB_BYTES = 384 * 1024;

// IP rate limit on the public fetch endpoint. Per-tag fetches are how
// recipients pull individual entries; a power user with N connections, K writes
// per connection per session would issue N×K reads. 1800/hour matches the
// share_inbox fetch budget — both are cache reads with the same blast radius.
const MAX_LOG_FETCHES_PER_HOUR = 1800;

// Recognized blob types. Future protocol versions get their own values;
// share-log-v1 is the only one for 5b.
const VALID_BLOB_TYPES = new Set(['share-log-v1']);

// ============ POST /api/v1/share/log/publish ============

export async function handleShareLogPublish(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') {
    return errorResponse('Only user accounts can publish to a share log', 403, cors);
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
  if (ciphertext_base64.length > Math.ceil(MAX_LOG_BLOB_BYTES * 4 / 3) + 4) {
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
  // Minimum sane size: 12 (AES-GCM IV) + 16 (tag). Anything below is malformed.
  if (ciphertext.length < 28) {
    return errorResponse('ciphertext is too short to be an AES-GCM blob', 400, cors);
  }
  if (ciphertext.length > MAX_LOG_BLOB_BYTES) {
    return errorResponse(`ciphertext exceeds ${MAX_LOG_BLOB_BYTES} bytes`, 413, cors);
  }

  // Per-tag uniqueness check (sharing §9.1). The unique index on
  // (app_id, log_tag, blob_type) is the source of truth — we look up first
  // so we can return the existing txid in the 409, then INSERT and let the
  // index reject any concurrent collision atomically.
  const existing = await env.DB.prepare(
    'SELECT txid FROM share_log WHERE app_id = ?1 AND log_tag = ?2 AND blob_type = ?3'
  ).bind(auth.app, tag, type).first();
  if (existing?.txid) {
    return jsonResponse({
      error: 'tag already published',
      existing_txid: existing.txid,
    }, 409, cors);
  }

  // Sign + upload to Arweave. Same Turbo path as share-inbox + entries —
  // the API server signs all bundled writes; users' identities are not
  // exposed at the Arweave layer.
  //
  // Tags written to Arweave (sharing §8.1):
  //   App=tarn-share, Type=share-log-v1, To=<log_tag>, AppScope=<app_id>
  // The "App" value 'tarn-share' is reserved server-side (matches the
  // share-inbox convention).
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

  // D1 cache write — must succeed before we return success. The unique index
  // is the secondary source of truth: even if our pre-check above raced with
  // a concurrent publish at the same tag, the INSERT will fail and we return
  // 409 with the now-known existing txid.
  try {
    await env.DB.prepare(`
      INSERT INTO share_log (txid, app_id, log_tag, blob_type, ciphertext, data_lookup_key, published_at)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
    `).bind(txid, auth.app, tag, type, ciphertext, auth.data_lookup_key, Date.now()).run();
  } catch (err) {
    // SQLite unique-index violation is the expected concurrent-publish path.
    // Re-fetch the winner so the loser can use its txid for retry.
    if (typeof err?.message === 'string' && /UNIQUE/i.test(err.message)) {
      const winner = await env.DB.prepare(
        'SELECT txid FROM share_log WHERE app_id = ?1 AND log_tag = ?2 AND blob_type = ?3'
      ).bind(auth.app, tag, type).first();
      return jsonResponse({
        error: 'tag already published',
        existing_txid: winner?.txid ?? null,
      }, 409, cors);
    }
    console.error('[tarn-api] share_log D1 write failed:', txid, err.message);
    return errorResponse('Failed to cache share-log blob', 500, cors);
  }

  // Background Turbo upload — same model as share-inbox publish. If Turbo is
  // unhealthy the D1 cache still serves the blob; failed uploads need a
  // manual reconcile (documented separately).
  ctx.waitUntil((async () => {
    try {
      const turbo = await mirrorUploadWithTracking({
        uploadFn: () => uploadSignedDataItem(signedDataItem),
        db: env.DB,
        namespace: 'share-log',
        intendedTxid: txid,
        tags: arweaveTags,
        signedDataItem,
      });
      if (!turbo.ok) {
        console.warn(`[tarn-api] share-log Turbo upload failed: ${turbo.status} ${turbo.body}`);
      }
    } catch (err) {
      console.error('[tarn-api] share-log Turbo upload error:', err.message);
    }
  })());

  return jsonResponse({
    txid,
    gateway: `${TURBO_GATEWAY}/${txid}`,
    status: 'pending',
  }, 200, cors);
}

// ============ GET /api/v1/share/log/fetch ============

async function checkLogFetchRateLimit(env, request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const data = new TextEncoder().encode(ip + '-tarn-share-log-fetch-salt');
  const hash = await crypto.subtle.digest('SHA-256', data);
  const ipHash = Array.from(new Uint8Array(hash)).slice(0, 8)
    .map(b => b.toString(16).padStart(2, '0')).join('');
  const hour = new Date().toISOString().slice(0, 13);
  const key = `share-log-fetch:${ipHash}:${hour}`;
  const { allowed, count } = await checkAndIncrementRateLimit(env.RATE_KV, key, MAX_LOG_FETCHES_PER_HOUR);
  return { allowed, remaining: Math.max(0, MAX_LOG_FETCHES_PER_HOUR - count) };
}

function blobToBase64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

export async function handleShareLogFetch(url, request, env, cors) {
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

  const { allowed, remaining } = await checkLogFetchRateLimit(env, request);
  if (!allowed) {
    return errorResponse('Rate limit exceeded', 429, { ...cors, 'Retry-After': '3600' });
  }

  // Per-tag uniqueness means at most one row matches. Use first() rather than
  // all() to make the cardinality assumption explicit at the SQL layer.
  const row = await env.DB.prepare(
    'SELECT txid, ciphertext, published_at FROM share_log '
    + 'WHERE app_id = ?1 AND log_tag = ?2 AND blob_type = ?3'
  ).bind(app, tag, type).first();

  if (!row) {
    return jsonResponse({ blob: null }, 404, {
      ...cors, 'X-RateLimit-Remaining': String(remaining),
    });
  }

  return jsonResponse({
    blob: {
      txid: row.txid,
      ciphertext_base64: blobToBase64(row.ciphertext),
      published_at: row.published_at,
    },
  }, 200, {
    ...cors, 'X-RateLimit-Remaining': String(remaining),
  });
}
