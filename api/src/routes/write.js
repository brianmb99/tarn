// Write endpoints: POST/PUT/DELETE entries
// Auth via ECDSA P-256 JWT, write authorization via rules engine.
// Pattern: build + sign DataItem → compute txid locally → cache in D1 → upload to Turbo in background.
// This means D1 cache is immediately populated and reads work instantly.
// Turbo upload is best-effort (background). If it fails, data is in D1 but not yet on Arweave.

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { checkWriteRateLimit } from '../rate_limit.js';
import { upsertWriteThrough, trackPendingTx, getEntryByTxid } from '../cache.js';
import { evaluateRules } from '../rules.js';
import { buildSignedDataItem, uploadSignedDataItem, TURBO_GATEWAY } from '../turbo.js';
import { MAX_UPLOAD_BYTES } from '../constants.js';

// ============ HELPERS ============

function parseTags(request) {
  const raw = request.headers.get('X-Arweave-Tags');
  if (!raw) return { tags: null, error: 'Missing X-Arweave-Tags header' };
  try {
    const tags = JSON.parse(raw);
    if (!Array.isArray(tags)) return { tags: null, error: 'X-Arweave-Tags must be an array' };
    return { tags, error: null };
  } catch (e) {
    return { tags: null, error: `Invalid X-Arweave-Tags: ${e.message}` };
  }
}

function tagValue(tags, name) {
  return tags.find(t => t.name === name)?.value || null;
}

async function getAccountRules(db, dataLookupKey) {
  const account = await db.prepare(
    'SELECT rules_json FROM accounts WHERE data_lookup_key = ?1'
  ).bind(dataLookupKey).first();
  return account?.rules_json || null;
}

/**
 * Common write flow: build DataItem, cache in D1, upload to Turbo in background.
 * Returns the txid (computed locally from DataItem signature).
 */
async function signCacheAndUpload(body, tags, env, ctx, auth) {
  const signingKey = env.APP_SIGNING_KEY;
  if (!signingKey) {
    return { error: 'Server signing key not configured', status: 500 };
  }

  // Build and sign DataItem, compute txid locally
  const { signedDataItem, txid } = await buildSignedDataItem(new Uint8Array(body), tags, signingKey);

  const app = tagValue(tags, 'App') || '';
  const type = tagValue(tags, 'Type') || '';

  // Write to D1 cache immediately (synchronous)
  await upsertWriteThrough(env.DB, txid, tags);
  await trackPendingTx(env.DB, txid, auth.data_lookup_key, app, type);

  // Upload to Turbo in background (non-blocking)
  ctx.waitUntil((async () => {
    const result = await uploadSignedDataItem(signedDataItem);
    if (result.ok) {
      console.log(`[tarn-api] Turbo upload OK: ${txid}`);
    } else {
      console.warn(`[tarn-api] Turbo upload failed for ${txid}: ${result.status} ${result.body}`);
      // Data is still in D1 cache. Will sync to Arweave on retry or backfill.
    }
  })());

  return { txid };
}

// ============ POST /api/v1/entries — Create ============

export async function handleCreateEntry(request, env, ctx, cors) {
  // Auth
  const auth = await requireAuth(request, env);
  if (!auth) return errorResponse('Unauthorized', 401, cors);

  // Rate limit
  const { allowed, remaining } = await checkWriteRateLimit(env, auth.data_lookup_key);
  if (!allowed) {
    return jsonResponse(
      { error: 'Rate limit exceeded', retryAfter: 3600 },
      429,
      { ...cors, 'Retry-After': '3600' }
    );
  }

  // Read body
  const body = await request.arrayBuffer();
  if (!body || body.byteLength === 0) {
    return errorResponse('Empty payload', 400, cors);
  }
  if (body.byteLength > MAX_UPLOAD_BYTES) {
    return jsonResponse(
      { error: 'Payload too large', maxBytes: MAX_UPLOAD_BYTES, receivedBytes: body.byteLength },
      413, cors
    );
  }

  // Parse tags
  const { tags, error: tagError } = parseTags(request);
  if (tagError) return errorResponse(tagError, 400, cors);

  // Validate Lk tag matches authenticated user
  const lkTag = tagValue(tags, 'Lk');
  if (!lkTag || lkTag !== auth.data_lookup_key) {
    return errorResponse('Lk tag does not match authenticated identity', 403, cors);
  }

  // Validate App tag matches JWT app claim
  const app = tagValue(tags, 'App') || '';
  if (!auth.app || app !== auth.app) {
    return errorResponse('App tag does not match authenticated app', 403, cors);
  }
  const type = tagValue(tags, 'Type') || '';

  const rulesJson = await getAccountRules(env.DB, auth.data_lookup_key);
  const ruleResult = await evaluateRules(env.DB, rulesJson, {
    data_lookup_key: auth.data_lookup_key,
    app,
    type,
    payloadBytes: body.byteLength,
  });

  if (!ruleResult.allowed) {
    return jsonResponse(
      { error: 'Write denied by authorization rules', detail: ruleResult.failedRule },
      403, cors
    );
  }

  // Sign, cache, upload
  const result = await signCacheAndUpload(body, tags, env, ctx, auth);
  if (result.error) {
    return errorResponse(result.error, result.status, cors);
  }

  return jsonResponse({
    id: result.txid,
    gateway: `${TURBO_GATEWAY}/${result.txid}`,
    status: 'pending',
  }, 200, { ...cors, 'X-RateLimit-Remaining': String(remaining) });
}

// ============ POST /api/v1/entries/batch — Bulk Import ============

const MAX_BATCH_SIZE = 100;

export async function handleBatchCreate(request, env, ctx, cors) {
  // Auth
  const auth = await requireAuth(request, env);
  if (!auth) return errorResponse('Unauthorized', 401, cors);

  // Rate limit (batch counts as 1 rate-limit hit)
  const { allowed, remaining } = await checkWriteRateLimit(env, auth.data_lookup_key);
  if (!allowed) {
    return jsonResponse(
      { error: 'Rate limit exceeded', retryAfter: 3600 },
      429, { ...cors, 'Retry-After': '3600' }
    );
  }

  // Parse JSON body
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { entries } = body;
  if (!Array.isArray(entries) || entries.length === 0) {
    return errorResponse('entries[] is required and must be non-empty', 400, cors);
  }
  if (entries.length > MAX_BATCH_SIZE) {
    return errorResponse(`entries[] max ${MAX_BATCH_SIZE} items`, 400, cors);
  }

  // Validate all entries upfront
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    if (!entry.data || typeof entry.data !== 'string') {
      return errorResponse(`entries[${i}]: data is required (base64-encoded bytes)`, 400, cors);
    }
    if (!Array.isArray(entry.tags)) {
      return errorResponse(`entries[${i}]: tags[] is required`, 400, cors);
    }

    // Validate Lk tag
    const lk = tagValue(entry.tags, 'Lk');
    if (!lk || lk !== auth.data_lookup_key) {
      return errorResponse(`entries[${i}]: Lk tag does not match authenticated identity`, 403, cors);
    }

    // Validate App tag
    const app = tagValue(entry.tags, 'App') || '';
    if (!auth.app || app !== auth.app) {
      return errorResponse(`entries[${i}]: App tag does not match authenticated app`, 403, cors);
    }

    // Decode and check size
    let dataBytes;
    try {
      dataBytes = Uint8Array.from(atob(entry.data), c => c.charCodeAt(0));
    } catch {
      return errorResponse(`entries[${i}]: invalid base64 data`, 400, cors);
    }
    if (dataBytes.length === 0) {
      return errorResponse(`entries[${i}]: empty data`, 400, cors);
    }
    if (dataBytes.length > MAX_UPLOAD_BYTES) {
      return errorResponse(`entries[${i}]: data exceeds ${MAX_UPLOAD_BYTES} bytes`, 413, cors);
    }

    // Stash decoded bytes for processing
    entry._dataBytes = dataBytes;
  }

  // Evaluate rules with batch size
  const firstEntry = entries[0];
  const app = tagValue(firstEntry.tags, 'App') || '';
  const type = tagValue(firstEntry.tags, 'Type') || '';

  const rulesJson = await getAccountRules(env.DB, auth.data_lookup_key);
  const ruleResult = await evaluateRules(env.DB, rulesJson, {
    data_lookup_key: auth.data_lookup_key,
    app,
    type,
    payloadBytes: Math.max(...entries.map(e => e._dataBytes.length)),
    batchSize: entries.length,
  });

  if (!ruleResult.allowed) {
    return jsonResponse(
      { error: 'Write denied by authorization rules', detail: ruleResult.failedRule },
      403, cors
    );
  }

  // Signing key check
  const signingKey = env.APP_SIGNING_KEY;
  if (!signingKey) {
    return errorResponse('Server signing key not configured', 500, cors);
  }

  // Process all entries: sign, cache, upload in background
  const results = [];

  for (const entry of entries) {
    const { signedDataItem, txid } = await buildSignedDataItem(entry._dataBytes, entry.tags, signingKey);
    const entryApp = tagValue(entry.tags, 'App') || '';
    const entryType = tagValue(entry.tags, 'Type') || '';

    // Cache in D1 immediately
    await upsertWriteThrough(env.DB, txid, entry.tags);
    await trackPendingTx(env.DB, txid, auth.data_lookup_key, entryApp, entryType);

    // Upload to Turbo in background
    ctx.waitUntil((async () => {
      const result = await uploadSignedDataItem(signedDataItem);
      if (result.ok) {
        console.log(`[tarn-api] Batch Turbo upload OK: ${txid}`);
      } else {
        console.warn(`[tarn-api] Batch Turbo upload failed for ${txid}: ${result.status} ${result.body}`);
      }
    })());

    results.push({ txid, gateway: `${TURBO_GATEWAY}/${txid}` });
  }

  return jsonResponse({
    entries: results,
    count: results.length,
    status: 'pending',
  }, 200, cors);
}

// ============ PUT /api/v1/entries/:id — Edit ============

export async function handleEditEntry(priorTxid, request, env, ctx, cors) {
  // Auth
  const auth = await requireAuth(request, env);
  if (!auth) return errorResponse('Unauthorized', 401, cors);

  // Rate limit
  const { allowed, remaining } = await checkWriteRateLimit(env, auth.data_lookup_key);
  if (!allowed) {
    return jsonResponse(
      { error: 'Rate limit exceeded', retryAfter: 3600 },
      429, { ...cors, 'Retry-After': '3600' }
    );
  }

  // Validate prior entry exists and belongs to this user
  const prior = await getEntryByTxid(env.DB, priorTxid);
  if (!prior || (prior.lookup_key && prior.lookup_key !== auth.data_lookup_key)) {
    return errorResponse('Entry not found', 404, cors);
  }

  // Read body
  const body = await request.arrayBuffer();
  if (!body || body.byteLength === 0) return errorResponse('Empty payload', 400, cors);
  if (body.byteLength > MAX_UPLOAD_BYTES) {
    return jsonResponse({ error: 'Payload too large', maxBytes: MAX_UPLOAD_BYTES }, 413, cors);
  }

  // Parse and validate tags
  const { tags, error: tagError } = parseTags(request);
  if (tagError) return errorResponse(tagError, 400, cors);

  const lkTag = tagValue(tags, 'Lk');
  if (!lkTag || lkTag !== auth.data_lookup_key) {
    return errorResponse('Lk tag does not match authenticated identity', 403, cors);
  }

  // Validate App tag matches JWT app claim
  const app = tagValue(tags, 'App') || '';
  if (!auth.app || app !== auth.app) {
    return errorResponse('App tag does not match authenticated app', 403, cors);
  }

  const prevTag = tagValue(tags, 'Prev');
  if (!prevTag || prevTag !== priorTxid) {
    return errorResponse('Prev tag must match the entry being edited', 400, cors);
  }

  // Evaluate write rules
  const rulesJson = await getAccountRules(env.DB, auth.data_lookup_key);
  const ruleResult = await evaluateRules(env.DB, rulesJson, {
    data_lookup_key: auth.data_lookup_key,
    app,
    type: tagValue(tags, 'Type') || '',
    payloadBytes: body.byteLength,
  });

  if (!ruleResult.allowed) {
    return jsonResponse(
      { error: 'Write denied by authorization rules', detail: ruleResult.failedRule },
      403, cors
    );
  }

  // Sign, cache, upload
  const result = await signCacheAndUpload(body, tags, env, ctx, auth);
  if (result.error) {
    return errorResponse(result.error, result.status, cors);
  }

  return jsonResponse({
    id: result.txid,
    gateway: `${TURBO_GATEWAY}/${result.txid}`,
    prevTxid: priorTxid,
    status: 'pending',
  }, 200, { ...cors, 'X-RateLimit-Remaining': String(remaining) });
}

// ============ DELETE /api/v1/entries/:id — Tombstone ============

export async function handleDeleteEntry(targetTxid, request, env, ctx, cors) {
  // Auth
  const auth = await requireAuth(request, env);
  if (!auth) return errorResponse('Unauthorized', 401, cors);

  // Rate limit
  const { allowed, remaining } = await checkWriteRateLimit(env, auth.data_lookup_key);
  if (!allowed) {
    return jsonResponse(
      { error: 'Rate limit exceeded', retryAfter: 3600 },
      429, { ...cors, 'Retry-After': '3600' }
    );
  }

  // Validate target entry exists and belongs to this user
  const target = await getEntryByTxid(env.DB, targetTxid);
  if (!target || (target.lookup_key && target.lookup_key !== auth.data_lookup_key)) {
    return errorResponse('Entry not found', 404, cors);
  }

  // Read body
  const body = await request.arrayBuffer();
  if (!body || body.byteLength === 0) return errorResponse('Empty payload', 400, cors);

  // Parse and validate tags
  const { tags, error: tagError } = parseTags(request);
  if (tagError) return errorResponse(tagError, 400, cors);

  const lkTag = tagValue(tags, 'Lk');
  if (!lkTag || lkTag !== auth.data_lookup_key) {
    return errorResponse('Lk tag does not match authenticated identity', 403, cors);
  }

  // Validate App tag matches JWT app claim
  const app = tagValue(tags, 'App') || '';
  if (!auth.app || app !== auth.app) {
    return errorResponse('App tag does not match authenticated app', 403, cors);
  }

  if (!tags.some(t => t.name === 'Op' && t.value === 'tombstone')) {
    return errorResponse('Missing Op=tombstone tag', 400, cors);
  }
  const refTag = tagValue(tags, 'Ref');
  if (!refTag || refTag !== targetTxid) {
    return errorResponse('Ref tag must match the entry being deleted', 400, cors);
  }

  // Evaluate write rules
  const rulesJson = await getAccountRules(env.DB, auth.data_lookup_key);
  const ruleResult = await evaluateRules(env.DB, rulesJson, {
    data_lookup_key: auth.data_lookup_key,
    app,
    type: tagValue(tags, 'Type') || '',
    payloadBytes: body.byteLength,
  });

  if (!ruleResult.allowed) {
    return jsonResponse(
      { error: 'Write denied by authorization rules', detail: ruleResult.failedRule },
      403, cors
    );
  }

  // Sign, cache, upload
  const result = await signCacheAndUpload(body, tags, env, ctx, auth);
  if (result.error) {
    return errorResponse(result.error, result.status, cors);
  }

  return jsonResponse({
    id: result.txid,
    gateway: `${TURBO_GATEWAY}/${result.txid}`,
    tombstoneRef: targetTxid,
    status: 'pending',
  }, 200, { ...cors, 'X-RateLimit-Remaining': String(remaining) });
}
