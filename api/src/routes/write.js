// Write endpoints: POST/PUT/DELETE entries
// Auth via ECDSA P-256 JWT, write authorization via rules engine.

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { checkWriteRateLimit } from '../rate_limit.js';
import { upsertWriteThrough, trackPendingTx, getEntryByTxid } from '../cache.js';
import { evaluateRules } from '../rules.js';
import { uploadToArweave, forwardToTurbo, TURBO_GATEWAY } from '../turbo.js';
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

/**
 * Look up account rules_json by data_lookup_key.
 */
async function getAccountRules(db, dataLookupKey) {
  const account = await db.prepare(
    'SELECT rules_json FROM accounts WHERE data_lookup_key = ?1'
  ).bind(dataLookupKey).first();
  return account?.rules_json || null;
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

  // Evaluate write authorization rules
  const app = tagValue(tags, 'App') || '';
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

  // Sign DataItem server-side and upload to Turbo
  const signingKey = env.APP_SIGNING_KEY;
  if (!signingKey) {
    return errorResponse('Server signing key not configured', 500, cors);
  }

  const turbo = await uploadToArweave(new Uint8Array(body), tags, signingKey);
  if (!turbo.ok) {
    return jsonResponse(
      { error: 'Turbo upload failed', turboStatus: turbo.status, detail: turbo.body },
      502, cors
    );
  }

  const txid = turbo.txid;

  // Write-through cache + pending tracking (non-blocking)
  if (txid) {
    ctx.waitUntil(Promise.all([
      upsertWriteThrough(env.DB, txid, tags),
      trackPendingTx(env.DB, txid, auth.data_lookup_key, app, type),
    ]));
  }

  return jsonResponse({
    id: txid,
    gateway: txid ? `${TURBO_GATEWAY}/${txid}` : null,
    status: 'pending',
  }, 200, { ...cors, 'X-RateLimit-Remaining': String(remaining) });
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

  const prevTag = tagValue(tags, 'Prev');
  if (!prevTag || prevTag !== priorTxid) {
    return errorResponse('Prev tag must match the entry being edited', 400, cors);
  }

  // Evaluate write rules (edits count too)
  const app = tagValue(tags, 'App') || '';
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

  // Sign DataItem server-side and upload to Turbo
  const turbo = await uploadToArweave(new Uint8Array(body), tags, env.APP_SIGNING_KEY);
  if (!turbo.ok) {
    return jsonResponse(
      { error: 'Turbo upload failed', turboStatus: turbo.status, detail: turbo.body },
      502, cors
    );
  }

  const txid = turbo.txid;

  if (txid) {
    ctx.waitUntil(Promise.all([
      upsertWriteThrough(env.DB, txid, tags),
      trackPendingTx(env.DB, txid, auth.data_lookup_key, app, type),
    ]));
  }

  return jsonResponse({
    id: txid,
    gateway: txid ? `${TURBO_GATEWAY}/${txid}` : null,
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

  if (!tags.some(t => t.name === 'Op' && t.value === 'tombstone')) {
    return errorResponse('Missing Op=tombstone tag', 400, cors);
  }
  const refTag = tagValue(tags, 'Ref');
  if (!refTag || refTag !== targetTxid) {
    return errorResponse('Ref tag must match the entry being deleted', 400, cors);
  }

  // Evaluate write rules (tombstones count too — expired subscriptions can't delete)
  const app = tagValue(tags, 'App') || '';
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

  // Sign DataItem server-side and upload to Turbo
  const turbo = await uploadToArweave(new Uint8Array(body), tags, env.APP_SIGNING_KEY);
  if (!turbo.ok) {
    return jsonResponse(
      { error: 'Turbo upload failed', turboStatus: turbo.status, detail: turbo.body },
      502, cors
    );
  }

  const txid = turbo.txid;

  if (txid) {
    ctx.waitUntil(Promise.all([
      upsertWriteThrough(env.DB, txid, tags),
      trackPendingTx(env.DB, txid, auth.data_lookup_key, app, type),
    ]));
  }

  return jsonResponse({
    id: txid,
    gateway: txid ? `${TURBO_GATEWAY}/${txid}` : null,
    tombstoneRef: targetTxid,
    status: 'pending',
  }, 200, { ...cors, 'X-RateLimit-Remaining': String(remaining) });
}
