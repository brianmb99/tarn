// Write endpoints: POST/PUT/DELETE entries
// Ports upload-proxy logic with write-through D1 cache and pending tx tracking.

import { ethers } from 'ethers';
import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { checkWriteRateLimit } from '../rate_limit.js';
import { upsertWriteThrough, trackPendingTx, getEntryByTxid } from '../cache.js';
import {
  PROTOCOL_WALLET, EXPECTED_FEE_WEI, MAX_UPLOAD_BYTES,
  FEE_EXEMPT_TYPES, FEE_SCHEDULE,
} from '../constants.js';

const TURBO_UPLOAD_SIGNED_URL = 'https://upload.ardrive.io/v1/tx';
const TURBO_GATEWAY = 'https://turbo-gateway.com';
const BASE_RPC_FALLBACK = 'https://mainnet.base.org';

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

function isFeeExempt(tags) {
  if (tags.some(t => t.name === 'Prev' && t.value)) return true;
  if (tags.some(t => t.name === 'Op' && t.value === 'tombstone')) return true;
  const type = tagValue(tags, 'Type');
  if (type && FEE_EXEMPT_TYPES.has(type)) return true;
  return false;
}

function parsePayment(request) {
  const raw = request.headers.get('X-Payment');
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

function validateSignedTx(payment) {
  if (!payment?.signedTx) return 'missing signedTx field';
  try {
    const tx = ethers.Transaction.from(payment.signedTx);
    if (!tx.to || tx.to.toLowerCase() !== PROTOCOL_WALLET.toLowerCase()) {
      return `wrong recipient: expected ${PROTOCOL_WALLET}, got ${tx.to}`;
    }
    if (tx.value < BigInt(EXPECTED_FEE_WEI)) {
      return `fee too low: expected >= ${EXPECTED_FEE_WEI} wei, got ${tx.value}`;
    }
    if (tx.chainId !== 8453n) {
      return `wrong chain: expected 8453, got ${tx.chainId}`;
    }
    return null;
  } catch (e) {
    return `invalid signed transaction: ${e.message}`;
  }
}

async function broadcastFee(signedTx, env) {
  const rpcUrl = env?.BASE_RPC_URL || BASE_RPC_FALLBACK;
  const network = ethers.Network.from(8453);
  const provider = new ethers.JsonRpcProvider(rpcUrl, network, { staticNetwork: true });
  const txResponse = await provider.broadcastTransaction(signedTx);
  return { txHash: txResponse.hash };
}

async function forwardToTurbo(body) {
  const res = await fetch(TURBO_UPLOAD_SIGNED_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body,
    signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();
  if (!res.ok) {
    return { ok: false, status: res.status, body: text.slice(0, 500) };
  }
  let result;
  try { result = JSON.parse(text); } catch { result = { raw: text }; }
  return { ok: true, result, txid: result.id || result.dataItemId };
}

// ============ POST /api/v1/entries — Create ============

export async function handleCreateEntry(request, env, ctx, cors) {
  // Auth
  const auth = await requireAuth(request, env);
  if (!auth) return errorResponse('Unauthorized', 401, cors);

  // Rate limit
  const { allowed, remaining } = await checkWriteRateLimit(env, auth.address);
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

  // Validate wallet match
  const addrTag = tagValue(tags, 'Addr');
  if (!addrTag || addrTag.toLowerCase() !== auth.address.toLowerCase()) {
    return errorResponse('Addr tag does not match authenticated wallet', 403, cors);
  }

  // Fee handling
  let feeTxHash = null;
  let feeError = null;
  if (!isFeeExempt(tags)) {
    const payment = parsePayment(request);
    if (!payment) {
      return jsonResponse(
        { error: 'Payment required', feeSchedule: FEE_SCHEDULE },
        402, cors
      );
    }
    const valError = validateSignedTx(payment);
    if (valError) {
      return jsonResponse(
        { error: 'Invalid payment', detail: valError, feeSchedule: FEE_SCHEDULE },
        402, cors
      );
    }
    try {
      const result = await broadcastFee(payment.signedTx, env);
      feeTxHash = result.txHash;
      console.log(`[tarn-api] Fee broadcast: ${feeTxHash}`);
    } catch (e) {
      feeError = e.message;
      console.error(`[tarn-api] Fee broadcast failed (non-blocking): ${feeError}`);
    }
  }

  // Forward to Turbo
  const turbo = await forwardToTurbo(body);
  if (!turbo.ok) {
    return jsonResponse(
      { error: 'Turbo upload failed', turboStatus: turbo.status, detail: turbo.body, feeTxHash, feeError },
      502, cors
    );
  }

  const txid = turbo.txid;
  const app = tagValue(tags, 'App') || '';
  const type = tagValue(tags, 'Type') || '';

  // Write-through cache + pending tracking (non-blocking)
  if (txid) {
    ctx.waitUntil(Promise.all([
      upsertWriteThrough(env.DB, txid, tags),
      trackPendingTx(env.DB, txid, auth.address, app, type),
    ]));
  }

  return jsonResponse({
    id: txid,
    gateway: txid ? `${TURBO_GATEWAY}/${txid}` : null,
    feeTxHash,
    feeError,
    status: 'pending',
  }, 200, { ...cors, 'X-RateLimit-Remaining': String(remaining) });
}

// ============ PUT /api/v1/entries/:id — Edit ============

export async function handleEditEntry(priorTxid, request, env, ctx, cors) {
  // Auth
  const auth = await requireAuth(request, env);
  if (!auth) return errorResponse('Unauthorized', 401, cors);

  // Rate limit
  const { allowed, remaining } = await checkWriteRateLimit(env, auth.address);
  if (!allowed) {
    return jsonResponse(
      { error: 'Rate limit exceeded', retryAfter: 3600 },
      429, { ...cors, 'Retry-After': '3600' }
    );
  }

  // Validate prior entry exists and belongs to this wallet
  const prior = await getEntryByTxid(env.DB, priorTxid);
  if (!prior || (prior.wallet_addr && prior.wallet_addr.toLowerCase() !== auth.address.toLowerCase())) {
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

  const addrTag = tagValue(tags, 'Addr');
  if (!addrTag || addrTag.toLowerCase() !== auth.address.toLowerCase()) {
    return errorResponse('Addr tag does not match authenticated wallet', 403, cors);
  }

  const prevTag = tagValue(tags, 'Prev');
  if (!prevTag || prevTag !== priorTxid) {
    return errorResponse('Prev tag must match the entry being edited', 400, cors);
  }

  // Edits are always fee-exempt — forward to Turbo
  const turbo = await forwardToTurbo(body);
  if (!turbo.ok) {
    return jsonResponse(
      { error: 'Turbo upload failed', turboStatus: turbo.status, detail: turbo.body },
      502, cors
    );
  }

  const txid = turbo.txid;
  const app = tagValue(tags, 'App') || '';
  const type = tagValue(tags, 'Type') || '';

  if (txid) {
    ctx.waitUntil(Promise.all([
      upsertWriteThrough(env.DB, txid, tags),
      trackPendingTx(env.DB, txid, auth.address, app, type),
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
  const { allowed, remaining } = await checkWriteRateLimit(env, auth.address);
  if (!allowed) {
    return jsonResponse(
      { error: 'Rate limit exceeded', retryAfter: 3600 },
      429, { ...cors, 'Retry-After': '3600' }
    );
  }

  // Validate target entry exists and belongs to this wallet
  const target = await getEntryByTxid(env.DB, targetTxid);
  if (!target || (target.wallet_addr && target.wallet_addr.toLowerCase() !== auth.address.toLowerCase())) {
    return errorResponse('Entry not found', 404, cors);
  }

  // Read body
  const body = await request.arrayBuffer();
  if (!body || body.byteLength === 0) return errorResponse('Empty payload', 400, cors);

  // Parse and validate tags
  const { tags, error: tagError } = parseTags(request);
  if (tagError) return errorResponse(tagError, 400, cors);

  const addrTag = tagValue(tags, 'Addr');
  if (!addrTag || addrTag.toLowerCase() !== auth.address.toLowerCase()) {
    return errorResponse('Addr tag does not match authenticated wallet', 403, cors);
  }

  if (!tags.some(t => t.name === 'Op' && t.value === 'tombstone')) {
    return errorResponse('Missing Op=tombstone tag', 400, cors);
  }
  const refTag = tagValue(tags, 'Ref');
  if (!refTag || refTag !== targetTxid) {
    return errorResponse('Ref tag must match the entry being deleted', 400, cors);
  }

  // Tombstones are always fee-exempt — forward to Turbo
  const turbo = await forwardToTurbo(body);
  if (!turbo.ok) {
    return jsonResponse(
      { error: 'Turbo upload failed', turboStatus: turbo.status, detail: turbo.body },
      502, cors
    );
  }

  const txid = turbo.txid;
  const app = tagValue(tags, 'App') || '';
  const type = tagValue(tags, 'Type') || '';

  if (txid) {
    ctx.waitUntil(Promise.all([
      upsertWriteThrough(env.DB, txid, tags),
      trackPendingTx(env.DB, txid, auth.address, app, type),
    ]));
  }

  return jsonResponse({
    id: txid,
    gateway: txid ? `${TURBO_GATEWAY}/${txid}` : null,
    tombstoneRef: targetTxid,
    status: 'pending',
  }, 200, { ...cors, 'X-RateLimit-Remaining': String(remaining) });
}
