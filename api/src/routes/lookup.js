// Lookup endpoint for credential mappings and account metadata (by Lk tag)
// Unauthenticated — IP rate-limited.

import { jsonResponse, errorResponse } from '../worker.js';
import { getEntryByLookupKey, refreshLookupCache } from '../cache.js';

const MAX_LOOKUPS_PER_HOUR = 30;

async function hashIP(ip) {
  const data = new TextEncoder().encode(ip + '-tarn-api-salt');
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkRateLimit(env, request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ipHash = await hashIP(ip);
  const hour = new Date().toISOString().slice(0, 13); // YYYY-MM-DDTHH
  const key = `lookup:${ipHash}:${hour}`;
  const count = parseInt(await env.RATE_KV.get(key) || '0');
  if (count >= MAX_LOOKUPS_PER_HOUR) {
    return { allowed: false, remaining: 0 };
  }
  await env.RATE_KV.put(key, String(count + 1), { expirationTtl: 3600 });
  return { allowed: true, remaining: MAX_LOOKUPS_PER_HOUR - count - 1 };
}

export async function handleLookup(url, request, env, ctx, cors) {
  const app = url.searchParams.get('app');
  const type = url.searchParams.get('type');
  const key = url.searchParams.get('key');

  if (!app || !type || !key) {
    return errorResponse('Missing required params: app, type, key', 400, cors);
  }

  // Validate lookup key format (64-char hex)
  if (!/^[a-f0-9]{64}$/i.test(key)) {
    return errorResponse('Invalid key format: expected 64-char hex', 400, cors);
  }

  // IP rate limiting
  const { allowed, remaining } = await checkRateLimit(env, request);
  if (!allowed) {
    return errorResponse('Rate limit exceeded', 429, { ...cors, 'Retry-After': '3600' });
  }

  // Check cache, refresh from Arweave if needed
  await refreshLookupCache(env, ctx, app, type, key);

  const entry = await getEntryByLookupKey(env.DB, key);
  if (!entry) {
    return errorResponse('Not found', 404, cors);
  }

  return jsonResponse({
    txid: entry.txid,
    tags: entry.tags_json ? JSON.parse(entry.tags_json) : [],
    confirmed: entry.block_timestamp != null,
    gatewayUrl: `https://arweave.net/${entry.txid}`,
  }, 200, { ...cors, 'X-RateLimit-Remaining': String(remaining) });
}
