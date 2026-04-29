// Sharing keypair lookup endpoint (issue #13).
//
// Returns a recipient's published `share_pub` for connection-handshake
// bootstrap (sharing design §4 + §9.6). The query is keyed by
// `share_lookup_key` — derivable from email + app_id alone (no password) so a
// connection-to-be who only knows the recipient's email can fetch the keypair
// without an authenticated session against the recipient's account.
//
// Discoverability gate: when the account has `share_discoverable=false`,
// `share_pub` is returned as null even if the row exists. This matches the
// design's "strangers cannot bootstrap a request" semantics. Existing
// connections already cache `share_pub` from the original handshake (Section
// 5 work) and don't depend on this endpoint, so the gate is a no-op for them.
//
// Privacy: lookup-by-email leaks "user A is interested in user B" at handshake
// time — accepted residual leak per sharing §11.5. We rate-limit by IP to make
// bulk enumeration of the email space expensive.

import { jsonResponse, errorResponse } from '../worker.js';

const MAX_LOOKUPS_PER_HOUR = 60;

async function hashIP(ip) {
  const data = new TextEncoder().encode(ip + '-tarn-share-lookup-salt');
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkRateLimit(env, request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ipHash = await hashIP(ip);
  const hour = new Date().toISOString().slice(0, 13);
  const key = `share-lookup:${ipHash}:${hour}`;
  const count = parseInt(await env.RATE_KV.get(key) || '0');
  if (count >= MAX_LOOKUPS_PER_HOUR) {
    return { allowed: false, remaining: 0 };
  }
  await env.RATE_KV.put(key, String(count + 1), { expirationTtl: 3600 });
  return { allowed: true, remaining: MAX_LOOKUPS_PER_HOUR - count - 1 };
}

export async function handleShareLookup(url, request, env, cors) {
  const app = url.searchParams.get('app');
  const key = url.searchParams.get('key');

  if (!app || !key) {
    return errorResponse('Missing required params: app, key', 400, cors);
  }
  if (!/^[a-f0-9]{64}$/.test(key)) {
    return errorResponse('Invalid key format: expected 64-char hex', 400, cors);
  }

  const { allowed, remaining } = await checkRateLimit(env, request);
  if (!allowed) {
    return errorResponse('Rate limit exceeded', 429, { ...cors, 'Retry-After': '3600' });
  }

  // Look up directly by share_lookup_key. The (app, share_lookup_key) pair is
  // unique within an app because share_lookup_key embeds app_id in its HKDF
  // info — but we still scope the SELECT to the requested app so a misrouted
  // query (e.g., bookish app probing a cellar account) returns 404 cleanly.
  const row = await env.DB.prepare(
    'SELECT share_pub, share_discoverable FROM accounts WHERE share_lookup_key = ?1 AND app = ?2'
  ).bind(key, app).first();

  if (!row) {
    // Indistinguishable from "exists but non-discoverable" by design — the
    // alternative would let queriers enumerate which emails are registered.
    return jsonResponse({ share_pub: null, share_discoverable: false }, 200, {
      ...cors, 'X-RateLimit-Remaining': String(remaining),
    });
  }

  // Discoverability gate: hide share_pub if the account opted out, but keep
  // returning the flag so the client can distinguish "discoverable but no
  // keypair published yet" (pre-#13 account) from "discoverable with keypair"
  // (post-#13 account) — both have share_discoverable=true but only the latter
  // returns a non-null share_pub.
  const discoverable = row.share_discoverable !== 0;
  return jsonResponse({
    share_pub: discoverable ? (row.share_pub ?? null) : null,
    share_discoverable: discoverable,
  }, 200, { ...cors, 'X-RateLimit-Remaining': String(remaining) });
}
