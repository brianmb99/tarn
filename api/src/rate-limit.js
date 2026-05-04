// rate-limit.js — shared per-bucket counter via Cloudflare KV.
//
// Used by every route that does abuse-prevention rate limiting (register,
// share-lookup, inbox publish/fetch, share-log fetch, etc.).
//
// Fails open: if KV is unavailable (e.g., free-tier daily put limit
// exceeded), the rate limit is not enforced and requests pass through with
// a warning log. Rate limiting here is abuse mitigation, not a security
// boundary — letting requests through during a KV outage is the correct
// default. The alternative (returning 500 to legitimate users when the
// rate-limit store is unhealthy) would be strictly worse than the abuse
// risk during the outage window.

/**
 * Atomically read + increment a per-key counter in RATE_KV with a TTL.
 *
 * @param {KVNamespace} kv - the RATE_KV binding from `env`
 * @param {string} key - the bucket key, e.g. `register:<ipHash>:<hour>`
 * @param {number} max - max count allowed in this bucket
 * @param {number} ttlSec - bucket TTL in seconds (typically 3600 for hourly)
 * @returns {Promise<{allowed: boolean, count: number}>}
 *   `allowed` is false only when the counter is already at or above `max`.
 *   On KV failure, returns `{allowed: true, count: 0}` (fail open).
 */
export async function checkAndIncrementRateLimit(kv, key, max, ttlSec = 3600) {
  if (!kv) {
    console.warn(`[rate-limit] no KV binding for ${key}; allowing request`);
    return { allowed: true, count: 0 };
  }

  let count = 0;
  try {
    const raw = await kv.get(key);
    count = parseInt(raw || '0', 10);
    if (Number.isNaN(count)) count = 0;
  } catch (err) {
    console.warn(`[rate-limit] KV get failed for ${key}: ${err?.message || err}; allowing request`);
    return { allowed: true, count: 0 };
  }

  if (count >= max) {
    return { allowed: false, count };
  }

  try {
    await kv.put(key, String(count + 1), { expirationTtl: ttlSec });
  } catch (err) {
    console.warn(`[rate-limit] KV put failed for ${key}: ${err?.message || err}; counter not incremented (request still allowed)`);
  }

  return { allowed: true, count: count + 1 };
}
