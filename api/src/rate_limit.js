// Write + read rate limiting.
//
// Writes use a D1 atomic counter (INSERT ... ON CONFLICT DO UPDATE … RETURNING
// count) so concurrent requests can't blow past the cap by racing the KV
// get-then-put. Writes spend Tarn's Arweave wallet, so the stronger guarantee
// is worth the D1 round-trip.
//
// Reads use the KV-backed counter in rate-limit.js. The failure mode of the
// read TOCTOU race is "slightly more reads than the cap during a burst,"
// which is acceptable for read throttling — reads are cheap and don't drain
// money. Both call sites fail open on store outage.

import { checkAndIncrementRateLimit } from './rate-limit.js';

const MAX_WRITES_PER_HOUR = 100;

// Authenticated reads are keyed on data_lookup_key (mirrors the write path).
// Originally read limits were per-IP, which caused noisy-neighbor failures on
// shared NAT (one user — or one bad client — could lock out everyone behind
// the same WiFi). Per-account keying gives every authenticated user their own
// bucket, independent of network topology.
//
// Reads happen in bursts during sync (delta-poll + per-entry blob fetch) so a
// higher value than the 100/hr write limit is appropriate. Raised from the
// tarn#31 starting point of 1000 to 3000 to accommodate cold-bootstrap: on a
// fresh device the SDK pulls a library's full live state via the bulk path —
// one blob read per live entry, routed through THIS per-account bucket (the
// fan-out passes `key`). A ~500-entry library is ~500 reads in one burst, and
// a user may resync a few times within the hour (cleared cache during testing,
// multiple tabs), so 3000 leaves comfortable headroom. Reads are cheap and
// don't drain the Arweave wallet, so the ceiling is generous by design.
const MAX_READS_PER_HOUR_PER_ACCOUNT = 3000;

// Unauthenticated read fallback (handleEntryById with no `key` param). Same
// numeric cap as the per-account limit — the cap shape is "N reads/hour per
// identifier"; the identifier is dlk when we have one, IP-hash otherwise.
const MAX_READS_PER_HOUR_PER_IP = 3000;

export async function checkWriteRateLimit(env, dataLookupKey) {
  const hour = new Date().toISOString().slice(0, 13); // YYYY-MM-DDTHH
  const key = `write:${dataLookupKey}:${hour}`;
  const expiresAt = Date.now() + 3600_000;

  // Atomic increment: INSERT or UPDATE count in one statement
  const result = await env.DB.prepare(`
    INSERT INTO write_rate_limits (key, count, expires_at)
    VALUES (?1, 1, ?2)
    ON CONFLICT(key) DO UPDATE SET count = count + 1
    RETURNING count
  `).bind(key, expiresAt).first();

  const count = result?.count ?? 1;

  if (count > MAX_WRITES_PER_HOUR) {
    return { allowed: false, remaining: 0 };
  }

  // Opportunistic cleanup of expired rows (non-blocking, best-effort)
  if (Math.random() < 0.05) { // 5% of requests trigger cleanup
    env.DB.prepare('DELETE FROM write_rate_limits WHERE expires_at < ?1')
      .bind(Date.now()).run().catch(() => {});
  }

  return { allowed: true, remaining: MAX_WRITES_PER_HOUR - count };
}

/**
 * Per-account read rate limit. Used by every entry-read endpoint that has an
 * authenticated identity available (i.e. the URL's `key` query param is
 * required, or a JWT is required). Bucket key mirrors the write path:
 * `read:<data_lookup_key>:<hour>`.
 *
 * @param {Env} env
 * @param {string} dataLookupKey
 * @returns {Promise<{allowed: boolean, remaining: number}>}
 */
export async function checkReadRateLimitByAccount(env, dataLookupKey) {
  const hour = new Date().toISOString().slice(0, 13);
  const key = `read:${dataLookupKey}:${hour}`;
  const { allowed, count } = await checkAndIncrementRateLimit(
    env.RATE_KV, key, MAX_READS_PER_HOUR_PER_ACCOUNT,
  );
  return { allowed, remaining: Math.max(0, MAX_READS_PER_HOUR_PER_ACCOUNT - count) };
}

/**
 * Per-IP read rate limit. Only used by deliberately unauthenticated read
 * paths — currently just `GET /api/v1/entries/{txid}` when called without a
 * `key` query param (the "txid-only metadata lookup" case, which is allowed
 * because entry tags are already public on Arweave). Every authenticated read
 * path should use `checkReadRateLimitByAccount` instead.
 *
 * @param {Env} env
 * @param {Request} request
 * @returns {Promise<{allowed: boolean, remaining: number}>}
 */
export async function checkReadRateLimitByIp(env, request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const data = new TextEncoder().encode(ip + '-tarn-read-salt');
  const hash = await crypto.subtle.digest('SHA-256', data);
  const ipHash = Array.from(new Uint8Array(hash)).slice(0, 8)
    .map(b => b.toString(16).padStart(2, '0')).join('');
  const hour = new Date().toISOString().slice(0, 13);
  const key = `read-ip:${ipHash}:${hour}`;
  const { allowed, count } = await checkAndIncrementRateLimit(
    env.RATE_KV, key, MAX_READS_PER_HOUR_PER_IP,
  );
  return { allowed, remaining: Math.max(0, MAX_READS_PER_HOUR_PER_IP - count) };
}

// Re-exported for tests + any future caller that wants to assert the numeric
// caps without importing the constants twice.
export const _testing = {
  MAX_WRITES_PER_HOUR,
  MAX_READS_PER_HOUR_PER_ACCOUNT,
  MAX_READS_PER_HOUR_PER_IP,
};
