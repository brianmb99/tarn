// Write rate limiting: 100 writes per hour per data_lookup_key
// Uses D1 atomic INSERT ... ON CONFLICT for write limits (wallet-draining defense).
// The KV-based TOCTOU race (get-then-put) allowed concurrent requests to exceed limits.
// D1's single-statement atomicity prevents this.

const MAX_WRITES_PER_HOUR = 100;

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
