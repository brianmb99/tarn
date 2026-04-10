// Write rate limiting: 100 writes per hour per wallet address

const MAX_WRITES_PER_HOUR = 100;

export async function checkWriteRateLimit(env, walletAddr) {
  const hour = new Date().toISOString().slice(0, 13); // YYYY-MM-DDTHH
  const key = `write:${walletAddr.toLowerCase()}:${hour}`;
  const count = parseInt(await env.RATE_KV.get(key) || '0');
  if (count >= MAX_WRITES_PER_HOUR) {
    return { allowed: false, remaining: 0 };
  }
  await env.RATE_KV.put(key, String(count + 1), { expirationTtl: 3600 });
  return { allowed: true, remaining: MAX_WRITES_PER_HOUR - count - 1 };
}
