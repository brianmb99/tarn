// Auth primitives: JWT, challenge/nonce management
// Uses WebCrypto HMAC-SHA256 for JWT (zero deps).
// P-256 signature verification is in crypto.js (separate module).

const JWT_TTL_SECONDS = 900; // 15 minutes
const NONCE_TTL_SECONDS = 300; // 5 minutes

// Passkey-authenticated JWTs live for the full session-blob lifetime (7 days)
// because the SDK has no refresh path for passkey-only sessions: it can't
// re-sign a challenge without #signingKeyPair, which is null when the user
// signed in via passkey. Matching the JWT lifetime to the session-blob TTL
// closes the gap the SDK's existing "exp > now + 30s" early-return covers.
//
// The session-blob TTL (`now + 7 * 24 * 60 * 60`) is defined client-side in
// client/src/tarn.ts → serializeSession(). Keep these in sync. See issue #28.
const PASSKEY_JWT_TTL_SECONDS = 7 * 24 * 3600; // 7 days

export { JWT_TTL_SECONDS, NONCE_TTL_SECONDS, PASSKEY_JWT_TTL_SECONDS };

// ============ CHALLENGE / NONCE ============

/**
 * Generate a challenge nonce for P-256 signing.
 * The client signs the raw nonce bytes with their private key.
 * @returns {string} 64-character hex nonce
 */
export function generateChallenge() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Store a nonce in D1 (auth_nonces table), scoped to a credential_lookup_key.
 * Nonces are single-use and expire after NONCE_TTL_SECONDS.
 *
 * Migrated from AUTH_KV in migration 0012 — KV hit the free-tier daily put
 * limit during testing-heavy days, taking down the entire auth flow. D1 has
 * no equivalent cap for a workload of this size.
 *
 * @param {Object} env - Worker environment (needs DB binding)
 * @param {string} nonce - The nonce to store
 * @param {string} credentialLookupKey - The credential_lookup_key this nonce is for
 */
export async function storeNonce(env, nonce, credentialLookupKey) {
  const now = Date.now();
  const expiresAt = now + NONCE_TTL_SECONDS * 1000;
  await env.DB.prepare(
    'INSERT INTO auth_nonces (nonce, credential_lookup_key, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)'
  ).bind(nonce, credentialLookupKey, now, expiresAt).run();
}

/**
 * Consume a nonce (single-use). Returns stored data or null.
 *
 * Atomic-ish via D1's DELETE...RETURNING: the nonce row is removed on first
 * read, so a concurrent second read can't replay it. Expired rows return
 * null (lazy pruning — the SELECT side filters by expires_at, and the
 * deleted row goes away in the same statement).
 *
 * @param {Object} env - Worker environment
 * @param {string} nonce - The nonce to consume
 * @returns {Promise<{credentialLookupKey: string, createdAt: number}|null>}
 */
export async function consumeNonce(env, nonce) {
  const now = Date.now();
  const row = await env.DB.prepare(
    'DELETE FROM auth_nonces WHERE nonce = ?1 RETURNING credential_lookup_key, created_at, expires_at'
  ).bind(nonce).first();
  if (!row) return null;
  if (row.expires_at < now) return null;
  return { credentialLookupKey: row.credential_lookup_key, createdAt: row.created_at };
}

// ============ JWT (WebCrypto HMAC-SHA256) ============

let _hmacKey = null;
let _cachedSecret = null;

async function getHMACKey(secret) {
  if (_hmacKey && _cachedSecret === secret) return _hmacKey;
  const keyData = Uint8Array.from(atob(secret), c => c.charCodeAt(0));
  _hmacKey = await crypto.subtle.importKey(
    'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );
  _cachedSecret = secret;
  return _hmacKey;
}

function base64url(data) {
  if (typeof data === 'string') {
    return btoa(data).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  }
  // ArrayBuffer
  return btoa(String.fromCharCode(...new Uint8Array(data)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64urlDecode(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - str.length % 4) % 4);
  return atob(padded);
}

/**
 * Sign a JWT with HMAC-SHA256.
 * @param {Object} payload - JWT claims (sub, role, data_lookup_key, etc.)
 * @param {string} secret - Base64-encoded HMAC secret
 * @param {number} [ttlSeconds] - Optional override for token lifetime in
 *   seconds. Defaults to JWT_TTL_SECONDS (15 minutes). Passkey-authenticated
 *   tokens override this to PASSKEY_JWT_TTL_SECONDS (7 days) so they match
 *   the session-blob lifetime (issue #28).
 * @returns {Promise<string>} Signed JWT
 */
export async function signJWT(payload, secret, ttlSeconds = JWT_TTL_SECONDS) {
  const key = await getHMACKey(secret);
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const now = Math.floor(Date.now() / 1000);
  const body = base64url(JSON.stringify({
    ...payload,
    iat: now,
    exp: now + ttlSeconds,
  }));
  const sigInput = new TextEncoder().encode(`${header}.${body}`);
  const sig = await crypto.subtle.sign('HMAC', key, sigInput);
  return `${header}.${body}.${base64url(sig)}`;
}

/**
 * Verify a JWT and return its payload, or null if invalid/expired.
 * @param {string} token - JWT string
 * @param {string} secret - Base64-encoded HMAC secret
 * @returns {Promise<Object|null>} Decoded payload or null
 */
export async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const key = await getHMACKey(secret);
  const sigInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const signature = Uint8Array.from(base64urlDecode(parts[2]), c => c.charCodeAt(0));

  const valid = await crypto.subtle.verify('HMAC', key, signature, sigInput);
  if (!valid) return null;

  try {
    const payload = JSON.parse(base64urlDecode(parts[1]));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

/**
 * Clear cached HMAC key (for testing).
 */
export function _resetHMACKey() {
  _hmacKey = null;
  _cachedSecret = null;
}
