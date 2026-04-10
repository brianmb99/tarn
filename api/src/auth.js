// Auth primitives: JWT, challenge/nonce management
// Uses WebCrypto HMAC-SHA256 for JWT (zero deps).
// P-256 signature verification is in crypto.js (separate module).

const JWT_TTL_SECONDS = 900; // 15 minutes
const NONCE_TTL_SECONDS = 300; // 5 minutes

export { JWT_TTL_SECONDS, NONCE_TTL_SECONDS };

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
 * Store a nonce in AUTH_KV, scoped to a credential_lookup_key.
 * Nonces are single-use and expire after NONCE_TTL_SECONDS.
 * @param {Object} env - Worker environment (needs AUTH_KV binding)
 * @param {string} nonce - The nonce to store
 * @param {string} credentialLookupKey - The credential_lookup_key this nonce is for
 */
export async function storeNonce(env, nonce, credentialLookupKey) {
  await env.AUTH_KV.put(
    `nonce:${nonce}`,
    JSON.stringify({ credentialLookupKey, createdAt: Date.now() }),
    { expirationTtl: NONCE_TTL_SECONDS }
  );
}

/**
 * Consume a nonce (single-use). Returns stored data or null.
 * Deletes the nonce from KV immediately to prevent replay.
 * @param {Object} env - Worker environment
 * @param {string} nonce - The nonce to consume
 * @returns {Promise<{credentialLookupKey: string, createdAt: number}|null>}
 */
export async function consumeNonce(env, nonce) {
  const key = `nonce:${nonce}`;
  const raw = await env.AUTH_KV.get(key);
  if (!raw) return null;
  // Single-use: delete immediately
  await env.AUTH_KV.delete(key);
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// ============ JWT (WebCrypto HMAC-SHA256) ============

let _hmacKey = null;

async function getHMACKey(secret) {
  if (_hmacKey) return _hmacKey;
  const keyData = Uint8Array.from(atob(secret), c => c.charCodeAt(0));
  _hmacKey = await crypto.subtle.importKey(
    'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );
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
 * @returns {Promise<string>} Signed JWT
 */
export async function signJWT(payload, secret) {
  const key = await getHMACKey(secret);
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const now = Math.floor(Date.now() / 1000);
  const body = base64url(JSON.stringify({
    ...payload,
    iat: now,
    exp: now + JWT_TTL_SECONDS,
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
}
