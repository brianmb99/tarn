// crypto.js — ECDSA P-256 primitives for Tarn API auth
// Pure WebCrypto — no external dependencies.
// Used server-side (Cloudflare Workers) for signature verification.

const P256_ALGO = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_ALGO = { name: 'ECDSA', hash: 'SHA-256' };

// ============ PUBLIC KEY IMPORT / EXPORT ============

/**
 * Import a base64-encoded SPKI public key as a CryptoKey for verification.
 * @param {string} base64Spki - Base64-encoded SubjectPublicKeyInfo (DER)
 * @returns {Promise<CryptoKey>}
 * @throws {Error} if import fails (invalid format, wrong algorithm)
 */
export async function importPublicKey(base64Spki) {
  if (!base64Spki || typeof base64Spki !== 'string') {
    throw new Error('Public key is required (base64 SPKI string)');
  }
  const der = base64ToBytes(base64Spki);
  return await crypto.subtle.importKey('spki', der, P256_ALGO, true, ['verify']);
}

/**
 * Export a CryptoKey to base64-encoded SPKI format.
 * @param {CryptoKey} key - P-256 public key
 * @returns {Promise<string>} Base64-encoded SPKI
 */
export async function exportPublicKey(key) {
  const der = await crypto.subtle.exportKey('spki', key);
  return bytesToBase64(new Uint8Array(der));
}

// ============ SIGNATURE VERIFICATION ============

/**
 * Verify an ECDSA P-256 signature against a nonce.
 * @param {CryptoKey} publicKey - Imported P-256 public key
 * @param {string} nonceHex - The nonce that was signed (64-char hex)
 * @param {string} signatureBase64 - Base64-encoded raw signature (64 bytes: r || s)
 * @returns {Promise<boolean>} True if signature is valid
 */
export async function verifySignature(publicKey, nonceHex, signatureBase64) {
  try {
    const nonceBytes = hexToBytes(nonceHex);
    const sigBytes = base64ToBytes(signatureBase64);

    // P-256 raw signature is exactly 64 bytes (r: 32, s: 32)
    if (sigBytes.length !== 64) return false;

    return await crypto.subtle.verify(SIGN_ALGO, publicKey, sigBytes, nonceBytes);
  } catch {
    return false;
  }
}

// ============ NONCE GENERATION ============

/**
 * Generate a random nonce for challenge-response auth.
 * @returns {string} 64-character hex string (32 random bytes)
 */
export function generateNonce() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============ VALIDATION ============

/**
 * Validate that a string is a 64-character hex string (lookup key format).
 * @param {string} value
 * @returns {boolean}
 */
export function isValidHex64(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

// ============ ENCODING HELPERS ============

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function base64ToBytes(base64) {
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}
