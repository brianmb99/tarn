// Tarn Client Crypto — key derivation, encryption, signing
// Pure WebCrypto — works in browsers and Node.js 15+.
//
// Key derivation uses HKDF-Expand (RFC 5869) with structured info strings.
// Key wrapping uses AES-KW (RFC 3394).
// All sub-keys include app_id for per-app isolation.

// ============ CONSTANTS ============

const PBKDF2_ITERATIONS = 600000;
const PBKDF2_HASH = 'SHA-256';
const KEY_LENGTH_BITS = 256;

// Structured HKDF info: protocol || purpose || app_id || version || counter
const PROTOCOL_ID = 'tarn';
const DERIVATION_VERSION = '1';
const HKDF_COUNTER = new Uint8Array([0x01]); // Single-block HKDF-Expand

// P-256 curve order (n) — for private key range validation
// n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
const P256_ORDER = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');

// PKCS#8 DER template for P-256 private key (without public key section)
const PKCS8_P256_PREFIX = new Uint8Array([
  0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13,
  0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
  0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
]);

// ============ EMAIL NORMALIZATION ============

export function normalizeEmail(email) {
  if (!email || typeof email !== 'string') throw new Error('Email is required');
  return email.trim().toLowerCase();
}

// ============ HKDF-EXPAND (RFC 5869) ============

/**
 * HKDF-Expand with a single 32-byte output block.
 * This is equivalent to: HMAC-SHA256(prk, info || 0x01)
 *
 * @param {Uint8Array} prk - Pseudorandom key (master_key)
 * @param {string} purpose - Key purpose: "lookup", "encrypt", or "sign"
 * @param {string} appId - App identifier
 * @param {number} [counter=1] - HKDF counter (for P-256 retry)
 * @returns {Promise<Uint8Array>} 32-byte derived key
 */
async function hkdfExpand(prk, purpose, appId, counter = 1) {
  const encoder = new TextEncoder();

  // Import master_key as HMAC key
  const hmacKey = await crypto.subtle.importKey(
    'raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );

  // info = protocol || purpose || app_id || version || counter_byte
  const info = concatBytes(
    encoder.encode(PROTOCOL_ID + purpose + appId + DERIVATION_VERSION),
    new Uint8Array([counter])
  );

  const result = await crypto.subtle.sign('HMAC', hmacKey, info);
  return new Uint8Array(result);
}

// ============ KEY DERIVATION ============

/**
 * Derive master_key from email + password via PBKDF2-SHA256.
 * The master_key is app-independent — app isolation happens in sub-key derivation.
 * @param {string} email
 * @param {string} password
 * @returns {Promise<Uint8Array>} 32-byte master key
 */
export async function deriveMasterKey(email, password) {
  if (!email || !password) throw new Error('Email and password are required');

  const normalizedEmail = normalizeEmail(email);
  const encoder = new TextEncoder();

  // Salt = SHA-256(normalizedEmail)
  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(normalizedEmail)));

  const passwordKey = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
  );

  const masterKeyBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: PBKDF2_HASH },
    passwordKey,
    KEY_LENGTH_BITS
  );

  return new Uint8Array(masterKeyBits);
}

/**
 * Derive credential_lookup_key from master_key for a specific app.
 * @param {Uint8Array} masterKey
 * @param {string} appId - Registered app identifier
 * @returns {Promise<string>} 64-char hex string
 */
export async function deriveCredentialLookupKey(masterKey, appId) {
  if (!appId) throw new Error('appId is required');
  const hash = await hkdfExpand(masterKey, 'lookup', appId);
  return bytesToHex(hash);
}

/**
 * Derive credential encryption key material from master_key for a specific app.
 * Returns both an AES-GCM key (for data encryption) and an AES-KW key (for key wrapping).
 * Both are derived from the same raw bytes — same key, different WebCrypto usages.
 * @param {Uint8Array} masterKey
 * @param {string} appId
 * @returns {Promise<{gcmKey: CryptoKey, kwKey: CryptoKey, rawBytes: Uint8Array}>}
 */
export async function deriveCredentialEncryptionKey(masterKey, appId) {
  if (!appId) throw new Error('appId is required');
  const keyBytes = await hkdfExpand(masterKey, 'encrypt', appId);

  const [gcmKey, kwKey] = await Promise.all([
    crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', keyBytes, 'AES-KW', true, ['wrapKey', 'unwrapKey']),
  ]);

  return { gcmKey, kwKey, rawBytes: keyBytes };
}

/**
 * Derive ECDSA P-256 signing key pair from master_key for a specific app.
 * Deterministic: same master_key + appId always produces the same key pair.
 * Validates that the derived scalar is in [1, n-1] per P-256 spec.
 * @param {Uint8Array} masterKey
 * @param {string} appId
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>}
 */
export async function deriveSigningKeyPair(masterKey, appId) {
  if (!appId) throw new Error('appId is required');

  // Derive seed, validate P-256 range, retry with incrementing counter if needed
  let seed;
  for (let counter = 1; counter <= 3; counter++) {
    seed = await hkdfExpand(masterKey, 'sign', appId, counter);
    const scalar = bytesToBigInt(seed);
    if (scalar > 0n && scalar < P256_ORDER) break;
    if (counter === 3) throw new Error('Failed to derive valid P-256 private key (extremely unlikely)');
  }

  // Build PKCS#8 DER
  const pkcs8 = new Uint8Array(PKCS8_P256_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_P256_PREFIX, 0);
  pkcs8.set(seed, PKCS8_P256_PREFIX.length);

  const privateKey = await crypto.subtle.importKey(
    'pkcs8', pkcs8,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign']
  );

  // Derive public key from private key via JWK round-trip
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  delete jwk.d;
  jwk.key_ops = ['verify'];

  const publicKey = await crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );

  return { privateKey, publicKey };
}

/**
 * Export public key to base64-encoded SPKI format.
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>}
 */
export async function exportPublicKey(publicKey) {
  const der = await crypto.subtle.exportKey('spki', publicKey);
  return bytesToBase64(new Uint8Array(der));
}

// ============ AES-256-GCM ENCRYPTION (data blobs) ============

/**
 * Encrypt JSON payload with AES-256-GCM.
 * @param {CryptoKey} key - AES-256-GCM key
 * @param {Object} plaintext - JSON-serializable object
 * @returns {Promise<Uint8Array>} Wire format: IV(12) || ciphertext+tag
 */
export async function encrypt(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(plaintext));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, data
  ));

  const result = new Uint8Array(iv.length + ciphertext.length);
  result.set(iv, 0);
  result.set(ciphertext, iv.length);
  return result;
}

/**
 * Decrypt AES-256-GCM encrypted bytes to JSON.
 * @param {CryptoKey} key - AES-256-GCM key
 * @param {Uint8Array} blob - Wire format: IV(12) || ciphertext+tag
 * @returns {Promise<Object>}
 */
export async function decrypt(key, blob) {
  if (blob.length < 13) throw new Error('Blob too short');
  const iv = blob.slice(0, 12);
  const ciphertext = blob.slice(12);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(decrypted));
}

// ============ AES-KW KEY WRAPPING (RFC 3394) ============

/**
 * Wrap data_encryption_key using AES-KW.
 * At registration: self-wrap (key wraps itself).
 * After credential change: old key wrapped with new key.
 * @param {CryptoKey} dataKey - Key to wrap
 * @param {CryptoKey} wrappingKey - Key to wrap with (credential_encryption_key)
 * @returns {Promise<string>} Base64-encoded AES-KW ciphertext (40 bytes: 32 key + 8 overhead)
 */
export async function wrapDataKey(dataKey, wrappingKey) {
  const wrapped = await crypto.subtle.wrapKey('raw', dataKey, wrappingKey, 'AES-KW');
  return bytesToBase64(new Uint8Array(wrapped));
}

/**
 * Unwrap data_encryption_key using AES-KW.
 * @param {string} wrappedBase64 - Base64-encoded AES-KW ciphertext
 * @param {CryptoKey} unwrappingKey - credential_encryption_key
 * @returns {Promise<CryptoKey>} Unwrapped AES-256-GCM data encryption key
 */
export async function unwrapDataKey(wrappedBase64, unwrappingKey) {
  const wrapped = base64ToBytes(wrappedBase64);
  return await crypto.subtle.unwrapKey(
    'raw', wrapped, unwrappingKey, 'AES-KW',
    { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']
  );
}

// ============ CHALLENGE SIGNING ============

/**
 * Sign a nonce with the ECDSA P-256 private key.
 * @param {CryptoKey} privateKey
 * @param {string} nonceHex - 64-char hex nonce
 * @returns {Promise<string>} Base64-encoded raw ECDSA signature (64 bytes: r||s)
 */
export async function signChallenge(privateKey, nonceHex) {
  const nonceBytes = hexToBytes(nonceHex);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, privateKey, nonceBytes
  );
  return bytesToBase64(new Uint8Array(signature));
}

// ============ CONVENIENCE: DERIVE ALL KEYS ============

/**
 * Derive all keys from email + password + app in one call.
 * @param {string} email
 * @param {string} password
 * @param {string} appId - Registered app identifier
 * @returns {Promise<{masterKey, credentialLookupKey, credentialEncryptionKey: {gcmKey, kwKey, rawBytes}, signingKeyPair}>}
 */
export async function deriveAllKeys(email, password, appId) {
  if (!appId) throw new Error('appId is required');
  const masterKey = await deriveMasterKey(email, password);
  const [credentialLookupKey, credentialEncryptionKey, signingKeyPair] = await Promise.all([
    deriveCredentialLookupKey(masterKey, appId),
    deriveCredentialEncryptionKey(masterKey, appId),
    deriveSigningKeyPair(masterKey, appId),
  ]);
  return { masterKey, credentialLookupKey, credentialEncryptionKey, signingKeyPair };
}

// ============ ENCODING HELPERS ============

function concatBytes(a, b) {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}

function bytesToBigInt(bytes) {
  let result = 0n;
  for (const b of bytes) result = (result << 8n) | BigInt(b);
  return result;
}

export function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

export function base64ToBytes(base64) {
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
