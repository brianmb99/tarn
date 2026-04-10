// Tarn Client Crypto — key derivation, encryption, signing
// Pure WebCrypto — works in browsers and Node.js 15+.
// This is the client-side counterpart to api/src/crypto.js.

// ============ CONSTANTS ============

const PBKDF2_ITERATIONS = 600000;
const PBKDF2_HASH = 'SHA-256';
const KEY_LENGTH_BITS = 256;

const CREDENTIAL_LOOKUP_DOMAIN = 'tarn-credential-lookup-v1';
const CREDENTIAL_ENCRYPT_DOMAIN = 'tarn-credential-encrypt-v1';
const SIGNING_DOMAIN = 'tarn-signing-v1';

// PKCS#8 DER template for P-256 private key (without public key section)
// 73 bytes total: 41 fixed bytes + 32 variable (private key d)
const PKCS8_P256_PREFIX = new Uint8Array([
  0x30, 0x41, // SEQUENCE, 65 bytes
  0x02, 0x01, 0x00, // INTEGER 0 (version)
  0x30, 0x13, // SEQUENCE, 19 bytes
  0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID prime256v1
  0x04, 0x27, // OCTET STRING, 39 bytes
  0x30, 0x25, // SEQUENCE, 37 bytes
  0x02, 0x01, 0x01, // INTEGER 1 (version)
  0x04, 0x20, // OCTET STRING, 32 bytes
  // ... 32 bytes of private key d follow
]);

// ============ EMAIL NORMALIZATION ============

/**
 * Normalize email for consistent key derivation.
 * @param {string} email
 * @returns {string}
 */
export function normalizeEmail(email) {
  if (!email || typeof email !== 'string') throw new Error('Email is required');
  return email.trim().toLowerCase();
}

// ============ KEY DERIVATION ============

/**
 * Derive master_key from email + password via PBKDF2-SHA256.
 * @param {string} email - User email (will be normalized)
 * @param {string} password - User password
 * @returns {Promise<Uint8Array>} 32-byte master key
 */
export async function deriveMasterKey(email, password) {
  if (!email || !password) throw new Error('Email and password are required');

  const normalizedEmail = normalizeEmail(email);
  const encoder = new TextEncoder();

  // Salt = SHA-256(normalizedEmail + domain)
  const saltInput = encoder.encode(normalizedEmail + CREDENTIAL_LOOKUP_DOMAIN);
  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', saltInput));

  // Import password as PBKDF2 key material
  const passwordKey = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
  );

  // Derive master key
  const masterKeyBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: PBKDF2_HASH },
    passwordKey,
    KEY_LENGTH_BITS
  );

  return new Uint8Array(masterKeyBits);
}

/**
 * Derive credential_lookup_key from master_key.
 * @param {Uint8Array} masterKey
 * @returns {Promise<string>} 64-char hex string
 */
export async function deriveCredentialLookupKey(masterKey) {
  const input = concatBytes(masterKey, new TextEncoder().encode(CREDENTIAL_LOOKUP_DOMAIN));
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  return bytesToHex(hash);
}

/**
 * Derive credential_encryption_key from master_key.
 * This is also the initial data_encryption_key at account creation.
 * @param {Uint8Array} masterKey
 * @returns {Promise<CryptoKey>} AES-256-GCM key
 */
export async function deriveCredentialEncryptionKey(masterKey) {
  const input = concatBytes(masterKey, new TextEncoder().encode(CREDENTIAL_ENCRYPT_DOMAIN));
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  return await crypto.subtle.importKey(
    'raw', hash, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']
  );
}

/**
 * Derive ECDSA P-256 signing key pair from master_key.
 * Deterministic: same master_key always produces the same key pair.
 * @param {Uint8Array} masterKey
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>}
 */
export async function deriveSigningKeyPair(masterKey) {
  const input = concatBytes(masterKey, new TextEncoder().encode(SIGNING_DOMAIN));
  const seed = new Uint8Array(await crypto.subtle.digest('SHA-256', input));

  // Build PKCS#8 DER: prefix + 32 bytes of seed
  const pkcs8 = new Uint8Array(PKCS8_P256_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_P256_PREFIX, 0);
  pkcs8.set(seed, PKCS8_P256_PREFIX.length);

  // Import as ECDSA P-256 private key
  const privateKey = await crypto.subtle.importKey(
    'pkcs8', pkcs8,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // extractable (needed to derive public key)
    ['sign']
  );

  // Export as JWK to get the public key components, then re-import as public key
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  delete jwk.d; // Remove private component
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
 * Export public key to base64-encoded SPKI format (for sending to API).
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>} Base64 SPKI
 */
export async function exportPublicKey(publicKey) {
  const der = await crypto.subtle.exportKey('spki', publicKey);
  return bytesToBase64(new Uint8Array(der));
}

// ============ AES-256-GCM ENCRYPTION ============

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
    { name: 'AES-GCM', iv },
    key,
    data
  ));

  // Wire format: IV || ciphertext (includes 16-byte GCM tag appended by WebCrypto)
  const result = new Uint8Array(iv.length + ciphertext.length);
  result.set(iv, 0);
  result.set(ciphertext, iv.length);
  return result;
}

/**
 * Decrypt AES-256-GCM encrypted bytes to JSON.
 * @param {CryptoKey} key - AES-256-GCM key
 * @param {Uint8Array} blob - Wire format: IV(12) || ciphertext+tag
 * @returns {Promise<Object>} Decrypted JSON object
 */
export async function decrypt(key, blob) {
  if (blob.length < 13) throw new Error('Blob too short');

  const iv = blob.slice(0, 12);
  const ciphertext = blob.slice(12);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );

  return JSON.parse(new TextDecoder().decode(decrypted));
}

// ============ WRAPPED DATA KEY ============

/**
 * Wrap (encrypt) a data encryption key with a credential encryption key.
 * At registration: key wraps itself (redundant self-encryption).
 * After credential change: old key wrapped with new key.
 * @param {CryptoKey} dataKey - The key to wrap (data_encryption_key)
 * @param {CryptoKey} wrappingKey - The key to wrap with (credential_encryption_key)
 * @returns {Promise<string>} Base64-encoded wrapped key
 */
export async function wrapDataKey(dataKey, wrappingKey) {
  // Export data key as raw bytes, then encrypt with wrapping key
  const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', dataKey));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    rawKey
  ));

  // Wire format: IV || ciphertext+tag
  const wrapped = new Uint8Array(iv.length + ciphertext.length);
  wrapped.set(iv, 0);
  wrapped.set(ciphertext, iv.length);

  return bytesToBase64(wrapped);
}

/**
 * Unwrap (decrypt) a wrapped data key.
 * @param {string} wrappedBase64 - Base64-encoded wrapped key
 * @param {CryptoKey} unwrappingKey - credential_encryption_key
 * @returns {Promise<CryptoKey>} Unwrapped AES-256-GCM data encryption key
 */
export async function unwrapDataKey(wrappedBase64, unwrappingKey) {
  const wrapped = base64ToBytes(wrappedBase64);
  if (wrapped.length < 13) throw new Error('Wrapped key too short');

  const iv = wrapped.slice(0, 12);
  const ciphertext = wrapped.slice(12);

  const rawKey = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    unwrappingKey,
    ciphertext
  ));

  return await crypto.subtle.importKey(
    'raw', rawKey, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']
  );
}

// ============ CHALLENGE SIGNING ============

/**
 * Sign a nonce (challenge) with the ECDSA P-256 private key.
 * @param {CryptoKey} privateKey - P-256 private key
 * @param {string} nonceHex - 64-char hex nonce from the API
 * @returns {Promise<string>} Base64-encoded raw ECDSA signature (64 bytes: r||s)
 */
export async function signChallenge(privateKey, nonceHex) {
  const nonceBytes = hexToBytes(nonceHex);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    nonceBytes
  );
  return bytesToBase64(new Uint8Array(signature));
}

// ============ CONVENIENCE: DERIVE ALL KEYS ============

/**
 * Derive all keys from email + password in one call.
 * @param {string} email
 * @param {string} password
 * @returns {Promise<{
 *   masterKey: Uint8Array,
 *   credentialLookupKey: string,
 *   credentialEncryptionKey: CryptoKey,
 *   signingKeyPair: {privateKey: CryptoKey, publicKey: CryptoKey}
 * }>}
 */
export async function deriveAllKeys(email, password) {
  const masterKey = await deriveMasterKey(email, password);
  const [credentialLookupKey, credentialEncryptionKey, signingKeyPair] = await Promise.all([
    deriveCredentialLookupKey(masterKey),
    deriveCredentialEncryptionKey(masterKey),
    deriveSigningKeyPair(masterKey),
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

export function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

export function base64ToBytes(base64) {
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
