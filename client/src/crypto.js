// Tarn Client Crypto — key derivation, encryption, signing
// WebCrypto for everything except the password→master_key KDF.
// The KDF uses Argon2id (via hash-wasm) for new accounts; legacy accounts
// continue to use PBKDF2-SHA256 for backward compatibility.
//
// Key derivation uses HKDF-Expand (RFC 5869) with structured info strings.
// Key wrapping uses AES-KW (RFC 3394).
// All sub-keys include app_id for per-app isolation.
//
// Works in browsers and Node.js 15+ (WebAssembly required for Argon2id).

import { argon2id as argon2idHash } from 'hash-wasm';

// ============ CONSTANTS ============

// KDF versions for the master_key derivation step.
// v1 — PBKDF2-SHA256, 600k iterations (legacy, accounts created before Argon2id rollout).
// v2 — Argon2id, m=64 MiB, t=3, p=1 (current default for new accounts).
//
// Argon2id parameters chosen to keep login latency near ~200ms on a recent
// laptop, ~1–1.5s on a 3-year-old phone — well under the ~2s acceptance bar.
// Memory-hard params neutralize GPU/ASIC parallelism on a leaked Arweave
// credential blob, in line with the OWASP Argon2id recommendation.
export const KDF_V1_PBKDF2 = 1;
export const KDF_V2_ARGON2ID = 2;
export const KDF_DEFAULT = KDF_V2_ARGON2ID;

const PBKDF2_ITERATIONS = 600000;
const PBKDF2_HASH = 'SHA-256';

const ARGON2ID_MEMORY_KIB = 64 * 1024; // 64 MiB
const ARGON2ID_ITERATIONS = 3;
const ARGON2ID_PARALLELISM = 1;

const KEY_LENGTH_BITS = 256;
const KEY_LENGTH_BYTES = 32;

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
 * Derive master_key from email + password.
 * The master_key is app-independent — app isolation happens in sub-key derivation.
 *
 * KDF dispatch:
 *   v2 (default) — Argon2id over UTF-8 password, salt = SHA-256(normalizedEmail)
 *   v1 (legacy)  — PBKDF2-SHA256 600k iters, same salt
 *
 * Both KDFs use SHA-256(normalizedEmail) as the salt so an account's salt is
 * stable across logins regardless of which KDF was originally used.
 *
 * @param {string} email
 * @param {string} password
 * @param {number} [kdfVersion=KDF_DEFAULT] — KDF_V1_PBKDF2 or KDF_V2_ARGON2ID
 * @returns {Promise<Uint8Array>} 32-byte master key
 */
export async function deriveMasterKey(email, password, kdfVersion = KDF_DEFAULT) {
  if (!email || !password) throw new Error('Email and password are required');

  const normalizedEmail = normalizeEmail(email);
  const encoder = new TextEncoder();

  // Salt = SHA-256(normalizedEmail) — same for both KDFs.
  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(normalizedEmail)));

  if (kdfVersion === KDF_V2_ARGON2ID) {
    const out = await argon2idHash({
      password: encoder.encode(password),
      salt,
      parallelism: ARGON2ID_PARALLELISM,
      iterations: ARGON2ID_ITERATIONS,
      memorySize: ARGON2ID_MEMORY_KIB,
      hashLength: KEY_LENGTH_BYTES,
      outputType: 'binary',
    });
    return out instanceof Uint8Array ? out : new Uint8Array(out);
  }

  if (kdfVersion === KDF_V1_PBKDF2) {
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

  throw new Error(`Unknown KDF version: ${kdfVersion}`);
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
 * Wrap data_encryption_key using AES-KW (raw bytes only — no envelope metadata).
 * Use {@link wrapDataKeyEnvelope} for the wire format that includes KDF version.
 * @param {CryptoKey} dataKey - Key to wrap
 * @param {CryptoKey} wrappingKey - Key to wrap with (credential_encryption_key)
 * @returns {Promise<string>} Base64-encoded AES-KW ciphertext (40 bytes: 32 key + 8 overhead)
 */
export async function wrapDataKey(dataKey, wrappingKey) {
  const wrapped = await crypto.subtle.wrapKey('raw', dataKey, wrappingKey, 'AES-KW');
  return bytesToBase64(new Uint8Array(wrapped));
}

/**
 * Unwrap data_encryption_key from raw AES-KW ciphertext (no envelope handling).
 * Use {@link unwrapDataKeyEnvelope} for the wire format.
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

// ============ WRAPPED-DATA-KEY WIRE FORMAT (KDF-versioned envelope) ============
//
// The `wrapped_data_key` field stored on the API/Arweave is opaque to the
// server but carries a KDF version indicator so the client can verify which
// KDF was used at registration. The API column is plain TEXT; the Arweave
// credential mapping blob embeds the same string.
//
// v1 (legacy) — bare base64 of the AES-KW ciphertext. Implies PBKDF2 master_key.
// v2 (current) — JSON envelope: { v, kdf, kdf_params, wrapped }.
//
// Detection: if the string parses as JSON and has v >= 2, it's an envelope;
// otherwise it's legacy v1 (bare base64).

/**
 * Wrap the data encryption key and pack into the wire format for the given KDF.
 * @param {CryptoKey} dataKey
 * @param {CryptoKey} wrappingKey
 * @param {number} kdfVersion - KDF_V1_PBKDF2 or KDF_V2_ARGON2ID
 * @returns {Promise<string>} The `wrapped_data_key` value to send to the API
 */
export async function wrapDataKeyEnvelope(dataKey, wrappingKey, kdfVersion) {
  const wrappedBase64 = await wrapDataKey(dataKey, wrappingKey);

  if (kdfVersion === KDF_V1_PBKDF2) {
    return wrappedBase64;
  }

  if (kdfVersion === KDF_V2_ARGON2ID) {
    return JSON.stringify({
      v: 2,
      kdf: 'argon2id',
      kdf_params: { m_kib: ARGON2ID_MEMORY_KIB, t: ARGON2ID_ITERATIONS, p: ARGON2ID_PARALLELISM },
      wrapped: wrappedBase64,
    });
  }

  throw new Error(`Unknown KDF version: ${kdfVersion}`);
}

/**
 * Inspect a wire-format `wrapped_data_key` without unwrapping.
 * @param {string} wireValue
 * @returns {{ kdfVersion: number, wrappedBase64: string, kdfParams: object|null }}
 */
export function parseWrappedDataKey(wireValue) {
  if (typeof wireValue !== 'string' || wireValue.length === 0) {
    throw new Error('wrapped_data_key must be a non-empty string');
  }

  // v2+ envelopes are JSON objects starting with '{'. Bare base64 never starts
  // with '{' (base64 alphabet is [A-Za-z0-9+/=]), so this prefix check is
  // a safe, allocation-free dispatch before attempting JSON.parse.
  if (wireValue[0] !== '{') {
    return { kdfVersion: KDF_V1_PBKDF2, wrappedBase64: wireValue, kdfParams: null };
  }

  let parsed;
  try {
    parsed = JSON.parse(wireValue);
  } catch {
    throw new Error('wrapped_data_key looks like an envelope but is not valid JSON');
  }

  if (!parsed || typeof parsed !== 'object' || typeof parsed.wrapped !== 'string') {
    throw new Error('wrapped_data_key envelope is missing required fields');
  }

  if (parsed.v === 2 && parsed.kdf === 'argon2id') {
    return { kdfVersion: KDF_V2_ARGON2ID, wrappedBase64: parsed.wrapped, kdfParams: parsed.kdf_params || null };
  }

  throw new Error(`Unsupported wrapped_data_key envelope version: v=${parsed.v} kdf=${parsed.kdf}`);
}

/**
 * Unwrap the data encryption key from the wire format.
 * @param {string} wireValue
 * @param {CryptoKey} unwrappingKey
 * @returns {Promise<{ dataKey: CryptoKey, kdfVersion: number, kdfParams: object|null }>}
 */
export async function unwrapDataKeyEnvelope(wireValue, unwrappingKey) {
  const parsed = parseWrappedDataKey(wireValue);
  const dataKey = await unwrapDataKey(parsed.wrappedBase64, unwrappingKey);
  return { dataKey, kdfVersion: parsed.kdfVersion, kdfParams: parsed.kdfParams };
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
 * @param {number} [kdfVersion=KDF_DEFAULT] — KDF_V1_PBKDF2 or KDF_V2_ARGON2ID
 * @returns {Promise<{masterKey, credentialLookupKey, credentialEncryptionKey: {gcmKey, kwKey, rawBytes}, signingKeyPair, kdfVersion}>}
 */
export async function deriveAllKeys(email, password, appId, kdfVersion = KDF_DEFAULT) {
  if (!appId) throw new Error('appId is required');
  const masterKey = await deriveMasterKey(email, password, kdfVersion);
  const [credentialLookupKey, credentialEncryptionKey, signingKeyPair] = await Promise.all([
    deriveCredentialLookupKey(masterKey, appId),
    deriveCredentialEncryptionKey(masterKey, appId),
    deriveSigningKeyPair(masterKey, appId),
  ]);
  return { masterKey, credentialLookupKey, credentialEncryptionKey, signingKeyPair, kdfVersion };
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
