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

// Wrapping factors (issue #12). Each entry in a v4 dek_chain is wrapped under
// one or more factors; any factor's KEK independently unwraps the DEK.
//   PASSWORD        — derived from email+password via deriveCredentialEncryptionKey
//   RECOVERY_PHRASE — derived from BIP39 phrase via deriveRecoveryKey
export const FACTOR_PASSWORD = 'password';
export const FACTOR_RECOVERY_PHRASE = 'recovery_phrase';

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

// Recovery factor (issue #12): 16-byte random salt per account. Stored in the
// v4 envelope's `recovery.salt` field and used as the Argon2id salt for the
// recovery KEK. 128 bits is sufficient — the phrase itself is 256 bits of
// entropy, the salt's role is only to prevent cross-user precomputation.
const RECOVERY_SALT_LEN = 16;

// Per-content CEK pattern (issue #11):
// New content blobs are prefixed with a 5-byte magic so the format is
// unambiguously detectable without consulting tags.
//   magic = "TARN" || version_byte (0x02)
// Layout: magic(5) || wrapped_CEK(40) || iv(12) || ciphertext+tag(N+16).
// Generation indicator lives in the Arweave `Gen` tag — keeps the byte
// offsets stable so a recipient (Section 5 work) can skip bytes 5..44
// without parsing tags.
export const TARN_BLOB_MAGIC = new Uint8Array([0x54, 0x41, 0x52, 0x4e, 0x02]);
const WRAPPED_CEK_LEN = 40; // 32-byte CEK + 8-byte AES-KW overhead
const CEK_LEN_BYTES = 32;
const IV_LEN_BYTES = 12;
const GCM_TAG_LEN_BYTES = 16;
const MIN_NEW_FORMAT_LEN =
  TARN_BLOB_MAGIC.length + WRAPPED_CEK_LEN + IV_LEN_BYTES + GCM_TAG_LEN_BYTES;

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
 * Derive a recovery KEK from a BIP39 mnemonic phrase + per-account salt
 * (issue #12).
 *
 * The mnemonic is normalized via NFKD + lowercase + single-spaced, matching
 * the BIP39 spec for seed derivation. Argon2id is overkill against brute force
 * (24-word phrase = 256 bits of entropy) but we use it anyway: the same WASM
 * code path as password derivation, no separate library, and harmless margin
 * if a user picks a weaker phrase manually. Salt prevents precomputation
 * across users and is stored in the credential blob alongside KDF params.
 *
 * Returns AES-GCM and AES-KW handles (same 32 bytes, two WebCrypto views) so
 * the caller can both wrap chain entries with AES-KW and use the raw key for
 * any future per-content operations.
 *
 * @param {string} mnemonic - BIP39 mnemonic phrase (12-24 words)
 * @param {Uint8Array} salt - Per-account 16-byte salt from the credential blob
 * @param {{m_kib: number, t: number, p: number}} [params] - Argon2id params
 * @returns {Promise<{gcmKey: CryptoKey, kwKey: CryptoKey, rawBytes: Uint8Array}>}
 */
export async function deriveRecoveryKey(mnemonic, salt, params) {
  if (!mnemonic || typeof mnemonic !== 'string') {
    throw new Error('mnemonic must be a non-empty string');
  }
  if (!(salt instanceof Uint8Array) || salt.length !== RECOVERY_SALT_LEN) {
    throw new Error(`salt must be a Uint8Array of length ${RECOVERY_SALT_LEN}`);
  }
  const memorySize = params?.m_kib ?? ARGON2ID_MEMORY_KIB;
  const iterations = params?.t ?? ARGON2ID_ITERATIONS;
  const parallelism = params?.p ?? ARGON2ID_PARALLELISM;

  // BIP39 normalization: NFKD + lowercase + collapse whitespace to single space.
  const normalized = mnemonic.normalize('NFKD').toLowerCase().trim().split(/\s+/).join(' ');

  const out = await argon2idHash({
    password: new TextEncoder().encode(normalized),
    salt,
    parallelism,
    iterations,
    memorySize,
    hashLength: KEY_LENGTH_BYTES,
    outputType: 'binary',
  });
  const rawBytes = out instanceof Uint8Array ? out : new Uint8Array(out);

  const [gcmKey, kwKey] = await Promise.all([
    crypto.subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', rawBytes, 'AES-KW', true, ['wrapKey', 'unwrapKey']),
  ]);

  return { gcmKey, kwKey, rawBytes };
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
 * Derive recovery_lookup_key from phrase entropy for a specific app
 * (issue #12). The recovery lookup key is a phrase-derived secondary index
 * the API uses to find an account row during the recovery flow — independent
 * of the password, so it works when the user has lost their credentials.
 *
 * Derivation uses HKDF-Expand (HMAC-SHA-256 single block) with a different
 * purpose label from the password-derived `lookup` key, ensuring the two
 * lookup keys never collide for the same account. The phrase entropy itself
 * is the PRK (256 bits, sufficient for an HMAC PRK).
 *
 * @param {Uint8Array} phraseEntropy - Raw BIP39 entropy bytes (32 for 24-word)
 * @param {string} appId
 * @returns {Promise<string>} 64-char hex string
 */
export async function deriveRecoveryLookupKey(phraseEntropy, appId) {
  if (!(phraseEntropy instanceof Uint8Array) || phraseEntropy.length === 0) {
    throw new Error('phraseEntropy must be a non-empty Uint8Array');
  }
  if (!appId) throw new Error('appId is required');
  const hash = await hkdfExpand(phraseEntropy, 'recovery-lookup', appId);
  return bytesToHex(hash);
}

/**
 * Derive the recovery ECDSA P-256 signing key pair from phrase entropy for a
 * specific app (issue #12). The public key is published in the credential
 * blob; the private key signs the recovery-flow challenge nonce so the API
 * can verify the user holds the recovery phrase before issuing a JWT.
 *
 * Mirrors {@link deriveSigningKeyPair}'s P-256 scalar validation + retry
 * (probability ~2^-128 of needing the second counter byte).
 *
 * @param {Uint8Array} phraseEntropy
 * @param {string} appId
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>}
 */
export async function deriveRecoverySigningKeyPair(phraseEntropy, appId) {
  if (!(phraseEntropy instanceof Uint8Array) || phraseEntropy.length === 0) {
    throw new Error('phraseEntropy must be a non-empty Uint8Array');
  }
  if (!appId) throw new Error('appId is required');

  let seed;
  for (let counter = 1; counter <= 3; counter++) {
    seed = await hkdfExpand(phraseEntropy, 'recovery-sign', appId, counter);
    const scalar = bytesToBigInt(seed);
    if (scalar > 0n && scalar < P256_ORDER) break;
    if (counter === 3) throw new Error('Failed to derive valid recovery P-256 private key (extremely unlikely)');
  }

  const pkcs8 = new Uint8Array(PKCS8_P256_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_P256_PREFIX, 0);
  pkcs8.set(seed, PKCS8_P256_PREFIX.length);

  const privateKey = await crypto.subtle.importKey(
    'pkcs8', pkcs8,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign']
  );

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

// ============ PER-CONTENT CEK BLOB FORMAT (issue #11) ============

/**
 * Detect whether a blob is in the new per-content CEK format.
 * Cheap O(1) prefix check; safe on legacy blobs (legacy AES-GCM IVs are random
 * 12-byte values — collision with the 5-byte magic has probability 2^-40).
 *
 * @param {Uint8Array} blob
 * @returns {boolean}
 */
export function hasTarnBlobMagic(blob) {
  if (!(blob instanceof Uint8Array) || blob.length < TARN_BLOB_MAGIC.length) {
    return false;
  }
  for (let i = 0; i < TARN_BLOB_MAGIC.length; i++) {
    if (blob[i] !== TARN_BLOB_MAGIC[i]) return false;
  }
  return true;
}

/**
 * Encrypt JSON payload with a fresh random CEK; produce a v3-magic blob.
 *
 * The CEK is wrapped under the supplied DEK (AES-KW). The generation indicator
 * is NOT embedded in the blob — it travels alongside as the Arweave `Gen` tag.
 * This keeps the byte layout from the design doc unchanged so a recipient
 * who only has the CEK can skip bytes 5..44 without parsing tags.
 *
 * @param {CryptoKey} dek - AES-KW wrapping key for the current generation
 * @param {Object} plaintext - JSON-serializable payload
 * @returns {Promise<Uint8Array>} Wire format: magic(5) || wrapped_CEK(40) || iv(12) || ciphertext+tag
 */
export async function encryptWithCEK(dek, plaintext) {
  // Generate a fresh CEK and import into both AES-GCM (for content) and AES-KW
  // (so it can be wrapped). Same raw bytes, two WebCrypto handles.
  const cekBytes = crypto.getRandomValues(new Uint8Array(CEK_LEN_BYTES));
  const [cekGcm, cekKw] = await Promise.all([
    crypto.subtle.importKey('raw', cekBytes, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', cekBytes, 'AES-KW', true, ['wrapKey', 'unwrapKey']),
  ]);

  const wrappedCEK = new Uint8Array(
    await crypto.subtle.wrapKey('raw', cekKw, dek, 'AES-KW')
  );
  if (wrappedCEK.length !== WRAPPED_CEK_LEN) {
    throw new Error(`wrapped_CEK length ${wrappedCEK.length} != ${WRAPPED_CEK_LEN}`);
  }

  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN_BYTES));
  const data = new TextEncoder().encode(JSON.stringify(plaintext));
  const ciphertextAndTag = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cekGcm, data)
  );

  const out = new Uint8Array(
    TARN_BLOB_MAGIC.length + WRAPPED_CEK_LEN + IV_LEN_BYTES + ciphertextAndTag.length
  );
  let off = 0;
  out.set(TARN_BLOB_MAGIC, off); off += TARN_BLOB_MAGIC.length;
  out.set(wrappedCEK, off); off += WRAPPED_CEK_LEN;
  out.set(iv, off); off += IV_LEN_BYTES;
  out.set(ciphertextAndTag, off);
  return out;
}

/**
 * Decrypt a per-content CEK blob using a DEK from the chain.
 *
 * Layout: magic(5) || wrapped_CEK(40) || iv(12) || ciphertext+tag
 *
 * @param {CryptoKey} dek - AES-KW unwrapping key for the blob's generation
 * @param {Uint8Array} blob
 * @returns {Promise<Object>}
 */
export async function decryptWithCEK(dek, blob) {
  if (!hasTarnBlobMagic(blob)) {
    throw new Error('Blob does not have TARN magic prefix');
  }
  if (blob.length < MIN_NEW_FORMAT_LEN) {
    throw new Error(`Blob too short for new format: ${blob.length} < ${MIN_NEW_FORMAT_LEN}`);
  }

  const wrappedCEK = blob.slice(
    TARN_BLOB_MAGIC.length,
    TARN_BLOB_MAGIC.length + WRAPPED_CEK_LEN,
  );
  const ivStart = TARN_BLOB_MAGIC.length + WRAPPED_CEK_LEN;
  const iv = blob.slice(ivStart, ivStart + IV_LEN_BYTES);
  const ciphertextAndTag = blob.slice(ivStart + IV_LEN_BYTES);

  const cekGcm = await crypto.subtle.unwrapKey(
    'raw', wrappedCEK, dek, 'AES-KW',
    { name: 'AES-GCM' }, false, ['decrypt'],
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv }, cekGcm, ciphertextAndTag,
  );
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
// v2 — JSON envelope with a single wrapped DEK: { v, kdf, kdf_params, wrapped }.
//      DEK == credential_encryption_key (self-wrapping). Pre-issue-#11.
// v3 — JSON envelope with a single-factor DEK chain (issue #11):
//      { v: 3, kdf, kdf_params, dek_chain: [{gen, wrapped}, ...] }.
//      Each entry's `wrapped` is AES-KW(DEK_at_gen, credential_encryption_key).
//      Forward-secret rotation: append a fresh DEK at gen N+1 on every
//      credential change; old gens stay accessible for past data.
// v4 (current default for new accounts) — JSON envelope with a multi-factor
//      DEK chain (issue #12):
//        { v: 4, kdf, kdf_params,
//          recovery: { kdf, kdf_params, salt: <base64 16 bytes> } | absent,
//          dek_chain: [{gen, wrappings: [{factor, wrapped}, ...]}, ...] }
//      Each chain entry holds N wrappings of the same DEK under different
//      KEKs (factors). Any factor's KEK independently unwraps the DEK at its
//      generation. v4 envelopes without a `recovery` block are semantically
//      equivalent to v3 (single password factor); the caller can add a
//      recovery factor later via re-publishing.
//
// Detection: if the string parses as JSON, dispatch on `v`; otherwise legacy v1.
// Read normalization: v1/v2/v3 are coerced to a single-factor v4-shaped chain
// (factor = "password") so callers can branch on shape, not version.

/**
 * Wrap the data encryption key and pack into the wire format for the given KDF.
 * Produces the legacy single-key shape (envelope v1 for PBKDF2, envelope v2
 * for Argon2id). For new accounts after issue #11, prefer
 * {@link wrapDataKeyChainEnvelope} which produces a v3 chain envelope.
 *
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
 * Generate a fresh random 32-byte DEK and import it as both an AES-GCM key
 * (for legacy/direct content encryption — and as a fallback when the chain
 * has only one entry) and an AES-KW key (for wrapping per-content CEKs).
 *
 * @returns {Promise<{gcmKey: CryptoKey, kwKey: CryptoKey, rawBytes: Uint8Array}>}
 */
export async function generateRandomDataKey() {
  const rawBytes = crypto.getRandomValues(new Uint8Array(KEY_LENGTH_BYTES));
  const [gcmKey, kwKey] = await Promise.all([
    crypto.subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', rawBytes, 'AES-KW', true, ['wrapKey', 'unwrapKey']),
  ]);
  return { gcmKey, kwKey, rawBytes };
}

/**
 * Inspect a wire-format `wrapped_data_key` without unwrapping.
 *
 * Returns a normalized shape regardless of envelope version. v1/v2/v3 envelopes
 * are coerced into the v4-shaped multi-factor chain with a single `password`
 * wrapping per entry, so callers can branch on shape, not version:
 *   - `kdfVersion`      — KDF used to derive master_key (v1 or v2)
 *   - `envelopeVersion` — 1 (bare base64), 2 (single wrapped), 3 (DEK chain),
 *                          or 4 (multi-factor DEK chain — issue #12)
 *   - `dekChain`        — `[{gen, wrappings: [{factor, wrappedBase64}, ...]}, ...]`
 *                          (length 1 for v1/v2; single wrapping per entry for v1/v2/v3)
 *   - `wrappedBase64`   — convenience: highest-gen entry's `password` factor
 *                          wrapping (current generation, password-side)
 *   - `kdfParams`       — master_key KDF params copy (or null for v1)
 *   - `recovery`        — recovery-factor metadata for v4 envelopes that have one:
 *                          `{kdf, kdfParams, salt: Uint8Array}`. Null for v1/v2/v3
 *                          and for v4 envelopes that haven't enrolled a recovery
 *                          factor yet.
 *
 * @param {string} wireValue
 * @returns {{
 *   kdfVersion: number,
 *   envelopeVersion: number,
 *   dekChain: Array<{gen: number, wrappings: Array<{factor: string, wrappedBase64: string}>}>,
 *   wrappedBase64: string,
 *   kdfParams: object|null,
 *   recovery: { kdf: string, kdfParams: object, salt: Uint8Array } | null,
 * }}
 */
export function parseWrappedDataKey(wireValue) {
  if (typeof wireValue !== 'string' || wireValue.length === 0) {
    throw new Error('wrapped_data_key must be a non-empty string');
  }

  // v2+ envelopes are JSON objects starting with '{'. Bare base64 never starts
  // with '{' (base64 alphabet is [A-Za-z0-9+/=]), so this prefix check is
  // a safe, allocation-free dispatch before attempting JSON.parse.
  if (wireValue[0] !== '{') {
    return {
      kdfVersion: KDF_V1_PBKDF2,
      envelopeVersion: 1,
      dekChain: [{ gen: 1, wrappings: [{ factor: FACTOR_PASSWORD, wrappedBase64: wireValue }] }],
      wrappedBase64: wireValue,
      kdfParams: null,
      recovery: null,
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(wireValue);
  } catch {
    throw new Error('wrapped_data_key looks like an envelope but is not valid JSON');
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('wrapped_data_key envelope is missing required fields');
  }

  if (parsed.v === 2 && parsed.kdf === 'argon2id') {
    if (typeof parsed.wrapped !== 'string') {
      throw new Error('wrapped_data_key envelope is missing required fields');
    }
    return {
      kdfVersion: KDF_V2_ARGON2ID,
      envelopeVersion: 2,
      dekChain: [{ gen: 1, wrappings: [{ factor: FACTOR_PASSWORD, wrappedBase64: parsed.wrapped }] }],
      wrappedBase64: parsed.wrapped,
      kdfParams: parsed.kdf_params || null,
      recovery: null,
    };
  }

  if (parsed.v === 3 && parsed.kdf === 'argon2id') {
    if (!Array.isArray(parsed.dek_chain) || parsed.dek_chain.length === 0) {
      throw new Error('v3 wrapped_data_key envelope must have a non-empty dek_chain');
    }
    const chain = parsed.dek_chain.map((entry, idx) => {
      if (
        !entry ||
        typeof entry !== 'object' ||
        typeof entry.gen !== 'number' ||
        !Number.isInteger(entry.gen) ||
        entry.gen < 1 ||
        typeof entry.wrapped !== 'string'
      ) {
        throw new Error(`v3 wrapped_data_key envelope dek_chain[${idx}] is malformed`);
      }
      return {
        gen: entry.gen,
        wrappings: [{ factor: FACTOR_PASSWORD, wrappedBase64: entry.wrapped }],
      };
    });
    // The current generation is the entry with the highest `gen`. We don't
    // require chain order to be strictly ascending, but reject duplicates.
    const seen = new Set();
    for (const e of chain) {
      if (seen.has(e.gen)) {
        throw new Error(`v3 wrapped_data_key envelope has duplicate gen: ${e.gen}`);
      }
      seen.add(e.gen);
    }
    chain.sort((a, b) => a.gen - b.gen);
    return {
      kdfVersion: KDF_V2_ARGON2ID,
      envelopeVersion: 3,
      dekChain: chain,
      wrappedBase64: chain[chain.length - 1].wrappings[0].wrappedBase64,
      kdfParams: parsed.kdf_params || null,
      recovery: null,
    };
  }

  if (parsed.v === 4 && parsed.kdf === 'argon2id') {
    if (!Array.isArray(parsed.dek_chain) || parsed.dek_chain.length === 0) {
      throw new Error('v4 wrapped_data_key envelope must have a non-empty dek_chain');
    }
    const chain = parsed.dek_chain.map((entry, idx) => {
      if (
        !entry ||
        typeof entry !== 'object' ||
        typeof entry.gen !== 'number' ||
        !Number.isInteger(entry.gen) ||
        entry.gen < 1 ||
        !Array.isArray(entry.wrappings) ||
        entry.wrappings.length === 0
      ) {
        throw new Error(`v4 wrapped_data_key envelope dek_chain[${idx}] is malformed`);
      }
      const wrappings = entry.wrappings.map((w, wIdx) => {
        if (
          !w ||
          typeof w !== 'object' ||
          typeof w.factor !== 'string' ||
          w.factor.length === 0 ||
          typeof w.wrapped !== 'string'
        ) {
          throw new Error(`v4 wrapped_data_key envelope dek_chain[${idx}].wrappings[${wIdx}] is malformed`);
        }
        return { factor: w.factor, wrappedBase64: w.wrapped };
      });
      // No two wrappings in the same entry should share a factor name.
      const factorSeen = new Set();
      for (const w of wrappings) {
        if (factorSeen.has(w.factor)) {
          throw new Error(`v4 wrapped_data_key envelope dek_chain[${idx}] has duplicate factor: ${w.factor}`);
        }
        factorSeen.add(w.factor);
      }
      return { gen: entry.gen, wrappings };
    });
    const seen = new Set();
    for (const e of chain) {
      if (seen.has(e.gen)) {
        throw new Error(`v4 wrapped_data_key envelope has duplicate gen: ${e.gen}`);
      }
      seen.add(e.gen);
    }
    chain.sort((a, b) => a.gen - b.gen);

    let recovery = null;
    if (parsed.recovery) {
      const r = parsed.recovery;
      if (
        !r ||
        typeof r !== 'object' ||
        r.kdf !== 'argon2id' ||
        !r.kdf_params ||
        typeof r.salt !== 'string'
      ) {
        throw new Error('v4 wrapped_data_key envelope has malformed recovery block');
      }
      const saltBytes = base64ToBytes(r.salt);
      if (saltBytes.length !== RECOVERY_SALT_LEN) {
        throw new Error(`v4 recovery.salt must decode to ${RECOVERY_SALT_LEN} bytes, got ${saltBytes.length}`);
      }
      recovery = { kdf: r.kdf, kdfParams: r.kdf_params, salt: saltBytes };
    }

    // Convenience field: highest-gen `password` wrapping (current write-side
    // wrapping). If there is no password wrapping at the current gen (would be
    // unusual — all current writers include one) fall back to the first
    // wrapping at the current gen.
    const top = chain[chain.length - 1];
    const pw = top.wrappings.find(w => w.factor === FACTOR_PASSWORD);
    const wrappedBase64 = (pw || top.wrappings[0]).wrappedBase64;

    return {
      kdfVersion: KDF_V2_ARGON2ID,
      envelopeVersion: 4,
      dekChain: chain,
      wrappedBase64,
      kdfParams: parsed.kdf_params || null,
      recovery,
    };
  }

  throw new Error(`Unsupported wrapped_data_key envelope version: v=${parsed.v} kdf=${parsed.kdf}`);
}

/**
 * Unwrap the data encryption key from the wire format. For backward compat
 * with the v1/v2 single-key shape, returns the highest-gen DEK as `dataKey`.
 *
 * For v3 envelopes, prefer {@link unwrapDataKeyChain} which returns the full
 * generation map needed to read older blobs.
 *
 * @param {string} wireValue
 * @param {CryptoKey} unwrappingKey
 * @returns {Promise<{ dataKey: CryptoKey, kdfVersion: number, kdfParams: object|null }>}
 */
export async function unwrapDataKeyEnvelope(wireValue, unwrappingKey) {
  const parsed = parseWrappedDataKey(wireValue);
  const dataKey = await unwrapDataKey(parsed.wrappedBase64, unwrappingKey);
  return { dataKey, kdfVersion: parsed.kdfVersion, kdfParams: parsed.kdfParams };
}

/**
 * Unwrap every DEK in the chain via the named factor (defaults to
 * `FACTOR_PASSWORD`). Returns a Map keyed by generation plus the current
 * (highest) generation number. Always returns a Map even for legacy single-key
 * envelopes — they expose a synthetic password wrapping per entry.
 *
 * Each value is a pair of WebCrypto handles for the same 32-byte DEK:
 *   - `gcmKey`: AES-GCM, extractable (used for legacy direct-DEK decryption,
 *               and as the key passed to AES-KW wrapKey on credential change)
 *   - `kwKey`:  AES-KW, used to wrap/unwrap per-content CEKs
 *
 * For v4 envelopes the caller passes the relevant factor's KEK (password or
 * recovery). The parser ensures every entry has at least one wrapping; if any
 * entry lacks the requested factor, this throws.
 *
 * @param {string} wireValue
 * @param {CryptoKey} unwrappingKey - AES-KW handle for the chosen factor's KEK
 * @param {string} [factor=FACTOR_PASSWORD]
 * @returns {Promise<{
 *   dekByGen: Map<number, {gcmKey: CryptoKey, kwKey: CryptoKey}>,
 *   currentGen: number,
 *   envelopeVersion: number,
 *   kdfVersion: number,
 *   kdfParams: object|null,
 *   recovery: { kdf: string, kdfParams: object, salt: Uint8Array } | null,
 * }>}
 */
export async function unwrapDataKeyChain(wireValue, unwrappingKey, factor = FACTOR_PASSWORD) {
  const parsed = parseWrappedDataKey(wireValue);
  const dekByGen = new Map();
  for (const entry of parsed.dekChain) {
    const wrapping = entry.wrappings.find(w => w.factor === factor);
    if (!wrapping) {
      throw new Error(`No '${factor}' wrapping for gen ${entry.gen}`);
    }
    const wrapped = base64ToBytes(wrapping.wrappedBase64);
    const [gcmKey, kwKey] = await Promise.all([
      crypto.subtle.unwrapKey(
        'raw', wrapped, unwrappingKey, 'AES-KW',
        { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'],
      ),
      crypto.subtle.unwrapKey(
        'raw', wrapped, unwrappingKey, 'AES-KW',
        'AES-KW', false, ['wrapKey', 'unwrapKey'],
      ),
    ]);
    dekByGen.set(entry.gen, { gcmKey, kwKey });
  }
  const currentGen = parsed.dekChain[parsed.dekChain.length - 1].gen;
  return {
    dekByGen,
    currentGen,
    envelopeVersion: parsed.envelopeVersion,
    kdfVersion: parsed.kdfVersion,
    kdfParams: parsed.kdfParams,
    recovery: parsed.recovery,
  };
}

/**
 * Build a v3 envelope from a chain of (gen, raw_wrapped_base64) pairs.
 * Used when the chain has already been re-wrapped (e.g., after credential
 * change) and the wrapped bytes need to be packaged as a single envelope.
 *
 * @param {Array<{gen: number, wrappedBase64: string}>} chain
 * @returns {string}
 */
export function buildV3Envelope(chain) {
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new Error('chain must be a non-empty array');
  }
  const sorted = chain.slice().sort((a, b) => a.gen - b.gen);
  return JSON.stringify({
    v: 3,
    kdf: 'argon2id',
    kdf_params: { m_kib: ARGON2ID_MEMORY_KIB, t: ARGON2ID_ITERATIONS, p: ARGON2ID_PARALLELISM },
    dek_chain: sorted.map(e => ({ gen: e.gen, wrapped: e.wrappedBase64 })),
  });
}

/**
 * Wrap an array of DEK CryptoKeys (one per generation) under the given
 * wrapping key and pack into a v3 envelope.
 *
 * Each chain entry is `{gen, key}` where `key` is an extractable CryptoKey
 * holding the DEK bytes (any algorithm — AES-GCM or AES-KW handle both work,
 * since AES-KW wrapKey operates on raw bytes).
 *
 * @param {Array<{gen: number, key: CryptoKey}>} chain
 * @param {CryptoKey} wrappingKey
 * @returns {Promise<string>} The `wrapped_data_key` wire value (v3 envelope).
 */
export async function wrapDataKeyChainEnvelope(chain, wrappingKey) {
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new Error('chain must be a non-empty array');
  }
  const wrapped = [];
  for (const entry of chain) {
    if (!entry || typeof entry.gen !== 'number' || !entry.key) {
      throw new Error('chain entries must be {gen: number, key: CryptoKey}');
    }
    const wrappedBase64 = await wrapDataKey(entry.key, wrappingKey);
    wrapped.push({ gen: entry.gen, wrappedBase64 });
  }
  return buildV3Envelope(wrapped);
}

// ============ v4 ENVELOPE — MULTI-FACTOR WRAPPING (issue #12) ============

/**
 * Generate a fresh random salt for the recovery KDF (per-account, 16 bytes).
 * Stored in the v4 envelope's `recovery.salt` field.
 *
 * @returns {Uint8Array}
 */
export function generateRecoverySalt() {
  return crypto.getRandomValues(new Uint8Array(RECOVERY_SALT_LEN));
}

/**
 * Build a v4 envelope from a chain whose entries each carry one or more
 * already-wrapped factors (raw base64 ciphertexts). Recovery metadata is
 * required when any chain entry has a `recovery_phrase` wrapping; otherwise
 * pass `null` to indicate no recovery factor is enrolled.
 *
 * @param {Array<{gen: number, wrappings: Array<{factor: string, wrappedBase64: string}>}>} chain
 * @param {{ salt: Uint8Array, kdfParams?: {m_kib: number, t: number, p: number} } | null} recovery
 * @returns {string}
 */
export function buildV4Envelope(chain, recovery) {
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new Error('chain must be a non-empty array');
  }
  for (const entry of chain) {
    if (
      !entry ||
      typeof entry.gen !== 'number' ||
      !Number.isInteger(entry.gen) ||
      entry.gen < 1 ||
      !Array.isArray(entry.wrappings) ||
      entry.wrappings.length === 0
    ) {
      throw new Error('chain entries must be {gen: number, wrappings: [{factor, wrappedBase64}, ...]}');
    }
  }
  const sorted = chain.slice().sort((a, b) => a.gen - b.gen);

  // If any entry references a recovery_phrase wrapping, the envelope MUST
  // carry the recovery metadata block — otherwise readers can't derive the
  // recovery KEK.
  const hasRecoveryWrap = sorted.some(e => e.wrappings.some(w => w.factor === FACTOR_RECOVERY_PHRASE));
  if (hasRecoveryWrap && !recovery) {
    throw new Error('chain has recovery_phrase wrappings but no recovery metadata supplied');
  }

  const out = {
    v: 4,
    kdf: 'argon2id',
    kdf_params: { m_kib: ARGON2ID_MEMORY_KIB, t: ARGON2ID_ITERATIONS, p: ARGON2ID_PARALLELISM },
  };
  if (recovery) {
    if (!(recovery.salt instanceof Uint8Array) || recovery.salt.length !== RECOVERY_SALT_LEN) {
      throw new Error(`recovery.salt must be a Uint8Array of length ${RECOVERY_SALT_LEN}`);
    }
    out.recovery = {
      kdf: 'argon2id',
      kdf_params: recovery.kdfParams || {
        m_kib: ARGON2ID_MEMORY_KIB,
        t: ARGON2ID_ITERATIONS,
        p: ARGON2ID_PARALLELISM,
      },
      salt: bytesToBase64(recovery.salt),
    };
  }
  out.dek_chain = sorted.map(e => ({
    gen: e.gen,
    wrappings: e.wrappings.map(w => ({ factor: w.factor, wrapped: w.wrappedBase64 })),
  }));
  return JSON.stringify(out);
}

/**
 * Wrap a chain of DEK CryptoKeys under one or more factors and pack into a v4
 * envelope. Each chain entry is wrapped independently under every factor.
 *
 * Factors are passed as `{name, wrappingKey}` records — `name` is the factor
 * label written into the envelope (e.g., `FACTOR_PASSWORD`, `FACTOR_RECOVERY_PHRASE`)
 * and `wrappingKey` is the AES-KW handle used to wrap each entry's DEK.
 *
 * The output envelope is byte-stable for a fixed (chain, factors) input set:
 * AES-KW is deterministic, JSON.stringify is insertion-ordered, and chain +
 * wrappings are written in the input order. Callers that need register-retry
 * idempotency must call this with a stable factor order.
 *
 * @param {Array<{gen: number, key: CryptoKey}>} chain
 * @param {Array<{name: string, wrappingKey: CryptoKey}>} factors
 * @param {{ salt: Uint8Array, kdfParams?: {m_kib: number, t: number, p: number} } | null} recovery
 * @returns {Promise<string>} The `wrapped_data_key` wire value (v4 envelope).
 */
export async function wrapDataKeyChainEnvelopeV4(chain, factors, recovery) {
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new Error('chain must be a non-empty array');
  }
  if (!Array.isArray(factors) || factors.length === 0) {
    throw new Error('factors must be a non-empty array');
  }
  for (const f of factors) {
    if (!f || typeof f.name !== 'string' || !f.wrappingKey) {
      throw new Error('factors must be {name: string, wrappingKey: CryptoKey}');
    }
  }
  // Forbid duplicate factor names — each entry's wrappings list must be unique
  // by factor.
  const seenFactors = new Set();
  for (const f of factors) {
    if (seenFactors.has(f.name)) throw new Error(`Duplicate factor name: ${f.name}`);
    seenFactors.add(f.name);
  }
  const hasRecoveryFactor = factors.some(f => f.name === FACTOR_RECOVERY_PHRASE);
  if (hasRecoveryFactor && !recovery) {
    throw new Error('recovery metadata is required when factors include recovery_phrase');
  }

  const wrappedChain = [];
  for (const entry of chain) {
    if (!entry || typeof entry.gen !== 'number' || !entry.key) {
      throw new Error('chain entries must be {gen: number, key: CryptoKey}');
    }
    const wrappings = [];
    for (const f of factors) {
      const wrappedBase64 = await wrapDataKey(entry.key, f.wrappingKey);
      wrappings.push({ factor: f.name, wrappedBase64 });
    }
    wrappedChain.push({ gen: entry.gen, wrappings });
  }
  return buildV4Envelope(wrappedChain, recovery);
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
