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
import { x25519 } from '@noble/curves/ed25519';

// ============ BRANDED TYPES ============
//
// String-shaped values that the runtime can't tell apart but the type system
// should. Keeps a base64url shareKey from being passed where a hex
// lookup_key is expected, etc. Brands are erased at runtime — these are
// pure type-level distinctions.

declare const __brand: unique symbol;
type Brand<T, B extends string> = T & { readonly [__brand]: B };

/** 64-char lowercase hex SHA-256-derived account lookup key. */
export type LookupKey = Brand<string, 'LookupKey'>;
/** Base64url-encoded raw 32-byte CEK ("share key" — same bytes, different name on the wire). */
export type ShareKey = Brand<string, 'ShareKey'>;
/** Base64-encoded AES-KW ciphertext (40 bytes: 32-byte CEK + 8-byte AES-KW overhead). */
export type WrappedDataKey = Brand<string, 'WrappedDataKey'>;
/** Standard base64 (with `+/=`). */
export type Base64 = Brand<string, 'Base64'>;
/** Base64url (RFC 4648 §5: `-_`, no padding). */
export type Base64Url = Brand<string, 'Base64Url'>;
/** Lowercase hex string. */
export type Hex = Brand<string, 'Hex'>;
/** Wire `wrapped_data_key` field — opaque envelope, sometimes JSON, sometimes bare base64. */
export type WrappedDataKeyEnvelope = Brand<string, 'WrappedDataKeyEnvelope'>;

// Constructor helpers — these are pure casts. The brand is opt-in: passing a
// raw `string` will fail TS, but a value originally produced by a brand-aware
// function flows through unchanged.
const asLookupKey = (s: string): LookupKey => s as LookupKey;
const asShareKey = (s: string): ShareKey => s as ShareKey;
const asWrappedDataKey = (s: string): WrappedDataKey => s as WrappedDataKey;
const asBase64 = (s: string): Base64 => s as Base64;
const asBase64Url = (s: string): Base64Url => s as Base64Url;
const asHex = (s: string): Hex => s as Hex;
const asEnvelope = (s: string): WrappedDataKeyEnvelope => s as WrappedDataKeyEnvelope;

// ============ WebCrypto BufferSource helper ============
//
// TS 5.x narrowed `BufferSource` to require an `ArrayBuffer`-not-`SharedArrayBuffer`
// backing buffer. Modern lib types say `Uint8Array<ArrayBufferLike>`, which
// doesn't satisfy that constraint at the type level (runtime is fine — both
// work). Rather than `as BufferSource` at every call site, this single helper
// makes the boundary explicit: every WebCrypto input flows through `bs()`.
//
// It is a literal identity at runtime (returns the same object).
function bs(b: ArrayBufferView | ArrayBuffer): BufferSource {
  return b as BufferSource;
}

// ============ CONSTANTS ============

// KDF versions for the master_key derivation step.
// v1 — PBKDF2-SHA256, 600k iterations (legacy, accounts created before Argon2id rollout).
// v2 — Argon2id, m=64 MiB, t=3, p=1 (current default for new accounts).
//
// Argon2id parameters chosen to keep login latency near ~200ms on a recent
// laptop, ~1–1.5s on a 3-year-old phone — well under the ~2s acceptance bar.
// Memory-hard params neutralize GPU/ASIC parallelism on a leaked Arweave
// credential blob, in line with the OWASP Argon2id recommendation.
export const KDF_V1_PBKDF2 = 1 as const;
export const KDF_V2_ARGON2ID = 2 as const;
export const KDF_DEFAULT = KDF_V2_ARGON2ID;
export type KdfVersion = typeof KDF_V1_PBKDF2 | typeof KDF_V2_ARGON2ID;

// Wrapping factors (issue #12). Each entry in a v4 dek_chain is wrapped under
// one or more factors; any factor's KEK independently unwraps the DEK.
//   PASSWORD        — derived from email+password via deriveCredentialEncryptionKey
//   RECOVERY_PHRASE — derived from BIP39 phrase via deriveRecoveryKey
export const FACTOR_PASSWORD = 'password' as const;
export const FACTOR_RECOVERY_PHRASE = 'recovery_phrase' as const;
export type Factor = typeof FACTOR_PASSWORD | typeof FACTOR_RECOVERY_PHRASE;

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
// (HKDF_COUNTER unused outside hkdfExpand; literal in the call.)

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

// Sharing keypair (issue #13). X25519 keys are 32 bytes for both private and
// public — public key is base64url-encoded into the credential blob's
// `share_pub` field for connection handshake bootstrap (Section 5 work).
const X25519_KEY_LEN = 32;

// Per-content CEK pattern (issue #11):
// New content blobs are prefixed with a 5-byte magic so the format is
// unambiguously detectable without consulting tags.
//   magic = "TARN" || version_byte (0x02)
// Layout: magic(5) || wrapped_CEK(40) || iv(12) || ciphertext+tag(N+16).
// Generation indicator lives in the Arweave `Gen` tag — keeps the byte
// offsets stable so a recipient (Section 5 work) can skip bytes 5..44
// without parsing tags.
export const TARN_BLOB_MAGIC = new Uint8Array([0x54, 0x41, 0x52, 0x4e, 0x02]);
export const TARN_BLOB_MAGIC_LEN = TARN_BLOB_MAGIC.length;
export const TARN_WRAPPED_CEK_LEN = 40; // 32-byte CEK + 8-byte AES-KW overhead
const WRAPPED_CEK_LEN = TARN_WRAPPED_CEK_LEN; // internal alias for the existing call sites
const CEK_LEN_BYTES = 32;
const IV_LEN_BYTES = 12;
const GCM_TAG_LEN_BYTES = 16;
const MIN_NEW_FORMAT_LEN =
  TARN_BLOB_MAGIC.length + WRAPPED_CEK_LEN + IV_LEN_BYTES + GCM_TAG_LEN_BYTES;

// ============ COMMON TYPES ============

/** A 32-byte AES key materialized as both AES-GCM and AES-KW handles + raw bytes. */
export type DataKeyHandles = {
  gcmKey: CryptoKey;
  kwKey: CryptoKey;
  rawBytes: Uint8Array;
};

/** A 32-byte AES key materialized as both handles, no raw bytes (for unwrapped chain entries). */
export type DataKeyPair = {
  gcmKey: CryptoKey;
  kwKey: CryptoKey;
};

/** ECDSA P-256 signing keypair. */
export type SigningKeyPair = {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
};

/** X25519 sharing keypair (raw bytes — `@noble/curves` operates on bytes, not WebCrypto). */
export type SharingKeyPair = {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
};

/** Argon2id parameter object as stored in envelope KDF metadata. */
export type Argon2idParams = {
  m_kib: number;
  t: number;
  p: number;
};

/** v4 envelope recovery-factor metadata. */
export type RecoveryMetadata = {
  kdf: 'argon2id';
  kdfParams: Argon2idParams;
  salt: Uint8Array;
};

// ============ EMAIL NORMALIZATION ============

export function normalizeEmail(email: string): string {
  if (!email || typeof email !== 'string') throw new Error('Email is required');
  return email.trim().toLowerCase();
}

// ============ HKDF-EXPAND (RFC 5869) ============

/**
 * HKDF-Expand with a single 32-byte output block.
 * This is equivalent to: HMAC-SHA256(prk, info || 0x01)
 *
 * @param prk - Pseudorandom key (master_key)
 * @param purpose - Key purpose: "lookup", "encrypt", or "sign"
 * @param appId - App identifier
 * @param counter - HKDF counter (for P-256 retry); defaults to 1
 */
async function hkdfExpand(
  prk: Uint8Array,
  purpose: string,
  appId: string,
  counter: number = 1,
): Promise<Uint8Array> {
  const encoder = new TextEncoder();

  // Import master_key as HMAC key
  const hmacKey = await crypto.subtle.importKey(
    'raw', bs(prk), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );

  // info = protocol || purpose || app_id || version || counter_byte
  const info = concatBytes(
    encoder.encode(PROTOCOL_ID + purpose + appId + DERIVATION_VERSION),
    new Uint8Array([counter]),
  );

  const result = await crypto.subtle.sign('HMAC', hmacKey, bs(info));
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
 */
export async function deriveMasterKey(
  email: string,
  password: string,
  kdfVersion: KdfVersion = KDF_DEFAULT,
): Promise<Uint8Array> {
  if (!email || !password) throw new Error('Email and password are required');

  const normalizedEmail = normalizeEmail(email);
  const encoder = new TextEncoder();

  // Salt = SHA-256(normalizedEmail) — same for both KDFs.
  const salt = new Uint8Array(
    await crypto.subtle.digest('SHA-256', bs(encoder.encode(normalizedEmail))),
  );

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
      'raw', bs(encoder.encode(password)), 'PBKDF2', false, ['deriveBits'],
    );
    const masterKeyBits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: bs(salt), iterations: PBKDF2_ITERATIONS, hash: PBKDF2_HASH },
      passwordKey,
      KEY_LENGTH_BITS,
    );
    return new Uint8Array(masterKeyBits);
  }

  throw new Error(`Unknown KDF version: ${kdfVersion as number}`);
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
 */
export async function deriveRecoveryKey(
  mnemonic: string,
  salt: Uint8Array,
  params?: Partial<Argon2idParams>,
): Promise<DataKeyHandles> {
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
    crypto.subtle.importKey('raw', bs(rawBytes), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', bs(rawBytes), 'AES-KW', true, ['wrapKey', 'unwrapKey']),
  ]);

  return { gcmKey, kwKey, rawBytes };
}

/** Derive credential_lookup_key from master_key for a specific app. */
export async function deriveCredentialLookupKey(masterKey: Uint8Array, appId: string): Promise<LookupKey> {
  if (!appId) throw new Error('appId is required');
  const hash = await hkdfExpand(masterKey, 'lookup', appId);
  return asLookupKey(bytesToHex(hash));
}

/**
 * Derive recovery_lookup_key from phrase entropy for a specific app
 * (issue #12). The recovery lookup key is a phrase-derived secondary index
 * the API uses to find an account row during the recovery flow — independent
 * of the password, so it works when the user has lost their credentials.
 */
export async function deriveRecoveryLookupKey(phraseEntropy: Uint8Array, appId: string): Promise<LookupKey> {
  if (!(phraseEntropy instanceof Uint8Array) || phraseEntropy.length === 0) {
    throw new Error('phraseEntropy must be a non-empty Uint8Array');
  }
  if (!appId) throw new Error('appId is required');
  const hash = await hkdfExpand(phraseEntropy, 'recovery-lookup', appId);
  return asLookupKey(bytesToHex(hash));
}

/**
 * Derive the recovery ECDSA P-256 signing key pair from phrase entropy for a
 * specific app (issue #12). The public key is published in the credential
 * blob; the private key signs the recovery-flow challenge nonce so the API
 * can verify the user holds the recovery phrase before issuing a JWT.
 *
 * Mirrors {@link deriveSigningKeyPair}'s P-256 scalar validation + retry
 * (probability ~2^-128 of needing the second counter byte).
 */
export async function deriveRecoverySigningKeyPair(
  phraseEntropy: Uint8Array,
  appId: string,
): Promise<SigningKeyPair> {
  if (!(phraseEntropy instanceof Uint8Array) || phraseEntropy.length === 0) {
    throw new Error('phraseEntropy must be a non-empty Uint8Array');
  }
  if (!appId) throw new Error('appId is required');

  let seed: Uint8Array | undefined;
  for (let counter = 1; counter <= 3; counter++) {
    seed = await hkdfExpand(phraseEntropy, 'recovery-sign', appId, counter);
    const scalar = bytesToBigInt(seed);
    if (scalar > 0n && scalar < P256_ORDER) break;
    if (counter === 3) throw new Error('Failed to derive valid recovery P-256 private key (extremely unlikely)');
  }
  if (!seed) throw new Error('Internal: P-256 seed derivation loop exited without a value');

  return await importP256KeyPair(seed);
}

/**
 * Derive credential encryption key material from master_key for a specific app.
 * Returns both an AES-GCM key (for data encryption) and an AES-KW key (for key wrapping).
 * Both are derived from the same raw bytes — same key, different WebCrypto usages.
 */
export async function deriveCredentialEncryptionKey(
  masterKey: Uint8Array,
  appId: string,
): Promise<DataKeyHandles> {
  if (!appId) throw new Error('appId is required');
  const keyBytes = await hkdfExpand(masterKey, 'encrypt', appId);

  const [gcmKey, kwKey] = await Promise.all([
    crypto.subtle.importKey('raw', bs(keyBytes), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', bs(keyBytes), 'AES-KW', true, ['wrapKey', 'unwrapKey']),
  ]);

  return { gcmKey, kwKey, rawBytes: keyBytes };
}

/**
 * Derive ECDSA P-256 signing key pair from master_key for a specific app.
 * Deterministic: same master_key + appId always produces the same key pair.
 * Validates that the derived scalar is in [1, n-1] per P-256 spec.
 */
export async function deriveSigningKeyPair(masterKey: Uint8Array, appId: string): Promise<SigningKeyPair> {
  if (!appId) throw new Error('appId is required');

  // Derive seed, validate P-256 range, retry with incrementing counter if needed
  let seed: Uint8Array | undefined;
  for (let counter = 1; counter <= 3; counter++) {
    seed = await hkdfExpand(masterKey, 'sign', appId, counter);
    const scalar = bytesToBigInt(seed);
    if (scalar > 0n && scalar < P256_ORDER) break;
    if (counter === 3) throw new Error('Failed to derive valid P-256 private key (extremely unlikely)');
  }
  if (!seed) throw new Error('Internal: P-256 seed derivation loop exited without a value');

  return await importP256KeyPair(seed);
}

/**
 * Internal: build a PKCS#8 P-256 private key from a 32-byte seed and round-trip
 * to JWK to derive the matching public key. Used by both the master-key-derived
 * and phrase-entropy-derived signing keypair flows.
 */
async function importP256KeyPair(seed: Uint8Array): Promise<SigningKeyPair> {
  const pkcs8 = new Uint8Array(PKCS8_P256_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_P256_PREFIX, 0);
  pkcs8.set(seed, PKCS8_P256_PREFIX.length);

  const privateKey = await crypto.subtle.importKey(
    'pkcs8', bs(pkcs8),
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign'],
  );

  // Derive public key from private key via JWK round-trip.
  const jwk = await crypto.subtle.exportKey('jwk', privateKey) as JsonWebKey & { d?: string };
  delete jwk.d;
  jwk.key_ops = ['verify'];

  const publicKey = await crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify'],
  );

  return { privateKey, publicKey };
}

/** Export public key to base64-encoded SPKI format. */
export async function exportPublicKey(publicKey: CryptoKey): Promise<Base64> {
  const der = await crypto.subtle.exportKey('spki', publicKey);
  return asBase64(bytesToBase64Raw(new Uint8Array(der)));
}

// ============ SHARING KEYPAIR (issue #13) ============

/**
 * Derive an email-only `share_lookup_key` for the connection-handshake bootstrap
 * (issue #13). This is the index Tarn uses to find a recipient's `share_pub`
 * when the requester knows only the recipient's email + app — i.e., before any
 * handshake has happened, when no shared secret exists yet.
 *
 * Derivation does NOT use master_key — it uses the SHA-256 of the normalized
 * email (already the salt for `master_key`) as the HKDF PRK. Anyone who knows
 * the recipient's email can compute this value and check whether the recipient
 * is registered. That's the inherent semantics of "look up Bob by email" and
 * is documented as an accepted residual leak (sharing §11.5).
 *
 * Per-app isolated via the same HKDF info pattern as every other sub-key, so
 * the same email registered to Bookish and Cellar produces distinct lookup
 * keys.
 */
export async function deriveShareLookupKey(email: string, appId: string): Promise<LookupKey> {
  if (!email) throw new Error('email is required');
  if (!appId) throw new Error('appId is required');
  const normalized = normalizeEmail(email);
  const encoder = new TextEncoder();
  const emailHash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', bs(encoder.encode(normalized))),
  );
  const out = await hkdfExpand(emailHash, 'share-lookup', appId);
  return asLookupKey(bytesToHex(out));
}

/**
 * Derive the per-app X25519 sharing keypair from `master_key` (sharing design §4.1).
 *
 * The seed is HKDF-Expand(master_key, "tarn"||"share"||app_id||"1"||0x01) —
 * same single-block info pattern as the existing `lookup`/`encrypt`/`sign`
 * sub-keys. Per-app isolation is preserved: the same email+password registered
 * to Bookish vs. Cellar produces distinct sharing keypairs.
 */
export async function deriveSharingKeyPair(masterKey: Uint8Array, appId: string): Promise<SharingKeyPair> {
  if (!appId) throw new Error('appId is required');
  const seed = await hkdfExpand(masterKey, 'share', appId);
  if (seed.length !== X25519_KEY_LEN) {
    throw new Error(`sharing seed length ${seed.length} != ${X25519_KEY_LEN}`);
  }
  const publicKey = x25519.getPublicKey(seed);
  return { privateKey: seed, publicKey };
}

/**
 * Encode an X25519 public key (32 raw bytes) for transport in a credential
 * blob's `share_pub` field. Base64url, no padding (sharing design notation `B(...)`).
 */
export function encodeSharePub(publicKey: Uint8Array): Base64Url {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== X25519_KEY_LEN) {
    throw new Error(`share_pub must be a Uint8Array of length ${X25519_KEY_LEN}`);
  }
  return asBase64Url(bytesToBase64UrlRaw(publicKey));
}

/**
 * Decode a base64url `share_pub` string back to 32 raw bytes. Throws if the
 * input is the wrong length, so callers don't have to length-check after.
 */
export function decodeSharePub(encoded: string): Uint8Array {
  if (typeof encoded !== 'string' || encoded.length === 0) {
    throw new Error('share_pub must be a non-empty string');
  }
  const bytes = base64UrlToBytesRaw(encoded);
  if (bytes.length !== X25519_KEY_LEN) {
    throw new Error(`share_pub must decode to ${X25519_KEY_LEN} bytes, got ${bytes.length}`);
  }
  return bytes;
}

// ============ AES-256-GCM ENCRYPTION (data blobs) ============

/** Encrypt JSON payload with AES-256-GCM. Wire: IV(12) || ciphertext+tag. */
export async function encrypt(key: CryptoKey, plaintext: unknown): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(plaintext));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: bs(iv) }, key, bs(data),
  ));

  const result = new Uint8Array(iv.length + ciphertext.length);
  result.set(iv, 0);
  result.set(ciphertext, iv.length);
  return result;
}

/** Decrypt AES-256-GCM bytes to JSON. Wire: IV(12) || ciphertext+tag. */
export async function decrypt(key: CryptoKey, blob: Uint8Array): Promise<unknown> {
  if (blob.length < 13) throw new Error('Blob too short');
  const iv = blob.slice(0, 12);
  const ciphertext = blob.slice(12);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bs(iv) }, key, bs(ciphertext));
  return JSON.parse(new TextDecoder().decode(decrypted));
}

// ============ PER-CONTENT CEK BLOB FORMAT (issue #11) ============

/**
 * Detect whether a blob is in the new per-content CEK format.
 * Cheap O(1) prefix check; safe on legacy blobs (legacy AES-GCM IVs are random
 * 12-byte values — collision with the 5-byte magic has probability 2^-40).
 */
export function hasTarnBlobMagic(blob: Uint8Array): boolean {
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
 * The raw CEK is returned alongside the blob (base64url-encoded) so the
 * caller can publish it through the share-log without re-deriving via an
 * AES-KW unwrap. Sharing-path callers populate the SDK's in-memory shareKey
 * cache from this; non-sharing callers simply ignore the field.
 */
export async function encryptWithCEK(
  dek: CryptoKey,
  plaintext: unknown,
): Promise<{ blob: Uint8Array; shareKey: ShareKey }> {
  // Generate a fresh CEK and import into both AES-GCM (for content) and AES-KW
  // (so it can be wrapped). Same raw bytes, two WebCrypto handles.
  const cekBytes = crypto.getRandomValues(new Uint8Array(CEK_LEN_BYTES));
  const [cekGcm, cekKw] = await Promise.all([
    crypto.subtle.importKey('raw', bs(cekBytes), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', bs(cekBytes), 'AES-KW', true, ['wrapKey', 'unwrapKey']),
  ]);

  const wrappedCEK = new Uint8Array(
    await crypto.subtle.wrapKey('raw', cekKw, dek, 'AES-KW'),
  );
  if (wrappedCEK.length !== WRAPPED_CEK_LEN) {
    throw new Error(`wrapped_CEK length ${wrappedCEK.length} != ${WRAPPED_CEK_LEN}`);
  }

  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN_BYTES));
  const data = new TextEncoder().encode(JSON.stringify(plaintext));
  const ciphertextAndTag = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: bs(iv) }, cekGcm, bs(data)),
  );

  const blob = new Uint8Array(
    TARN_BLOB_MAGIC.length + WRAPPED_CEK_LEN + IV_LEN_BYTES + ciphertextAndTag.length,
  );
  let off = 0;
  blob.set(TARN_BLOB_MAGIC, off); off += TARN_BLOB_MAGIC.length;
  blob.set(wrappedCEK, off); off += WRAPPED_CEK_LEN;
  blob.set(iv, off); off += IV_LEN_BYTES;
  blob.set(ciphertextAndTag, off);

  return { blob, shareKey: asShareKey(bytesToBase64UrlRaw(cekBytes)) };
}

/**
 * Decrypt a per-content CEK blob using a DEK from the chain.
 *
 * Layout: magic(5) || wrapped_CEK(40) || iv(12) || ciphertext+tag
 */
export async function decryptWithCEK(dek: CryptoKey, blob: Uint8Array): Promise<unknown> {
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
    'raw', bs(wrappedCEK), dek, 'AES-KW',
    { name: 'AES-GCM' }, false, ['decrypt'],
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bs(iv) }, cekGcm, bs(ciphertextAndTag),
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}

/**
 * Decrypt a per-content CEK blob using a shareKey directly (skipping the
 * wrapped CEK slot). This is the recipient path: a friend has fetched the
 * shareKey via the share-log and the blob bytes via the gateway, but does
 * NOT have the writer's DEK to unwrap the in-blob slot. We use the supplied
 * shareKey instead and ignore bytes 5..44.
 *
 * Layout: magic(5) || wrapped_CEK(40) || iv(12) || ciphertext+tag
 */
export async function decryptBlobWithSharedCEK(
  blob: Uint8Array,
  shareKeyBase64Url: string,
): Promise<unknown> {
  if (!hasTarnBlobMagic(blob)) {
    throw new Error('Blob does not have TARN magic prefix');
  }
  if (blob.length < MIN_NEW_FORMAT_LEN) {
    throw new Error(`Blob too short for new format: ${blob.length} < ${MIN_NEW_FORMAT_LEN}`);
  }

  const cekBytes = base64UrlToBytesRaw(shareKeyBase64Url);
  if (cekBytes.length !== CEK_LEN_BYTES) {
    throw new Error(`shareKey must be ${CEK_LEN_BYTES} raw bytes; got ${cekBytes.length}`);
  }

  const cekGcm = await crypto.subtle.importKey(
    'raw', bs(cekBytes), { name: 'AES-GCM' }, false, ['decrypt'],
  );

  const ivStart = TARN_BLOB_MAGIC.length + WRAPPED_CEK_LEN;
  const iv = blob.slice(ivStart, ivStart + IV_LEN_BYTES);
  const ciphertextAndTag = blob.slice(ivStart + IV_LEN_BYTES);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bs(iv) }, cekGcm, bs(ciphertextAndTag),
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}

// ============ AES-KW KEY WRAPPING (RFC 3394) ============

/**
 * Wrap data_encryption_key using AES-KW (raw bytes only — no envelope metadata).
 * Use {@link wrapDataKeyEnvelope} for the wire format that includes KDF version.
 */
export async function wrapDataKey(dataKey: CryptoKey, wrappingKey: CryptoKey): Promise<WrappedDataKey> {
  const wrapped = await crypto.subtle.wrapKey('raw', dataKey, wrappingKey, 'AES-KW');
  return asWrappedDataKey(bytesToBase64Raw(new Uint8Array(wrapped)));
}

/**
 * Unwrap data_encryption_key from raw AES-KW ciphertext (no envelope handling).
 * Use {@link unwrapDataKeyEnvelope} for the wire format.
 */
export async function unwrapDataKey(wrappedBase64: string, unwrappingKey: CryptoKey): Promise<CryptoKey> {
  const wrapped = base64ToBytesRaw(wrappedBase64);
  return await crypto.subtle.unwrapKey(
    'raw', bs(wrapped), unwrappingKey, 'AES-KW',
    { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'],
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
// v4 (current default for new accounts) — multi-factor DEK chain (issue #12):
//      { v: 4, kdf, kdf_params,
//        recovery: { kdf, kdf_params, salt: <base64 16 bytes> } | absent,
//        dek_chain: [{gen, wrappings: [{factor, wrapped}, ...]}, ...] }
//
// Detection: if the string parses as JSON, dispatch on `v`; otherwise legacy v1.
// Read normalization: v1/v2/v3 are coerced to a single-factor v4-shaped chain
// (factor = "password") so callers can branch on shape, not version.

export type EnvelopeVersion = 1 | 2 | 3 | 4;

export type ChainWrapping = {
  factor: string; // narrowed to Factor at the v4 layer; v1/v2/v3 use FACTOR_PASSWORD
  wrappedBase64: string;
};

export type DekChainEntry = {
  gen: number;
  wrappings: ChainWrapping[];
};

export type ParsedWrappedDataKey = {
  kdfVersion: KdfVersion;
  envelopeVersion: EnvelopeVersion;
  dekChain: DekChainEntry[];
  wrappedBase64: string;
  kdfParams: Argon2idParams | null;
  recovery: RecoveryMetadata | null;
};

/**
 * Wrap the data encryption key and pack into the wire format for the given KDF.
 * Produces the legacy single-key shape (envelope v1 for PBKDF2, envelope v2
 * for Argon2id). For new accounts after issue #11, prefer
 * {@link wrapDataKeyChainEnvelope} which produces a v3 chain envelope.
 */
export async function wrapDataKeyEnvelope(
  dataKey: CryptoKey,
  wrappingKey: CryptoKey,
  kdfVersion: KdfVersion,
): Promise<WrappedDataKeyEnvelope> {
  const wrappedBase64 = await wrapDataKey(dataKey, wrappingKey);

  if (kdfVersion === KDF_V1_PBKDF2) {
    return asEnvelope(wrappedBase64);
  }

  if (kdfVersion === KDF_V2_ARGON2ID) {
    return asEnvelope(JSON.stringify({
      v: 2,
      kdf: 'argon2id',
      kdf_params: { m_kib: ARGON2ID_MEMORY_KIB, t: ARGON2ID_ITERATIONS, p: ARGON2ID_PARALLELISM },
      wrapped: wrappedBase64,
    }));
  }

  throw new Error(`Unknown KDF version: ${kdfVersion as number}`);
}

/**
 * Generate a fresh random 32-byte DEK and import it as both an AES-GCM key
 * (for legacy/direct content encryption — and as a fallback when the chain
 * has only one entry) and an AES-KW key (for wrapping per-content CEKs).
 */
export async function generateRandomDataKey(): Promise<DataKeyHandles> {
  const rawBytes = crypto.getRandomValues(new Uint8Array(KEY_LENGTH_BYTES));
  const [gcmKey, kwKey] = await Promise.all([
    crypto.subtle.importKey('raw', bs(rawBytes), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', bs(rawBytes), 'AES-KW', true, ['wrapKey', 'unwrapKey']),
  ]);
  return { gcmKey, kwKey, rawBytes };
}

/**
 * Inspect a wire-format `wrapped_data_key` without unwrapping.
 *
 * Returns a normalized shape regardless of envelope version. v1/v2/v3 envelopes
 * are coerced into the v4-shaped multi-factor chain with a single `password`
 * wrapping per entry, so callers can branch on shape, not version.
 */
export function parseWrappedDataKey(wireValue: string): ParsedWrappedDataKey {
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

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(wireValue) as Record<string, unknown>;
  } catch {
    throw new Error('wrapped_data_key looks like an envelope but is not valid JSON');
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('wrapped_data_key envelope is missing required fields');
  }

  if (parsed['v'] === 2 && parsed['kdf'] === 'argon2id') {
    const wrapped = parsed['wrapped'];
    if (typeof wrapped !== 'string') {
      throw new Error('wrapped_data_key envelope is missing required fields');
    }
    return {
      kdfVersion: KDF_V2_ARGON2ID,
      envelopeVersion: 2,
      dekChain: [{ gen: 1, wrappings: [{ factor: FACTOR_PASSWORD, wrappedBase64: wrapped }] }],
      wrappedBase64: wrapped,
      kdfParams: (parsed['kdf_params'] as Argon2idParams | undefined) ?? null,
      recovery: null,
    };
  }

  if (parsed['v'] === 3 && parsed['kdf'] === 'argon2id') {
    const dekChainRaw = parsed['dek_chain'];
    if (!Array.isArray(dekChainRaw) || dekChainRaw.length === 0) {
      throw new Error('v3 wrapped_data_key envelope must have a non-empty dek_chain');
    }
    const chain: DekChainEntry[] = dekChainRaw.map((entry: unknown, idx: number) => {
      const e = entry as Record<string, unknown> | null;
      if (
        !e ||
        typeof e !== 'object' ||
        typeof e['gen'] !== 'number' ||
        !Number.isInteger(e['gen']) ||
        (e['gen'] as number) < 1 ||
        typeof e['wrapped'] !== 'string'
      ) {
        throw new Error(`v3 wrapped_data_key envelope dek_chain[${idx}] is malformed`);
      }
      return {
        gen: e['gen'] as number,
        wrappings: [{ factor: FACTOR_PASSWORD, wrappedBase64: e['wrapped'] as string }],
      };
    });
    const seen = new Set<number>();
    for (const e of chain) {
      if (seen.has(e.gen)) {
        throw new Error(`v3 wrapped_data_key envelope has duplicate gen: ${e.gen}`);
      }
      seen.add(e.gen);
    }
    chain.sort((a, b) => a.gen - b.gen);
    const top = chain[chain.length - 1]!;
    return {
      kdfVersion: KDF_V2_ARGON2ID,
      envelopeVersion: 3,
      dekChain: chain,
      wrappedBase64: top.wrappings[0]!.wrappedBase64,
      kdfParams: (parsed['kdf_params'] as Argon2idParams | undefined) ?? null,
      recovery: null,
    };
  }

  if (parsed['v'] === 4 && parsed['kdf'] === 'argon2id') {
    const dekChainRaw = parsed['dek_chain'];
    if (!Array.isArray(dekChainRaw) || dekChainRaw.length === 0) {
      throw new Error('v4 wrapped_data_key envelope must have a non-empty dek_chain');
    }
    const chain: DekChainEntry[] = dekChainRaw.map((entry: unknown, idx: number) => {
      const e = entry as Record<string, unknown> | null;
      if (
        !e ||
        typeof e !== 'object' ||
        typeof e['gen'] !== 'number' ||
        !Number.isInteger(e['gen']) ||
        (e['gen'] as number) < 1 ||
        !Array.isArray(e['wrappings']) ||
        (e['wrappings'] as unknown[]).length === 0
      ) {
        throw new Error(`v4 wrapped_data_key envelope dek_chain[${idx}] is malformed`);
      }
      const wrappings: ChainWrapping[] = (e['wrappings'] as unknown[]).map((w: unknown, wIdx: number) => {
        const wo = w as Record<string, unknown> | null;
        if (
          !wo ||
          typeof wo !== 'object' ||
          typeof wo['factor'] !== 'string' ||
          (wo['factor'] as string).length === 0 ||
          typeof wo['wrapped'] !== 'string'
        ) {
          throw new Error(`v4 wrapped_data_key envelope dek_chain[${idx}].wrappings[${wIdx}] is malformed`);
        }
        return { factor: wo['factor'] as string, wrappedBase64: wo['wrapped'] as string };
      });
      // No two wrappings in the same entry should share a factor name.
      const factorSeen = new Set<string>();
      for (const w of wrappings) {
        if (factorSeen.has(w.factor)) {
          throw new Error(`v4 wrapped_data_key envelope dek_chain[${idx}] has duplicate factor: ${w.factor}`);
        }
        factorSeen.add(w.factor);
      }
      return { gen: e['gen'] as number, wrappings };
    });
    const seen = new Set<number>();
    for (const e of chain) {
      if (seen.has(e.gen)) {
        throw new Error(`v4 wrapped_data_key envelope has duplicate gen: ${e.gen}`);
      }
      seen.add(e.gen);
    }
    chain.sort((a, b) => a.gen - b.gen);

    let recovery: RecoveryMetadata | null = null;
    const recoveryRaw = parsed['recovery'];
    if (recoveryRaw) {
      const r = recoveryRaw as Record<string, unknown>;
      if (
        !r ||
        typeof r !== 'object' ||
        r['kdf'] !== 'argon2id' ||
        !r['kdf_params'] ||
        typeof r['salt'] !== 'string'
      ) {
        throw new Error('v4 wrapped_data_key envelope has malformed recovery block');
      }
      const saltBytes = base64ToBytesRaw(r['salt'] as string);
      if (saltBytes.length !== RECOVERY_SALT_LEN) {
        throw new Error(`v4 recovery.salt must decode to ${RECOVERY_SALT_LEN} bytes, got ${saltBytes.length}`);
      }
      recovery = {
        kdf: 'argon2id',
        kdfParams: r['kdf_params'] as Argon2idParams,
        salt: saltBytes,
      };
    }

    // Convenience field: highest-gen `password` wrapping (current write-side
    // wrapping). If there is no password wrapping at the current gen (would be
    // unusual — all current writers include one) fall back to the first
    // wrapping at the current gen.
    const top = chain[chain.length - 1]!;
    const pw = top.wrappings.find(w => w.factor === FACTOR_PASSWORD);
    const wrappedBase64 = (pw ?? top.wrappings[0]!).wrappedBase64;

    return {
      kdfVersion: KDF_V2_ARGON2ID,
      envelopeVersion: 4,
      dekChain: chain,
      wrappedBase64,
      kdfParams: (parsed['kdf_params'] as Argon2idParams | undefined) ?? null,
      recovery,
    };
  }

  throw new Error(`Unsupported wrapped_data_key envelope version: v=${String(parsed['v'])} kdf=${String(parsed['kdf'])}`);
}

/**
 * Unwrap the data encryption key from the wire format. For backward compat
 * with the v1/v2 single-key shape, returns the highest-gen DEK as `dataKey`.
 *
 * For v3 envelopes, prefer {@link unwrapDataKeyChain} which returns the full
 * generation map needed to read older blobs.
 */
export async function unwrapDataKeyEnvelope(
  wireValue: string,
  unwrappingKey: CryptoKey,
): Promise<{ dataKey: CryptoKey; kdfVersion: KdfVersion; kdfParams: Argon2idParams | null }> {
  const parsed = parseWrappedDataKey(wireValue);
  const dataKey = await unwrapDataKey(parsed.wrappedBase64, unwrappingKey);
  return { dataKey, kdfVersion: parsed.kdfVersion, kdfParams: parsed.kdfParams };
}

/** Result of unwrapping every DEK in a chain via a chosen factor's KEK. */
export type UnwrappedDekChain = {
  dekByGen: Map<number, DataKeyPair>;
  currentGen: number;
  envelopeVersion: EnvelopeVersion;
  kdfVersion: KdfVersion;
  kdfParams: Argon2idParams | null;
  recovery: RecoveryMetadata | null;
};

/**
 * Unwrap every DEK in the chain via the named factor (defaults to
 * `FACTOR_PASSWORD`). Returns a Map keyed by generation plus the current
 * (highest) generation number. Always returns a Map even for legacy single-key
 * envelopes — they expose a synthetic password wrapping per entry.
 *
 * Each value is a pair of WebCrypto handles for the same 32-byte DEK:
 *   - `gcmKey`: AES-GCM, extractable
 *   - `kwKey`:  AES-KW, used to wrap/unwrap per-content CEKs
 */
export async function unwrapDataKeyChain(
  wireValue: string,
  unwrappingKey: CryptoKey,
  factor: string = FACTOR_PASSWORD,
): Promise<UnwrappedDekChain> {
  const parsed = parseWrappedDataKey(wireValue);
  const dekByGen = new Map<number, DataKeyPair>();
  for (const entry of parsed.dekChain) {
    const wrapping = entry.wrappings.find(w => w.factor === factor);
    if (!wrapping) {
      throw new Error(`No '${factor}' wrapping for gen ${entry.gen}`);
    }
    const wrapped = base64ToBytesRaw(wrapping.wrappedBase64);
    const [gcmKey, kwKey] = await Promise.all([
      crypto.subtle.unwrapKey(
        'raw', bs(wrapped), unwrappingKey, 'AES-KW',
        { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'],
      ),
      crypto.subtle.unwrapKey(
        'raw', bs(wrapped), unwrappingKey, 'AES-KW',
        'AES-KW', false, ['wrapKey', 'unwrapKey'],
      ),
    ]);
    dekByGen.set(entry.gen, { gcmKey, kwKey });
  }
  const currentGen = parsed.dekChain[parsed.dekChain.length - 1]!.gen;
  return {
    dekByGen,
    currentGen,
    envelopeVersion: parsed.envelopeVersion,
    kdfVersion: parsed.kdfVersion,
    kdfParams: parsed.kdfParams,
    recovery: parsed.recovery,
  };
}

/** Build a v3 envelope from a chain of (gen, raw_wrapped_base64) pairs. */
export function buildV3Envelope(
  chain: ReadonlyArray<{ gen: number; wrappedBase64: string }>,
): WrappedDataKeyEnvelope {
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new Error('chain must be a non-empty array');
  }
  const sorted = chain.slice().sort((a, b) => a.gen - b.gen);
  return asEnvelope(JSON.stringify({
    v: 3,
    kdf: 'argon2id',
    kdf_params: { m_kib: ARGON2ID_MEMORY_KIB, t: ARGON2ID_ITERATIONS, p: ARGON2ID_PARALLELISM },
    dek_chain: sorted.map(e => ({ gen: e.gen, wrapped: e.wrappedBase64 })),
  }));
}

/**
 * Wrap an array of DEK CryptoKeys (one per generation) under the given
 * wrapping key and pack into a v3 envelope.
 */
export async function wrapDataKeyChainEnvelope(
  chain: ReadonlyArray<{ gen: number; key: CryptoKey }>,
  wrappingKey: CryptoKey,
): Promise<WrappedDataKeyEnvelope> {
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new Error('chain must be a non-empty array');
  }
  const wrapped: Array<{ gen: number; wrappedBase64: string }> = [];
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

/** Generate a fresh random salt for the recovery KDF (per-account, 16 bytes). */
export function generateRecoverySalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(RECOVERY_SALT_LEN));
}

export type V4FactorInput = { name: string; wrappingKey: CryptoKey };
export type V4ChainEntry = { gen: number; wrappings: ChainWrapping[] };
export type V4Recovery = { salt: Uint8Array; kdfParams?: Argon2idParams } | null;

/**
 * Build a v4 envelope from a chain whose entries each carry one or more
 * already-wrapped factors (raw base64 ciphertexts).
 */
export function buildV4Envelope(
  chain: ReadonlyArray<V4ChainEntry>,
  recovery: V4Recovery,
): WrappedDataKeyEnvelope {
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
  const sorted: V4ChainEntry[] = chain.slice().sort((a, b) => a.gen - b.gen);

  // If any entry references a recovery_phrase wrapping, the envelope MUST
  // carry the recovery metadata block.
  const hasRecoveryWrap = sorted.some((e: V4ChainEntry) =>
    e.wrappings.some((w: ChainWrapping) => w.factor === FACTOR_RECOVERY_PHRASE),
  );
  if (hasRecoveryWrap && !recovery) {
    throw new Error('chain has recovery_phrase wrappings but no recovery metadata supplied');
  }

  const out: Record<string, unknown> = {
    v: 4,
    kdf: 'argon2id',
    kdf_params: { m_kib: ARGON2ID_MEMORY_KIB, t: ARGON2ID_ITERATIONS, p: ARGON2ID_PARALLELISM },
  };
  if (recovery) {
    if (!(recovery.salt instanceof Uint8Array) || recovery.salt.length !== RECOVERY_SALT_LEN) {
      throw new Error(`recovery.salt must be a Uint8Array of length ${RECOVERY_SALT_LEN}`);
    }
    out['recovery'] = {
      kdf: 'argon2id',
      kdf_params: recovery.kdfParams ?? {
        m_kib: ARGON2ID_MEMORY_KIB,
        t: ARGON2ID_ITERATIONS,
        p: ARGON2ID_PARALLELISM,
      },
      salt: bytesToBase64Raw(recovery.salt),
    };
  }
  out['dek_chain'] = sorted.map((e: V4ChainEntry) => ({
    gen: e.gen,
    wrappings: e.wrappings.map((w: ChainWrapping) => ({ factor: w.factor, wrapped: w.wrappedBase64 })),
  }));
  return asEnvelope(JSON.stringify(out));
}

/**
 * Wrap a chain of DEK CryptoKeys under one or more factors and pack into a v4
 * envelope. Each chain entry is wrapped independently under every factor.
 */
export async function wrapDataKeyChainEnvelopeV4(
  chain: ReadonlyArray<{ gen: number; key: CryptoKey }>,
  factors: ReadonlyArray<V4FactorInput>,
  recovery: V4Recovery,
): Promise<WrappedDataKeyEnvelope> {
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
  const seenFactors = new Set<string>();
  for (const f of factors) {
    if (seenFactors.has(f.name)) throw new Error(`Duplicate factor name: ${f.name}`);
    seenFactors.add(f.name);
  }
  const hasRecoveryFactor = factors.some(f => f.name === FACTOR_RECOVERY_PHRASE);
  if (hasRecoveryFactor && !recovery) {
    throw new Error('recovery metadata is required when factors include recovery_phrase');
  }

  const wrappedChain: V4ChainEntry[] = [];
  for (const entry of chain) {
    if (!entry || typeof entry.gen !== 'number' || !entry.key) {
      throw new Error('chain entries must be {gen: number, key: CryptoKey}');
    }
    const wrappings: ChainWrapping[] = [];
    for (const f of factors) {
      const wrappedBase64 = await wrapDataKey(entry.key, f.wrappingKey);
      wrappings.push({ factor: f.name, wrappedBase64 });
    }
    wrappedChain.push({ gen: entry.gen, wrappings });
  }
  return buildV4Envelope(wrappedChain, recovery);
}

// ============ CHALLENGE SIGNING ============

/** Sign a nonce with the ECDSA P-256 private key. Returns base64-encoded raw signature. */
export async function signChallenge(privateKey: CryptoKey, nonceHex: string): Promise<Base64> {
  const nonceBytes = hexToBytes(nonceHex);
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, privateKey, bs(nonceBytes),
  );
  return asBase64(bytesToBase64Raw(new Uint8Array(signature)));
}

// ============ CONVENIENCE: DERIVE ALL KEYS ============

export type AllKeys = {
  masterKey: Uint8Array;
  credentialLookupKey: LookupKey;
  credentialEncryptionKey: DataKeyHandles;
  signingKeyPair: SigningKeyPair;
  sharingKeyPair: SharingKeyPair;
  kdfVersion: KdfVersion;
};

/**
 * Derive all keys from email + password + app in one call.
 *
 * Also derives the sharing keypair (issue #13) so callers that need to publish
 * a `share_pub` (register, changeCredentials) get it without an extra HKDF
 * call. The keypair is per-app — `share_pub` for the same email+password
 * differs across `app_id` values, just like the existing sub-keys.
 */
export async function deriveAllKeys(
  email: string,
  password: string,
  appId: string,
  kdfVersion: KdfVersion = KDF_DEFAULT,
): Promise<AllKeys> {
  if (!appId) throw new Error('appId is required');
  const masterKey = await deriveMasterKey(email, password, kdfVersion);
  const [credentialLookupKey, credentialEncryptionKey, signingKeyPair, sharingKeyPair] = await Promise.all([
    deriveCredentialLookupKey(masterKey, appId),
    deriveCredentialEncryptionKey(masterKey, appId),
    deriveSigningKeyPair(masterKey, appId),
    deriveSharingKeyPair(masterKey, appId),
  ]);
  return { masterKey, credentialLookupKey, credentialEncryptionKey, signingKeyPair, sharingKeyPair, kdfVersion };
}

// ============ ENCODING HELPERS ============

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  return bytes;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) result = (result << 8n) | BigInt(b);
  return result;
}

// Internal raw versions (return plain `string`, not branded). Public wrappers
// further down brand the result.
function bytesToBase64Raw(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

function base64ToBytesRaw(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToBase64UrlRaw(bytes: Uint8Array): string {
  return bytesToBase64Raw(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytesRaw(b64url: string): Uint8Array {
  const padded = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  return base64ToBytesRaw(padded + '='.repeat(padLen));
}

// Public encoding helpers — keep `string` returns to match the existing JS
// surface (callers haven't been migrated to brands yet). The branded
// constructors are available internally for new code that wants the
// type-safety.
export function bytesToBase64(bytes: Uint8Array): string {
  return bytesToBase64Raw(bytes);
}

export function base64ToBytes(base64: string): Uint8Array {
  return base64ToBytesRaw(base64);
}

// Base64url (RFC 4648 §5) — `+` → `-`, `/` → `_`, no padding. Used by the
// sharing design's `B(x)` notation (sharing §2) for `share_pub` and other
// share-log values where URL/tag safety matters.
export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64UrlRaw(bytes);
}

export function base64UrlToBytes(b64url: string): Uint8Array {
  return base64UrlToBytesRaw(b64url);
}
