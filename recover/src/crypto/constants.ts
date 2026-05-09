/**
 * Crypto constants — borrowed verbatim from `client/src/crypto.ts`.
 *
 * Argon2id parameters, key sizes, magic prefix bytes, factor names. These
 * mirror the wire-protocol values in `docs/TARN_PROTOCOL.md` §2/§4 and MUST
 * stay byte-identical to the writer-side values in `client/src/crypto.ts`.
 */

// Argon2id — m=64 MiB, t=3, p=1. OWASP-recommended for password-derived KEKs.
export const ARGON2ID_MEMORY_KIB = 64 * 1024;
export const ARGON2ID_ITERATIONS = 3;
export const ARGON2ID_PARALLELISM = 1;

export const KEY_LENGTH_BITS = 256;
export const KEY_LENGTH_BYTES = 32;

// Structured HKDF info: protocol || purpose || app_id || version || counter
export const PROTOCOL_ID = 'tarn';
export const DERIVATION_VERSION = '1';

// Recovery factor — 16-byte per-account random salt for the recovery KEK
// (Argon2id), stored in the v1 envelope's `recovery.salt` field.
export const RECOVERY_SALT_LEN = 16;

// Per-content CEK blob (issue #11) — 5-byte magic prefix.
//   magic = "TARN" || version_byte (0x02)
// Layout: magic(5) || wrapped_CEK(40) || iv(12) || ciphertext+tag(N+16).
export const TARN_BLOB_MAGIC = new Uint8Array([0x54, 0x41, 0x52, 0x4e, 0x02]);
export const TARN_BLOB_MAGIC_LEN = TARN_BLOB_MAGIC.length;
export const TARN_WRAPPED_CEK_LEN = 40; // 32-byte CEK + 8-byte AES-KW overhead
export const CEK_LEN_BYTES = 32;
export const IV_LEN_BYTES = 12;
export const GCM_TAG_LEN_BYTES = 16;

// Wrapping factors. Every account currently carries `password` and
// `recovery_phrase`; `passkey_prf` is forward-compat for Phase 6.
export const FACTOR_PASSWORD = 'password' as const;
export const FACTOR_RECOVERY_PHRASE = 'recovery_phrase' as const;
export const FACTOR_PASSKEY_PRF = 'passkey_prf' as const;
export type Factor =
  | typeof FACTOR_PASSWORD
  | typeof FACTOR_RECOVERY_PHRASE
  | typeof FACTOR_PASSKEY_PRF;

/** Fixed AAD on the `wrapped_account_key` envelope. */
export const WRAPPED_ACCOUNT_KEY_AAD = new TextEncoder().encode(
  'tarn-wrapped-account-key-v1',
);
