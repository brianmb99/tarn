/**
 * Shared crypto types — borrowed verbatim from `client/src/crypto.ts`.
 */

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

/** Argon2id parameter object as stored in envelope KDF metadata. */
export type Argon2idParams = {
  m_kib: number;
  t: number;
  p: number;
};

/** v1 envelope recovery-factor metadata. */
export type RecoveryMetadata = {
  kdf: 'argon2id';
  kdfParams: Argon2idParams;
  salt: Uint8Array;
};
