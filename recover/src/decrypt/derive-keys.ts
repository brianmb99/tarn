/**
 * Factor-KEK derivation for the recovery pipeline.
 *
 * Given user-supplied factor inputs, produce the AES-KW unwrapping key
 * (`CryptoKey`) needed to unwrap a v1 envelope's DEK chain.
 *
 * Two factors are supported in Phase 3:
 *   - `password` — `(username, password)` → master_key (Argon2id) →
 *     credential_encryption_key (HKDF) → AES-KW handle.
 *   - `recovery_phrase` — `(account_key, recovery_salt, kdf_params)` →
 *     recovery KEK (Argon2id) → AES-KW handle.
 *
 * The third factor (`passkey_prf`) is forward-compat infrastructure and
 * will be wired in Phase 6 alongside the v2 envelope.
 */

import {
  deriveCredentialEncryptionKey,
  deriveMasterKey,
  deriveRecoveryKey,
} from '../crypto/kdf.js';
import type { Argon2idParams } from '../crypto/types.js';

export type DerivePasswordKEKArgs = {
  /** As-typed username — normalization happens inside `deriveMasterKey`. */
  username: string;
  /** As-typed password. */
  password: string;
  /** App identifier (used to per-app-isolate the credential KEK). */
  appId: string;
};

/**
 * Derive the AES-KW unwrapping key for the `password` factor.
 *
 * Returns the AES-KW WebCrypto handle directly — pass it to
 * `unwrapDekChain(envelope, kek, 'password')`.
 */
export async function derivePasswordKEK(
  args: DerivePasswordKEKArgs,
): Promise<CryptoKey> {
  const { username, password, appId } = args;
  if (!username || typeof username !== 'string') {
    throw new Error('derivePasswordKEK: username must be a non-empty string');
  }
  if (!password || typeof password !== 'string') {
    throw new Error('derivePasswordKEK: password must be a non-empty string');
  }
  if (!appId || typeof appId !== 'string') {
    throw new Error('derivePasswordKEK: appId must be a non-empty string');
  }
  const masterKey = await deriveMasterKey(username, password);
  const cek = await deriveCredentialEncryptionKey(masterKey, appId);
  return cek.kwKey;
}

export type DeriveRecoveryKEKArgs = {
  /** 24-word account key as the user typed it (normalization is internal). */
  accountKey: string;
  /**
   * Per-account 16-byte salt — comes from the parsed envelope's
   * `recovery.salt` field, not the user.
   */
  recoverySalt: Uint8Array;
  /**
   * Argon2id parameters from the envelope's `recovery.kdf_params` field.
   * Defaults to the OWASP-recommended (m=64MiB, t=3, p=1) when omitted —
   * but well-formed v1 envelopes always carry the params, so callers
   * should pass them through verbatim.
   */
  kdfParams?: Partial<Argon2idParams>;
};

/**
 * Derive the AES-KW unwrapping key for the `recovery_phrase` factor.
 *
 * The salt and KDF params live IN the envelope, not in the user's head —
 * call `parseWrappedDataKey()` first, then pass `parsed.recovery.salt` and
 * `parsed.recovery.kdfParams` here.
 *
 * Returns the AES-KW WebCrypto handle directly — pass it to
 * `unwrapDekChain(envelope, kek, 'recovery_phrase')`.
 */
export async function deriveRecoveryKEK(
  args: DeriveRecoveryKEKArgs,
): Promise<CryptoKey> {
  const { accountKey, recoverySalt, kdfParams } = args;
  if (!accountKey || typeof accountKey !== 'string') {
    throw new Error('deriveRecoveryKEK: accountKey must be a non-empty string');
  }
  if (!(recoverySalt instanceof Uint8Array)) {
    throw new Error('deriveRecoveryKEK: recoverySalt must be a Uint8Array');
  }
  const handles = await deriveRecoveryKey(accountKey, recoverySalt, kdfParams);
  return handles.kwKey;
}
