/**
 * Envelope unwrap — Phase 3 entry point.
 *
 * Given a parsed v1 envelope and a factor's AES-KW KEK, unwrap every DEK
 * in the chain. The output is the same shape `client/src/crypto.ts`
 * `unwrapDataKeyChain` produces (see the `UnwrappedDekChain` type) so
 * downstream phases can drop in code that today operates on
 * `TarnClient.#dekByGen` without translating.
 */

import {
  parseWrappedDataKey,
  unwrapDataKeyChain,
  type ParsedWrappedDataKey,
  type UnwrappedDekChain,
} from '../crypto/envelope.js';
import {
  FACTOR_PASSWORD,
  FACTOR_RECOVERY_PHRASE,
  type Factor,
} from '../crypto/constants.js';

/**
 * Re-export the parsed-envelope type so consumers can type their inputs
 * without reaching into the crypto module.
 */
export type { ParsedWrappedDataKey, UnwrappedDekChain };

/** Phase 3 supports the two user-facing factors. `passkey_prf` is Phase 6. */
export type RecoverFactor = typeof FACTOR_PASSWORD | typeof FACTOR_RECOVERY_PHRASE;

export type UnwrapDekChainArgs = {
  /**
   * The wrapped-data-key wire string (the JSON envelope as published in
   * the credential blob's `wrapped_data_key` field).
   */
  envelope: string;
  /** AES-KW handle from `derivePasswordKEK` or `deriveRecoveryKEK`. */
  kek: CryptoKey;
  /** Which factor's wrapping to consume. */
  factor: RecoverFactor;
};

/**
 * Unwrap every DEK in the envelope's chain via the named factor's KEK.
 *
 * Returns a `UnwrappedDekChain` (Map of gen → DEK handles) — the same
 * shape used internally by `client/src/crypto.ts`. Each value carries
 * both an AES-GCM handle (for legacy raw-DEK blobs and per-content-CEK
 * unwrap) and an AES-KW handle (for nested key-wrap chains).
 */
export async function unwrapDekChain(
  args: UnwrapDekChainArgs,
): Promise<UnwrappedDekChain> {
  const { envelope, kek, factor } = args;
  if (!envelope || typeof envelope !== 'string') {
    throw new Error('unwrapDekChain: envelope must be a non-empty string');
  }
  if (!kek) {
    throw new Error('unwrapDekChain: kek (AES-KW CryptoKey) is required');
  }
  if (factor !== FACTOR_PASSWORD && factor !== FACTOR_RECOVERY_PHRASE) {
    throw new Error(
      `unwrapDekChain: unsupported factor '${factor}' — Phase 3 only supports '${FACTOR_PASSWORD}' and '${FACTOR_RECOVERY_PHRASE}'`,
    );
  }
  return await unwrapDataKeyChain(envelope, kek, factor as Factor);
}

/**
 * Convenience wrapper: parse the envelope only (no unwrap), useful when a
 * caller wants the recovery salt + KDF params before deriving the
 * recovery KEK (the standard recovery flow).
 */
export function parseEnvelope(envelope: string): ParsedWrappedDataKey {
  return parseWrappedDataKey(envelope);
}
