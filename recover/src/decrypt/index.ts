/**
 * Public surface of the unwrap pipeline.
 *
 * Two entry points:
 *   - `derivePasswordKEK` / `deriveRecoveryKEK` — produce the AES-KW
 *     handle for a given factor.
 *   - `unwrapDekChain` — consume that handle plus the envelope string,
 *     return the per-gen DEK map.
 *
 * Typical use:
 *
 *   import { parseEnvelope, deriveRecoveryKEK, unwrapDekChain } from '@tarn/recover';
 *
 *   const parsed = parseEnvelope(envelopeJson);
 *   const kek = await deriveRecoveryKEK({
 *     accountKey: '<24 words>',
 *     recoverySalt: parsed.recovery.salt,
 *     kdfParams: parsed.recovery.kdfParams,
 *   });
 *   const { dekByGen, currentGen } = await unwrapDekChain({
 *     envelope: envelopeJson,
 *     kek,
 *     factor: 'recovery_phrase',
 *   });
 */

export {
  derivePasswordKEK,
  deriveRecoveryKEK,
  type DerivePasswordKEKArgs,
  type DeriveRecoveryKEKArgs,
} from './derive-keys.js';

export {
  unwrapDekChain,
  parseEnvelope,
  type RecoverFactor,
  type UnwrapDekChainArgs,
  type ParsedWrappedDataKey,
  type UnwrappedDekChain,
} from './unwrap-envelope.js';
