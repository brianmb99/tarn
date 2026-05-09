/**
 * Envelope decoder dispatch — version-aware entry point.
 *
 * # Forward-compatibility contract (constitutional)
 *
 * Every wrapped-data-key envelope on Arweave carries a top-level `v` field.
 * `@tarn/recover` MUST decode every version it has ever supported, forever.
 * Adding a new envelope version is an **additive** operation:
 *
 *   1. Add `./vN.ts` with `parseEnvelopeVN` + `unwrapEnvelopeVN`.
 *   2. Register it in {@link DECODERS_BY_VERSION} below.
 *   3. Add fixtures to `recover/fixtures/envelope-vN-*` (see
 *      `recover/fixtures/README.md`).
 *
 * What you MUST NOT do:
 *   - Delete an existing version module.
 *   - Modify an existing version module's wire interpretation.
 *   - Replace `vN` with a "cleaned-up vN" — instead, ship `v(N+1)`.
 *
 * The fixture suite (`recover/tests/forward-compat.test.ts`) and the
 * fixture-vault meta-test (`recover/tests/fixture-vault.test.ts`) enforce
 * these rules at CI time. See `recover/fixtures/README.md` for the full
 * contract narrative.
 *
 * # Why dispatch lives here
 *
 * The single entry point keeps "what version did the writer publish?" out
 * of every consumer. Callers see one shape (`UnwrappedDekChain`) regardless
 * of the on-wire version; the dispatch handles routing.
 */

import {
  parseEnvelopeV1,
  unwrapEnvelopeV1,
  type ParsedEnvelopeV1,
  type UnwrappedEnvelopeV1,
} from './v1.js';
import { FACTOR_PASSWORD } from '../constants.js';
import type { Argon2idParams, DataKeyPair, RecoveryMetadata } from '../types.js';

/** Union of every envelope version `@tarn/recover` has ever supported. */
export type EnvelopeVersion = 1;

/** The "current" envelope version writers emit. Bumped only when a new version ships. */
export const ENVELOPE_VERSION: EnvelopeVersion = 1;

/**
 * Per-version decoder. Each version provides:
 *  - `parse(parsedJson)`: structural validation + shape extraction.
 *  - `unwrap(parsed, kek, factor, credentialId?)`: the crypto step.
 *
 * Both yield the version-specific shape; the public {@link parseWrappedDataKey}
 * + {@link unwrapDataKeyChain} normalize to the cross-version shapes
 * {@link ParsedWrappedDataKey} / {@link UnwrappedDekChain}.
 */
type Decoder<TParsed extends { envelopeVersion: EnvelopeVersion }, TUnwrapped> = {
  parse: (json: Record<string, unknown>) => TParsed;
  unwrap: (
    parsed: TParsed,
    kek: CryptoKey,
    factor: string,
    credentialId?: string,
  ) => Promise<TUnwrapped>;
};

/**
 * Dispatch table: envelope-version-byte → decoder module.
 *
 * **Adding a new version is the only allowed mutation.** Removing or replacing
 * an entry is a contract violation.
 */
const DECODERS_BY_VERSION: Record<EnvelopeVersion, Decoder<ParsedEnvelopeV1, UnwrappedEnvelopeV1>> = {
  1: { parse: parseEnvelopeV1, unwrap: unwrapEnvelopeV1 },
};

/**
 * Cross-version normalized shape for a parsed envelope.
 *
 * The fields are intentionally a subset of every version's shape —
 * downstream code never sees version-specific fields except through
 * `envelopeVersion`. New versions adding new fields surface them via a
 * separate per-version API; never via this type.
 *
 * Re-exported from `../envelope.ts` for backwards compatibility with
 * pre-Phase-6 import sites.
 */
export type ParsedWrappedDataKey = {
  envelopeVersion: EnvelopeVersion;
  dekChain: ParsedEnvelopeV1['dekChain'];
  wrappedBase64: string;
  kdfParams: Argon2idParams;
  recovery: RecoveryMetadata;
};

/** Cross-version normalized shape for an unwrapped DEK chain. */
export type UnwrappedDekChain = {
  dekByGen: Map<number, DataKeyPair>;
  currentGen: number;
  envelopeVersion: EnvelopeVersion;
  kdfParams: Argon2idParams;
  recovery: RecoveryMetadata;
};

/**
 * Read the `v` field off a wire envelope without invoking the version's
 * full parser. Useful for callers that want to decide ahead of time which
 * code path they're entering (e.g. fixture-suite tests).
 *
 * Throws on malformed JSON or missing `v`. Does NOT validate that `v` is
 * a supported version — that happens in {@link parseWrappedDataKey}.
 */
export function readEnvelopeVersion(wireValue: string): number {
  if (typeof wireValue !== 'string' || wireValue.length === 0) {
    throw new Error('wrapped_data_key must be a non-empty string');
  }
  if (wireValue[0] !== '{') {
    throw new Error('wrapped_data_key must be a JSON envelope');
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
  if (typeof parsed['v'] !== 'number') {
    throw new Error('wrapped_data_key envelope is missing a numeric `v` field');
  }
  return parsed['v'] as number;
}

/**
 * Inspect a wire-format `wrapped_data_key` without unwrapping. Dispatches
 * on the envelope's `v` field to the matching decoder; throws if no decoder
 * is registered for that version.
 *
 * The error message on unknown-version explicitly references the
 * forward-compat contract — when a future Tarn writer ships envelope vN,
 * older `@tarn/recover` versions will surface this exact error. The user's
 * remediation is "upgrade `@tarn/recover`," and the contract guarantees
 * upgrading is always safe (no old versions removed).
 */
export function parseWrappedDataKey(wireValue: string): ParsedWrappedDataKey {
  const version = readEnvelopeVersion(wireValue);
  const decoder = DECODERS_BY_VERSION[version as EnvelopeVersion];
  if (!decoder) {
    throw new Error(
      `wrapped_data_key: unsupported envelope version v=${version}. ` +
      `This @tarn/recover release supports versions [${Object.keys(DECODERS_BY_VERSION).join(', ')}]. ` +
      `Upgrade @tarn/recover to read newer envelopes — old versions are never removed (forward-compat contract).`,
    );
  }
  // Safe to re-parse: we already validated JSON in `readEnvelopeVersion`.
  const json = JSON.parse(wireValue) as Record<string, unknown>;
  const parsed = decoder.parse(json);
  // Per-version shapes happen to be field-compatible with the cross-version
  // shape today; if v2 introduces new fields they go on a v2-specific API
  // surface, not here.
  return parsed;
}

/**
 * Unwrap every DEK in the envelope's chain via the named factor's KEK.
 * Dispatches on envelope version under the hood.
 *
 * Returns a {@link UnwrappedDekChain} — the cross-version normalized shape.
 *
 * @param wireValue Wire envelope (the JSON string from `wrapped_data_key`).
 * @param unwrappingKey AES-KW handle from the factor's KEK derivation.
 * @param factor Factor name (default `'password'`).
 * @param credentialId For `passkey_prf` factor only: which passkey wrapping
 *                    to consume.
 */
export async function unwrapDataKeyChain(
  wireValue: string,
  unwrappingKey: CryptoKey,
  factor: string = FACTOR_PASSWORD,
  credentialId?: string,
): Promise<UnwrappedDekChain> {
  const version = readEnvelopeVersion(wireValue);
  const decoder = DECODERS_BY_VERSION[version as EnvelopeVersion];
  if (!decoder) {
    throw new Error(
      `wrapped_data_key: unsupported envelope version v=${version}. ` +
      `This @tarn/recover release supports versions [${Object.keys(DECODERS_BY_VERSION).join(', ')}]. ` +
      `Upgrade @tarn/recover to read newer envelopes — old versions are never removed (forward-compat contract).`,
    );
  }
  const json = JSON.parse(wireValue) as Record<string, unknown>;
  const parsed = decoder.parse(json);
  return await decoder.unwrap(parsed, unwrappingKey, factor, credentialId);
}

// Re-export per-version pieces so consumers that intentionally pin a version
// (fixture tests, debug tooling) can do so explicitly.
export {
  parseEnvelopeV1,
  unwrapEnvelopeV1,
  type ParsedEnvelopeV1,
  type UnwrappedEnvelopeV1,
  type EnvelopeV1Version,
  ENVELOPE_V1_VERSION,
  type ChainWrapping,
  type DekChainEntry,
} from './v1.js';
