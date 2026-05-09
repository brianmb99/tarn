/**
 * Envelope decoder façade — re-exports from the version-dispatched
 * `./envelope/` subpackage so legacy import sites
 * (`from '../crypto/envelope.js'`) keep working.
 *
 * **Adding a new envelope version:** edit `./envelope/index.ts` and add a
 * `./envelope/vN.ts` module. Do NOT add per-version code here — this file
 * is a stable surface for callers that only need the cross-version shapes.
 *
 * The forward-compatibility contract for envelope decoders lives in
 * `./envelope/index.ts` and `recover/fixtures/README.md`.
 */

export {
  ENVELOPE_VERSION,
  parseWrappedDataKey,
  unwrapDataKeyChain,
  readEnvelopeVersion,
  type EnvelopeVersion,
  type ParsedWrappedDataKey,
  type UnwrappedDekChain,
  // Per-version pieces — exported so fixture-suite tests and debug tooling
  // can pin to a specific version intentionally.
  parseEnvelopeV1,
  unwrapEnvelopeV1,
  ENVELOPE_V1_VERSION,
  type EnvelopeV1Version,
  type ParsedEnvelopeV1,
  type UnwrappedEnvelopeV1,
  type ChainWrapping,
  type DekChainEntry,
} from './envelope/index.js';
