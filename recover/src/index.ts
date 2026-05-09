/**
 * `@tarn/recover` — standalone, server-free recovery for Tarn-backed accounts.
 *
 * Phase 3 status: this entry point now re-exports both the gateway-direct
 * read primitives (Phase 2) and the crypto / unwrap pipeline (Phase 3).
 * The `recover()` orchestrator and the schema-aware reader land in later
 * phases (see `docs/STANDALONE_RECOVERY_PLAN.md`).
 *
 * Phase 2 surface — gateway-direct read primitives:
 *
 *   import { makeMultiGatewayClient, findCredentialBlob } from '@tarn/recover';
 *
 *   const client = makeMultiGatewayClient([
 *     'https://arweave.net',
 *     'https://g8way.io',
 *   ]);
 *
 *   const blob = await findCredentialBlob(client, {
 *     recoveryLookupKey: '<64-hex>',
 *   });
 *
 * Phase 3 surface — KDFs + envelope unwrap (browser-side decrypt path):
 *
 *   import {
 *     parseEnvelope,
 *     deriveRecoveryKEK,
 *     unwrapDekChain,
 *     decryptWithCEK,
 *   } from '@tarn/recover';
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
 *   // dekByGen.get(currentGen) is the latest DEK; pass to decryptWithCEK
 *   // alongside an Arweave-fetched per-content-CEK blob.
 */

export * from './gateway/index.js';

// Borrowed crypto primitives — pure WebCrypto + hash-wasm + @scure/bip39.
// See `src/crypto/index.ts` for the cross-validation contract.
export * from './crypto/index.js';

// Phase 3 unwrap pipeline — derive-KEK + unwrap-envelope.
export * from './decrypt/index.js';
