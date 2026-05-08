/**
 * `@tarn/recover` — standalone, server-free recovery for Tarn-backed accounts.
 *
 * Phase 2 status: this entry point currently re-exports the gateway-direct
 * read primitives only. The `recover()` orchestrator, the schema-aware
 * reader, and the sharing/connections surface land in later phases (see
 * `docs/STANDALONE_RECOVERY_PLAN.md`).
 *
 * For Phase 2, consumers can drive the gateway primitives directly:
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
 */

export * from './gateway/index.js';
