/**
 * `@tarn/recover` — standalone, server-free recovery for Tarn-backed accounts.
 *
 * Public surface (Phase 4):
 *
 *   import { recover } from '@tarn/recover';
 *
 *   const reader = await recover({
 *     appId: 'bookish',
 *     schema: bookishSchema,
 *     arweaveGateways: ['https://arweave.net', 'https://g8way.io'],
 *     credentials: { type: 'password', username, password },
 *     // OR: credentials: { type: 'accountKey', accountKey },
 *     onProgress: (stage, info) => { ... },
 *   });
 *
 *   for await (const book of reader.entries('books')) {
 *     render(book);
 *   }
 *
 * What's covered:
 *   - Both credential factors (`password` / `accountKey`) end-to-end.
 *   - Multi-gateway fallback for every Arweave fetch (Phase 2).
 *   - Multi-gen DEK chain unwrap (Phase 3) — accounts that have rotated
 *     credentials decrypt content from every generation correctly.
 *   - Tombstone application + Eid + Prev-chain resolution, ported from
 *     the server-side resolver (`api/src/cache.js` `resolveEntries`).
 *   - Schema-version marker (`_schemaVersion`) on entries written under
 *     a schema version older than the caller's.
 *
 * Not in this phase (see `docs/STANDALONE_RECOVERY_PLAN.md` for the
 * full roadmap):
 *   - Sharing / connections / share-log iteration (Phase 5).
 *   - Forward-compat fixture suite (Phase 6).
 *   - Reference HTML in `examples/` (Phase 7).
 *   - README + forward-compat contract (Phase 8).
 *   - Arweave-publish of the example HTML (Phase 9).
 */

// === Public entry point + reader surface ===

export { recover } from './recover.js';
export type { RecoverOptions, RecoverCredentials } from './recover.js';
export {
  Reader,
  type DecryptedEntry,
  type ReaderInit,
  type ReaderSchema,
  type ReaderAccount,
} from './reader/index.js';
export type { OnProgress, RecoverStage, RecoverProgress } from './progress.js';

// === Re-exports from earlier phases ===
//
// These remain accessible so callers that need lower-level primitives
// (e.g., bespoke reader logic, fixture-vault tooling) don't have to
// reach into deep paths.

export * from './gateway/index.js';
export * from './crypto/index.js';
export * from './decrypt/index.js';
