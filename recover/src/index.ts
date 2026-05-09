/**
 * `@tarn/recover` — standalone, server-free recovery for Tarn-backed accounts.
 *
 * Public surface (through Phase 5):
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
 *   const peers = await reader.connections();
 *   for await (const event of reader.shareLog({ direction: 'incoming' })) {
 *     // typed event union: add | update | rotate | remove | snapshot |
 *     // rotate_identity, with `connection`, `seq`, `verified` metadata
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
 *   - Connections + per-pair share-log replay (Phase 5). Note:
 *     **only the password factor lights up the sharing surface** — the
 *     account-key path cannot derive the X25519 share keypair (see
 *     `crypto/share-key.ts`). On the account-key factor `connections()`
 *     returns `[]` and the share-log iterators yield nothing.
 *
 * Not in this phase (see `docs/STANDALONE_RECOVERY_PLAN.md` for the
 * full roadmap):
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
  // Phase 5 sharing surface
  SharingReader,
  replayConnection,
  type SharingReaderInit,
  type Connection,
  type ShareLogEvent,
  type ShareLogEntryBase,
  type ShareLogDirection,
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
export * from './sharing/index.js';
