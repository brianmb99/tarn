/**
 * Reader — the object returned by {@link import('../recover.js').recover}.
 *
 * Bound to:
 *   - a `MultiGatewayClient` (Phase 2),
 *   - an unwrapped DEK chain (Phase 3),
 *   - a caller-supplied schema (`defineSchema()` output),
 *   - the app id, data lookup key, and account metadata,
 *   - optionally, the user's X25519 sharing keypair (Phase 5 — the
 *     `password` factor derives this from `master_key`; the `accountKey`
 *     factor cannot, see `crypto/share-key.ts` for why).
 *
 * Surface:
 *   - `reader.collections`              — names declared in the schema.
 *   - `reader.account`                  — vintage / structural metadata.
 *   - `reader.tombstoneCount`           — populated after each `entries()` walk.
 *   - `reader.entries(name)`            — async iterator of typed entries.
 *   - `reader.allEntries(name)`         — buffered batch helper.
 *   - `reader.connections()`            — accepted-connections list (Phase 5).
 *   - `reader.shareLog({ direction })`  — async iterator of share-log events.
 *   - `reader.allShareLog({ direction })` — buffered batch helper.
 *
 * The reader caches tombstone counts per collection — every fresh walk
 * overwrites the count so `tombstoneCount` always reflects the most
 * recent collection iterated. Callers that want per-collection counts
 * should sum them themselves; the field is intentionally a simple
 * scalar to match the API plan.
 */

import type { MultiGatewayClient } from '../gateway/multi-gateway.js';
import type { OnProgress as RecoverOnProgress, RecoverProgress } from '../progress.js';
import { findContentBlobs, type BlobRecord } from '../gateway/queries.js';
import { decryptWithCEK } from '../crypto/aes.js';
import type { UnwrappedDekChain } from '../crypto/envelope.js';
import { resolveContentBlobs } from './resolve.js';
import { attachSchemaVersionMarker, type DecryptedEntry } from './decode.js';
import {
  SharingReader,
  type Connection,
  type ShareLogDirection,
  type ShareLogEvent,
} from './sharing-reader.js';

/**
 * Caller-side schema shape consumed by the Reader. We intentionally don't
 * import from `client/src/schema/types.ts` so the recover package stays
 * SDK-independent — apps can pass any object that satisfies this minimal
 * contract (which `defineSchema()` happens to match exactly).
 */
export type ReaderSchema = {
  appId: string;
  version: number;
  collections: Record<string, unknown>;
};

/** Account-level metadata exposed via `reader.account`. */
export type ReaderAccount = {
  appId: string;
  envelopeVersion: number;
  totalGens: number;
  /** Username if the caller authenticated via the password factor; otherwise undefined. */
  username?: string;
};

export interface ReaderInit {
  appId: string;
  schema: ReaderSchema;
  client: MultiGatewayClient;
  dataLookupKey: string;
  dekChain: UnwrappedDekChain;
  account: ReaderAccount;
  onProgress?: RecoverOnProgress;
  /**
   * Optional X25519 sharing keypair (32 raw bytes each). Populated by the
   * `recover()` orchestrator when the password factor is used (the keypair
   * is derived from `master_key`); omitted on the account-key path. When
   * absent, `connections()` returns `[]` and `shareLog(...)` yields nothing
   * — see `recover/src/crypto/share-key.ts` for the architectural reason
   * (the share keypair is rotated whenever credentials change and is not
   * derivable from the recovery factor).
   */
  shareKeyPair?: { privateKey: Uint8Array; publicKey: Uint8Array };
}

/**
 * Read-only handle returned by `recover()`. See module header for the
 * full surface and Phase 4 scope.
 */
export class Reader {
  /** Names of every collection declared in the caller-supplied schema. */
  readonly collections: string[];

  /** Account-level metadata surfaced for app diagnostics. */
  readonly account: ReaderAccount;

  /**
   * Count of distinct logical records that were tombstoned on the most
   * recently iterated collection. Zero before the first `entries()` /
   * `allEntries()` call.
   */
  tombstoneCount: number = 0;

  readonly #appId: string;
  readonly #schemaVersion: number;
  readonly #client: MultiGatewayClient;
  readonly #dataLookupKey: string;
  readonly #dekChain: UnwrappedDekChain;
  readonly #onProgress: RecoverOnProgress | undefined;
  /**
   * Composed sharing reader; only populated when the caller supplied a
   * share keypair. When undefined, `connections()` returns `[]` and the
   * share-log iterators yield nothing.
   */
  readonly #sharing: SharingReader | undefined;

  constructor(init: ReaderInit) {
    if (!init.schema || !init.schema.collections) {
      throw new Error('Reader: schema with `collections` is required');
    }
    if (!init.client) {
      throw new Error('Reader: gateway client is required');
    }
    if (!init.dekChain || init.dekChain.dekByGen.size === 0) {
      throw new Error('Reader: dekChain is required and must be non-empty');
    }
    this.#appId = init.appId;
    this.#schemaVersion = init.schema.version;
    this.#client = init.client;
    this.#dataLookupKey = init.dataLookupKey;
    this.#dekChain = init.dekChain;
    this.#onProgress = init.onProgress;
    this.account = init.account;
    this.collections = Object.keys(init.schema.collections);
    if (init.shareKeyPair) {
      this.#sharing = new SharingReader({
        appId: init.appId,
        client: init.client,
        dataLookupKey: init.dataLookupKey,
        dekChain: init.dekChain,
        shareKeyPair: init.shareKeyPair,
      });
    }
  }

  /**
   * Async iterator over every live entry in a collection. Tombstoned
   * records are filtered out; superseded versions of records are filtered
   * out (only the live tip is yielded). `tombstoneCount` is updated once
   * the iterator finishes producing the first batch (we do tag-resolution
   * up-front, then stream decrypts).
   */
  async *entries(collectionName: string): AsyncIterable<DecryptedEntry> {
    this.#assertCollection(collectionName);
    this.#emit('walking-log', { collection: collectionName });

    const blobs = await findContentBlobs(this.#client, {
      app: this.#appId,
      type: collectionName,
      dataLookupKey: this.#dataLookupKey,
    });

    const { live, tombstoneCount } = resolveContentBlobs(blobs);
    this.tombstoneCount = tombstoneCount;
    this.#emit('walking-log', {
      collection: collectionName,
      total: blobs.length,
      live: live.length,
      tombstoneCount,
    });

    for (let i = 0; i < live.length; i++) {
      const blob = live[i]!;
      this.#emit('decrypting', { collection: collectionName, current: i + 1, total: live.length });
      try {
        const decrypted = await this.#decryptBlob(blob);
        yield attachSchemaVersionMarker(blob, decrypted, this.#schemaVersion);
      } catch (err) {
        // Mirror the live SDK's `getEntries` posture: log + skip rather
        // than aborting the whole iterator on one bad entry. Callers
        // generally want partial results over an all-or-nothing failure.
        const msg = err instanceof Error ? err.message : String(err);
        // eslint-disable-next-line no-console
        console.warn(
          `[@tarn/recover] Reader.entries('${collectionName}'): skipping ${blob.txid}: ${msg}`,
        );
      }
    }

    this.#emit('done', { collection: collectionName });
  }

  /**
   * Buffered convenience: drain the async iterator into an array. Use
   * `entries()` for streaming-friendly consumption (large collections,
   * progress UI, etc.).
   */
  async allEntries(collectionName: string): Promise<DecryptedEntry[]> {
    const out: DecryptedEntry[] = [];
    for await (const e of this.entries(collectionName)) {
      out.push(e);
    }
    return out;
  }

  // ============ Sharing surface (Phase 5) ============

  /**
   * Return the user's accepted connections (peers + their stable identifiers).
   * Returns `[]` when the caller authenticated via the account-key factor —
   * see `recover/src/crypto/share-key.ts` for why the share keypair isn't
   * derivable on that path.
   */
  async connections(): Promise<Connection[]> {
    if (!this.#sharing) return [];
    return this.#sharing.connections();
  }

  /**
   * Async iterator over share-log events for the requested direction.
   * `direction: 'incoming'` reads peers' outbound logs (events the user
   * received); `direction: 'outgoing'` reads the user's outbound logs
   * (events the user emitted). Yields nothing when the share keypair is
   * unavailable (account-key factor).
   *
   * Each event carries `connection` (peer identity), `seq`, `direction`,
   * `txid`, and `verified` (false means the event's ECDSA signature did
   * not validate against the connection's `signing_pub` — apps generally
   * treat unverified events as forgeries).
   */
  shareLog(opts: { direction: ShareLogDirection }): AsyncIterable<ShareLogEvent> {
    if (!this.#sharing) {
      return emptyAsyncIterable<ShareLogEvent>();
    }
    return this.#sharing.shareLog(opts);
  }

  /**
   * Buffered batch helper: drain {@link shareLog} into a flat array. Returns
   * `[]` when the share keypair is unavailable.
   */
  async allShareLog(opts: { direction: ShareLogDirection }): Promise<ShareLogEvent[]> {
    if (!this.#sharing) return [];
    return this.#sharing.allShareLog(opts);
  }

  // ============ Internal helpers ============

  #assertCollection(name: string): void {
    if (!this.collections.includes(name)) {
      throw new Error(
        `Reader: '${name}' is not a declared collection. Known: ${this.collections.join(', ')}`,
      );
    }
  }

  /**
   * Decrypt a single content blob with the right gen's DEK. Mirrors
   * `TarnClient.#decryptBlob` (`client/src/tarn.ts` 5986-5996): pull the
   * `Gen` tag (defaulting to gen 1), look up the DEK in the chain, and
   * call `decryptWithCEK`.
   */
  async #decryptBlob(blob: BlobRecord): Promise<Record<string, unknown>> {
    const bytes = await blob.loadBody();
    const genRaw = blob.tagMap['Gen'];
    let gen = 1;
    if (genRaw !== undefined) {
      const parsed = Number.parseInt(genRaw, 10);
      if (Number.isInteger(parsed) && parsed >= 1) gen = parsed;
    }
    const dek = this.#dekChain.dekByGen.get(gen);
    if (!dek) {
      throw new Error(
        `No DEK for blob generation ${gen} — chain has gens [${[...this.#dekChain.dekByGen.keys()].join(', ')}]`,
      );
    }
    const decoded = await decryptWithCEK(dek.kwKey, bytes);
    if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) {
      throw new Error(`decrypted payload is not a plain object`);
    }
    return decoded as Record<string, unknown>;
  }

  #emit(stage: RecoverProgress['stage'], info: Record<string, unknown> = {}): void {
    if (!this.#onProgress) return;
    try {
      this.#onProgress(stage, info);
    } catch {
      // onProgress callbacks are diagnostic — never let one break the read.
    }
  }
}

/** Empty async iterable — returned when the share keypair is unavailable. */
function emptyAsyncIterable<T>(): AsyncIterable<T> {
  return {
    [Symbol.asyncIterator]: async function* () {
      // intentionally empty
    },
  };
}
