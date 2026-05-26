/**
 * `tarn.advanced.*` — escape hatches.
 *
 * Power-user surface: direct entry CRUD by type string (no schema), blob
 * fetching by txid, and shared-blob decryption with a known shareKey.
 * Also exposes the share-log primitives for apps that want fine-grained
 * control beyond the typed Collection sharing methods.
 *
 * Apps SHOULDN'T need this for typical CRUD + sharing flows. It exists for
 * prototypes, debugging, integration tests, and any future use case the
 * typed surface doesn't yet cover.
 */

import type { ITarnClient, Tag } from '../../collections/index.js';

export interface IAdvancedClient extends ITarnClient {
  // ITarnClient already covers entry CRUD + blob + shareKey + sharing primitives.
  // Add any further escape-hatch methods here as needs arise.
}

export class AdvancedNamespace<C extends IAdvancedClient = IAdvancedClient> {
  readonly entries: AdvancedEntries<C>;
  readonly shareLog: AdvancedShareLog<C>;

  constructor(client: C) {
    this.entries = new AdvancedEntries(client);
    this.shareLog = new AdvancedShareLog(client);
  }
}

export class AdvancedEntries<C extends IAdvancedClient> {
  readonly #client: C;
  constructor(client: C) {
    this.#client = client;
  }

  /**
   * Schema-less entry create. Returns the freshly-issued shareKey so the
   * caller can publish through the share-log directly.
   */
  async create(
    type: string,
    payload: Record<string, unknown>,
    extraTags: Tag[] = [],
  ): Promise<{ txid: string; shareKey: string | null }> {
    return this.#client.createEntry(type, payload, extraTags);
  }

  /**
   * Schema-less bulk create. Writes 1-25 entries in a single batch. Counts as
   * 1 rate-limit hit regardless of batch size (vs N hits for N single calls).
   * Returns `[{ txid, shareKey }]` in input order.
   *
   * Schema-less by design — partial-failure validation semantics across a
   * batch don't have a clean answer, so the typed `client.<collection>.create`
   * path stays single-item. Callers wanting per-item validation should call
   * the collection's `validate(item)` upstream before batching, or use the
   * typed surface per item (at the cost of 1 rate-limit hit per item).
   *
   * Throws on empty input or `items.length > 25`. Idempotent: a retry on the
   * same input produces the same list of txids (server-side de-dupe via one
   * idempotency key per batch).
   *
   * Note: `extraTags` is forwarded for forward-compat with the interface
   * signature; the bundled underlying client currently ignores it on batch
   * writes (single-item `create` honors it). If you need extra tags per
   * batched item today, use single-item `create` until the underlying
   * surface adds support.
   */
  async batchCreate(
    type: string,
    items: Array<Record<string, unknown>>,
    extraTags: Tag[] = [],
  ): Promise<Array<{ txid: string; shareKey: string | null }>> {
    if (!Array.isArray(items) || items.length === 0) {
      throw new Error('advanced.entries.batchCreate: items must be a non-empty array');
    }
    if (items.length > 25) {
      throw new Error(
        `advanced.entries.batchCreate: items max 25 per batch (got ${items.length})`,
      );
    }
    return this.#client.batchCreate(type, items, extraTags);
  }

  /** Schema-less update. */
  async update(
    priorTxid: string,
    type: string,
    payload: Record<string, unknown>,
    extraTags: Tag[] = [],
  ): Promise<{ txid: string; shareKey: string | null }> {
    return this.#client.updateEntry(priorTxid, type, payload, extraTags);
  }

  /** Schema-less delete (tombstone). */
  async delete(targetTxid: string, type: string, extraTags: Tag[] = []): Promise<{ txid: string }> {
    return this.#client.deleteEntry(targetTxid, type, extraTags);
  }

  /**
   * Schema-less delta-sync. The typed wrapper is `tarn.<collection>.getEntriesSince()`,
   * which decodes records into the collection's TS type and emits Eids
   * alongside; this escape hatch returns the raw shape so apps without
   * a schema-typed surface (or wanting the txid / tag stream directly)
   * can drive their own sync loop.
   *
   * Cursor is shared with the typed surface — persisted per `(appId, dlk, type)`,
   * so mixing typed and advanced calls for the same `type` is safe but
   * usually unnecessary.
   */
  async getEntriesSince(type: string): Promise<{
    entries: Array<{ eid: string | null; txid: string; data: Record<string, unknown>; tags: Tag[] }>;
    deleted: string[];
  }> {
    return this.#client.getEntriesSince(type);
  }

  /** Fetch encrypted blob bytes for any txid via Tarn (lazy-loads from gateway on miss). */
  async fetchBlob(txid: string): Promise<Uint8Array | null> {
    return this.#client.fetchBlob(txid);
  }

  /** Decrypt a v3-format blob using a shareKey directly (the recipient path). */
  async decryptSharedBlob(
    blob: Uint8Array,
    shareKey: string,
  ): Promise<Record<string, unknown>> {
    return this.#client.decryptSharedBlob(blob, shareKey);
  }

  /**
   * Resolve the shareKey for an entry we wrote. Cache lookup with a
   * fetch + AES-KW unwrap fallback. Null only for unrecoverable blobs
   * (unfetchable or malformed).
   */
  async getShareKey(txid: string): Promise<string | null> {
    return this.#client.getShareKey(txid);
  }
}

export class AdvancedShareLog<C extends IAdvancedClient> {
  readonly #client: C;
  constructor(client: C) {
    this.#client = client;
  }

  /**
   * Read a connection's share-log directly as a state map.
   * `Collection.listShared()` is the typed wrapper — use that for normal
   * recipient flows.
   */
  async read(
    connection: { share_pub: string; signing_pub: string },
    opts: { refresh?: boolean } = {},
  ): Promise<Record<string, { tx_id: string; cek: string }>> {
    return this.#client.readShareLog(connection, opts);
  }

  /**
   * Publish a (contentId, txid, shareKey) triple to a connection's
   * share-log. `Collection.share(connection, primaryKey)` is the typed
   * wrapper — use that for normal sender flows.
   */
  async share(
    connection: { share_pub: string; signing_pub: string },
    contentId: string,
    txid: string,
    shareKey: string,
  ): Promise<unknown> {
    return this.#client.shareContent(connection, contentId, txid, shareKey);
  }

  /** Publish a remove op for a contentId. */
  async unshare(
    connection: { share_pub: string; signing_pub: string },
    contentId: string,
  ): Promise<unknown> {
    return this.#client.unshareContent(connection, contentId);
  }
}
