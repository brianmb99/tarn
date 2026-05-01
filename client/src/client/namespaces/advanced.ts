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
   * fetch + AES-KW unwrap fallback. Null on legacy accounts or unrecoverable
   * blobs.
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
