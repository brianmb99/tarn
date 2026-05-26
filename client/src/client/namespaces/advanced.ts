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
import { deriveEid } from '../../collections/eid.js';

export interface IAdvancedClient extends ITarnClient {
  // ITarnClient already covers entry CRUD + blob + shareKey + sharing primitives.
  // Add any further escape-hatch methods here as needs arise.
}

/**
 * Schema info passed down from TarnClient.create so the advanced surface
 * can transparently stamp Eid + SchemaV tags when callers write to a `type`
 * that corresponds to a defined collection. The escape-hatch semantics stay
 * intact for unknown types — those writes still go through with whatever
 * tags the caller supplies (no auto-stamping).
 *
 * Invariant the SDK now upholds: every data-bearing write to a defined
 * collection carries an Eid tag, regardless of whether it went through
 * the typed Collection<T> surface or the advanced escape hatch. The wire
 * protocol can rely on it; the delta-sync surface can rely on it.
 */
export interface AdvancedSchemaInfo {
  /** Map from collection name (the `type` arg) to its primaryKey field. */
  primaryKeyByType: ReadonlyMap<string, string>;
  /** Top-level schema version — used as the SchemaV tag value. */
  schemaVersion: number;
  /** App id, used to derive Eids. */
  appId: string;
}

export class AdvancedNamespace<C extends IAdvancedClient = IAdvancedClient> {
  readonly entries: AdvancedEntries<C>;
  readonly shareLog: AdvancedShareLog<C>;

  constructor(client: C, schemaInfo?: AdvancedSchemaInfo) {
    this.entries = new AdvancedEntries(client, schemaInfo);
    this.shareLog = new AdvancedShareLog(client);
  }
}

export class AdvancedEntries<C extends IAdvancedClient> {
  readonly #client: C;
  readonly #schemaInfo: AdvancedSchemaInfo | null;
  constructor(client: C, schemaInfo?: AdvancedSchemaInfo) {
    this.#client = client;
    this.#schemaInfo = schemaInfo ?? null;
  }

  /**
   * If `type` corresponds to a defined collection, derive the Eid + SchemaV
   * tags from the payload's primaryKey field and return them. Otherwise
   * returns an empty array (schema-less type — caller manages tags).
   *
   * Throws when the type IS defined but the payload's primaryKey value is
   * missing or non-string. The escape hatch will not silently produce
   * an orphan in a typed collection.
   */
  async #protocolTagsFor(type: string, payload: Record<string, unknown>): Promise<Tag[]> {
    if (!this.#schemaInfo) return [];
    const primaryKeyField = this.#schemaInfo.primaryKeyByType.get(type);
    if (primaryKeyField === undefined) return [];
    const pkValue = payload[primaryKeyField];
    if (typeof pkValue !== 'string' || pkValue.length === 0) {
      throw new Error(
        `advanced.entries: type '${type}' is a defined collection but the payload ` +
        `is missing a usable primaryKey at field '${primaryKeyField}' (expected non-empty string)`,
      );
    }
    const eid = await deriveEid(this.#schemaInfo.appId, type, pkValue);
    return [
      { name: 'Eid', value: eid },
      { name: 'SchemaV', value: String(this.#schemaInfo.schemaVersion) },
    ];
  }

  /**
   * Schema-less entry create. When `type` matches a defined collection, the
   * Eid + SchemaV tags are auto-stamped from the payload's primaryKey;
   * caller-supplied tags are preserved and prepended.
   */
  async create(
    type: string,
    payload: Record<string, unknown>,
    extraTags: Tag[] = [],
  ): Promise<{ txid: string; shareKey: string | null }> {
    const auto = await this.#protocolTagsFor(type, payload);
    return this.#client.createEntry(type, payload, [...extraTags, ...auto]);
  }

  /**
   * Bulk create up to 25 entries in one request. Counts as 1 rate-limit hit
   * regardless of batch size (vs N hits for N single calls). Returns
   * `[{ txid, shareKey }]` in input order.
   *
   * When `type` matches a defined collection, the SDK auto-stamps Eid +
   * SchemaV per item from each item's primaryKey field — so batched
   * entries are NOT orphans on the wire. This pairs with the protocol
   * invariant that every write to a defined collection carries an Eid.
   * Throws if any item is missing its primaryKey for a defined type.
   *
   * Throws on empty input or `items.length > 25`. Idempotent: a retry on
   * the same input produces the same list of txids (server-side de-dupe
   * via one idempotency key per batch).
   *
   * Tag composition per item (left-to-right, later wins on duplicate names):
   *   1. `extraTags` — batch-level tags applied to every item (legacy,
   *      e.g., a `Migration: v1` marker on every entry of a bulk import).
   *   2. `perItemExtraTags[i]` — per-item tags. Required when each entry
   *      needs distinct metadata, e.g., `Prev: <orphan-txid>` for a
   *      migration that chains each new entry to a specific predecessor.
   *      Length must equal `items.length`.
   *   3. Auto-stamped Eid + SchemaV for defined-collection types.
   */
  async batchCreate(
    type: string,
    items: Array<Record<string, unknown>>,
    extraTags: Tag[] = [],
    perItemExtraTags?: Tag[][],
  ): Promise<Array<{ txid: string; shareKey: string | null }>> {
    if (!Array.isArray(items) || items.length === 0) {
      throw new Error('advanced.entries.batchCreate: items must be a non-empty array');
    }
    if (items.length > 25) {
      throw new Error(
        `advanced.entries.batchCreate: items max 25 per batch (got ${items.length})`,
      );
    }
    if (perItemExtraTags !== undefined && perItemExtraTags.length !== items.length) {
      throw new Error(
        `advanced.entries.batchCreate: perItemExtraTags.length (${perItemExtraTags.length}) ` +
        `must equal items.length (${items.length})`,
      );
    }
    // Build per-item tags: batch-level extraTags + per-item extras + auto-stamped Eid + SchemaV.
    const perItem: Tag[][] = [];
    for (let i = 0; i < items.length; i++) {
      const item = items[i]!;
      const itemSpecific = perItemExtraTags?.[i] ?? [];
      const auto = await this.#protocolTagsFor(type, item);
      perItem.push([...extraTags, ...itemSpecific, ...auto]);
    }
    return this.#client.batchCreate(type, items, perItem);
  }

  /**
   * Schema-less update. When `type` matches a defined collection, the
   * Eid + SchemaV tags are auto-stamped from the payload's primaryKey.
   */
  async update(
    priorTxid: string,
    type: string,
    payload: Record<string, unknown>,
    extraTags: Tag[] = [],
  ): Promise<{ txid: string; shareKey: string | null }> {
    const auto = await this.#protocolTagsFor(type, payload);
    return this.#client.updateEntry(priorTxid, type, payload, [...extraTags, ...auto]);
  }

  /**
   * Schema-less delete (tombstone). No auto-stamping here because delete
   * doesn't carry a payload to derive a primaryKey from. Callers writing
   * tombstones for a defined collection through this escape hatch must
   * supply the Eid via `extraTags` themselves — or, more commonly, use
   * the typed `Collection<T>.delete(primaryKey)` path which derives Eid
   * automatically.
   */
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
