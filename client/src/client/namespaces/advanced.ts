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
import type { CollectionDef } from '../../schema/index.js';
import { validateRecordForCreate, TarnSchemaError } from '../../schema/index.js';

export interface IAdvancedClient extends ITarnClient {
  // ITarnClient already covers entry CRUD + blob + shareKey + sharing primitives.
  // Add any further escape-hatch methods here as needs arise.
}

/**
 * Schema info passed down from TarnClient.create so the advanced surface
 * can transparently validate payloads and stamp Eid + SchemaV tags when
 * callers write to a `type` that corresponds to a defined collection. The
 * escape-hatch semantics stay intact for unknown types — those writes still
 * go through with whatever tags the caller supplies (no validation, no
 * auto-stamping).
 *
 * Invariant the SDK now upholds: every data-bearing write to a defined
 * collection is validated against the schema AND carries an Eid tag
 * derived from the validated record's primaryKey, regardless of whether
 * it went through the typed Collection<T> surface or the advanced escape
 * hatch. The wire protocol can rely on it; the delta-sync surface can
 * rely on it; users no longer end up with silent orphans on chain.
 */
export interface AdvancedSchemaInfo {
  /**
   * Map from collection name (the `type` arg) to its full CollectionDef.
   * Used both to enforce schema validation on writes targeting a defined
   * collection and to look up the primaryKey field name for Eid derivation.
   */
  collectionsByType: ReadonlyMap<string, CollectionDef>;
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
   * Prepare a write to `type` with `payload` and caller-supplied `extraTags`.
   *
   * When `type` matches a defined collection (the failure mode this code
   * exists to prevent — silent orphans landing in a typed collection via
   * the escape hatch):
   *   1. Validate the payload against the schema using the same
   *      `validateRecordForCreate` the typed Collection.create path uses.
   *      A missing primaryKey, unknown field, or type mismatch throws
   *      TarnSchemaError — nothing is written.
   *   2. Derive the Eid from the validated record's primaryKey via the same
   *      `deriveEid` the typed path uses.
   *   3. If the caller already supplied an `Eid` tag in extraTags, honor
   *      it but assert it matches the derived value. A mismatch is almost
   *      certainly a caller bug (records would become unreachable via the
   *      typed read path) and throws TarnSchemaError. If the caller's Eid
   *      matches, the auto-stamp is suppressed so the wire carries a single
   *      Eid tag (no duplicates).
   *   4. Similarly, suppress the auto SchemaV tag if the caller already
   *      supplied one.
   *
   * For an undefined `type` (legitimate escape-hatch use — app-internal
   * types, prototypes, share-log helpers), passes through unchanged: no
   * validation, no auto-stamping, no normalization of the payload.
   *
   * Returns the payload that should be written (validated/normalized for
   * defined collections, original for undefined types) and the extraTags
   * array to apply on the wire.
   */
  async #prepareWrite(
    type: string,
    payload: Record<string, unknown>,
    extraTags: Tag[],
  ): Promise<{ payload: Record<string, unknown>; tags: Tag[] }> {
    if (!this.#schemaInfo) return { payload, tags: extraTags };
    const def = this.#schemaInfo.collectionsByType.get(type);
    if (def === undefined) return { payload, tags: extraTags };

    // Validate. `validateRecordForCreate` enforces required fields (including
    // the primaryKey), rejects unknown fields, applies defaults, and coerces
    // dates. Throws TarnSchemaError on any failure — caller never gets a
    // half-written record on the wire.
    const validated = validateRecordForCreate(type, def, payload);

    // Extract the primaryKey from the validated record. validateRecordForCreate
    // already required it to be present and the right type, but we also
    // need non-empty (Eid derivation collapses on '').
    const pkValue = validated[def.primaryKey];
    if (typeof pkValue !== 'string' || pkValue.length === 0) {
      throw new TarnSchemaError(
        `advanced.entries: type '${type}' primaryKey '${def.primaryKey}' ` +
        `must be a non-empty string`,
      );
    }
    const derivedEid = await deriveEid(this.#schemaInfo.appId, type, pkValue);

    // Reconcile caller-supplied tags. If the caller already put `Eid` or
    // `SchemaV` in extraTags, respect them but validate Eid matches what
    // we'd derive (mismatches are caller bugs — typed reads would drop
    // the record). Then suppress the auto-stamp for any tag they supplied
    // so we don't ship duplicates.
    let callerHasEid = false;
    let callerHasSchemaV = false;
    for (const tag of extraTags) {
      if (tag.name === 'Eid') {
        if (tag.value !== derivedEid) {
          throw new TarnSchemaError(
            `advanced.entries: caller-supplied Eid '${tag.value}' does not match ` +
            `derived Eid '${derivedEid}' for type '${type}' primaryKey '${pkValue}'. ` +
            `Either omit the Eid tag (the SDK will derive it) or correct the value.`,
          );
        }
        callerHasEid = true;
      } else if (tag.name === 'SchemaV') {
        callerHasSchemaV = true;
      }
    }
    const auto: Tag[] = [];
    if (!callerHasEid) auto.push({ name: 'Eid', value: derivedEid });
    if (!callerHasSchemaV) {
      auto.push({ name: 'SchemaV', value: String(this.#schemaInfo.schemaVersion) });
    }
    return { payload: validated, tags: [...extraTags, ...auto] };
  }

  /**
   * Schema-less entry create. When `type` matches a defined collection the
   * payload is validated against the schema and Eid + SchemaV tags are
   * auto-stamped — same invariants as `tarn.<collection>.create()`. A
   * mismatched caller-supplied Eid throws TarnSchemaError; a payload
   * missing the collection's primaryKey throws TarnSchemaError. For an
   * undefined `type`, behaves as a pure pass-through (no validation,
   * no auto-stamping).
   */
  async create(
    type: string,
    payload: Record<string, unknown>,
    extraTags: Tag[] = [],
  ): Promise<{ txid: string; shareKey: string | null }> {
    const { payload: finalPayload, tags } = await this.#prepareWrite(type, payload, extraTags);
    return this.#client.createEntry(type, finalPayload, tags);
  }

  /**
   * Bulk create up to 25 entries in one request. Counts as 1 rate-limit hit
   * regardless of batch size (vs N hits for N single calls). Returns
   * `[{ txid, shareKey }]` in input order.
   *
   * When `type` matches a defined collection, every item is validated
   * against the schema and gets Eid + SchemaV auto-stamped from its
   * primaryKey — same invariants as `tarn.<collection>.batchCreate()`.
   * Validation is atomic across the batch: if ANY item fails, an error
   * listing all failing indexes is thrown and nothing is written. This
   * matches the typed `Collection.batchCreate` semantics and closes the
   * "silent orphan via escape hatch" gap that motivated this surface's
   * tightening (Tarn #34).
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
    // Build per-item (payload, tags) up front. For a defined `type`, every
    // item's #prepareWrite runs validation + Eid derivation + caller-tag
    // reconciliation; failures are collected by input index so the caller
    // sees every problem in one error, not just the first. No wire call
    // happens unless every item passes.
    const preparedPayloads: Array<Record<string, unknown> | null> = new Array(items.length).fill(null);
    const preparedTags: Array<Tag[]> = new Array(items.length);
    const failures: Array<{ index: number; error: string }> = [];
    for (let i = 0; i < items.length; i++) {
      const item = items[i]!;
      const itemSpecific = perItemExtraTags?.[i] ?? [];
      const callerTags: Tag[] = [...extraTags, ...itemSpecific];
      try {
        const prepared = await this.#prepareWrite(type, item, callerTags);
        preparedPayloads[i] = prepared.payload;
        preparedTags[i] = prepared.tags;
      } catch (err) {
        failures.push({
          index: i,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    if (failures.length > 0) {
      const summary = failures
        .map((f) => `[${f.index}] ${f.error}`)
        .join('; ');
      throw new TarnSchemaError(
        `advanced.entries.batchCreate: validation failed for ` +
        `${failures.length}/${items.length} item(s) of type '${type}': ${summary}`,
      );
    }
    const finalItems = preparedPayloads as Array<Record<string, unknown>>;
    return this.#client.batchCreate(type, finalItems, preparedTags);
  }

  /**
   * Schema-less update. When `type` matches a defined collection the
   * payload is validated against the schema and Eid + SchemaV are
   * auto-stamped from the payload's primaryKey — same invariants as the
   * create path. Update carries a full payload (apps doing a partial
   * update on a typed collection should use `tarn.<collection>.update(pk,
   * patch)` which does the read-merge-write); the escape hatch only
   * accepts a complete record because there's nothing to merge against.
   */
  async update(
    priorTxid: string,
    type: string,
    payload: Record<string, unknown>,
    extraTags: Tag[] = [],
  ): Promise<{ txid: string; shareKey: string | null }> {
    const { payload: finalPayload, tags } = await this.#prepareWrite(type, payload, extraTags);
    return this.#client.updateEntry(priorTxid, type, finalPayload, tags);
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
