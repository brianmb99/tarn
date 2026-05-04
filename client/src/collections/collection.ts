/**
 * Collection<T> — typed CRUD surface over a single schema-declared collection.
 *
 * Wraps an underlying ITarnClient with:
 *   - schema validation on writes (defaults applied, types coerced, unknown
 *     fields rejected, primaryKey integrity enforced)
 *   - deterministic Eid tagging for cross-device record identity
 *   - SchemaV tagging so future migrations can dispatch by version
 *   - primaryKey-keyed addressing — apps never see txids
 *
 * Read path note: each `get` / `list` issues one `getEntries(collectionName)`
 * call to the underlying client, which already returns one decrypted entry
 * per live record (the API's resolver collapses Prev chains and tombstones
 * server-side). This makes `get(pk)` an O(N) client-side filter today; it
 * is fast enough for the record counts we expect, and a per-collection
 * in-memory cache is a straightforward optimization to add in a later
 * step if it becomes worth the bookkeeping.
 */

import type { CollectionDef, CollectionRecord } from '../schema/index.js';
import { validateRecordForCreate, validateRecordForUpdate } from '../schema/index.js';
import { deriveEid } from './eid.js';
import { TarnCollectionError } from './types.js';
import type { DecryptedEntry, ITarnClient, ShareConnection, Tag } from './types.js';

/**
 * Options bag accepted by `list()`. Reserved for forward compatibility (e.g.,
 * filter, sort, limit). Empty for now — apps post-process the result array.
 */
export type ListOpts = Record<string, never>;

/**
 * Generic collection. Parameterized over the record type so `create({...})`
 * and `update(id, {...})` argument types come from the schema declaration.
 *
 * Apps obtain instances via `createCollection()` (step 2) or via the
 * dynamic `tarn.<name>` namespace once the TarnClient class lands (step 4).
 */
export class Collection<TRecord extends Record<string, unknown>> {
  readonly #client: ITarnClient;
  readonly #appId: string;
  readonly #name: string;
  readonly #def: CollectionDef;
  readonly #schemaVersion: number;

  constructor(args: {
    client: ITarnClient;
    appId: string;
    name: string;
    def: CollectionDef;
    schemaVersion: number;
  }) {
    this.#client = args.client;
    this.#appId = args.appId;
    this.#name = args.name;
    this.#def = args.def;
    this.#schemaVersion = args.schemaVersion;
  }

  /** Create a new record. Validates against the schema, attaches Eid + SchemaV tags. */
  async create(record: TRecord): Promise<TRecord> {
    const validated = validateRecordForCreate(this.#name, this.#def, record);
    const pk = this.#extractPrimaryKey(validated);
    const eid = await deriveEid(this.#appId, this.#name, pk);
    await this.#client.createEntry(this.#name, validated, this.#protocolTags(eid));
    return validated as TRecord;
  }

  /**
   * Partial update of an existing record. Reads the current record, merges
   * the patch, re-validates, writes a new entry chained via `Prev` and
   * sharing the same Eid. Apps pass only changed fields.
   */
  async update(primaryKey: string, patch: Partial<TRecord>): Promise<TRecord> {
    const validatedPatch = validateRecordForUpdate(this.#name, this.#def, patch);
    const { entry, current } = await this.#findCurrent(primaryKey);

    // Merge, then re-validate as a full record so defaults, required-field,
    // and type rules apply to the result. This is more conservative than
    // strictly necessary (the patch is already validated) but it catches
    // the unusual case where the prior record on Arweave is malformed for
    // the current schema version.
    const merged = { ...current, ...validatedPatch };
    const revalidated = validateRecordForCreate(this.#name, this.#def, merged);

    const eid = await deriveEid(this.#appId, this.#name, primaryKey);
    await this.#client.updateEntry(entry.txid, this.#name, revalidated, this.#protocolTags(eid));
    return revalidated as TRecord;
  }

  /**
   * Tombstone the record. Idempotent at the protocol layer; calling delete
   * on an already-deleted record throws TarnCollectionError because the
   * underlying entry is no longer in the live set.
   */
  async delete(primaryKey: string): Promise<void> {
    const { entry } = await this.#findCurrent(primaryKey);
    const eid = await deriveEid(this.#appId, this.#name, primaryKey);
    await this.#client.deleteEntry(entry.txid, this.#name, this.#protocolTags(eid));
  }

  /** Return the live record for this primaryKey, or null if absent. */
  async get(primaryKey: string): Promise<TRecord | null> {
    const all = await this.list();
    return all.find((r) => this.#primaryKeyOf(r) === primaryKey) ?? null;
  }

  /** Return all live records in this collection. Returns [] if none. */
  async list(_opts: ListOpts = {}): Promise<TRecord[]> {
    const entries = await this.#client.getEntries(this.#name);
    const out: TRecord[] = [];
    for (const e of entries) {
      try {
        out.push(e.data as TRecord);
      } catch (err) {
        // Underlying entries are already validated at write; this branch
        // exists for entries written by buggy/legacy clients. Log and skip,
        // consistent with how readShareLog handles unverifiable entries.
        console.warn(
          `[TarnClient] Collection '${this.#name}': skipping malformed entry ${e.txid}: `,
          err instanceof Error ? err.message : err,
        );
      }
    }
    return out;
  }

  // ============ Sharing (only present if collection is shareable) ============

  /**
   * Publish this record to a connection's share-log so the friend can read it.
   *
   * The shareKey is resolved from the SDK's in-memory cache (populated by
   * the most recent create/update) or fetched + AES-KW-unwrapped on cache
   * miss. Apps don't see the shareKey.
   *
   * Re-sharing a contentId that's already in the connection's share-log
   * supersedes the prior entry — that's how update flows propagate to
   * friends. Apps that update a record and want friends to see the new
   * version simply call share() again.
   */
  async share(connection: ShareConnection, primaryKey: string): Promise<void> {
    this.#assertShareable('share');
    const { entry } = await this.#findCurrent(primaryKey);
    const shareKey = await this.#client.getShareKey(entry.txid);
    if (!shareKey) {
      throw new TarnCollectionError(
        `Collection '${this.#name}': no shareKey available for record '${primaryKey}' ` +
        `(blob unfetchable or malformed)`,
      );
    }
    await this.#client.shareContent(connection, this.#contentIdFor(primaryKey), entry.txid, shareKey);
  }

  /**
   * Publish this record to every connection that isn't muted. Returns counts
   * of successes and the per-connection failures (if any) — failures don't
   * stop the loop; a flaky one connection shouldn't block the others.
   */
  async shareWithAll(
    primaryKey: string,
  ): Promise<{ ok: number; failed: Array<{ connection: ShareConnection; error: string }> }> {
    this.#assertShareable('shareWithAll');
    const { entry } = await this.#findCurrent(primaryKey);
    const shareKey = await this.#client.getShareKey(entry.txid);
    if (!shareKey) {
      throw new TarnCollectionError(
        `Collection '${this.#name}': no shareKey available for record '${primaryKey}' ` +
        `(blob unfetchable or malformed)`,
      );
    }
    const contentId = this.#contentIdFor(primaryKey);
    const connections = await this.#client.listConnections();
    let ok = 0;
    const failed: Array<{ connection: ShareConnection; error: string }> = [];
    for (const conn of connections) {
      if (await this.#client.isMuted(conn)) continue;
      try {
        await this.#client.shareContent(conn, contentId, entry.txid, shareKey);
        ok++;
      } catch (err) {
        failed.push({
          connection: conn,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    return { ok, failed };
  }

  /** Revoke a previously-shared record from one connection's view. */
  async unshare(connection: ShareConnection, primaryKey: string): Promise<void> {
    this.#assertShareable('unshare');
    await this.#client.unshareContent(connection, this.#contentIdFor(primaryKey));
  }

  /**
   * Fetch and decrypt every record this connection has shared with us under
   * this collection. Reads the connection's share-log (one request per page),
   * fetches each blob from Tarn, decrypts with the shareKey, and returns the
   * decrypted records.
   *
   * Records that fail to fetch or decrypt are logged and skipped — partial
   * results are returned rather than aborting the whole call.
   */
  async listShared(connection: ShareConnection): Promise<TRecord[]> {
    this.#assertShareable('listShared');
    const state = await this.#client.readShareLog(connection);
    const collectionPrefix = this.#contentIdPrefix();
    const out: TRecord[] = [];
    for (const [contentId, entry] of Object.entries(state)) {
      if (!contentId.startsWith(collectionPrefix)) continue;
      try {
        const blob = await this.#client.fetchBlob(entry.tx_id);
        if (!blob) {
          console.warn(
            `[TarnClient] Collection.listShared: blob ${entry.tx_id} unavailable; skipping`,
          );
          continue;
        }
        const plaintext = await this.#client.decryptSharedBlob(blob, entry.cek);
        out.push(plaintext as TRecord);
      } catch (err) {
        console.warn(
          `[TarnClient] Collection.listShared: decrypt failed for ${entry.tx_id}: `,
          err instanceof Error ? err.message : err,
        );
      }
    }
    return out;
  }

  // ============ Internal helpers ============

  /** Build the protocol-level extra tags applied to every write. */
  #protocolTags(eid: string): Tag[] {
    return [
      { name: 'Eid', value: eid },
      { name: 'SchemaV', value: String(this.#schemaVersion) },
    ];
  }

  /**
   * Throw if the collection is not declared shareable. Apps see this as a
   * usage error; the schema is the source of truth for what can be shared.
   */
  #assertShareable(method: string): void {
    if (!this.#def.shareable) {
      throw new TarnCollectionError(
        `Collection '${this.#name}': ${method}() requires the collection to declare shareable: true`,
      );
    }
  }

  /**
   * Compose a globally-unique content id for the share-log layer. Sharing
   * happens per-connection; a single connection might have multiple
   * collections shared (books, notes, etc.). Prefixing the primaryKey with
   * the collection name keeps the share-log namespace clean and lets
   * listShared() filter by collection.
   */
  #contentIdFor(primaryKey: string): string {
    return `${this.#name}:${primaryKey}`;
  }

  #contentIdPrefix(): string {
    return `${this.#name}:`;
  }

  /** Locate the live txid + decoded record for a primaryKey, or throw. */
  async #findCurrent(primaryKey: string): Promise<{ entry: DecryptedEntry; current: TRecord }> {
    const entries = await this.#client.getEntries(this.#name);
    for (const e of entries) {
      const candidate = e.data as TRecord;
      if (this.#primaryKeyOf(candidate) === primaryKey) {
        return { entry: e, current: candidate };
      }
    }
    throw new TarnCollectionError(
      `Collection '${this.#name}': no record with primaryKey '${primaryKey}'`,
    );
  }

  #extractPrimaryKey(record: Record<string, unknown>): string {
    const v = record[this.#def.primaryKey];
    if (typeof v !== 'string' || v.length === 0) {
      throw new TarnCollectionError(
        `Collection '${this.#name}': primaryKey '${this.#def.primaryKey}' must be a non-empty string`,
      );
    }
    return v;
  }

  #primaryKeyOf(record: TRecord): string | undefined {
    const v = record[this.#def.primaryKey];
    return typeof v === 'string' ? v : undefined;
  }
}

// ============ Public factory ============

/**
 * Create a Collection<T> bound to a schema-declared collection name. The
 * generic `T` should be `CollectionRecord<S['collections'][K]>` for proper
 * inference; helper types in `../schema/types.ts` derive this automatically
 * once the TarnClient namespace lands in step 4.
 */
export function createCollection<TRecord extends Record<string, unknown>>(args: {
  client: ITarnClient;
  appId: string;
  name: string;
  def: CollectionDef;
  schemaVersion: number;
}): Collection<TRecord> {
  return new Collection<TRecord>(args);
}

// Re-export the derived-record type alias so step-4 callers can spell the
// generic precisely without reaching into the schema barrel.
export type { CollectionRecord };
