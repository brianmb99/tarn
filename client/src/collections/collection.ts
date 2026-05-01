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
import type { DecryptedEntry, ITarnClient, Tag } from './types.js';

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

  // ============ Internal helpers ============

  /** Build the protocol-level extra tags applied to every write. */
  #protocolTags(eid: string): Tag[] {
    return [
      { name: 'Eid', value: eid },
      { name: 'SchemaV', value: String(this.#schemaVersion) },
    ];
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
