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
 * Read path: single-record operations (`get`, `update`, `delete`, `share`,
 * `shareWithAll`) compute the Eid locally from the primaryKey and issue a
 * narrow `getEntryByEid` lookup — one round trip, one decrypted blob,
 * regardless of how many other records exist in the collection. `list()`
 * is the only path that legitimately fans out across every entry.
 */

import type { CollectionDef, CollectionRecord, Migration } from '../schema/index.js';
import { validateRecordForCreate, validateRecordForUpdate, coerceDatesForRead } from '../schema/index.js';
import { deriveEid } from './eid.js';
import { TarnCollectionError } from './types.js';
import type { DecryptedEntry, ITarnClient, ShareConnection, Tag } from './types.js';
import { dispatchSchemaVersion, TarnSchemaVersionError } from './schema-version.js';

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
  readonly #migrations: Record<number, Migration> | undefined;

  constructor(args: {
    client: ITarnClient;
    appId: string;
    name: string;
    def: CollectionDef;
    schemaVersion: number;
    /**
     * Per-version forward-migrators declared in the schema
     * (`migrations[v]` migrates a v→(v+1) record). Optional; the read-side
     * version dispatch applies them to older entries on read. Undefined /
     * empty means only additive (backward-compatible) schema changes are
     * supported — see `schema-version.ts` and `docs/SDK_ARCHITECTURE.md`.
     */
    migrations?: Record<number, Migration> | undefined;
  }) {
    this.#client = args.client;
    this.#appId = args.appId;
    this.#name = args.name;
    this.#def = args.def;
    this.#schemaVersion = args.schemaVersion;
    this.#migrations = args.migrations;
  }

  /**
   * Create a new record. Validates against the schema, attaches Eid + SchemaV tags.
   *
   * Pass `opts.idempotencyKey` to make the write retry-safe across the seam:
   * the key is forwarded verbatim as the API's `X-Idempotency-Key`, so a
   * caller that retries the SAME logical create (e.g. an offline-replay path
   * re-running a queued op after a crash, or after a lost response) sends the
   * SAME key and the API's 24h dedup collapses the duplicate — no second
   * remote entry. Omit it (the default) and each call mints a fresh key
   * internally, i.e. today's behavior: every attempt is treated as distinct.
   * The key must be stable across attempts to dedup; derive it from the
   * record's persistent identity (e.g. its primaryKey), not per-call randomness.
   * See tarn #8 / bookish#225 (seam S-2).
   *
   * DEFAULT behavior on a primaryKey that already has a live record is
   * **last-write-wins**: the new entry shares the existing record's Eid, so it
   * supersedes the prior one (the prior version stays on Arweave but is no
   * longer the live record). This is intentional and unchanged — `create()` and
   * `update()` produce the same Eid for a given key.
   *
   * Pass `opts.failIfExists: true` (Tarn #56) to instead REJECT a create whose
   * primaryKey already has a live record, throwing `TarnCollectionError`
   * without writing. Use it when a duplicate create signals an app bug (e.g.
   * minting a fresh id that must be unique) rather than an intended overwrite.
   * Note it costs one extra read (an Eid lookup) before the write, and it is
   * best-effort: it is not an atomic check-and-set, so two concurrent creates
   * of the same new key can still race past the check (last-write-wins
   * reconciles them via the shared Eid). For idempotent retry-safety of the
   * SAME logical create, prefer `idempotencyKey` over `failIfExists`.
   */
  async create(
    record: TRecord,
    opts?: { idempotencyKey?: string; failIfExists?: boolean },
  ): Promise<TRecord> {
    const validated = validateRecordForCreate(this.#name, this.#def, record);
    const pk = this.#extractPrimaryKey(validated);
    const eid = await deriveEid(this.#appId, this.#name, pk);
    if (opts?.failIfExists) {
      // Best-effort existence guard (not atomic — see doc comment). One narrow
      // Eid lookup; throws before any write if a live record already exists.
      const existing = await this.#client.getEntryByEid(this.#name, eid);
      if (existing) {
        throw new TarnCollectionError(
          `Collection '${this.#name}': create({ failIfExists: true }) — a record ` +
          `with primaryKey '${pk}' already exists. Use update() to modify it, or ` +
          `omit failIfExists for last-write-wins.`,
        );
      }
    }
    // `createEntry` accepts only `{ idempotencyKey }`; failIfExists is a typed-
    // layer concern and must not leak to the wire call.
    const createOpts = opts?.idempotencyKey !== undefined
      ? { idempotencyKey: opts.idempotencyKey }
      : undefined;
    await this.#client.createEntry(this.#name, validated, this.#protocolTags(eid), createOpts);
    return validated as TRecord;
  }

  /**
   * Bulk-create up to 25 records in one request. Each record is validated
   * against the schema, gets its own Eid (derived from its primaryKey), and
   * gets the collection's SchemaV tag. Counts as 1 rate-limit hit regardless
   * of batch size (vs N hits for N single `create()` calls).
   *
   * This is the typed entry point for bulk writes — Eid is always stamped
   * per item, so batched records are NOT orphans on the wire and surface
   * normally through `getEntriesSince`. Apps doing bulk imports should
   * prefer this over `advanced.entries.batchCreate` (which only auto-stamps
   * Eid when the `type` string happens to match a defined collection).
   *
   * Returns the validated records in input order, mirroring single-item
   * `create()` which returns the validated record. Throws on empty input
   * or `items.length > 25`.
   *
   * Validation: every record is checked against the schema before any wire
   * call. If any record fails, throws a `TarnCollectionError` listing the
   * failing indexes and their reasons — nothing is written. This makes the
   * batch atomic from the caller's perspective: all records validate and
   * ship, or none do. Partial-success semantics across a batch don't apply.
   */
  async batchCreate(items: TRecord[]): Promise<TRecord[]> {
    if (!Array.isArray(items) || items.length === 0) {
      throw new TarnCollectionError(
        `Collection '${this.#name}': batchCreate requires a non-empty array`,
      );
    }
    if (items.length > 25) {
      throw new TarnCollectionError(
        `Collection '${this.#name}': batchCreate max 25 items per batch (got ${items.length})`,
      );
    }
    // Validate every record up front; collect all failures with their input
    // index so the caller can see exactly which records to fix. The wire
    // call only happens if every record passes — no partial writes.
    const validated: Array<TRecord | null> = new Array(items.length).fill(null);
    const failures: Array<{ index: number; error: string }> = [];
    for (let i = 0; i < items.length; i++) {
      try {
        validated[i] = validateRecordForCreate(this.#name, this.#def, items[i]!) as TRecord;
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
      throw new TarnCollectionError(
        `Collection '${this.#name}': batchCreate validation failed for ` +
        `${failures.length}/${items.length} record(s): ${summary}`,
      );
    }
    // All records validated — build per-item Eid + SchemaV tags. PK
    // extraction can still throw (empty/non-string primaryKey); that path
    // is rare since validateRecordForCreate already enforces field types,
    // but it's per-record, so wrap it the same way.
    //
    // Tarn #56: also reject intra-batch duplicate primaryKeys. Two items in one
    // batch sharing a pk would derive the SAME Eid and silently collapse to a
    // single live record (last one wins) — almost always a caller bug, so we
    // fail the whole batch (atomic, no wire call) and name the colliding index.
    const extraTagsPerItem: Tag[][] = [];
    const firstIndexByPk = new Map<string, number>();
    for (let i = 0; i < validated.length; i++) {
      const v = validated[i] as TRecord;
      try {
        const pk = this.#extractPrimaryKey(v as Record<string, unknown>);
        const firstIndex = firstIndexByPk.get(pk);
        if (firstIndex !== undefined) {
          failures.push({
            index: i,
            error: `duplicate primaryKey '${pk}' (already used at index ${firstIndex})`,
          });
          // Still push a placeholder so extraTagsPerItem stays index-aligned;
          // the batch aborts below regardless.
          extraTagsPerItem.push([]);
          continue;
        }
        firstIndexByPk.set(pk, i);
        const eid = await deriveEid(this.#appId, this.#name, pk);
        extraTagsPerItem.push(this.#protocolTags(eid));
      } catch (err) {
        failures.push({
          index: i,
          error: err instanceof Error ? err.message : String(err),
        });
        extraTagsPerItem.push([]);
      }
    }
    if (failures.length > 0) {
      const summary = failures
        .map((f) => `[${f.index}] ${f.error}`)
        .join('; ');
      throw new TarnCollectionError(
        `Collection '${this.#name}': batchCreate validation failed for ` +
        `${failures.length}/${items.length} record(s): ${summary}`,
      );
    }
    const final = validated as TRecord[];
    await this.#client.batchCreate(
      this.#name,
      final as Array<Record<string, unknown>>,
      extraTagsPerItem,
    );
    return final;
  }

  /**
   * Partial update of an existing record. Reads the current record, merges
   * the patch, re-validates, writes a new entry chained via `Prev` and
   * sharing the same Eid. Apps pass only changed fields.
   *
   * Pass `opts.unset` to clear specific fields on the existing record.
   * Fields listed in `unset` are deleted from the merged record *after*
   * the patch is applied, so if the same key appears in both `patch`
   * and `unset` the unset wins. Unsetting a field that wasn't present
   * is a no-op. Unsetting a required field throws the standard
   * "required field missing" validation error from the re-validate step
   * (no new error class).
   *
   * The `keyof TRecord & string` constraint on the unset list lets
   * callers spell the field names with normal autocomplete, without
   * `as any` casts.
   *
   * primaryKey immutability is enforced here, not by convention. The Eid is
   * derived as `hash(appId, collection, primaryKey)`; changing the primaryKey
   * would mint a new Eid and silently fork the logical record (the old Eid's
   * entries orphan). So if the patch carries the primaryKey field with a value
   * differing from the existing record's, this throws `TarnCollectionError`.
   * Including the primaryKey with the *same* value is a harmless no-op — it's
   * stripped before merge so it can't perturb anything downstream.
   */
  async update(
    primaryKey: string,
    patch: Partial<TRecord>,
    opts?: { unset?: Array<keyof TRecord & string> },
  ): Promise<TRecord> {
    const { entry, current } = await this.#findCurrent(primaryKey);

    // Enforce primaryKey immutability before validation. We compare against
    // the existing record's primaryKey rather than the `primaryKey` argument
    // because that argument is the lookup key by definition — the record on
    // the wire is the source of truth. A same-value primaryKey in the patch
    // is a no-op (stripped here); a differing value forks the record's Eid.
    const pkField = this.#def.primaryKey;
    const patchObj = patch as Record<string, unknown>;
    if (Object.prototype.hasOwnProperty.call(patchObj, pkField)) {
      const patchPk = patchObj[pkField];
      const existingPk = (current as Record<string, unknown>)[pkField];
      if (patchPk !== existingPk) {
        throw new TarnCollectionError(
          `Collection '${this.#name}': cannot change primaryKey '${pkField}' on ` +
          `update (immutable per logical record). ` +
          `Existing: '${String(existingPk)}', patch: '${String(patchPk)}'`,
        );
      }
      // Same value — strip it so validateRecordForUpdate (which rejects any
      // primaryKey in a patch) treats this as the no-op it is.
      const rest: Record<string, unknown> = { ...patchObj };
      delete rest[pkField];
      patch = rest as Partial<TRecord>;
    }

    const validatedPatch = validateRecordForUpdate(this.#name, this.#def, patch);

    // Merge, then re-validate as a full record so defaults, required-field,
    // and type rules apply to the result. This is more conservative than
    // strictly necessary (the patch is already validated) but it catches
    // the unusual case where the prior record on Arweave is malformed for
    // the current schema version.
    const merged: Record<string, unknown> = { ...current, ...validatedPatch };
    const unsetList = opts?.unset ?? [];
    for (const key of unsetList) {
      // Delete after merge so a key appearing in both `patch` and `unset`
      // ends up cleared. Deleting an absent key is a no-op (standard JS).
      delete merged[key];
    }
    // Pass the unset keys through so re-validation does NOT re-apply a field's
    // default to a deliberately-cleared field (Tarn #58a). Without this, unset
    // on a defaulted field silently reverts to the default. A required field in
    // the unset list still fails the required check — unchanged behavior.
    const unsetKeys = unsetList.length > 0 ? new Set<string>(unsetList) : undefined;
    const revalidated = validateRecordForCreate(this.#name, this.#def, merged, { unsetKeys });

    const eid = await deriveEid(this.#appId, this.#name, primaryKey);
    await this.#client.updateEntry(entry.txid, this.#name, revalidated, this.#protocolTags(eid));
    return revalidated as TRecord;
  }

  /**
   * Tombstone the record. Idempotent — calling delete on a primaryKey that
   * has no live entry (already tombstoned, or never written) returns
   * successfully without contacting the protocol layer. This matches REST
   * DELETE semantics and prevents retry loops from latching into permanent
   * errors when the work has already been done.
   */
  async delete(primaryKey: string): Promise<void> {
    const eid = await deriveEid(this.#appId, this.#name, primaryKey);
    const entry = await this.#client.getEntryByEid(this.#name, eid);
    if (!entry) return;
    await this.#client.deleteEntry(entry.txid, this.#name, this.#protocolTags(eid));
  }

  /**
   * Return the live record for this primaryKey, or null if absent.
   *
   * Single-record reads SURFACE a future-version entry as a thrown
   * `TarnSchemaVersionError` rather than skipping it (Tarn #37 policy): when
   * an app explicitly asks for one record by key, silently returning null
   * would be indistinguishable from "not found" and could mask data the user
   * knows exists. The caller should prompt the user to upgrade the app.
   */
  async get(primaryKey: string): Promise<TRecord | null> {
    const eid = await deriveEid(this.#appId, this.#name, primaryKey);
    const entry = await this.#client.getEntryByEid(this.#name, eid);
    if (!entry) return null;
    // Throws TarnSchemaVersionError for a future-version entry (intentional —
    // single-record reads don't swallow it).
    return this.#applySchemaVersion(entry) as TRecord;
  }

  /**
   * Delta-sync read: returns the events that have happened in this
   * collection since the last `getEntriesSince()` call. First call returns
   * the full live state; subsequent calls return only what changed.
   *
   * Each entry comes with its Eid alongside the typed record so the caller
   * can index local state by Eid (matching the `deleted` shape) — or by
   * primary key, with Eid as the bridge. Eid is deterministic from
   * `(appId, collectionName, primaryKey)`; use `collection.eidFor(pk)` if
   * you need to compute it for a record you already have locally.
   *
   * The SDK guarantees at most one event per Eid per call (dedup across
   * server pages, latest event wins). A `create → delete → recreate`
   * sequence within one window surfaces as a single live event with the
   * recreated data — the transient deletion is invisible. Apply `entries`
   * and `deleted` in either order; the result is identical.
   *
   * Cursor is persisted in IndexedDB per `(appId, dlk, collectionName)`.
   * A cleared cursor (private mode, fresh device, cleared site data)
   * naturally triggers a full re-sync on the next call.
   */
  async getEntriesSince(): Promise<{
    entries: Array<{ record: TRecord; eid: string }>;
    deleted: string[];
  }> {
    const raw = await this.#client.getEntriesSince(this.#name);
    const entries: Array<{ record: TRecord; eid: string }> = [];
    for (const e of raw.entries) {
      if (!e.eid) {
        // Orphan event (no Eid tag — legacy or malformed write). Typed
        // Collection drops these: every well-formed Collection write
        // carries an Eid (set in #protocolTags), so an orphan is by
        // construction not a record this Collection produced.
        console.warn(
          `[TarnClient] Collection '${this.#name}': dropping orphan delta event for txid ${e.txid}`,
        );
        continue;
      }
      try {
        // Read-side SchemaV dispatch (Tarn #37): migrate older entries
        // forward; SKIP-WITH-WARNING a future-version entry so one newer
        // record can't break a whole sync (same posture as orphan drops).
        const dispatched = dispatchSchemaVersion({
          record: e.data,
          tags: e.tags,
          clientVersion: this.#schemaVersion,
          migrations: this.#migrations,
          def: this.#def,
          txid: e.txid,
        });
        // Tarn #54: re-hydrate `date` fields to Date on the delta-sync path too.
        const record = coerceDatesForRead(this.#def, dispatched) as TRecord;
        entries.push({ record, eid: e.eid });
      } catch (err) {
        if (err instanceof TarnSchemaVersionError) {
          console.warn(
            `[TarnClient] Collection '${this.#name}': skipping delta entry ${e.txid} ` +
            `written under a newer schema version: ${err.message}`,
          );
          continue;
        }
        console.warn(
          `[TarnClient] Collection '${this.#name}': skipping malformed delta entry ${e.txid}: `,
          err instanceof Error ? err.message : err,
        );
      }
    }
    return { entries, deleted: raw.deleted };
  }

  /**
   * Derive the Eid for a primaryKey under this collection. Cheap, pure
   * function of `(appId, collectionName, primaryKey)` — no network. Useful
   * for callers that index their local store by primaryKey and need to
   * map an Eid (from `getEntriesSince`) back to a primaryKey.
   */
  async eidFor(primaryKey: string): Promise<string> {
    return await deriveEid(this.#appId, this.#name, primaryKey);
  }

  /**
   * Return all live records in this collection. Returns [] if none.
   *
   * Read-side SchemaV dispatch (Tarn #37): each entry is version-checked.
   * Older entries are migrated forward (no-op when no migrations declared);
   * an entry written under a FUTURE schema version is SKIPPED-WITH-WARNING
   * rather than thrown — a single record from a newer client must not break a
   * whole-collection read, the same defensive posture as the orphan / malformed
   * branch below.
   */
  async list(_opts: ListOpts = {}): Promise<TRecord[]> {
    const entries = await this.#client.getEntries(this.#name);
    const out: TRecord[] = [];
    for (const e of entries) {
      try {
        out.push(this.#applySchemaVersion(e) as TRecord);
      } catch (err) {
        if (err instanceof TarnSchemaVersionError) {
          // Future-version entry: skip so one newer record can't break the
          // whole list. The app should prompt the user to upgrade.
          console.warn(
            `[TarnClient] Collection '${this.#name}': skipping entry ${e.txid} ` +
            `written under a newer schema version: ${err.message}`,
          );
          continue;
        }
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
   * Uses `syncShareLog` rather than `readShareLog` so a previously-cached
   * (and possibly empty) read-state is always advanced forward to pick up
   * entries published since the last call. `readShareLog` short-circuits on
   * any cached state when called without `{ refresh: true }`; an app that
   * polls `listShared` (the common case) would seed an empty cache on its
   * first call — before the peer shares anything — and then return that stale
   * empty map forever, never surfacing newly-shared content. `syncShareLog`
   * cold-starts with a full bootstrap and otherwise syncs incrementally.
   *
   * Records that fail to fetch or decrypt are logged and skipped — partial
   * results are returned rather than aborting the whole call.
   */
  async listShared(connection: ShareConnection): Promise<TRecord[]> {
    this.#assertShareable('listShared');
    const state = await this.#client.syncShareLog(connection);
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
        // Tarn #54: re-hydrate `date` fields on shared records too, so the
        // read contract is uniform across own and shared reads.
        out.push(coerceDatesForRead(this.#def, plaintext) as TRecord);
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
   * Apply read-side SchemaV version dispatch to a freshly-decrypted entry
   * (Tarn #37). Reads the entry's `SchemaV` tag and branches on it:
   *   - same version → returns the record unchanged.
   *   - older version → migrates forward via declared `migrations` (no-op
   *     when none are declared — the backward-compatible-evolution contract).
   *   - newer version → throws `TarnSchemaVersionError` (the strict validator
   *     must never see a future entry; it would silently strip fields).
   *
   * Centralizes the policy so every read path (`get`, `list`,
   * `getEntriesSince`, `#findCurrent`) dispatches identically. Each caller
   * decides whether a thrown `TarnSchemaVersionError` is fatal (single-record
   * `get` / `#findCurrent`) or skip-with-warning (`list` / `getEntriesSince`).
   */
  #applySchemaVersion(entry: DecryptedEntry): Record<string, unknown> {
    const dispatched = dispatchSchemaVersion({
      record: entry.data,
      tags: entry.tags,
      clientVersion: this.#schemaVersion,
      migrations: this.#migrations,
      def: this.#def,
      txid: entry.txid,
    });
    // Tarn #54: re-hydrate `date` fields (ISO string on the wire) back to Date
    // so the runtime value matches the declared TS type. Lenient + in-place.
    return coerceDatesForRead(this.#def, dispatched);
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

  /**
   * Locate the live txid + decoded record for a primaryKey, or throw.
   *
   * Like `get`, this is a single-record path (update / share / shareWithAll),
   * so a future-version entry surfaces as `TarnSchemaVersionError` rather than
   * being silently skipped — refusing to read-modify-write a record we don't
   * fully understand is the safe choice (an update would otherwise be written
   * back under the OLDER current-client schema, dropping the future fields).
   */
  async #findCurrent(primaryKey: string): Promise<{ entry: DecryptedEntry; current: TRecord }> {
    const eid = await deriveEid(this.#appId, this.#name, primaryKey);
    const entry = await this.#client.getEntryByEid(this.#name, eid);
    if (!entry) {
      throw new TarnCollectionError(
        `Collection '${this.#name}': no record with primaryKey '${primaryKey}'`,
      );
    }
    const current = this.#applySchemaVersion(entry) as TRecord;
    return { entry, current };
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
  migrations?: Record<number, Migration> | undefined;
}): Collection<TRecord> {
  return new Collection<TRecord>(args);
}

// Re-export the derived-record type alias so step-4 callers can spell the
// generic precisely without reaching into the schema barrel.
export type { CollectionRecord };
