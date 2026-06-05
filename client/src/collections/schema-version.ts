/**
 * Read-side SchemaV version dispatch (Tarn #37 / audit finding SDK-1).
 *
 * Every write stamps a `SchemaV` Arweave tag carrying the schema version the
 * writer used (see `Collection.#protocolTags` and `advanced.entries`). Until
 * now nothing on the read path consumed it — so the first schema-version bump
 * had no defined cross-version read behavior. This module is that consumer.
 *
 * The contract is intentionally conservative (an MVP that closes the landmine,
 * not a general migration engine). See `docs/SDK_ARCHITECTURE.md` →
 * "Schema versioning" for the full rationale. The four cases:
 *
 *   - `entryV === clientV` → normal path (today's behavior, unchanged).
 *   - `entryV <  clientV`  → BACKWARD-COMPATIBLE EVOLUTION. The entry was
 *     written by an older client. We apply any declared per-version
 *     `migrations` for versions `[entryV, clientV - 1]` in ascending order
 *     (the migration seam — a no-op today when no app declares migrations),
 *     then pass the record through to validation as before. The contract:
 *     today, only additive / backward-compatible schema changes are
 *     supported, OR the app declares a `migrations[v]` forward-migrator.
 *   - `entryV >  clientV`  → FUTURE ENTRY the current client can't understand.
 *     We do NOT feed it to the strict validator (which would silently strip
 *     unknown fields or throw on a missing-required mismatch and corrupt the
 *     read). Instead the dispatcher raises `TarnSchemaVersionError`. The
 *     read-path caller decides whether to skip-with-warning (list / delta —
 *     so one future entry can't break a whole sync) or surface the error
 *     (single-record `get`). See `collection.ts`.
 *   - missing `SchemaV` tag (legacy / orphan entries) → treated as the
 *     OLDEST known version (1). Never crashes — folds into the `entryV <=
 *     clientV` paths above. (A legacy entry is, by definition, not newer than
 *     the current client.)
 */

import type { Migration } from '../schema/index.js';
import type { Tag } from './types.js';

/**
 * Raised when an entry was written under a schema version NEWER than the one
 * this client understands (`entryV > clientV`). The strict validator must not
 * see such an entry — it would silently strip the unknown-to-us fields. The
 * read path catches this to skip-with-warning (list / delta-sync) or rethrow
 * (single-record `get`).
 *
 * Carries the offending versions and the entry's txid so callers can log /
 * surface a precise message ("this record needs a newer app version").
 */
export class TarnSchemaVersionError extends Error {
  override readonly name = 'TarnSchemaVersionError';
  /** Schema version the entry was written under (from the `SchemaV` tag). */
  readonly entryVersion: number;
  /** Schema version this client understands. */
  readonly clientVersion: number;
  /** Arweave txid of the offending entry, if known. */
  readonly txid: string | null;

  constructor(args: { entryVersion: number; clientVersion: number; txid?: string | null | undefined }) {
    super(
      `Entry was written under schema version ${args.entryVersion}, but this ` +
      `client only understands version ${args.clientVersion}. Reading it with ` +
      `the current validator could corrupt the record (unknown fields stripped). ` +
      `Upgrade the app to a build that understands schema v${args.entryVersion}.` +
      (args.txid ? ` (txid: ${args.txid})` : ''),
    );
    this.entryVersion = args.entryVersion;
    this.clientVersion = args.clientVersion;
    this.txid = args.txid ?? null;
  }
}

/** Oldest schema version. Used as the fallback for entries with no SchemaV tag. */
export const OLDEST_SCHEMA_VERSION = 1;

/**
 * Read the integer value of the `SchemaV` tag from an Arweave tag list.
 *
 * Returns `null` when the tag is absent or malformed — callers treat that as
 * "unknown / oldest" (legacy or orphan entries written before SchemaV existed,
 * or by a non-typed write path). Mirrors how `readGenTag` parses the `Gen`
 * tag on the protocol read path.
 */
export function readSchemaVTag(tags: Tag[] | undefined): number | null {
  if (!Array.isArray(tags)) return null;
  const tag = tags.find((t) => t && t.name === 'SchemaV');
  if (!tag || typeof tag.value !== 'string') return null;
  const n = parseInt(tag.value, 10);
  if (!Number.isInteger(n) || n < 1) return null;
  return n;
}

/**
 * Apply read-side schema-version dispatch to a single decrypted record.
 *
 * Implements the four-case policy documented at the top of this module.
 * Pure and synchronous — no I/O. The caller supplies the decrypted record,
 * the entry's tags (for the SchemaV value), and the client's schema version.
 *
 * Returns the record to hand to the strict validator (migrated forward if
 * older + a migrator was declared; unchanged otherwise). Throws
 * `TarnSchemaVersionError` for a future-version entry — the caller decides
 * whether to skip or rethrow.
 *
 * @param record       the decrypted plaintext object
 * @param tags         the entry's Arweave tags (SchemaV is read from here)
 * @param clientVersion the schema version this client understands
 * @param migrations   per-version forward-migrators declared in the schema
 *                      (`migrations[v]` migrates a v→(v+1) record); empty/no-op
 *                      when the app declares none. Today this is the migration
 *                      seam: present so forward-migration can be wired up
 *                      later without another read-path landmine.
 * @param txid         optional txid for error/diagnostic context
 */
export function dispatchSchemaVersion(args: {
  record: Record<string, unknown>;
  tags: Tag[] | undefined;
  clientVersion: number;
  migrations?: Record<number, Migration> | undefined;
  txid?: string | null | undefined;
}): Record<string, unknown> {
  const { record, tags, clientVersion, migrations, txid } = args;
  const entryVersion = readSchemaVTag(tags) ?? OLDEST_SCHEMA_VERSION;

  // Case: future entry the current client can't understand. Never validate.
  if (entryVersion > clientVersion) {
    throw new TarnSchemaVersionError({ entryVersion, clientVersion, txid });
  }

  // Case: same version → normal path, untouched.
  if (entryVersion === clientVersion) return record;

  // Case: older entry → backward-compatible evolution. Apply declared
  // forward-migrators for [entryVersion, clientVersion - 1] in ascending
  // order. With no migrations declared this is a pure pass-through — the
  // documented "additive change" contract — and the seam stays inert.
  let migrated = record;
  if (migrations) {
    for (let v = entryVersion; v < clientVersion; v++) {
      const migrate = migrations[v];
      if (typeof migrate === 'function') {
        migrated = migrate(migrated);
      }
    }
  }
  return migrated;
}
