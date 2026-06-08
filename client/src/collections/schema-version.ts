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

import type { CollectionDef, Migration } from '../schema/index.js';
import { normalizeField } from '../schema/index.js';
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
 * @param def          optional collection definition. When supplied, an older
 *                      entry that is STILL missing a required field after
 *                      migration triggers a `console.warn` (Tarn #57) — the
 *                      "added a required field without a default or migrator"
 *                      landmine. The record is returned as-is (non-breaking: we
 *                      warn, we do not throw or drop), so apps can detect the
 *                      contract violation in dev without legacy reads suddenly
 *                      failing in production.
 * @param txid         optional txid for error/diagnostic context
 */
export function dispatchSchemaVersion(args: {
  record: Record<string, unknown>;
  tags: Tag[] | undefined;
  clientVersion: number;
  migrations?: Record<number, Migration> | undefined;
  def?: CollectionDef | undefined;
  txid?: string | null | undefined;
}): Record<string, unknown> {
  const { record, tags, clientVersion, migrations, def, txid } = args;
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
    // Tarn #58c: a gap in the migration chain (a step in the walked range with
    // no declared migrator) used to be a SILENT no-op for that step. That's the
    // documented "this step was additive" contract when the app declares NO
    // migrations at all — but once an app DOES declare migrations, a missing
    // step is far more likely an authoring mistake (e.g. declaring `2` and `4`
    // but forgetting `3`) that silently skips a needed transform. We still
    // tolerate it (skipping is the safe runtime choice — the additive contract
    // may genuinely hold for that step), but warn so the gap is visible.
    const declaredAny = Object.keys(migrations).length > 0;
    const missing: number[] = [];
    for (let v = entryVersion; v < clientVersion; v++) {
      const migrate = migrations[v];
      if (typeof migrate === 'function') {
        migrated = migrate(migrated);
      } else if (declaredAny) {
        missing.push(v);
      }
    }
    if (missing.length > 0) {
      console.warn(
        `[TarnClient] schema-version dispatch: migration chain gap — no migrator ` +
        `declared for version(s) ${missing.join(', ')} while migrating an entry ` +
        `from v${entryVersion} toward v${clientVersion}` +
        (txid ? ` (txid: ${txid})` : '') +
        `. That step is being skipped (assumed additive / backward-compatible). ` +
        `If the step was NOT additive, declare migrations[v] for it.`,
      );
    }
  }

  // Tarn #57: an older entry that is STILL missing a required field after any
  // migration is the "added a required field without a default or migrator"
  // landmine — the additive-evolution contract only safely covers added
  // OPTIONAL fields (or required fields with a default). We do NOT throw or
  // drop (that would break apps reading legacy data); we warn so the contract
  // violation is visible in dev. The strict create-time validator still
  // enforces requiredness on writes; this is purely a read-path heads-up.
  warnIfMissingRequired(migrated, def, entryVersion, clientVersion, txid);

  return migrated;
}

/**
 * Emit a `console.warn` if `record` is missing any field the collection
 * declares as required (Tarn #57). No-op when no `def` is supplied or every
 * required field is present. Never throws — read-path defensive posture.
 */
function warnIfMissingRequired(
  record: Record<string, unknown>,
  def: CollectionDef | undefined,
  entryVersion: number,
  clientVersion: number,
  txid: string | null | undefined,
): void {
  if (!def) return;
  const missingRequired: string[] = [];
  for (const [fieldName, fieldDef] of Object.entries(def.fields)) {
    const norm = normalizeField(fieldDef);
    // A required field with a declared default is never "missing" — the
    // create-time validator fills it. Only flag required fields with neither a
    // value nor a default.
    if (norm.required && !norm.hasDefault && record[fieldName] === undefined) {
      missingRequired.push(fieldName);
    }
  }
  if (missingRequired.length > 0) {
    console.warn(
      `[TarnClient] schema-version dispatch: entry written under schema v${entryVersion} ` +
      `is missing required field(s) [${missingRequired.join(', ')}] under current ` +
      `schema v${clientVersion}` +
      (txid ? ` (txid: ${txid})` : '') +
      `. This is the "added a required field without a default or migrator" case: ` +
      `the additive-evolution contract only covers added OPTIONAL fields (or ` +
      `required fields WITH a default). Add a default, or declare a migrations[${entryVersion}] ` +
      `migrator that fills the field. The record is returned unchanged (this is a warning, not an error).`,
    );
  }
}
