/**
 * Runtime validators for record payloads against a CollectionDef.
 *
 * `validateRecordForCreate` is strict: missing required fields throw, unknown
 * fields throw (typo protection), defaults are applied. `validateRecordForUpdate`
 * is partial: only the keys present in the patch are validated; primaryKey
 * cannot be updated.
 *
 * Both functions return a normalized payload with defaults applied and any
 * `Date`/string coercion for `date` fields done. Caller hands the result to
 * the encryption layer.
 */

import { TarnSchemaError } from './define.js';
import type { CollectionDef, FieldDef, FieldTypeName } from './types.js';

type NormalizedField = {
  type: FieldTypeName;
  required: boolean;
  hasDefault: boolean;
  default: unknown;                          // may be undefined — see hasDefault for presence
  enum: readonly unknown[] | undefined;      // explicit `| undefined` for exactOptionalPropertyTypes
};

/** Internal: normalize the FieldDef union to a single shape. */
export function normalizeField(def: FieldDef): NormalizedField {
  if (typeof def === 'string') {
    if (def.endsWith('?')) {
      return {
        type: def.slice(0, -1) as FieldTypeName,
        required: false,
        hasDefault: false,
        default: undefined,
        enum: undefined,
      };
    }
    return {
      type: def as FieldTypeName,
      required: true,
      hasDefault: false,
      default: undefined,
      enum: undefined,
    };
  }
  return {
    type: def.type,
    required: def.required !== false,
    hasDefault: 'default' in def && def.default !== undefined,
    default: def.default,
    enum: def.enum,
  };
}

/**
 * Validate a payload for a `create` call. Applies defaults for absent fields
 * with declared defaults. Rejects unknown fields and missing requireds.
 *
 * `opts.unsetKeys` (Tarn #58a) names fields the caller is deliberately CLEARING
 * — the update path uses this when re-validating a post-unset merged record.
 * For a key in this set, the declared default is NOT re-applied (so unsetting a
 * defaulted optional field actually clears it instead of silently reverting to
 * the default). A required field in this set still fails the required check, so
 * required fields remain un-clearable. No effect on the normal create path,
 * which passes no `unsetKeys`.
 */
export function validateRecordForCreate(
  collectionName: string,
  collection: CollectionDef,
  payload: unknown,
  opts?: { unsetKeys?: ReadonlySet<string> | undefined },
): Record<string, unknown> {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new TarnSchemaError(
      `Collection '${collectionName}': payload must be a non-array object`,
    );
  }
  const obj = payload as Record<string, unknown>;
  const fieldDefs = collection.fields;
  const fieldNames = new Set(Object.keys(fieldDefs));

  // Reject unknown fields.
  for (const key of Object.keys(obj)) {
    if (!fieldNames.has(key)) {
      throw new TarnSchemaError(
        `Collection '${collectionName}': unknown field '${key}' ` +
        `(allowed: ${[...fieldNames].join(', ')})`,
      );
    }
  }

  const unsetKeys = opts?.unsetKeys;
  const out: Record<string, unknown> = {};
  for (const fieldName of fieldNames) {
    const fdef = fieldDefs[fieldName];
    if (fdef === undefined) continue;
    const norm = normalizeField(fdef);
    let value = obj[fieldName];

    // Re-apply the declared default for an absent field — UNLESS the caller is
    // deliberately clearing this field via update({ unset }). Skipping the
    // default there is what makes unset actually clear a defaulted field
    // instead of reverting it (Tarn #58a). A required field still trips the
    // required check below, so it can't be cleared.
    if (value === undefined && norm.hasDefault && !(unsetKeys?.has(fieldName))) {
      value = norm.default;
    }

    if (value === undefined) {
      if (norm.required) {
        throw new TarnSchemaError(
          `Collection '${collectionName}': required field '${fieldName}' is missing`,
        );
      }
      continue;
    }

    out[fieldName] = coerceAndValidate(collectionName, fieldName, norm, value);
  }
  return out;
}

/**
 * Validate a patch for an `update` call. Only the keys present in the patch
 * are validated. Cannot include primaryKey. Returns the normalized patch (the
 * caller merges it with the prior record before encrypting).
 */
export function validateRecordForUpdate(
  collectionName: string,
  collection: CollectionDef,
  patch: unknown,
): Record<string, unknown> {
  if (typeof patch !== 'object' || patch === null || Array.isArray(patch)) {
    throw new TarnSchemaError(
      `Collection '${collectionName}': patch must be a non-array object`,
    );
  }
  const obj = patch as Record<string, unknown>;
  const fieldDefs = collection.fields;
  const fieldNames = new Set(Object.keys(fieldDefs));

  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj)) {
    if (!fieldNames.has(key)) {
      throw new TarnSchemaError(
        `Collection '${collectionName}': unknown field '${key}' in patch`,
      );
    }
    if (key === collection.primaryKey) {
      throw new TarnSchemaError(
        `Collection '${collectionName}': cannot update primaryKey '${key}'`,
      );
    }
    const value = obj[key];
    if (value === undefined) {
      // A patch with `{ field: undefined }` is treated as "do not touch this field."
      // Explicit field removal is out of scope for v1; revisit if needed.
      continue;
    }
    const fdef = fieldDefs[key];
    if (fdef === undefined) continue;
    const norm = normalizeField(fdef);
    out[key] = coerceAndValidate(collectionName, key, norm, value);
  }
  return out;
}

// ============ Per-field type checking + coercion ============

function coerceAndValidate(
  collectionName: string,
  fieldName: string,
  norm: NormalizedField,
  value: unknown,
): unknown {
  // Enum check is type-agnostic.
  if (norm.enum !== undefined && !norm.enum.includes(value)) {
    throw new TarnSchemaError(
      `Collection '${collectionName}', field '${fieldName}': value not in enum ` +
      `(allowed: ${norm.enum.map((v) => JSON.stringify(v)).join(', ')})`,
    );
  }

  switch (norm.type) {
    case 'string':
      if (typeof value !== 'string') {
        throw fieldTypeError(collectionName, fieldName, 'string', value);
      }
      return value;

    case 'number':
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw fieldTypeError(collectionName, fieldName, 'finite number', value);
      }
      return value;

    case 'integer':
      if (typeof value !== 'number' || !Number.isInteger(value)) {
        throw fieldTypeError(collectionName, fieldName, 'integer', value);
      }
      return value;

    case 'boolean':
      if (typeof value !== 'boolean') {
        throw fieldTypeError(collectionName, fieldName, 'boolean', value);
      }
      return value;

    case 'date': {
      if (value instanceof Date) {
        if (Number.isNaN(value.getTime())) {
          throw fieldTypeError(collectionName, fieldName, 'valid Date', value);
        }
        return value;
      }
      if (typeof value === 'string') {
        const d = new Date(value);
        if (Number.isNaN(d.getTime())) {
          throw fieldTypeError(collectionName, fieldName, 'ISO date string or Date', value);
        }
        return d;
      }
      throw fieldTypeError(collectionName, fieldName, 'Date or ISO string', value);
    }

    case 'json':
      // Any JSON-serializable value is accepted. Verify by JSON.stringify
      // round-trip — catches `undefined` in arrays, functions, symbols, BigInts.
      try {
        JSON.stringify(value);
      } catch (err) {
        throw new TarnSchemaError(
          `Collection '${collectionName}', field '${fieldName}': ` +
          `value is not JSON-serializable (${err instanceof Error ? err.message : 'unknown error'})`,
        );
      }
      return value;
  }
}

/**
 * Validate a long-form field's declared `default` against its own type + enum
 * at schema-definition time (Tarn #58b). Without this, a malformed default
 * (wrong type, or a value outside the field's enum) sails through
 * `defineSchema()` and only blows up at the first `create()` that omits the
 * field — far from where the mistake actually lives.
 *
 * Runs the default through the exact same `coerceAndValidate` path that a
 * supplied field value would hit on create, so the type/enum rules can never
 * drift between "validating a default" and "validating a real value". The
 * coerced result is discarded — this is a check, not a mutation of the schema
 * (the default is re-coerced normally on each create). Throws `TarnSchemaError`
 * on a bad default; no-op for fields without a default.
 */
export function validateFieldDefault(
  collectionName: string,
  fieldName: string,
  def: FieldDef,
): void {
  // Shorthand fields ('string', 'date?', …) can't carry a default — nothing to check.
  if (typeof def === 'string') return;
  if (!('default' in def) || def.default === undefined) return;
  const norm = normalizeField(def);
  // Reuse the create-time validator so a default is held to the identical
  // type + enum contract a real value would be. Any failure is rethrown with
  // a "default" prefix so the message points at the schema, not a phantom create.
  try {
    coerceAndValidate(collectionName, fieldName, norm, norm.default);
  } catch (err) {
    throw new TarnSchemaError(
      `Collection '${collectionName}', field '${fieldName}': invalid default — ` +
      `${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Re-hydrate `date`-typed fields on READ (Tarn #54).
 *
 * The write path coerces a `date` field to a `Date`, but the wire format is
 * JSON: `JSON.stringify` turns the `Date` into an ISO string, and the read path
 * does `JSON.parse`, so the field comes back as a **string** — contradicting the
 * declared TS type (`ScalarTypeOf<'date'> === Date`). An app that read the field
 * and called `.getTime()` would throw at runtime despite a clean compile.
 *
 * This function walks the collection's declared fields and converts each
 * present `date` field from an ISO string back to a `Date`, so the runtime
 * value matches the type the schema promises. Conversion is LENIENT and
 * non-destructive:
 *   - a value already a `Date` is left as-is;
 *   - a string that parses to a valid date becomes a `Date`;
 *   - a string that does NOT parse (corrupt / legacy junk), or any non-string
 *     non-Date value, is left UNCHANGED — read-path code must never throw on a
 *     single bad field. (The strict create-time validator already guards
 *     writes; a bad value on read is logged elsewhere, not crashed here.)
 *
 * Returns the SAME object reference, mutated in place for the date keys only —
 * the record came fresh from `JSON.parse` / version dispatch, so in-place
 * mutation is safe and avoids an extra copy on the hot read path.
 *
 * Bookish impact: Bookish declares NO `date`-typed fields (its date-like
 * fields — dateRead, readingStartedAt, createdAt, modifiedAt — are all
 * `number?` ms-epoch), so this path is inert for the live app. See the issue
 * notes for the full audit.
 */
export function coerceDatesForRead(
  collection: CollectionDef,
  record: Record<string, unknown>,
): Record<string, unknown> {
  for (const [fieldName, fieldDef] of Object.entries(collection.fields)) {
    const norm = normalizeField(fieldDef);
    if (norm.type !== 'date') continue;
    const value = record[fieldName];
    if (value === undefined || value === null) continue;
    if (value instanceof Date) continue;
    if (typeof value === 'string') {
      const d = new Date(value);
      if (!Number.isNaN(d.getTime())) {
        record[fieldName] = d;
      }
      // else: leave the malformed string untouched — never throw on read.
    }
    // Non-string, non-Date (e.g. a number someone wrote via the escape hatch):
    // leave untouched. The typed write path can't produce this.
  }
  return record;
}

function fieldTypeError(
  collectionName: string,
  fieldName: string,
  expected: string,
  got: unknown,
): TarnSchemaError {
  const gotDesc =
    got === null ? 'null'
      : Array.isArray(got) ? 'array'
        : typeof got;
  return new TarnSchemaError(
    `Collection '${collectionName}', field '${fieldName}': expected ${expected}, got ${gotDesc}`,
  );
}
