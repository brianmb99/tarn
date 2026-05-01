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
 */
export function validateRecordForCreate(
  collectionName: string,
  collection: CollectionDef,
  payload: unknown,
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

  const out: Record<string, unknown> = {};
  for (const fieldName of fieldNames) {
    const fdef = fieldDefs[fieldName];
    if (fdef === undefined) continue;
    const norm = normalizeField(fdef);
    let value = obj[fieldName];

    if (value === undefined && norm.hasDefault) {
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
