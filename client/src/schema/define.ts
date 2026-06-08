/**
 * `defineSchema()` — the entry point for app-side schema declaration.
 *
 * Validates the schema shape eagerly (fails fast at module load), enforces
 * the reserved-name list against the Tarn base schema, and brands the
 * returned object so only `defineSchema()` output is accepted by the SDK.
 */

import { RESERVED_TYPE_NAMES } from './reserved.js';
import { validateFieldDefault } from './validate.js';
import { isScopedMigrations, isPositiveIntKey } from './migrations.js';
import type {
  CollectionDef,
  FieldDef,
  FieldTypeName,
  Schema,
  SchemaInput,
  SchemaMigrations,
} from './types.js';

export class TarnSchemaError extends Error {
  override readonly name = 'TarnSchemaError';
}

/**
 * Declare an app schema. Validates the shape eagerly at runtime and reserves
 * the base-tier namespace. Returns a branded `Schema<S>` whose generic
 * parameter carries the declarative shape into the TS type system for
 * downstream record-type derivation.
 *
 * The input parameter is intentionally untyped at the constraint level —
 * TypeScript's `<const>` inference widens literal types when constrained by
 * generic types containing `Record<string, X>` index signatures (notably:
 * field shorthand `'string'` widens to `string`). Forgoing the constraint
 * lets `<const>` capture the literal shape, which is what makes
 * `tarn.books.create({ ... })` autocomplete work later. Structural validity
 * is checked at runtime by `validateSchemaInput`; downstream type derivation
 * navigates the inferred shape and surfaces type errors at consumption
 * sites instead of the definition site.
 */
export function defineSchema<const S>(input: S): Schema<S extends SchemaInput ? S : never> {
  validateSchemaInput(input as unknown as SchemaInput);
  return input as Schema<S extends SchemaInput ? S : never>;
}

// ============ Runtime validation ============

function validateSchemaInput(input: SchemaInput): void {
  if (typeof input !== 'object' || input === null) {
    throw new TarnSchemaError('Schema must be an object');
  }
  if (typeof input.appId !== 'string' || input.appId.length === 0) {
    throw new TarnSchemaError('Schema.appId must be a non-empty string');
  }
  if (!Number.isInteger(input.version) || input.version < 1) {
    throw new TarnSchemaError('Schema.version must be a positive integer (got ' + String(input.version) + ')');
  }
  if (typeof input.collections !== 'object' || input.collections === null) {
    throw new TarnSchemaError('Schema.collections must be an object');
  }

  const collectionNames = Object.keys(input.collections);
  if (collectionNames.length === 0) {
    throw new TarnSchemaError('Schema.collections must declare at least one collection');
  }

  for (const name of collectionNames) {
    if (RESERVED_TYPE_NAMES.has(name)) {
      throw new TarnSchemaError(
        `Collection name '${name}' is reserved by Tarn base schema. ` +
        `Reserved: ${[...RESERVED_TYPE_NAMES].join(', ')}`,
      );
    }
    if (!isValidCollectionName(name)) {
      throw new TarnSchemaError(
        `Collection name '${name}' must match /^[a-z][a-z0-9-]*$/ (lowercase, hyphen-separated)`,
      );
    }
    const def = input.collections[name];
    if (def === undefined) continue; // unreachable given Object.keys above, but TS needs it
    validateCollection(name, def);
  }

  if (input.migrations !== undefined) {
    validateMigrations(input.migrations, input.version, collectionNames);
  }
}

function validateCollection(name: string, def: CollectionDef): void {
  if (typeof def !== 'object' || def === null) {
    throw new TarnSchemaError(`Collection '${name}' must be an object`);
  }
  if (typeof def.primaryKey !== 'string' || def.primaryKey.length === 0) {
    throw new TarnSchemaError(`Collection '${name}': primaryKey must be a non-empty string`);
  }
  if (typeof def.fields !== 'object' || def.fields === null) {
    throw new TarnSchemaError(`Collection '${name}': fields must be an object`);
  }
  const fieldNames = Object.keys(def.fields);
  if (fieldNames.length === 0) {
    throw new TarnSchemaError(`Collection '${name}': must declare at least one field`);
  }
  if (!fieldNames.includes(def.primaryKey)) {
    throw new TarnSchemaError(
      `Collection '${name}': primaryKey '${def.primaryKey}' is not declared in fields`,
    );
  }
  if (def.shareable !== undefined && typeof def.shareable !== 'boolean') {
    throw new TarnSchemaError(`Collection '${name}': shareable must be a boolean if provided`);
  }
  for (const fieldName of fieldNames) {
    const fd = def.fields[fieldName];
    if (fd === undefined) continue;
    validateFieldDef(name, fieldName, fd);
  }
  // primaryKey field cannot be optional — primary keys must always be present.
  const pkDef = def.fields[def.primaryKey];
  if (pkDef !== undefined && isFieldDefOptional(pkDef)) {
    throw new TarnSchemaError(
      `Collection '${name}': primaryKey field '${def.primaryKey}' must be required (cannot be optional)`,
    );
  }
}

function validateFieldDef(collection: string, field: string, def: FieldDef): void {
  if (typeof def === 'string') {
    const stripped = def.endsWith('?') ? def.slice(0, -1) : def;
    if (!isValidTypeName(stripped)) {
      throw new TarnSchemaError(
        `Collection '${collection}', field '${field}': invalid type '${def}' ` +
        `(allowed: string, number, integer, boolean, date, json — with optional '?' suffix)`,
      );
    }
    return;
  }
  if (typeof def !== 'object' || def === null) {
    throw new TarnSchemaError(
      `Collection '${collection}', field '${field}': must be a type-name string or an object definition`,
    );
  }
  if (!isValidTypeName(def.type)) {
    throw new TarnSchemaError(
      `Collection '${collection}', field '${field}': invalid type '${String(def.type)}'`,
    );
  }
  if (def.required !== undefined && typeof def.required !== 'boolean') {
    throw new TarnSchemaError(
      `Collection '${collection}', field '${field}': 'required' must be a boolean if provided`,
    );
  }
  if ('enum' in def && def.enum !== undefined) {
    if (!Array.isArray(def.enum) || def.enum.length === 0) {
      throw new TarnSchemaError(
        `Collection '${collection}', field '${field}': 'enum' must be a non-empty array`,
      );
    }
  }
  // Tarn #58b: validate the declared default against this field's own type +
  // enum NOW, at schema-definition time — not lazily at the first create that
  // omits the field. A bad default is a schema bug; fail where it lives.
  validateFieldDefault(collection, field, def);
}

/**
 * Validate the `migrations` block. Accepts both the flat (legacy) shape
 * `{ [version]: fn }` and the collection-scoped shape
 * `{ [collectionName]: { [version]: fn } }` (Tarn #55), disambiguated by
 * `isScopedMigrations`. Scoped keys must name declared collections so a typo'd
 * collection name fails at definition time rather than silently never running.
 */
function validateMigrations(
  migs: SchemaMigrations,
  currentVersion: number,
  collectionNames: string[],
): void {
  if (typeof migs !== 'object' || migs === null) {
    throw new TarnSchemaError('Schema.migrations must be an object');
  }
  if (isScopedMigrations(migs)) {
    const known = new Set(collectionNames);
    for (const collName of Object.keys(migs)) {
      if (!known.has(collName)) {
        throw new TarnSchemaError(
          `Schema.migrations references unknown collection '${collName}' ` +
          `(declared collections: ${collectionNames.join(', ')})`,
        );
      }
      const perColl = (migs as Record<string, unknown>)[collName];
      if (typeof perColl !== 'object' || perColl === null) {
        throw new TarnSchemaError(
          `Schema.migrations['${collName}'] must be an object of { [version]: fn }`,
        );
      }
      validateVersionMap(perColl as Record<string, unknown>, currentVersion, `migrations['${collName}']`);
    }
    return;
  }
  // Flat / legacy shape: { [version]: fn } applied to every collection.
  validateVersionMap(migs as Record<string, unknown>, currentVersion, 'migrations');
}

/** Validate a single `{ [version]: fn }` map (shared by both migration shapes). */
function validateVersionMap(
  map: Record<string, unknown>,
  currentVersion: number,
  label: string,
): void {
  for (const key of Object.keys(map)) {
    if (!isPositiveIntKey(key)) {
      throw new TarnSchemaError(`${label}: version key '${key}' must be a positive integer`);
    }
    const v = Number(key);
    if (v >= currentVersion) {
      throw new TarnSchemaError(
        `${label}: migration for version ${v} is not less than current schema.version ` +
        `${currentVersion}; migrations apply only to entries written under PRIOR versions`,
      );
    }
    if (typeof map[key] !== 'function') {
      throw new TarnSchemaError(`${label}: migration for version ${v} must be a function`);
    }
  }
}

// ============ Helpers ============

function isFieldDefOptional(def: FieldDef): boolean {
  if (typeof def === 'string') return def.endsWith('?');
  return def.required === false;
}

function isValidTypeName(s: unknown): s is FieldTypeName {
  return s === 'string' || s === 'number' || s === 'integer'
    || s === 'boolean' || s === 'date' || s === 'json';
}

function isValidCollectionName(s: string): boolean {
  return /^[a-z][a-z0-9-]*$/.test(s);
}
