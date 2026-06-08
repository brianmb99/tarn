/**
 * Public surface of the schema module.
 *
 * Apps import from here:
 *
 * ```ts
 * import { defineSchema } from '@tarn/sdk/schema';
 *
 * export const mySchema = defineSchema({ ... });
 * ```
 *
 * Internal modules (collection API, sharing, etc.) import from this barrel
 * too — keeps the import surface uniform.
 */

export { defineSchema, TarnSchemaError } from './define.js';
export { validateRecordForCreate, validateRecordForUpdate, normalizeField, validateFieldDefault, coerceDatesForRead } from './validate.js';
export { RESERVED_TYPE_NAMES } from './reserved.js';
export { resolveCollectionMigrations, isScopedMigrations } from './migrations.js';

export type {
  // DSL
  FieldTypeName,
  FieldShorthand,
  FieldLongForm,
  FieldDef,
  CollectionDef,
  Migration,
  CollectionMigrations,
  ScopedMigrations,
  SchemaMigrations,
  SchemaInput,
  Schema,
  // Type derivation
  ResolveFieldType,
  IsFieldOptional,
  RecordOf,
  CollectionRecord,
  RecordOfCollection,
  PrimaryKeyValueOf,
} from './types.js';
