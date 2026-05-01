/**
 * Schema DSL types and TS-level record-type derivation.
 *
 * The DSL is pure data (a JS object literal). `defineSchema()` is generic over
 * its argument so the declarative shape is captured into the type system,
 * which lets the Collection<T> API derive concrete record types from the
 * schema declaration without hand-written `.d.ts` files.
 */

// ============ Field type DSL ============

export type FieldTypeName =
  | 'string'
  | 'number'
  | 'integer'
  | 'boolean'
  | 'date'
  | 'json';

/** Shorthand: type name, with optional trailing `?` for optional. */
export type FieldShorthand = FieldTypeName | `${FieldTypeName}?`;

/** Long-form field definition. */
export type FieldLongForm = {
  type: FieldTypeName;
  required?: boolean;
  default?: unknown;
  enum?: readonly unknown[];
};

export type FieldDef = FieldShorthand | FieldLongForm;

// ============ Collection / Schema input ============

export type CollectionDef = {
  /** Name of the field that uniquely identifies a record. Must be a declared field. */
  primaryKey: string;
  fields: Record<string, FieldDef>;
  /** Whether records of this collection can be shared via `share()`. Default: false. */
  shareable?: boolean;
};

export type Migration = (old: Record<string, unknown>) => Record<string, unknown>;

export type SchemaInput = {
  appId: string;
  /** Bumped on shape changes; drives migrations on read. */
  version: number;
  collections: Record<string, CollectionDef>;
  /** Per-version migrators applied on read for entries written under older schema versions. */
  migrations?: Record<number, Migration>;
};

/** Branded schema — only produced by `defineSchema()`. */
export type Schema<S extends SchemaInput = SchemaInput> = S & {
  readonly __tarnSchemaBrand: unique symbol;
};

// ============ TS type derivation: FieldDef → record field type ============

type ScalarTypeOf<T extends FieldTypeName> =
  T extends 'string' ? string :
  T extends 'number' ? number :
  T extends 'integer' ? number :
  T extends 'boolean' ? boolean :
  T extends 'date' ? Date :
  T extends 'json' ? unknown :
  never;

type StripOptional<T extends string> = T extends `${infer U}?` ? U : T;
type IsShorthandOptional<T extends string> = T extends `${string}?` ? true : false;

/** Resolve a single FieldDef to a concrete TS type. */
export type ResolveFieldType<T extends FieldDef> =
  T extends FieldShorthand
    ? ScalarTypeOf<Extract<StripOptional<T>, FieldTypeName>>
    : T extends FieldLongForm
      ? T extends { enum: infer E extends readonly unknown[] }
        ? E[number]
        : ScalarTypeOf<T['type']>
      : never;

/** Whether a FieldDef is optional. */
export type IsFieldOptional<T extends FieldDef> =
  T extends FieldShorthand
    ? IsShorthandOptional<T>
    : T extends FieldLongForm
      ? T['required'] extends false
        ? true
        : false
      : false;

/** Build a record type from a fields object. */
export type RecordOf<F extends Record<string, FieldDef>> =
  // Required fields:
  {
    [K in keyof F as IsFieldOptional<F[K]> extends false ? K : never]: ResolveFieldType<F[K]>;
  }
  // Optional fields:
  & {
    [K in keyof F as IsFieldOptional<F[K]> extends true ? K : never]?: ResolveFieldType<F[K]>;
  };

/** Type of a single record in a collection. */
export type CollectionRecord<C extends CollectionDef> = RecordOf<C['fields']>;

/** Helper: lookup the record type for a named collection in a schema. */
export type RecordOfCollection<S extends SchemaInput, K extends keyof S['collections']> =
  S['collections'][K] extends CollectionDef ? CollectionRecord<S['collections'][K]> : never;

/** Helper: type of the primaryKey value for a collection (always string in v1). */
export type PrimaryKeyValueOf<C extends CollectionDef> =
  C['fields'][C['primaryKey']] extends FieldDef
    ? ResolveFieldType<C['fields'][C['primaryKey']]>
    : never;
