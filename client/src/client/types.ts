/**
 * Public types for the TarnClient class.
 *
 * `ClientConfig` is what apps pass to `TarnClient.create()`. The schema
 * generic carries the full declarative shape into the type system so the
 * dynamic `tarn.<collection>` namespace gets typed record arguments and
 * returns automatically.
 */

import type { Collection, ITarnClient } from '../collections/index.js';
import type {
  CollectionDef,
  Schema,
  SchemaInput,
  CollectionRecord,
} from '../schema/index.js';
import type { TarnStorageAdapter } from '../storage/index.js';

/** The branded schema produced by `defineSchema()`; keeps the type guard explicit. */
export type AnySchema = Schema<SchemaInput>;

/** Configuration accepted by `TarnClient.create()`. */
export type ClientConfig<S extends AnySchema> = {
  /** Tarn API base URL, e.g. 'https://api.tarn.dev'. */
  apiBase: string;

  /** Registered app identifier (must match the schema's appId). */
  appId: string;

  /** App schema as produced by `defineSchema()`. */
  schema: S;

  /** Where to persist the session blob. Use `TarnStorage.localStorage()` for typical browser apps. */
  storage: TarnStorageAdapter;

  /**
   * Optional fetch override (testing). Defaults to global `fetch`. The
   * underlying client's retry / error-mapping behavior is unchanged.
   */
  fetchImpl?: typeof fetch;
};

/**
 * Map of collection name → typed Collection<TRecord>, derived from the
 * schema declaration. Drives the dynamic `tarn.<collection>` namespace.
 */
export type CollectionsOf<S extends SchemaInput> = {
  [K in keyof S['collections']]: S['collections'][K] extends CollectionDef
    ? Collection<CollectionRecord<S['collections'][K]>>
    : never;
};

/** Top-level surface re-exported for use in the TarnClient class. */
export type { Collection, ITarnClient };
