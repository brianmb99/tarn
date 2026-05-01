/**
 * Top-level barrel for the new SDK surface (in-progress).
 *
 * Apps import from here:
 *
 *   import { TarnClient, defineSchema, TarnStorage } from '@tarn/sdk';
 *
 * Step 4 ships TarnClient + the dynamic collection namespace + lifecycle
 * namespaces. Step 6 ports the underlying JS client to TS (no public-API
 * change). Step 7 wires the build pipeline so consumers see this as the
 * entry point in package.json.
 */

export { TarnClient } from './client/index.js';
export type {
  ClientConfig,
  AnySchema,
  CollectionsOf,
  TarnClientCreateConfig,
  IUnderlyingClient,
  UnderlyingFactory,
} from './client/index.js';

export { defineSchema, TarnSchemaError } from './schema/index.js';
export type {
  Schema,
  SchemaInput,
  CollectionDef,
  FieldDef,
  CollectionRecord,
  RecordOfCollection,
} from './schema/index.js';

export { Collection, TarnCollectionError } from './collections/index.js';
export type { ITarnClient } from './collections/index.js';

export { TarnStorage } from './storage/index.js';
export type { TarnStorageAdapter } from './storage/index.js';

export type { Connection } from './sharing/index.js';
