/**
 * Public surface of the collections module.
 *
 * Step 2 ships the typed Collection<T> wrapper consumed by the new SDK.
 * The dynamic `tarn.<name>` namespace lands in step 4.
 */

export { Collection, createCollection } from './collection.js';
export type { ListOpts } from './collection.js';
export { deriveEid } from './eid.js';
export { TarnCollectionError } from './types.js';
export type { ITarnClient, DecryptedEntry, Tag, ShareConnection } from './types.js';
