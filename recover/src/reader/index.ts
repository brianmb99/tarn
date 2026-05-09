/**
 * Public surface of the schema-aware reader.
 *
 * The Reader class is normally obtained from
 * {@link import('../recover.js').recover}; the types are re-exported here
 * for callers that want to spell them in their own type annotations.
 */

export { Reader } from './reader.js';
export type { ReaderInit, ReaderSchema, ReaderAccount } from './reader.js';
export { resolveContentBlobs } from './resolve.js';
export { attachSchemaVersionMarker, type DecryptedEntry } from './decode.js';
export {
  SharingReader,
  replayConnection,
  type SharingReaderInit,
  type Connection,
  type ShareLogEvent,
  type ShareLogEntryBase,
  type ShareLogDirection,
} from './sharing-reader.js';
