/**
 * Schema-aware decode: turn a decrypted JSON payload into a typed record
 * tagged with `_schemaVersion` if the writer's schema version is older
 * than the caller's.
 *
 * The recover package deliberately does NOT run apps' migrations
 * automatically. The plan is explicit (see `STANDALONE_RECOVERY_PLAN.md`
 * §"API shape" notes): "App decides how to migrate / display." We simply
 * surface the version marker so the app can route to the right code path.
 *
 * Tarn's writer attaches a `SchemaV` Arweave tag (see `Collection.create`
 * in `client/src/collections/collection.ts`). When the tag is present and
 * its numeric value is less than the caller's `schema.version`, we attach
 * `_schemaVersion: <writer-version>` to the returned record. When the tag
 * is absent (very old / pre-collections data) we skip the marker — there
 * is nothing to compare against.
 */

import type { BlobRecord } from '../gateway/queries.js';

/**
 * The shape yielded by the Reader's `entries(...)` async iterator.
 *
 * `data` is the decrypted plaintext payload as written. `_schemaVersion`
 * is attached when the entry was written under an older schema version
 * than the caller's `schema.version`. `tags` is the original Arweave tag
 * list (see `BlobRecord.tags`) so apps can inspect protocol metadata
 * without re-walking the blob.
 */
export type DecryptedEntry = {
  /** Arweave transaction id of the live tip for this logical record. */
  txid: string;
  /** Plaintext record fields (per the caller-supplied schema). */
  data: Record<string, unknown>;
  /** Original Arweave tags (App, Type, Lk, Eid, SchemaV, Gen, ...). */
  tags: { name: string; value: string }[];
  /**
   * Present only when the entry was written under a schema older than the
   * caller's. Apps detect "this record needs migration" by checking for
   * this property's presence.
   */
  _schemaVersion?: number;
};

/**
 * Stamp a decrypted payload with the version marker when applicable.
 *
 * Pure: no I/O, no global state. Reads `tagMap['SchemaV']`, parses it as
 * an integer, and returns a `DecryptedEntry` shape.
 */
export function attachSchemaVersionMarker(
  blob: BlobRecord,
  data: Record<string, unknown>,
  callerSchemaVersion: number,
): DecryptedEntry {
  const out: DecryptedEntry = {
    txid: blob.txid,
    data,
    tags: blob.tags,
  };
  const raw = blob.tagMap['SchemaV'];
  if (raw !== undefined) {
    const writerVersion = Number.parseInt(raw, 10);
    if (
      Number.isInteger(writerVersion) &&
      writerVersion >= 1 &&
      writerVersion < callerSchemaVersion
    ) {
      out._schemaVersion = writerVersion;
    }
  }
  return out;
}
