/**
 * Types for the Collection<T> abstraction.
 *
 * Collection<T> wraps an underlying TarnClient (currently the JS client in
 * tarn.js — step 6 of the redesign ports it to TS). The wrapper validates
 * payloads against a schema, attaches `Eid` and `SchemaV` tags for
 * cross-device record identity, and exposes a primary-key-keyed CRUD surface
 * with no Arweave concepts visible to apps.
 *
 * `ITarnClient` defines exactly what Collection consumes from the underlying
 * client. As long as a client satisfies this interface, Collection<T> works.
 * This isolates the Collection layer from the JS-vs-TS distinction during
 * the migration.
 */

/** Arweave tag — name/value pair attached to an entry on write. */
export type Tag = { name: string; value: string };

/**
 * A decrypted entry as returned by `getEntries`. The `data` field is the
 * plaintext object the writer encrypted; `tags` are the Arweave tags on the
 * entry (App, Type, Lk, Eid, SchemaV, etc.).
 */
export type DecryptedEntry = {
  txid: string;
  data: Record<string, unknown>;
  tags: Tag[];
};

/**
 * The slice of TarnClient that Collection<T> needs. Step 6 will replace the
 * JS implementation behind this interface with a native TS implementation.
 */
export interface ITarnClient {
  isLoggedIn(): boolean;

  createEntry(
    type: string,
    plaintext: Record<string, unknown>,
    extraTags?: Tag[],
  ): Promise<{ txid: string }>;

  updateEntry(
    priorTxid: string,
    type: string,
    plaintext: Record<string, unknown>,
    extraTags?: Tag[],
  ): Promise<{ txid: string }>;

  deleteEntry(
    targetTxid: string,
    type: string,
    extraTags?: Tag[],
  ): Promise<{ txid: string }>;

  getEntries(type: string): Promise<DecryptedEntry[]>;
}

/** Error class for Collection-level failures (record not found, etc.). */
export class TarnCollectionError extends Error {
  override readonly name = 'TarnCollectionError';
}
