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
 *
 * Writes return the freshly-issued `shareKey` alongside the `txid` so
 * sharing-path callers can publish through the share-log without an extra
 * blob fetch + AES-KW unwrap. `shareKey` is null on legacy v1/v2 accounts
 * (no per-content CEK); sharing primitives reject null shareKeys.
 */
export interface ITarnClient {
  isLoggedIn(): boolean;

  // ---- Entry CRUD ----

  createEntry(
    type: string,
    plaintext: Record<string, unknown>,
    extraTags?: Tag[],
  ): Promise<{ txid: string; shareKey: string | null }>;

  updateEntry(
    priorTxid: string,
    type: string,
    plaintext: Record<string, unknown>,
    extraTags?: Tag[],
  ): Promise<{ txid: string; shareKey: string | null }>;

  deleteEntry(
    targetTxid: string,
    type: string,
    extraTags?: Tag[],
  ): Promise<{ txid: string }>;

  getEntries(type: string): Promise<DecryptedEntry[]>;

  // ---- Blob / shareKey helpers ----

  /** Resolve the shareKey for a txid (cache + fallback unwrap). Null on miss. */
  getShareKey(txid: string): Promise<string | null>;

  /** Fetch encrypted blob bytes for a txid. Null if unavailable. */
  fetchBlob(txid: string): Promise<Uint8Array | null>;

  /** Decrypt a blob using a known shareKey directly (the recipient path). */
  decryptSharedBlob(blob: Uint8Array, shareKey: string): Promise<Record<string, unknown>>;

  // ---- Sharing primitives ----

  /**
   * Iterable of the user's connections. Returns the underlying client's
   * record shape — the Collection layer only consumes `share_pub`,
   * `signing_pub`, and `muted` (via `isMuted`); other fields are passed
   * through unchanged. The `tarn.connections.*` namespace normalizes
   * these to the public `Connection` type.
   */
  listConnections(): Promise<UnderlyingConnection[]>;

  /** Whether a connection is muted (skips share publishing). */
  isMuted(connection: ShareConnection): Promise<boolean>;

  /**
   * Publish a (contentId, txid, shareKey) triple to a connection's share-log.
   * The §8.4 idempotency rules ensure a re-share with the same contentId
   * supersedes the prior entry.
   */
  shareContent(
    connection: ShareConnection,
    contentId: string,
    txid: string,
    shareKey: string,
  ): Promise<unknown>;

  /** Publish a remove op for a contentId on a connection's share-log. */
  unshareContent(connection: ShareConnection, contentId: string): Promise<unknown>;

  /**
   * Read a connection's share-log and return the resolved state map:
   * `{ [contentId]: { tx_id, cek } }`.
   */
  readShareLog(
    connection: ShareConnection,
    opts?: { refresh?: boolean },
  ): Promise<Record<string, { tx_id: string; cek: string }>>;
}

/**
 * Minimal connection shape consumed by Collection<T>. The public sharing
 * module uses a richer `Connection` type (in `../sharing/types.ts`) but
 * Collection only depends on the two stable identifiers — any object with
 * those two fields satisfies the contract.
 */
export type ShareConnection = {
  share_pub: string;
  signing_pub: string;
  label?: string;
  muted?: boolean;
};

/**
 * Underlying-client connection record. The JS client's `listConnections`
 * returns rich objects; Collection<T> and the connections namespace both
 * accept the same shape and project / normalize as needed. ShareConnection
 * is structurally a subset.
 *
 * The four optional fields below are part of the protocol record (see
 * sharing.ts `ConnectionEntry` and the upsertConnection sites) and are
 * surfaced on the typed `Connection` shape. They're declared here so the
 * connections namespace can reach them without going through the index
 * signature.
 */
export type UnderlyingConnection = ShareConnection & {
  email?: string | null;
  established_at?: number | null;
  initial_request_nonce?: string | null;
} & Record<string, unknown>;

/** Error class for Collection-level failures (record not found, etc.). */
export class TarnCollectionError extends Error {
  override readonly name = 'TarnCollectionError';
}
