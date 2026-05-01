/**
 * Public types for the sharing layer.
 *
 * `Connection` is the typed wrapper apps see. The underlying client tracks
 * far more state per connection (share-keypair pair material, signing keys,
 * pending request envelopes, mute state, etc.) — those live in the
 * underlying client and stay encapsulated. Apps only see the stable
 * identifiers needed to call collection.share() / unshare() / listShared().
 *
 * The `share_pub` field is the recipient's X25519 sharing public key
 * (base64url, 32 raw bytes). It functions as the connection's stable
 * identifier in the share-log layer; we surface it here so apps can route
 * sharing calls without parsing the underlying connection record format.
 */

/**
 * A connection (friend) the user has established. Returned by
 * `tarn.connections.list()` and consumed by collection sharing methods.
 *
 * Apps should treat the contents as opaque. The shape may grow over time
 * (e.g., adding `acceptedAt`, `lastSyncedAt`) but `share_pub` and
 * `signing_pub` are stable identifiers.
 */
export type Connection = {
  /** Recipient's X25519 sharing public key, base64url. Stable identifier. */
  share_pub: string;
  /** Recipient's signing public key, base64url. Used to verify their share-log entries. */
  signing_pub: string;
  /** Optional human-friendly label set by the user. */
  label?: string;
  /** Whether this connection is currently muted (set by `tarn.connections.mute`). */
  muted?: boolean;
};

/**
 * One entry in a friend's share-log map: a content_id pointing at the latest
 * Arweave txid plus the per-content shareKey needed to decrypt that blob.
 */
export type ShareLogEntry = {
  contentId: string;
  txid: string;
  shareKey: string;
};

/** Outcome of `Collection.shareWithAll()`. */
export type ShareWithAllResult = {
  ok: number;
  failed: Array<{ connection: Connection; error: string }>;
};
