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
 * `share_pub` and `signing_pub` are stable identifiers. The other fields
 * are present when known to this client — e.g., a connection formed via
 * email-based handshake will carry the peer's email; a connection formed
 * via invite-token redemption may not.
 */
export type Connection = {
  /** Recipient's X25519 sharing public key, base64url. Stable identifier. */
  share_pub: string;
  /** Recipient's signing public key, base64url. Used to verify their share-log entries. */
  signing_pub: string;
  /**
   * The peer's email under this app, when known.
   *
   * Present for email-based handshakes (the email is the lookup that
   * found the peer). Often absent for invite-token connections where the
   * inviter doesn't see the redeemer's email and vice versa.
   *
   * The most durable human-readable identifier — survives label changes,
   * which is useful for "manage connections" UI.
   */
  email?: string;
  /** Optional human-friendly label set by the user. */
  label?: string;
  /** Whether this connection is currently muted (set by `tarn.connections.mute`). */
  muted?: boolean;
  /**
   * Unix seconds at which this connection was established (the timestamp
   * carried in the accept envelope on the side that processed the accept).
   *
   * Drives "most recently connected first" ordering and serves as a
   * tiebreaker when ordering by app-level events. Always present for
   * connections formed under SDK v1 or later.
   */
  established_at?: number;
  /**
   * The request nonce that bootstrapped this connection — set on whichever
   * side initiated, kept for debugging affordances ("this connection was
   * formed via invite XYZ at time T"). Apps generally don't need to read it.
   */
  initial_request_nonce?: string;
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

/**
 * Result of `tarn.connections.createInvite(...)` — a single-use invite link
 * the inviter hands off to the recipient (via QR code, SMS, etc.).
 *
 * `invite_url` is the shareable form: `<template>/<token_id>#<payload_key>`.
 * The `payload_key` lives in the URL fragment and never leaves the device,
 * so the API server can't decrypt the payload.
 */
export type InviteToken = {
  token_id: string;
  invite_url: string;
  /** Unix seconds at which the invite expires (server enforces a 30-day cap). */
  expires_at: number;
};

/** Options accepted by `tarn.connections.createInvite()`. */
export type CreateInviteOpts = {
  /**
   * Optional local label for the connection-to-be (≤ 64 chars). Stored only
   * in the inviter's encrypted issued-invites record; surfaced in
   * `listIssuedInvites()` and used to seed `Connection.label` when the
   * matching redemption auto-accepts. Never sent to the recipient — Tarn
   * has no concept of a user-facing display name on the wire.
   */
  label?: string;
  /** 1–30; defaults to 7. */
  expiry_days?: number;
};

/**
 * Result of `tarn.connections.previewInvite(...)` — non-consuming peek at
 * an invite token. Returns null on any recoverable failure (expired, used,
 * not found, wrong payload key); never throws on those.
 *
 * Tarn does not carry a name for the inviter on the wire — the encrypted
 * payload contains only their public keys. Apps that want to show "X
 * invited you" UI should pass the inviter's name through their own
 * delivery channel (e.g., the message accompanying the link).
 */
export type InvitePreview = {
  /**
   * Short hex digest of the inviter's share_pub. Stable identifier for the
   * inviter that doesn't expose their email — useful for "this is the same
   * person who invited me last week" UI.
   */
  inviter_share_pub_fingerprint: string;
  app_id: string;
  /** Unix seconds. */
  issued_at: number;
  /** Unix seconds. */
  expires_at: number;
};

/**
 * One row in `tarn.connections.listIssuedInvites()` — the inviter's view of
 * the invites they've created. Apps surface this in "Manage invites" UI
 * with a revoke action.
 */
export type IssuedInvite = {
  token_id: string;
  /**
   * Local-only label the inviter chose at invite-creation time. Used to
   * render "Manage invites" UI ("Pending: Maya") and to seed
   * `Connection.label` when the matching redemption auto-accepts. Never
   * sent to the recipient.
   */
  label: string;
  issued_at: number;
  expires_at: number;
  /** Unix seconds at which the invite was redeemed; null if still pending. */
  redeemed_at: number | null;
  /** Hex fingerprint of the redeemer's share_pub (set on redemption). */
  redeemer_share_pub_fingerprint: string | null;
};

/**
 * Result of `tarn.connections.redeemInvite(...)` — the request_nonce of the
 * connection-request the redeem call sent back to the inviter. The
 * inviter's poll auto-accepts the matching request, after which both sides
 * see each other in `tarn.connections.list()`.
 */
export type RedeemedInvite = {
  request_nonce: string;
  /** Inviter's share_pub, base64url. */
  recipient_share_pub: string;
};

/**
 * One row in `tarn.connections.listIncomingRequests()` — a pending
 * connection-request waiting for the user to accept. Apps surface these as
 * "X wants to connect" prompts; on user action, call
 * `tarn.connections.accept(request_nonce)`.
 */
export type IncomingRequest = {
  /** Sender's email under their app. */
  email: string;
  /** Sender's share_pub, base64url. */
  share_pub: string;
  /** Sender's signing_pub, base64url. */
  signing_pub: string;
  /** Sender's app_id (must equal the recipient's app_id for the request to be valid). */
  app_id: string;
  /** Pass to `accept()` to bind the inbound request. */
  request_nonce: string;
  /** Unix seconds. */
  timestamp: number;
  message: string | null;
  /**
   * Set when the sender redeemed an invite token to bootstrap this request.
   * The inviter's auto-accept path matches by token_id; apps usually don't
   * need to read it.
   */
  via_invite_token?: string;
  /** The Arweave txid of the inbox blob carrying this request. */
  txid: string;
};

/** Options accepted by `tarn.connections.listIncomingRequests()`. */
export type ListIncomingOpts = {
  /** How many recent inbox windows to scan. Defaults to the SDK's poll budget. */
  windows?: number;
};
