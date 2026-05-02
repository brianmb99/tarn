/**
 * `tarn.connections.*` — lifecycle of friend connections.
 *
 * Wraps the underlying client's connection primitives and re-shapes them
 * around typed objects. Internally the underlying state is richer
 * (share-keypair pair material, signing keys, mute state, pending
 * requests, etc.) but apps see only the stable identifiers needed to call
 * collection sharing methods, plus the small set of "manage connections"
 * affordances (invite preview, issued-invite list, incoming-request poll).
 */

import type {
  Connection,
  CreateInviteOpts,
  IncomingRequest,
  InvitePreview,
  InviteToken,
  IssuedInvite,
  ListIncomingOpts,
  RedeemedInvite,
} from '../../sharing/index.js';
import type { UnderlyingConnection } from '../../collections/index.js';

// ============ Underlying-shape types ============
//
// The underlying client returns rich, loosely-typed objects (see tarn.ts).
// We declare just enough structure here to project them into the typed
// namespace shapes without scattering `as any` casts.

interface UnderlyingInviteToken {
  token_id: string;
  invite_url: string;
  expires_at: number;
}

interface UnderlyingInvitePreview {
  inviter_display_name: string;
  inviter_share_pub_fingerprint: string;
  app_id: string;
  issued_at: number;
  expires_at: number;
}

interface UnderlyingIssuedInvite {
  token_id: string;
  display_name: string;
  issued_at: number;
  expires_at: number;
  redeemed_at: number | null;
  redeemer_share_pub_fingerprint: string | null;
}

interface UnderlyingRedeemedInvite {
  requestNonce: string;
  recipientSharePubBase64Url: string;
}

interface UnderlyingIncomingRequest {
  senderEmail: string;
  senderSharePubBase64Url: string;
  senderSigningPubBase64: string;
  senderAppId: string;
  requestNonce: string;
  timestamp: number;
  message: string | null;
  viaInviteToken?: string | null;
  txid: string;
}

interface UnderlyingRevokeResult {
  revoked: boolean;
}

/**
 * The slice of the underlying TarnClient this namespace consumes. Listed
 * here rather than on the shared ITarnClient because Collection<T> doesn't
 * need most of these — only this namespace does.
 */
export interface IConnectionsClient {
  listConnections(): Promise<UnderlyingConnection[]>;
  setConnectionLabel(connection: { share_pub: string }, label: string): Promise<unknown>;
  muteConnection(connection: { share_pub: string }): Promise<unknown>;
  unmuteConnection(connection: { share_pub: string }): Promise<unknown>;
  isMuted(connection: { share_pub: string }): Promise<boolean>;
  removeConnection(connection: { share_pub: string }, opts?: Record<string, unknown>): Promise<unknown>;
  sendConnectionRequest(recipientEmail: string, opts?: Record<string, unknown>): Promise<unknown>;
  acceptConnectionRequest(requestNonce: string, opts?: Record<string, unknown>): Promise<unknown>;
  listIncomingRequests(opts?: Record<string, unknown>): Promise<UnderlyingIncomingRequest[]>;
  createInviteToken(opts?: Record<string, unknown>): Promise<UnderlyingInviteToken>;
  redeemInviteToken(tokenId: string, payloadKeyB64Url: string): Promise<UnderlyingRedeemedInvite>;
  previewInviteToken(tokenId: string, payloadKeyB64Url: string): Promise<UnderlyingInvitePreview | null>;
  listIssuedInvites(): Promise<UnderlyingIssuedInvite[]>;
  revokeIssuedInvite(tokenId: string): Promise<UnderlyingRevokeResult>;
}

export class ConnectionsNamespace {
  readonly #client: IConnectionsClient;
  constructor(client: IConnectionsClient) {
    this.#client = client;
  }

  /**
   * List the user's accepted connections. Each entry carries the stable
   * identifiers (`share_pub`, `signing_pub`) plus the optional fields the
   * underlying record actually has (`email`, `label`, `muted`,
   * `established_at`, `initial_request_nonce`).
   */
  async list(): Promise<Connection[]> {
    const raw = await this.#client.listConnections();
    return raw.map((r) => this.#toConnection(r));
  }

  /** Set or change the human label on a connection. */
  async setLabel(connection: Connection, label: string): Promise<void> {
    await this.#client.setConnectionLabel(connection, label);
  }

  /**
   * Mute a connection — sharing primitives skip muted connections, so
   * `Collection.shareWithAll()` won't publish to them. Reversible via unmute.
   */
  async mute(connection: Connection): Promise<void> {
    await this.#client.muteConnection(connection);
  }

  async unmute(connection: Connection): Promise<void> {
    await this.#client.unmuteConnection(connection);
  }

  async isMuted(connection: Connection): Promise<boolean> {
    return this.#client.isMuted(connection);
  }

  /** Remove a connection. */
  async remove(connection: Connection): Promise<void> {
    await this.#client.removeConnection(connection);
  }

  /**
   * Send a connection request to another user (by their email under this app).
   * The recipient sees it via `listIncomingRequests`.
   */
  async invite(recipientEmail: string, opts: Record<string, unknown> = {}): Promise<unknown> {
    return this.#client.sendConnectionRequest(recipientEmail, opts);
  }

  /**
   * Accept a previously-received connection request by its nonce. Apps get
   * the nonce from `listIncomingRequests()` and pass it here.
   */
  async accept(requestNonce: string, opts: Record<string, unknown> = {}): Promise<unknown> {
    return this.#client.acceptConnectionRequest(requestNonce, opts);
  }

  /**
   * List pending incoming connection requests — connection-request blobs
   * the user hasn't accepted yet. Side effect: requests with a matching
   * issued-invite token auto-accept (the invite-token flow's whole purpose
   * is to skip the manual accept step).
   *
   * Apps call this on app-open / on a poll cadence to surface "X wants to
   * connect" UI; calling code paths can also use it as a heartbeat to
   * trigger pending-invite redemptions.
   */
  async listIncomingRequests(opts: ListIncomingOpts = {}): Promise<IncomingRequest[]> {
    const raw = await this.#client.listIncomingRequests(opts);
    return raw.map((r) => this.#toIncomingRequest(r));
  }

  /**
   * Create a single-use invite token + URL. The recipient redeems it to form
   * a connection without an in-app account search.
   */
  async createInvite(opts: CreateInviteOpts = {}): Promise<InviteToken> {
    const raw = await this.#client.createInviteToken(opts as Record<string, unknown>);
    return {
      token_id: raw.token_id,
      invite_url: raw.invite_url,
      expires_at: raw.expires_at,
    };
  }

  /**
   * Non-consuming peek at an invite token. Returns `null` for any
   * recoverable failure (expired, already used, not found, wrong payload
   * key) — never throws on those modes. Throws only on malformed args.
   *
   * Apps render the result on the redeem landing page so the recipient
   * sees who's inviting them before committing.
   */
  async previewInvite(tokenId: string, payloadKey: string): Promise<InvitePreview | null> {
    const raw = await this.#client.previewInviteToken(tokenId, payloadKey);
    if (!raw) return null;
    return {
      inviter_display_name: raw.inviter_display_name,
      inviter_share_pub_fingerprint: raw.inviter_share_pub_fingerprint,
      app_id: raw.app_id,
      issued_at: raw.issued_at,
      expires_at: raw.expires_at,
    };
  }

  /** Redeem an invite token (the recipient side of `createInvite`). */
  async redeemInvite(tokenId: string, payloadKey: string): Promise<RedeemedInvite> {
    const raw = await this.#client.redeemInviteToken(tokenId, payloadKey);
    return {
      request_nonce: raw.requestNonce,
      recipient_share_pub: raw.recipientSharePubBase64Url,
    };
  }

  /**
   * List the user's outstanding issued invites. Apps surface this in
   * "Manage invites" UI with a revoke action.
   */
  async listIssuedInvites(): Promise<IssuedInvite[]> {
    const raw = await this.#client.listIssuedInvites();
    return raw.map((r) => ({
      token_id: r.token_id,
      display_name: r.display_name,
      issued_at: r.issued_at,
      expires_at: r.expires_at,
      redeemed_at: r.redeemed_at,
      redeemer_share_pub_fingerprint: r.redeemer_share_pub_fingerprint,
    }));
  }

  /**
   * Revoke an issued invite. Best-effort: deletes the server-side row (so
   * the link can no longer be redeemed) and removes the local entry. A
   * 404 on the server delete is treated as success.
   */
  async revokeIssuedInvite(tokenId: string): Promise<{ revoked: boolean }> {
    const raw = await this.#client.revokeIssuedInvite(tokenId);
    return { revoked: raw.revoked };
  }

  // ============ helpers ============

  #toConnection(raw: UnderlyingConnection): Connection {
    // Surface every field the underlying record carries that has a typed
    // home on Connection. Each is optional — invite-token connections may
    // lack `email`, very old records may lack `established_at`, etc.
    const out: Connection = { share_pub: raw.share_pub, signing_pub: raw.signing_pub };
    if (typeof raw.email === 'string') out.email = raw.email;
    if (typeof raw.label === 'string') out.label = raw.label;
    if (typeof raw.muted === 'boolean') out.muted = raw.muted;
    if (typeof raw.established_at === 'number') out.established_at = raw.established_at;
    if (typeof raw.initial_request_nonce === 'string') {
      out.initial_request_nonce = raw.initial_request_nonce;
    }
    return out;
  }

  #toIncomingRequest(raw: UnderlyingIncomingRequest): IncomingRequest {
    const out: IncomingRequest = {
      email: raw.senderEmail,
      share_pub: raw.senderSharePubBase64Url,
      signing_pub: raw.senderSigningPubBase64,
      app_id: raw.senderAppId,
      request_nonce: raw.requestNonce,
      timestamp: raw.timestamp,
      message: raw.message,
      txid: raw.txid,
    };
    if (typeof raw.viaInviteToken === 'string') out.via_invite_token = raw.viaInviteToken;
    return out;
  }
}
