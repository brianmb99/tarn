/**
 * `tarn.connections.*` — lifecycle of friend connections.
 *
 * Wraps the underlying client's connection primitives and re-shapes them
 * around a typed `Connection` object. Internally the underlying state is
 * richer (share-keypair pair material, signing keys, mute state, pending
 * requests, etc.) but apps see only the stable identifiers needed to call
 * collection sharing methods.
 */

import type { Connection } from '../../sharing/index.js';
import type { UnderlyingConnection } from '../../collections/index.js';

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
  listIncomingRequests(opts?: Record<string, unknown>): Promise<unknown>;
  createInviteToken(opts?: Record<string, unknown>): Promise<unknown>;
  redeemInviteToken(tokenId: string, payloadKeyB64Url: string): Promise<unknown>;
}

export class ConnectionsNamespace {
  readonly #client: IConnectionsClient;
  constructor(client: IConnectionsClient) {
    this.#client = client;
  }

  /**
   * List the user's accepted connections. The underlying client returns rich
   * connection records (UnderlyingConnection has share_pub + signing_pub
   * required, plus arbitrary additional fields); we normalize to the public
   * `Connection` shape and drop unknown fields.
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
   * The recipient sees it via `listIncomingRequests` (currently advanced).
   */
  async invite(recipientEmail: string, opts: Record<string, unknown> = {}): Promise<unknown> {
    return this.#client.sendConnectionRequest(recipientEmail, opts);
  }

  /**
   * Accept a previously-received connection request by its nonce. The nonce
   * is part of the inbound request envelope; apps surface it via incoming-
   * request UI.
   */
  async accept(requestNonce: string, opts: Record<string, unknown> = {}): Promise<unknown> {
    return this.#client.acceptConnectionRequest(requestNonce, opts);
  }

  /**
   * Create a single-use invite token + URL. The recipient redeems it to form
   * a connection without an in-app account search.
   */
  async createInvite(opts: Record<string, unknown> = {}): Promise<unknown> {
    return this.#client.createInviteToken(opts);
  }

  /** Redeem an invite token (the recipient side of `createInvite`). */
  async redeemInvite(tokenId: string, payloadKey: string): Promise<unknown> {
    return this.#client.redeemInviteToken(tokenId, payloadKey);
  }

  // ============ helpers ============

  #toConnection(raw: UnderlyingConnection): Connection {
    const out: Connection = { share_pub: raw.share_pub, signing_pub: raw.signing_pub };
    if (typeof raw.label === 'string') out.label = raw.label;
    if (typeof raw.muted === 'boolean') out.muted = raw.muted;
    return out;
  }
}
