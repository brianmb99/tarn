/**
 * Sharing-side reader (Phase 5): connections + per-pair share-log walks.
 *
 * Composed by {@link import('./reader.js').Reader} — apps don't instantiate
 * this directly; they call `reader.connections()` / `reader.shareLog(...)`.
 *
 * The two surfaces:
 *
 *   - `connections()` returns the user's friend list, drawn from the
 *     `tarn-share-state` collection (Eid=`tarn-connections-v1`). The
 *     connections record is a single encrypted blob owned by the user, so
 *     reusing the schema-aware reader's resolution + decrypt path is a
 *     near-trivial wiring.
 *
 *   - `shareLog({ direction })` returns each event the user has on either
 *     side of every connected pair. For each connection we derive the
 *     per-pair keys (X25519 + HKDF), discover the highest seq via the
 *     stealth-tag probe, walk back to the most recent snapshot, then walk
 *     forward applying the §8.4 idempotency rules. We yield every entry
 *     as a typed `ShareLogEvent` discriminated union — apps that just
 *     want the final state can re-derive it from the events, but per-event
 *     access is the more general primitive.
 *
 * Out of scope for v1:
 *   - HPKE-inbox bootstrap. The connections record IS the source of truth
 *     for who the user is connected to; the inbox carries handshake material
 *     that has already been processed into that record by the live SDK. We
 *     do NOT crawl the inbox during recovery — there's no peer that the
 *     connections record doesn't already mention. (If a future scenario
 *     emerges where this matters, the `hpkeOpen` + `validateConnection*`
 *     primitives are already exported from `recover/src/sharing/`.)
 *
 *   - rotate_identity follow-on log re-bootstrap. The current implementation
 *     yields the rotate_identity event in-stream and then stops walking the
 *     OLD log (matching the live SDK's "terminal on the old log" semantics)
 *     but does NOT auto-discover the rotated peer's NEW connection record.
 *     If the user's connections record was kept up-to-date at write time,
 *     the rotated peer appears as a separate Connection with the new keys;
 *     `shareLog()` walks that connection independently. If the connections
 *     record was NOT kept up-to-date (e.g. the user logged out before the
 *     rotation propagated), the rotated entries are unreachable until the
 *     live SDK reconciles. This matches the same constraint the live SDK
 *     has across devices.
 */

import type { MultiGatewayClient } from '../gateway/multi-gateway.js';
import { findContentBlobs, findShareLogBlobs, type BlobRecord } from '../gateway/queries.js';
import { decryptWithCEK } from '../crypto/aes.js';
import { base64UrlToBytes } from '../crypto/encoding.js';
import type { UnwrappedDekChain } from '../crypto/envelope.js';
import { resolveContentBlobs } from './resolve.js';
import {
  CONNECTIONS_CONTENT_ID,
  isConnectionsRecord,
  type ConnectionsRecord,
  type ConnectionEntry,
} from '../sharing/hpke-primitives.js';
import {
  decryptShareLogEntry,
  deriveLogTag,
  discoverHighestSeq,
  verifyOperationSignature,
  applyOperationToState,
  OP_SNAPSHOT,
  OP_ROTATE_IDENTITY,
  type OperationSigned,
  type ShareLogState,
} from '../sharing/share-log-primitives.js';
import { getPairKeysFor } from '../sharing/pair-keys.js';

// ============ Public types ============

/**
 * One connection in the user's friend list, projected from the underlying
 * `ConnectionEntry` record. Mirrors `client/src/sharing/types.ts` — same
 * keys, same shapes.
 */
export type Connection = {
  /** Peer's X25519 sharing public key, base64url. Stable identifier. */
  share_pub: string;
  /** Peer's signing public key, base64url. */
  signing_pub: string;
  /** Peer's username under the same app, when known. */
  username?: string;
  /** Optional human label set by the user. */
  label?: string;
  /** Whether the user had muted this connection (only present when set). */
  muted?: boolean;
  /** Unix seconds at which the connection was established. */
  established_at?: number;
  /** Request nonce that bootstrapped the connection (debugging affordance). */
  initial_request_nonce?: string;
  /** Peer's `credential_lookup_key`, when carried in the underlying record. */
  credential_lookup_key?: string;
  /** When the peer rotated their identity, the unix timestamp of that rotation. */
  rotated_at?: number;
  /** When the peer rotated their identity, their prior share_pub. */
  prior_share_pub?: string;
};

/**
 * Discriminated union of every event a recover client may surface from a
 * per-pair share log. Mirrors the operation shapes in
 * `recover/src/sharing/share-log-primitives.ts`, plus a `connection` field
 * carrying the peer this event came from and a `verified` boolean (false
 * means the entry's ECDSA signature did not validate against the
 * connection's `signing_pub` — apps generally treat unverified events as
 * forgeries to ignore).
 */
export type ShareLogEvent =
  | (ShareLogEntryBase & {
      type: 'add';
      content_id: string;
      tx_id: string;
      cek: string;
      shared_at: number;
    })
  | (ShareLogEntryBase & {
      type: 'update';
      content_id: string;
      tx_id: string;
      updated_at: number;
    })
  | (ShareLogEntryBase & {
      type: 'rotate';
      content_id: string;
      cek: string;
      rotated_at: number;
    })
  | (ShareLogEntryBase & {
      type: 'remove';
      content_id: string;
      removed_at: number;
    })
  | (ShareLogEntryBase & {
      type: 'snapshot';
      state: Record<string, { tx_id: string; cek: string }>;
      snapshot_at: number;
      prior_seq: number | null;
    })
  | (ShareLogEntryBase & {
      type: 'rotate_identity';
      new_share_pub: string;
      new_signing_pub: string;
      new_credential_lookup_key: string;
      rotated_at: number;
    });

/** Fields every {@link ShareLogEvent} carries regardless of type. */
export type ShareLogEntryBase = {
  /** The connection this event came from. */
  connection: Connection;
  /** Sequence number on the per-pair log. */
  seq: number;
  /** Direction relative to the recovered user. */
  direction: 'incoming' | 'outgoing';
  /** Arweave transaction id of the entry blob. */
  txid: string;
  /** Whether the entry's ECDSA signature was verifiable by the peer's signing_pub. */
  verified: boolean;
};

/** Direction selector accepted by `shareLog()`. */
export type ShareLogDirection = 'incoming' | 'outgoing';

// ============ SharingReader ============

export interface SharingReaderInit {
  appId: string;
  client: MultiGatewayClient;
  dataLookupKey: string;
  dekChain: UnwrappedDekChain;
  /** The recovered user's X25519 share key (private + public, raw bytes). */
  shareKeyPair: { privateKey: Uint8Array; publicKey: Uint8Array };
}

/**
 * Lazily-cached reader over the user's social graph. Expensive computations
 * (the connections-record fetch, per-connection pair-key derivation) are
 * memoized so repeated `connections()` / `shareLog()` calls don't redo work.
 */
export class SharingReader {
  readonly #appId: string;
  readonly #client: MultiGatewayClient;
  readonly #dataLookupKey: string;
  readonly #dekChain: UnwrappedDekChain;
  readonly #sharePriv: Uint8Array;
  readonly #sharePub: Uint8Array;

  /** Promise cache for the connections record. Single in-flight request. */
  #connectionsPromise: Promise<Connection[]> | undefined;

  /** Pair-key cache keyed by peer share_pub (base64url). */
  readonly #pairKeyCache = new Map<
    string,
    Promise<Awaited<ReturnType<typeof getPairKeysFor>>>
  >();

  constructor(init: SharingReaderInit) {
    if (!init.client) throw new Error('SharingReader: client is required');
    if (!init.dekChain || init.dekChain.dekByGen.size === 0) {
      throw new Error('SharingReader: dekChain is required and must be non-empty');
    }
    if (!(init.shareKeyPair?.privateKey instanceof Uint8Array)
      || init.shareKeyPair.privateKey.length !== 32) {
      throw new Error('SharingReader: shareKeyPair.privateKey must be a 32-byte Uint8Array');
    }
    if (!(init.shareKeyPair?.publicKey instanceof Uint8Array)
      || init.shareKeyPair.publicKey.length !== 32) {
      throw new Error('SharingReader: shareKeyPair.publicKey must be a 32-byte Uint8Array');
    }
    this.#appId = init.appId;
    this.#client = init.client;
    this.#dataLookupKey = init.dataLookupKey;
    this.#dekChain = init.dekChain;
    this.#sharePriv = init.shareKeyPair.privateKey;
    this.#sharePub = init.shareKeyPair.publicKey;
  }

  // ============ Connections ============

  /**
   * Return the user's accepted connections. The connections record is a
   * single owned blob (collection `tarn-share-state`, Eid
   * `tarn-connections-v1`); we fetch + decrypt it once and reshape into
   * the public {@link Connection} type.
   *
   * Returns an empty array if no connections record exists yet. Throws
   * on decrypt failure (the record exists but bytes are corrupt) — this
   * is intentionally distinct from "no record yet" so callers can tell
   * the two apart.
   */
  async connections(): Promise<Connection[]> {
    if (!this.#connectionsPromise) {
      this.#connectionsPromise = this.#loadConnectionsImpl();
    }
    return this.#connectionsPromise;
  }

  async #loadConnectionsImpl(): Promise<Connection[]> {
    const blobs = await findContentBlobs(this.#client, {
      app: this.#appId,
      type: 'tarn-share-state',
      dataLookupKey: this.#dataLookupKey,
    });
    const { live } = resolveContentBlobs(blobs);
    // Pick the entry whose Eid tag matches the connections content-id.
    const record = live.find((b) => b.tagMap['Eid'] === CONNECTIONS_CONTENT_ID);
    if (!record) return [];

    const decoded = await this.#decryptOwnedBlob(record);
    if (!isConnectionsRecord(decoded)) {
      throw new Error(
        `SharingReader: connections record blob ${record.txid} did not match expected shape`,
      );
    }
    if (decoded.app_id !== this.#appId) {
      throw new Error(
        `SharingReader: connections record app_id '${decoded.app_id}' != reader appId '${this.#appId}'`,
      );
    }
    return decoded.connections.map(toConnection);
  }

  // ============ Share log ============

  /**
   * Async iterator over every event in every pair's share log, for a
   * single direction (incoming or outgoing).
   *
   * For each connection in the user's connections record:
   *   1. Derive the per-pair X25519 + HKDF keys.
   *   2. Discover the highest seq via O(log N) stealth-tag probes
   *      (`discoverHighestSeq`).
   *   3. Walk back from `highestSeq` to the most recent snapshot
   *      (or seq=0 if none) — yielding each entry as it's decoded.
   *   4. Walk forward from snapshot to highestSeq, yielding each entry.
   *
   * Entries that fail decryption are skipped with a console warning.
   * Entries whose signature does not verify against the connection's
   * `signing_pub` are still yielded, but with `verified: false`.
   *
   * When `direction === 'incoming'`, we read the peer's outbound log
   * (which is our inbound). When `direction === 'outgoing'`, we read
   * our own outbound log. Both are addressable because per-pair keys
   * are direction-aware (see sharing §4.5).
   */
  async *shareLog(opts: { direction: ShareLogDirection }): AsyncIterable<ShareLogEvent> {
    if (opts?.direction !== 'incoming' && opts?.direction !== 'outgoing') {
      throw new Error(`SharingReader.shareLog: direction must be 'incoming' or 'outgoing'`);
    }
    const direction = opts.direction;
    const connections = await this.connections();
    for (const connection of connections) {
      yield* this.#walkConnection(connection, direction);
    }
  }

  /**
   * Buffered batch helper: drain {@link shareLog} into a flat array. Useful
   * for callers that want everything in memory (small graphs, offline
   * reports). Streaming consumers should iterate `shareLog()` directly.
   */
  async allShareLog(opts: { direction: ShareLogDirection }): Promise<ShareLogEvent[]> {
    const out: ShareLogEvent[] = [];
    for await (const e of this.shareLog(opts)) {
      out.push(e);
    }
    return out;
  }

  async *#walkConnection(
    connection: Connection,
    direction: ShareLogDirection,
  ): AsyncIterable<ShareLogEvent> {
    let pair: Awaited<ReturnType<typeof getPairKeysFor>>;
    try {
      pair = await this.#pairKeysForCached(connection.share_pub);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn(
        `[@tarn/recover] SharingReader: cannot derive pair keys for ${connection.share_pub.slice(0, 8)}...: ${msg(err)}`,
      );
      return;
    }

    // Pick the right tag-seed + decryption key based on direction.
    //   - "incoming" reads the PEER's outbound log → that's our inbound.
    //   - "outgoing" reads OUR outbound log.
    const tagSeed = direction === 'incoming' ? pair.inboundTagSeed : pair.outboundTagSeed;
    const decryptKey = direction === 'incoming' ? pair.inboundKey : pair.outboundKey;

    // Find the highest published seq via O(log N) probes against the gateway.
    const probe = async (seq: number): Promise<boolean> => {
      const tag = await deriveLogTag(tagSeed, seq);
      const blobs = await findShareLogBlobs(this.#client, {
        logTag: tag,
        appScope: this.#appId,
      });
      return blobs.length > 0;
    };
    const { highestSeq } = await discoverHighestSeq({ probe, anchor: 0 });
    if (highestSeq < 0) return; // empty log

    // Walk back to the most recent snapshot. We collect entries on the way
    // so we don't refetch when the forward walk needs them.
    const fetched = new Map<number, FetchedEntry | null>();
    let snapshotSeq = -1;
    for (let seq = highestSeq; seq >= 0; seq--) {
      const entry = await this.#fetchEntry(seq, tagSeed, decryptKey, connection);
      fetched.set(seq, entry);
      if (entry?.operation && (entry.operation as { type?: string }).type === OP_SNAPSHOT) {
        snapshotSeq = seq;
        break;
      }
    }

    // Walk forward from snapshot (or seq=0) and yield each entry. The
    // §13.5 rotate_identity terminal-on-old-log rule applies: we yield it
    // and stop. (See the module-header comment for the v1 caveats around
    // re-bootstrapping the rotated peer.)
    const startSeq = snapshotSeq >= 0 ? snapshotSeq : 0;
    for (let seq = startSeq; seq <= highestSeq; seq++) {
      const cached = fetched.has(seq) ? fetched.get(seq) : await this.#fetchEntry(seq, tagSeed, decryptKey, connection);
      if (!cached) continue;
      const event = makeEvent(cached, connection, direction);
      yield event;
      if (event.type === OP_ROTATE_IDENTITY) {
        // Terminal on the OLD log per §13.5. Stop walking; the rotated
        // peer (if known) appears as its own Connection.
        return;
      }
    }
  }

  async #fetchEntry(
    seq: number,
    tagSeed: Uint8Array,
    decryptKey: CryptoKey,
    connection: Connection,
  ): Promise<FetchedEntry | null> {
    const tag = await deriveLogTag(tagSeed, seq);
    const blobs = await findShareLogBlobs(this.#client, {
      logTag: tag,
      appScope: this.#appId,
    });
    if (blobs.length === 0) return null;
    // Per protocol there's at most one blob per tag (uniqueness enforced
    // server-side via the unique index). On the off-chance the gateway
    // surfaces duplicates, take the earliest-by-block (the §9.1 winner).
    const blob = blobs[0]!;
    const ciphertext = await blob.loadBody();
    let operation: unknown;
    try {
      operation = await decryptShareLogEntry(ciphertext, decryptKey);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn(
        `[@tarn/recover] SharingReader: decrypt failed at seq=${seq} for ${connection.share_pub.slice(0, 8)}...: ${msg(err)}`,
      );
      return null;
    }
    const verified = await verifyOperationSignature(operation, connection.signing_pub);
    return { txid: blob.txid, operation, verified };
  }

  // ============ Caches ============

  async #pairKeysForCached(peerSharePubBase64Url: string): Promise<Awaited<ReturnType<typeof getPairKeysFor>>> {
    let p = this.#pairKeyCache.get(peerSharePubBase64Url);
    if (!p) {
      p = getPairKeysFor({
        selfSharePriv: this.#sharePriv,
        selfSharePub: this.#sharePub,
        peerSharePubBase64Url,
        appId: this.#appId,
      });
      this.#pairKeyCache.set(peerSharePubBase64Url, p);
    }
    return p;
  }

  // ============ Owned-blob decrypt (mirrors Reader.#decryptBlob) ============

  async #decryptOwnedBlob(blob: BlobRecord): Promise<Record<string, unknown>> {
    const bytes = await blob.loadBody();
    const genRaw = blob.tagMap['Gen'];
    let gen = 1;
    if (genRaw !== undefined) {
      const parsed = Number.parseInt(genRaw, 10);
      if (Number.isInteger(parsed) && parsed >= 1) gen = parsed;
    }
    const dek = this.#dekChain.dekByGen.get(gen);
    if (!dek) {
      throw new Error(
        `No DEK for blob generation ${gen} — chain has gens [${[...this.#dekChain.dekByGen.keys()].join(', ')}]`,
      );
    }
    const decoded = await decryptWithCEK(dek.kwKey, bytes);
    if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) {
      throw new Error(`SharingReader: decrypted payload is not a plain object`);
    }
    return decoded as Record<string, unknown>;
  }
}

// ============ Helpers ============

interface FetchedEntry {
  txid: string;
  operation: unknown;
  verified: boolean;
}

function msg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function toConnection(entry: ConnectionEntry): Connection {
  const out: Connection = {
    share_pub: entry.share_pub,
    signing_pub: entry.signing_pub,
  };
  if (typeof entry['username'] === 'string') out.username = entry['username'] as string;
  if (typeof entry['label'] === 'string') out.label = entry['label'] as string;
  if (typeof entry['muted'] === 'boolean') out.muted = entry['muted'] as boolean;
  if (typeof entry['established_at'] === 'number') {
    out.established_at = entry['established_at'] as number;
  }
  if (typeof entry['initial_request_nonce'] === 'string') {
    out.initial_request_nonce = entry['initial_request_nonce'] as string;
  }
  if (typeof entry['credential_lookup_key'] === 'string') {
    out.credential_lookup_key = entry['credential_lookup_key'];
  }
  if (typeof entry['rotated_at'] === 'number') {
    out.rotated_at = entry['rotated_at'];
  }
  if (typeof entry['prior_share_pub'] === 'string') {
    out.prior_share_pub = entry['prior_share_pub'];
  }
  return out;
}

function makeEvent(
  fetched: FetchedEntry,
  connection: Connection,
  direction: ShareLogDirection,
): ShareLogEvent {
  const op = fetched.operation as OperationSigned;
  const base: ShareLogEntryBase = {
    connection,
    seq: op.seq,
    direction,
    txid: fetched.txid,
    verified: fetched.verified,
  };
  // The operation already carries the per-type fields verbatim — just
  // project them into the typed event shape. We trust the wire format
  // matches `OperationSigned`; the canonical-JSON signature check happens
  // upstream in verifyOperationSignature, but a malformed entry that
  // happens to verify (the writer signed garbage) is still surfaced.
  switch (op.type) {
    case 'add':
      return { ...base, type: 'add', content_id: op.content_id, tx_id: op.tx_id, cek: op.cek, shared_at: op.shared_at };
    case 'update':
      return { ...base, type: 'update', content_id: op.content_id, tx_id: op.tx_id, updated_at: op.updated_at };
    case 'rotate':
      return { ...base, type: 'rotate', content_id: op.content_id, cek: op.cek, rotated_at: op.rotated_at };
    case 'remove':
      return { ...base, type: 'remove', content_id: op.content_id, removed_at: op.removed_at };
    case 'snapshot':
      return { ...base, type: 'snapshot', state: op.state, snapshot_at: op.snapshot_at, prior_seq: op.prior_seq };
    case 'rotate_identity':
      return {
        ...base,
        type: 'rotate_identity',
        new_share_pub: op.new_share_pub,
        new_signing_pub: op.new_signing_pub,
        new_credential_lookup_key: op.new_credential_lookup_key,
        rotated_at: op.rotated_at,
      };
    default: {
      // Unknown operation — surface it minimally as a snapshot-with-empty-state
      // shape with the actual type preserved. This branch shouldn't fire in
      // practice; KNOWN_OP_TYPES exhaustively covers the wire spec.
      throw new Error(`SharingReader: unknown share-log operation type ${String((op as { type?: unknown }).type)}`);
    }
  }
}

/**
 * Compute the final per-content state map a connection's outbound log
 * resolves to, by replaying every event (matches the live SDK's
 * `readShareLog` return shape). Convenience helper for callers that want
 * the rolled-up "current state" rather than the per-event stream.
 */
export function replayConnection(events: ShareLogEvent[]): ShareLogState {
  const state: ShareLogState = {};
  for (const e of events) {
    if (!e.verified) continue;
    applyOperationToState(state, e);
  }
  return state;
}

/**
 * Re-export base64UrlToBytes for callers that need to round-trip a
 * connection's `share_pub` between the typed wire format and raw bytes.
 */
export { base64UrlToBytes };
