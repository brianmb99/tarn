// Tarn Client — Sharing Section 5a: HPKE connection handshake
//
// Implements the connection-handshake bootstrap from
// `2026-04-28-tarn-sharing-design.md` §6 (handshake), §7 (connections +
// pending records), §13.8 (replay defense), §13.9 (forged-accept defense).
//
// Stops short of the share log (5b) — this module produces no signed
// operations, no per-pair shared secret, no stealth-addressed tags, no
// snapshot. Two users completing the handshake end up in each other's
// connections record, and that's the entire surface.
//
// Section 6 (issue #18) renamed the public surface from "friend" to
// "connection" to keep the SDK product-neutral. Apps wanting Strava-style
// asymmetric follow build it on top of the mutual-connection primitive plus
// the per-side mute filter (see `mute*` methods on TarnClient).
//
// Crypto suite (RFC 9180): DHKEM-X25519 + HKDF-SHA-256 + AES-256-GCM.
// HPKE library: `@hpke/core` 1.9 — modular core, ~60 KB raw ESM after
// tree-shaking, all WebCrypto-native (no separate JS impl). The
// `@hpke/dhkem-x25519` companion package was redundant by 1.9 — `@hpke/core`
// re-exports `DhkemX25519HkdfSha256` directly.

import {
  CipherSuite,
  DhkemX25519HkdfSha256,
  HkdfSha256,
  Aes256Gcm,
} from '@hpke/core';
import { bytesToBase64Url, base64UrlToBytes } from './crypto.js';

// ============ CONSTANTS ============

const TEXT_ENCODER = new TextEncoder();

// HPKE info strings — bind ciphertexts to a specific protocol version + role,
// per RFC 9180 §5.1 recommendations. Mismatched info on Open() returns
// AEAD-level decryption failure, so a connection-request sealed under one info
// cannot be replayed as an accept (or any other future role) even if it lands
// at the same tag.
export const INFO_CONNECTION_REQUEST = 'tarn-connection-request-v1';
export const INFO_CONNECTION_ACCEPT = 'tarn-connection-accept-v1';

// Inbox-tag HMAC info string (sharing design §6.1):
//   inbox_tag = B(HMAC(H(recipient_share_pub),
//     "tarn-connection-inbox-v1-" || app_id || "-" || encode_uint64(window)))
const INBOX_TAG_LABEL_PREFIX = 'tarn-connection-inbox-v1-';

// Day-granularity rolling window (sharing §6.1).
const SECONDS_PER_DAY = 86400;

// Replay defense (sharing §13.8): timestamp must be within ±REPLAY_WINDOW_SEC
// of "now". 7 days back is the design-doc floor; we also reject far-future
// timestamps (>1 day) to bound clock-skew leniency.
export const REPLAY_PAST_WINDOW_SEC = 7 * SECONDS_PER_DAY;
export const REPLAY_FUTURE_WINDOW_SEC = 1 * SECONDS_PER_DAY;

// In-memory replay-nonce cache TTL — keep a nonce remembered for at least the
// replay-past window so a re-publish during that span is rejected. (The cache
// can be larger; this is the floor.)
export const REPLAY_NONCE_TTL_SEC = REPLAY_PAST_WINDOW_SEC + SECONDS_PER_DAY;

// Default polling depth (sharing §6.1: "the current window plus the previous
// N (default 30) on each login").
export const DEFAULT_POLL_WINDOWS = 30;

// Connection-request blob size cap. The plaintext is a small JSON object
// (sender_email + 32-byte sender_share_pub + 65-byte sender_signing_pub +
// nonce + timestamp + optional message). HPKE sealed adds 32 (enc) + 16
// (AEAD tag). 8 KB is a generous cap that catches nothing legitimate but
// bounds memory before we touch crypto.
export const MAX_HANDSHAKE_BLOB_BYTES = 8 * 1024;

// Cap on user-supplied free-text greeting in a connection request. UI surface,
// not a security property — but limits abuse vectors and keeps the JSON small
// enough to fit comfortably under the blob cap.
export const MAX_REQUEST_MESSAGE_LEN = 280;

// ============ HPKE SUITE ============

// Single shared CipherSuite instance. The suite is stateless; constructing it
// is cheap (no async setup), but reusing a singleton keeps the call sites
// terse and aligns with the @hpke/core pattern.
const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

// ============ WebCrypto BufferSource cast (matches crypto.ts pattern) ============

function bs(b: ArrayBufferView | ArrayBuffer): BufferSource {
  return b as BufferSource;
}

// ============ INBOX TAG DERIVATION ============

/** Compute the rolling day window for a unix timestamp (sharing §6.1). */
export function inboxWindowFor(unixSeconds: number): number {
  return Math.floor(unixSeconds / SECONDS_PER_DAY);
}

/** Current inbox window — `floor(unix_timestamp / 86400)`. */
export function currentInboxWindow(now: number = Date.now()): number {
  return inboxWindowFor(Math.floor(now / 1000));
}

/**
 * Last `count` inbox windows ending at the current window, descending
 * (newest first). Used by `listIncomingRequests` to poll the recent backlog
 * (default 30 days per design §6.1).
 */
export function recentInboxWindows(count: number, now: number = Date.now()): number[] {
  const cur = currentInboxWindow(now);
  const out: number[] = [];
  for (let i = 0; i < count; i++) out.push(cur - i);
  return out;
}

function encodeUint64BE(n: number): Uint8Array {
  // Unsigned 64-bit BE. JS numbers are safe up to 2^53; inbox windows are
  // (unix/86400) — well under 2^53 for any plausible timestamp — so a plain
  // bigint conversion at the boundary is enough without needing a BigInt
  // throughout the codebase.
  const buf = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

/**
 * Derive an inbox tag for a recipient (sharing §6.1):
 *   inbox_tag(recipient_share_pub, app_id, window) =
 *     B(HMAC(H(recipient_share_pub),
 *       "tarn-connection-inbox-v1-" || app_id || "-" || encode_uint64(window)))
 */
export async function deriveInboxTag(
  recipientSharePub: Uint8Array,
  appId: string,
  window: number,
): Promise<string> {
  if (!(recipientSharePub instanceof Uint8Array) || recipientSharePub.length !== 32) {
    throw new Error('recipientSharePub must be a 32-byte Uint8Array');
  }
  if (!appId) throw new Error('appId is required');
  if (!Number.isInteger(window) || window < 0) {
    throw new Error('window must be a non-negative integer');
  }
  const hmacKeyBytes = new Uint8Array(
    await crypto.subtle.digest('SHA-256', bs(recipientSharePub)),
  );
  const hmacKey = await crypto.subtle.importKey(
    'raw', bs(hmacKeyBytes), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const labelPrefix = TEXT_ENCODER.encode(INBOX_TAG_LABEL_PREFIX);
  const appBytes = TEXT_ENCODER.encode(appId);
  const dash = TEXT_ENCODER.encode('-');
  const windowBytes = encodeUint64BE(window);
  const msg = new Uint8Array(labelPrefix.length + appBytes.length + dash.length + windowBytes.length);
  let off = 0;
  msg.set(labelPrefix, off); off += labelPrefix.length;
  msg.set(appBytes, off); off += appBytes.length;
  msg.set(dash, off); off += dash.length;
  msg.set(windowBytes, off);

  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, bs(msg)));
  return bytesToBase64Url(sig);
}

// ============ HPKE SEAL / OPEN ============

async function importHpkePublicKey(sharePub: Uint8Array): Promise<CryptoKey> {
  if (!(sharePub instanceof Uint8Array) || sharePub.length !== 32) {
    throw new Error('share_pub must be a 32-byte Uint8Array');
  }
  return await suite.kem.importKey(
    'raw',
    sharePub.buffer.slice(sharePub.byteOffset, sharePub.byteOffset + 32) as ArrayBuffer,
    true,
  );
}

async function importHpkePrivateKeyPair(sharePriv: Uint8Array): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  if (!(sharePriv instanceof Uint8Array) || sharePriv.length !== 32) {
    throw new Error('share_priv must be a 32-byte Uint8Array');
  }
  const privateKey = await suite.kem.importKey(
    'raw',
    sharePriv.buffer.slice(sharePriv.byteOffset, sharePriv.byteOffset + 32) as ArrayBuffer,
    false,
  );
  // The KEM exposes derivePublicKey via its primitives interface — use it via
  // the suite's kem instance. Falls back to JWK round-trip if needed.
  const jwk = await crypto.subtle.exportKey('jwk', privateKey) as JsonWebKey & { d?: string };
  delete jwk.d;
  delete jwk.key_ops;
  const publicKey = await crypto.subtle.importKey('jwk', jwk, { name: 'X25519' }, true, []);
  return { privateKey, publicKey };
}

/** HPKE-Seal an arbitrary plaintext to a recipient. Wire blob: enc(32) || ciphertext+tag. */
export async function hpkeSeal(opts: {
  recipientSharePub: Uint8Array;
  info: string;
  plaintext: Uint8Array;
}): Promise<Uint8Array> {
  const { recipientSharePub, info, plaintext } = opts;
  if (!info) throw new Error('info is required');
  if (!(plaintext instanceof Uint8Array)) {
    throw new Error('plaintext must be a Uint8Array');
  }
  const recipientPub = await importHpkePublicKey(recipientSharePub);
  const sender = await suite.createSenderContext({
    recipientPublicKey: recipientPub,
    info: TEXT_ENCODER.encode(info),
  });
  const enc = new Uint8Array(sender.enc);
  const ct = new Uint8Array(await sender.seal(
    plaintext.buffer.slice(plaintext.byteOffset, plaintext.byteOffset + plaintext.byteLength) as ArrayBuffer,
  ));
  if (enc.length !== 32) {
    throw new Error(`unexpected enc length ${enc.length} (X25519 should give 32)`);
  }
  const out = new Uint8Array(enc.length + ct.length);
  out.set(enc, 0);
  out.set(ct, enc.length);
  return out;
}

/**
 * HPKE-Open a wire blob with the local share_priv. Throws on AEAD failure
 * (wrong key, tampered ciphertext, or `info` mismatch).
 */
export async function hpkeOpen(opts: {
  sharePriv: Uint8Array;
  info: string;
  blob: Uint8Array;
}): Promise<Uint8Array> {
  const { sharePriv, info, blob } = opts;
  if (!info) throw new Error('info is required');
  if (!(blob instanceof Uint8Array) || blob.length < 32 + 16) {
    throw new Error('blob too short for HPKE envelope');
  }
  if (blob.length > MAX_HANDSHAKE_BLOB_BYTES) {
    throw new Error(`blob exceeds MAX_HANDSHAKE_BLOB_BYTES (${MAX_HANDSHAKE_BLOB_BYTES})`);
  }
  const enc = blob.slice(0, 32);
  const ct = blob.slice(32);
  const recipientKey = await importHpkePrivateKeyPair(sharePriv);
  const recipient = await suite.createRecipientContext({
    recipientKey,
    enc: enc.buffer.slice(enc.byteOffset, enc.byteOffset + enc.byteLength) as ArrayBuffer,
    info: TEXT_ENCODER.encode(info),
  });
  const ptBuf = await recipient.open(ct.buffer.slice(ct.byteOffset, ct.byteOffset + ct.byteLength) as ArrayBuffer);
  return new Uint8Array(ptBuf);
}

// ============ CONNECTION REQUEST / ACCEPT PAYLOADS ============

export type BuildConnectionRequestOpts = {
  senderUsername: string;
  senderSharePub: Uint8Array;
  senderSigningPubBase64: string;
  senderAppId: string;
  message?: string;
  timestamp?: number;
  nonce?: Uint8Array;
  viaInviteToken?: string;
};

export type ConnectionRequestPayload = {
  type: 'connection_request';
  sender_email: string;
  sender_share_pub: string;
  sender_signing_pub: string;
  sender_app_id: string;
  nonce: string;
  timestamp: number;
  message?: string;
  via_invite_token?: string;
};

export function buildConnectionRequestPayload(opts: BuildConnectionRequestOpts): ConnectionRequestPayload {
  const senderUsername = requireString(opts.senderUsername, 'senderUsername');
  const senderSigningPub = requireString(opts.senderSigningPubBase64, 'senderSigningPubBase64');
  const senderAppId = requireString(opts.senderAppId, 'senderAppId');
  if (!(opts.senderSharePub instanceof Uint8Array) || opts.senderSharePub.length !== 32) {
    throw new Error('senderSharePub must be a 32-byte Uint8Array');
  }
  if (opts.message != null) {
    if (typeof opts.message !== 'string') throw new Error('message must be a string');
    if (opts.message.length > MAX_REQUEST_MESSAGE_LEN) {
      throw new Error(`message exceeds ${MAX_REQUEST_MESSAGE_LEN} chars`);
    }
  }
  if (opts.viaInviteToken != null && typeof opts.viaInviteToken !== 'string') {
    throw new Error('viaInviteToken must be a string when present');
  }
  const nonce = opts.nonce instanceof Uint8Array
    ? opts.nonce
    : crypto.getRandomValues(new Uint8Array(16));
  if (nonce.length !== 16) throw new Error('nonce must be 16 bytes');
  const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1000);

  const out: ConnectionRequestPayload = {
    type: 'connection_request',
    sender_email: senderUsername,
    sender_share_pub: bytesToBase64Url(opts.senderSharePub),
    sender_signing_pub: senderSigningPub,
    sender_app_id: senderAppId,
    nonce: bytesToBase64Url(nonce),
    timestamp,
  };
  if (opts.message) out.message = opts.message;
  if (opts.viaInviteToken) out.via_invite_token = opts.viaInviteToken;
  return out;
}

export type NormalizedConnectionRequest = {
  type: 'connection_request';
  senderUsername: string;
  senderSharePub: Uint8Array;
  senderSharePubBase64Url: string;
  senderSigningPubBase64: string;
  senderAppId: string;
  nonce: Uint8Array;
  nonceBase64Url: string;
  timestamp: number;
  message: string | null;
  viaInviteToken: string | null;
};

export type ValidationResult<T> =
  | { valid: true; normalized: T }
  | { valid: false; reason: string };

/**
 * Validate a decoded connection-request payload (sharing §6.3 + §13.8).
 *
 * Returns `{ valid: false, reason }` on any structural problem, replay-window
 * violation, or wrong-app mismatch. Returns `{ valid: true, normalized }` on
 * success.
 */
export function validateConnectionRequestPayload(
  payload: unknown,
  expectedAppId: string,
  now: number = Math.floor(Date.now() / 1000),
): ValidationResult<NormalizedConnectionRequest> {
  if (!payload || typeof payload !== 'object') {
    return { valid: false, reason: 'payload must be an object' };
  }
  const p = payload as Record<string, unknown>;
  if (p['type'] !== 'connection_request') {
    return { valid: false, reason: `wrong type: ${String(p['type'])}` };
  }
  if (typeof p['sender_email'] !== 'string' || (p['sender_email'] as string).length === 0) {
    return { valid: false, reason: 'sender_email missing or invalid' };
  }
  if (typeof p['sender_app_id'] !== 'string' || p['sender_app_id'] !== expectedAppId) {
    return { valid: false, reason: `sender_app_id ${String(p['sender_app_id'])} != ${expectedAppId}` };
  }
  let senderSharePub: Uint8Array;
  try {
    senderSharePub = base64UrlToBytes(p['sender_share_pub'] as string);
    if (senderSharePub.length !== 32) {
      return { valid: false, reason: `sender_share_pub must be 32 bytes, got ${senderSharePub.length}` };
    }
  } catch {
    return { valid: false, reason: 'sender_share_pub is not valid base64url' };
  }
  if (typeof p['sender_signing_pub'] !== 'string' || (p['sender_signing_pub'] as string).length === 0) {
    return { valid: false, reason: 'sender_signing_pub missing or invalid' };
  }
  let nonce: Uint8Array;
  try {
    nonce = base64UrlToBytes(p['nonce'] as string);
    if (nonce.length !== 16) {
      return { valid: false, reason: `nonce must be 16 bytes, got ${nonce.length}` };
    }
  } catch {
    return { valid: false, reason: 'nonce is not valid base64url' };
  }
  if (!Number.isFinite(p['timestamp']) || !Number.isInteger(p['timestamp'])) {
    return { valid: false, reason: 'timestamp must be an integer' };
  }
  const ts = p['timestamp'] as number;
  if (ts < now - REPLAY_PAST_WINDOW_SEC) {
    return { valid: false, reason: 'timestamp too old (>7 days)' };
  }
  if (ts > now + REPLAY_FUTURE_WINDOW_SEC) {
    return { valid: false, reason: 'timestamp too far in the future' };
  }
  if (p['message'] != null) {
    if (typeof p['message'] !== 'string') {
      return { valid: false, reason: 'message must be a string when present' };
    }
    if ((p['message'] as string).length > MAX_REQUEST_MESSAGE_LEN) {
      return { valid: false, reason: `message exceeds ${MAX_REQUEST_MESSAGE_LEN} chars` };
    }
  }
  if (p['via_invite_token'] != null && typeof p['via_invite_token'] !== 'string') {
    return { valid: false, reason: 'via_invite_token must be a string when present' };
  }
  return {
    valid: true,
    normalized: {
      type: 'connection_request',
      senderUsername: p['sender_email'] as string,
      senderSharePub,
      senderSharePubBase64Url: p['sender_share_pub'] as string,
      senderSigningPubBase64: p['sender_signing_pub'] as string,
      senderAppId: p['sender_app_id'] as string,
      nonce,
      nonceBase64Url: p['nonce'] as string,
      timestamp: ts,
      message: (p['message'] as string | undefined) ?? null,
      viaInviteToken: (p['via_invite_token'] as string | undefined) ?? null,
    },
  };
}

export type BuildConnectionAcceptOpts = {
  senderUsername: string;
  senderSharePub: Uint8Array;
  senderSigningPubBase64: string;
  senderAppId: string;
  inReplyToNonceBase64Url: string;
  timestamp?: number;
};

export type ConnectionAcceptPayload = {
  type: 'connection_accept';
  sender_email: string;
  sender_share_pub: string;
  sender_signing_pub: string;
  sender_app_id: string;
  in_reply_to: string;
  timestamp: number;
};

export function buildConnectionAcceptPayload(opts: BuildConnectionAcceptOpts): ConnectionAcceptPayload {
  const senderUsername = requireString(opts.senderUsername, 'senderUsername');
  const senderSigningPub = requireString(opts.senderSigningPubBase64, 'senderSigningPubBase64');
  const senderAppId = requireString(opts.senderAppId, 'senderAppId');
  const inReplyTo = requireString(opts.inReplyToNonceBase64Url, 'inReplyToNonceBase64Url');
  if (!(opts.senderSharePub instanceof Uint8Array) || opts.senderSharePub.length !== 32) {
    throw new Error('senderSharePub must be a 32-byte Uint8Array');
  }
  return {
    type: 'connection_accept',
    sender_email: senderUsername,
    sender_share_pub: bytesToBase64Url(opts.senderSharePub),
    sender_signing_pub: senderSigningPub,
    sender_app_id: senderAppId,
    in_reply_to: inReplyTo,
    timestamp: opts.timestamp ?? Math.floor(Date.now() / 1000),
  };
}

export type NormalizedConnectionAccept = {
  type: 'connection_accept';
  senderUsername: string;
  senderSharePub: Uint8Array;
  senderSharePubBase64Url: string;
  senderSigningPubBase64: string;
  senderAppId: string;
  inReplyToNonceBase64Url: string;
  timestamp: number;
};

export function validateConnectionAcceptPayload(
  payload: unknown,
  expectedAppId: string,
  now: number = Math.floor(Date.now() / 1000),
): ValidationResult<NormalizedConnectionAccept> {
  if (!payload || typeof payload !== 'object') {
    return { valid: false, reason: 'payload must be an object' };
  }
  const p = payload as Record<string, unknown>;
  if (p['type'] !== 'connection_accept') {
    return { valid: false, reason: `wrong type: ${String(p['type'])}` };
  }
  if (typeof p['sender_email'] !== 'string' || (p['sender_email'] as string).length === 0) {
    return { valid: false, reason: 'sender_email missing or invalid' };
  }
  if (typeof p['sender_app_id'] !== 'string' || p['sender_app_id'] !== expectedAppId) {
    return { valid: false, reason: `sender_app_id ${String(p['sender_app_id'])} != ${expectedAppId}` };
  }
  let senderSharePub: Uint8Array;
  try {
    senderSharePub = base64UrlToBytes(p['sender_share_pub'] as string);
    if (senderSharePub.length !== 32) {
      return { valid: false, reason: `sender_share_pub must be 32 bytes, got ${senderSharePub.length}` };
    }
  } catch {
    return { valid: false, reason: 'sender_share_pub is not valid base64url' };
  }
  if (typeof p['sender_signing_pub'] !== 'string' || (p['sender_signing_pub'] as string).length === 0) {
    return { valid: false, reason: 'sender_signing_pub missing or invalid' };
  }
  if (typeof p['in_reply_to'] !== 'string' || (p['in_reply_to'] as string).length === 0) {
    return { valid: false, reason: 'in_reply_to missing' };
  }
  if (!Number.isFinite(p['timestamp']) || !Number.isInteger(p['timestamp'])) {
    return { valid: false, reason: 'timestamp must be an integer' };
  }
  const ts = p['timestamp'] as number;
  if (ts < now - REPLAY_PAST_WINDOW_SEC) {
    return { valid: false, reason: 'timestamp too old (>7 days)' };
  }
  if (ts > now + REPLAY_FUTURE_WINDOW_SEC) {
    return { valid: false, reason: 'timestamp too far in the future' };
  }
  return {
    valid: true,
    normalized: {
      type: 'connection_accept',
      senderUsername: p['sender_email'] as string,
      senderSharePub,
      senderSharePubBase64Url: p['sender_share_pub'] as string,
      senderSigningPubBase64: p['sender_signing_pub'] as string,
      senderAppId: p['sender_app_id'] as string,
      inReplyToNonceBase64Url: p['in_reply_to'] as string,
      timestamp: ts,
    },
  };
}

// ============ REPLAY-NONCE CACHE (sharing §13.8) ============

export type ReplayNonceCache = { entries: Map<string, number> };

export function makeReplayNonceCache(): ReplayNonceCache {
  return { entries: new Map() };
}

export function checkAndRecordNonce(
  cache: ReplayNonceCache,
  nonceBase64Url: string,
  now: number = Math.floor(Date.now() / 1000),
): { replay: boolean } {
  if (!cache || !(cache.entries instanceof Map)) {
    throw new Error('cache must be a replay-nonce cache (use makeReplayNonceCache)');
  }
  if (typeof nonceBase64Url !== 'string' || nonceBase64Url.length === 0) {
    throw new Error('nonceBase64Url is required');
  }
  // Opportunistic eviction of expired entries — small map, single-pass scan.
  const cutoff = now - REPLAY_NONCE_TTL_SEC;
  for (const [k, t] of cache.entries) {
    if (t < cutoff) cache.entries.delete(k);
  }
  if (cache.entries.has(nonceBase64Url)) {
    return { replay: true };
  }
  cache.entries.set(nonceBase64Url, now);
  return { replay: false };
}

// ============ FORGED-ACCEPT DETECTION (sharing §13.9) ============

/**
 * Cross-reference an incoming accept's `in_reply_to` nonce against the local
 * outbound pending list. Unmatched accepts are silently ignored.
 *
 * Accepts entries that expose either `request_nonce` (the on-the-wire record
 * shape per §7.2) or `requestNonce` (the camelCase view typically used in
 * UI/SDK code).
 */
export function findOutboundForAccept<T extends { request_nonce?: string; requestNonce?: string }>(
  inReplyToNonceBase64Url: string,
  outboundPending: Iterable<T>,
): T | null {
  if (typeof inReplyToNonceBase64Url !== 'string') return null;
  for (const entry of outboundPending) {
    if (!entry) continue;
    if (entry.request_nonce === inReplyToNonceBase64Url) return entry;
    if (entry.requestNonce === inReplyToNonceBase64Url) return entry;
  }
  return null;
}

// ============ CONNECTIONS + PENDING-REQUESTS RECORD SHAPES ============

export const CONNECTIONS_CONTENT_ID = 'tarn-connections-v1';
export const PENDING_REQUESTS_CONTENT_ID = 'tarn-pending-requests-v1';

/** A single durable connection entry, as stored in the connections record. */
export type ConnectionEntry = {
  share_pub: string;
  signing_pub: string;
  credential_lookup_key?: string;
  rotated_at?: number;
  prior_share_pub?: string;
  // Apps may attach additional fields (label, etc.); pass-through.
  [key: string]: unknown;
};

export type ConnectionsRecord = {
  app_id: string;
  version: 1;
  connections: ConnectionEntry[];
};

export type PendingEntry = {
  request_nonce: string;
  // Other fields (peer_share_pub, peer_email, message, timestamp, ...) flow through.
  [key: string]: unknown;
};

export type PendingRequestsRecord = {
  app_id: string;
  version: 1;
  outbound: PendingEntry[];
  inbound: PendingEntry[];
};

export function emptyConnectionsRecord(appId: string): ConnectionsRecord {
  return { app_id: appId, version: 1, connections: [] };
}

export function emptyPendingRequestsRecord(appId: string): PendingRequestsRecord {
  return { app_id: appId, version: 1, outbound: [], inbound: [] };
}

/**
 * Append a connection (idempotent on `share_pub`) to the connections record.
 * Replaces an existing entry with the same share_pub if present.
 */
export function upsertConnection(record: ConnectionsRecord, connection: ConnectionEntry): ConnectionsRecord {
  if (!record || !Array.isArray(record.connections)) {
    throw new Error('record must be a connections record');
  }
  if (!connection || typeof connection.share_pub !== 'string') {
    throw new Error('connection.share_pub is required');
  }
  const idx = record.connections.findIndex((c: ConnectionEntry) => c.share_pub === connection.share_pub);
  const out: ConnectionsRecord = { ...record, connections: record.connections.slice() };
  if (idx >= 0) out.connections[idx] = connection;
  else out.connections.push(connection);
  return out;
}

/**
 * Remove a connection (idempotent on `share_pub`) from the connections record.
 * Returns the record unchanged if no entry matched.
 */
export function removeConnection(
  record: ConnectionsRecord,
  connectionSharePubBase64Url: string,
): ConnectionsRecord {
  if (!record || !Array.isArray(record.connections)) {
    throw new Error('record must be a connections record');
  }
  if (typeof connectionSharePubBase64Url !== 'string' || connectionSharePubBase64Url.length === 0) {
    throw new Error('connectionSharePubBase64Url is required');
  }
  return {
    ...record,
    connections: record.connections.filter((c: ConnectionEntry) => c.share_pub !== connectionSharePubBase64Url),
  };
}

export type RotateIdentityUpdate = {
  newSharePubBase64Url: string;
  newSigningPubBase64: string;
  newCredentialLookupKey: string;
  rotatedAt: number;
};

/**
 * Apply a `rotate_identity` announcement (sharing §13.5) to a connection's
 * entry in the connections record. The caller is responsible for verifying
 * the announcement's ECDSA signature against the connection's
 * currently-cached `signing_pub` BEFORE calling this — the helper itself
 * does no crypto.
 */
export function rotateConnectionIdentity(
  record: ConnectionsRecord,
  connectionSharePubBase64Url: string,
  update: RotateIdentityUpdate,
): ConnectionsRecord {
  if (!record || !Array.isArray(record.connections)) {
    throw new Error('record must be a connections record');
  }
  if (typeof connectionSharePubBase64Url !== 'string' || connectionSharePubBase64Url.length === 0) {
    throw new Error('connectionSharePubBase64Url is required');
  }
  if (!update
    || typeof update.newSharePubBase64Url !== 'string'
    || typeof update.newSigningPubBase64 !== 'string'
    || typeof update.newCredentialLookupKey !== 'string'
    || !Number.isInteger(update.rotatedAt)
  ) {
    throw new Error('rotateConnectionIdentity: update must have newSharePubBase64Url, newSigningPubBase64, newCredentialLookupKey, rotatedAt');
  }
  const idx = record.connections.findIndex((c: ConnectionEntry) => c.share_pub === connectionSharePubBase64Url);
  if (idx < 0) return record;
  const prior = record.connections[idx]!;
  const rotated: ConnectionEntry = {
    ...prior,
    share_pub: update.newSharePubBase64Url,
    signing_pub: update.newSigningPubBase64,
    credential_lookup_key: update.newCredentialLookupKey,
    rotated_at: update.rotatedAt,
    prior_share_pub: connectionSharePubBase64Url,
  };
  const connections = record.connections.slice();
  connections[idx] = rotated;
  return { ...record, connections };
}

/** Add an outbound pending request (idempotent on request_nonce). */
export function addOutboundPending(record: PendingRequestsRecord, entry: PendingEntry): PendingRequestsRecord {
  ensurePendingShape(record);
  if (!entry || typeof entry.request_nonce !== 'string') {
    throw new Error('entry.request_nonce is required');
  }
  if (record.outbound.some((o: PendingEntry) => o.request_nonce === entry.request_nonce)) {
    return record;
  }
  return { ...record, outbound: [...record.outbound, entry] };
}

/** Add an inbound pending request (idempotent on request_nonce). */
export function addInboundPending(record: PendingRequestsRecord, entry: PendingEntry): PendingRequestsRecord {
  ensurePendingShape(record);
  if (!entry || typeof entry.request_nonce !== 'string') {
    throw new Error('entry.request_nonce is required');
  }
  if (record.inbound.some((i: PendingEntry) => i.request_nonce === entry.request_nonce)) {
    return record;
  }
  return { ...record, inbound: [...record.inbound, entry] };
}

/** Remove an outbound pending entry by request_nonce. */
export function removeOutboundPending(record: PendingRequestsRecord, requestNonce: string): PendingRequestsRecord {
  ensurePendingShape(record);
  return { ...record, outbound: record.outbound.filter((o: PendingEntry) => o.request_nonce !== requestNonce) };
}

/** Remove an inbound pending entry by request_nonce. */
export function removeInboundPending(record: PendingRequestsRecord, requestNonce: string): PendingRequestsRecord {
  ensurePendingShape(record);
  return { ...record, inbound: record.inbound.filter((i: PendingEntry) => i.request_nonce !== requestNonce) };
}

function ensurePendingShape(record: PendingRequestsRecord): void {
  if (!record || !Array.isArray(record.outbound) || !Array.isArray(record.inbound)) {
    throw new Error('record must be a pending-requests record');
  }
}

// ============ MUTED-CONNECTIONS RECORD (Section 6, issue #18) ============

export const MUTED_CONNECTIONS_CONTENT_ID = 'tarn-muted-connections-v1';

export type MutedEntry = { share_pub: string; muted_at: number };
export type MutedConnectionsRecord = {
  app_id: string;
  version: 1;
  muted: MutedEntry[];
};

export function emptyMutedConnectionsRecord(appId: string): MutedConnectionsRecord {
  return { app_id: appId, version: 1, muted: [] };
}

export function addMutedConnection(
  record: MutedConnectionsRecord,
  connectionSharePubBase64Url: string,
  mutedAt: number,
): MutedConnectionsRecord {
  if (!record || !Array.isArray(record.muted)) {
    throw new Error('record must be a muted-connections record');
  }
  if (typeof connectionSharePubBase64Url !== 'string' || connectionSharePubBase64Url.length === 0) {
    throw new Error('connectionSharePubBase64Url is required');
  }
  if (!Number.isInteger(mutedAt)) {
    throw new Error('mutedAt must be an integer (unix seconds)');
  }
  if (record.muted.some((m: MutedEntry) => m.share_pub === connectionSharePubBase64Url)) {
    return record;
  }
  return {
    ...record,
    muted: [...record.muted, { share_pub: connectionSharePubBase64Url, muted_at: mutedAt }],
  };
}

export function removeMutedConnection(
  record: MutedConnectionsRecord,
  connectionSharePubBase64Url: string,
): MutedConnectionsRecord {
  if (!record || !Array.isArray(record.muted)) {
    throw new Error('record must be a muted-connections record');
  }
  if (typeof connectionSharePubBase64Url !== 'string' || connectionSharePubBase64Url.length === 0) {
    throw new Error('connectionSharePubBase64Url is required');
  }
  return {
    ...record,
    muted: record.muted.filter((m: MutedEntry) => m.share_pub !== connectionSharePubBase64Url),
  };
}

export function isMutedInRecord(record: MutedConnectionsRecord, connectionSharePubBase64Url: string): boolean {
  if (!record || !Array.isArray(record.muted)) {
    throw new Error('record must be a muted-connections record');
  }
  return record.muted.some((m: MutedEntry) => m.share_pub === connectionSharePubBase64Url);
}

function requireString(v: unknown, name: string): string {
  if (typeof v !== 'string' || v.length === 0) throw new Error(`${name} must be a non-empty string`);
  return v;
}

// ============ ISSUED-INVITES RECORD (Section 8, issue #22) ============

export const ISSUED_INVITES_CONTENT_ID = 'tarn-issued-invites-v1';

export type IssuedInviteEntry = {
  token_id: string;
  // Other fields (created_at, expires_at, ...) flow through.
  [key: string]: unknown;
};

export type IssuedInvitesRecord = {
  app_id: string;
  version: 1;
  invites: IssuedInviteEntry[];
};

export function emptyIssuedInvitesRecord(appId: string): IssuedInvitesRecord {
  return { app_id: appId, version: 1, invites: [] };
}

export function addIssuedInvite(record: IssuedInvitesRecord, entry: IssuedInviteEntry): IssuedInvitesRecord {
  if (!record || !Array.isArray(record.invites)) {
    throw new Error('record must be an issued-invites record');
  }
  if (!entry || typeof entry.token_id !== 'string') {
    throw new Error('entry.token_id is required');
  }
  if (record.invites.some((i: IssuedInviteEntry) => i.token_id === entry.token_id)) {
    return record;
  }
  return { ...record, invites: [...record.invites, entry] };
}

export function removeIssuedInvite(record: IssuedInvitesRecord, tokenId: string): IssuedInvitesRecord {
  if (!record || !Array.isArray(record.invites)) {
    throw new Error('record must be an issued-invites record');
  }
  return { ...record, invites: record.invites.filter((i: IssuedInviteEntry) => i.token_id !== tokenId) };
}
