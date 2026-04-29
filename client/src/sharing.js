// Tarn Client — Sharing Section 5a: HPKE friend handshake
//
// Implements the friend-handshake bootstrap from
// `2026-04-28-tarn-sharing-design.md` §6 (handshake), §7 (friends + pending
// records), §13.8 (replay defense), §13.9 (forged-accept defense).
//
// Stops short of the share log (5b) — this module produces no signed
// operations, no per-pair shared secret, no stealth-addressed tags, no
// snapshot. Two users completing the handshake end up in each other's
// friends record, and that's the entire surface.
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
const TEXT_DECODER = new TextDecoder();

// HPKE info strings — bind ciphertexts to a specific protocol version + role,
// per RFC 9180 §5.1 recommendations. Mismatched info on Open() returns
// AEAD-level decryption failure, so a connection-request sealed under one info
// cannot be replayed as an accept (or any other future role) even if it lands
// at the same tag.
export const INFO_FRIEND_REQUEST = 'tarn-connection-request-v1';
export const INFO_FRIEND_ACCEPT = 'tarn-connection-accept-v1';

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

// Friend-request blob size cap. The plaintext is a small JSON object
// (sender_email + 32-byte sender_share_pub + 65-byte sender_signing_pub +
// nonce + timestamp + optional message). HPKE sealed adds 32 (enc) + 16
// (AEAD tag). 8 KB is a generous cap that catches nothing legitimate but
// bounds memory before we touch crypto.
export const MAX_HANDSHAKE_BLOB_BYTES = 8 * 1024;

// Cap on user-supplied free-text greeting in a friend request. UI surface,
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

// ============ INBOX TAG DERIVATION ============

/**
 * Compute the rolling day window for a unix timestamp (sharing §6.1).
 * @param {number} unixSeconds
 * @returns {number}
 */
export function inboxWindowFor(unixSeconds) {
  return Math.floor(unixSeconds / SECONDS_PER_DAY);
}

/** Current inbox window — `floor(unix_timestamp / 86400)`. */
export function currentInboxWindow(now = Date.now()) {
  return inboxWindowFor(Math.floor(now / 1000));
}

/**
 * Last `count` inbox windows ending at the current window, descending
 * (newest first). Used by `listIncomingRequests` to poll the recent backlog
 * (default 30 days per design §6.1).
 *
 * @param {number} count
 * @param {number} [now=Date.now()]
 * @returns {number[]}
 */
export function recentInboxWindows(count, now = Date.now()) {
  const cur = currentInboxWindow(now);
  const out = [];
  for (let i = 0; i < count; i++) out.push(cur - i);
  return out;
}

function encodeUint64BE(n) {
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
 *
 * The HMAC key is `SHA-256(share_pub)` — a stable per-recipient secret in the
 * sense that it is publicly derivable by anyone who knows the recipient's
 * share_pub, which is intentional: senders need to compute it.
 *
 * @param {Uint8Array} recipientSharePub - 32 raw X25519 bytes
 * @param {string} appId
 * @param {number} window - integer day window from `currentInboxWindow()`
 * @returns {Promise<string>} base64url tag value (43 chars)
 */
export async function deriveInboxTag(recipientSharePub, appId, window) {
  if (!(recipientSharePub instanceof Uint8Array) || recipientSharePub.length !== 32) {
    throw new Error('recipientSharePub must be a 32-byte Uint8Array');
  }
  if (!appId) throw new Error('appId is required');
  if (!Number.isInteger(window) || window < 0) {
    throw new Error('window must be a non-negative integer');
  }
  const hmacKeyBytes = new Uint8Array(
    await crypto.subtle.digest('SHA-256', recipientSharePub),
  );
  const hmacKey = await crypto.subtle.importKey(
    'raw', hmacKeyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  // Concatenate the label, app_id, "-", and 8-byte window. The label already
  // ends with "-" so no extra separator before app_id; we add an explicit "-"
  // between app_id and the window bytes to match the design notation.
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

  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, msg));
  return bytesToBase64Url(sig);
}

// ============ HPKE SEAL / OPEN ============

/**
 * Wire-format envelope for an HPKE-sealed handshake blob:
 *   bytes[0..32)  = enc (ephemeral pubkey, 32 bytes for X25519)
 *   bytes[32..)   = AEAD ciphertext + tag
 *
 * Total overhead vs. plaintext: 32 (enc) + 16 (AEAD tag) = 48 bytes. The two
 * pieces are concatenated so that consumers can store/transmit a single blob
 * without a separate "enc" sidecar — matching the design doc's "request_blob"
 * + "accept_blob" being single Arweave blobs.
 */

/**
 * Import a 32-byte raw X25519 public key as an HPKE recipient public key.
 * @param {Uint8Array} sharePub
 */
async function importHpkePublicKey(sharePub) {
  if (!(sharePub instanceof Uint8Array) || sharePub.length !== 32) {
    throw new Error('share_pub must be a 32-byte Uint8Array');
  }
  return await suite.kem.importKey('raw', sharePub.buffer.slice(sharePub.byteOffset, sharePub.byteOffset + 32), true);
}

/**
 * Import a 32-byte raw X25519 private key as an HPKE recipient private key,
 * and re-derive the matching public key. The HPKE library expects a CryptoKey
 * pair (`{ privateKey, publicKey }`) when opening; deriving the public from
 * the private is cheaper than re-deriving it from `master_key` here.
 *
 * @param {Uint8Array} sharePriv - 32-byte X25519 scalar
 */
async function importHpkePrivateKeyPair(sharePriv) {
  if (!(sharePriv instanceof Uint8Array) || sharePriv.length !== 32) {
    throw new Error('share_priv must be a 32-byte Uint8Array');
  }
  const privateKey = await suite.kem.importKey(
    'raw',
    sharePriv.buffer.slice(sharePriv.byteOffset, sharePriv.byteOffset + 32),
    false,
  );
  // The KEM exposes derivePublicKey via its primitives interface — use it via
  // the suite's kem instance. Falls back to JWK round-trip if needed.
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  delete jwk.d;
  delete jwk.key_ops;
  const publicKey = await crypto.subtle.importKey('jwk', jwk, { name: 'X25519' }, true, []);
  return { privateKey, publicKey };
}

/**
 * HPKE-Seal an arbitrary plaintext to a recipient (sharing §6.2 / §6.4).
 *
 * @param {{
 *   recipientSharePub: Uint8Array,
 *   info: string,
 *   plaintext: Uint8Array,
 * }} opts
 * @returns {Promise<Uint8Array>} Wire blob: enc(32) || ciphertext+tag
 */
export async function hpkeSeal({ recipientSharePub, info, plaintext }) {
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
  const ct = new Uint8Array(await sender.seal(plaintext.buffer.slice(plaintext.byteOffset, plaintext.byteOffset + plaintext.byteLength)));
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
 *
 * @param {{
 *   sharePriv: Uint8Array,
 *   info: string,
 *   blob: Uint8Array,
 * }} opts
 * @returns {Promise<Uint8Array>} plaintext
 */
export async function hpkeOpen({ sharePriv, info, blob }) {
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
    enc: enc.buffer.slice(enc.byteOffset, enc.byteOffset + enc.byteLength),
    info: TEXT_ENCODER.encode(info),
  });
  const ptBuf = await recipient.open(ct.buffer.slice(ct.byteOffset, ct.byteOffset + ct.byteLength));
  return new Uint8Array(ptBuf);
}

// ============ FRIEND REQUEST / ACCEPT PAYLOADS ============

/**
 * Build a friend-request payload (sharing §6.2). Returns the JSON object —
 * caller will serialize, HPKE-seal, and publish.
 *
 * @param {{
 *   senderEmail: string,
 *   senderSharePub: Uint8Array,
 *   senderSigningPubBase64: string,    // existing Tarn ECDSA P-256 SPKI base64
 *   senderAppId: string,
 *   message?: string,
 *   timestamp?: number,                // unix seconds; defaults to now
 *   nonce?: Uint8Array,                // 16 random bytes; generated if absent
 * }} opts
 * @returns {{ type: 'connection_request', sender_email: string, sender_share_pub: string, sender_signing_pub: string, sender_app_id: string, nonce: string, timestamp: number, message?: string }}
 */
export function buildFriendRequestPayload(opts) {
  const senderEmail = requireString(opts.senderEmail, 'senderEmail');
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
  const nonce = opts.nonce instanceof Uint8Array
    ? opts.nonce
    : crypto.getRandomValues(new Uint8Array(16));
  if (nonce.length !== 16) throw new Error('nonce must be 16 bytes');
  const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1000);

  const out = {
    type: 'connection_request',
    sender_email: senderEmail,
    sender_share_pub: bytesToBase64Url(opts.senderSharePub),
    sender_signing_pub: senderSigningPub,
    sender_app_id: senderAppId,
    nonce: bytesToBase64Url(nonce),
    timestamp,
  };
  if (opts.message) out.message = opts.message;
  return out;
}

/**
 * Validate a decoded friend-request payload (sharing §6.3 + §13.8).
 *
 * Returns `{ valid: false, reason }` on any structural problem, replay-window
 * violation, or wrong-app mismatch. Returns `{ valid: true, normalized }` on
 * success — `normalized` is a typed view (with `senderSharePub` and `nonce`
 * already decoded to bytes) suitable for storing in the inbound pending list.
 *
 * Replay protection (the recent-nonce cache check) is performed by
 * {@link checkAndRecordNonce}, *not* here — we want callers to validate the
 * payload first (cheap) before consulting the cache.
 *
 * @param {*} payload - Anything that decoded out of HPKE-Open + JSON.parse
 * @param {string} expectedAppId - app_id of the recipient's TarnClient
 * @param {number} [now=Date.now()/1000] - unix seconds, override for tests
 */
export function validateFriendRequestPayload(payload, expectedAppId, now = Math.floor(Date.now() / 1000)) {
  if (!payload || typeof payload !== 'object') {
    return { valid: false, reason: 'payload must be an object' };
  }
  if (payload.type !== 'connection_request') {
    return { valid: false, reason: `wrong type: ${payload.type}` };
  }
  if (typeof payload.sender_email !== 'string' || payload.sender_email.length === 0) {
    return { valid: false, reason: 'sender_email missing or invalid' };
  }
  if (typeof payload.sender_app_id !== 'string' || payload.sender_app_id !== expectedAppId) {
    // Per-app isolation (sharing §1.4): a request originating in app X must
    // not be processable as an app-Y request even if it lands at the wrong
    // inbox tag (tags differ across apps but defense-in-depth is cheap).
    return { valid: false, reason: `sender_app_id ${payload.sender_app_id} != ${expectedAppId}` };
  }
  let senderSharePub;
  try {
    senderSharePub = base64UrlToBytes(payload.sender_share_pub);
    if (senderSharePub.length !== 32) {
      return { valid: false, reason: `sender_share_pub must be 32 bytes, got ${senderSharePub.length}` };
    }
  } catch {
    return { valid: false, reason: 'sender_share_pub is not valid base64url' };
  }
  if (typeof payload.sender_signing_pub !== 'string' || payload.sender_signing_pub.length === 0) {
    return { valid: false, reason: 'sender_signing_pub missing or invalid' };
  }
  let nonce;
  try {
    nonce = base64UrlToBytes(payload.nonce);
    if (nonce.length !== 16) {
      return { valid: false, reason: `nonce must be 16 bytes, got ${nonce.length}` };
    }
  } catch {
    return { valid: false, reason: 'nonce is not valid base64url' };
  }
  if (!Number.isFinite(payload.timestamp) || !Number.isInteger(payload.timestamp)) {
    return { valid: false, reason: 'timestamp must be an integer' };
  }
  if (payload.timestamp < now - REPLAY_PAST_WINDOW_SEC) {
    return { valid: false, reason: 'timestamp too old (>7 days)' };
  }
  if (payload.timestamp > now + REPLAY_FUTURE_WINDOW_SEC) {
    return { valid: false, reason: 'timestamp too far in the future' };
  }
  if (payload.message != null) {
    if (typeof payload.message !== 'string') {
      return { valid: false, reason: 'message must be a string when present' };
    }
    if (payload.message.length > MAX_REQUEST_MESSAGE_LEN) {
      return { valid: false, reason: `message exceeds ${MAX_REQUEST_MESSAGE_LEN} chars` };
    }
  }
  return {
    valid: true,
    normalized: {
      type: 'connection_request',
      senderEmail: payload.sender_email,
      senderSharePub,
      senderSharePubBase64Url: payload.sender_share_pub,
      senderSigningPubBase64: payload.sender_signing_pub,
      senderAppId: payload.sender_app_id,
      nonce,
      nonceBase64Url: payload.nonce,
      timestamp: payload.timestamp,
      message: payload.message ?? null,
    },
  };
}

/**
 * Build an accept payload (sharing §6.4).
 *
 * @param {{
 *   senderEmail: string,
 *   senderSharePub: Uint8Array,
 *   senderSigningPubBase64: string,
 *   senderAppId: string,
 *   inReplyToNonceBase64Url: string,
 *   timestamp?: number,
 * }} opts
 */
export function buildFriendAcceptPayload(opts) {
  const senderEmail = requireString(opts.senderEmail, 'senderEmail');
  const senderSigningPub = requireString(opts.senderSigningPubBase64, 'senderSigningPubBase64');
  const senderAppId = requireString(opts.senderAppId, 'senderAppId');
  const inReplyTo = requireString(opts.inReplyToNonceBase64Url, 'inReplyToNonceBase64Url');
  if (!(opts.senderSharePub instanceof Uint8Array) || opts.senderSharePub.length !== 32) {
    throw new Error('senderSharePub must be a 32-byte Uint8Array');
  }
  return {
    type: 'connection_accept',
    sender_email: senderEmail,
    sender_share_pub: bytesToBase64Url(opts.senderSharePub),
    sender_signing_pub: senderSigningPub,
    sender_app_id: senderAppId,
    in_reply_to: inReplyTo,
    timestamp: opts.timestamp ?? Math.floor(Date.now() / 1000),
  };
}

/**
 * Validate a decoded accept payload. Same shape as
 * {@link validateFriendRequestPayload} except for `in_reply_to`. Forged-accept
 * defense (sharing §13.9) is performed by callers cross-referencing the
 * returned `inReplyTo` against their outbound pending list — see
 * {@link findOutboundForAccept}.
 */
export function validateFriendAcceptPayload(payload, expectedAppId, now = Math.floor(Date.now() / 1000)) {
  if (!payload || typeof payload !== 'object') {
    return { valid: false, reason: 'payload must be an object' };
  }
  if (payload.type !== 'connection_accept') {
    return { valid: false, reason: `wrong type: ${payload.type}` };
  }
  if (typeof payload.sender_email !== 'string' || payload.sender_email.length === 0) {
    return { valid: false, reason: 'sender_email missing or invalid' };
  }
  if (typeof payload.sender_app_id !== 'string' || payload.sender_app_id !== expectedAppId) {
    return { valid: false, reason: `sender_app_id ${payload.sender_app_id} != ${expectedAppId}` };
  }
  let senderSharePub;
  try {
    senderSharePub = base64UrlToBytes(payload.sender_share_pub);
    if (senderSharePub.length !== 32) {
      return { valid: false, reason: `sender_share_pub must be 32 bytes, got ${senderSharePub.length}` };
    }
  } catch {
    return { valid: false, reason: 'sender_share_pub is not valid base64url' };
  }
  if (typeof payload.sender_signing_pub !== 'string' || payload.sender_signing_pub.length === 0) {
    return { valid: false, reason: 'sender_signing_pub missing or invalid' };
  }
  if (typeof payload.in_reply_to !== 'string' || payload.in_reply_to.length === 0) {
    return { valid: false, reason: 'in_reply_to missing' };
  }
  if (!Number.isFinite(payload.timestamp) || !Number.isInteger(payload.timestamp)) {
    return { valid: false, reason: 'timestamp must be an integer' };
  }
  if (payload.timestamp < now - REPLAY_PAST_WINDOW_SEC) {
    return { valid: false, reason: 'timestamp too old (>7 days)' };
  }
  if (payload.timestamp > now + REPLAY_FUTURE_WINDOW_SEC) {
    return { valid: false, reason: 'timestamp too far in the future' };
  }
  return {
    valid: true,
    normalized: {
      type: 'connection_accept',
      senderEmail: payload.sender_email,
      senderSharePub,
      senderSharePubBase64Url: payload.sender_share_pub,
      senderSigningPubBase64: payload.sender_signing_pub,
      senderAppId: payload.sender_app_id,
      inReplyToNonceBase64Url: payload.in_reply_to,
      timestamp: payload.timestamp,
    },
  };
}

// ============ REPLAY-NONCE CACHE (sharing §13.8) ============

/**
 * In-memory recent-nonce cache. Each device keeps one cache; entries expire
 * after `REPLAY_NONCE_TTL_SEC`. Replay defense is best-effort — it does not
 * survive client restart, so an attacker re-publishing a captured request
 * after the recipient's session ends would still be re-surfaced. The
 * timestamp window check (which the recipient performs on every payload) is
 * the primary defense; the cache is the runtime tightening for the live
 * session.
 *
 * The cache is keyed by `nonceBase64Url` only — same payload, same nonce,
 * same key. We do NOT scope by sender, so an attacker swapping `sender_email`
 * but keeping `nonce` still gets dropped. (Sender swap can't pass HPKE_Open
 * anyway — the recipient's private key is what unwraps, and the inner
 * sender_share_pub is what gets compared during friending — but the cache
 * dedupe is one extra layer.)
 */

/** @returns {{ entries: Map<string, number> }} */
export function makeReplayNonceCache() {
  return { entries: new Map() };
}

/**
 * Record a nonce as seen, OR reject as a replay if already present.
 *
 * @param {{ entries: Map<string, number> }} cache
 * @param {string} nonceBase64Url - the request's nonce in base64url
 * @param {number} [now=Date.now()/1000] - unix seconds
 * @returns {{ replay: boolean }}
 */
export function checkAndRecordNonce(cache, nonceBase64Url, now = Math.floor(Date.now() / 1000)) {
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
 * outbound pending list. Unmatched accepts are silently ignored — the user
 * is not prompted, no friend record entry is created.
 *
 * Accepts entries that expose either `request_nonce` (the on-the-wire record
 * shape per §7.2) or `requestNonce` (the camelCase view typically used in
 * UI/SDK code). Test fixtures and the real persisted record can mix shapes
 * cheaply this way without forcing a normalization step at every call site.
 *
 * @param {string} inReplyToNonceBase64Url
 * @param {Iterable<{request_nonce?: string, requestNonce?: string}>} outboundPending
 * @returns {object | null} the matching outbound pending entry, or null on forgery
 */
export function findOutboundForAccept(inReplyToNonceBase64Url, outboundPending) {
  if (typeof inReplyToNonceBase64Url !== 'string') return null;
  for (const entry of outboundPending) {
    if (!entry) continue;
    if (entry.request_nonce === inReplyToNonceBase64Url) return entry;
    if (entry.requestNonce === inReplyToNonceBase64Url) return entry;
  }
  return null;
}

// ============ FRIENDS + PENDING-REQUESTS RECORD SHAPES ============

// Empty initial record bodies (sharing §7.1, §7.2). The friends + pending
// records live as encrypted Tarn data blobs (per-content CEK pattern from
// issue #11 / Section 2). Operational state like `last_seq_seen` is per-
// device, NOT in the durable record (Section 3 review).

export const FRIENDS_CONTENT_ID = 'tarn-connections-v1';
export const PENDING_REQUESTS_CONTENT_ID = 'tarn-pending-requests-v1';

/**
 * Shape: an empty friends record for a fresh account.
 * @param {string} appId
 */
export function emptyFriendsRecord(appId) {
  return { app_id: appId, version: 1, friends: [] };
}

/** Shape: an empty pending-requests record. */
export function emptyPendingRequestsRecord(appId) {
  return { app_id: appId, version: 1, outbound: [], inbound: [] };
}

/**
 * Append a friend (idempotent on `share_pub`) to the friends record.
 * Replaces an existing entry with the same share_pub if present.
 *
 * Inputs are de-typed (base64url strings + JSON numbers) so the record can
 * be JSON-serialized verbatim.
 */
export function upsertFriend(record, friend) {
  if (!record || !Array.isArray(record.friends)) {
    throw new Error('record must be a friends record');
  }
  if (!friend || typeof friend.share_pub !== 'string') {
    throw new Error('friend.share_pub is required');
  }
  const idx = record.friends.findIndex(f => f.share_pub === friend.share_pub);
  const out = { ...record, friends: record.friends.slice() };
  if (idx >= 0) out.friends[idx] = friend;
  else out.friends.push(friend);
  return out;
}

/**
 * Remove a friend (idempotent on `share_pub`) from the friends record. Used
 * by the §10.1 unfriend flow. Returns the record unchanged if no entry
 * matched. Direction-aware: this is one-side; the unfriended party retains
 * their own friends record entry until they independently unfriend back.
 */
export function removeFriend(record, friendSharePubBase64Url) {
  if (!record || !Array.isArray(record.friends)) {
    throw new Error('record must be a friends record');
  }
  if (typeof friendSharePubBase64Url !== 'string' || friendSharePubBase64Url.length === 0) {
    throw new Error('friendSharePubBase64Url is required');
  }
  return {
    ...record,
    friends: record.friends.filter(f => f.share_pub !== friendSharePubBase64Url),
  };
}

/**
 * Apply a `rotate_identity` announcement (sharing §13.5) to a friend's entry
 * in the friends record. The caller is responsible for verifying the
 * announcement's ECDSA signature against the friend's currently-cached
 * `signing_pub` BEFORE calling this — the helper itself does no crypto.
 *
 * Replaces share_pub, signing_pub, and credential_lookup_key with the values
 * carried in the announcement. Records the rotation timestamp and the
 * pre-rotation share_pub for audit. Returns the record unchanged if the
 * friend isn't found (defensive — should not happen in normal flow).
 *
 * @param {Object} record - friends record
 * @param {string} friendSharePubBase64Url - the friend's CURRENT share_pub
 * @param {{
 *   newSharePubBase64Url: string,
 *   newSigningPubBase64: string,
 *   newCredentialLookupKey: string,
 *   rotatedAt: number,
 * }} update
 */
export function rotateFriendIdentity(record, friendSharePubBase64Url, update) {
  if (!record || !Array.isArray(record.friends)) {
    throw new Error('record must be a friends record');
  }
  if (typeof friendSharePubBase64Url !== 'string' || friendSharePubBase64Url.length === 0) {
    throw new Error('friendSharePubBase64Url is required');
  }
  if (!update
    || typeof update.newSharePubBase64Url !== 'string'
    || typeof update.newSigningPubBase64 !== 'string'
    || typeof update.newCredentialLookupKey !== 'string'
    || !Number.isInteger(update.rotatedAt)
  ) {
    throw new Error('rotateFriendIdentity: update must have newSharePubBase64Url, newSigningPubBase64, newCredentialLookupKey, rotatedAt');
  }
  const idx = record.friends.findIndex(f => f.share_pub === friendSharePubBase64Url);
  if (idx < 0) return record;
  const prior = record.friends[idx];
  const rotated = {
    ...prior,
    share_pub: update.newSharePubBase64Url,
    signing_pub: update.newSigningPubBase64,
    credential_lookup_key: update.newCredentialLookupKey,
    rotated_at: update.rotatedAt,
    prior_share_pub: friendSharePubBase64Url,
  };
  const friends = record.friends.slice();
  friends[idx] = rotated;
  return { ...record, friends };
}

/** Add an outbound pending request (idempotent on request_nonce). */
export function addOutboundPending(record, entry) {
  ensurePendingShape(record);
  if (!entry || typeof entry.request_nonce !== 'string') {
    throw new Error('entry.request_nonce is required');
  }
  if (record.outbound.some(o => o.request_nonce === entry.request_nonce)) {
    return record; // already there
  }
  return { ...record, outbound: [...record.outbound, entry] };
}

/** Add an inbound pending request (idempotent on request_nonce). */
export function addInboundPending(record, entry) {
  ensurePendingShape(record);
  if (!entry || typeof entry.request_nonce !== 'string') {
    throw new Error('entry.request_nonce is required');
  }
  if (record.inbound.some(i => i.request_nonce === entry.request_nonce)) {
    return record;
  }
  return { ...record, inbound: [...record.inbound, entry] };
}

/** Remove an outbound pending entry by request_nonce. */
export function removeOutboundPending(record, requestNonce) {
  ensurePendingShape(record);
  return { ...record, outbound: record.outbound.filter(o => o.request_nonce !== requestNonce) };
}

/** Remove an inbound pending entry by request_nonce. */
export function removeInboundPending(record, requestNonce) {
  ensurePendingShape(record);
  return { ...record, inbound: record.inbound.filter(i => i.request_nonce !== requestNonce) };
}

function ensurePendingShape(record) {
  if (!record || !Array.isArray(record.outbound) || !Array.isArray(record.inbound)) {
    throw new Error('record must be a pending-requests record');
  }
}

function requireString(v, name) {
  if (typeof v !== 'string' || v.length === 0) throw new Error(`${name} must be a non-empty string`);
  return v;
}
