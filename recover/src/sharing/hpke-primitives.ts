/**
 * HPKE seal/open + connection-record helpers — borrowed verbatim from
 * `client/src/sharing.ts` (Phase 5).
 *
 * The recover client uses the read-side surface to:
 *   - derive an inbox tag for the user's share-key
 *   - HPKE-decrypt connection-request / connection-accept blobs from the inbox
 *   - validate decoded payloads (replay-window, app-id, structural sanity)
 *
 * Encrypt / build helpers are included for symmetry — the recover package
 * never mints fresh handshake material in production, but tests use them to
 * stage synthetic fixtures without re-implementing the wire format.
 *
 * Crypto suite (RFC 9180): DHKEM-X25519 + HKDF-SHA-256 + AES-256-GCM.
 *
 * See `docs/TARN_PROTOCOL.md` §sharing for the on-the-wire definition.
 */

import {
  CipherSuite,
  DhkemX25519HkdfSha256,
  HkdfSha256,
  Aes256Gcm,
} from '@hpke/core';
import { bytesToBase64Url, base64UrlToBytes } from '../crypto/encoding.js';

// ============ CONSTANTS ============

const TEXT_ENCODER = new TextEncoder();

export const INFO_CONNECTION_REQUEST = 'tarn-connection-request-v1';
export const INFO_CONNECTION_ACCEPT = 'tarn-connection-accept-v1';

const INBOX_TAG_LABEL_PREFIX = 'tarn-connection-inbox-v1-';

const SECONDS_PER_DAY = 86400;

export const REPLAY_PAST_WINDOW_SEC = 7 * SECONDS_PER_DAY;
export const REPLAY_FUTURE_WINDOW_SEC = 1 * SECONDS_PER_DAY;
export const REPLAY_NONCE_TTL_SEC = REPLAY_PAST_WINDOW_SEC + SECONDS_PER_DAY;

export const DEFAULT_POLL_WINDOWS = 30;

export const MAX_HANDSHAKE_BLOB_BYTES = 8 * 1024;
export const MAX_REQUEST_MESSAGE_LEN = 280;

// Wire content-id constants for the share-state records the user's account
// owns (these live as encrypted entries in the `tarn-share-state` collection,
// disambiguated by the `Eid` Arweave tag).
export const CONNECTIONS_CONTENT_ID = 'tarn-connections-v1';
export const PENDING_REQUESTS_CONTENT_ID = 'tarn-pending-requests-v1';
export const MUTED_CONNECTIONS_CONTENT_ID = 'tarn-muted-connections-v1';
export const ISSUED_INVITES_CONTENT_ID = 'tarn-issued-invites-v1';

// ============ HPKE SUITE ============

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

// ============ WebCrypto BufferSource cast ============

function bs(b: ArrayBufferView | ArrayBuffer): BufferSource {
  return b as BufferSource;
}

// ============ INBOX TAG DERIVATION ============

/** Compute the rolling day window for a unix timestamp. */
export function inboxWindowFor(unixSeconds: number): number {
  return Math.floor(unixSeconds / SECONDS_PER_DAY);
}

/** Current inbox window — `floor(unix_timestamp / 86400)`. */
export function currentInboxWindow(now: number = Date.now()): number {
  return inboxWindowFor(Math.floor(now / 1000));
}

/**
 * Last `count` inbox windows ending at the current window, descending
 * (newest first). Recover clients walk a wide range to catch the original
 * handshake even when it happened months ago.
 */
export function recentInboxWindows(count: number, now: number = Date.now()): number[] {
  const cur = currentInboxWindow(now);
  const out: number[] = [];
  for (let i = 0; i < count; i++) out.push(cur - i);
  return out;
}

function encodeUint64BE(n: number): Uint8Array {
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
 *
 * Recover clients deliberately disable the replay-window cutoff (pass an
 * `now` that's after every plausible historical timestamp) — old handshakes
 * are exactly what we want to recover.
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

export type ConnectionAcceptPayload = {
  type: 'connection_accept';
  sender_email: string;
  sender_share_pub: string;
  sender_signing_pub: string;
  sender_app_id: string;
  in_reply_to: string;
  timestamp: number;
};

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

// ============ CONNECTION RECORD SHAPES ============

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

export function emptyConnectionsRecord(appId: string): ConnectionsRecord {
  return { app_id: appId, version: 1, connections: [] };
}

/**
 * Quick shape check for a connections-record blob decoded from
 * `tarn-share-state` storage. Returns true iff the shape matches; recover
 * clients then iterate `connections` directly.
 */
export function isConnectionsRecord(value: unknown): value is ConnectionsRecord {
  if (!value || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  if (typeof v['app_id'] !== 'string') return false;
  if (v['version'] !== 1) return false;
  if (!Array.isArray(v['connections'])) return false;
  for (const c of v['connections'] as unknown[]) {
    if (!c || typeof c !== 'object') return false;
    const ce = c as Record<string, unknown>;
    if (typeof ce['share_pub'] !== 'string') return false;
    if (typeof ce['signing_pub'] !== 'string') return false;
  }
  return true;
}
