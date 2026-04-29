// Tarn Client — Sharing Section 5b: per-pair share log primitives.
//
// Implements the write-side of the per-pair share log from
// `2026-04-28-tarn-sharing-design.md`:
//
//   §4.2–4.5  per-pair shared secret S_AB (X25519 ECDH) and direction-aware
//             sub-keys K_AB / T_AB_seed via distinct HKDF info strings
//   §4.4      log_tag(T_AB_seed, seq) = B(HMAC(T_AB_seed,
//                                              "log_v1_" || encode_uint64(seq)))
//   §8.1      log entry blob format with sender ECDSA-P256 signature, AES-GCM
//             ciphertext under K_AB, AAD "tarn-share-log-v1"
//   §8.3      five normal operation types (add/update/rotate/remove/snapshot);
//             rotate_identity is recognized as a sixth type for forward-compat
//   §8.4      idempotency rules surfaced via parsed-operation predicates
//   §8.6      writer-side snapshot compaction (default every 100 deltas)
//   §9.1      per-tag uniqueness on publish
//
// 5b stops short of:
//   - revocation flow (§10 — 5d)
//   - rotate_identity *emission/processing* (§13.5 — 5d). The type itself ships
//     here so 5d can layer on the emit path without a parser change.
//
// 5c (this file's later additions) layers on top of 5b:
//   - discoverHighestSeq (§9.2): exponential probe + bisect over a caller-
//     supplied probe(seq)->bool. The seed never leaves the device — Tarn sees
//     individual pseudorandom tag fetches only.
//   - applyOperationToState (§8.4 idempotency rules) and replayOperations as
//     pure helpers. The TarnClient layer composes these with the §8.1 fetch
//     primitives to do bootstrap + incremental sync (§8.5).

import { x25519 } from '@noble/curves/ed25519';
import {
  bytesToBase64Url,
  base64UrlToBytes,
} from './crypto.js';

// ============ CONSTANTS ============

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

// AAD on the AES-GCM seal — ties the ciphertext to "share log v1" so a future
// v2 format with the same K_AB can't be replayed as a v1 entry.
const SHARE_LOG_AAD = 'tarn-share-log-v1';

// Signature input prefix per §8.1.
const SHARE_LOG_SIG_PREFIX = 'tarn-share-log-v1-sig';

// Tag derivation label per §4.4. The "log_v1_" prefix is part of the HMAC
// message — different versions get distinct tag streams from the same seed.
const TAG_LABEL_PREFIX = 'log_v1_';

// HKDF info pieces (sharing §4.3 / §4.5) — match the existing tarn pattern of
// `tarn || purpose || app_id || version || counter_byte`. Direction is baked
// into the purpose label rather than as a separate field, matching the design.
//
// §4.5 names two direction-keyed info strings for the same pair:
//   K_AB_to_B   — "share-key"      (the "forward" direction)
//   K_AB_to_A   — "share-key-rev"  (the "reverse" direction)
//
// Both sides compute identical bytes from the same S_AB + same info — the
// design is symmetric. To turn that symmetry into directed channels both
// parties agree on, we pick the party whose share_pub sorts lex-lower as
// "A" (the "forward writer"). That role is stable across sessions, devices,
// and re-derivations, so each side knows which HKDF info string to use for
// its own outbound stream.
const PROTOCOL_ID = 'tarn';
const DERIVATION_VERSION = '1';
const HKDF_COUNTER_BYTE = 0x01;
const PURPOSE_KEY_FORWARD = 'share-key';      // K_AB_to_B (lex-lower → lex-higher)
const PURPOSE_KEY_REVERSE = 'share-key-rev';  // K_AB_to_A (lex-higher → lex-lower)
const PURPOSE_TAG_FORWARD = 'share-tag';      // T_AB_seed_to_B
const PURPOSE_TAG_REVERSE = 'share-tag-rev';  // T_AB_seed_to_A

// AES-GCM IV is 12 bytes per RFC 5116; 16-byte tag.
const IV_LEN = 12;
const GCM_TAG_LEN = 16;

// Operation types per §8.3 + the §13.5 forward-compat type.
export const OP_ADD             = 'add';
export const OP_UPDATE          = 'update';
export const OP_ROTATE          = 'rotate';
export const OP_REMOVE          = 'remove';
export const OP_SNAPSHOT        = 'snapshot';
export const OP_ROTATE_IDENTITY = 'rotate_identity';

export const KNOWN_OP_TYPES = new Set([
  OP_ADD, OP_UPDATE, OP_ROTATE, OP_REMOVE, OP_SNAPSHOT, OP_ROTATE_IDENTITY,
]);

// Wire type tag for the publish endpoint and Arweave Type tag.
export const SHARE_LOG_TYPE = 'share-log-v1';

// Snapshot compaction policy per §8.6. After every COMPACTION_INTERVAL non-
// snapshot operations the writer emits a snapshot at the next seq. Tunable —
// the constant is exported so tests and apps can override it without forking.
export const DEFAULT_COMPACTION_INTERVAL = 100;

// Cap on a single share-log blob's plaintext size — protects callers + the
// API. The `snapshot` operation grows linearly with shared-content count;
// 256 KB plaintext fits ~2,500 entries at ~95 bytes each (sharing §12.1),
// well above the 200-item Bookish-class user the design budgets for.
export const MAX_LOG_BLOB_PLAINTEXT_BYTES = 256 * 1024;

// ============ ENCODING HELPERS ============

function encodeUint64BE(n) {
  const buf = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function assertU8(b, name, expectedLen) {
  if (!(b instanceof Uint8Array)) throw new Error(`${name} must be a Uint8Array`);
  if (expectedLen != null && b.length !== expectedLen) {
    throw new Error(`${name} must be ${expectedLen} bytes, got ${b.length}`);
  }
}

function assertSeq(seq) {
  if (!Number.isInteger(seq) || seq < 0) {
    throw new Error(`seq must be a non-negative integer, got ${seq}`);
  }
}

// ============ HKDF-EXPAND (single block, 32 bytes) ============

// Match crypto.js's `hkdfExpand` — single-block HKDF-Expand with the
// info layout `protocol || purpose || app_id || version || counter_byte`.
// We re-implement here rather than importing crypto.js's private helper
// because that one is module-private and signing it as a public export just
// for this caller would widen the surface unnecessarily.
async function hkdfExpand32(prk, purpose, appId) {
  assertU8(prk, 'prk', 32);
  if (!purpose) throw new Error('purpose is required');
  if (!appId) throw new Error('appId is required');
  const hmacKey = await crypto.subtle.importKey(
    'raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const info = concatBytes(
    TEXT_ENCODER.encode(PROTOCOL_ID + purpose + appId + DERIVATION_VERSION),
    new Uint8Array([HKDF_COUNTER_BYTE]),
  );
  const sig = await crypto.subtle.sign('HMAC', hmacKey, info);
  return new Uint8Array(sig);
}

// ============ PER-PAIR KEY DERIVATION (sharing §4.2–§4.5) ============

/**
 * Per-pair shared secret S_AB = ECDH_X25519(share_priv, peer_share_pub).
 * Symmetric: both sides compute the same 32 bytes from their respective
 * (priv, peer_pub) inputs (sharing §4.2).
 *
 * @param {Uint8Array} sharePriv - 32-byte X25519 scalar (own share_priv)
 * @param {Uint8Array} peerSharePub - 32-byte X25519 group element (peer share_pub)
 * @returns {Uint8Array} 32 bytes
 */
export function deriveSharedSecret(sharePriv, peerSharePub) {
  assertU8(sharePriv, 'sharePriv', 32);
  assertU8(peerSharePub, 'peerSharePub', 32);
  const out = x25519.getSharedSecret(sharePriv, peerSharePub);
  // Defensive: `getSharedSecret` always returns 32 bytes for X25519 today, but
  // a mis-import or library upgrade could change that — fail loud rather than
  // silently produce shorter HKDF inputs.
  if (out.length !== 32) {
    throw new Error(`X25519 shared secret length ${out.length} != 32`);
  }
  return out;
}

/**
 * Direction-aware per-pair keys (sharing §4.5).
 *
 * Both sides compute the same K_AB_to_B and K_AB_to_A from S_AB; the design
 * leaves the assignment of "who is A vs B" to the implementation. We use a
 * stable tiebreaker: the party with the lex-smaller `share_pub` is A
 * ("forward writer"); the lex-larger party is B ("reverse writer"). Each
 * caller passes `selfSharePub` and `peerSharePub` so we can compute the
 * tiebreaker locally and surface direction-aware {outbound, inbound} keys
 * from the caller's perspective:
 *
 *   - selfSharePub < peerSharePub → caller is A (forward)
 *     outbound = K_AB_to_B (forward HKDF)
 *     inbound  = K_AB_to_A (reverse HKDF)
 *   - selfSharePub > peerSharePub → caller is B (reverse)
 *     outbound = K_AB_to_A (reverse HKDF)
 *     inbound  = K_AB_to_B (forward HKDF)
 *
 * Net result: A's outbound bytes equal B's inbound bytes (same forward HKDF),
 * and B's outbound bytes equal A's inbound bytes (same reverse HKDF). Both
 * parties read what the other writes. (Lex-equal share_pubs would imply the
 * same X25519 keypair on both sides, which is a friend-with-self case the
 * handshake would never produce; we throw if it happens.)
 *
 * @param {{
 *   sharedSecret: Uint8Array,    // 32 bytes from deriveSharedSecret
 *   appId: string,
 *   selfSharePub: Uint8Array,    // 32 bytes — caller's share_pub
 *   peerSharePub: Uint8Array,    // 32 bytes — friend's share_pub
 * }} opts
 * @returns {Promise<{
 *   outboundKey: CryptoKey,
 *   inboundKey:  CryptoKey,
 *   outboundTagSeed: Uint8Array,
 *   inboundTagSeed:  Uint8Array,
 *   outboundKeyBytes: Uint8Array,
 *   inboundKeyBytes:  Uint8Array,
 *   role: 'forward' | 'reverse',
 * }>}
 */
export async function derivePairKeys({ sharedSecret, appId, selfSharePub, peerSharePub }) {
  assertU8(sharedSecret, 'sharedSecret', 32);
  assertU8(selfSharePub, 'selfSharePub', 32);
  assertU8(peerSharePub, 'peerSharePub', 32);
  if (!appId) throw new Error('appId is required');

  const cmp = compareBytes(selfSharePub, peerSharePub);
  if (cmp === 0) {
    throw new Error('derivePairKeys: selfSharePub == peerSharePub (cannot pair with self)');
  }
  const role = cmp < 0 ? 'forward' : 'reverse';

  // Derive both directed keys + tag seeds; we slot them into outbound/inbound
  // based on `role`. Using the SAME HKDF info on both sides means the bytes
  // are identical — only the role label differs.
  const [forwardKey, reverseKey, forwardTag, reverseTag] = await Promise.all([
    hkdfExpand32(sharedSecret, PURPOSE_KEY_FORWARD, appId),
    hkdfExpand32(sharedSecret, PURPOSE_KEY_REVERSE, appId),
    hkdfExpand32(sharedSecret, PURPOSE_TAG_FORWARD, appId),
    hkdfExpand32(sharedSecret, PURPOSE_TAG_REVERSE, appId),
  ]);

  const outboundKeyBytes  = role === 'forward' ? forwardKey : reverseKey;
  const inboundKeyBytes   = role === 'forward' ? reverseKey : forwardKey;
  const outboundTagSeed   = role === 'forward' ? forwardTag : reverseTag;
  const inboundTagSeed    = role === 'forward' ? reverseTag : forwardTag;

  const [outboundKey, inboundKey] = await Promise.all([
    crypto.subtle.importKey('raw', outboundKeyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', inboundKeyBytes,  { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']),
  ]);

  return {
    outboundKey, inboundKey,
    outboundTagSeed, inboundTagSeed,
    outboundKeyBytes, inboundKeyBytes,
    role,
  };
}

function compareBytes(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  if (a.length < b.length) return -1;
  if (a.length > b.length) return 1;
  return 0;
}

// ============ PER-ENTRY TAG DERIVATION (sharing §4.4) ============

/**
 * Derive a stealth-addressed Arweave tag for the entry at `seq` under a given
 * direction's tag seed.
 *
 *   log_tag(T_AB_seed, seq) = B(HMAC(T_AB_seed,
 *                                    "log_v1_" || encode_uint64(seq)))
 *
 * Output is base64url of 32 bytes (43 chars, matching the inbox tag format).
 * The HMAC seed never leaves the device — Tarn sees only the resulting
 * pseudorandom tag value.
 *
 * @param {Uint8Array} tagSeed - 32 raw bytes
 * @param {number} seq - non-negative integer
 * @returns {Promise<string>} 43-char base64url
 */
export async function deriveLogTag(tagSeed, seq) {
  assertU8(tagSeed, 'tagSeed', 32);
  assertSeq(seq);
  const hmacKey = await crypto.subtle.importKey(
    'raw', tagSeed, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const message = concatBytes(
    TEXT_ENCODER.encode(TAG_LABEL_PREFIX),
    encodeUint64BE(seq),
  );
  const out = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, message));
  return bytesToBase64Url(out);
}

// ============ JSON CANONICALIZATION (RFC 8785-ish) ============

/**
 * Deterministic JSON canonicalization for signature inputs (sharing §8.1).
 *
 * RFC 8785 (JCS) defines a canonical encoding: sort object keys
 * lexicographically by UTF-16 code units, recurse, no whitespace. We don't
 * pull in a dependency for this — the operation payloads are small and use
 * only ASCII keys + number/string/bool/array/object/null values. This
 * implementation:
 *
 *   - Object keys sorted by JS string compare (UTF-16 code units, same as
 *     `Array#sort()` default — which matches RFC 8785 for ASCII keys; all
 *     keys we emit are ASCII).
 *   - Nested objects + arrays canonicalized recursively.
 *   - Numbers serialized via `JSON.stringify` (base-10, no special forms).
 *   - Strings serialized via `JSON.stringify` (correctly escapes \", \\, \b,
 *     \f, \n, \r, \t, control chars, lone surrogates per ECMA-262).
 *   - `null`, `true`, `false` serialized verbatim.
 *   - `undefined`, functions, and other non-JSON values throw — matching the
 *     "values must be JSON-representable" precondition of RFC 8785.
 *   - Number rules: rejects NaN, ±Infinity (not representable in JSON);
 *     accepts integer + finite float (integers we emit fit in 2^53 — seq +
 *     timestamp).
 *
 * This is RFC 8785 *equivalent* for the value subset we emit. We do NOT
 * implement RFC 8785's I-JSON number canonicalization (which renormalizes
 * floats), because operations only contain integer numbers.
 *
 * @param {*} value - any JSON-representable value
 * @returns {string} canonical JSON string
 */
export function canonicalJSONStringify(value) {
  return canonicalize(value);
}

function canonicalize(v) {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  const t = typeof v;
  if (t === 'string') return JSON.stringify(v);
  if (t === 'number') {
    if (!Number.isFinite(v)) {
      throw new Error(`canonicalJSONStringify: ${v} is not JSON-representable`);
    }
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) {
    return '[' + v.map(canonicalize).join(',') + ']';
  }
  if (t === 'object') {
    const keys = Object.keys(v).sort();
    const parts = [];
    for (const k of keys) {
      const child = v[k];
      if (child === undefined) continue; // RFC 8785: drop undefined entries
      parts.push(JSON.stringify(k) + ':' + canonicalize(child));
    }
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`canonicalJSONStringify: unsupported type ${t}`);
}

/**
 * Convenience: canonical bytes (UTF-8) of a value. The signer uses
 * H(canonical_bytes(operation_unsigned)) per §8.1, and the verifier recomputes
 * the same bytes from the parsed JSON.
 *
 * @param {*} value
 * @returns {Uint8Array}
 */
export function canonicalJSONBytes(value) {
  return TEXT_ENCODER.encode(canonicalJSONStringify(value));
}

// ============ OPERATION CONSTRUCTION + VALIDATION (sharing §8.3) ============

/**
 * Build an unsigned operation object — a plain JS object with a `type`, a
 * `seq`, and the operation-specific fields. The signature is added by
 * {@link signOperation}.
 *
 * Validates that the operation-specific fields are present and well-shaped.
 * Throws on malformed inputs; this is a public-but-semi-internal helper, so
 * "throw on bad input from the SDK caller" is the right surface.
 *
 * @param {{type: string, seq: number, [key: string]: any}} fields
 * @returns {{type: string, seq: number, [key: string]: any}}
 */
export function buildOperationUnsigned(fields) {
  if (!fields || typeof fields !== 'object') {
    throw new Error('buildOperationUnsigned: fields must be an object');
  }
  const { type, seq } = fields;
  if (!KNOWN_OP_TYPES.has(type)) {
    throw new Error(`buildOperationUnsigned: unknown operation type ${type}`);
  }
  assertSeq(seq);
  switch (type) {
    case OP_ADD:
      requireString(fields.content_id, 'content_id');
      requireString(fields.tx_id, 'tx_id');
      requireBase64UrlBytes(fields.cek, 'cek', 32);
      requireUnixSeconds(fields.shared_at, 'shared_at');
      break;
    case OP_UPDATE:
      requireString(fields.content_id, 'content_id');
      requireString(fields.tx_id, 'tx_id');
      requireUnixSeconds(fields.updated_at, 'updated_at');
      break;
    case OP_ROTATE:
      requireString(fields.content_id, 'content_id');
      requireBase64UrlBytes(fields.cek, 'cek', 32);
      requireUnixSeconds(fields.rotated_at, 'rotated_at');
      break;
    case OP_REMOVE:
      requireString(fields.content_id, 'content_id');
      requireUnixSeconds(fields.removed_at, 'removed_at');
      break;
    case OP_SNAPSHOT:
      requireSnapshotState(fields.state);
      requireUnixSeconds(fields.snapshot_at, 'snapshot_at');
      requirePriorSeq(fields.prior_seq);
      break;
    case OP_ROTATE_IDENTITY:
      // 5b recognizes the type for forward-compat parsing only — we don't emit
      // it here. Validation is "permissive but typed" so a 5d-emitted entry
      // round-trips through buildOperationUnsigned cleanly.
      requireBase64UrlBytes(fields.new_share_pub, 'new_share_pub', 32);
      requireString(fields.new_signing_pub, 'new_signing_pub');
      requireUnixSeconds(fields.rotated_at, 'rotated_at');
      break;
    default:
      throw new Error(`buildOperationUnsigned: unhandled type ${type}`);
  }
  // Return a fresh shallow clone with the well-known fields only — drops any
  // extraneous caller-provided keys so the canonical signature input is
  // predictable. (Future versions can add fields; old verifiers will skip
  // them since the canonical-bytes input bakes only the present fields.)
  const out = { type, seq };
  copyKnownFieldsByType(out, fields, type);
  return out;
}

function copyKnownFieldsByType(out, src, type) {
  switch (type) {
    case OP_ADD:
      out.content_id = src.content_id;
      out.tx_id = src.tx_id;
      out.cek = src.cek;
      out.shared_at = src.shared_at;
      break;
    case OP_UPDATE:
      out.content_id = src.content_id;
      out.tx_id = src.tx_id;
      out.updated_at = src.updated_at;
      break;
    case OP_ROTATE:
      out.content_id = src.content_id;
      out.cek = src.cek;
      out.rotated_at = src.rotated_at;
      break;
    case OP_REMOVE:
      out.content_id = src.content_id;
      out.removed_at = src.removed_at;
      break;
    case OP_SNAPSHOT:
      out.state = canonicalSnapshotState(src.state);
      out.snapshot_at = src.snapshot_at;
      out.prior_seq = src.prior_seq ?? null;
      break;
    case OP_ROTATE_IDENTITY:
      out.new_share_pub = src.new_share_pub;
      out.new_signing_pub = src.new_signing_pub;
      out.rotated_at = src.rotated_at;
      break;
  }
}

function canonicalSnapshotState(state) {
  // Make sure the state object only contains the {tx_id, cek} shape we expect;
  // strip extraneous keys per content_id so a future-version field doesn't
  // accidentally end up in the signed bytes.
  const out = {};
  for (const [contentId, entry] of Object.entries(state)) {
    out[contentId] = { tx_id: entry.tx_id, cek: entry.cek };
  }
  return out;
}

function requireString(v, name) {
  if (typeof v !== 'string' || v.length === 0) {
    throw new Error(`${name} must be a non-empty string`);
  }
}

function requireUnixSeconds(v, name) {
  if (!Number.isInteger(v) || v < 0) {
    throw new Error(`${name} must be a non-negative integer (unix seconds)`);
  }
}

function requirePriorSeq(v) {
  if (v === null || v === undefined) return;
  if (!Number.isInteger(v) || v < 0) {
    throw new Error('prior_seq must be a non-negative integer or null');
  }
}

function requireBase64UrlBytes(v, name, expectedLen) {
  if (typeof v !== 'string' || v.length === 0) {
    throw new Error(`${name} must be a non-empty base64url string`);
  }
  let bytes;
  try { bytes = base64UrlToBytes(v); } catch {
    throw new Error(`${name} is not valid base64url`);
  }
  if (expectedLen != null && bytes.length !== expectedLen) {
    throw new Error(`${name} must decode to ${expectedLen} bytes, got ${bytes.length}`);
  }
}

function requireSnapshotState(state) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    throw new Error('snapshot.state must be an object');
  }
  for (const [contentId, entry] of Object.entries(state)) {
    if (!contentId) throw new Error('snapshot.state: empty content_id');
    if (!entry || typeof entry !== 'object') {
      throw new Error(`snapshot.state["${contentId}"] must be an object`);
    }
    requireString(entry.tx_id, `snapshot.state["${contentId}"].tx_id`);
    requireBase64UrlBytes(entry.cek, `snapshot.state["${contentId}"].cek`, 32);
  }
}

// ============ SIGNATURE CONSTRUCTION + VERIFICATION (sharing §8.1) ============

/**
 * Compute the signature input bytes per §8.1:
 *
 *   sig_input = "tarn-share-log-v1-sig" || encode_uint64(seq) ||
 *               H(canonical_bytes(operation_unsigned))
 *
 * Used both by signers (to feed `signature = ECDSA_P256_Sign(...)`) and by
 * verifiers (to recompute the same bytes for `crypto.subtle.verify`).
 *
 * @param {{seq: number}} operationUnsigned
 * @returns {Promise<Uint8Array>}
 */
export async function computeSigInput(operationUnsigned) {
  const seq = operationUnsigned?.seq;
  assertSeq(seq);
  const canonical = canonicalJSONBytes(operationUnsigned);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', canonical));
  return concatBytes(
    TEXT_ENCODER.encode(SHARE_LOG_SIG_PREFIX),
    encodeUint64BE(seq),
    digest,
  );
}

/**
 * Sign an unsigned operation with the sender's existing ECDSA P-256 signing
 * key. Returns the operation_signed object (deep clone with `signature`
 * appended). The signing key is the same one already used for Tarn auth
 * challenges — no new key material per the design.
 *
 * @param {Object} operationUnsigned
 * @param {CryptoKey} signingPrivateKey - ECDSA P-256 private key
 * @returns {Promise<Object>} operation_signed = operation_unsigned + {signature}
 */
export async function signOperation(operationUnsigned, signingPrivateKey) {
  const sigInput = await computeSigInput(operationUnsigned);
  const sigRaw = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, signingPrivateKey, sigInput,
  ));
  return { ...operationUnsigned, signature: bytesToBase64Url(sigRaw) };
}

/**
 * Verify the signature on a parsed `operation_signed` against the sender's
 * cached public key. Returns true on valid, false on any failure (parse,
 * key import, AEAD-side verify failure, etc.) — never throws.
 *
 * @param {Object} operationSigned - the parsed JSON from a decrypted entry
 * @param {string} senderSigningPubBase64 - the signing_pub from the friends
 *   record (existing Tarn ECDSA P-256 SPKI in standard base64).
 * @returns {Promise<boolean>}
 */
export async function verifyOperationSignature(operationSigned, senderSigningPubBase64) {
  if (!operationSigned || typeof operationSigned !== 'object') return false;
  if (typeof operationSigned.signature !== 'string') return false;

  let signatureBytes;
  try { signatureBytes = base64UrlToBytes(operationSigned.signature); } catch {
    return false;
  }

  const operationUnsigned = { ...operationSigned };
  delete operationUnsigned.signature;

  let sigInput;
  try { sigInput = await computeSigInput(operationUnsigned); } catch {
    return false;
  }

  let pubKey;
  try {
    pubKey = await importEcdsaP256SpkiBase64(senderSigningPubBase64);
  } catch {
    return false;
  }

  try {
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      pubKey,
      signatureBytes,
      sigInput,
    );
  } catch {
    return false;
  }
}

async function importEcdsaP256SpkiBase64(b64) {
  // The friends record stores `signing_pub` as standard base64 (matches the
  // existing exportPublicKey output in crypto.js). Decode tolerantly to allow
  // base64url too in case a caller hands us one.
  const padded = b64.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - (padded.length % 4)) % 4;
  const bin = atob(padded + '='.repeat(pad));
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  return await crypto.subtle.importKey(
    'spki', der, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'],
  );
}

// ============ ENTRY ENCRYPT / DECRYPT (sharing §8.1) ============

/**
 * Encrypt a signed operation under K_AB.
 *
 *   iv = random_bytes(12)
 *   ct_and_tag = AES-GCM-Encrypt(K_AB, iv, JSON(operation_signed),
 *                                 aad="tarn-share-log-v1")
 *   entry_blob = iv || ct_and_tag
 *
 * @param {Object} operationSigned
 * @param {CryptoKey} outboundKey - AES-256-GCM key (K_AB outbound direction)
 * @returns {Promise<Uint8Array>} entry blob
 */
export async function encryptShareLogEntry(operationSigned, outboundKey) {
  const plaintext = TEXT_ENCODER.encode(JSON.stringify(operationSigned));
  if (plaintext.length > MAX_LOG_BLOB_PLAINTEXT_BYTES) {
    throw new Error(
      `share-log entry plaintext exceeds ${MAX_LOG_BLOB_PLAINTEXT_BYTES} bytes`,
    );
  }
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: TEXT_ENCODER.encode(SHARE_LOG_AAD),
    },
    outboundKey,
    plaintext,
  ));
  return concatBytes(iv, ct);
}

/**
 * Decrypt an entry blob with the inbound K_AB. Returns the parsed JSON
 * operation_signed object, or throws if decryption / JSON parse fails.
 *
 * Signature verification is the caller's responsibility (use
 * {@link verifyOperationSignature}). Decoupled because callers may want to
 * surface the parsed operation even when verification fails (e.g., logging),
 * but should NEVER apply an operation without verifying first.
 *
 * @param {Uint8Array} blob
 * @param {CryptoKey} inboundKey
 * @returns {Promise<Object>}
 */
export async function decryptShareLogEntry(blob, inboundKey) {
  if (!(blob instanceof Uint8Array)) {
    throw new Error('blob must be a Uint8Array');
  }
  if (blob.length < IV_LEN + GCM_TAG_LEN) {
    throw new Error('blob too short to be a share-log entry');
  }
  const iv = blob.slice(0, IV_LEN);
  const ct = blob.slice(IV_LEN);
  const ptBuf = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: TEXT_ENCODER.encode(SHARE_LOG_AAD),
    },
    inboundKey,
    ct,
  );
  const text = TEXT_DECODER.decode(new Uint8Array(ptBuf));
  return JSON.parse(text);
}

// ============ COMPACTION POLICY (sharing §8.6) ============

/**
 * Decide whether a writer should emit a snapshot at the next seq, given the
 * current outbound counters. Pure decision function — the caller (a TarnClient
 * publish helper) drives the actual snapshot construction.
 *
 * Policy: emit a snapshot when the count of NON-snapshot operations since the
 * last snapshot reaches `compactionInterval` (default: 100). Snapshots
 * themselves consume a seq slot but do not count toward the next compaction
 * (matching §8.6: snapshots are regular log entries that bound bootstrap cost,
 * not a separate stream).
 *
 * @param {{
 *   nonSnapshotsSinceLastSnapshot: number,
 *   compactionInterval?: number,
 * }} state
 * @returns {boolean}
 */
export function shouldEmitSnapshot(state) {
  const interval = state.compactionInterval ?? DEFAULT_COMPACTION_INTERVAL;
  if (!Number.isInteger(interval) || interval < 1) {
    throw new Error('compactionInterval must be a positive integer');
  }
  return (state.nonSnapshotsSinceLastSnapshot ?? 0) >= interval;
}

// ============ HIGHEST-SEQ DISCOVERY (sharing §9.2) ============

// Cap on the exponential phase. With doubling, 64 hits cover seq up to 2^63 —
// far beyond any realistic share-log size. The cap mostly defends against a
// runaway probe loop if `probe` lies (always returns true), and gives tests a
// way to assert logarithmic probe count.
const DEFAULT_MAX_EXPONENTIAL_PROBES = 64;

/**
 * Walk a per-pair share log forward to find the highest existing seq, using
 * O(log N) tag probes. The caller supplies a `probe(seq) -> Promise<boolean>`
 * function — typically a thin wrapper over `GET /share/log/fetch` for the
 * specific tag derived from a (T_AB_seed, seq) pair. The tag seed itself
 * never crosses this boundary, matching the design's "no per-pair prefix
 * sent to Tarn" property.
 *
 * Algorithm (sharing §9.2):
 *   1. Exponential probe starting at `anchor`, with stride 1 doubling each
 *      hit: probe(anchor), probe(anchor+1), probe(anchor+3), probe(anchor+7),
 *      ... until first miss.
 *   2. Bisect the interval [lastHit + 1, firstMiss - 1] — the highest seq
 *      that exists is the largest seq in that range that probes true.
 *
 * Returns `{ highestSeq, probeCount }`:
 *   - `highestSeq` is `anchor - 1` if no seq >= anchor exists (i.e. the very
 *     first probe missed).
 *   - `highestSeq` is the largest seq that probes true otherwise.
 *   - `probeCount` is the total number of probe(seq) calls made — useful for
 *     tests that assert logarithmic behavior.
 *
 * For the typical bootstrap call (anchor=1) on a log of size N, total probes
 * are ~ 2*log2(N). For an incremental-sync call (anchor=lastSeqSeen+1) over
 * a gap of G new entries, total probes are ~ 2*log2(G).
 *
 * @param {{
 *   probe: (seq: number) => Promise<boolean>,
 *   anchor?: number,                    // lowest seq to consider (default 1)
 *   maxExponentialProbes?: number,      // safety cap on phase 1
 * }} opts
 * @returns {Promise<{ highestSeq: number, probeCount: number }>}
 */
export async function discoverHighestSeq({
  probe,
  anchor = 1,
  maxExponentialProbes = DEFAULT_MAX_EXPONENTIAL_PROBES,
} = {}) {
  if (typeof probe !== 'function') {
    throw new Error('discoverHighestSeq: probe must be a function');
  }
  if (!Number.isInteger(anchor) || anchor < 0) {
    throw new Error('discoverHighestSeq: anchor must be a non-negative integer');
  }
  if (!Number.isInteger(maxExponentialProbes) || maxExponentialProbes < 1) {
    throw new Error('discoverHighestSeq: maxExponentialProbes must be a positive integer');
  }

  let lastHit = anchor - 1;
  let firstMiss = -1;
  let probeCount = 0;
  let candidate = anchor;
  let stride = 1;

  for (let i = 0; i < maxExponentialProbes; i++) {
    probeCount++;
    if (await probe(candidate)) {
      lastHit = candidate;
      candidate += stride;
      stride *= 2;
    } else {
      firstMiss = candidate;
      break;
    }
  }

  // Empty case: anchor itself missed → no seq >= anchor exists.
  if (lastHit < anchor) {
    return { highestSeq: anchor - 1, probeCount };
  }

  // Saturation case: hit the cap with no miss. Treat lastHit as best-effort
  // floor; readers will at least see up to that seq. Practically this only
  // happens when probe is mocked or the log is impossibly large.
  if (firstMiss < 0) {
    return { highestSeq: lastHit, probeCount, truncated: true };
  }

  // Bisect [lastHit + 1, firstMiss - 1]. Loop invariant:
  //   probe(lo) is known true, probe(hi) is known false, and we want the
  //   greatest seq < hi that probes true.
  let lo = lastHit;
  let hi = firstMiss;
  while (hi - lo > 1) {
    const mid = lo + Math.floor((hi - lo) / 2);
    probeCount++;
    if (await probe(mid)) lo = mid;
    else hi = mid;
  }
  return { highestSeq: lo, probeCount };
}

// ============ STATE MACHINE (sharing §8.4) ============

/**
 * Apply a single (parsed) operation to a state map in place, per the
 * idempotency rules of §8.4. State is `{ content_id: { tx_id, cek } }`. The
 * caller is responsible for verifying the sender signature first
 * ({@link verifyOperationSignature}); operations that fail verification or
 * decryption MUST be skipped at the call site, not passed to this function.
 *
 * Idempotency rules (§8.4):
 *   - `add` for a known content_id → treat as `update` with the supplied
 *     tx_id; if the cek differs, log an error and adopt the new cek
 *     (defensive — should not occur in normal flow).
 *   - `update` for an unknown content_id → log warning, no-op.
 *   - `rotate` for an unknown content_id → log warning, no-op.
 *   - `remove` for an unknown content_id → silent no-op.
 *   - `snapshot` → replace state wholesale.
 *   - `rotate_identity` → recognized but no-op for now (5d will add the
 *     actual processing). Treat as a state-preserving operation.
 *   - Unknown types → log warning, no-op.
 *
 * Replay safety: repeated application of the same operation produces the
 * same final state. Reordering can produce a defensible result
 * (`update`-before-`add` warns and is dropped; `remove`-then-`add` returns
 * to "added" state).
 *
 * @param {Object} state - mutated in place
 * @param {Object} operation - parsed operation_signed (or operation_unsigned)
 * @param {{
 *   onWarn?: (msg: string) => void,
 *   onError?: (msg: string) => void,
 * }} [hooks]
 */
export function applyOperationToState(state, operation, hooks = {}) {
  const warn = hooks.onWarn ?? defaultWarn;
  const error = hooks.onError ?? defaultError;

  if (!state || typeof state !== 'object') {
    throw new Error('applyOperationToState: state must be an object');
  }
  if (!operation || typeof operation !== 'object') {
    throw new Error('applyOperationToState: operation must be an object');
  }

  switch (operation.type) {
    case OP_ADD: {
      const cid = operation.content_id;
      if (state[cid]) {
        // §8.4: treat as update with supplied tx_id; if cek differs, log
        // error and adopt new cek defensively.
        if (state[cid].cek !== operation.cek) {
          error(`share-log: add for known content_id ${cid} with different CEK; adopting new CEK`);
        }
        state[cid] = { tx_id: operation.tx_id, cek: operation.cek };
      } else {
        state[cid] = { tx_id: operation.tx_id, cek: operation.cek };
      }
      return;
    }
    case OP_UPDATE: {
      const cid = operation.content_id;
      if (!state[cid]) {
        warn(`share-log: update for unknown content_id ${cid}; ignoring`);
        return;
      }
      state[cid] = { tx_id: operation.tx_id, cek: state[cid].cek };
      return;
    }
    case OP_ROTATE: {
      const cid = operation.content_id;
      if (!state[cid]) {
        warn(`share-log: rotate for unknown content_id ${cid}; ignoring`);
        return;
      }
      state[cid] = { tx_id: state[cid].tx_id, cek: operation.cek };
      return;
    }
    case OP_REMOVE: {
      delete state[operation.content_id];
      return;
    }
    case OP_SNAPSHOT: {
      for (const k of Object.keys(state)) delete state[k];
      const snap = operation.state || {};
      for (const [cid, entry] of Object.entries(snap)) {
        state[cid] = { tx_id: entry.tx_id, cek: entry.cek };
      }
      return;
    }
    case OP_ROTATE_IDENTITY: {
      // §13.5 / 5d: parsing-only no-op for now. Recognized so the read flow
      // doesn't warn on encountering one in a long log.
      return;
    }
    default:
      warn(`share-log: unknown operation type ${operation.type}; ignoring`);
  }
}

function defaultWarn(msg) { console.warn(`[share-log] ${msg}`); }
function defaultError(msg) { console.error(`[share-log] ${msg}`); }

/**
 * Apply a sequence of operations in order, returning a fresh state map.
 * Convenience wrapper around {@link applyOperationToState}.
 *
 * @param {Array<Object>} operations
 * @param {Object} [initialState] - default {}
 * @param {{ onWarn?: Function, onError?: Function }} [hooks]
 * @returns {Object}
 */
export function replayOperations(operations, initialState = {}, hooks = {}) {
  const state = { ...initialState };
  for (const op of operations) {
    applyOperationToState(state, op, hooks);
  }
  return state;
}
