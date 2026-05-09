/**
 * Per-pair share-log primitives — borrowed verbatim from
 * `client/src/share-log.ts` (Phase 5).
 *
 * The original module is a pure WebCrypto + `@noble/curves` implementation
 * with no `TarnClient` coupling, so the bytes-for-bytes copy here keeps the
 * recover package self-contained without re-importing the live SDK. The
 * cross-validation tests in `tests/sharing-cross-validate.test.ts` enforce
 * byte-equality with the client-side originals so the two copies cannot
 * drift.
 *
 * What's exported (the read-side surface — the only piece the recover
 * package consumes; encrypt is included for symmetry and so test fixtures
 * can mint synthetic entries without re-implementing the wire format):
 *
 *   - `deriveSharedSecret`  — X25519 ECDH
 *   - `derivePairKeys`      — direction-aware K_AB / T_AB_seed via HKDF
 *   - `deriveLogTag`        — stealth tag derivation per `(seed, seq)`
 *   - `decryptShareLogEntry` / `encryptShareLogEntry` — AES-256-GCM seal/open
 *   - `verifyOperationSignature` — ECDSA P-256 signature verification
 *   - `discoverHighestSeq`  — O(log N) probe walk
 *   - `applyOperationToState` / `replayOperations` — state-machine
 *   - operation-type constants (`OP_ADD` ... `OP_ROTATE_IDENTITY`)
 *
 * See `docs/TARN_PROTOCOL.md` §sharing for the on-the-wire definition.
 */

import { x25519 } from '@noble/curves/ed25519';
import { bytesToBase64Url, base64UrlToBytes } from '../crypto/encoding.js';

// ============ CONSTANTS ============

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

const SHARE_LOG_AAD = 'tarn-share-log-v1';
const SHARE_LOG_SIG_PREFIX = 'tarn-share-log-v1-sig';
const TAG_LABEL_PREFIX = 'log_v1_';

const PROTOCOL_ID = 'tarn';
const DERIVATION_VERSION = '1';
const HKDF_COUNTER_BYTE = 0x01;
const PURPOSE_KEY_FORWARD = 'share-key';
const PURPOSE_KEY_REVERSE = 'share-key-rev';
const PURPOSE_TAG_FORWARD = 'share-tag';
const PURPOSE_TAG_REVERSE = 'share-tag-rev';

const IV_LEN = 12;
const GCM_TAG_LEN = 16;

export const OP_ADD             = 'add' as const;
export const OP_UPDATE          = 'update' as const;
export const OP_ROTATE          = 'rotate' as const;
export const OP_REMOVE          = 'remove' as const;
export const OP_SNAPSHOT        = 'snapshot' as const;
export const OP_ROTATE_IDENTITY = 'rotate_identity' as const;

export type OpType =
  | typeof OP_ADD
  | typeof OP_UPDATE
  | typeof OP_ROTATE
  | typeof OP_REMOVE
  | typeof OP_SNAPSHOT
  | typeof OP_ROTATE_IDENTITY;

export const KNOWN_OP_TYPES: ReadonlySet<OpType> = new Set<OpType>([
  OP_ADD, OP_UPDATE, OP_ROTATE, OP_REMOVE, OP_SNAPSHOT, OP_ROTATE_IDENTITY,
]);

export const SHARE_LOG_TYPE = 'share-log-v1';

export const MAX_LOG_BLOB_PLAINTEXT_BYTES = 256 * 1024;

// ============ WebCrypto BufferSource cast ============

function bs(b: ArrayBufferView | ArrayBuffer): BufferSource {
  return b as BufferSource;
}

// ============ ENCODING HELPERS ============

function encodeUint64BE(n: number): Uint8Array {
  const buf = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
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

function assertU8(b: unknown, name: string, expectedLen?: number): asserts b is Uint8Array {
  if (!(b instanceof Uint8Array)) throw new Error(`${name} must be a Uint8Array`);
  if (expectedLen != null && b.length !== expectedLen) {
    throw new Error(`${name} must be ${expectedLen} bytes, got ${b.length}`);
  }
}

function assertSeq(seq: unknown): asserts seq is number {
  if (!Number.isInteger(seq) || (seq as number) < 0) {
    throw new Error(`seq must be a non-negative integer, got ${String(seq)}`);
  }
}

// ============ HKDF-EXPAND (single block, 32 bytes) ============

async function hkdfExpand32(prk: Uint8Array, purpose: string, appId: string): Promise<Uint8Array> {
  assertU8(prk, 'prk', 32);
  if (!purpose) throw new Error('purpose is required');
  if (!appId) throw new Error('appId is required');
  const hmacKey = await crypto.subtle.importKey(
    'raw', bs(prk), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const info = concatBytes(
    TEXT_ENCODER.encode(PROTOCOL_ID + purpose + appId + DERIVATION_VERSION),
    new Uint8Array([HKDF_COUNTER_BYTE]),
  );
  const sig = await crypto.subtle.sign('HMAC', hmacKey, bs(info));
  return new Uint8Array(sig);
}

// ============ PER-PAIR KEY DERIVATION (sharing §4.2–§4.5) ============

/** Per-pair shared secret S_AB = ECDH_X25519(share_priv, peer_share_pub). */
export function deriveSharedSecret(sharePriv: Uint8Array, peerSharePub: Uint8Array): Uint8Array {
  assertU8(sharePriv, 'sharePriv', 32);
  assertU8(peerSharePub, 'peerSharePub', 32);
  const out = x25519.getSharedSecret(sharePriv, peerSharePub);
  if (out.length !== 32) {
    throw new Error(`X25519 shared secret length ${out.length} != 32`);
  }
  return out;
}

export type DerivePairKeysOpts = {
  sharedSecret: Uint8Array;
  appId: string;
  selfSharePub: Uint8Array;
  peerSharePub: Uint8Array;
};

export type PairKeys = {
  outboundKey: CryptoKey;
  inboundKey: CryptoKey;
  outboundTagSeed: Uint8Array;
  inboundTagSeed: Uint8Array;
  outboundKeyBytes: Uint8Array;
  inboundKeyBytes: Uint8Array;
  role: 'forward' | 'reverse';
};

/**
 * Direction-aware per-pair keys (sharing §4.5). Both sides compute identical
 * bytes from the same `sharedSecret`; lex-sort of share_pubs assigns who
 * uses the forward vs. reverse HKDF info string for outbound/inbound.
 */
export async function derivePairKeys(opts: DerivePairKeysOpts): Promise<PairKeys> {
  const { sharedSecret, appId, selfSharePub, peerSharePub } = opts;
  assertU8(sharedSecret, 'sharedSecret', 32);
  assertU8(selfSharePub, 'selfSharePub', 32);
  assertU8(peerSharePub, 'peerSharePub', 32);
  if (!appId) throw new Error('appId is required');

  const cmp = compareBytes(selfSharePub, peerSharePub);
  if (cmp === 0) {
    throw new Error('derivePairKeys: selfSharePub == peerSharePub (cannot pair with self)');
  }
  const role: 'forward' | 'reverse' = cmp < 0 ? 'forward' : 'reverse';

  const [forwardKey, reverseKey, forwardTag, reverseTag] = await Promise.all([
    hkdfExpand32(sharedSecret, PURPOSE_KEY_FORWARD, appId),
    hkdfExpand32(sharedSecret, PURPOSE_KEY_REVERSE, appId),
    hkdfExpand32(sharedSecret, PURPOSE_TAG_FORWARD, appId),
    hkdfExpand32(sharedSecret, PURPOSE_TAG_REVERSE, appId),
  ]);

  const outboundKeyBytes = role === 'forward' ? forwardKey : reverseKey;
  const inboundKeyBytes  = role === 'forward' ? reverseKey : forwardKey;
  const outboundTagSeed  = role === 'forward' ? forwardTag : reverseTag;
  const inboundTagSeed   = role === 'forward' ? reverseTag : forwardTag;

  const [outboundKey, inboundKey] = await Promise.all([
    crypto.subtle.importKey('raw', bs(outboundKeyBytes), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', bs(inboundKeyBytes),  { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']),
  ]);

  return {
    outboundKey, inboundKey,
    outboundTagSeed, inboundTagSeed,
    outboundKeyBytes, inboundKeyBytes,
    role,
  };
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const ai = a[i]!;
    const bi = b[i]!;
    if (ai < bi) return -1;
    if (ai > bi) return 1;
  }
  if (a.length < b.length) return -1;
  if (a.length > b.length) return 1;
  return 0;
}

// ============ PER-ENTRY TAG DERIVATION (sharing §4.4) ============

/** Derive a stealth-addressed Arweave tag for the entry at `seq`. Returns 43-char base64url. */
export async function deriveLogTag(tagSeed: Uint8Array, seq: number): Promise<string> {
  assertU8(tagSeed, 'tagSeed', 32);
  assertSeq(seq);
  const hmacKey = await crypto.subtle.importKey(
    'raw', bs(tagSeed), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const message = concatBytes(
    TEXT_ENCODER.encode(TAG_LABEL_PREFIX),
    encodeUint64BE(seq),
  );
  const out = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, bs(message)));
  return bytesToBase64Url(out);
}

// ============ JSON CANONICALIZATION (RFC 8785-ish) ============

export function canonicalJSONStringify(value: unknown): string {
  return canonicalize(value);
}

function canonicalize(v: unknown): string {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  const t = typeof v;
  if (t === 'string') return JSON.stringify(v);
  if (t === 'number') {
    if (!Number.isFinite(v)) {
      throw new Error(`canonicalJSONStringify: ${String(v)} is not JSON-representable`);
    }
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) {
    return '[' + v.map(canonicalize).join(',') + ']';
  }
  if (t === 'object') {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const child = obj[k];
      if (child === undefined) continue; // RFC 8785: drop undefined entries
      parts.push(JSON.stringify(k) + ':' + canonicalize(child));
    }
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`canonicalJSONStringify: unsupported type ${t}`);
}

export function canonicalJSONBytes(value: unknown): Uint8Array {
  return TEXT_ENCODER.encode(canonicalJSONStringify(value));
}

// ============ OPERATION SHAPES (sharing §8.3) ============

export type OpAddFields = {
  type: typeof OP_ADD;
  seq: number;
  content_id: string;
  tx_id: string;
  cek: string;        // base64url, 32 bytes
  shared_at: number;  // unix seconds
};

export type OpUpdateFields = {
  type: typeof OP_UPDATE;
  seq: number;
  content_id: string;
  tx_id: string;
  updated_at: number;
};

export type OpRotateFields = {
  type: typeof OP_ROTATE;
  seq: number;
  content_id: string;
  cek: string;
  rotated_at: number;
};

export type OpRemoveFields = {
  type: typeof OP_REMOVE;
  seq: number;
  content_id: string;
  removed_at: number;
};

export type SnapshotState = Record<string, { tx_id: string; cek: string }>;

export type OpSnapshotFields = {
  type: typeof OP_SNAPSHOT;
  seq: number;
  state: SnapshotState;
  snapshot_at: number;
  prior_seq: number | null;
};

export type OpRotateIdentityFields = {
  type: typeof OP_ROTATE_IDENTITY;
  seq: number;
  new_share_pub: string;
  new_signing_pub: string;
  new_credential_lookup_key: string;
  rotated_at: number;
};

export type OperationUnsigned =
  | OpAddFields
  | OpUpdateFields
  | OpRotateFields
  | OpRemoveFields
  | OpSnapshotFields
  | OpRotateIdentityFields;

export type OperationSigned = OperationUnsigned & { signature: string };

// ============ SIGNATURE CONSTRUCTION + VERIFICATION (sharing §8.1) ============

/** Compute the signature input bytes per §8.1. */
export async function computeSigInput(operationUnsigned: { seq: number }): Promise<Uint8Array> {
  const seq = operationUnsigned?.seq;
  assertSeq(seq);
  const canonical = canonicalJSONBytes(operationUnsigned);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bs(canonical)));
  return concatBytes(
    TEXT_ENCODER.encode(SHARE_LOG_SIG_PREFIX),
    encodeUint64BE(seq),
    digest,
  );
}

/** Sign an unsigned operation with the sender's existing ECDSA P-256 signing key. */
export async function signOperation(
  operationUnsigned: OperationUnsigned,
  signingPrivateKey: CryptoKey,
): Promise<OperationSigned> {
  const sigInput = await computeSigInput(operationUnsigned);
  const sigRaw = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, signingPrivateKey, bs(sigInput),
  ));
  return { ...operationUnsigned, signature: bytesToBase64Url(sigRaw) };
}

/**
 * Verify the signature on a parsed `operation_signed` against the sender's
 * cached public key. Returns true on valid, false on any failure — never throws.
 */
export async function verifyOperationSignature(
  operationSigned: unknown,
  senderSigningPubBase64: string,
): Promise<boolean> {
  if (!operationSigned || typeof operationSigned !== 'object') return false;
  const op = operationSigned as Record<string, unknown>;
  if (typeof op['signature'] !== 'string') return false;

  let signatureBytes: Uint8Array;
  try { signatureBytes = base64UrlToBytes(op['signature'] as string); } catch {
    return false;
  }

  const operationUnsigned: Record<string, unknown> = { ...op };
  delete operationUnsigned['signature'];

  let sigInput: Uint8Array;
  try {
    sigInput = await computeSigInput(operationUnsigned as { seq: number });
  } catch {
    return false;
  }

  let pubKey: CryptoKey;
  try {
    pubKey = await importEcdsaP256SpkiBase64(senderSigningPubBase64);
  } catch {
    return false;
  }

  try {
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      pubKey,
      bs(signatureBytes),
      bs(sigInput),
    );
  } catch {
    return false;
  }
}

async function importEcdsaP256SpkiBase64(b64: string): Promise<CryptoKey> {
  const padded = b64.replace(/-/g, '+').replace(/_/g, '/');
  const pad = (4 - (padded.length % 4)) % 4;
  const bin = atob(padded + '='.repeat(pad));
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  return await crypto.subtle.importKey(
    'spki', bs(der), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'],
  );
}

// ============ ENTRY ENCRYPT / DECRYPT (sharing §8.1) ============

/** Encrypt a signed operation under K_AB. Wire: iv || ct_and_tag, AAD "tarn-share-log-v1". */
export async function encryptShareLogEntry(operationSigned: OperationSigned, outboundKey: CryptoKey): Promise<Uint8Array> {
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
      iv: bs(iv),
      additionalData: bs(TEXT_ENCODER.encode(SHARE_LOG_AAD)),
    },
    outboundKey,
    bs(plaintext),
  ));
  return concatBytes(iv, ct);
}

/** Decrypt an entry blob with the inbound K_AB. */
export async function decryptShareLogEntry(blob: Uint8Array, inboundKey: CryptoKey): Promise<unknown> {
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
      iv: bs(iv),
      additionalData: bs(TEXT_ENCODER.encode(SHARE_LOG_AAD)),
    },
    inboundKey,
    bs(ct),
  );
  const text = TEXT_DECODER.decode(new Uint8Array(ptBuf));
  return JSON.parse(text);
}

// ============ HIGHEST-SEQ DISCOVERY (sharing §9.2) ============

const DEFAULT_MAX_EXPONENTIAL_PROBES = 64;

export type DiscoverHighestSeqOpts = {
  probe: (seq: number) => Promise<boolean>;
  anchor?: number;
  maxExponentialProbes?: number;
};

export type DiscoverHighestSeqResult = {
  highestSeq: number;
  probeCount: number;
  truncated?: boolean;
};

/**
 * Walk a per-pair share log forward to find the highest existing seq, using
 * O(log N) tag probes. The probe callback decides "is there a blob at this
 * seq?" — for the recover client, that's a GraphQL existence check by the
 * stealth tag, so latency is dominated by gateway round trips.
 */
export async function discoverHighestSeq(opts: DiscoverHighestSeqOpts): Promise<DiscoverHighestSeqResult> {
  const {
    probe,
    anchor = 1,
    maxExponentialProbes = DEFAULT_MAX_EXPONENTIAL_PROBES,
  } = opts;

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

  // Saturation case: hit the cap with no miss.
  if (firstMiss < 0) {
    return { highestSeq: lastHit, probeCount, truncated: true };
  }

  // Bisect [lastHit + 1, firstMiss - 1].
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

export type ShareLogState = Record<string, { tx_id: string; cek: string }>;

export type StateHooks = {
  onWarn?: (msg: string) => void;
  onError?: (msg: string) => void;
};

/**
 * Apply a single (parsed) operation to a state map in place, per the
 * idempotency rules of §8.4. State is `{ content_id: { tx_id, cek } }`.
 */
export function applyOperationToState(
  state: ShareLogState,
  operation: unknown,
  hooks: StateHooks = {},
): void {
  const warn = hooks.onWarn ?? defaultWarn;
  const error = hooks.onError ?? defaultError;

  if (!state || typeof state !== 'object') {
    throw new Error('applyOperationToState: state must be an object');
  }
  if (!operation || typeof operation !== 'object') {
    throw new Error('applyOperationToState: operation must be an object');
  }
  const op = operation as Record<string, unknown>;

  switch (op['type']) {
    case OP_ADD: {
      const cid = op['content_id'] as string;
      const tx_id = op['tx_id'] as string;
      const cek = op['cek'] as string;
      const existing = state[cid];
      if (existing) {
        if (existing.cek !== cek) {
          error(`share-log: add for known content_id ${cid} with different CEK; adopting new CEK`);
        }
        state[cid] = { tx_id, cek };
      } else {
        state[cid] = { tx_id, cek };
      }
      return;
    }
    case OP_UPDATE: {
      const cid = op['content_id'] as string;
      const existing = state[cid];
      if (!existing) {
        warn(`share-log: update for unknown content_id ${cid}; ignoring`);
        return;
      }
      state[cid] = { tx_id: op['tx_id'] as string, cek: existing.cek };
      return;
    }
    case OP_ROTATE: {
      const cid = op['content_id'] as string;
      const existing = state[cid];
      if (!existing) {
        warn(`share-log: rotate for unknown content_id ${cid}; ignoring`);
        return;
      }
      state[cid] = { tx_id: existing.tx_id, cek: op['cek'] as string };
      return;
    }
    case OP_REMOVE: {
      delete state[op['content_id'] as string];
      return;
    }
    case OP_SNAPSHOT: {
      for (const k of Object.keys(state)) delete state[k];
      const snap = (op['state'] as SnapshotState) ?? {};
      for (const [cid, entry] of Object.entries(snap)) {
        state[cid] = { tx_id: entry.tx_id, cek: entry.cek };
      }
      return;
    }
    case OP_ROTATE_IDENTITY: {
      // §13.5 / 5d: parsing-only no-op for now.
      return;
    }
    default:
      warn(`share-log: unknown operation type ${String(op['type'])}; ignoring`);
  }
}

function defaultWarn(msg: string): void { console.warn(`[share-log] ${msg}`); }
function defaultError(msg: string): void { console.error(`[share-log] ${msg}`); }

/** Apply a sequence of operations in order, returning a fresh state map. */
export function replayOperations(
  operations: ReadonlyArray<unknown>,
  initialState: ShareLogState = {},
  hooks: StateHooks = {},
): ShareLogState {
  const state: ShareLogState = { ...initialState };
  for (const op of operations) {
    applyOperationToState(state, op, hooks);
  }
  return state;
}
