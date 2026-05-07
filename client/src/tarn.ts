// Tarn Client — TypeScript API client for the Tarn protocol
// Handles key derivation, encryption/decryption, and all API interactions.
// Works in browsers and Node.js 15+.
//
// Each TarnClient instance is scoped to one app. Same username+password with
// different app IDs produces completely isolated accounts.
//
// NOTE: Protocol version ('0.4.0') is hardcoded in tag construction below.
// When the protocol version bumps, update the V tag values here. This is
// intentionally not imported from the server — the client library is
// independently distributable and should not depend on server internals.

import {
  deriveAllKeys,
  deriveRecoveryKey,
  deriveRecoveryLookupKey,
  deriveRecoverySigningKeyPair,
  deriveShareLookupKey,
  exportPublicKey,
  encodeSharePub,
  decodeSharePub,
  wrapDataKeyChainEnvelope,
  buildEnvelope,
  unwrapDataKeyChain,
  signChallenge,
  encrypt,
  decrypt,
  encryptWithCEK,
  decryptWithCEK,
  decryptBlobWithSharedCEK,
  hasTarnBlobMagic,
  TARN_BLOB_MAGIC_LEN,
  TARN_WRAPPED_CEK_LEN,
  generateRandomDataKey,
  generateRecoverySalt,
  parseWrappedDataKey,
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64,
  bytesToBase64Url,
  wrapAccountKey,
  unwrapAccountKey,
  FACTOR_PASSWORD,
  FACTOR_RECOVERY_PHRASE,
  FACTOR_PASSKEY_PRF,
  derivePasskeyWrappingKey,
} from './crypto.js';
import {
  generateAccountKey,
  validateAccountKey,
  accountKeyToEntropy,
} from './recovery.js';
import {
  encryptSessionBlob,
  decryptSessionBlob,
  getOrCreateWrappingKey,
  clearWrappingKey,
} from './session-persistence.js';
import {
  deriveInboxTag,
  recentInboxWindows,
  currentInboxWindow,
  hpkeSeal,
  hpkeOpen,
  buildConnectionRequestPayload,
  validateConnectionRequestPayload,
  buildConnectionAcceptPayload,
  validateConnectionAcceptPayload,
  makeReplayNonceCache,
  checkAndRecordNonce,
  findOutboundForAccept,
  emptyConnectionsRecord,
  emptyPendingRequestsRecord,
  upsertConnection,
  removeConnection,
  rotateConnectionIdentity,
  addOutboundPending,
  addInboundPending,
  removeOutboundPending,
  removeInboundPending,
  CONNECTIONS_CONTENT_ID,
  PENDING_REQUESTS_CONTENT_ID,
  INFO_CONNECTION_REQUEST,
  INFO_CONNECTION_ACCEPT,
  DEFAULT_POLL_WINDOWS,
  MUTED_CONNECTIONS_CONTENT_ID,
  emptyMutedConnectionsRecord,
  addMutedConnection,
  removeMutedConnection,
  isMutedInRecord,
  ISSUED_INVITES_CONTENT_ID,
  emptyIssuedInvitesRecord,
  addIssuedInvite,
  removeIssuedInvite,
} from './sharing.js';
import {
  deriveSharedSecret,
  derivePairKeys,
  deriveLogTag,
  buildOperationUnsigned,
  signOperation,
  verifyOperationSignature,
  encryptShareLogEntry,
  decryptShareLogEntry,
  shouldEmitSnapshot,
  discoverHighestSeq,
  applyOperationToState,
  DEFAULT_COMPACTION_INTERVAL,
  SHARE_LOG_TYPE,
  OP_ADD,
  OP_UPDATE,
  OP_ROTATE,
  OP_REMOVE,
  OP_SNAPSHOT,
  OP_ROTATE_IDENTITY,
} from './share-log.js';

// Local type aliases used throughout the class.
import type {
  Argon2idParams,
  DataKeyHandles,
  DataKeyPair,
  RecoveryMetadata,
  SigningKeyPair,
  SharingKeyPair,
} from './crypto.js';
import type { ReplayNonceCache } from './sharing.js';

type Tag = { name: string; value: string };

/** Internal recovery-factor metadata cached on the live client. */
type RecoveryFactorMeta = {
  salt: Uint8Array;
  kdfParams: Argon2idParams;
  wrappingsByGen: Map<number, string>;
};

// Loose internal aliases. Replace these with proper named types in step 6d-ii
// (entry CRUD / sharing primitives) and 6d-iii (share-log + invites + sessions).
type AnyRecord = Record<string, any>;       // eslint-disable-line @typescript-eslint/no-explicit-any
type ConnectionEntry = { share_pub: string; signing_pub: string; [k: string]: any };
type PendingState = { record: AnyRecord; txid: string | null };

// WebCrypto BufferSource cast (matches crypto.ts pattern).
function bs(b: ArrayBufferView | ArrayBuffer): BufferSource {
  return b as BufferSource;
}

// Re-export the account-key surface so consumers can import them directly
// from the package root without reaching into ./recovery (private path).
export { generateAccountKey, validateAccountKey };

/**
 * Thrown by `viewAccountKey()` when the wrap decrypts cleanly but the
 * resulting account-key entropy derives a `recovery_lookup_key` that does
 * NOT match the value the server has on record.
 *
 * Possible causes (all security-relevant):
 *   - The server returned a tampered wrap that decrypts to a *different*
 *     valid 24-word BIP39 phrase under a colluding/compromised storage
 *     backend.
 *   - The server returned a wrap belonging to a different account under a
 *     mis-binding bug.
 *
 * Callers SHOULD surface this distinctly from generic decryption errors —
 * it is a security warning, not a "wrong password" or "network failure".
 */
export class AccountKeyPinningError extends Error {
  constructor(message = 'Account-key pinning check failed: derived recovery_lookup_key does not match the server') {
    super(message);
    this.name = 'AccountKeyPinningError';
  }
}

/**
 * Thrown by `authenticateWithPasskey` when the server flags the just-used
 * credential as stale (no `passkey_prf` wrapping on the latest gen) AND
 * the caller did not provide a `stalePasskeyHandler` to repair it inline.
 *
 * "Stale" happens when an envelope-mutating flow on another device
 * (typically `changeCredentials`) created a new gen and the user did not
 * re-tap this passkey at change-time. The credential can still unwrap
 * pre-change gens, so the auth response still carries useful state — but
 * the latest gen is unreachable through this passkey alone, and any data
 * written post-change is therefore unreadable until the wrap is repaired.
 *
 * The repair requires a second factor: typically the password (path 1 —
 * supply a `stalePasskeyHandler` that prompts for it) or a re-registration
 * of the passkey from a logged-in session. Apps catching this error can
 * surface either path.
 */
export class StalePasskeyError extends Error {
  readonly credentialId: string;
  readonly requiresReregistration: boolean;
  constructor(args: { credentialId: string; message?: string }) {
    super(
      args.message ??
        `Passkey ${args.credentialId.slice(0, 8)}… has no wrapping for the current generation. ` +
          'Repair it by re-authenticating with a stalePasskeyHandler that supplies the password, ' +
          'or by re-registering the passkey from a password-authenticated session.',
    );
    this.name = 'StalePasskeyError';
    this.credentialId = args.credentialId;
    this.requiresReregistration = true;
  }
}

export class TarnClient {
  #apiBase: string;
  #appId: string;
  #jwt: string | null = null;
  #dataLookupKey: string | null = null;
  #credentialLookupKey: string | null = null;
  #credentialEncryptionKey: DataKeyHandles | null = null;
  #signingKeyPair: SigningKeyPair | null = null;

  // DEK chain. Populated on every successful login/register/recoverAccount.
  // Keys are {gcmKey, kwKey} pairs holding two WebCrypto handles for the same
  // 32 raw bytes (AES-GCM for direct decryption, AES-KW for wrapping
  // per-content CEKs). Old generations stay in the chain so blobs written
  // under prior credentials remain decryptable after a credential rotation.
  #dekByGen: Map<number, DataKeyPair> | null = null;
  #currentGen: number | null = null;

  // Sharing handshake state (issue #14, Section 5a). Populated on every
  // register/login/changeCredentials/recoverAccount path so the connection
  // handshake methods can HPKE-Open inbox blobs without re-deriving from
  // master_key on every call. share_priv NEVER leaves the device.
  #username: string | null = null;
  #sharingKeyPair: SharingKeyPair | null = null;
  #replayNonceCache: ReplayNonceCache = makeReplayNonceCache();

  // Per-connection share-log state (issue #15, Section 5b). Map keyed on the
  // connection's `share_pub` (base64url string) — small, fast lookups by
  // stable identifier. Each entry holds:
  //   - keys: derived once per session via derivePairKeys()
  //   - nextOutboundSeq: writer-side counter for our outbound-to-connection log
  //   - nonSnapshotsSinceLastSnapshot: snapshot-compaction trigger (§8.6)
  // Cache is in-memory only; on session restart the writer must rediscover
  // the highest existing seq before publishing (5c work). For 5b, the
  // counters are seeded at register/handshake time and remain authoritative
  // for the lifetime of the session.
  #pairKeyCache: Map<string, any> = new Map();
  #shareLogCounters: Map<string, any> = new Map();

  // Per-connection reconstructed inbound state (issue #16, Section 5c).
  // Keyed on the connection's `share_pub`, holds the application's view of
  // what the connection has shared with us — the result of replaying their
  // outbound log per §8.5. `lastSeqSeen` is the highest seq we've applied
  // (or -1 if no entries yet). In-memory only; on session restart
  // `readShareLog` re-bootstraps from Arweave. Wholly invalidated on
  // credential change / recovery / delete.
  #readStateCache: Map<string, any> = new Map();

  // Per-connection reconstructed OUTBOUND state (issue #16, Section 5c).
  // Tracks what we've shared with each connection so the writer can emit
  // meaningful snapshots during auto-compaction (§8.6). An empty snapshot
  // is NOT a no-op per §8.3.5 — it tells the recipient "I'm sharing nothing
  // with you anymore", which would erase their entire view.
  //
  // Hydration: lazily reconstructed on the first high-level publish call
  // per session by replaying our own outbound log. Updated incrementally
  // by shareContent / updateShareContent / unshareContent / explicit
  // snapshotShareLog. Wholly invalidated on credential change / recovery /
  // delete (the per-pair keys rotate, so the cache is stale anyway).
  #outboundStateCache: Map<string, any> = new Map();

  // Per-connection set of outbound txids we've successfully published in
  // this session (issue #16, Section 5c). Used by the multi-device retry
  // path (§13.1) to detect "this 409 is reporting back my own previous
  // publish" (e.g., the SDK retried after a transient response loss). When
  // the 409's `existing_txid` is in this set, we treat the publish as
  // already-done rather than republishing at the next seq. Cleared with the
  // rest of the share-log caches on credential change / recovery / delete.
  #publishedTxidsByConnection: Map<string, Set<string>> = new Map();

  // Muted-connections record (issue #18, Section 6). Loaded on demand on
  // the first mute-related call per session and kept in sync with the
  // persisted `tarn-muted-connections-v1` blob across calls. The record
  // syncs across devices via the encrypted Tarn data blob; subsequent
  // sessions hydrate from Arweave. Wholly invalidated on credential change
  // / recovery / delete (re-hydrate on next mute-related call).
  #mutedConnectionsState: PendingState | null = null;

  // Issued-invites record (issue #22, Section 8). Mirrors the muted-
  // connections pattern but with a critical exception: the auto-accept
  // path in listIncomingRequests() always re-reads the blob fresh from
  // the API (bypasses this cache) so an invite created on a different
  // device is recognized.
  #issuedInvitesState: PendingState | null = null;

  // Recently-written content keys, keyed by Arweave txid. Populated by
  // createEntry / updateEntry / batchCreate so a subsequent share() call
  // resolves the shareKey without an extra blob fetch + AES-KW unwrap.
  // Bounded LRU (newest at end of insertion order; evicts the oldest entry
  // when over cap) — keeps memory predictable without making it the SDK's
  // job to track every shareKey forever. Cold path (sharing an entry from
  // a prior session) falls back to fetch + unwrap via getShareKey().
  #shareKeyCache: Map<string, string> = new Map();
  #shareKeyCacheCap = 64;

  // Recovery-factor state. Holds enough information to preserve existing
  // recovery wrappings across a credential change without requiring the user
  // to re-enter the phrase: the per-account salt + KDF params (so a future
  // write that DOES have the phrase can re-derive the same KEK), and a
  // snapshot of the existing wrapped recovery bytes per gen (so we can
  // re-emit them verbatim).
  #recoveryFactorMeta: RecoveryFactorMeta | null = null;
  #recoveryLookupKey: string | null = null;

  // Phase 6 — snapshot of passkey wrappings present in the live envelope,
  // keyed by (gen → array of {credentialId, wrappedBase64}). Same purpose
  // as #recoveryFactorMeta.wrappingsByGen: lets envelope-mutating flows
  // (changeCredentials, rotateAccountKey, recoverAccount) preserve passkey
  // wrappings byte-for-byte even though we don't have the PRF outputs to
  // re-wrap. Empty Map = no passkeys registered (the common case).
  #passkeyWrappingsByGen: Map<number, Array<{ credentialId: string; wrappedBase64: string }>> = new Map();

  // Section 7.5 (issue #20) — server-side session id from the JWT's `sid` claim.
  // Sent back as `previous_sid` on /auth/verify so the server reuses the same
  // sessions row instead of minting a fresh one. Null until the first verify.
  #sid: string | null = null;
  // One-shot device label consumed by the next #authenticate call. Set by
  // register/login/recoverAccount; cleared after the verify body is built.
  #pendingDeviceLabel: string | null = null;

  // Phase 3 (RECOVERY_PLAN.md) — Model B indicator surfaced on /auth/verify.
  // True when the account has a wrap stored on the server (Model B); false
  // for Model A; null until the first verify completes. Apps read this via
  // `tarn.session.isAccountKeyStored()` to render the right Settings UI.
  #accountKeyStored: boolean | null = null;

  /**
   * @param apiBaseUrl - Tarn API base URL (e.g., 'https://api.tarn.dev')
   * @param appId - Registered app identifier (e.g., 'bookish')
   */
  constructor(apiBaseUrl: string, appId: string) {
    if (!appId) throw new Error('appId is required');
    this.#apiBase = apiBaseUrl.replace(/\/$/, '');
    this.#appId = appId;
  }

  // ============ AUTH ============

  /**
   * Register a new account for this app (issue #12 — v4 envelope with
   * mandatory recovery factor).
   *
   * Generates a fresh random 32-byte DEK at gen 1 (issue #11) and a 24-word
   * BIP39 account key. The DEK is wrapped twice into a v4 envelope:
   *   - under the password-derived KEK (factor: "password")
   *   - under an account-key-derived KEK (factor: "recovery_phrase")
   * The envelope is opaque to the API (passes the existing length/type check).
   *
   * The caller MUST pass `recoveryAcknowledged: true` — without it, register
   * fails synchronously with no network call. This is the SDK enforcement of
   * the design-doc requirement that the account key is mandatory at signup.
   *
   * The account key is returned to the caller in the result payload. The
   * TarnClient instance does NOT cache the key — the caller is responsible
   * for surfacing it to the user (downloadable kit, printable page,
   * app-operated delivery channel, etc.) and dropping the in-memory copy
   * promptly. Tarn no longer renders kits in-SDK; the app owns the kit
   * format and delivery.
   *
   * Account-key storage (Phase 3 — RECOVERY_PLAN.md):
   *   - `storeAccountKey: true` (default) → Model B. The SDK encrypts the
   *     account-key UTF-8 under the gen-1 DEK with AAD
   *     `"tarn-wrapped-account-key-v1"` and ships the ciphertext as
   *     `wrapped_account_key` in the register payload. Logged-in users can
   *     later retrieve and view the account key via `tarn.accountKey.view()`.
   *   - `storeAccountKey: false` → Model A. The wrap is omitted; Tarn never
   *     stores any form of the account key. The user holds the only copy.
   *
   * Apps choose at registration time; users can switch later via the toggle
   * endpoints (Phase 4 — not yet shipped).
   *
   * @param {string} username
   * @param {string} password
   * @param {{
   *   recoveryAcknowledged: boolean,
   *   storeAccountKey?: boolean,
   * }} [opts]
   * @returns {Promise<{
   *   dataLookupKey: string,
   *   accountKey: string,
   *   }>}
   */
  async register(username: string, password: string, opts: any = {}): Promise<any> {
    if (!opts || opts.recoveryAcknowledged !== true) {
      throw new Error('register(): recoveryAcknowledged: true is required (issue #12)');
    }
    // Default Model B per RECOVERY_PLAN.md. Apps that want strict
    // zero-knowledge "no backup stored" pass `storeAccountKey: false`.
    const storeAccountKey = opts.storeAccountKey !== false;
    // Sharing keypair publication (issue #13). Defaults to discoverable so a
    // new social-app user can connect by username out of the box. Apps that
    // want a "private by default" stance can pass `shareDiscoverable: false`.
    const shareDiscoverable = opts.shareDiscoverable !== false;
    // Section 7.5 (issue #20): optional human-readable label for this device,
    // surfaced via listSessions on every device tied to this account.
    if (opts.deviceLabel != null) this.#pendingDeviceLabel = opts.deviceLabel;

    // Derive password-side keys + account-key-side keys + share-lookup
    // key in parallel — Argon2id calls dominate registration latency, so
    // overlap them. share_lookup_key is HKDF over SHA-256(username), independent
    // of the password.
    const phrase = generateAccountKey();
    const phraseEntropy = accountKeyToEntropy(phrase);
    const recoverySalt = generateRecoverySalt();

    const [keys, recoveryKEK, recoveryLookupKey, recoverySigningKeyPair, shareLookupKey] = await Promise.all([
      deriveAllKeys(username, password, this.#appId),
      deriveRecoveryKey(phrase, recoverySalt),
      deriveRecoveryLookupKey(phraseEntropy, this.#appId),
      deriveRecoverySigningKeyPair(phraseEntropy, this.#appId),
      deriveShareLookupKey(username, this.#appId),
    ]);

    const [publicKeyBase64, recoveryPublicKeyBase64] = await Promise.all([
      exportPublicKey(keys.signingKeyPair.publicKey),
      exportPublicKey(recoverySigningKeyPair.publicKey),
    ]);
    const sharePub = encodeSharePub(keys.sharingKeyPair.publicKey);

    // Random DEK at generation 1. Wrap under both password + recovery factors.
    const dek = await generateRandomDataKey();
    const wrappedDataKey = await wrapDataKeyChainEnvelope(
      [{ gen: 1, key: dek.gcmKey }],
      [
        { name: FACTOR_PASSWORD,        wrappingKey: keys.credentialEncryptionKey.kwKey },
        { name: FACTOR_RECOVERY_PHRASE, wrappingKey: recoveryKEK.kwKey },
      ],
      { salt: recoverySalt },
    );

    // Phase 3 — Model B: encrypt the account-key UTF-8 under the gen-1 DEK.
    // The wrap is opaque to Tarn; only a logged-in user (with the password
    // to derive DEK_gen1) plus a step-up token can fetch and decrypt it.
    const wrappedAccountKey = storeAccountKey
      ? await wrapAccountKey(dek.gcmKey, phrase)
      : null;

    const registerBody: Record<string, unknown> = {
      credential_lookup_key: keys.credentialLookupKey,
      public_key: publicKeyBase64,
      wrapped_data_key: wrappedDataKey,
      app: this.#appId,
      recovery_lookup_key: recoveryLookupKey,
      recovery_public_key: recoveryPublicKeyBase64,
      share_pub: sharePub,
      share_discoverable: shareDiscoverable,
      share_lookup_key: shareLookupKey,
    };
    if (wrappedAccountKey) registerBody['wrapped_account_key'] = wrappedAccountKey;

    const res = await this.#fetch('/api/v1/auth/register', {
      method: 'POST',
      retry: true, // idempotent since tarn #6 (envelope is byte-stable)
      body: registerBody,
    });

    if (res.status !== 201) {
      throw new Error(`Registration failed: ${res.json?.error || res.status}`);
    }

    this.#credentialLookupKey = keys.credentialLookupKey;
    this.#credentialEncryptionKey = keys.credentialEncryptionKey;
    this.#signingKeyPair = keys.signingKeyPair;
    this.#dataLookupKey = res.json.data_lookup_key;
    this.#dekByGen = new Map([[1, { gcmKey: dek.gcmKey, kwKey: dek.kwKey }]]);
    this.#currentGen = 1;
    this.#username = username;
    this.#sharingKeyPair = keys.sharingKeyPair;
    // Snapshot the recovery wrapping bytes for the freshly-registered chain
    // so a subsequent changeCredentials() can preserve them without needing
    // the phrase. Re-parse the envelope (cheap — local JSON) to capture the
    // exact wire bytes after wrap.
    {
      const re = parseWrappedDataKey(wrappedDataKey);
      const wrappingsByGen = new Map<number, string>();
      for (const entry of re.dekChain) {
        const w = entry.wrappings.find(w => w.factor === FACTOR_RECOVERY_PHRASE);
        if (w) wrappingsByGen.set(entry.gen, w.wrappedBase64);
      }
      this.#recoveryFactorMeta = {
        salt: re.recovery.salt,
        kdfParams: re.recovery.kdfParams,
        wrappingsByGen,
      };
      this.#capturePasskeyWrappings(re);
    }
    this.#recoveryLookupKey = recoveryLookupKey;

    await this.#authenticate();

    return {
      dataLookupKey: this.#dataLookupKey,
      accountKey: phrase,
    };
  }

  /**
   * Recover an account using only the account key + new credentials.
   * Used when the user has lost their password (or wants a security-grade
   * reset that the design-doc positions as "the response to suspected
   * compromise").
   *
   * Flow:
   *   1. Derive recovery_lookup_key + recovery signing key from the account key
   *   2. POST /auth/challenge { recovery_lookup_key } → get the existing
   *      credential blob's wrapped_data_key + a nonce
   *   3. Parse the v4 envelope, extract the recovery salt, derive recovery KEK
   *   4. Unwrap the DEK chain via the recovery factor
   *   5. Sign the nonce with the recovery signing private key → JWT (the API
   *      verifies against the stored recovery_public_key)
   *   6. Derive new password KEK from (newUsername, newPassword)
   *   7. Re-wrap the DEK chain under both new password KEK + (kept) recovery
   *      KEK and PUT /auth to publish the new credential blob
   *
   * On success the client is authenticated under the new credentials and
   * holds the full DEK chain — old data is still readable.
   *
   * @param {{ phrase: string, newUsername: string, newPassword: string }} opts
   * @returns {Promise<{dataLookupKey: string}>}
   */
  async recoverAccount(args: any = {}): Promise<any> {
    const { phrase, newUsername, newPassword, ...opts } = args;
    const validation = validateAccountKey(phrase);
    if (!validation.valid) {
      throw new Error(`recoverAccount(): ${validation.reason}`);
    }
    if (!newUsername || !newPassword) {
      throw new Error('recoverAccount(): newUsername and newPassword are required');
    }
    // Section 7.5 (issue #20): optional deviceLabel applied to the post-recover
    // re-auth (the second #authenticate below, after credentials rotate).
    if (opts && opts.deviceLabel != null) this.#pendingDeviceLabel = opts.deviceLabel;

    const phraseEntropy = accountKeyToEntropy(validation.normalized);
    const [recoveryLookupKey, recoverySigningKeyPair] = await Promise.all([
      deriveRecoveryLookupKey(phraseEntropy, this.#appId),
      deriveRecoverySigningKeyPair(phraseEntropy, this.#appId),
    ]);

    // Step 2: ask for a challenge keyed by recovery_lookup_key.
    const challengeRes = await this.#fetch('/api/v1/auth/challenge', {
      method: 'POST',
      retry: true, // fresh nonce per call
      body: { recovery_lookup_key: recoveryLookupKey },
    });
    if (challengeRes.status === 404) {
      throw new Error('recoverAccount(): no account found for this account key + app');
    }
    if (challengeRes.status !== 200) {
      throw new Error(`recoverAccount(): challenge failed: ${challengeRes.json?.error || challengeRes.status}`);
    }
    const { nonce, data_lookup_key, wrapped_data_key } = challengeRes.json;

    // Steps 3-4: derive recovery KEK from the envelope salt + phrase, then
    // unwrap the DEK chain via the recovery factor.
    // Two-pass: parse envelope to get the recovery salt + params, derive
    // the recovery KEK, then unwrap. The flow is explicit (rather than baked
    // into unwrapDataKeyChain) because the salt + params live in the envelope
    // and the KEK derivation is the slow Argon2id step.
    const parsed = parseWrappedDataKey(wrapped_data_key);
    const recoveryKEK = await deriveRecoveryKey(
      validation.normalized,
      parsed.recovery.salt,
      parsed.recovery.kdfParams,
    );
    const unwrapped = await unwrapDataKeyChain(
      wrapped_data_key,
      recoveryKEK.kwKey,
      FACTOR_RECOVERY_PHRASE,
    );

    // Step 5: sign nonce with recovery signing key to obtain a JWT.
    const signature = await signChallenge(recoverySigningKeyPair.privateKey, nonce);
    const verifyRes = await this.#fetch('/api/v1/auth/verify', {
      method: 'POST',
      body: { recovery_lookup_key: recoveryLookupKey, nonce, signature },
    });
    if (verifyRes.status !== 200) {
      throw new Error(`recoverAccount(): verify failed: ${verifyRes.json?.error || verifyRes.status}`);
    }
    this.#jwt = verifyRes.json.jwt;
    this.#sid = this.#extractSidFromJwt(this.#jwt);
    this.#dataLookupKey = data_lookup_key;
    // We do NOT yet have the password-side identity — those are derived next.

    // Steps 6-7: derive new password keys, re-wrap DEK chain under both
    // factors, publish via PUT /auth. The sharing keypair (issue #13) and
    // share_lookup_key are also rederived under the new credentials so the
    // recovered account stays discoverable post-recovery (or non-discoverable,
    // if the caller passed `shareDiscoverable: false`).
    const [newKeys, newShareLookupKey] = await Promise.all([
      deriveAllKeys(newUsername, newPassword, this.#appId),
      deriveShareLookupKey(newUsername, this.#appId),
    ]);
    const newPublicKey = await exportPublicKey(newKeys.signingKeyPair.publicKey);
    const newSharePub = encodeSharePub(newKeys.sharingKeyPair.publicKey);

    const chain = [];
    for (const [gen, pair] of unwrapped.dekByGen) {
      chain.push({ gen, key: pair.gcmKey });
    }
    chain.sort((a, b) => a.gen - b.gen);

    // Phase 6: preserve any `passkey_prf` wrappings byte-for-byte. The
    // existing envelope (`parsed`) carries them; a fresh recovery flow
    // doesn't have the PRF outputs to re-derive, but the underlying DEKs
    // didn't change, so the wrappings are still valid.
    const passkeyExtras = new Map<number, Array<{ factor: string; wrappedBase64: string; credentialId: string }>>();
    for (const entry of parsed.dekChain) {
      const list: Array<{ factor: string; wrappedBase64: string; credentialId: string }> = [];
      for (const w of entry.wrappings) {
        if (w.factor === FACTOR_PASSKEY_PRF && w.credentialId) {
          list.push({
            factor: FACTOR_PASSKEY_PRF,
            wrappedBase64: w.wrappedBase64,
            credentialId: w.credentialId,
          });
        }
      }
      if (list.length > 0) passkeyExtras.set(entry.gen, list);
    }

    const newWrappedDataKey = await wrapDataKeyChainEnvelope(
      chain,
      [
        { name: FACTOR_PASSWORD,        wrappingKey: newKeys.credentialEncryptionKey.kwKey },
        { name: FACTOR_RECOVERY_PHRASE, wrappingKey: recoveryKEK.kwKey },
      ],
      { salt: parsed.recovery.salt, kdfParams: parsed.recovery.kdfParams },
      passkeyExtras,
    );

    // recovery_lookup_key + recovery_public_key are derived purely from the
    // phrase and don't change across recovery — but we re-send them anyway
    // so a corrupted server-side row gets healed on the next credential
    // change. This is also what register sends.
    const recoveryPublicKey = await exportPublicKey(recoverySigningKeyPair.publicKey);

    // Snapshot OLD key material + outbound state per connection before swapping.
    // Recovery rotates share_priv + signing_priv just like changeCredentials,
    // so the §13.5 rotation announcement applies identically. Note: in the
    // recovery code path the user has rotated credentials AS A RESULT of
    // suspected compromise OR routine — the §13.5 known limitation about
    // rotation under compromised OLD keys is documented and accepted.
    //
    // Two recovery scenarios:
    //   - Fresh-client recovery (most common): a new TarnClient is calling
    //     recoverAccount with no prior login. #sharingKeyPair and
    //     #signingKeyPair are null → no OLD keys to sign rotation
    //     announcements with. Skip the announce loop; connections will need to
    //     reconcile via out-of-band channel (the §13.5 known limitation).
    //   - Logged-in recovery (rare): the user is already authenticated under
    //     the OLD identity and is recovering for routine reasons. OLD keys
    //     and DEK chain are in memory → we can announce.
    const oldSharingKeyPair = this.#sharingKeyPair;
    const oldSigningKeyPair = this.#signingKeyPair;
    const skipRotationAnnounce = opts?.skipRotationAnnounce === true;
    const canAnnounce = !skipRotationAnnounce
      && !!oldSharingKeyPair?.privateKey
      && !!oldSigningKeyPair?.privateKey
      && this.#dekByGen != null;

    let oldConnectionsState: { record: { connections: any[]; [k: string]: any }; txid: string | null } = { record: { connections: [] }, txid: null };
    const outboundStateByConnection = new Map();
    if (canAnnounce) {
      try {
        oldConnectionsState = await this.#loadConnectionsRecord();
      } catch (err: any) {
        console.warn(
          `[TarnClient] recoverAccount: connections record load failed (no rotation announce): ${err.message}`,
        );
      }
      for (const connection of oldConnectionsState.record.connections) {
        try {
          await this.#hydrateOutboundState(connection);
          outboundStateByConnection.set(connection.share_pub, this.#tentativeOutboundState(connection));
        } catch (err: any) {
          console.warn(
            `[TarnClient] recoverAccount: outbound state hydration failed for ${connection.share_pub.slice(0, 8)}...: ${err.message}`,
          );
          outboundStateByConnection.set(connection.share_pub, {});
        }
      }
    }

    const putRes = await this.#fetch('/api/v1/auth', {
      method: 'PUT',
      auth: true,
      body: {
        new_credential_lookup_key: newKeys.credentialLookupKey,
        new_public_key: newPublicKey,
        new_wrapped_data_key: newWrappedDataKey,
        new_recovery_lookup_key: recoveryLookupKey,
        new_recovery_public_key: recoveryPublicKey,
        new_share_pub: newSharePub,
        new_share_lookup_key: newShareLookupKey,
      },
    });
    if (putRes.status !== 200) {
      throw new Error(`recoverAccount(): credential change failed: ${putRes.json?.error || putRes.status}`);
    }

    // §7 invalidation: signing/DEK rotation makes any prior session blob
    // un-resumable. Wipe the IndexedDB wrapping key so prior blobs become
    // unreadable on this origin. Best-effort — IndexedDB failure must not
    // fail the credential operation.
    try { await this.clearSession(); } catch {}

    // Announce the rotation to connections BEFORE swapping local key state, so
    // we can sign with the OLD signing_priv and encrypt under OLD K_AB.
    let rotationAnnouncements = [];
    if (canAnnounce && oldConnectionsState.record.connections.length > 0) {
      try {
        rotationAnnouncements = await this.#announceIdentityRotationToConnections({
          oldSharingKeyPair,
          oldSigningKeyPair,
          oldConnectionsRecord: oldConnectionsState.record,
          newSharingPublicKey: newKeys.sharingKeyPair.publicKey,
          newSigningPublicKey: newKeys.signingKeyPair.publicKey,
          newCredentialLookupKey: newKeys.credentialLookupKey,
          rotatedAt: Math.floor(Date.now() / 1000),
        });
      } catch (err: any) {
        console.warn(`[TarnClient] recoverAccount: rotation announce failed: ${err.message}`);
      }
    }

    // Update local state to the new identity.
    this.#credentialLookupKey = newKeys.credentialLookupKey;
    this.#credentialEncryptionKey = newKeys.credentialEncryptionKey;
    this.#signingKeyPair = newKeys.signingKeyPair;
    this.#dekByGen = unwrapped.dekByGen;
    this.#currentGen = unwrapped.currentGen;
    this.#username = newUsername;
    this.#sharingKeyPair = newKeys.sharingKeyPair;
    // Repopulate recovery-factor metadata so a subsequent
    // changeCredentials / rotateAccountKey on this client preserves the
    // existing recovery wrappings (or rotates them) without needing the
    // user to re-enter the phrase. The salt/params come from the parsed
    // envelope; the wrappings come from the chain we just re-wrapped.
    {
      const reparsed = parseWrappedDataKey(newWrappedDataKey);
      const wrappingsByGen = new Map<number, string>();
      for (const entry of reparsed.dekChain) {
        const w = entry.wrappings.find(w => w.factor === FACTOR_RECOVERY_PHRASE);
        if (w) wrappingsByGen.set(entry.gen, w.wrappedBase64);
      }
      this.#recoveryFactorMeta = {
        salt: reparsed.recovery.salt,
        kdfParams: reparsed.recovery.kdfParams,
        wrappingsByGen,
      };
      this.#capturePasskeyWrappings(reparsed);
    }
    this.#recoveryLookupKey = recoveryLookupKey;
    // Pair-key cache is derived from share_priv; recovery rotates it.
    this.#pairKeyCache.clear();
    this.#shareLogCounters.clear();
    this.#readStateCache.clear();
    this.#outboundStateCache.clear();
    this.#publishedTxidsByConnection.clear();
    this.#mutedConnectionsState = null;
    this.#issuedInvitesState = null;
    this.#jwt = null; // force re-auth under the new credentials
    await this.#authenticate();

    // §13.5 step 8: publish a fresh seq=0 snapshot to every connection's NEW
    // outbound log under the new pair keys. Only meaningful if we ran
    // rotation announce (we need to have known the OLD log existed +
    // captured outbound state).
    if (canAnnounce) {
      for (const connection of oldConnectionsState.record.connections) {
        const state = outboundStateByConnection.get(connection.share_pub) ?? {};
        try {
          await this._publishInitialSnapshot(connection, { state });
        } catch (err: any) {
          console.warn(
            `[TarnClient] recoverAccount: NEW-log seq=0 snapshot publish failed for ${connection.share_pub.slice(0, 8)}...: ${err.message}`,
          );
        }
      }
    }

    // Phase 4 — optional account-key rotation piggybacked on recovery.
    // The user is performing a forgot-password flow but ALSO suspects
    // their account key has been compromised — flipping `rotatePhrase`
    // on the same call evicts the old key in one round trip rather than
    // requiring a separate post-recovery `rotateAccountKey` call.
    //
    // Reuses rotateAccountKey directly: same wire-format, same atomicity
    // guarantee. Returns the freshly-generated key in the result so the
    // app can show it to the user (single-use, surfaced once).
    let newAccountKey: string | undefined;
    if (opts?.rotatePhrase === true) {
      try {
        const rotated = await this.rotateAccountKey({ password: newPassword });
        newAccountKey = rotated.accountKey;
      } catch (err: any) {
        // The recovery itself succeeded; surface the rotation failure as
        // a partial-success error. The user is logged in under the new
        // credentials but the OLD account key still works. They can call
        // tarn.accountKey.rotate() manually to retry.
        throw new Error(
          `recoverAccount({ rotatePhrase: true }): recovery succeeded but rotation failed: ${err?.message || err}. ` +
          `Call tarn.accountKey.rotate() to retry.`,
        );
      }
    }

    const result: any = { dataLookupKey: this.#dataLookupKey, rotationAnnouncements };
    if (newAccountKey !== undefined) result.accountKey = newAccountKey;
    return result;
  }

  /**
   * Log in to an existing account for this app.
   * @param {string} username
   * @param {string} password
   * @param {{ deviceLabel?: string }} [opts]
   * @returns {Promise<{dataLookupKey: string}>}
   */
  async login(username: string, password: string, opts: any = {}): Promise<any> {
    // Section 7.5 (issue #20): one-shot device label, consumed by the next
    // /auth/verify call inside #verifyChallenge below.
    if (opts && opts.deviceLabel != null) this.#pendingDeviceLabel = opts.deviceLabel;
    // Single-KDF login: Argon2id is the only path. Legacy PBKDF2 accounts no
    // longer exist (back-compat was cut cleanly when there was still only one
    // user — see TARN_PROTOCOL.md §2).
    const keys = await deriveAllKeys(username, password, this.#appId);
    const challengeRes = await this.#fetch('/api/v1/auth/challenge', {
      method: 'POST',
      retry: true, // generates a fresh nonce per call — safe to retry
      body: { credential_lookup_key: keys.credentialLookupKey },
    });

    if (challengeRes.status === 404) {
      throw new Error('Account not found');
    }
    if (challengeRes.status !== 200) {
      throw new Error(`Challenge failed: ${challengeRes.json?.error || challengeRes.status}`);
    }

    this.#credentialLookupKey = keys.credentialLookupKey;
    this.#credentialEncryptionKey = keys.credentialEncryptionKey;
    this.#signingKeyPair = keys.signingKeyPair;
    this.#dataLookupKey = challengeRes.json.data_lookup_key;

    // Unwrap the DEK chain via the password factor.
    const unwrapped = await unwrapDataKeyChain(
      challengeRes.json.wrapped_data_key,
      keys.credentialEncryptionKey.kwKey,
    );
    this.#dekByGen = unwrapped.dekByGen;
    this.#currentGen = unwrapped.currentGen;
    this.#username = username;
    this.#sharingKeyPair = keys.sharingKeyPair;
    // Capture the recovery-factor metadata so a subsequent changeCredentials()
    // can preserve existing recovery wrappings without requiring the user to
    // re-enter the phrase. Login does NOT reveal the recovery_lookup_key (the
    // server doesn't return it on the password-side challenge);
    // recoveryLookupKey stays null until the next register or recoverAccount
    // call repopulates it.
    {
      const reparsed = parseWrappedDataKey(challengeRes.json.wrapped_data_key);
      const wrappingsByGen = new Map<number, string>();
      for (const entry of reparsed.dekChain) {
        const w = entry.wrappings.find(w => w.factor === FACTOR_RECOVERY_PHRASE);
        if (w) wrappingsByGen.set(entry.gen, w.wrappedBase64);
      }
      this.#recoveryFactorMeta = {
        salt: unwrapped.recovery.salt,
        kdfParams: unwrapped.recovery.kdfParams,
        wrappingsByGen,
      };
      this.#capturePasskeyWrappings(reparsed);
    }
    this.#recoveryLookupKey = null;

    // Verify
    await this.#verifyChallenge(challengeRes.json.nonce);

    return { dataLookupKey: this.#dataLookupKey };
  }

  /**
   * Change credentials (username and/or password). Requires an active session.
   *
   * Forward-secret DEK rotation: on every credential change, mint a fresh
   * random DEK at gen N+1 and append to the chain. Existing gens stay
   * accessible (re-wrapped under the new credential_encryption_key) so prior
   * data is still readable.
   *
   * Recovery factor handling:
   * - Old gens' recovery wrappings are PRESERVED verbatim — we don't have the
   *   recovery KEK in this code path (user is logged in via password), so we
   *   can't re-wrap. AES-KW is deterministic anyway: re-wrapping the same DEK
   *   under the same recovery KEK would produce identical bytes, so preserving
   *   is byte-equivalent.
   * - The NEW gen (N+1) gets a recovery wrapping when the caller passes
   *   `phrase`. Required by default: without it, the new gen has only a
   *   password wrapping, and recovery for data written under that gen is not
   *   possible until the user runs `recoverAccount` (or, once implemented,
   *   the planned `rotateAccountKey` primitive) to repair the gap. Apps with
   *   a non-interactive flow that knowingly accepts the gap may pass
   *   `acceptRecoveryGap: true`.
   *
   * Connection-side identity rotation (sharing §13.5): after the credential
   * blob is published, this method announces the new sharing + signing pubkeys
   * to every connection by publishing a `rotate_identity` entry to each
   * connection's OLD outbound log under OLD per-pair keys. Connections' clients
   * pick up the rotation on their next read/sync, update the connection record,
   * and switch to the new keys without user intervention. The known limitation
   * about rotation under compromised OLD keys (sharing §13.5) is accepted for
   * v1; out-of-band recovery is the documented response.
   *
   * Passkey re-tap (Phase 6.1):
   * - If the account has any registered passkeys, the SDK MUST re-wrap the
   *   new gen under each of them so the passkey factor stays usable for
   *   data written post-change. The SDK has no PRF outputs cached, so the
   *   user must physically re-tap each registered authenticator at change
   *   time. The caller supplies a `passkeyTapHandler` that surfaces the
   *   per-credential tap UI; the handler returns true to proceed or false
   *   to skip. If WebAuthn fails (authenticator unavailable, user
   *   dismissed, etc.) the credential is left without a new-gen wrapping
   *   and becomes "stale" — the next `authenticateWithPasskey()` for that
   *   credential will surface a stale-credential repair flow.
   * - If passkeys are registered and `passkeyTapHandler` is omitted, this
   *   method throws. Apps are expected to know about the tap requirement
   *   and supply a handler — silently producing stale credentials would
   *   be a worse UX failure than refusing to proceed.
   *
   * @param {string} newUsername
   * @param {string} newPassword
   * @param {{
   *   phrase?: string,
   *   acceptRecoveryGap?: boolean,
   *   skipRotationAnnounce?: boolean,
   *   passkeyTapHandler?: (cred: { credentialId: string; deviceLabel: string | null }) => Promise<boolean>,
   * }} [opts]
   *   - `phrase`: BIP39 account key. Required unless `acceptRecoveryGap:
   *     true` is set. Extends the recovery wrapping to gen N+1.
   *   - `acceptRecoveryGap`: opt out of the phrase requirement. The new gen
   *     ships without a recovery wrapping.
   *   - `skipRotationAnnounce`: skip the §13.5 rotation announcement to
   *     connections. Used by tests + low-level flows that intentionally manage
   *     identity rotation themselves; production callers should leave it
   *     unset (default false).
   */
  async changeCredentials(newUsername: string, newPassword: string, opts: any = {}): Promise<any> {
    await this.#requireAuth();

    // Phrase is required by default. Skipping it leaves the new gen without a
    // recovery wrapping; if the user later forgets the password, data written
    // under the new gen is lost.
    if (!opts.phrase && opts.acceptRecoveryGap !== true) {
      throw new Error(
        'changeCredentials(): must supply `phrase` (the account key) ' +
        'so the new generation gets a recovery wrapping. Pass `acceptRecoveryGap: true` ' +
        'to override (the new gen will be unrecoverable via the account key until repaired).',
      );
    }

    const [newKeys, newShareLookupKey] = await Promise.all([
      deriveAllKeys(newUsername, newPassword, this.#appId),
      deriveShareLookupKey(newUsername, this.#appId),
    ]);
    const newPublicKey = await exportPublicKey(newKeys.signingKeyPair.publicKey);
    // Sharing keypair rotates with master_key (depends on both username and
    // password). The discoverability flag is preserved by the API when
    // omitted; let `opts.shareDiscoverable` override it for callers that also
    // want to flip it as part of the credential change.
    const newSharePub = encodeSharePub(newKeys.sharingKeyPair.publicKey);

    if (!this.#recoveryFactorMeta) {
      // Should never happen — every account has a recovery factor at register.
      throw new Error('changeCredentials(): missing recovery-factor metadata (corrupt session?)');
    }

    // Multi-factor re-wrap. Build the new chain (existing gens + a fresh
    // gen N+1), re-wrap every gen under the new password KEK, preserve the
    // existing recovery wrappings byte-for-byte, and (when `phrase` was
    // supplied) extend the recovery wrapping to gen N+1.
    const nextGen = this.#currentGen! + 1;
    const newDek = await generateRandomDataKey();

    const chain: Array<{ gen: number; key: CryptoKey }> = [];
    for (const [gen, pair] of this.#dekByGen!) {
      chain.push({ gen, key: pair.gcmKey });
    }
    chain.push({ gen: nextGen, key: newDek.gcmKey });
    chain.sort((a, b) => a.gen - b.gen);

    const reWrappedPassword = new Map<number, string>();
    for (const entry of chain) {
      const wrappedBase64 = await this.#wrapDekRaw(entry.key, newKeys.credentialEncryptionKey.kwKey);
      reWrappedPassword.set(entry.gen, wrappedBase64);
    }

    const recoveryWrappingsByGen = new Map<number, string>();
    for (const [gen, b64] of this.#recoveryFactorMeta.wrappingsByGen) {
      recoveryWrappingsByGen.set(gen, b64);
    }
    if (opts.phrase) {
      const validation = validateAccountKey(opts.phrase);
      if (!validation.valid) {
        throw new Error(`changeCredentials(): invalid phrase: ${validation.reason}`);
      }
      const recKEK = await deriveRecoveryKey(
        validation.normalized,
        this.#recoveryFactorMeta.salt,
        this.#recoveryFactorMeta.kdfParams,
      );
      const wrappedNewGen = await this.#wrapDekRaw(newDek.gcmKey, recKEK.kwKey);
      recoveryWrappingsByGen.set(nextGen, wrappedNewGen);
    }

    // Phase 6.1: passkey re-tap. If the account has registered passkeys we
    // need to re-wrap the new-gen DEK under each one's PRF-derived wrapping
    // key so passkey auth still unwraps post-change data. The PRF output is
    // not in our cache (PRF outputs are never persisted) — the user must
    // physically tap each authenticator. Credentials whose tap is skipped
    // or fails become "stale" — no new-gen wrapping — and the next
    // authenticate-with-passkey hits the stale-credential refresh path.
    const newGenPasskeyWraps = await this.#collectNewGenPasskeyWraps(
      newDek.gcmKey,
      opts.passkeyTapHandler,
    );

    const wireChain = chain.map(({ gen }) => {
      const wrappings: Array<{ factor: string; wrappedBase64: string; credentialId?: string }> = [
        { factor: FACTOR_PASSWORD, wrappedBase64: reWrappedPassword.get(gen)! },
      ];
      const recWrap = recoveryWrappingsByGen.get(gen);
      if (recWrap !== undefined) {
        wrappings.push({ factor: FACTOR_RECOVERY_PHRASE, wrappedBase64: recWrap });
      }
      // Phase 6: preserve passkey wrappings byte-for-byte for existing
      // gens. AES-KW is deterministic, so a re-wrap under the same PRF
      // KEK would produce identical bytes — preserving avoids the tap.
      const passkeyList = this.#passkeyWrappingsByGen.get(gen) ?? [];
      for (const pk of passkeyList) {
        wrappings.push({
          factor: FACTOR_PASSKEY_PRF,
          wrappedBase64: pk.wrappedBase64,
          credentialId: pk.credentialId,
        });
      }
      // Phase 6.1: new-gen passkey wrappings, one per credential the user
      // re-tapped. Credentials whose tap was skipped/failed simply have
      // no entry here (handled by the stale-credential refresh path).
      if (gen === nextGen) {
        for (const pk of newGenPasskeyWraps) {
          wrappings.push({
            factor: FACTOR_PASSKEY_PRF,
            wrappedBase64: pk.wrappedBase64,
            credentialId: pk.credentialId,
          });
        }
      }
      return { gen, wrappings };
    });

    const newWrappedDataKey: string = buildEnvelope(
      wireChain,
      { salt: this.#recoveryFactorMeta.salt, kdfParams: this.#recoveryFactorMeta.kdfParams },
    );

    const newDekByGen = new Map(this.#dekByGen!);
    newDekByGen.set(nextGen, { gcmKey: newDek.gcmKey, kwKey: newDek.kwKey });
    const newCurrentGen = nextGen;
    const newRecoveryFactorMeta: RecoveryFactorMeta = {
      salt: this.#recoveryFactorMeta.salt,
      kdfParams: this.#recoveryFactorMeta.kdfParams,
      wrappingsByGen: recoveryWrappingsByGen,
    };

    // Capture OLD key material BEFORE the PUT swaps things over. The
    // rotation-announce flow (§13.5) needs OLD share_priv + OLD signing_priv
    // to derive the OLD per-pair keys and sign the announcement under the
    // key Bob has cached. Pause non-rotation share-log writes during the
    // rotation window per §13.5; we accomplish this implicitly because the
    // rotation announce + new-log snapshots run inline before the method
    // returns control to the caller.
    const oldSharingKeyPair = this.#sharingKeyPair;
    const oldSigningKeyPair = this.#signingKeyPair;
    const skipRotationAnnounce = opts.skipRotationAnnounce === true;

    // Hydrate outbound state per connection BEFORE the swap so we can publish
    // meaningful seq=0 snapshots to the NEW logs after rotation. Hydration
    // runs against the OLD per-pair keys (still cached) and reads our own
    // outbound entries from the OLD logs. Only loads the connections record
    // when we're going to announce (skipRotationAnnounce keeps test surfaces
    // clean for unit tests that mock fetch without a connections record).
    let oldConnectionsState: { record: { connections: any[]; [k: string]: any }; txid: string | null } = { record: { connections: [] }, txid: null };
    const outboundStateByConnection = new Map();
    if (!skipRotationAnnounce) {
      try {
        oldConnectionsState = await this.#loadConnectionsRecord();
      } catch (err: any) {
        console.warn(
          `[TarnClient] changeCredentials: connections record load failed (no rotation announce): ${err.message}`,
        );
      }
      for (const connection of oldConnectionsState.record.connections) {
        try {
          await this.#hydrateOutboundState(connection);
          outboundStateByConnection.set(connection.share_pub, this.#tentativeOutboundState(connection));
        } catch (err: any) {
          console.warn(
            `[TarnClient] changeCredentials: outbound state hydration failed for ${connection.share_pub.slice(0, 8)}...: ${err.message}`,
          );
          outboundStateByConnection.set(connection.share_pub, {});
        }
      }
    }

    const res = await this.#fetch('/api/v1/auth', {
      method: 'PUT',
      auth: true,
      body: {
        new_credential_lookup_key: newKeys.credentialLookupKey,
        new_public_key: newPublicKey,
        new_wrapped_data_key: newWrappedDataKey,
        new_share_pub: newSharePub,
        new_share_lookup_key: newShareLookupKey,
        ...(opts.shareDiscoverable != null
          ? { new_share_discoverable: opts.shareDiscoverable !== false }
          : {}),
      },
    });

    if (res.status !== 200) {
      throw new Error(`Credential change failed: ${res.json?.error || res.status}`);
    }

    // §7 invalidation: signing/DEK rotation makes any prior session blob
    // un-resumable. Wipe the IndexedDB wrapping key so prior blobs become
    // unreadable on this origin. Best-effort — IndexedDB failure must not
    // fail the credential operation.
    try { await this.clearSession(); } catch {}

    // §13.5 step 4: with the new credential blob published (durable
    // indicator of rotation in flight), publish a `rotate_identity`
    // announcement to every connection's OLD outbound log under OLD pair keys.
    // The OLD signing_priv proves authenticity to the connection (their cached
    // signing_pub still matches OLD).
    let rotationAnnouncements = [];
    if (!skipRotationAnnounce && oldConnectionsState.record.connections.length > 0) {
      try {
        rotationAnnouncements = await this.#announceIdentityRotationToConnections({
          oldSharingKeyPair,
          oldSigningKeyPair,
          oldConnectionsRecord: oldConnectionsState.record,
          newSharingPublicKey: newKeys.sharingKeyPair.publicKey,
          newSigningPublicKey: newKeys.signingKeyPair.publicKey,
          newCredentialLookupKey: newKeys.credentialLookupKey,
          rotatedAt: Math.floor(Date.now() / 1000),
        });
      } catch (err: any) {
        console.warn(`[TarnClient] changeCredentials: rotation announce failed: ${err.message}`);
      }
    }

    this.#credentialLookupKey = newKeys.credentialLookupKey;
    this.#credentialEncryptionKey = newKeys.credentialEncryptionKey;
    this.#signingKeyPair = newKeys.signingKeyPair;
    this.#dekByGen = newDekByGen;
    this.#currentGen = newCurrentGen;
    this.#recoveryFactorMeta = newRecoveryFactorMeta;
    // Phase 6.1: refresh the passkey-wrappings snapshot so subsequent
    // envelope-mutating ops in this session preserve the just-emitted
    // wrappings (including any new-gen wrappings the user re-tapped for).
    try {
      this.#capturePasskeyWrappings(parseWrappedDataKey(newWrappedDataKey));
    } catch {
      // Reparse failure is theoretically impossible — we just built the
      // envelope. Fall back to clearing the snapshot rather than leaving
      // it stale; the next login() rehydrates anyway.
      this.#passkeyWrappingsByGen = new Map();
    }
    this.#username = newUsername;
    this.#sharingKeyPair = newKeys.sharingKeyPair;
    // Per-pair S_AB is derived from share_priv, which just rotated — every
    // cached entry is stale. The NEW pair keys are derived lazily on first
    // use via #getPairKeysFor (post-rotation).
    this.#pairKeyCache.clear();
    this.#shareLogCounters.clear();
    this.#readStateCache.clear();
    this.#outboundStateCache.clear();
    this.#publishedTxidsByConnection.clear();
    this.#mutedConnectionsState = null;
    this.#issuedInvitesState = null;

    await this.#authenticate();

    // §13.5 step 8: publish a fresh seq=0 snapshot to every connection's NEW
    // outbound log so the recipient bootstraps the new log with the
    // expected state. Best-effort: a per-connection failure is logged and the
    // method still returns success — the connection can re-bootstrap once we
    // publish later operations.
    if (!skipRotationAnnounce) {
      for (const connection of oldConnectionsState.record.connections) {
        const state = outboundStateByConnection.get(connection.share_pub) ?? {};
        try {
          await this._publishInitialSnapshot(connection, { state });
        } catch (err: any) {
          console.warn(
            `[TarnClient] changeCredentials: NEW-log seq=0 snapshot publish failed for ${connection.share_pub.slice(0, 8)}...: ${err.message}`,
          );
        }
      }
    }

    return { rotationAnnouncements };
  }

  /**
   * Phase 6 helper. Snapshot all `passkey_prf` wrappings from a parsed
   * envelope into `#passkeyWrappingsByGen` so envelope-mutating flows
   * (changeCredentials, rotateAccountKey, recoverAccount) can re-emit
   * them verbatim without holding the PRF outputs. Cleared and rebuilt
   * on every successful auth round trip.
   */
  #capturePasskeyWrappings(parsed: ReturnType<typeof parseWrappedDataKey>): void {
    const m = new Map<number, Array<{ credentialId: string; wrappedBase64: string }>>();
    for (const entry of parsed.dekChain) {
      const list: Array<{ credentialId: string; wrappedBase64: string }> = [];
      for (const w of entry.wrappings) {
        if (w.factor === FACTOR_PASSKEY_PRF && w.credentialId) {
          list.push({ credentialId: w.credentialId, wrappedBase64: w.wrappedBase64 });
        }
      }
      if (list.length > 0) m.set(entry.gen, list);
    }
    this.#passkeyWrappingsByGen = m;
  }

  /**
   * Wrap a single DEK CryptoKey under an AES-KW wrapping key, returning the
   * raw base64 ciphertext. Thin convenience used by the changeCredentials
   * re-wrap loop so we can build wrappings imperatively without the
   * higher-level envelope helpers.
   */
  async #wrapDekRaw(dekGcmKey: CryptoKey, wrappingKey: CryptoKey): Promise<string> {
    const wrapped = await crypto.subtle.wrapKey('raw', dekGcmKey, wrappingKey, 'AES-KW');
    return bytesToBase64(new Uint8Array(wrapped));
  }

  /**
   * Phase 6.1 — collect new-gen passkey wrappings during `changeCredentials`.
   *
   * For each registered passkey on the account, surface a per-credential
   * tap prompt via the supplied handler. If the user proceeds and the
   * WebAuthn ceremony completes, derive the PRF-based wrapping key and
   * wrap the new-gen DEK under it. Returns an array of
   * `{credentialId, wrappedBase64}` for every credential that succeeded;
   * skipped/failed credentials are simply absent from the result (they
   * become "stale" on the new gen and the next authenticateWithPasskey
   * call surfaces the refresh path).
   *
   * Throws if the account has registered passkeys and no handler was
   * supplied — silent stale credentials would be a worse UX failure than
   * refusing to proceed.
   */
  async #collectNewGenPasskeyWraps(
    newDekGcmKey: CryptoKey,
    handler?: (cred: { credentialId: string; deviceLabel: string | null }) => Promise<boolean>,
  ): Promise<Array<{ credentialId: string; wrappedBase64: string }>> {
    // Distinct credentialIds across all gens. The snapshot may have a
    // credential present at gen 1 but absent at the latest gen (legacy
    // stale state from a prior changeCredentials that ran without a
    // handler). Treat the union as "registered passkeys" — re-tapping
    // any of them gives us a chance to repair the gap.
    const credentialIds = new Set<string>();
    for (const list of this.#passkeyWrappingsByGen.values()) {
      for (const pk of list) credentialIds.add(pk.credentialId);
    }
    if (credentialIds.size === 0) return [];

    if (typeof handler !== 'function') {
      throw new Error(
        'changeCredentials(): account has registered passkeys but no `passkeyTapHandler` ' +
          'was supplied. Pass a handler that prompts the user to tap each authenticator, ' +
          'or remove the passkey(s) first via tarn.passkeys.remove().',
      );
    }

    // Best-effort: enrich with device labels from the server so the
    // handler can surface a friendly prompt. A network failure here is
    // not fatal — fall back to credentialId-only entries.
    let labels = new Map<string, string | null>();
    try {
      const list = await this.listPasskeys();
      for (const p of list) labels.set(p.credentialId, p.deviceLabel);
    } catch (err: any) {
      console.warn(
        `[TarnClient] changeCredentials: listPasskeys() failed (continuing without device labels): ${err?.message || err}`,
      );
    }

    const results: Array<{ credentialId: string; wrappedBase64: string }> = [];
    // Sequential — the WebAuthn ceremony is modal per browser, so the
    // user can only tap one authenticator at a time.
    for (const credentialId of credentialIds) {
      const deviceLabel = labels.get(credentialId) ?? null;
      let proceed = false;
      try {
        proceed = await handler({ credentialId, deviceLabel });
      } catch (err: any) {
        console.warn(
          `[TarnClient] changeCredentials: passkeyTapHandler threw for ${credentialId.slice(0, 8)}…; treating as skip: ${err?.message || err}`,
        );
        proceed = false;
      }
      if (!proceed) continue;

      let wrappedBase64: string | null = null;
      try {
        wrappedBase64 = await this.#deriveAndWrapForPasskey(credentialId, newDekGcmKey);
      } catch (err: any) {
        // WebAuthn failure (user dismissed, no authenticator, sig fail).
        // Mark stale by simply not adding to results.
        console.warn(
          `[TarnClient] changeCredentials: re-tap failed for ${credentialId.slice(0, 8)}…; credential will be stale on new gen: ${err?.message || err}`,
        );
        wrappedBase64 = null;
      }
      if (wrappedBase64) {
        results.push({ credentialId, wrappedBase64 });
      }
    }
    return results;
  }

  /**
   * Drive a WebAuthn assertion against a specific credential, derive the
   * PRF-based wrapping key, and wrap the supplied DEK under it. Returns
   * the base64-encoded wrap. Throws on any WebAuthn / PRF failure.
   *
   * Used both by `#collectNewGenPasskeyWraps` (re-tap during
   * changeCredentials) and `authenticateWithPasskey` (the stale-credential
   * refresh helper). Centralized here so both paths use the identical
   * options-fetch + assertion + KEK-derivation chain.
   */
  async #deriveAndWrapForPasskey(credentialId: string, dekGcmKey: CryptoKey): Promise<string> {
    const optsRes = await this.#fetch('/api/v1/auth/passkey/authentication-options', {
      method: 'POST',
      retry: false,
      body: { credential_id: credentialId },
    });
    if (optsRes.status !== 200) {
      throw new Error(
        `passkey authentication-options failed: ${optsRes.json?.error || optsRes.status}`,
      );
    }
    const pkOptions = optsRes.json?.options;
    if (!pkOptions) {
      throw new Error('passkey authentication-options: server did not return options');
    }
    // Note: we deliberately do NOT submit the assertion to
    // /auth/passkey/authenticate here — we only need the PRF output to
    // derive a wrapping key. The challenge will eventually time out and
    // get pruned (60 s TTL); no replay risk because consume-on-use binds
    // it to /authenticate. For environments where this matters, a future
    // /auth/passkey/prf-only options endpoint could mint a non-auth
    // challenge specifically for re-wrapping ceremonies.
    const { startAuthentication } = await import('@simplewebauthn/browser');
    const credential = await startAuthentication({ optionsJSON: pkOptions });
    const prfResults = (credential as any)?.clientExtensionResults?.prf?.results?.first;
    if (!prfResults) {
      throw new Error('passkey re-tap: PRF extension produced no output');
    }
    const prfOutput = new Uint8Array(prfResults);
    const { kwKey: passkeyKEK } = await derivePasskeyWrappingKey(prfOutput);
    return this.#wrapDekRaw(dekGcmKey, passkeyKEK);
  }

  /**
   * Phase 3 (RECOVERY_PLAN.md) — Model B account-key retrieval.
   *
   * Orchestrates the full step-up gated flow:
   *   1. Derive credential keys from the freshly re-entered password.
   *   2. POST /auth/challenge → nonce
   *   3. Sign nonce, POST /auth/step-up { scope: "account_key_fetch" }
   *      → single-use step-up token (60s TTL)
   *   4. GET /account/account-key with the session JWT + step-up token
   *      → { wrapped_account_key, recovery_lookup_key, ... }
   *   5. AES-GCM-decrypt the wrap under DEK_gen1 with AAD
   *      "tarn-wrapped-account-key-v1".
   *   6. Wrap-pinning check: derive recovery_lookup_key from the decrypted
   *      account-key entropy (same chain `recoverAccount` uses) and compare
   *      to the value the server returned. Mismatch → throw
   *      AccountKeyPinningError without returning the phrase.
   *
   * The SDK does NOT cache or retain the returned account key — the caller
   * is responsible for surfacing it to the user briefly and dropping the
   * in-memory copy as soon as possible.
   *
   * @param opts - Must contain `password` (the freshly re-entered password).
   * @returns `{ accountKey: string }` on success.
   * @throws AccountKeyPinningError on wrap-pinning failure.
   * @throws Error with message containing "no_account_key_stored" for Model
   *   A accounts (caller renders "no backup stored" UI).
   * @throws Error on wrong password (step-up fails), expired token,
   *   network failure, or AES-GCM decryption failure.
   */
  async viewAccountKey(opts: { password: string }): Promise<{ accountKey: string }> {
    await this.#requireAuth();
    if (!opts || typeof opts.password !== 'string' || opts.password.length === 0) {
      throw new Error('viewAccountKey(): password is required');
    }
    if (!this.#username) {
      throw new Error('viewAccountKey(): username unknown — log in first');
    }
    if (!this.#dekByGen || !this.#dekByGen.has(1)) {
      throw new Error('viewAccountKey(): DEK_gen1 not available (corrupt session?)');
    }
    const dekGen1 = this.#dekByGen.get(1)!;

    // Step 1: re-derive credential keys from the freshly-entered password.
    const reKeys = await deriveAllKeys(this.#username, opts.password, this.#appId);

    // Step 2: fresh challenge for this credential.
    const challengeRes = await this.#fetch('/api/v1/auth/challenge', {
      method: 'POST',
      retry: true,
      body: { credential_lookup_key: reKeys.credentialLookupKey },
    });
    if (challengeRes.status !== 200) {
      throw new Error(`viewAccountKey(): challenge failed: ${challengeRes.json?.error || challengeRes.status}`);
    }

    // Step 3: sign + step-up.
    const signature = await signChallenge(reKeys.signingKeyPair.privateKey, challengeRes.json.nonce);
    const stepUpRes = await this.#fetch('/api/v1/auth/step-up', {
      method: 'POST',
      body: {
        credential_lookup_key: reKeys.credentialLookupKey,
        nonce: challengeRes.json.nonce,
        signature,
        scope: 'account_key_fetch',
      },
    });
    if (stepUpRes.status === 401) {
      throw new Error('viewAccountKey(): step-up auth failed (wrong password?)');
    }
    if (stepUpRes.status !== 200) {
      throw new Error(`viewAccountKey(): step-up failed: ${stepUpRes.json?.error || stepUpRes.status}`);
    }
    const stepUpToken = stepUpRes.json.step_up_token;
    if (!stepUpToken) {
      throw new Error('viewAccountKey(): step-up succeeded but no token returned');
    }

    // Step 4: fetch the wrap. Must include BOTH the session JWT and the
    // single-use step-up token. Use #fetchRaw so we can attach the custom
    // X-Step-Up-Token header.
    const fetchRes = await this.#fetchRaw('/api/v1/account/account-key', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${this.#jwt}`,
        'X-Step-Up-Token': stepUpToken,
        'Content-Type': 'application/json',
      },
    });
    const fetchText = await fetchRes.text();
    let fetchJson: any = null;
    try { fetchJson = JSON.parse(fetchText); } catch {}

    if (fetchRes.status === 404 && fetchJson?.error === 'no_account_key_stored') {
      throw new Error('viewAccountKey(): no_account_key_stored — this account is in Model A');
    }
    if (fetchRes.status !== 200) {
      throw new Error(`viewAccountKey(): fetch failed: ${fetchJson?.error || fetchRes.status}`);
    }
    const { wrapped_account_key, recovery_lookup_key } = fetchJson || {};
    if (!wrapped_account_key) {
      throw new Error('viewAccountKey(): server returned no wrapped_account_key');
    }

    // Step 5: decrypt the wrap with DEK_gen1 + fixed AAD.
    let phrase: string;
    try {
      phrase = await unwrapAccountKey(dekGen1.gcmKey, wrapped_account_key);
    } catch (err: any) {
      throw new Error(`viewAccountKey(): wrap decryption failed: ${err?.message || err}`);
    }

    // Step 6: wrap-pinning. Derive recovery_lookup_key from the decrypted
    // entropy and compare to the server-stored value. Mismatch implies the
    // wrap doesn't belong to this account — refuse to return it.
    if (recovery_lookup_key) {
      const validation = validateAccountKey(phrase);
      if (!validation.valid) {
        throw new AccountKeyPinningError(
          `Decrypted wrap is not a valid account key: ${validation.reason}`,
        );
      }
      const entropy = accountKeyToEntropy(validation.normalized);
      const derived = await deriveRecoveryLookupKey(entropy, this.#appId);
      if (derived !== recovery_lookup_key) {
        throw new AccountKeyPinningError();
      }
    }

    return { accountKey: phrase };
  }

  /**
   * Phase 4 (RECOVERY_PLAN.md) — internal helper. Run the step-up
   * challenge/sign/exchange dance and return the resulting opaque token.
   * Throws on any failure; the token is single-use and 60s-TTL.
   *
   * Used by enableKeyStorage / disableKeyStorage (PUT/DELETE on
   * /account/account-key both require step-up). viewAccountKey runs the
   * same flow inline today; we don't extract its copy to avoid churning
   * the Phase 3 path mid-Phase-4.
   */
  async #performStepUp(password: string, scope: string): Promise<string> {
    if (!this.#username) {
      throw new Error('#performStepUp: username unknown — log in first');
    }
    const reKeys = await deriveAllKeys(this.#username, password, this.#appId);
    const challengeRes = await this.#fetch('/api/v1/auth/challenge', {
      method: 'POST',
      retry: true,
      body: { credential_lookup_key: reKeys.credentialLookupKey },
    });
    if (challengeRes.status !== 200) {
      throw new Error(`step-up challenge failed: ${challengeRes.json?.error || challengeRes.status}`);
    }
    const signature = await signChallenge(reKeys.signingKeyPair.privateKey, challengeRes.json.nonce);
    const stepUpRes = await this.#fetch('/api/v1/auth/step-up', {
      method: 'POST',
      body: {
        credential_lookup_key: reKeys.credentialLookupKey,
        nonce: challengeRes.json.nonce,
        signature,
        scope,
      },
    });
    if (stepUpRes.status === 401) {
      throw new Error('step-up auth failed (wrong password?)');
    }
    if (stepUpRes.status !== 200) {
      throw new Error(`step-up failed: ${stepUpRes.json?.error || stepUpRes.status}`);
    }
    const token = stepUpRes.json.step_up_token;
    if (!token) {
      throw new Error('step-up succeeded but no token returned');
    }
    return token;
  }

  /**
   * Phase 4 — enable Model B storage (Model A → Model B).
   *
   * The caller passes the freshly-entered password (drives the step-up
   * proof + DEK derivation) AND the user's existing account key (the SDK
   * does not retain it post-registration; the app prompts the user to
   * type their saved key, validates it via `validateAccountKey`, and
   * passes it here).
   *
   * Flow:
   *   1. Validate the supplied account key (BIP39 checksum).
   *   2. Re-derive credential keys + DEK from the password (step-up dance).
   *   3. Wrap the account key under DEK_gen1 with the v1 AAD.
   *   4. Wrap-pinning client-side: derive `recovery_lookup_key` from the
   *      supplied key and confirm it matches the value cached on the
   *      client (recovered via parseWrappedDataKey on prior login). This
   *      catches "user typed a valid-but-wrong 24-word phrase" before we
   *      poison the server with a wrap that decrypts to the wrong key.
   *   5. PUT /account/account-key with JWT + step-up token.
   *   6. Update the cached `account_key_stored` indicator.
   *
   * @returns `{ stored: true }` on success.
   * @throws Error on invalid phrase, wrong password (step-up fails), or
   *   pin-check mismatch (the server-known recovery_lookup_key does not
   *   match what derives from the supplied phrase).
   */
  async enableKeyStorage(opts: { password: string; accountKey: string }): Promise<{ stored: true }> {
    await this.#requireAuth();
    if (!opts || typeof opts.password !== 'string' || opts.password.length === 0) {
      throw new Error('enableKeyStorage(): password is required');
    }
    if (!opts.accountKey || typeof opts.accountKey !== 'string') {
      throw new Error('enableKeyStorage(): accountKey is required');
    }
    const validation = validateAccountKey(opts.accountKey);
    if (!validation.valid) {
      throw new Error(`enableKeyStorage(): invalid account key: ${validation.reason}`);
    }
    if (!this.#username) {
      throw new Error('enableKeyStorage(): username unknown — log in first');
    }
    if (!this.#dekByGen || !this.#dekByGen.has(1)) {
      throw new Error('enableKeyStorage(): DEK_gen1 not available (corrupt session?)');
    }

    // Pre-flight pin: derive recovery_lookup_key from the supplied phrase
    // and compare to what the client knows. We learn the cached value at
    // register-time (#recoveryLookupKey, set in register/recoverAccount).
    // Login does NOT expose it (the password-side challenge response does
    // not reveal it), so on a login-only session we skip the check rather
    // than fail. The server still has the value and the user can recover
    // their way out of any bad wrap via the existing recoverAccount flow.
    const phraseEntropy = accountKeyToEntropy(validation.normalized);
    const derivedLookup = await deriveRecoveryLookupKey(phraseEntropy, this.#appId);
    if (this.#recoveryLookupKey && derivedLookup !== this.#recoveryLookupKey) {
      throw new AccountKeyPinningError(
        'enableKeyStorage(): supplied account key does not match the account on file. ' +
        'Did you type the right phrase? Refusing to store an unrelated key.',
      );
    }

    // Step-up first — fails fast on wrong password before we compute the wrap.
    const stepUpToken = await this.#performStepUp(opts.password, 'account_key_fetch');

    // Compute the wrap under DEK_gen1 with the v1 AAD. The wrap is
    // deterministic w.r.t. (DEK, plaintext, IV); the IV is random, so the
    // ciphertext bytes change per call even for the same phrase — fine,
    // the server stores whatever we send.
    const dekGen1 = this.#dekByGen.get(1)!;
    const wrappedAccountKey = await wrapAccountKey(dekGen1.gcmKey, validation.normalized);

    const res = await this.#fetchRaw('/api/v1/account/account-key', {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${this.#jwt}`,
        'X-Step-Up-Token': stepUpToken,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ wrapped_account_key: wrappedAccountKey }),
    });
    const text = await res.text();
    let json: any = null;
    try { json = JSON.parse(text); } catch {}
    if (res.status !== 200) {
      throw new Error(`enableKeyStorage(): PUT failed: ${json?.error || res.status}`);
    }
    if (json?.stored !== true) {
      throw new Error(`enableKeyStorage(): unexpected response shape: ${text}`);
    }
    this.#accountKeyStored = true;
    return { stored: true };
  }

  /**
   * Phase 4 — disable Model B storage (Model B → Model A).
   *
   * The caller passes only their freshly-entered password (drives the
   * step-up proof). No phrase needed; the server simply nulls the wrap
   * column and republishes the credential blob to Arweave.
   *
   * Idempotent: calling on an account that is already in Model A returns
   * `{ stored: false, alreadyDisabled: true }` (the API returns 200 with
   * `already_disabled: true`).
   *
   * @returns `{ stored: false }` on success.
   * @throws Error on wrong password (step-up fails) or 4xx/5xx response.
   */
  async disableKeyStorage(opts: { password: string }): Promise<{ stored: false; alreadyDisabled?: boolean }> {
    await this.#requireAuth();
    if (!opts || typeof opts.password !== 'string' || opts.password.length === 0) {
      throw new Error('disableKeyStorage(): password is required');
    }
    const stepUpToken = await this.#performStepUp(opts.password, 'account_key_fetch');

    const res = await this.#fetchRaw('/api/v1/account/account-key', {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${this.#jwt}`,
        'X-Step-Up-Token': stepUpToken,
        'Content-Type': 'application/json',
      },
    });
    const text = await res.text();
    let json: any = null;
    try { json = JSON.parse(text); } catch {}
    if (res.status !== 200) {
      throw new Error(`disableKeyStorage(): DELETE failed: ${json?.error || res.status}`);
    }
    if (json?.stored !== false) {
      throw new Error(`disableKeyStorage(): unexpected response shape: ${text}`);
    }
    this.#accountKeyStored = false;
    if (json.already_disabled) {
      return { stored: false, alreadyDisabled: true };
    }
    return { stored: false };
  }

  /**
   * Phase 4 — rotate the account key. The user has indicated they want
   * to evict the current account key (suspected leak, routine hygiene,
   * etc.). The SDK generates a fresh one, derives all dependent values,
   * re-wraps every gen of the DEK chain under {existing password KEK,
   * NEW recovery KEK}, and submits the bundle atomically.
   *
   * Salt rotation: the recovery salt is regenerated as part of this flow.
   * The salt is per-account random; rotating it as part of an explicit
   * "evict the recovery factor" operation is the cleanest reset (a
   * security-scoped attacker who recorded the OLD salt + ciphertext gains
   * nothing against the new state). Previous data wrapped under the OLD
   * salt + OLD KEK remains on Arweave forever (immutable history) but is
   * unwrappable without the OLD phrase, which is now defunct.
   *
   * The caller must have a live session and supply the current password
   * (needed to verify we still hold the existing DEK chain via the local
   * #dekByGen — no server round-trip for the password proof, since
   * rotation is JWT-only at the API).
   *
   * Flow:
   *   1. Generate a new account key.
   *   2. Generate a NEW recovery salt; derive new recovery_KEK,
   *      recovery_lookup_key, recovery_signing_key, recovery_public_key.
   *   3. Re-wrap every gen of the DEK chain under {existing password
   *      KEKs (unchanged — the password did not rotate), NEW recovery
   *      KEK}.
   *   4. If Model B (isStored() === true): compute new wrapped_account_key
   *      under DEK_gen1.
   *   5. POST /account/rotate-account-key with the bundle.
   *   6. Update the cached recovery-factor metadata + #recoveryLookupKey.
   *   7. Return the new account key string. The SDK does NOT retain it.
   *
   * @returns `{ accountKey: string }` on success — the new phrase. The
   *   app surfaces it to the user (downloadable kit, printable page, etc.)
   *   and drops the in-memory copy promptly.
   * @throws Error on wrong password (re-derived password KEK can't unwrap
   *   the existing chain), 409 on lookup-key conflict, or 4xx/5xx response.
   */
  async rotateAccountKey(opts: { password: string }): Promise<{ accountKey: string }> {
    await this.#requireAuth();
    if (!opts || typeof opts.password !== 'string' || opts.password.length === 0) {
      throw new Error('rotateAccountKey(): password is required');
    }
    if (!this.#username) {
      throw new Error('rotateAccountKey(): username unknown — log in first');
    }
    if (!this.#dekByGen || this.#dekByGen.size === 0) {
      throw new Error('rotateAccountKey(): DEK chain unavailable (corrupt session?)');
    }

    // Re-derive password keys from the current password. We use this both
    // as a wrong-password tripwire (the credential_lookup_key must match
    // what we already have) and as the source of the password KEK for
    // re-wrapping the chain.
    const reKeys = await deriveAllKeys(this.#username, opts.password, this.#appId);
    if (this.#credentialLookupKey && reKeys.credentialLookupKey !== this.#credentialLookupKey) {
      throw new Error('rotateAccountKey(): wrong password — credential mismatch');
    }

    // 1. Generate a new account key + 2. derive new recovery state
    //    (new salt + KEK + lookup + signing).
    const newPhrase = generateAccountKey();
    const newPhraseEntropy = accountKeyToEntropy(newPhrase);
    const newRecoverySalt = generateRecoverySalt();
    const [newRecoveryKEK, newRecoveryLookupKey, newRecoverySigningKeyPair] = await Promise.all([
      deriveRecoveryKey(newPhrase, newRecoverySalt),
      deriveRecoveryLookupKey(newPhraseEntropy, this.#appId),
      deriveRecoverySigningKeyPair(newPhraseEntropy, this.#appId),
    ]);
    const newRecoveryPublicKey = await exportPublicKey(newRecoverySigningKeyPair.publicKey);

    // 3. Re-wrap every gen under {existing password KEK, NEW recovery KEK}.
    //    Build the chain in gen order and wrap each entry under both
    //    factors; new salt goes into the envelope's recovery section.
    const chain: Array<{ gen: number; key: CryptoKey }> = [];
    for (const [gen, pair] of this.#dekByGen!) {
      chain.push({ gen, key: pair.gcmKey });
    }
    chain.sort((a, b) => a.gen - b.gen);

    // Phase 6: preserve passkey wrappings byte-for-byte. Rotation
    // changes the recovery factor only — the underlying DEKs and any
    // registered passkeys are unaffected.
    const passkeyExtras = new Map<number, Array<{ factor: string; wrappedBase64: string; credentialId: string }>>();
    for (const [gen, list] of this.#passkeyWrappingsByGen) {
      passkeyExtras.set(gen, list.map(p => ({
        factor: FACTOR_PASSKEY_PRF,
        wrappedBase64: p.wrappedBase64,
        credentialId: p.credentialId,
      })));
    }

    const newWrappedDataKey = await wrapDataKeyChainEnvelope(
      chain,
      [
        { name: FACTOR_PASSWORD,        wrappingKey: reKeys.credentialEncryptionKey.kwKey },
        { name: FACTOR_RECOVERY_PHRASE, wrappingKey: newRecoveryKEK.kwKey },
      ],
      { salt: newRecoverySalt },
      passkeyExtras,
    );

    // 4. New wrap_account_key only if Model B. We treat #accountKeyStored
    //    as the source of truth here; if it's null (resumed session that
    //    never re-verified), we play it safe and skip the wrap. The user
    //    can re-enable storage explicitly via enableKeyStorage afterwards.
    let newWrappedAccountKey: string | null = null;
    if (this.#accountKeyStored === true) {
      const dekGen1 = this.#dekByGen!.get(1);
      if (!dekGen1) {
        throw new Error('rotateAccountKey(): DEK_gen1 missing — cannot compute wrap (chain corruption?)');
      }
      newWrappedAccountKey = await wrapAccountKey(dekGen1.gcmKey, newPhrase);
    }

    // 5. Submit. The API performs an atomic UPDATE across all four fields.
    const res = await this.#fetch('/api/v1/account/rotate-account-key', {
      method: 'POST',
      auth: true,
      body: {
        new_envelope: newWrappedDataKey,
        new_recovery_lookup_key: newRecoveryLookupKey,
        new_recovery_public_key: newRecoveryPublicKey,
        new_wrapped_account_key: newWrappedAccountKey,
      },
    });
    if (res.status === 409) {
      // Salt + entropy collision yielding the same recovery_lookup_key as
      // another account is astronomically unlikely (HMAC over 32 random
      // bytes → 256-bit space), but propagate the conflict cleanly so the
      // app can prompt a retry.
      throw new Error(`rotateAccountKey(): conflict: ${res.json?.error || 'recovery_lookup_key in use'}`);
    }
    if (res.status !== 200) {
      throw new Error(`rotateAccountKey(): rotation failed: ${res.json?.error || res.status}`);
    }

    // 6. Update cached recovery-factor metadata so a subsequent
    //    changeCredentials() preserves the NEW wrappings (not the old).
    {
      const reparsed = parseWrappedDataKey(newWrappedDataKey);
      const wrappingsByGen = new Map<number, string>();
      for (const entry of reparsed.dekChain) {
        const w = entry.wrappings.find(w => w.factor === FACTOR_RECOVERY_PHRASE);
        if (w) wrappingsByGen.set(entry.gen, w.wrappedBase64);
      }
      this.#recoveryFactorMeta = {
        salt: reparsed.recovery.salt,
        kdfParams: reparsed.recovery.kdfParams,
        wrappingsByGen,
      };
      this.#capturePasskeyWrappings(reparsed);
    }
    this.#recoveryLookupKey = newRecoveryLookupKey;
    // accountKeyStored is unchanged (rotation does not flip the model).

    // 7. Return the new phrase. SDK does NOT cache it.
    return { accountKey: newPhrase };
  }

  // ============ PASSKEYS (Phase 6) ============
  //
  // WebAuthn-PRF passkey factor. Opt-in per account; an account with no
  // registered passkeys behaves exactly as it did before Phase 6.
  //
  // The PRF wrapping is a third independent factor in the dek_chain
  // envelope. Each registered passkey adds one wrapping per gen, keyed
  // by credential_id. Removing a passkey strips its wrappings; the
  // remaining wrappings (password, recovery_phrase, other passkeys)
  // are preserved verbatim.

  /**
   * Feature-detect WebAuthn + PRF support on the current device.
   *
   * Returns false on:
   *   - Non-browser environment (no `navigator.credentials`)
   *   - Browsers without `PublicKeyCredential`
   *   - Platform without an authenticator (`isUserVerifyingPlatformAuthenticatorAvailable`
   *     returns false — typical on a desktop without Touch ID, Windows
   *     Hello, or a security key)
   *   - Browsers without PRF extension support
   *
   * PRF detection is the load-bearing one. The cleanest reliable check
   * (per WebAuthn WG guidance, mid-2026) is to call the static
   * `getClientCapabilities()` method when present (Chrome 132+, Safari
   * 18+ both expose it); if absent, fall back to checking
   * `PublicKeyCredential.prototype.getClientExtensionResults` exists,
   * which signals at minimum that `extensions` is a known field.
   *
   * Apps call this before surfacing any passkey UX. If false, fall back
   * to password-only — the SDK does NOT register a passkey on a device
   * without PRF (the wrap would be unrecoverable on the next login).
   */
  async passkeysSupported(): Promise<boolean> {
    if (typeof navigator === 'undefined' || !navigator.credentials) return false;
    const G = globalThis as any;
    if (typeof G.PublicKeyCredential === 'undefined') return false;
    try {
      // Platform authenticator presence — required (we don't surface
      // roaming-only flows in v1).
      if (typeof G.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
        const ok = await G.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        if (!ok) return false;
      }
      // PRF capability check. The standard exposes
      // `getClientCapabilities()` returning { prf: true } on supporting
      // browsers. Older builds gate on whether the extension shape is
      // recognized in `getClientExtensionResults` — coarse but the only
      // signal pre-getClientCapabilities.
      if (typeof G.PublicKeyCredential.getClientCapabilities === 'function') {
        const caps = await G.PublicKeyCredential.getClientCapabilities();
        return !!(caps && caps.prf === true);
      }
      // Fallback: browsers that don't expose getClientCapabilities and
      // don't recognize PRF will silently drop the extension and return
      // an empty results map — there's no reliable a-priori signal short
      // of attempting a registration. Return false to be safe; apps that
      // want to opportunistically try can call `register()` directly and
      // catch the failure.
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Register a new passkey for the logged-in account. Re-wraps the
   * existing DEK chain to add a `passkey_prf` wrapping per gen, keyed
   * by the new credential_id, and submits both the credential metadata
   * and the new envelope atomically.
   *
   * Flow:
   *   1. POST /auth/passkey/register-options → { options, prf_salt }
   *   2. navigator.credentials.create(options) — user authenticates via
   *      Touch ID / Face ID / Windows Hello / etc. The PRF extension
   *      yields a 32-byte deterministic secret bound to (passkey, salt).
   *   3. Derive an AES-KW wrapping key from the PRF output via HKDF
   *      with the `tarn-passkey-prf-v1` info string.
   *   4. Wrap every gen of the existing DEK chain under the new key.
   *   5. POST /auth/passkey/register with the credential, prf_salt, and
   *      the new envelope. Server stores the credential and atomically
   *      replaces the envelope.
   *
   * @returns `{ credentialId, deviceLabel }`. Apps render the
   *   credentialId in Settings UI (truncated for display) so the user
   *   can identify which device a passkey corresponds to. The SDK
   *   never retains the PRF output.
   *
   * @throws if PRF is not supported on this device, the user cancels,
   *   the WebAuthn ceremony fails, or the server rejects the
   *   registration.
   */
  async registerPasskey(opts: { deviceLabel?: string } = {}): Promise<{ credentialId: string; deviceLabel: string | null }> {
    await this.#requireAuth();
    if (!this.#dekByGen || this.#dekByGen.size === 0) {
      throw new Error('registerPasskey(): DEK chain unavailable (corrupt session?)');
    }
    if (!this.#recoveryFactorMeta) {
      throw new Error('registerPasskey(): missing recovery-factor metadata');
    }

    // 1. Fetch options + the server-generated PRF salt.
    const optsRes = await this.#fetch('/api/v1/auth/passkey/register-options', {
      method: 'POST',
      auth: true,
      retry: false, // single-use challenge — retrying could leak rows
      body: { device_label: opts.deviceLabel ?? null },
    });
    if (optsRes.status !== 200) {
      throw new Error(`registerPasskey(): options failed: ${optsRes.json?.error || optsRes.status}`);
    }
    const { options: pkOptions, prf_salt: prfSaltB64Url } = optsRes.json;
    if (!pkOptions || !prfSaltB64Url) {
      throw new Error('registerPasskey(): server did not return options + prf_salt');
    }

    // 2. Convert the JSON-friendly option payload back to BufferSource
    //    fields and call navigator.credentials.create. Use the helper
    //    from @simplewebauthn/browser for the round trip.
    const { startRegistration } = await import('@simplewebauthn/browser');
    const credential = await startRegistration({ optionsJSON: pkOptions });

    // 3. Extract the PRF output and derive the wrapping key.
    const prfResults = (credential as any)?.clientExtensionResults?.prf?.results?.first;
    if (!prfResults) {
      throw new Error('registerPasskey(): PRF extension produced no output (browser may not support PRF)');
    }
    const prfOutput = new Uint8Array(prfResults);
    const { kwKey: passkeyKEK } = await derivePasskeyWrappingKey(prfOutput);

    // 4. Re-wrap every gen under the existing factors PLUS the new passkey.
    //    Existing wrappings are preserved verbatim (AES-KW is deterministic;
    //    the recovery wrappings come from the cached snapshot).
    const credentialId = credential.id; // base64url string
    const newEnvelope = await this.#rebuildEnvelopeWithExtraPasskey(
      credentialId,
      passkeyKEK,
    );

    // 5. Submit. Server verifies the WebAuthn ceremony, stores the
    //    credential row, swaps the envelope, and republishes to Arweave.
    const regRes = await this.#fetch('/api/v1/auth/passkey/register', {
      method: 'POST',
      auth: true,
      body: {
        credential,
        prf_salt: prfSaltB64Url,
        new_envelope: newEnvelope,
        device_label: opts.deviceLabel ?? null,
      },
    });
    if (regRes.status !== 201) {
      throw new Error(`registerPasskey(): register failed: ${regRes.json?.error || regRes.status}`);
    }

    // Refresh the local snapshot of passkey wrappings so subsequent
    // envelope-mutating flows in the same session (a second
    // registerPasskey, rotateAccountKey, changeCredentials) preserve
    // this credential's wrapping. Without this, the snapshot stays
    // pinned to whatever was on the envelope at login time and the next
    // envelope rebuild silently drops the passkey we just enrolled.
    try {
      const reparsed = parseWrappedDataKey(newEnvelope);
      this.#capturePasskeyWrappings(reparsed);
    } catch {
      // Failure to reparse the freshly-built envelope would indicate a
      // serious bug; the server would also have rejected it. Log and
      // continue rather than failing the user-visible operation.
    }

    return {
      credentialId,
      deviceLabel: regRes.json?.device_label ?? null,
    };
  }

  /**
   * Authenticate with a passkey. No prior session required — this is an
   * alternative to `login()`. On success the client behaves identically
   * to a logged-in client.
   *
   * Flow:
   *   1. POST /auth/passkey/authentication-options → { options,
   *      allow_credentials: [{ credential_id, prf_salt }, ...] }
   *   2. navigator.credentials.get(options) — user authenticates.
   *   3. Extract the PRF output for the credential the user picked.
   *   4. POST /auth/passkey/authenticate → { jwt, wrapped_data_key, ... }
   *   5. Derive the passkey wrapping key from the PRF output, unwrap
   *      the DEK chain, install session state.
   */
  async authenticateWithPasskey(opts: {
    deviceLabel?: string;
    credentialId?: string;
    /**
     * Phase 6.1 — handler invoked when the server flags the just-used
     * credential as stale (no `passkey_prf` wrapping on the latest gen).
     * The handler should prompt the user for their password and resolve
     * with it; resolving with null aborts the repair and surfaces a
     * `StalePasskeyError` instead. If no handler is supplied and a stale
     * credential is detected, this method throws `StalePasskeyError`
     * directly so the app can surface a re-registration UI.
     */
    stalePasskeyHandler?: () => Promise<string | null>;
  } = {}): Promise<{ dataLookupKey: string }> {
    if (opts.deviceLabel != null) this.#pendingDeviceLabel = opts.deviceLabel;

    // 1. Auth options.
    const optsRes = await this.#fetch('/api/v1/auth/passkey/authentication-options', {
      method: 'POST',
      retry: false,
      body: opts.credentialId ? { credential_id: opts.credentialId } : {},
    });
    if (optsRes.status !== 200) {
      throw new Error(`authenticateWithPasskey(): options failed: ${optsRes.json?.error || optsRes.status}`);
    }
    const pkOptions = optsRes.json?.options;
    if (!pkOptions) {
      throw new Error('authenticateWithPasskey(): server did not return options');
    }

    // 2. Get the assertion + PRF output.
    const { startAuthentication } = await import('@simplewebauthn/browser');
    const credential = await startAuthentication({ optionsJSON: pkOptions });
    const prfResults = (credential as any)?.clientExtensionResults?.prf?.results?.first;
    if (!prfResults) {
      throw new Error('authenticateWithPasskey(): PRF extension produced no output');
    }
    const prfOutput = new Uint8Array(prfResults);
    const { kwKey: passkeyKEK } = await derivePasskeyWrappingKey(prfOutput);

    // 3. Submit assertion. Server verifies, returns JWT + envelope.
    const authRes = await this.#fetch('/api/v1/auth/passkey/authenticate', {
      method: 'POST',
      body: {
        credential,
        previous_sid: this.#sid,
        device_label: opts.deviceLabel ?? null,
      },
    });
    if (authRes.status !== 200) {
      throw new Error(`authenticateWithPasskey(): authenticate failed: ${authRes.json?.error || authRes.status}`);
    }
    const {
      jwt,
      data_lookup_key,
      wrapped_data_key,
      account_key_stored,
      credential_id,
      stale_credential,
    } = authRes.json;
    if (!jwt || !wrapped_data_key || !credential_id) {
      throw new Error('authenticateWithPasskey(): server response missing required fields');
    }

    // 4. Unwrap the DEK chain via the passkey factor for THIS credential_id.
    //    For stale credentials, only the gens that DO have a passkey
    //    wrapping for this credential are unwrappable here — the latest
    //    gen needs the password-side repair below. Everything is funnelled
    //    through #unwrapPasskeyChainPartial so the call site does not
    //    need to discriminate.
    const unwrapped = stale_credential
      ? await this.#unwrapPasskeyChainPartial(wrapped_data_key, passkeyKEK, credential_id)
      : await unwrapDataKeyChain(
          wrapped_data_key,
          passkeyKEK,
          FACTOR_PASSKEY_PRF,
          credential_id,
        );

    // 5. Install session state. Mirrors the tail of login() — same fields
    //    populated, same caches reset (they were already empty on a fresh
    //    client). Note we don't have a username here (passkey login is
    //    discoverable / username-less), so #username remains null until
    //    the user explicitly sets one via subsequent operations. This
    //    means certain follow-up operations that require the username
    //    (changeCredentials, viewAccountKey, enable/disable/rotate
    //    account-key, sharing handshake) will fail; passkey-only sessions
    //    are intended for read access and entry CRUD that doesn't need
    //    the master_key.
    this.#jwt = jwt;
    this.#sid = this.#extractSidFromJwt(jwt);
    this.#dataLookupKey = data_lookup_key;
    this.#dekByGen = unwrapped.dekByGen;
    this.#currentGen = unwrapped.currentGen;
    this.#accountKeyStored =
      typeof account_key_stored === 'boolean' ? account_key_stored : null;
    // Snapshot recovery wrapping bytes so a future write that DOES have the
    // password can preserve them. (We don't have the recovery KEK here —
    // same as login.)
    {
      const reparsed = parseWrappedDataKey(wrapped_data_key);
      const wrappingsByGen = new Map<number, string>();
      for (const entry of reparsed.dekChain) {
        const w = entry.wrappings.find(w => w.factor === FACTOR_RECOVERY_PHRASE);
        if (w) wrappingsByGen.set(entry.gen, w.wrappedBase64);
      }
      this.#recoveryFactorMeta = {
        salt: unwrapped.recovery.salt,
        kdfParams: unwrapped.recovery.kdfParams,
        wrappingsByGen,
      };
      // Snapshot existing passkey wrappings (including this one) so a
      // follow-up envelope mutation in the same session preserves them.
      // Mirrors the call sites in login()/recoverAccount()/rotation.
      this.#capturePasskeyWrappings(reparsed);
    }

    // 6. Stale-credential repair. The latest gen has no `passkey_prf`
    //    wrapping for this credential — typically because another device
    //    ran changeCredentials and the user did not re-tap this passkey.
    //    Repair path 1: prompt for the password (via handler), unwrap
    //    the latest gen via the password factor, re-wrap it under THIS
    //    passkey's PRF KEK, submit the updated envelope. After this the
    //    credential is no longer stale.
    //    Repair path 2 (no handler): throw `StalePasskeyError` so the
    //    app can prompt the user to re-register the passkey from a
    //    password-authenticated session.
    if (stale_credential) {
      if (typeof opts.stalePasskeyHandler !== 'function') {
        throw new StalePasskeyError({ credentialId: credential_id });
      }
      const password = await opts.stalePasskeyHandler();
      if (typeof password !== 'string' || password.length === 0) {
        throw new StalePasskeyError({
          credentialId: credential_id,
          message:
            `Passkey ${credential_id.slice(0, 8)}… is stale and the stalePasskeyHandler ` +
            'returned no password — re-register the passkey to repair.',
        });
      }
      await this.#repairStaleCredential({
        credentialId: credential_id,
        password,
        passkeyKEK,
        wrappedDataKey: wrapped_data_key,
      });
    }

    return { dataLookupKey: this.#dataLookupKey! };
  }

  /**
   * Phase 6.1 — partial unwrap for a stale-credential authenticate.
   *
   * Identical to `unwrapDataKeyChain(_, _, FACTOR_PASSKEY_PRF, credId)`
   * except that gens lacking a passkey wrapping for this credential are
   * silently skipped instead of throwing. Used when the server has
   * flagged the credential as stale: the latest gen will be unwrapped
   * via the password factor in the repair step.
   */
  async #unwrapPasskeyChainPartial(
    wireValue: string,
    passkeyKEK: CryptoKey,
    credentialId: string,
  ): Promise<{
    dekByGen: Map<number, DataKeyPair>;
    currentGen: number;
    envelopeVersion: 1;
    kdfParams: Argon2idParams;
    recovery: RecoveryMetadata;
  }> {
    const parsed = parseWrappedDataKey(wireValue);
    const dekByGen = new Map<number, DataKeyPair>();
    for (const entry of parsed.dekChain) {
      const wrapping = entry.wrappings.find(
        w => w.factor === FACTOR_PASSKEY_PRF && w.credentialId === credentialId,
      );
      if (!wrapping) continue; // stale gen — repair step fills it in
      const wrapped = base64ToBytes(wrapping.wrappedBase64);
      const [gcmKey, kwKey] = await Promise.all([
        crypto.subtle.unwrapKey(
          'raw', bs(wrapped), passkeyKEK, 'AES-KW',
          { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'],
        ),
        crypto.subtle.unwrapKey(
          'raw', bs(wrapped), passkeyKEK, 'AES-KW',
          'AES-KW', false, ['wrapKey', 'unwrapKey'],
        ),
      ]);
      dekByGen.set(entry.gen, { gcmKey, kwKey });
    }
    const currentGen = parsed.dekChain[parsed.dekChain.length - 1]!.gen;
    return {
      dekByGen,
      currentGen,
      envelopeVersion: parsed.envelopeVersion,
      kdfParams: parsed.kdfParams,
      recovery: parsed.recovery,
    };
  }

  /**
   * Phase 6.1 — repair a stale credential by:
   *   1. Looking up the username via /auth/passkey/whoami (server replies
   *      with the credential blob the SDK already has — we already have
   *      the dataLookupKey from the auth response, but we need a
   *      username-side credential_lookup_key to finish the password
   *      challenge). Fall back to deriving from the in-memory username if
   *      the caller previously called `login()` on the same client.
   *   2. Deriving password keys from the supplied password.
   *   3. Unwrapping the LATEST gen via the password factor.
   *   4. Wrapping it under the passkey's PRF KEK.
   *   5. Submitting the rebuilt envelope to the refresh-credential endpoint.
   *
   * After step 5 the credential is no longer stale; the local
   * `#dekByGen` snapshot is updated in place to include the (now-repaired)
   * latest gen.
   *
   * Note: the SDK does not look up the username at the server (Tarn never
   * stores plaintext usernames). The handler-supplied password alone is
   * enough — credential_lookup_key derives from (username, password,
   * appId), and the user would have only set the password they're
   * supplying now if it goes with the username on this account. So we
   * try the in-memory `#username` (set when the client previously logged
   * in via password); if absent, the repair fails with a clear message
   * directing the app to use re-registration instead. This is acceptable
   * because the typical app flow stores the username in a way that can
   * be plumbed back through (re-render the login form), and the
   * less-typical "log in via passkey only, then change password on a
   * different device" pattern is rare enough to leave to re-registration.
   */
  async #repairStaleCredential(args: {
    credentialId: string;
    password: string;
    passkeyKEK: CryptoKey;
    wrappedDataKey: string;
  }): Promise<void> {
    if (!this.#dataLookupKey) {
      throw new StalePasskeyError({
        credentialId: args.credentialId,
        message: 'stale-credential repair requires an authenticated passkey session',
      });
    }
    // Parse the live envelope. The latest gen is what we need to unwrap
    // via password and re-wrap under the passkey.
    const parsed = parseWrappedDataKey(args.wrappedDataKey);
    const latest = parsed.dekChain[parsed.dekChain.length - 1]!;
    const passwordWrap = latest.wrappings.find(w => w.factor === FACTOR_PASSWORD);
    if (!passwordWrap) {
      // Theoretically impossible — the parser asserts a password wrapping
      // on the current gen. Belt-and-braces.
      throw new StalePasskeyError({
        credentialId: args.credentialId,
        message: 'stale-credential repair: latest gen has no password wrapping',
      });
    }

    // We need the username to derive the password KEK. The simplest
    // path: the app re-uses a TarnClient that was previously
    // password-logged-in (username cached). If the client started via
    // authenticateWithPasskey alone, we can't derive the password KEK
    // here — surface a clear error. In practice the stale-handler is
    // typically invoked on the same client where the user is filling in
    // a password form, and apps can call `tarn.login()` first to
    // establish the username. A future endpoint could let the server
    // supply the username back to the client; deferred to a follow-up.
    if (!this.#username) {
      throw new StalePasskeyError({
        credentialId: args.credentialId,
        message:
          'stale-credential repair requires a username — call tarn.login() first or ' +
          're-register the passkey via tarn.passkeys.register() from a password session.',
      });
    }
    const reKeys = await deriveAllKeys(this.#username, args.password, this.#appId);

    // Unwrap the latest gen via the password factor, then wrap it under
    // the passkey KEK.
    const passwordWrapped = base64ToBytes(passwordWrap.wrappedBase64);
    let latestGcmKey: CryptoKey;
    let latestKwKey: CryptoKey;
    try {
      [latestGcmKey, latestKwKey] = await Promise.all([
        crypto.subtle.unwrapKey(
          'raw', bs(passwordWrapped), reKeys.credentialEncryptionKey.kwKey, 'AES-KW',
          { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'],
        ),
        crypto.subtle.unwrapKey(
          'raw', bs(passwordWrapped), reKeys.credentialEncryptionKey.kwKey, 'AES-KW',
          'AES-KW', false, ['wrapKey', 'unwrapKey'],
        ),
      ]);
    } catch (err: any) {
      throw new StalePasskeyError({
        credentialId: args.credentialId,
        message: 'stale-credential repair: password did not unwrap latest gen (wrong password?)',
      });
    }
    const newWrapped = await this.#wrapDekRaw(latestGcmKey, args.passkeyKEK);

    // Build the updated envelope: identical to the live envelope plus a
    // single new wrapping at the latest gen.
    const wireChain = parsed.dekChain.map(entry => {
      const wrappings: Array<{ factor: string; wrappedBase64: string; credentialId?: string }> =
        entry.wrappings.map(w => ({
          factor: w.factor,
          wrappedBase64: w.wrappedBase64,
          ...(w.credentialId ? { credentialId: w.credentialId } : {}),
        }));
      if (entry.gen === latest.gen) {
        // Defensive: if a (passkey_prf, credId) wrapping somehow already
        // exists on the latest gen (race with another device), don't
        // duplicate — overwrite by removing any prior copy.
        const filtered = wrappings.filter(
          w => !(w.factor === FACTOR_PASSKEY_PRF && w.credentialId === args.credentialId),
        );
        filtered.push({
          factor: FACTOR_PASSKEY_PRF,
          wrappedBase64: newWrapped,
          credentialId: args.credentialId,
        });
        return { gen: entry.gen, wrappings: filtered };
      }
      return { gen: entry.gen, wrappings };
    });
    const newEnvelope = buildEnvelope(wireChain, {
      salt: parsed.recovery.salt,
      kdfParams: parsed.recovery.kdfParams,
    });

    const refreshRes = await this.#fetch('/api/v1/auth/passkey/refresh-credential', {
      method: 'POST',
      auth: true,
      body: {
        credential_id: args.credentialId,
        new_envelope: newEnvelope,
      },
    });
    if (refreshRes.status !== 200) {
      throw new Error(
        `stale-credential repair: refresh-credential failed: ${refreshRes.json?.error || refreshRes.status}`,
      );
    }

    // Update local DEK chain to include the now-repaired latest gen.
    this.#dekByGen!.set(latest.gen, { gcmKey: latestGcmKey, kwKey: latestKwKey });
    this.#currentGen = latest.gen;
    // Refresh passkey-wrappings snapshot.
    try {
      this.#capturePasskeyWrappings(parseWrappedDataKey(newEnvelope));
    } catch {}
  }

  /**
   * List the passkeys registered against this account. Each entry is one
   * device the user has enrolled.
   */
  async listPasskeys(): Promise<Array<{
    credentialId: string;
    deviceLabel: string | null;
    createdAt: number;
    lastUsedAt: number | null;
  }>> {
    await this.#requireAuth();
    const res = await this.#fetch('/api/v1/account/passkeys', { method: 'GET', auth: true });
    if (res.status !== 200) {
      throw new Error(`listPasskeys(): failed: ${res.json?.error || res.status}`);
    }
    const rows = Array.isArray(res.json?.passkeys) ? res.json.passkeys : [];
    return rows.map((r: any) => ({
      credentialId: r.credential_id,
      deviceLabel: r.device_label ?? null,
      createdAt: r.created_at,
      lastUsedAt: r.last_used_at ?? null,
    }));
  }

  /**
   * Remove a registered passkey. Step-up gated (caller passes a fresh
   * password). Strips the corresponding `passkey_prf` wrappings from the
   * envelope and republishes.
   *
   * @throws on wrong password, unknown credentialId, or network failure.
   */
  async removePasskey(opts: { credentialId: string; password: string }): Promise<void> {
    await this.#requireAuth();
    if (!opts || typeof opts.credentialId !== 'string' || opts.credentialId.length === 0) {
      throw new Error('removePasskey(): credentialId is required');
    }
    if (typeof opts.password !== 'string' || opts.password.length === 0) {
      throw new Error('removePasskey(): password is required');
    }
    if (!this.#username) {
      throw new Error('removePasskey(): username unknown — log in with password first');
    }

    // Re-derive the password KEK so #rebuildEnvelopeWithoutPasskey can
    // emit the password wrapping even on passkey-authenticated sessions
    // (where #credentialEncryptionKey was never set).
    if (!this.#credentialEncryptionKey) {
      const reKeys = await deriveAllKeys(this.#username, opts.password, this.#appId);
      this.#credentialEncryptionKey = reKeys.credentialEncryptionKey;
    }

    const stepUpToken = await this.#performStepUp(opts.password, 'account_key_fetch');

    // Re-wrap the existing chain dropping the targeted credential_id.
    // Preserve all other wrappings byte-for-byte (no decryption; the
    // server doesn't have the keys to verify, just the shape).
    const newEnvelope = await this.#rebuildEnvelopeWithoutPasskey(opts.credentialId);

    const res = await this.#fetchRaw(
      `/api/v1/account/passkeys/${encodeURIComponent(opts.credentialId)}`,
      {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${this.#jwt}`,
          'X-Step-Up-Token': stepUpToken,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ new_envelope: newEnvelope }),
      },
    );
    const text = await res.text();
    let json: any = null;
    try { json = JSON.parse(text); } catch {}
    if (res.status !== 200) {
      throw new Error(`removePasskey(): failed: ${json?.error || res.status}`);
    }

    // Refresh local snapshot so a subsequent envelope-mutating flow
    // (e.g. removing a second passkey, rotating account-key) reflects
    // the now-stripped wrapping.
    try {
      const reparsed = parseWrappedDataKey(newEnvelope);
      this.#capturePasskeyWrappings(reparsed);
    } catch {}
  }

  /**
   * Build a fresh envelope from the cached client state + add a NEW
   * `passkey_prf` wrapping (one per gen) for the supplied
   * (credentialId, KEK) pair. Existing password/recovery/passkey
   * wrappings are emitted from the cached snapshots — no extra network
   * round trip.
   *
   * Concurrency caveat: a wrapping added by another device since this
   * session's last refresh will NOT appear here, and submitting this
   * envelope will overwrite that change. Acceptable for v1 — multi-device
   * passkey concurrency is rare and the recovery is "re-register the
   * passkey on the missing device". A stricter implementation would
   * re-fetch via /auth/challenge before submitting.
   */
  async #rebuildEnvelopeWithExtraPasskey(
    credentialId: string,
    passkeyKEK: CryptoKey,
  ): Promise<string> {
    if (!this.#dekByGen || !this.#recoveryFactorMeta || !this.#credentialEncryptionKey) {
      throw new Error('#rebuildEnvelopeWithExtraPasskey: missing client state');
    }

    const wireChain: Array<{ gen: number; wrappings: Array<{ factor: string; wrappedBase64: string; credentialId?: string }> }> = [];
    for (const [gen, dekPair] of this.#dekByGen) {
      const wrappings: Array<{ factor: string; wrappedBase64: string; credentialId?: string }> = [];
      // Re-wrap under the live password KEK (deterministic — produces
      // identical bytes to the previous wrapping).
      const passwordWrapped = await this.#wrapDekRaw(
        dekPair.gcmKey,
        this.#credentialEncryptionKey.kwKey,
      );
      wrappings.push({ factor: FACTOR_PASSWORD, wrappedBase64: passwordWrapped });
      // Recovery wrapping preserved verbatim from cached snapshot.
      const recWrap = this.#recoveryFactorMeta.wrappingsByGen.get(gen);
      if (recWrap !== undefined) {
        wrappings.push({ factor: FACTOR_RECOVERY_PHRASE, wrappedBase64: recWrap });
      }
      // Existing passkey wrappings preserved verbatim.
      const existingPasskeys = this.#passkeyWrappingsByGen.get(gen) ?? [];
      for (const pk of existingPasskeys) {
        wrappings.push({
          factor: FACTOR_PASSKEY_PRF,
          wrappedBase64: pk.wrappedBase64,
          credentialId: pk.credentialId,
        });
      }
      // New passkey wrapping for this gen.
      const newWrapped = await this.#wrapDekRaw(dekPair.gcmKey, passkeyKEK);
      wrappings.push({
        factor: FACTOR_PASSKEY_PRF,
        wrappedBase64: newWrapped,
        credentialId,
      });
      wireChain.push({ gen, wrappings });
    }
    return buildEnvelope(wireChain, {
      salt: this.#recoveryFactorMeta.salt,
      kdfParams: this.#recoveryFactorMeta.kdfParams,
    });
  }

  /**
   * Build a fresh envelope by stripping all `passkey_prf` wrappings whose
   * credentialId matches the supplied value. All other wrappings are
   * preserved byte-for-byte from the cached client state.
   */
  async #rebuildEnvelopeWithoutPasskey(credentialId: string): Promise<string> {
    if (!this.#dekByGen || !this.#recoveryFactorMeta || !this.#credentialEncryptionKey) {
      throw new Error('#rebuildEnvelopeWithoutPasskey: missing client state');
    }
    const wireChain: Array<{ gen: number; wrappings: Array<{ factor: string; wrappedBase64: string; credentialId?: string }> }> = [];
    for (const [gen, dekPair] of this.#dekByGen) {
      const wrappings: Array<{ factor: string; wrappedBase64: string; credentialId?: string }> = [];
      const passwordWrapped = await this.#wrapDekRaw(
        dekPair.gcmKey,
        this.#credentialEncryptionKey.kwKey,
      );
      wrappings.push({ factor: FACTOR_PASSWORD, wrappedBase64: passwordWrapped });
      const recWrap = this.#recoveryFactorMeta.wrappingsByGen.get(gen);
      if (recWrap !== undefined) {
        wrappings.push({ factor: FACTOR_RECOVERY_PHRASE, wrappedBase64: recWrap });
      }
      const existingPasskeys = this.#passkeyWrappingsByGen.get(gen) ?? [];
      for (const pk of existingPasskeys) {
        if (pk.credentialId === credentialId) continue;
        wrappings.push({
          factor: FACTOR_PASSKEY_PRF,
          wrappedBase64: pk.wrappedBase64,
          credentialId: pk.credentialId,
        });
      }
      if (wrappings.length === 1) {
        // Only the password wrapping remains — fine, but note for the
        // future password-removal scenario.
      }
      wireChain.push({ gen, wrappings });
    }
    return buildEnvelope(wireChain, {
      salt: this.#recoveryFactorMeta.salt,
      kdfParams: this.#recoveryFactorMeta.kdfParams,
    });
  }

  /**
   * Delete the account permanently.
   */
  async deleteAccount() {
    await this.#requireAuth();

    const res = await this.#fetch('/api/v1/auth', { method: 'DELETE', auth: true });

    if (res.status !== 200) {
      throw new Error(`Account deletion failed: ${res.json?.error || res.status}`);
    }

    // §7 invalidation: rotate the IndexedDB wrapping key so any persisted
    // session blob on this origin becomes unreadable. Best-effort — IndexedDB
    // failure must not fail the credential operation.
    try { await this.clearSession(); } catch {}

    this.#jwt = null;
    this.#sid = null;
    this.#dataLookupKey = null;
    this.#dekByGen = null;
    this.#currentGen = null;
    this.#credentialLookupKey = null;
    this.#credentialEncryptionKey = null;
    this.#signingKeyPair = null;
    this.#recoveryFactorMeta = null;
    this.#recoveryLookupKey = null;
    this.#passkeyWrappingsByGen = new Map();
    this.#username = null;
    this.#sharingKeyPair = null;
    this.#replayNonceCache = makeReplayNonceCache();
    this.#pairKeyCache.clear();
    this.#shareLogCounters.clear();
    this.#readStateCache.clear();
    this.#outboundStateCache.clear();
    this.#publishedTxidsByConnection.clear();
    this.#mutedConnectionsState = null;
    this.#issuedInvitesState = null;
  }

  // ============ DATA CRUD ============

  /**
   * Create a new data entry.
   * @param {string} type - Entry type (e.g., 'entry')
   * @param {Object} plaintext - JSON-serializable payload
   * @param {Array<{name: string, value: string}>} extraTags
   * @returns {Promise<{txid: string}>}
   */
  async createEntry(type: string, plaintext: any, extraTags: Tag[] = []): Promise<any> {
    await this.#requireAuth();

    const { encrypted, tags: cryptoTags, shareKey } = await this.#encryptForWrite(plaintext);
    const tags = [
      { name: 'App', value: this.#appId },
      { name: 'Type', value: type },
      { name: 'Lk', value: this.#dataLookupKey },
      ...cryptoTags,
      { name: 'V', value: '0.4.0' },
      ...extraTags,
    ];

    const res = await this.#fetchRaw('/api/v1/entries', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.#jwt}`,
        'X-Arweave-Tags': JSON.stringify(tags),
        'X-Idempotency-Key': generateIdempotencyKey(), // retry-safe (#8)
        'Content-Type': 'application/octet-stream',
      },
      body: encrypted,
    }, { retry: true });

    const json = await res.json().catch(() => null);
    if (res.status !== 200) {
      throw new Error(`Create failed: ${json?.error || res.status}`);
    }

    this.#cacheShareKey(json.id, shareKey);
    return { txid: json.id, shareKey };
  }

  /**
   * Bulk import multiple entries in one request.
   * Counts as 1 rate-limit hit regardless of batch size. Max 100 entries per batch.
   * @param {string} type - Entry type for all entries
   * @param {Array<Object>} items - Array of JSON-serializable payloads
   * @returns {Promise<Array<{txid: string}>>}
   */
  async batchCreate(type: string, items: any[]): Promise<any> {
    await this.#requireAuth();

    if (!Array.isArray(items) || items.length === 0) {
      throw new Error('items must be a non-empty array');
    }
    if (items.length > 25) {
      throw new Error('items max 25 per batch');
    }

    // Encrypt each item and build the batch payload. Capture per-item shareKeys
    // in the same order so we can pair them with the server-issued txids on
    // response.
    const entries = [];
    const shareKeys = [];
    for (const item of items) {
      const { encrypted, tags: cryptoTags, shareKey } = await this.#encryptForWrite(item);
      const tags = [
        { name: 'App', value: this.#appId },
        { name: 'Type', value: type },
        { name: 'Lk', value: this.#dataLookupKey },
        ...cryptoTags,
        { name: 'V', value: '0.4.0' },
      ];
      // Base64-encode the encrypted bytes for JSON transport
      const data = btoa(String.fromCharCode(...encrypted));
      entries.push({ data, tags });
      shareKeys.push(shareKey);
    }

    // Batch idempotency: one key for the whole batch. Server stores the full
    // list of txids against it; retry returns the same list (#8).
    const idempotencyKey = generateIdempotencyKey();
    const res = await this.#fetchBatch(entries, idempotencyKey);

    if (res.status !== 200) {
      throw new Error(`Batch create failed: ${res.json?.error || res.status}`);
    }

    // Pair each returned txid with its shareKey, populate the cache, and
    // return both to the caller.
    const out = [];
    const returned = res.json.entries || [];
    for (let i = 0; i < returned.length; i++) {
      const txid = returned[i].txid;
      const shareKey = shareKeys[i] ?? null;
      this.#cacheShareKey(txid, shareKey);
      out.push({ txid, shareKey });
    }
    return out;
  }

  async #fetchBatch(entries: any[], idempotencyKey: string): Promise<{ status: number; json: any; text: string }> {
    // Batch posts can't use #fetch because we need the custom header. Inline
    // the request setup here to keep the fetch-with-retry path.
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.#jwt}`,
      'X-Idempotency-Key': idempotencyKey,
    };
    const raw = await this.#fetchRaw('/api/v1/entries/batch', {
      method: 'POST',
      headers,
      body: JSON.stringify({ entries }),
    }, { retry: true });
    const text = await raw.text();
    let json; try { json = JSON.parse(text); } catch { json = null; }
    return { status: raw.status, json, text };
  }

  /**
   * Retrieve and decrypt entries.
   * @param {string} type - Entry type
   * @returns {Promise<Array<{txid: string, data: Object, tags: Array}>>}
   */
  async getEntries(type: string): Promise<any[]> {
    await this.#requireAuth();

    // Paginate through all entries (API returns up to 500 per page)
    const allRawEntries = [];
    let cursor = null;

    for (let page = 0; page < 50; page++) { // safety limit: 50 pages × 500 = 25,000 entries
      let url = `/api/v1/entries?app=${this.#appId}&type=${type}&key=${this.#dataLookupKey}&limit=500`;
      if (cursor) url += `&cursor=${cursor}`;

      const res = await this.#fetch(url);

      if (res.status !== 200) {
        throw new Error(`Get entries failed: ${res.json?.error || res.status}`);
      }

      const pageEntries = res.json.entries || [];
      allRawEntries.push(...pageEntries);

      if (!res.json.pagination?.hasMore) break;
      cursor = res.json.pagination.cursor;
      if (!cursor) break;
    }

    // Tarn list responses are metadata-only (returning ~10 MB of inline base64
    // would push the Worker past the 128 MB per-request memory limit). Fetch
    // each blob separately via #fetchBlob, which calls Tarn's per-entry
    // endpoint. Tarn serves the blob from D1 if present and lazy-loads from
    // an Arweave gateway if not, so this single round trip covers both
    // recently-written and cold-bootstrap entries.
    const entries = [];
    const CONCURRENCY = 20;

    for (let i = 0; i < allRawEntries.length; i += CONCURRENCY) {
      const batch = allRawEntries.slice(i, i + CONCURRENCY);
      const results = await Promise.allSettled(batch.map(async (entry) => {
        const blobBytes = await this.#fetchBlob(entry.txid);
        if (!blobBytes) return null;
        const data = await this.#decryptBlob(blobBytes, entry.tags);
        return { txid: entry.txid, data, tags: entry.tags };
      }));

      for (const result of results) {
        if (result.status === 'fulfilled' && result.value) {
          entries.push(result.value);
        } else if (result.status === 'rejected') {
          console.warn(`Failed to decrypt entry:`, result.reason?.message);
        }
      }
    }

    return entries;
  }

  /**
   * Update an existing entry.
   * @param {string} priorTxid
   * @param {string} type - Entry type
   * @param {Object} plaintext
   * @returns {Promise<{txid: string}>}
   */
  async updateEntry(priorTxid: string, type: string, plaintext: any, extraTags: Tag[] = []): Promise<any> {
    await this.#requireAuth();

    const { encrypted, tags: cryptoTags, shareKey } = await this.#encryptForWrite(plaintext);
    const tags = [
      { name: 'App', value: this.#appId },
      { name: 'Type', value: type },
      { name: 'Lk', value: this.#dataLookupKey },
      { name: 'Prev', value: priorTxid },
      ...cryptoTags,
      { name: 'V', value: '0.4.0' },
      ...extraTags,
    ];

    const res = await this.#fetchRaw(`/api/v1/entries/${priorTxid}`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${this.#jwt}`,
        'X-Arweave-Tags': JSON.stringify(tags),
        'X-Idempotency-Key': generateIdempotencyKey(), // retry-safe (#8)
        'Content-Type': 'application/octet-stream',
      },
      body: encrypted,
    }, { retry: true });

    const json = await res.json().catch(() => null);
    if (res.status !== 200) {
      throw new Error(`Update failed: ${json?.error || res.status}`);
    }

    // Each update generates a fresh shareKey (CEK is per-content); cache it
    // so a subsequent share() call resolves without an unwrap round trip.
    this.#cacheShareKey(json.id, shareKey);
    return { txid: json.id, shareKey };
  }

  /**
   * Delete an entry (tombstone).
   * @param {string} targetTxid
   * @param {string} type - Entry type
   * @returns {Promise<{txid: string}>}
   */
  async deleteEntry(targetTxid: string, type: string, extraTags: Tag[] = []): Promise<any> {
    await this.#requireAuth();

    const { encrypted, tags: cryptoTags } = await this.#encryptForWrite({
      tombstone: true,
      ref: targetTxid,
    });
    const tags = [
      { name: 'App', value: this.#appId },
      { name: 'Type', value: type },
      { name: 'Lk', value: this.#dataLookupKey },
      { name: 'Op', value: 'tombstone' },
      { name: 'Ref', value: targetTxid },
      ...cryptoTags,
      { name: 'V', value: '0.4.0' },
      ...extraTags,
    ];

    const res = await this.#fetchRaw(`/api/v1/entries/${targetTxid}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${this.#jwt}`,
        'X-Arweave-Tags': JSON.stringify(tags),
        'X-Idempotency-Key': generateIdempotencyKey(), // retry-safe (#8)
        'Content-Type': 'application/octet-stream',
      },
      body: encrypted,
    }, { retry: true });

    const json = await res.json().catch(() => null);
    if (res.status !== 200) {
      throw new Error(`Delete failed: ${json?.error || res.status}`);
    }

    return { txid: json.id };
  }

  // ============ Public blob / shareKey helpers (Section 6) ============

  /**
   * Fetch the encrypted blob bytes for a single Arweave txid via Tarn's
   * per-entry endpoint. Returns null if Tarn has no record of the entry
   * or the response is malformed; throws only on out-of-band protocol
   * errors (auth, network) that the retry layer couldn't recover.
   *
   * Tarn lazy-loads from a public Arweave gateway internally if its D1 cache
   * doesn't have the blob, so this method covers both freshly-written
   * (pending) entries and confirmed historical entries with a single
   * round trip per blob.
   *
   * @param {string} txid
   * @returns {Promise<Uint8Array | null>}
   */
  async fetchBlob(txid: string): Promise<Uint8Array | null> {
    return this.#fetchBlob(txid);
  }

  /**
   * Decrypt a v3-format blob using a shareKey supplied directly (the share-
   * recipient path). The wrapped CEK slot in bytes 5..44 is ignored; the
   * caller's shareKey is used to decrypt bytes 57..end as AES-256-GCM.
   *
   * Apps using the typed Collection API call `tarn.<collection>.listShared`
   * instead of this primitive. Exposed here for advanced use and direct
   * recovery-client consumption.
   *
   * @param {Uint8Array} blobBytes
   * @param {string} shareKeyBase64Url - 32-byte raw CEK, base64url
   * @returns {Promise<Object>} JSON-decoded plaintext
   */
  async decryptSharedBlob(blobBytes: Uint8Array, shareKeyBase64Url: string): Promise<any> {
    return await decryptBlobWithSharedCEK(blobBytes, shareKeyBase64Url);
  }

  /**
   * Resolve a shareKey for an entry we wrote. Looks up the in-memory cache
   * first (populated by createEntry / updateEntry / batchCreate); falls
   * back to fetching the blob from Tarn and AES-KW-unwrapping the in-blob
   * CEK slot using the writer's DEK. Returns null only if the blob is
   * unfetchable or malformed.
   *
   * @param {string} txid
   * @returns {Promise<string | null>} base64url shareKey or null
   */
  async getShareKey(txid: string): Promise<string | null> {
    const cached = this.#shareKeyCache.get(txid);
    if (cached !== undefined) {
      // Touch for LRU recency.
      this.#shareKeyCache.delete(txid);
      this.#shareKeyCache.set(txid, cached);
      return cached;
    }
    return await this.#recoverShareKey(txid);
  }

  /** Internal: cache a freshly-issued shareKey for a write. */
  #cacheShareKey(txid: string, shareKey: string | null): void {
    if (!txid || shareKey == null) return;
    if (this.#shareKeyCache.has(txid)) {
      this.#shareKeyCache.delete(txid);
    }
    this.#shareKeyCache.set(txid, shareKey);
    while (this.#shareKeyCache.size > this.#shareKeyCacheCap) {
      // Map iteration order is insertion order; first key is oldest.
      const oldest = this.#shareKeyCache.keys().next().value;
      if (oldest === undefined) break;
      this.#shareKeyCache.delete(oldest);
    }
  }

  /**
   * Internal cold-path: fetch the blob and unwrap its CEK slot using the
   * writer's DEK. Used by getShareKey() on cache miss. Returns null if
   * the blob is unfetchable or malformed.
   */
  async #recoverShareKey(txid: string): Promise<string | null> {
    const dek = this.#dekByGen!.get(this.#currentGen!);
    if (!dek) return null;
    const blob = await this.#fetchBlob(txid);
    if (!blob || !hasTarnBlobMagic(blob)) return null;

    try {
      const wrappedCEK = blob.slice(
        TARN_BLOB_MAGIC_LEN,
        TARN_BLOB_MAGIC_LEN + TARN_WRAPPED_CEK_LEN,
      );
      // Unwrap as raw bytes — we want the CEK material, not a CryptoKey, so
      // we can re-encode it as base64url for the share-log wire format.
      const cekBytes = new Uint8Array(
        await crypto.subtle.unwrapKey(
          'raw', bs(wrappedCEK), dek.kwKey, 'AES-KW',
          { name: 'AES-GCM' }, true, ['decrypt'],
        ).then((k) => crypto.subtle.exportKey('raw', k)) as ArrayBuffer,
      );
      const shareKey = bytesToBase64Url(cekBytes);
      this.#cacheShareKey(txid, shareKey);
      return shareKey;
    } catch (err: any) {
      console.warn(`[TarnClient] getShareKey: unwrap failed for ${txid}:`, err?.message || err);
      return null;
    }
  }

  // ============ SHARING (issue #13) ============

  /**
   * Look up a recipient's published X25519 sharing public key by username + this
   * client's app_id. Used by the connection-handshake bootstrap (Section 5 work)
   * to encrypt-to-pubkey before any pairwise shared secret has been
   * established.
   *
   * Returns null in three cases — the caller cannot distinguish them, by
   * design (sharing §11):
   *   - The recipient does not have an account in this app.
   *   - The recipient's account predates issue #13 and has not republished.
   *   - The recipient has set `share_discoverable=false`.
   *
   * The lookup is unauthenticated and IP rate-limited at the API. Per-username
   * leakage ("Alice queried Bob's share key") is an accepted residual leak
   * (sharing §11.5) — once the handshake completes, all subsequent traffic is
   * unlinkable.
   *
   * @param {string} username
   * @returns {Promise<{
   *   sharePub: Uint8Array | null,
   *   sharePubBase64Url: string | null,
   *   discoverable: boolean,
   * }>}
   */
  async getRecipientShareKey(username: string): Promise<any> {
    if (!username) throw new Error('username is required');
    const shareLookupKey = await deriveShareLookupKey(username, this.#appId);
    const url = `/api/v1/share/lookup?app=${encodeURIComponent(this.#appId)}&key=${shareLookupKey}`;
    const res = await this.#fetch(url);
    if (res.status !== 200) {
      throw new Error(`getRecipientShareKey(): lookup failed: ${res.json?.error || res.status}`);
    }
    const sharePubBase64Url = res.json?.share_pub ?? null;
    let sharePub = null;
    if (sharePubBase64Url) {
      // Defensive: the server validates the encoding, but a stale/buggy row
      // shouldn't crash the client. Fall back to null on decode failure.
      try {
        sharePub = decodeSharePub(sharePubBase64Url);
      } catch {
        sharePub = null;
      }
    }
    return {
      sharePub,
      sharePubBase64Url,
      discoverable: !!res.json?.share_discoverable,
    };
  }

  // ============ CONNECTION HANDSHAKE (issue #14, Section 5a; issue #18) ============

  /**
   * Send an HPKE-sealed connection request to the named recipient (sharing §6.2).
   *
   * Flow:
   *   1. Look up recipient's `share_pub` via `getRecipientShareKey`. If absent
   *      (pre-#13 account, or non-discoverable), fail with a recognizable
   *      error so the caller can surface "this person isn't connectable" UX.
   *   2. Build the request payload (sender_username, sender_share_pub,
   *      sender_signing_pub, sender_app_id, nonce, timestamp, optional message).
   *   3. HPKE_Seal to the recipient under info "tarn-connection-request-v1".
   *   4. Compute the recipient's current-window inbox tag.
   *   5. Publish the sealed blob to the inbox via the rate-limited endpoint.
   *   6. Append to our outbound pending list (encrypted Tarn data blob,
   *      content_id "tarn-pending-requests-v1") so we can later cross-reference
   *      incoming accepts (§13.9 forged-accept defense).
   *
   * Idempotency: the nonce is fresh per call. A retry by the user is a fresh
   * request from the recipient's standpoint; the protocol does not collapse
   * duplicates.
   *
   * @param {string} recipientUsername
   * @param {{ message?: string }} [opts]
   * @returns {Promise<{
   *   txid: string,                    // Arweave tx_id of the published request
   *   requestNonce: string,            // base64url 16 bytes
   *   recipientSharePubBase64Url: string,
   * }>}
   */
  async sendConnectionRequest(recipientUsername: string, opts: any = {}): Promise<any> {
    await this.#requireAuth();
    if (!this.#sharingKeyPair) {
      throw new Error('sendConnectionRequest(): no sharing keypair — login first');
    }
    if (!this.#username) {
      throw new Error('sendConnectionRequest(): client missing sender username — re-login');
    }

    const { sharePub, sharePubBase64Url } = await this.getRecipientShareKey(recipientUsername);
    if (!sharePub) {
      // Three causes are indistinguishable to the caller (sharing §11.5): the
      // recipient doesn't exist, the recipient's account predates #13, or the
      // recipient has set discoverable=false. Surface a single-shape error
      // that callers can match on without knowing which one.
      const err: any = new Error('sendConnectionRequest(): recipient is not connectable (no share_pub published, or discoverable=false)');
      err.code = 'RECIPIENT_NOT_CONNECTABLE';
      throw err;
    }

    const senderSigningPubBase64 = await exportPublicKey(this.#signingKeyPair!.publicKey);
    const payload = buildConnectionRequestPayload({
      senderUsername: this.#username!,
      senderSharePub: this.#sharingKeyPair.publicKey,
      senderSigningPubBase64,
      senderAppId: this.#appId,
      message: opts.message,
    });

    const blob = await hpkeSeal({
      recipientSharePub: sharePub,
      info: INFO_CONNECTION_REQUEST,
      plaintext: new TextEncoder().encode(JSON.stringify(payload)),
    });

    const tag = await deriveInboxTag(sharePub, this.#appId, currentInboxWindow());

    // Publish to the rate-limited inbox endpoint (sharing §9.5).
    const publishRes = await this.#fetch('/api/v1/share/inbox/publish', {
      method: 'POST',
      auth: true,
      // Not retry-safe: fresh nonce per call means a network-level retry
      // would silently send a *new* request to the same recipient. The
      // server-side rate limit is the protection if a caller does retry
      // explicitly; here we leave retry off so transient 5xx surfaces.
      body: {
        tag,
        type: 'connection-request-v1',
        ciphertext_base64: bytesToBase64(blob),
      },
    });
    if (publishRes.status !== 200) {
      throw new Error(`sendConnectionRequest(): publish failed: ${publishRes.json?.error || publishRes.status}`);
    }

    // Update outbound pending list. Persist before returning success so a
    // subsequent listIncomingRequests() that races with an accept can find
    // the matching outbound entry. (Without this, the incoming accept would
    // hit the forged-accept defense and be dropped.)
    const pending = await this.#loadPendingRequestsRecord();
    const outbound = {
      recipient_username: recipientUsername,
      recipient_share_pub: sharePubBase64Url,
      request_nonce: payload.nonce,
      sent_at: payload.timestamp,
    };
    const updated = addOutboundPending(pending.record, outbound);
    await this.#savePendingRequestsRecord(pending, updated);

    return {
      txid: publishRes.json.txid,
      requestNonce: payload.nonce,
      recipientSharePubBase64Url: sharePubBase64Url,
    };
  }

  /**
   * Poll the inbox for incoming connection requests (sharing §6.3 + §13.8).
   *
   * Walks the recent N day-windows (default 30, per design), fetches all
   * blobs at each (recipient_inbox_tag, connection-request-v1) tuple, attempts
   * HPKE_Open, validates the resulting payload, and deduplicates against
   * the recipient's recent-nonce cache. Surfaces validated requests; updates
   * the inbound pending record so subsequent calls (and accept) can see them.
   *
   * Failures (HPKE_Open returns nothing, validation fails, replay) are
   * silently dropped — never surfaced to the caller. This is the
   * spam-resilience property of §6.8.
   *
   * @param {{ windows?: number }} [opts]
   * @returns {Promise<Array<{
   *   senderUsername: string,
   *   senderSharePubBase64Url: string,
   *   senderSigningPubBase64: string,
   *   senderAppId: string,
   *   requestNonce: string,
   *   timestamp: number,
   *   message: string | null,
   *   txid: string,
   * }>>}
   */
  async listIncomingRequests(opts: any = {}): Promise<any> {
    await this.#requireAuth();
    if (!this.#sharingKeyPair) {
      throw new Error('listIncomingRequests(): no sharing keypair — login first');
    }
    const windows = Number.isInteger(opts.windows) && opts.windows > 0
      ? opts.windows
      : DEFAULT_POLL_WINDOWS;

    const myPub = this.#sharingKeyPair.publicKey;
    const myPriv = this.#sharingKeyPair.privateKey;

    // Fetch every window in parallel — typical case is no requests, so we
    // want to short-circuit fast. The fetch endpoint is IP rate-limited on
    // the API side; 30 fetches per login is well under the per-hour budget.
    const tags = await Promise.all(
      recentInboxWindows(windows).map(w => deriveInboxTag(myPub, this.#appId, w)),
    );
    const fetched = await Promise.all(
      tags.map(tag => this.#fetchInboxBlobs(tag, 'connection-request-v1')),
    );

    const surfaced = [];
    const pendingState = await this.#loadPendingRequestsRecord();
    let pendingRecord = pendingState.record;
    let pendingDirty = false;

    // Existing connections — used to silently drop replayed requests from
    // already-connected senders. Without this guard, a fresh-device session
    // (with an empty replay-nonce cache + cleared inbound-pending after
    // accept) would surface a re-fetched request blob as if it were a new
    // request from someone the user has already accepted. UX polish, not
    // a security check — `upsertConnection` is idempotent on share_pub.
    const connectionsState = await this.#loadConnectionsRecord();
    const existingConnectionPubs = new Set(
      (connectionsState.record.connections || []).map((c: any) => c.share_pub)
    );

    for (const blobs of fetched) {
      for (const blob of blobs) {
        let payload;
        try {
          const pt = await hpkeOpen({
            sharePriv: myPriv,
            info: INFO_CONNECTION_REQUEST,
            blob: blob.ciphertext,
          });
          payload = JSON.parse(new TextDecoder().decode(pt));
        } catch {
          // Not for us, or tampered, or wrong info — silently skip (§6.3).
          continue;
        }
        const validation = validateConnectionRequestPayload(payload, this.#appId);
        if (!validation.valid) continue;

        // Skip requests from senders we've already connected to. This handles
        // the "request blob replayed on a fresh device" case cleanly — the
        // user isn't prompted to re-accept someone they're already connected
        // to.
        if (existingConnectionPubs.has(validation.normalized.senderSharePubBase64Url)) {
          continue;
        }

        // Replay defense (§13.8): in-memory recent-nonce cache.
        const replayCheck = checkAndRecordNonce(this.#replayNonceCache, validation.normalized.nonceBase64Url);
        if (replayCheck.replay) continue;

        // De-dup against existing inbound pending — the same nonce might
        // already be in the persisted record from a prior session.
        if (pendingRecord.inbound.some((i: any) => i.request_nonce === validation.normalized.nonceBase64Url)) {
          // Surface from existing record (so the caller sees a stable view)
          // but don't duplicate-write.
          surfaced.push({
            senderUsername: validation.normalized.senderUsername,
            senderSharePubBase64Url: validation.normalized.senderSharePubBase64Url,
            senderSigningPubBase64: validation.normalized.senderSigningPubBase64,
            senderAppId: validation.normalized.senderAppId,
            requestNonce: validation.normalized.nonceBase64Url,
            timestamp: validation.normalized.timestamp,
            message: validation.normalized.message,
            viaInviteToken: validation.normalized.viaInviteToken,
            txid: blob.txid,
          });
          continue;
        }

        // Persist into inbound pending so the user can act on it later
        // (acceptConnectionRequest uses this list to find the matching request).
        pendingRecord = addInboundPending(pendingRecord, {
          sender_username: validation.normalized.senderUsername,
          sender_share_pub: validation.normalized.senderSharePubBase64Url,
          sender_signing_pub: validation.normalized.senderSigningPubBase64,
          sender_app_id: validation.normalized.senderAppId,
          request_nonce: validation.normalized.nonceBase64Url,
          message: validation.normalized.message,
          via_invite_token: validation.normalized.viaInviteToken,
          received_at: Math.floor(Date.now() / 1000),
        });
        pendingDirty = true;

        surfaced.push({
          senderUsername: validation.normalized.senderUsername,
          senderSharePubBase64Url: validation.normalized.senderSharePubBase64Url,
          senderSigningPubBase64: validation.normalized.senderSigningPubBase64,
          senderAppId: validation.normalized.senderAppId,
          requestNonce: validation.normalized.nonceBase64Url,
          timestamp: validation.normalized.timestamp,
          message: validation.normalized.message,
          viaInviteToken: validation.normalized.viaInviteToken,
          txid: blob.txid,
        });
      }
    }

    if (pendingDirty) {
      await this.#savePendingRequestsRecord(pendingState, pendingRecord);
    }

    // Section 8 auto-accept (issue #22). After persisting + surfacing, scan
    // for entries with via_invite_token, re-load the issued-invites blob
    // FRESH from the API (not the in-memory cache — the invite may have been
    // created on a different device), and auto-accept any matches. The
    // auto-accepted entry is removed from `surfaced` so the caller never
    // sees it. No-match invites stay in the surfaced list — the user
    // decides manually.
    let autoAccepted = null;
    const inviteCandidates = surfaced.filter(s => s.viaInviteToken);
    if (inviteCandidates.length > 0) {
      let issuedRecord = null;
      try {
        const fresh = await this.#loadIssuedInvitesFresh();
        issuedRecord = fresh.record;
      } catch (err: any) {
        console.warn(`[TarnClient] listIncomingRequests: issued-invites fresh load failed: ${err.message}`);
      }
      if (issuedRecord) {
        for (const cand of inviteCandidates) {
          const match = (issuedRecord.invites || []).find((i: any) => i.token_id === cand.viaInviteToken);
          if (!match) continue;
          try {
            await this.acceptConnectionRequest(cand.requestNonce, { label: match.label || null });
            (autoAccepted || (autoAccepted = new Set())).add(cand.requestNonce);
          } catch (err: any) {
            console.warn(`[TarnClient] listIncomingRequests: auto-accept failed for ${cand.requestNonce}: ${err.message}`);
          }
        }
      }
    }
    const surfacedFinal = autoAccepted
      ? surfaced.filter(s => !autoAccepted.has(s.requestNonce))
      : surfaced;

    // Also poll for incoming ACCEPTS while we're at it — Bob's accept lands
    // in Alice's inbox, so Alice's listIncomingRequests is also Alice's
    // accept-poll. This keeps the SDK surface narrow (one polling primitive
    // per direction was overkill for v1). Returns surfaced connection-requests
    // only; processed accepts mutate the connections record + pending record
    // silently.
    await this.#pollAndProcessIncomingAccepts(myPriv, myPub);

    return surfacedFinal;
  }

  /**
   * Accept a previously-received connection request (sharing §6.4).
   *
   * Looks up the inbound pending entry by `requestNonce`, builds an HPKE-
   * sealed accept blob targeted at the original sender's share_pub, and
   * publishes to the sender's inbox tag. On success, the sender is added to
   * our connections record and the inbound pending entry is removed. The sender
   * sees the accept on their next `listIncomingRequests` poll, which moves
   * the matching outbound pending into their connections record.
   *
   * `opts.label` (Section 8) — optional per-side display label persisted on
   * the connection record. Local to this user; the labeled party never sees
   * what they were labeled.
   *
   * @param {string} requestNonce - base64url nonce from the original request
   * @param {{ label?: string | null }} [opts]
   * @returns {Promise<{ txid: string }>}
   */
  async acceptConnectionRequest(requestNonce: string, opts: any = {}): Promise<any> {
    await this.#requireAuth();
    if (!this.#sharingKeyPair) {
      throw new Error('acceptConnectionRequest(): no sharing keypair — login first');
    }
    if (typeof requestNonce !== 'string' || requestNonce.length === 0) {
      throw new Error('requestNonce is required');
    }
    const labelOpt = normalizeConnectionLabel(opts?.label);

    const pendingState = await this.#loadPendingRequestsRecord();
    const inbound = pendingState.record.inbound.find((i: any) => i.request_nonce === requestNonce);
    if (!inbound) {
      throw new Error(`acceptConnectionRequest(): no inbound pending request with nonce ${requestNonce}`);
    }

    let senderSharePub;
    try {
      senderSharePub = decodeSharePub(inbound.sender_share_pub);
    } catch (err: any) {
      throw new Error(`acceptConnectionRequest(): inbound sender_share_pub is invalid: ${err.message}`);
    }

    const senderSigningPubBase64 = await exportPublicKey(this.#signingKeyPair!.publicKey);
    const payload = buildConnectionAcceptPayload({
      senderUsername: this.#username!,
      senderSharePub: this.#sharingKeyPair.publicKey,
      senderSigningPubBase64,
      senderAppId: this.#appId,
      inReplyToNonceBase64Url: requestNonce,
    });

    const blob = await hpkeSeal({
      recipientSharePub: senderSharePub,
      info: INFO_CONNECTION_ACCEPT,
      plaintext: new TextEncoder().encode(JSON.stringify(payload)),
    });

    const tag = await deriveInboxTag(senderSharePub, this.#appId, currentInboxWindow());
    const publishRes = await this.#fetch('/api/v1/share/inbox/publish', {
      method: 'POST',
      auth: true,
      body: {
        tag,
        type: 'connection-accept-v1',
        ciphertext_base64: bytesToBase64(blob),
      },
    });
    if (publishRes.status !== 200) {
      throw new Error(`acceptConnectionRequest(): publish failed: ${publishRes.json?.error || publishRes.status}`);
    }

    // Move inbound → connections. Persist both updates as a (small) sequence:
    // connections record first (the durable record), then pending second. If the
    // pending update fails, the user has a duplicate inbound entry but the
    // connection was added — re-running accept idempotently fixes it (the
    // connections-record upsertConnection is keyed on share_pub).
    const connectionsState = await this.#loadConnectionsRecord();
    const newConnection = {
      username: inbound.sender_username,
      share_pub: inbound.sender_share_pub,
      signing_pub: inbound.sender_signing_pub,
      established_at: payload.timestamp,
      initial_request_nonce: requestNonce,
      label: labelOpt,
    };
    const connectionsUpdated = upsertConnection(connectionsState.record, newConnection);
    await this.#saveConnectionsRecord(connectionsState, connectionsUpdated);

    const pendingUpdated = removeInboundPending(pendingState.record, requestNonce);
    await this.#savePendingRequestsRecord(pendingState, pendingUpdated);

    // Publish the seq=0 snapshot to our outbound-to-connection log (sharing §6.6).
    // Default state is empty — apps with "share my full library" semantics
    // should call _publishInitialSnapshot directly with their state, but the
    // platform-layer SDK is app-agnostic so we can't enumerate content here.
    // The snapshot is the bridge from §6 (handshake) into §8 (share log):
    // a single-entry log exists, ready for ongoing operations to land at
    // seq=1+.
    let initialSnapshotTxid = null;
    try {
      const snap = await this._publishInitialSnapshot(newConnection);
      initialSnapshotTxid = snap.txid;
    } catch (err: any) {
      // Don't roll back the connection addition if the snapshot publish fails —
      // the connectionship is established (durable in the connections record), and
      // the writer can publish later operations at seq=0 on retry. Surface
      // a warning so callers can investigate; the handshake is still useful
      // for direction-aware reads from the connection's outbound log.
      console.warn(
        `[TarnClient] acceptConnectionRequest: initial snapshot publish failed: ${err.message}`,
      );
    }

    return {
      txid: publishRes.json.txid,
      ...(initialSnapshotTxid ? { initialSnapshotTxid } : {}),
    };
  }

  /**
   * Read the connections record (sharing §7.1). Returns an empty list for users
   * who have not completed any handshakes yet.
   *
   * Section 8: every connection always includes `label: string | null`. Old
   * entries (pre-Section 8) that lack the field are surfaced with `label: null`.
   *
   * @returns {Promise<Array<{
   *   username: string,
   *   share_pub: string,
   *   signing_pub: string,
   *   established_at: number,
   *   initial_request_nonce: string,
   *   label: string | null,
   * }>>}
   */
  async listConnections() {
    await this.#requireAuth();
    const state = await this.#loadConnectionsRecord();
    return state.record.connections.map((c: any) => {
      const { email, ...rest } = c;
      return {
        ...rest,
        username: rest.username ?? email,
        label: rest.label != null ? rest.label : null,
      };
    });
  }

  /**
   * Update the persisted label on an existing connection (Section 8).
   * Idempotent — setting the label to its existing value is a write-skip.
   * The connection identity is matched by `share_pub`. The label is stored
   * locally only; the connection party never sees it.
   *
   * @param {{ share_pub: string }} connection
   * @param {string | null} label
   * @returns {Promise<{ updated: boolean, label: string | null }>}
   */
  async setConnectionLabel(connection: any, label: any): Promise<any> {
    await this.#requireAuth();
    if (!connection || typeof connection.share_pub !== 'string') {
      throw new Error('setConnectionLabel(): connection.share_pub is required');
    }
    const normalized = normalizeConnectionLabel(label);
    const state = await this.#loadConnectionsRecord();
    const idx = state.record.connections.findIndex((c: any) => c.share_pub === connection.share_pub);
    if (idx < 0) {
      throw new Error(`setConnectionLabel(): no connection with share_pub ${connection.share_pub.slice(0, 8)}...`);
    }
    const current = state.record.connections[idx].label ?? null;
    if (current === normalized) {
      return { updated: false, label: normalized };
    }
    const next = state.record.connections.slice();
    next[idx] = { ...next[idx], label: normalized };
    const updated = { ...state.record, connections: next };
    await this.#saveConnectionsRecord(state, updated);
    return { updated: true, label: normalized };
  }

  /**
   * Read the pending-requests record (sharing §7.2). Returns the union of
   * outbound (requests we've sent, awaiting accept) and inbound (requests
   * we've received, awaiting our action).
   */
  async getPendingRequests() {
    await this.#requireAuth();
    const state = await this.#loadPendingRequestsRecord();
    return {
      outbound: state.record.outbound.slice(),
      inbound: state.record.inbound.slice(),
    };
  }

  // ============ MUTED CONNECTIONS (issue #18, Section 6) ============

  /**
   * Mute a connection. Adds the connection's `share_pub` to the persisted
   * muted-connections record so subsequent sessions and other devices can
   * see the muted state. Idempotent — re-muting a muted connection is a
   * no-op (the original `muted_at` is preserved).
   *
   * Mute is purely a per-side visibility filter. It does NOT:
   *   - stop the muted party from publishing share-log entries to us
   *   - alter what they can see on their side (we don't notify them)
   *   - cause `readShareLog` / `syncShareLog` to short-circuit on their
   *     log — apps may want to display muted-connection content in a
   *     "Muted" tab even while excluding them from the main feed
   *
   * Apps decide when to filter; the SDK only stores the toggle.
   *
   * @param {{ share_pub: string }} connection
   * @returns {Promise<{ muted: boolean }>} `muted: true` on add, `muted: false`
   *   if the connection was already muted (no record write).
   */
  async muteConnection(connection: any): Promise<any> {
    await this.#requireAuth();
    if (!connection || typeof connection.share_pub !== 'string') {
      throw new Error('muteConnection(): connection.share_pub is required');
    }
    const state = await this.#loadMutedConnectionsRecord();
    if (isMutedInRecord(state.record, connection.share_pub)) {
      return { muted: false };
    }
    const updated = addMutedConnection(
      state.record, connection.share_pub, Math.floor(Date.now() / 1000),
    );
    const written = await this.#saveMutedConnectionsRecord(state, updated);
    this.#mutedConnectionsState = { record: written.record, txid: written.txid };
    return { muted: true };
  }

  /**
   * Unmute a connection. Removes the connection's `share_pub` from the
   * persisted muted-connections record. Idempotent — unmuting a non-muted
   * connection is a no-op.
   *
   * @param {{ share_pub: string }} connection
   * @returns {Promise<{ unmuted: boolean }>} `unmuted: true` on remove,
   *   `unmuted: false` if the connection wasn't muted (no record write).
   */
  async unmuteConnection(connection: any): Promise<any> {
    await this.#requireAuth();
    if (!connection || typeof connection.share_pub !== 'string') {
      throw new Error('unmuteConnection(): connection.share_pub is required');
    }
    const state = await this.#loadMutedConnectionsRecord();
    if (!isMutedInRecord(state.record, connection.share_pub)) {
      return { unmuted: false };
    }
    const updated = removeMutedConnection(state.record, connection.share_pub);
    const written = await this.#saveMutedConnectionsRecord(state, updated);
    this.#mutedConnectionsState = { record: written.record, txid: written.txid };
    return { unmuted: true };
  }

  /**
   * List currently-muted connections. Returns a shallow copy of the persisted
   * muted entries: `[{ share_pub, muted_at }, ...]`.
   *
   * On the first call per session this hydrates the record from Arweave; on
   * subsequent calls the in-memory copy is returned directly (kept current
   * by `muteConnection` / `unmuteConnection`).
   */
  async listMutedConnections() {
    await this.#requireAuth();
    const state = await this.#loadMutedConnectionsRecord();
    return state.record.muted.slice();
  }

  /**
   * True if `connection` is currently in the muted list.
   *
   * Like `listMutedConnections`, hydrates on first call per session.
   *
   * @param {{ share_pub: string }} connection
   * @returns {Promise<boolean>}
   */
  async isMuted(connection: any): Promise<boolean> {
    await this.#requireAuth();
    if (!connection || typeof connection.share_pub !== 'string') {
      throw new Error('isMuted(): connection.share_pub is required');
    }
    const state = await this.#loadMutedConnectionsRecord();
    return isMutedInRecord(state.record, connection.share_pub);
  }

  // ============ INVITE TOKENS (Section 8, issue #22) ============

  /**
   * Create a single-use invite token. Generates `token_id` (256-bit random)
   * and `payload_key` (AES-256-GCM key) client-side; encrypts a payload bound
   * to the inviter's identity; uploads the ciphertext to /api/v1/invite. The
   * payload_key NEVER leaves the device — it lives in the URL fragment.
   *
   * Default expiry is 7 days; server enforces a 30-day cap.
   *
   * @param {{ label?: string, expiry_days?: number }} [opts]
   * @returns {Promise<{ token_id: string, invite_url: string, expires_at: number }>}
   */
  async createInviteToken(opts: any = {}): Promise<any> {
    await this.#requireAuth();
    if (!this.#sharingKeyPair) {
      throw new Error('createInviteToken(): no sharing keypair — login first');
    }
    if (!this.#username) {
      throw new Error('createInviteToken(): client missing sender username — re-login');
    }
    // Local-only label: stored in the inviter's issued-invites record so
    // listIssuedInvites + the auto-accept path can label the resulting
    // connection. Never sent to the recipient — Tarn has no concept of a
    // user-facing display name on the wire.
    const label = opts.label == null ? '' : String(opts.label);
    if (label.length > 64) {
      throw new Error('createInviteToken(): label exceeds 64 chars');
    }
    const expiryDays = Number.isInteger(opts.expiry_days) ? opts.expiry_days : 7;
    if (expiryDays < 1 || expiryDays > 30) {
      throw new Error('createInviteToken(): expiry_days must be in [1, 30]');
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + expiryDays * 86400;

    // 32-byte token_id (URL-safe base64; 43 chars after stripping padding) +
    // 32-byte payload_key. Both are fresh-random per invite.
    const tokenIdBytes = crypto.getRandomValues(new Uint8Array(32));
    const tokenId = bytesToBase64Url(tokenIdBytes);
    const payloadKeyBytes = crypto.getRandomValues(new Uint8Array(32));
    const payloadKey = await crypto.subtle.importKey(
      'raw', bs(payloadKeyBytes), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'],
    );

    const inviterSigningPubBase64 = await exportPublicKey(this.#signingKeyPair!.publicKey);
    const inviterSharePubBase64Url = bytesToBase64Url(this.#sharingKeyPair.publicKey);

    const plaintext = {
      inviter_share_pub: inviterSharePubBase64Url,
      inviter_signing_pub: inviterSigningPubBase64,
      app_id: this.#appId,
      issued_at: now,
    };
    // encrypt() returns IV(12) || ciphertext+tag, the wire format the server
    // expects under base64. The payload_key never appears in this body.
    const payloadBytes = await encrypt(payloadKey, plaintext);
    const payloadBase64 = bytesToBase64(payloadBytes);

    const createRes = await this.#fetch('/api/v1/invite', {
      method: 'POST',
      auth: true,
      body: {
        token_id: tokenId,
        app_id: this.#appId,
        payload: payloadBase64,
        expires_at: expiresAt,
      },
    });
    if (createRes.status !== 201) {
      throw new Error(`createInviteToken(): create failed: ${createRes.json?.error || createRes.status}`);
    }

    // Build the share URL from the app's template. Empty template → fall back
    // to a `tarn:` scheme so the SDK still returns something usable; the app
    // can override by setting the template pre-call.
    let template = null;
    try {
      const tplRes = await this.#fetch(`/api/v1/apps/${encodeURIComponent(this.#appId)}/invite-template`, { method: 'GET' });
      if (tplRes.status === 200) template = tplRes.json?.invite_url_template ?? null;
    } catch {
      // Network/Worker hiccup — fall through to the tarn: fallback.
    }
    const payloadKeyB64Url = bytesToBase64Url(payloadKeyBytes);
    const inviteUrl = template
      ? template.replace('{token_id}', encodeURIComponent(tokenId)) + '#' + payloadKeyB64Url
      : `tarn:invite/${tokenId}#${payloadKeyB64Url}`;

    // Persist to the issued-invites blob so listIssuedInvites + the auto-
    // accept path can find it later. Best-effort — if the persist fails the
    // invite is still on the server, but local accounting will be off.
    try {
      const state = await this.#loadIssuedInvitesRecord();
      const updated = addIssuedInvite(state.record, {
        token_id: tokenId,
        label,
        issued_at: now,
        expires_at: expiresAt,
        redeemed_at: null,
        redeemer_share_pub_fingerprint: null,
      });
      const written = await this.#saveIssuedInvitesRecord(state, updated);
      this.#issuedInvitesState = { record: written.record, txid: written.txid };
    } catch (err: any) {
      console.warn(`[TarnClient] createInviteToken: issued-invites blob update failed: ${err.message}`);
    }

    return { token_id: tokenId, invite_url: inviteUrl, expires_at: expiresAt };
  }

  /**
   * Preview an invite token without consuming it. Unauthenticated to the
   * server; the recipient app calls this from the landing page to populate
   * "X invited you" UI before the user has even signed up. Returns null on
   * any 4xx (expired, used, not_found) — never throws on the recoverable
   * failure modes.
   *
   * @param {string} tokenId
   * @param {string} payloadKeyB64Url - base64url of the 32-byte AES key
   * @returns {Promise<{ inviter_share_pub_fingerprint: string, app_id: string, issued_at: number, expires_at: number } | null>}
   */
  async previewInviteToken(tokenId: string, payloadKeyB64Url: string): Promise<any> {
    if (typeof tokenId !== 'string' || tokenId.length === 0) {
      throw new Error('previewInviteToken(): tokenId is required');
    }
    if (typeof payloadKeyB64Url !== 'string' || payloadKeyB64Url.length === 0) {
      throw new Error('previewInviteToken(): payloadKeyB64Url is required');
    }
    let res;
    try {
      res = await this.#fetch(`/api/v1/invite/${encodeURIComponent(tokenId)}`, { method: 'GET' });
    } catch {
      return null;
    }
    if (res.status !== 200) return null;
    const { app_id, payload, issued_at, expires_at } = res.json || {};
    let payloadBytes;
    try {
      payloadBytes = base64ToBytes(payload);
    } catch {
      return null;
    }
    let plaintext: any;
    try {
      const payloadKeyBytes = base64UrlToBytes(payloadKeyB64Url);
      const key = await crypto.subtle.importKey('raw', bs(payloadKeyBytes), { name: 'AES-GCM' }, false, ['decrypt']);
      plaintext = await decrypt(key, payloadBytes);
    } catch {
      return null;
    }
    if (plaintext.app_id !== app_id) return null;

    let inviterSharePub;
    try {
      inviterSharePub = base64UrlToBytes(plaintext.inviter_share_pub);
    } catch {
      return null;
    }
    const fingerprint = await fingerprintSharePub(inviterSharePub);

    return {
      inviter_share_pub_fingerprint: fingerprint,
      app_id,
      issued_at,
      expires_at,
    };
  }

  /**
   * Redeem an invite token, then send a normal connection request back to
   * the inviter using the existing handshake primitives. The request payload
   * carries `via_invite_token` so the inviter's `listIncomingRequests` can
   * recognize and auto-accept.
   *
   * Throws on the unrecoverable failure modes (404 / 410 / 409 / signature
   * mismatch). The recoverable preview-only modes are exposed via
   * previewInviteToken() returning null instead.
   *
   * @param {string} tokenId
   * @param {string} payloadKeyB64Url
   * @returns {Promise<{ requestNonce: string, recipientSharePubBase64Url: string }>}
   */
  async redeemInviteToken(tokenId: string, payloadKeyB64Url: string): Promise<any> {
    await this.#requireAuth();
    if (!this.#sharingKeyPair) {
      throw new Error('redeemInviteToken(): no sharing keypair — login first');
    }
    if (!this.#username) {
      throw new Error('redeemInviteToken(): client missing sender username — re-login');
    }
    if (typeof tokenId !== 'string' || tokenId.length === 0) {
      throw new Error('redeemInviteToken(): tokenId is required');
    }
    if (typeof payloadKeyB64Url !== 'string' || payloadKeyB64Url.length === 0) {
      throw new Error('redeemInviteToken(): payloadKeyB64Url is required');
    }

    const myFingerprint = await fingerprintSharePub(this.#sharingKeyPair.publicKey);
    const res = await this.#fetch(`/api/v1/invite/redeem/${encodeURIComponent(tokenId)}`, {
      method: 'POST',
      auth: true,
      body: { redeemer_share_pub_fingerprint: myFingerprint },
    });
    if (res.status !== 200) {
      const code = res.status === 404 ? 'INVITE_NOT_FOUND'
        : res.status === 410 ? 'INVITE_EXPIRED'
        : res.status === 409 ? 'INVITE_ALREADY_USED'
        : 'INVITE_REDEEM_FAILED';
      const err: any = new Error(`redeemInviteToken(): ${res.json?.error || res.status}`);
      err.code = code;
      throw err;
    }

    const { app_id, payload } = res.json;
    if (app_id !== this.#appId) {
      const err: any = new Error(`redeemInviteToken(): invite app_id ${app_id} != client app_id ${this.#appId}`);
      err.code = 'INVITE_APP_MISMATCH';
      throw err;
    }
    const payloadBytes = base64ToBytes(payload);
    const payloadKeyBytes = base64UrlToBytes(payloadKeyB64Url);
    const key = await crypto.subtle.importKey('raw', bs(payloadKeyBytes), { name: 'AES-GCM' }, false, ['decrypt']);
    let plaintext: any;
    try {
      plaintext = await decrypt(key, payloadBytes);
    } catch (err: any) {
      throw new Error(`redeemInviteToken(): payload decrypt failed (wrong key?): ${err.message}`);
    }
    if (plaintext.app_id !== this.#appId) {
      const err: any = new Error(`redeemInviteToken(): payload app_id ${plaintext.app_id} != client app_id ${this.#appId}`);
      err.code = 'INVITE_APP_MISMATCH';
      throw err;
    }

    const inviterSharePub = base64UrlToBytes(plaintext.inviter_share_pub);
    if (inviterSharePub.length !== 32) {
      throw new Error('redeemInviteToken(): inviter_share_pub is not 32 bytes');
    }

    // Build + send the connection-request HPKE-sealed back to the inviter.
    // Same primitives as sendConnectionRequest, but addressed by the
    // inviter's share_pub from the decrypted payload (we never knew their
    // username) and tagged with via_invite_token so the inviter's auto-accept
    // path matches it.
    const senderSigningPubBase64 = await exportPublicKey(this.#signingKeyPair!.publicKey);
    const reqPayload = buildConnectionRequestPayload({
      senderUsername: this.#username!,
      senderSharePub: this.#sharingKeyPair.publicKey,
      senderSigningPubBase64,
      senderAppId: this.#appId,
      viaInviteToken: tokenId,
    });
    const blob = await hpkeSeal({
      recipientSharePub: inviterSharePub,
      info: INFO_CONNECTION_REQUEST,
      plaintext: new TextEncoder().encode(JSON.stringify(reqPayload)),
    });
    const tag = await deriveInboxTag(inviterSharePub, this.#appId, currentInboxWindow());
    const publishRes = await this.#fetch('/api/v1/share/inbox/publish', {
      method: 'POST',
      auth: true,
      body: {
        tag,
        type: 'connection-request-v1',
        ciphertext_base64: bytesToBase64(blob),
      },
    });
    if (publishRes.status !== 200) {
      throw new Error(`redeemInviteToken(): inbox publish failed: ${publishRes.json?.error || publishRes.status}`);
    }

    // Update outbound pending so a subsequent listIncomingRequests poll on
    // this side can recognize the inviter's (eventual) accept.
    const pending = await this.#loadPendingRequestsRecord();
    const inviterSharePubBase64Url = plaintext.inviter_share_pub;
    const outbound = {
      recipient_username: '',
      recipient_share_pub: inviterSharePubBase64Url,
      request_nonce: reqPayload.nonce,
      sent_at: reqPayload.timestamp,
      via_invite_token: tokenId,
    };
    const updated = addOutboundPending(pending.record, outbound);
    await this.#savePendingRequestsRecord(pending, updated);

    return {
      requestNonce: reqPayload.nonce,
      recipientSharePubBase64Url: inviterSharePubBase64Url,
    };
  }

  /**
   * List the current user's outstanding issued invites (Section 8). Cached
   * after the first call; refreshed by createInviteToken / revokeIssuedInvite.
   *
   * @returns {Promise<Array<{ token_id: string, label: string, issued_at: number, expires_at: number, redeemed_at: number | null, redeemer_share_pub_fingerprint: string | null }>>}
   */
  async listIssuedInvites() {
    await this.#requireAuth();
    const state = await this.#loadIssuedInvitesRecord();
    return (state.record.invites || []).slice();
  }

  /**
   * Revoke an issued invite. Best-effort: deletes the server-side row (so the
   * link can no longer be redeemed) and removes the local entry. A 404 on
   * the server-side delete is treated as success — the local cleanup still
   * runs.
   *
   * @param {string} tokenId
   * @returns {Promise<{ revoked: boolean }>}
   */
  async revokeIssuedInvite(tokenId: string): Promise<any> {
    await this.#requireAuth();
    if (typeof tokenId !== 'string' || tokenId.length === 0) {
      throw new Error('revokeIssuedInvite(): tokenId is required');
    }
    let serverDeleted = false;
    try {
      const res = await this.#fetch(`/api/v1/invite/${encodeURIComponent(tokenId)}`, {
        method: 'DELETE',
        auth: true,
      });
      serverDeleted = res.status === 204 || res.status === 404;
    } catch (err: any) {
      console.warn(`[TarnClient] revokeIssuedInvite: server delete failed: ${err.message}`);
    }
    const state = await this.#loadIssuedInvitesRecord();
    if (state.record.invites?.some((i: any) => i.token_id === tokenId)) {
      const updated = removeIssuedInvite(state.record, tokenId);
      const written = await this.#saveIssuedInvitesRecord(state, updated);
      this.#issuedInvitesState = { record: written.record, txid: written.txid };
    }
    return { revoked: serverDeleted };
  }

  // ============ SHARE LOG (issue #15, Section 5b) ============

  /**
   * Internal: derive (or fetch from cache) the per-pair keys for a given
   * connection. Connection is identified by `share_pub` base64url string — that's
   * the stable identifier in the connections record. Throws if the connection isn't
   * recognized; the caller is responsible for ensuring the handshake
   * completed first (acceptConnectionRequest, or sendConnectionRequest +
   * listIncomingRequests-processed accept).
   *
   * Caches the derived AES-GCM CryptoKey handles + raw HMAC tag seeds keyed
   * by `share_pub`. Every entry depends on the user's current `share_priv`,
   * so the cache is invalidated wholesale on credential change / recovery.
   */
  async #getPairKeysFor(connectionSharePubBase64Url: string): Promise<any> {
    if (!this.#sharingKeyPair) {
      throw new Error('share log: no sharing keypair — login first');
    }
    if (typeof connectionSharePubBase64Url !== 'string' || connectionSharePubBase64Url.length === 0) {
      throw new Error('share log: connectionSharePubBase64Url must be a non-empty string');
    }
    const cached = this.#pairKeyCache.get(connectionSharePubBase64Url);
    if (cached) return cached;
    const peerSharePub = decodeSharePub(connectionSharePubBase64Url);
    const sharedSecret = deriveSharedSecret(this.#sharingKeyPair.privateKey, peerSharePub);
    const keys = await derivePairKeys({
      sharedSecret,
      appId: this.#appId,
      selfSharePub: this.#sharingKeyPair.publicKey,
      peerSharePub,
    });
    const entry = { sharedSecret, ...keys };
    this.#pairKeyCache.set(connectionSharePubBase64Url, entry);
    return entry;
  }

  #getOrInitCounters(connectionSharePubBase64Url: string): any {
    let counters = this.#shareLogCounters.get(connectionSharePubBase64Url);
    if (!counters) {
      counters = {
        nextOutboundSeq: 0,
        nonSnapshotsSinceLastSnapshot: 0,
        compactionInterval: DEFAULT_COMPACTION_INTERVAL,
      };
      this.#shareLogCounters.set(connectionSharePubBase64Url, counters);
    }
    return counters;
  }

  /**
   * Look up a connection in the persisted connections record by share_pub. Used by
   * the share-log helpers to check that we're talking to a real connection (and
   * to grab the cached `signing_pub` for verification).
   *
   * @returns {Promise<Object | null>}
   */
  async #findConnectionBySharePub(connectionSharePubBase64Url: string): Promise<any> {
    const connectionsState = await this.#loadConnectionsRecord();
    return connectionsState.record.connections.find(
      (f: any) => f.share_pub === connectionSharePubBase64Url,
    ) || null;
  }

  /**
   * Internal: publish a single signed + encrypted share-log entry to a
   * connection's outbound log at the writer's next seq.
   *
   * Steps (sharing §8.1, §9.1):
   *   1. Resolve pair keys (S_AB, outbound K_AB / T_AB_seed).
   *   2. Allocate the next outbound seq from the per-connection counter.
   *   3. Build the operation with that seq baked in.
   *   4. Sign with the user's existing ECDSA P-256 signing key.
   *   5. AES-GCM encrypt under outbound K_AB (AAD = "tarn-share-log-v1").
   *   6. Compute the tag and POST to /share/log/publish.
   *   7. On 409, surface the error to the caller — multi-device retry is 5c.
   *   8. On success, advance the counters; emit a compaction snapshot if
   *      we just crossed the threshold (sharing §8.6) — but only if the
   *      caller didn't supply their own snapshot (`opts.skipCompaction`).
   *
   * Returns the final seq + tag + Arweave txid so callers (and tests) can
   * round-trip via `_fetchShareLogEntry`.
   *
   * 5c retry semantics (§13.1, multi-device): when `opts.retryOn409` is
   * `true`, a 409 from a sibling-device concurrent publish triggers up to
   * `opts.maxRetries` (default 5) re-attempts. Each retry re-runs outbound
   * highest-seq discovery (§9.2), advances the counter past the winner's
   * seq, **re-signs** the operation under the new seq (since `seq` is in
   * `sig_input` per §8.1), and re-encrypts under a fresh IV before
   * republishing. If the 409's `existing_txid` is one this session has
   * already published, the publish is treated as already-done — defends
   * against the network-hiccup-then-retry case where we won the race but
   * never observed the response.
   *
   * @param {Object} connection - connections-record entry (has share_pub, signing_pub)
   * @param {{type: string, [key: string]: any}} operationFields - omit `seq`
   * @param {{
   *   skipCompaction?: boolean,
   *   snapshotState?: Object,
   *   retryOn409?: boolean,
   *   maxRetries?: number,
   * }} [opts]
   * @returns {Promise<{
   *   seq: number,
   *   tag: string,
   *   txid: string,
   *   retried?: number,                            // count of 409 retries (0 if first try succeeded)
   *   alreadyPublished?: boolean,                  // true if 409 was our own previous publish
   *   compactionSnapshot?: { seq: number, tag: string, txid: string },
   * }>}
   */
  async _publishShareLogEntry(connection: any, operationFields: any, opts: any = {}): Promise<any> {
    await this.#requireAuth();
    if (!connection || typeof connection.share_pub !== 'string') {
      throw new Error('_publishShareLogEntry: connection.share_pub is required');
    }
    if (!operationFields || typeof operationFields !== 'object') {
      throw new Error('_publishShareLogEntry: operationFields is required');
    }

    const pair = await this.#getPairKeysFor(connection.share_pub);
    const counters = this.#getOrInitCounters(connection.share_pub);
    const retryOn409 = opts.retryOn409 === true;
    const maxRetries = Number.isInteger(opts.maxRetries) && opts.maxRetries > 0
      ? opts.maxRetries
      : 5;

    let attempts = 0;
    let alreadyPublished = false;
    let seq;
    let tag;
    let txid;

    while (true) {
      seq = counters.nextOutboundSeq;
      const operation = buildOperationUnsigned({ ...operationFields, seq });
      const signed = await signOperation(operation, this.#signingKeyPair!.privateKey);
      const blob = await encryptShareLogEntry(signed, pair.outboundKey);
      tag = await deriveLogTag(pair.outboundTagSeed, seq);

      try {
        txid = await this.#postShareLogPublish(tag, blob);
        break;
      } catch (err: any) {
        if (err.code !== 'SHARE_LOG_TAG_CONFLICT' || !retryOn409) {
          throw err;
        }

        // Network-hiccup-retry detection: if the winner txid is one this
        // session published, we *are* the winner — succeed with the known
        // txid rather than republishing the same op at the next seq.
        const ourTxids = this.#publishedTxidsByConnection.get(connection.share_pub);
        if (err.existingTxid && ourTxids?.has(err.existingTxid)) {
          // Advance the counter past the conflicting seq so subsequent
          // publishes don't re-collide with the same already-won slot.
          counters.nextOutboundSeq = seq + 1;
          if (operation.type === OP_SNAPSHOT) {
            counters.nonSnapshotsSinceLastSnapshot = 0;
          } else {
            counters.nonSnapshotsSinceLastSnapshot += 1;
          }
          txid = err.existingTxid;
          alreadyPublished = true;
          break;
        }

        attempts += 1;
        if (attempts > maxRetries) {
          throw new Error(
            `_publishShareLogEntry: exceeded ${maxRetries} retries for ${operation.type} ` +
            `to ${connection.share_pub.slice(0, 8)}... — last conflict at seq=${seq} ` +
            `(winner txid=${err.existingTxid ?? 'unknown'})`,
          );
        }

        // §13.1: another writer won this seq slot. Re-discover the current
        // highest outbound seq, bump our counter past it, re-sign at the new
        // seq, and republish. Re-signing is mandatory because `seq` is part
        // of the signature input (§8.1) — reusing the old signature would
        // make the entry fail recipient verification.
        const probedHighest = await this.#discoverOutboundHighestSeq(pair, {
          anchor: seq + 1,
        });
        const newNext = Math.max(seq + 1, probedHighest + 1);
        counters.nextOutboundSeq = newNext;
        // Loop continues — top of loop will pick up the new seq.
      }
    }

    if (!alreadyPublished) {
      counters.nextOutboundSeq = seq + 1;
      if (operationFields.type === OP_SNAPSHOT) {
        counters.nonSnapshotsSinceLastSnapshot = 0;
      } else {
        counters.nonSnapshotsSinceLastSnapshot += 1;
      }
    }

    // Track the txid for own-publish detection on subsequent retries.
    this.#recordPublishedTxid(connection.share_pub, txid);

    let compactionSnapshot;
    if (
      !opts.skipCompaction
      && operationFields.type !== OP_SNAPSHOT
      && shouldEmitSnapshot(counters)
    ) {
      // §8.3.5: a snapshot REPLACES state wholesale on the recipient. An
      // empty snapshot would erase the recipient's view of everything we've
      // shared — that's a destructive bug, not a no-op compaction. Two paths:
      //   1. Caller supplied `opts.snapshotState` — high-level methods like
      //      shareContent/updateShareContent/unshareContent build the tentative
      //      post-op state explicitly and pass it through.
      //   2. Caller omitted `opts.snapshotState` — auto-hydrate the outbound
      //      state from our own log and apply the just-published op to it
      //      so the snapshot reflects the correct post-op state.
      // The previous "fallback to {}" was a destructive default; #17 removes
      // it so callers can't accidentally publish an empty snapshot.
      let snapshotState;
      if (opts.snapshotState !== undefined) {
        snapshotState = opts.snapshotState;
      } else {
        await this.#hydrateOutboundState(connection);
        snapshotState = this.#tentativeOutboundState(connection);
        applyOperationToState(snapshotState, { ...operationFields, seq });
      }
      const snapshotFields = {
        type: OP_SNAPSHOT,
        state: snapshotState,
        snapshot_at: Math.floor(Date.now() / 1000),
        prior_seq: seq,
      };
      const snap = await this._publishShareLogEntry(
        connection, snapshotFields,
        { skipCompaction: true, retryOn409, maxRetries, snapshotState },
      );
      compactionSnapshot = { seq: snap.seq, tag: snap.tag, txid: snap.txid };
      // Commit the snapshot state into the outbound cache so subsequent
      // operations don't re-hydrate redundantly.
      this.#commitOutboundState(connection, snapshotState);
    }

    const out: any = { seq, tag, txid };
    if (attempts > 0) out.retried = attempts;
    if (alreadyPublished) out.alreadyPublished = true;
    if (compactionSnapshot) out.compactionSnapshot = compactionSnapshot;
    return out;
  }

  #recordPublishedTxid(sharePub: string, txid: string): void {
    if (!txid) return;
    let set = this.#publishedTxidsByConnection.get(sharePub);
    if (!set) {
      set = new Set();
      this.#publishedTxidsByConnection.set(sharePub, set);
    }
    set.add(txid);
  }

  /**
   * Probe an OUTBOUND tag for existence (no decryption). Used by the
   * multi-device retry path to find the winner's seq without trying to
   * decrypt their entry under our outbound key (which would fail anyway,
   * since outbound is the writer's encryption direction, not the reader's).
   */
  async #probeOutboundTagExists(pair: any, seq: number): Promise<boolean> {
    const tag = await deriveLogTag(pair.outboundTagSeed, seq);
    const blob = await this.#getShareLogBlobByTag(tag);
    return blob !== null;
  }

  /**
   * Discover the current highest outbound seq (the seq slot of the most
   * recent entry on our outbound-to-connection log). Used during multi-device
   * 409 retry (§13.1) to find where the winner landed without per-pair
   * prefix queries (§9.2).
   *
   * Returns -1 if no entry at or above `anchor` exists.
   */
  async #discoverOutboundHighestSeq(pair: any, opts: any = {}): Promise<number> {
    const result = await discoverHighestSeq({
      probe: (s) => this.#probeOutboundTagExists(pair, s),
      anchor: opts.anchor ?? 0,
    });
    return result.highestSeq;
  }

  /**
   * Internal: fetch a single share-log entry by seq from a connection's outbound
   * log (the inbound direction from our perspective). Decrypts with the
   * inbound K_AB, verifies the sender's ECDSA signature against the connection's
   * cached `signing_pub`, and returns the parsed signed operation.
   *
   * Single-entry fetch only — full state-machine read is 5c.
   *
   * @param {Object} connection - connections-record entry (has share_pub, signing_pub)
   * @param {number} seq
   * @returns {Promise<{
   *   txid: string,
   *   tag: string,
   *   operation: Object,            // operation_signed (with `signature` field)
   *   verified: boolean,            // ECDSA verify result vs. connection.signing_pub
   *   publishedAt: number | null,
   * } | null>}
   */
  async _fetchShareLogEntry(connection: any, seq: number): Promise<any> {
    await this.#requireAuth();
    if (!connection || typeof connection.share_pub !== 'string') {
      throw new Error('_fetchShareLogEntry: connection.share_pub is required');
    }
    if (typeof connection.signing_pub !== 'string') {
      throw new Error('_fetchShareLogEntry: connection.signing_pub is required');
    }

    const pair = await this.#getPairKeysFor(connection.share_pub);
    const tag = await deriveLogTag(pair.inboundTagSeed, seq);
    const fetched = await this.#getShareLogBlobByTag(tag);
    if (!fetched) return null;

    let operation;
    try {
      operation = await decryptShareLogEntry(fetched.ciphertext, pair.inboundKey);
    } catch (err: any) {
      throw new Error(`_fetchShareLogEntry: decrypt failed at seq ${seq}: ${err.message}`);
    }
    const verified = await verifyOperationSignature(operation, connection.signing_pub);

    return {
      txid: fetched.txid,
      tag,
      operation,
      verified,
      publishedAt: fetched.publishedAt ?? null,
    };
  }

  /**
   * Internal: publish a seq=0 snapshot to a freshly-connected outbound log
   * (sharing §6.6). Default: empty snapshot (a no-op bootstrap point). Apps
   * that want "Bob sees Alice's current full library" pass `state` explicitly
   * — Tarn's SDK is app-agnostic, so the platform layer doesn't know what
   * "full library" means for any given app.
   *
   * Public ish — prefixed with `_` to mark it as semi-internal so the public
   * surface stays predictable for 5c/5d. Apps will call higher-level
   * methods once those land.
   *
   * @param {Object} connection
   * @param {{ state?: Object }} [opts]
   */
  async _publishInitialSnapshot(connection: any, opts: any = {}): Promise<any> {
    const state = opts.state ?? {};
    const result = await this._publishShareLogEntry(connection, {
      type: OP_SNAPSHOT,
      state,
      snapshot_at: Math.floor(Date.now() / 1000),
      prior_seq: null,
    });
    // Seed the outbound state cache so subsequent shareContent / etc. emit
    // meaningful auto-snapshots without re-reading the log.
    this.#outboundStateCache.set(connection.share_pub, {
      state: { ...state },
      hydrated: true,
    });
    return result;
  }

  // ============ SHARE LOG — READ FLOW (issue #16, Section 5c) ============

  /**
   * Read a connection's outbound share log and reconstruct the full state
   * (sharing §8.5 bootstrap). Walks back from the highest seq to the most
   * recent `snapshot` (or seq=0 if none), then walks forward applying each
   * subsequent operation per the §8.4 idempotency rules.
   *
   * Returns the resulting `{ content_id: { tx_id, cek } }` map. The map is
   * also cached per-connection per-device so {@link syncShareLog} can apply
   * incremental updates without re-walking history.
   *
   * Highest-seq discovery is logarithmic (§9.2): O(log N) tag fetches for a
   * log of length N. The seed never crosses to Tarn — only individual
   * pseudorandom tag values.
   *
   * Entries that fail decryption or signature verification are logged as
   * warnings and skipped; the state machine continues with the next entry
   * (sharing §13.3).
   *
   * @param {{ share_pub: string, signing_pub: string }} connection - connections-record entry
   * @param {{
   *   refresh?: boolean,                       // ignore cache (default: false)
   * }} [opts]
   * @returns {Promise<Object>} state map: `{ [content_id]: { tx_id, cek } }`
   */
  async readShareLog(connection: any, opts: any = {}): Promise<any> {
    await this.#requireAuth();
    if (!connection || typeof connection.share_pub !== 'string') {
      throw new Error('readShareLog(): connection.share_pub is required');
    }
    if (typeof connection.signing_pub !== 'string') {
      throw new Error('readShareLog(): connection.signing_pub is required');
    }
    if (!opts.refresh) {
      const cached = this.#readStateCache.get(connection.share_pub);
      if (cached) return { ...cached.state };
    }

    const pair = await this.#getPairKeysFor(connection.share_pub);

    // §9.2 highest-seq discovery, anchored at seq=0 so the result is
    // unambiguous: -1 means truly empty (no entries at all), 0 means only
    // the handshake snapshot, N means N+1 entries. Probes 0, 1, 3, 7, 15,
    // ... — the doubling starts after the first hit.
    const { highestSeq } = await discoverHighestSeq({
      probe: (seq) => this.#probeInboundTagExists(pair, seq),
      anchor: 0,
    });

    if (highestSeq < 0) {
      // Truly empty log — no entries at all. Cache the empty state so
      // syncShareLog can incrementally pick up future entries.
      this.#readStateCache.set(connection.share_pub, {
        state: {},
        lastSeqSeen: -1,
      });
      return {};
    }

    // Walk back to the most recent snapshot (or seq=0 if none found before
    // we get there). Bootstrap cost is bounded by §8.6 compaction policy:
    // typical walks land at seq=0 (handshake snapshot) or within
    // `compactionInterval` entries.
    let snapshotSeq = -1;
    let snapshotPayload = null;
    for (let seq = highestSeq; seq >= 0; seq--) {
      const entry = await this._fetchShareLogEntry(connection, seq);
      if (!entry) {
        // Gap in the dense log — should not occur in normal flow. Continue
        // walking back; the §8.4 rules will keep state consistent if some
        // entries are missing.
        continue;
      }
      if (!entry.verified) {
        console.warn(
          `[TarnClient] readShareLog: skipping unverifiable entry from ${connection.share_pub.slice(0, 8)}... at seq=${seq}`,
        );
        continue;
      }
      if (entry.operation.type === OP_SNAPSHOT) {
        snapshotSeq = seq;
        snapshotPayload = entry.operation;
        break;
      }
    }

    // Apply snapshot (if any) then walk forward. If no snapshot was found
    // — unusual but possible if the handshake snapshot's signature failed
    // verification — start from empty state and apply every entry from
    // seq=0 forward, letting §8.4 idempotency rules resolve missing-prior
    // operations as warnings.
    const state = {};
    let cursorSeq;
    if (snapshotSeq >= 0) {
      applyOperationToState(state, snapshotPayload);
      cursorSeq = snapshotSeq + 1;
    } else {
      cursorSeq = 0;
    }

    let lastApplied = snapshotSeq;
    for (let seq = cursorSeq; seq <= highestSeq; seq++) {
      const entry = await this._fetchShareLogEntry(connection, seq);
      if (!entry) continue;
      if (!entry.verified) {
        console.warn(
          `[TarnClient] readShareLog: skipping unverifiable entry from ${connection.share_pub.slice(0, 8)}... at seq=${seq}`,
        );
        continue;
      }
      // §13.5: rotate_identity is a TERMINAL entry on the OLD log. Once we
      // see it (with a valid signature under the connection's currently-cached
      // signing_pub, i.e., the OLD signing_pub from the rotating party's
      // perspective), update the connection record and re-bootstrap on the
      // NEW log. Any further entries on the OLD log past this point are
      // forgeries or stale duplicates and must be ignored.
      if (entry.operation.type === OP_ROTATE_IDENTITY) {
        const updatedConnection = await this.#processRotateIdentityEntry(connection, entry.operation);
        // Re-bootstrap on the NEW log. The NEW log starts at seq=0 with a
        // fresh snapshot from the rotating party (sharing §13.5 step 8),
        // so a `refresh: true` read produces a defensible final state.
        return await this.readShareLog(updatedConnection, { refresh: true });
      }
      applyOperationToState(state, entry.operation);
      lastApplied = seq;
    }

    this.#readStateCache.set(connection.share_pub, {
      state: { ...state },
      lastSeqSeen: Math.max(highestSeq, lastApplied, -1),
    });
    return { ...state };
  }

  /**
   * Incrementally sync a connection's outbound log: apply any new entries past
   * the cached `lastSeqSeen` (sharing §8.5 incremental sync). If no cache
   * exists yet (cold start), this performs a full {@link readShareLog}
   * bootstrap.
   *
   * @param {{ share_pub: string, signing_pub: string }} connection
   * @returns {Promise<Object>} updated state map
   */
  async syncShareLog(connection: any): Promise<any> {
    await this.#requireAuth();
    if (!connection || typeof connection.share_pub !== 'string') {
      throw new Error('syncShareLog(): connection.share_pub is required');
    }
    if (typeof connection.signing_pub !== 'string') {
      throw new Error('syncShareLog(): connection.signing_pub is required');
    }
    const cached = this.#readStateCache.get(connection.share_pub);
    if (!cached) {
      return await this.readShareLog(connection);
    }

    const pair = await this.#getPairKeysFor(connection.share_pub);
    const { highestSeq } = await discoverHighestSeq({
      probe: (seq) => this.#probeInboundTagExists(pair, seq),
      anchor: cached.lastSeqSeen + 1,
    });

    if (highestSeq <= cached.lastSeqSeen) {
      return { ...cached.state };
    }

    const state = { ...cached.state };
    let lastApplied = cached.lastSeqSeen;
    for (let seq = cached.lastSeqSeen + 1; seq <= highestSeq; seq++) {
      const entry = await this._fetchShareLogEntry(connection, seq);
      if (!entry) continue;
      if (!entry.verified) {
        console.warn(
          `[TarnClient] syncShareLog: skipping unverifiable entry from ${connection.share_pub.slice(0, 8)}... at seq=${seq}`,
        );
        lastApplied = seq;
        continue;
      }
      if (entry.operation.type === OP_ROTATE_IDENTITY) {
        // §13.5: terminal entry on OLD log → process rotation, switch to
        // NEW log. Any further entries on the OLD log are ignored.
        const updatedConnection = await this.#processRotateIdentityEntry(connection, entry.operation);
        return await this.readShareLog(updatedConnection, { refresh: true });
      }
      applyOperationToState(state, entry.operation);
      lastApplied = seq;
    }

    this.#readStateCache.set(connection.share_pub, {
      state: { ...state },
      lastSeqSeen: Math.max(highestSeq, lastApplied),
    });
    return { ...state };
  }

  /**
   * Probe an INBOUND tag for existence (no decryption). Used by the
   * read-flow highest-seq discovery to avoid spending an AES-GCM decrypt
   * per probe.
   */
  async #probeInboundTagExists(pair: any, seq: number): Promise<boolean> {
    const tag = await deriveLogTag(pair.inboundTagSeed, seq);
    const blob = await this.#getShareLogBlobByTag(tag);
    return blob !== null;
  }

  /**
   * Test-only: peek at the read-state cache for a connection. Returns null if
   * no entry. Production code should not depend on this — it exists for
   * tests asserting cache-hit semantics.
   */
  _peekReadStateCache(connectionSharePubBase64Url: string): any {
    const e = this.#readStateCache.get(connectionSharePubBase64Url);
    if (!e) return null;
    return { state: { ...e.state }, lastSeqSeen: e.lastSeqSeen };
  }

  // ============ SHARE LOG — HIGH-LEVEL WRITE METHODS (Section 5c) ============

  /**
   * High-level: share a content item with a connection (sharing §8.3.1). Composes
   * 5b's `_publishShareLogEntry` primitive with 5c's multi-device retry
   * (§13.1). On a 409 from a sibling-device concurrent publish, the retry
   * loop re-runs highest-seq discovery, advances the counter, re-signs the
   * operation under the new seq (mandatory — `seq` is in the signature
   * input per §8.1), and republishes. Up to 5 retries before surfacing the
   * failure.
   *
   * Tracks the outbound state per connection so any auto-compaction snapshot
   * (§8.6) emits a meaningful state map rather than the empty-state default
   * — an empty snapshot is NOT a no-op (§8.3.5) and would wipe the
   * recipient's view of what we've shared.
   *
   * @param {{ share_pub: string, signing_pub: string }} connection
   * @param {string} contentId - app-stable content id (e.g., book id)
   * @param {string} txId - Arweave transaction id of the latest content blob
   * @param {string} cekBase64Url - 32-byte content encryption key, base64url
   * @returns {Promise<{ seq: number, tag: string, txid: string, retried?: number }>}
   */
  async shareContent(connection: any, contentId: string, txId: string, cekBase64Url: string): Promise<any> {
    await this.#hydrateOutboundState(connection);
    const tentative = this.#tentativeOutboundState(connection);
    tentative[contentId] = { tx_id: txId, cek: cekBase64Url };
    const result = await this._publishShareLogEntry(connection, {
      type: OP_ADD,
      content_id: contentId,
      tx_id: txId,
      cek: cekBase64Url,
      shared_at: Math.floor(Date.now() / 1000),
    }, { retryOn409: true, snapshotState: tentative });
    this.#commitOutboundState(connection, tentative);
    return result;
  }

  /**
   * High-level: notify a connection that a shared content item has a new
   * Arweave version (sharing §8.3.2). CEK is unchanged. Uses the same 409
   * retry semantics as {@link shareContent}.
   */
  async updateShareContent(connection: any, contentId: string, newTxId: string): Promise<any> {
    await this.#hydrateOutboundState(connection);
    const tentative = this.#tentativeOutboundState(connection);
    if (tentative[contentId]) {
      tentative[contentId] = { tx_id: newTxId, cek: tentative[contentId].cek };
    }
    const result = await this._publishShareLogEntry(connection, {
      type: OP_UPDATE,
      content_id: contentId,
      tx_id: newTxId,
      updated_at: Math.floor(Date.now() / 1000),
    }, { retryOn409: true, snapshotState: tentative });
    this.#commitOutboundState(connection, tentative);
    return result;
  }

  /**
   * High-level: revoke a content item from a connection's view (sharing §8.3.4
   * `remove`). Note this is a UI hint per the design — the recipient may
   * have cached prior versions locally, and `remove` does not retract those.
   * For cryptographic revocation, use a `rotate` (5d) instead.
   */
  async unshareContent(connection: any, contentId: string): Promise<any> {
    await this.#hydrateOutboundState(connection);
    const tentative = this.#tentativeOutboundState(connection);
    delete tentative[contentId];
    const result = await this._publishShareLogEntry(connection, {
      type: OP_REMOVE,
      content_id: contentId,
      removed_at: Math.floor(Date.now() / 1000),
    }, { retryOn409: true, snapshotState: tentative });
    this.#commitOutboundState(connection, tentative);
    return result;
  }

  /**
   * High-level: explicitly publish a snapshot capturing the current outbound
   * state to a connection (sharing §8.3.5 / §8.6). Apps can call this to bound
   * the bootstrap cost for new readers, or after a batch of mutations to
   * checkpoint.
   *
   * If `state` is omitted, the current tracked outbound state is used (i.e.,
   * lazy hydration + accumulated shareContent / updateShareContent /
   * unshareContent updates from this session).
   *
   * @param {{ share_pub: string, signing_pub: string }} connection
   * @param {Object | undefined} [state] - optional explicit override
   * @returns {Promise<{ seq: number, tag: string, txid: string }>}
   */
  async snapshotShareLog(connection: any, state?: any): Promise<any> {
    if (state === undefined) {
      await this.#hydrateOutboundState(connection);
      state = this.#tentativeOutboundState(connection);
    } else if (!state || typeof state !== 'object' || Array.isArray(state)) {
      throw new Error('snapshotShareLog(): state must be an object');
    }
    const counters = this.#getOrInitCounters(connection.share_pub);
    const result = await this._publishShareLogEntry(connection, {
      type: OP_SNAPSHOT,
      state,
      snapshot_at: Math.floor(Date.now() / 1000),
      prior_seq: counters.nextOutboundSeq > 0 ? counters.nextOutboundSeq - 1 : null,
    }, { retryOn409: true, snapshotState: state });
    this.#commitOutboundState(connection, state);
    return result;
  }

  // ============ REVOCATION (issue #17, Section 5d, sharing §10) ============

  /**
   * RemoveConnection (sharing §10.1). Removes the connection from the persisted connections
   * record; subsequent share-log writes to that connection stop, and the read
   * flow stops surfacing their outbound updates. Per-connection caches are
   * cleared so a subsequent re-connection (§13.7) starts clean.
   *
   * **Direction-aware**: this is one-side. The removeConnectioned party receives no
   * cryptographic signal — they may infer from sustained inactivity, or via
   * an app-level UX cue ("no recent activity from this connection"). Mutual
   * Mutual removal requires both sides to call `removeConnection` independently.
   *
   * **Optional courtesy** (`{ notify: true }`): before stopping further
   * publication, publishes a final `remove` operation to the connection's
   * outbound log for every content_id we were currently sharing with them.
   * This is a UI signal to the recipient, NOT a cryptographic enforcement.
   * The recipient may have cached prior versions locally; `remove` does not
   * retract those. Use {@link revokeContentFromConnections} for cryptographic
   * revocation (CEK rotation) of remaining connections' access.
   *
   * @param {{ share_pub: string }} connection
   * @param {{ notify?: boolean }} [opts]
   * @returns {Promise<{
   *   removed: boolean,
   *   notifications?: Array<{ content_id: string, seq: number, txid: string }>,
   * }>}
   */
  async removeConnection(connection: any, opts: any = {}): Promise<any> {
    await this.#requireAuth();
    if (!connection || typeof connection.share_pub !== 'string') {
      throw new Error('removeConnection(): connection.share_pub is required');
    }

    const connectionsState = await this.#loadConnectionsRecord();
    const present = connectionsState.record.connections.some((f: any) => f.share_pub === connection.share_pub);
    if (!present) {
      this.#clearConnectionCaches(connection.share_pub);
      return { removed: false };
    }

    let notifications;
    if (opts.notify === true) {
      // Courtesy: publish a final `remove` per content_id we're currently
      // sharing with this connection. We need the outbound state to enumerate
      // the content_ids — hydrate from the existing log if not cached.
      const fullConnection = connectionsState.record.connections.find((f: any) => f.share_pub === connection.share_pub) || connection;
      try {
        await this.#hydrateOutboundState(fullConnection);
      } catch (err: any) {
        // If hydration fails (e.g., transient API error), still proceed with
        // the removeConnection — the connection record removal is the durable signal.
        console.warn(`[TarnClient] removeConnection(notify): hydrate outbound state failed: ${err.message}`);
      }
      const tentative = this.#tentativeOutboundState(fullConnection);
      const contentIds = Object.keys(tentative);
      notifications = [];
      for (const contentId of contentIds) {
        try {
          const res = await this._publishShareLogEntry(fullConnection, {
            type: OP_REMOVE,
            content_id: contentId,
            removed_at: Math.floor(Date.now() / 1000),
          }, {
            retryOn409: true,
            // After this loop we drop all outbound state for this connection; the
            // tentative snapshotState reflects the running removal so any
            // mid-loop auto-compaction snapshot doesn't re-include items
            // we've already removed.
            snapshotState: { ...tentative },
          });
          delete tentative[contentId];
          notifications.push({ content_id: contentId, seq: res.seq, txid: res.txid });
        } catch (err: any) {
          // Best-effort: log + continue. The connection record removal still
          // happens below.
          console.warn(`[TarnClient] removeConnection(notify): remove ${contentId} failed: ${err.message}`);
        }
      }
    }

    const updated = removeConnection(connectionsState.record, connection.share_pub);
    await this.#saveConnectionsRecord(connectionsState, updated);
    this.#clearConnectionCaches(connection.share_pub);

    return notifications ? { removed: true, notifications } : { removed: true };
  }

  /**
   * Rotate the CEK for a content_id and announce it to all remaining connections
   * with access (sharing §10.3). Going-forward only: old versions of the
   * content (encrypted under the OLD CEK) remain decryptable to anyone who
   * already has them; the new CEK is required for future versions.
   *
   * Apps drive this when a content item should become inaccessible to a
   * just-removeConnectioned party (or to bound side-channel risk per §10.2). The
   * SDK fans out a signed `rotate` operation to every connection currently
   * sharing this content_id; the next published version of the content
   * blob (per the per-content CEK pattern from #11) wraps the new CEK
   * under the user's DEK. Apps are responsible for re-encrypting and
   * publishing the next content version under the new CEK — Tarn's SDK
   * is app-agnostic, so it returns the new CEK for the caller to use.
   *
   * Cost: O(remaining_connections_with_access) signed log entries per content
   * item rotated. Practical for typical Bookish-class connection counts.
   *
   * @param {string} contentId - app-stable content id (e.g., book id)
   * @param {{ connections?: Array<{share_pub: string}> }} [opts] - explicit
   *   connection list override; defaults to the current connections record. Apps
   *   that just removeConnectioned Bob should call `removeConnection(bob)` first, then
   *   `revokeContentFromConnections(bookId)` — the connections record already excludes
   *   Bob by then.
   * @returns {Promise<{
   *   newCekBase64Url: string,
   *   announcements: Array<{ connectionSharePub: string, seq: number, txid: string }>,
   *   skipped: Array<{ connectionSharePub: string, reason: string }>,
   * }>}
   */
  async revokeContentFromConnections(contentId: string, opts: any = {}): Promise<any> {
    await this.#requireAuth();
    if (typeof contentId !== 'string' || contentId.length === 0) {
      throw new Error('revokeContentFromConnections(): contentId is required');
    }

    let connections;
    if (Array.isArray(opts.connections)) {
      connections = opts.connections;
    } else {
      const connectionsState = await this.#loadConnectionsRecord();
      connections = connectionsState.record.connections;
    }

    // Generate a fresh 32-byte CEK. AES-KW unwrapped form lives client-side;
    // apps wrap it under their DEK on the next content publish.
    const newCekBytes = crypto.getRandomValues(new Uint8Array(32));
    const newCekBase64Url = bytesToBase64Url(newCekBytes);
    const rotatedAt = Math.floor(Date.now() / 1000);

    const announcements = [];
    const skipped = [];
    for (const connection of connections) {
      // Hydrate so we know whether this connection currently has access. A connection
      // not currently sharing this content_id gets skipped — emitting a rotate
      // for them is wasted log space (and per §8.4 idempotency, recipients
      // would log a warning and ignore it anyway).
      try {
        await this.#hydrateOutboundState(connection);
      } catch (err: any) {
        skipped.push({ connectionSharePub: connection.share_pub, reason: `hydrate failed: ${err.message}` });
        continue;
      }
      const tentative = this.#tentativeOutboundState(connection);
      if (!tentative[contentId]) {
        skipped.push({ connectionSharePub: connection.share_pub, reason: 'not currently sharing' });
        continue;
      }
      tentative[contentId] = { tx_id: tentative[contentId].tx_id, cek: newCekBase64Url };
      try {
        const res = await this._publishShareLogEntry(connection, {
          type: OP_ROTATE,
          content_id: contentId,
          cek: newCekBase64Url,
          rotated_at: rotatedAt,
        }, { retryOn409: true, snapshotState: tentative });
        this.#commitOutboundState(connection, tentative);
        announcements.push({ connectionSharePub: connection.share_pub, seq: res.seq, txid: res.txid });
      } catch (err: any) {
        skipped.push({ connectionSharePub: connection.share_pub, reason: err.message });
      }
    }

    return { newCekBase64Url, announcements, skipped };
  }

  // ============ IDENTITY ROTATION (issue #17, Section 5d, sharing §13.5) ============

  /**
   * Publish a `rotate_identity` announcement to every connection's OLD outbound
   * log (sharing §13.5). Called by `changeCredentials` and `recoverAccount`
   * AFTER the new credential blob is published but BEFORE the local key
   * material is swapped to the new identity.
   *
   * Invariants the caller must uphold:
   *   - `oldSharingKeyPair`, `oldSigningKeyPair`, `oldConnectionsRecord` reflect
   *     the pre-rotation state.
   *   - `this.#sharingKeyPair`, `this.#signingKeyPair`, `this.#pairKeyCache`
   *     all still hold OLD values (we read them via the pair-key cache to
   *     produce OLD K_AB_to_B + OLD T_AB_seed_to_B).
   *   - The new credential blob has already been written so a recipient who
   *     re-fetches Alice's blob mid-rotation sees the NEW pubkeys
   *     (the durable indicator of in-flight rotation per §13.5).
   *
   * Race handling: each per-connection publish uses 5c's `retryOn409` retry. If a
   * stale-device concurrent publish lands at `seq_max_old + 1` first, the
   * retry path advances past it and lands the rotation at `seq_max_old + 2`.
   * Recipients walking forward see the rotation in order; any further
   * entries on the OLD log after rotation are ignored per §13.5.
   *
   * Best-effort across connections: a per-connection failure is logged and the
   * announcement loop continues. The next session retries (the new credential
   * blob is already published, so the next session can detect "some connections
   * still have OLD pubkeys cached" via the rotation-in-flight signal).
   *
   * @returns {Promise<Array<{ connectionSharePub: string, seq?: number, txid?: string, error?: string }>>}
   */
  async #announceIdentityRotationToConnections(args: any): Promise<any[]> {
    const {
      oldSharingKeyPair,
      oldSigningKeyPair,
      oldConnectionsRecord,
      newSharingPublicKey,
      newSigningPublicKey,
      newCredentialLookupKey,
      rotatedAt,
    } = args;
    if (!oldSharingKeyPair?.privateKey) {
      throw new Error('#announceIdentityRotationToConnections: oldSharingKeyPair.privateKey is required');
    }
    if (!oldSigningKeyPair?.privateKey) {
      throw new Error('#announceIdentityRotationToConnections: oldSigningKeyPair.privateKey is required');
    }
    if (!oldConnectionsRecord || !Array.isArray(oldConnectionsRecord.connections)) {
      throw new Error('#announceIdentityRotationToConnections: oldConnectionsRecord is required');
    }

    const newSharePubBase64Url = encodeSharePub(newSharingPublicKey);
    const newSigningPubBase64 = await exportPublicKey(newSigningPublicKey);

    const results = [];
    for (const connection of oldConnectionsRecord.connections) {
      try {
        // Derive OLD per-pair keys directly (NOT via the cache; the cache
        // entry would be re-derived on the fly from the OLD share_priv but
        // we want explicit control here to keep the logic auditable).
        let peerSharePub;
        try {
          peerSharePub = decodeSharePub(connection.share_pub);
        } catch (err: any) {
          results.push({ connectionSharePub: connection.share_pub, error: `decode share_pub: ${err.message}` });
          continue;
        }
        const oldSharedSecret = deriveSharedSecret(oldSharingKeyPair.privateKey, peerSharePub);
        const oldPair = await derivePairKeys({
          sharedSecret: oldSharedSecret,
          appId: this.#appId,
          selfSharePub: oldSharingKeyPair.publicKey,
          peerSharePub,
        });

        // Discover the OLD highest seq so the rotation lands at seq_max + 1.
        const oldHighestSeq = await this.#discoverHighestSeqViaTagSeed(oldPair.outboundTagSeed, 0);
        const targetSeq = oldHighestSeq + 1;

        const txidOrError = await this.#publishRotateIdentityAtSeq({
          connection,
          oldPair,
          oldSigningPrivateKey: oldSigningKeyPair.privateKey,
          startSeq: targetSeq,
          payload: {
            new_share_pub: newSharePubBase64Url,
            new_signing_pub: newSigningPubBase64,
            new_credential_lookup_key: newCredentialLookupKey,
            rotated_at: rotatedAt,
          },
        });

        if (txidOrError.error) {
          results.push({ connectionSharePub: connection.share_pub, error: txidOrError.error });
        } else {
          results.push({
            connectionSharePub: connection.share_pub,
            seq: txidOrError.seq,
            txid: txidOrError.txid,
          });
        }
      } catch (err: any) {
        results.push({ connectionSharePub: connection.share_pub, error: err.message });
      }
    }
    return results;
  }

  /**
   * Discover the highest existing seq on a log identified by a tag seed, by
   * probing OUTBOUND tags. Used by the rotation-announce path (which works
   * with explicitly-derived pair keys, not the cached pair-key entry).
   */
  async #discoverHighestSeqViaTagSeed(tagSeed: Uint8Array, anchor: number = 0): Promise<number> {
    const result = await discoverHighestSeq({
      probe: async (seq) => {
        const tag = await deriveLogTag(tagSeed, seq);
        const blob = await this.#getShareLogBlobByTag(tag);
        return blob !== null;
      },
      anchor,
    });
    return result.highestSeq;
  }

  /**
   * Publish a rotate_identity entry under the OLD pair keys, with built-in
   * retry on 409 for the rotation window race (§13.5). Returns either
   * `{ seq, txid }` on success or `{ error }` on terminal failure.
   *
   * Each retry re-derives the next free seq, re-builds the operation with
   * that seq baked in, re-signs (mandatory — `seq` is in the signature input
   * per §8.1), re-encrypts under a fresh IV, and republishes. Bounded to 5
   * retries so a perpetually-busy log doesn't loop forever.
   */
  async #publishRotateIdentityAtSeq(args: any): Promise<any> {
    const { connection, oldPair, oldSigningPrivateKey, startSeq, payload } = args;
    const MAX_RETRIES = 5;
    let seq = startSeq;
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      const operation = buildOperationUnsigned({ type: OP_ROTATE_IDENTITY, seq, ...payload });
      const signed = await signOperation(operation, oldSigningPrivateKey);
      const blob = await encryptShareLogEntry(signed, oldPair.outboundKey);
      const tag = await deriveLogTag(oldPair.outboundTagSeed, seq);
      try {
        const txid = await this.#postShareLogPublish(tag, blob);
        return { seq, txid };
      } catch (err: any) {
        if (err.code !== 'SHARE_LOG_TAG_CONFLICT') {
          return { error: err.message };
        }
        if (attempt === MAX_RETRIES) {
          return { error: `rotate_identity exceeded ${MAX_RETRIES} retries (last conflict at seq=${seq})` };
        }
        // Re-discover anchored at seq+1 so we skip past whatever raced us.
        const probedHighest = await this.#discoverHighestSeqViaTagSeed(oldPair.outboundTagSeed, seq + 1);
        seq = Math.max(seq + 1, probedHighest + 1);
      }
    }
    return { error: 'rotate_identity: unreachable retry loop exit' };
  }

  /**
   * Recipient-side processing of a `rotate_identity` entry surfaced during
   * read/sync (sharing §13.5).
   *
   * Pre-condition: the caller has already verified the operation's signature
   * against the connection's CURRENT signing_pub (which is the OLD signing_pub
   * from the rotating party's perspective — that's what makes the
   * announcement trustworthy).
   *
   * Steps (§13.5 step 4-7):
   *   1. Update Alice's connection record entry: replace share_pub, signing_pub,
   *      credential_lookup_key. Persist.
   *   2. Clear all per-connection caches keyed on the OLD share_pub. The NEW
   *      share_pub becomes the cache key going forward.
   *   3. Return the updated connection object so the caller can re-bootstrap the
   *      read flow on the NEW log under the new keys.
   *
   * Idempotent: replaying the same announcement on a fresh device produces
   * the same final state (the connection record's signing_pub now matches the
   * announcement's `new_signing_pub` so a subsequent verify still succeeds
   * because the announcement has already been accepted; if the announcement
   * is replayed, the connection record's `share_pub` no longer matches the
   * incoming `connection.share_pub` so the caller's lookup short-circuits).
   *
   * @param {Object} connection - connections-record entry (has OLD share_pub +
   *   OLD signing_pub at call time)
   * @param {Object} operation - the parsed, signature-verified
   *   rotate_identity operation
   * @returns {Promise<Object>} updated connection entry
   */
  async #processRotateIdentityEntry(connection: any, operation: any): Promise<any> {
    const newSharePubBase64Url = operation.new_share_pub;
    const newSigningPubBase64 = operation.new_signing_pub;
    const newCredentialLookupKey = operation.new_credential_lookup_key;
    const rotatedAt = operation.rotated_at;

    if (typeof newSharePubBase64Url !== 'string'
      || typeof newSigningPubBase64 !== 'string'
      || typeof newCredentialLookupKey !== 'string'
      || !Number.isInteger(rotatedAt)
    ) {
      throw new Error(
        '#processRotateIdentityEntry: malformed rotate_identity payload — caller should have validated',
      );
    }

    // Defensive: validate the new share_pub decodes cleanly. A malformed
    // value here would explode the next pair-key derivation; better to bail
    // now than half-update the connection record.
    decodeSharePub(newSharePubBase64Url);

    const oldSharePub = connection.share_pub;
    const connectionsState = await this.#loadConnectionsRecord();
    const updatedRecord = rotateConnectionIdentity(connectionsState.record, oldSharePub, {
      newSharePubBase64Url,
      newSigningPubBase64,
      newCredentialLookupKey,
      rotatedAt,
    });

    if (updatedRecord !== connectionsState.record) {
      await this.#saveConnectionsRecord(connectionsState, updatedRecord);
    }

    // Clear OLD caches — the NEW share_pub is a different cache key, so
    // explicit invalidation is mostly defensive (no entry should exist under
    // the NEW key yet). The OLD-keyed entries are now stale and must not be
    // accidentally used.
    this.#clearConnectionCaches(oldSharePub);

    return (
      updatedRecord.connections.find(f => f.share_pub === newSharePubBase64Url)
      || { ...connection, share_pub: newSharePubBase64Url, signing_pub: newSigningPubBase64 }
    );
  }

  /**
   * Drop all per-connection share-log caches for a given share_pub. Used by
   * removeConnection (§10.1) and identity rotation (§13.5) — both invalidate the
   * cached pair keys + state since the pair-keys derivation is now stale
   * (the connection's share_pub no longer maps to a current relationship, or
   * has rotated to a new value).
   */
  #clearConnectionCaches(connectionSharePubBase64Url: string): void {
    this.#pairKeyCache.delete(connectionSharePubBase64Url);
    this.#shareLogCounters.delete(connectionSharePubBase64Url);
    this.#readStateCache.delete(connectionSharePubBase64Url);
    this.#outboundStateCache.delete(connectionSharePubBase64Url);
    this.#publishedTxidsByConnection.delete(connectionSharePubBase64Url);
  }

  // ---- Outbound state tracking (Section 5c) ----

  /**
   * Lazily reconstruct outbound state for a connection by replaying our own
   * outbound log. No-op if already hydrated this session. Invoked by the
   * high-level write methods on first use per connection.
   *
   * Same algorithm as {@link readShareLog} but with the OUTBOUND tag seed +
   * outbound key (we encrypted these entries; we can decrypt them with the
   * symmetric AES-GCM key) and our OWN signing pub for verification.
   */
  async #hydrateOutboundState(connection: any): Promise<void> {
    const existing = this.#outboundStateCache.get(connection.share_pub);
    if (existing?.hydrated) return;

    const pair = await this.#getPairKeysFor(connection.share_pub);
    const ownSigningPubBase64 = await exportPublicKey(this.#signingKeyPair!.publicKey);

    const { highestSeq } = await discoverHighestSeq({
      probe: (seq) => this.#probeOutboundTagExists(pair, seq),
      anchor: 0,
    });

    if (highestSeq < 0) {
      this.#outboundStateCache.set(connection.share_pub, { state: {}, hydrated: true });
      return;
    }

    // Pre-fetch all entries seq=0..highestSeq into an array. Avoids the
    // double-walk shape from a naive walk-back-then-forward implementation.
    // The per-connection cap of MAX_LOG_BLOB_PLAINTEXT_BYTES on the writer side
    // bounds memory; for typical Bookish-class users (~100s of entries)
    // this is well under 1 MB total.
    const entries = new Array(highestSeq + 1);
    for (let seq = 0; seq <= highestSeq; seq++) {
      entries[seq] = await this.#fetchOwnOutboundEntry(pair, seq, ownSigningPubBase64);
    }

    // Walk back to the latest snapshot (or seq=0 if none).
    let snapshotSeq = -1;
    for (let seq = highestSeq; seq >= 0; seq--) {
      const e = entries[seq];
      if (e?.verified && e.operation.type === OP_SNAPSHOT) {
        snapshotSeq = seq;
        break;
      }
    }

    // Apply snapshot then walk forward.
    const state = {};
    let cursorSeq;
    if (snapshotSeq >= 0) {
      applyOperationToState(state, entries[snapshotSeq].operation);
      cursorSeq = snapshotSeq + 1;
    } else {
      cursorSeq = 0;
    }
    for (let seq = cursorSeq; seq <= highestSeq; seq++) {
      const e = entries[seq];
      if (!e || !e.verified) continue;
      applyOperationToState(state, e.operation);
    }

    this.#outboundStateCache.set(connection.share_pub, { state, hydrated: true });

    // Seed the per-connection known-txids set with our own outbound entries so
    // the multi-device retry path can detect "this 409 reports our own
    // previous publish" across cold-session boundaries.
    let txids = this.#publishedTxidsByConnection.get(connection.share_pub);
    if (!txids) {
      txids = new Set();
      this.#publishedTxidsByConnection.set(connection.share_pub, txids);
    }
    for (const e of entries) {
      if (e?.txid) txids.add(e.txid);
    }

    // Seed the writer's nextOutboundSeq + nonSnapshotsSinceLastSnapshot from
    // the actual log tip — defends against fresh-session publishes at a
    // stale seq=0 (which would 409 immediately and trigger the retry path).
    const counters = this.#getOrInitCounters(connection.share_pub);
    counters.nextOutboundSeq = highestSeq + 1;
    if (snapshotSeq >= 0) {
      counters.nonSnapshotsSinceLastSnapshot = highestSeq - snapshotSeq;
    } else {
      counters.nonSnapshotsSinceLastSnapshot = highestSeq + 1;
    }
  }

  /**
   * Fetch our OWN outbound entry at seq. Decrypts with the outbound key
   * (same as encryption — AES-GCM is symmetric) and verifies against our
   * own signing pub.
   */
  async #fetchOwnOutboundEntry(pair: any, seq: number, ownSigningPubBase64: string): Promise<any> {
    const tag = await deriveLogTag(pair.outboundTagSeed, seq);
    const fetched = await this.#getShareLogBlobByTag(tag);
    if (!fetched) return null;
    let operation;
    try {
      operation = await decryptShareLogEntry(fetched.ciphertext, pair.outboundKey);
    } catch {
      return { txid: fetched.txid, tag, operation: null, verified: false };
    }
    const verified = await verifyOperationSignature(operation, ownSigningPubBase64);
    return { txid: fetched.txid, tag, operation, verified };
  }

  /**
   * Return a SHALLOW COPY of the current outbound state for a connection, used
   * as the working set for in-flight write methods. The returned object is
   * mutated by the caller, then committed via {@link #commitOutboundState}
   * on successful publish.
   */
  #tentativeOutboundState(connection: any): any {
    const cached = this.#outboundStateCache.get(connection.share_pub);
    return cached ? { ...cached.state } : {};
  }

  #commitOutboundState(connection: any, newState: any): void {
    this.#outboundStateCache.set(connection.share_pub, {
      state: { ...newState },
      hydrated: true,
    });
  }

  /**
   * Test-only: peek at the outbound state cache for a connection. Returns null
   * if not hydrated. Used by tests asserting outbound-snapshot semantics.
   */
  _peekOutboundStateCache(connectionSharePubBase64Url: string): any {
    const e = this.#outboundStateCache.get(connectionSharePubBase64Url);
    if (!e) return null;
    return { state: { ...e.state }, hydrated: !!e.hydrated };
  }

  // ---- Private share-log helpers ----

  async #postShareLogPublish(tag: string, blob: Uint8Array): Promise<string> {
    const res = await this.#fetch('/api/v1/share/log/publish', {
      method: 'POST',
      auth: true,
      // Per-tag uniqueness means a retry at the same tag will return 409
      // every time — not retry-safe in the usual sense. The fetch wrapper
      // only retries on 5xx/429 anyway, so this is just defense-in-depth
      // signaling.
      body: {
        tag,
        type: SHARE_LOG_TYPE,
        ciphertext_base64: bytesToBase64(blob),
      },
    });
    if (res.status === 409) {
      const err: any = new Error(
        `share-log publish at tag ${tag.slice(0, 8)}... collided with existing txid ${res.json?.existing_txid}`,
      );
      err.code = 'SHARE_LOG_TAG_CONFLICT';
      err.existingTxid = res.json?.existing_txid ?? null;
      err.tag = tag;
      throw err;
    }
    if (res.status !== 200) {
      throw new Error(`share-log publish failed: ${res.json?.error || res.status}`);
    }
    return res.json.txid;
  }

  async #getShareLogBlobByTag(tag: string): Promise<any> {
    const url = `/api/v1/share/log/fetch?app=${encodeURIComponent(this.#appId)}&tag=${tag}&type=${encodeURIComponent(SHARE_LOG_TYPE)}`;
    const res = await this.#fetch(url);
    if (res.status === 404) return null;
    if (res.status !== 200) {
      throw new Error(`share-log fetch failed: ${res.json?.error || res.status}`);
    }
    const b = res.json?.blob;
    if (!b) return null;
    return {
      txid: b.txid,
      ciphertext: base64ToBytes(b.ciphertext_base64),
      publishedAt: b.published_at ?? null,
    };
  }

  // ---- Private handshake helpers ----

  async #fetchInboxBlobs(tag: string, type: string): Promise<any[]> {
    // Public endpoint — no auth needed. The recipient (us) is the only party
    // that can decrypt anyway; the API just acts as a tag-keyed cache.
    const url = `/api/v1/share/inbox/fetch?app=${encodeURIComponent(this.#appId)}&tag=${tag}&type=${encodeURIComponent(type)}`;
    const res = await this.#fetch(url);
    if (res.status !== 200) {
      console.warn(`[TarnClient] inbox fetch ${tag.slice(0, 8)}.../${type} failed: ${res.json?.error || res.status}`);
      return [];
    }
    const blobs = res.json?.blobs ?? [];
    return blobs.map((b: any) => ({
      txid: b.txid,
      ciphertext: base64ToBytes(b.ciphertext_base64),
      published_at: b.published_at,
    }));
  }

  async #pollAndProcessIncomingAccepts(myPriv: Uint8Array, myPub: Uint8Array): Promise<void> {
    const windows = DEFAULT_POLL_WINDOWS;
    const tags = await Promise.all(
      recentInboxWindows(windows).map(w => deriveInboxTag(myPub, this.#appId, w)),
    );
    const fetched = await Promise.all(
      tags.map(tag => this.#fetchInboxBlobs(tag, 'connection-accept-v1')),
    );

    let pendingState = await this.#loadPendingRequestsRecord();
    let connectionsState = await this.#loadConnectionsRecord();
    let pendingDirty = false;
    let connectionsDirty = false;

    for (const blobs of fetched) {
      for (const blob of blobs) {
        let payload;
        try {
          const pt = await hpkeOpen({
            sharePriv: myPriv,
            info: INFO_CONNECTION_ACCEPT,
            blob: blob.ciphertext,
          });
          payload = JSON.parse(new TextDecoder().decode(pt));
        } catch {
          continue;
        }
        const v = validateConnectionAcceptPayload(payload, this.#appId);
        if (!v.valid) continue;

        // Forged-accept defense (§13.9): cross-reference against outbound
        // pending. Unmatched accepts are silently dropped — no connection record
        // entry created, no UI prompt. The user is not informed.
        const outbound = findOutboundForAccept(v.normalized.inReplyToNonceBase64Url, pendingState.record.outbound);
        if (!outbound) continue;

        // Replay protection on accepts: if we've already processed this
        // accept (it appears in connections already), skip without re-writing.
        const existingConnection = connectionsState.record.connections.find((f: any) => f.share_pub === v.normalized.senderSharePubBase64Url);
        if (existingConnection) {
          // Still clear the matched outbound — sender side already moved on.
          if (pendingState.record.outbound.some((o: any) => o.request_nonce === outbound.request_nonce)) {
            pendingState = { ...pendingState, record: removeOutboundPending(pendingState.record, outbound.request_nonce!) };
            pendingDirty = true;
          }
          continue;
        }

        const newConnection = {
          username: v.normalized.senderUsername,
          share_pub: v.normalized.senderSharePubBase64Url,
          signing_pub: v.normalized.senderSigningPubBase64,
          established_at: v.normalized.timestamp,
          initial_request_nonce: outbound.request_nonce,
          label: null,
        };
        connectionsState = {
          ...connectionsState,
          record: upsertConnection(connectionsState.record, newConnection),
        };
        connectionsDirty = true;

        pendingState = {
          ...pendingState,
          record: removeOutboundPending(pendingState.record, outbound.request_nonce!),
        };
        pendingDirty = true;

        // Publish our seq=0 snapshot to the new connection's outbound log
        // (sharing §6.6). We're the side that originated the connection request;
        // the accepting side already published their seq=0 inside
        // acceptConnectionRequest. Empty state by default — apps that want to
        // pre-populate should call _publishInitialSnapshot themselves with
        // explicit state.
        try {
          await this._publishInitialSnapshot(newConnection);
        } catch (err: any) {
          console.warn(
            `[TarnClient] processing accept from ${v.normalized.senderUsername}: initial snapshot publish failed: ${err.message}`,
          );
        }
      }
    }

    if (connectionsDirty) await this.#saveConnectionsRecord(connectionsState, connectionsState.record);
    if (pendingDirty) await this.#savePendingRequestsRecord(pendingState, pendingState.record);
  }

  /**
   * Load (or initialize) the connections record for the current app.
   * Returns `{ record, txid }` — `txid` is null if we're creating it for
   * the first time, or the prior version's txid if updating.
   */
  async #loadConnectionsRecord(): Promise<any> {
    const entry = await this.#findShareStateEntry(CONNECTIONS_CONTENT_ID);
    if (!entry) {
      return { record: emptyConnectionsRecord(this.#appId), txid: null };
    }
    return { record: entry.data, txid: entry.txid };
  }

  async #saveConnectionsRecord(state: any, newRecord: any): Promise<any> {
    return await this.#writeShareStateEntry(CONNECTIONS_CONTENT_ID, state, newRecord);
  }

  async #loadPendingRequestsRecord(): Promise<any> {
    const entry = await this.#findShareStateEntry(PENDING_REQUESTS_CONTENT_ID);
    if (!entry) {
      return { record: emptyPendingRequestsRecord(this.#appId), txid: null };
    }
    return { record: entry.data, txid: entry.txid };
  }

  async #savePendingRequestsRecord(state: any, newRecord: any): Promise<any> {
    return await this.#writeShareStateEntry(PENDING_REQUESTS_CONTENT_ID, state, newRecord);
  }

  /**
   * Load (or hydrate the cached) muted-connections record for the current
   * app (issue #18, Section 6). On the first call per session this issues a
   * fetch against Arweave (via the standard `tarn-share-state` lookup); on
   * subsequent calls the in-memory copy is returned. Mute / unmute keep the
   * cache in sync so reads after a write are immediate.
   *
   * Wholly invalidated on credential change / recovery / delete (the DEK
   * chain rotates; we re-hydrate on next mute-related call).
   */
  async #loadMutedConnectionsRecord(): Promise<any> {
    if (this.#mutedConnectionsState) return this.#mutedConnectionsState;
    const entry = await this.#findShareStateEntry(MUTED_CONNECTIONS_CONTENT_ID);
    const state = entry
      ? { record: entry.data, txid: entry.txid }
      : { record: emptyMutedConnectionsRecord(this.#appId), txid: null };
    this.#mutedConnectionsState = state;
    return state;
  }

  async #saveMutedConnectionsRecord(state: any, newRecord: any): Promise<any> {
    return await this.#writeShareStateEntry(MUTED_CONNECTIONS_CONTENT_ID, state, newRecord);
  }

  /**
   * Load the issued-invites record. Cached across calls — most read paths
   * (listIssuedInvites, revokeIssuedInvite) prefer the cached copy. The
   * auto-accept path in listIncomingRequests() bypasses this with
   * #loadIssuedInvitesFresh().
   */
  async #loadIssuedInvitesRecord(): Promise<any> {
    if (this.#issuedInvitesState) return this.#issuedInvitesState;
    return await this.#loadIssuedInvitesFresh();
  }

  /**
   * Re-fetch the issued-invites blob from the API, bypassing any in-memory
   * cache. Used by the auto-accept path: an invite created on a different
   * device must be recognized here even when this device's cached state is
   * stale.
   */
  async #loadIssuedInvitesFresh(): Promise<any> {
    const entry = await this.#findShareStateEntry(ISSUED_INVITES_CONTENT_ID);
    const state = entry
      ? { record: entry.data, txid: entry.txid }
      : { record: emptyIssuedInvitesRecord(this.#appId), txid: null };
    this.#issuedInvitesState = state;
    return state;
  }

  async #saveIssuedInvitesRecord(state: any, newRecord: any): Promise<any> {
    return await this.#writeShareStateEntry(ISSUED_INVITES_CONTENT_ID, state, newRecord);
  }

  /**
   * Find the latest (resolved) `tarn-share-state` entry for a given
   * content_id. Returns `{ txid, data }` or null if no entry exists yet.
   *
   * The connections + pending records use type='tarn-share-state' with
   * Eid=<content_id>. Resolution dedupes by Eid + Prev chain so we get the
   * single live version.
   */
  async #findShareStateEntry(contentId: string): Promise<any> {
    const entries = await this.getEntries('tarn-share-state');
    for (const e of entries) {
      const eid = e.tags?.find((t: any) => t.name === 'Eid')?.value;
      if (eid === contentId) return e;
    }
    return null;
  }

  async #writeShareStateEntry(contentId: string, state: any, newRecord: any): Promise<any> {
    // Build tags manually so we can include both Prev (continuity across
    // updates) and Eid (resolution-layer safety net for eid-dedup). The
    // public createEntry/updateEntry helpers don't expose Eid in their tag
    // construction, so we inline the request here.
    const extraTags = [{ name: 'Eid', value: contentId }];
    const { encrypted, tags: cryptoTags } = await this.#encryptForWrite(newRecord);
    const tags = [
      { name: 'App', value: this.#appId },
      { name: 'Type', value: 'tarn-share-state' },
      { name: 'Lk', value: this.#dataLookupKey },
      ...(state.txid ? [{ name: 'Prev', value: state.txid }] : []),
      ...cryptoTags,
      { name: 'V', value: '0.4.0' },
      ...extraTags,
    ];
    const path = state.txid
      ? `/api/v1/entries/${state.txid}`
      : '/api/v1/entries';
    const method = state.txid ? 'PUT' : 'POST';

    const res = await this.#fetchRaw(path, {
      method,
      headers: {
        'Authorization': `Bearer ${this.#jwt}`,
        'X-Arweave-Tags': JSON.stringify(tags),
        'X-Idempotency-Key': generateIdempotencyKey(),
        'Content-Type': 'application/octet-stream',
      },
      body: encrypted,
    }, { retry: true });

    const json = await res.json().catch(() => null);
    if (res.status !== 200) {
      throw new Error(`#writeShareStateEntry(${contentId}): ${json?.error || res.status}`);
    }
    return { record: newRecord, txid: json.id };
  }

  // ============ SESSION PERSISTENCE (Section 7, issue #19) ============

  /**
   * Serialize the in-memory session into an opaque base64url blob suitable for
   * `localStorage`. The blob is encrypted under an AES-256-GCM wrapping key
   * stored in IndexedDB (`tarn-session.keys["wrapping-key-v1"]`,
   * `extractable: false`). The blob hard-expires 7 days after creation; the
   * SDK does not auto-refresh on use.
   *
   * Apps MUST treat the result as opaque. The plaintext schema is documented
   * in the protocol doc only so the threat model can be reasoned about.
   *
   * @returns {Promise<string>} base64url ciphertext
   * @throws if the client is not authenticated
   */
  async serializeSession() {
    if (!this.#signingKeyPair || !this.#credentialLookupKey || !this.#dekByGen) {
      throw new Error('serializeSession(): client is not authenticated');
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + 7 * 24 * 60 * 60; // 7-day hard cap, no refresh-on-use

    const [pkcs8, spki] = await Promise.all([
      crypto.subtle.exportKey('pkcs8', this.#signingKeyPair.privateKey),
      crypto.subtle.exportKey('spki', this.#signingKeyPair.publicKey),
    ]);

    const dekByGen = [];
    for (const [gen, pair] of this.#dekByGen) {
      const raw = await crypto.subtle.exportKey('raw', pair.gcmKey);
      dekByGen.push({ gen, rawBytes: bytesToBase64(new Uint8Array(raw)) });
    }
    dekByGen.sort((a, b) => a.gen - b.gen);

    let recoveryFactorMeta = null;
    if (this.#recoveryFactorMeta) {
      const m = this.#recoveryFactorMeta;
      const wrappingsByGen = [];
      for (const [gen, wrapped] of m.wrappingsByGen) {
        wrappingsByGen.push({ gen, wrapped });
      }
      wrappingsByGen.sort((a, b) => a.gen - b.gen);
      recoveryFactorMeta = {
        salt: bytesToBase64(m.salt),
        kdfParams: m.kdfParams,
        wrappingsByGen,
      };
    }

    const payload = {
      // Schema v3 — drops the legacy kdfVersion / envelopeVersion fields that
      // disappeared with the single-envelope cleanup. v1/v2 blobs from prior
      // versions of the SDK no longer resume; they fail cleanly to null and
      // the user re-authenticates.
      v: 3,
      createdAt: now,
      expiresAt,
      apiBase: this.#apiBase,
      appId: this.#appId,
      username: this.#username,
      dataLookupKey: this.#dataLookupKey,
      credentialLookupKey: this.#credentialLookupKey,
      currentGen: this.#currentGen,
      dekByGen,
      signingPrivateKey: bytesToBase64(new Uint8Array(pkcs8)),
      signingPublicKey: bytesToBase64(new Uint8Array(spki)),
      sharingPrivateKey: bytesToBase64(this.#sharingKeyPair!.privateKey),
      sharingPublicKey: bytesToBase64(this.#sharingKeyPair!.publicKey),
      recoveryFactorMeta,
      jwt: this.#jwt,
      sid: this.#sid,
      // Phase 3: persist the Model B indicator so resumed sessions know
      // whether to surface "view your account key" without a fresh /verify
      // round trip. Strict boolean | null — undefined survives JSON.parse
      // as undefined, which we coerce back to null.
      accountKeyStored: this.#accountKeyStored,
    };

    const plaintext = new TextEncoder().encode(JSON.stringify(payload));
    const wrappingKey = await getOrCreateWrappingKey();
    const blob = await encryptSessionBlob(plaintext, wrappingKey);
    return bytesToBase64Url(blob);
  }

  /**
   * Resume a previously-serialized session. Returns a logged-in `TarnClient`
   * if the blob is well-formed, decryptable on this origin, schema v1, and
   * not past `expiresAt`. Returns `null` for any recoverable failure
   * (expired, tampered, schema-mismatched, wrong origin, missing fields,
   * malformed JSON, IndexedDB error). Apps fall back to the login UI on null.
   *
   * Never throws on bad blob data — only on programmer errors (missing args).
   *
   * @param {string} apiBase
   * @param {string} appId
   * @param {string} blob — base64url ciphertext from serializeSession()
   * @param {{ _nowSeconds?: number }} [opts] — test hook for the expiry path
   * @returns {Promise<TarnClient | null>}
   */
  static async resumeSession(apiBase: string, appId: string, blob: string, opts: any = {}): Promise<TarnClient | null> {
    if (!apiBase) throw new Error('resumeSession(): apiBase is required');
    if (!appId) throw new Error('resumeSession(): appId is required');
    if (typeof blob !== 'string' || blob.length === 0) {
      throw new Error('resumeSession(): blob is required');
    }

    try {
      let blobBytes;
      try {
        blobBytes = base64UrlToBytes(blob);
      } catch {
        return null;
      }
      const wrappingKey = await getOrCreateWrappingKey();
      let plaintext;
      try {
        plaintext = await decryptSessionBlob(blobBytes, wrappingKey);
      } catch {
        return null;
      }

      let payload;
      try {
        payload = JSON.parse(new TextDecoder().decode(plaintext));
      } catch {
        return null;
      }
      if (!payload || typeof payload !== 'object') return null;
      // Schema v3 only: v1/v2 blobs predate the single-envelope cleanup and
      // carry kdfVersion/envelopeVersion fields the live client no longer
      // tracks. Forcing v3 means stale blobs fail cleanly to null and the
      // user re-authenticates — no partial-state hazards.
      if (payload.v !== 3) return null;

      // Origin-binding check: a blob serialized for app A on api B must not
      // resume into app A' or api B'. The wrapping key is already origin-
      // scoped via IndexedDB, but a same-origin app that switches appId
      // (or apiBase) shouldn't accidentally rehydrate state from the other.
      if (payload.apiBase !== apiBase.replace(/\/$/, '')) return null;
      if (payload.appId !== appId) return null;

      const required = [
        'createdAt', 'expiresAt', 'username', 'dataLookupKey', 'credentialLookupKey',
        'currentGen', 'dekByGen',
        'signingPrivateKey', 'signingPublicKey', 'sharingPrivateKey', 'sharingPublicKey',
      ];
      for (const k of required) {
        if (payload[k] === undefined || payload[k] === null) return null;
      }
      if (!Array.isArray(payload.dekByGen) || payload.dekByGen.length === 0) return null;

      const nowSeconds = opts._nowSeconds != null ? opts._nowSeconds : Math.floor(Date.now() / 1000);
      if (typeof payload.expiresAt !== 'number' || nowSeconds >= payload.expiresAt) return null;

      // Rehydrate keys.
      const signingPrivateKey = await crypto.subtle.importKey(
        'pkcs8',
        bs(base64ToBytes(payload.signingPrivateKey)),
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign'],
      );
      const signingPublicKey = await crypto.subtle.importKey(
        'spki',
        bs(base64ToBytes(payload.signingPublicKey)),
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify'],
      );
      const dekByGen = new Map();
      for (const { gen, rawBytes } of payload.dekByGen) {
        if (typeof gen !== 'number' || typeof rawBytes !== 'string') return null;
        const raw = base64ToBytes(rawBytes);
        const [gcmKey, kwKey] = await Promise.all([
          crypto.subtle.importKey('raw', bs(raw), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']),
          crypto.subtle.importKey('raw', bs(raw), 'AES-KW', true, ['wrapKey', 'unwrapKey']),
        ]);
        dekByGen.set(gen, { gcmKey, kwKey });
      }
      if (!dekByGen.has(payload.currentGen)) return null;

      let recoveryFactorMeta = null;
      if (payload.recoveryFactorMeta) {
        const m = payload.recoveryFactorMeta;
        if (typeof m.salt !== 'string' || !m.kdfParams || !Array.isArray(m.wrappingsByGen)) {
          return null;
        }
        const wrappingsByGen = new Map();
        for (const { gen, wrapped } of m.wrappingsByGen) {
          if (typeof gen !== 'number' || typeof wrapped !== 'string') return null;
          wrappingsByGen.set(gen, wrapped);
        }
        recoveryFactorMeta = {
          salt: base64ToBytes(m.salt),
          kdfParams: m.kdfParams,
          wrappingsByGen,
        };
      }

      const client = new TarnClient(apiBase, appId);
      // Mirror the field-set pattern at the end of login() — populate the
      // private slots directly so the resumed client behaves identically to
      // one that just logged in. credentialEncryptionKey is intentionally
      // not persisted (no code path reads it post-login).
      client.#jwt = payload.jwt || null;
      client.#sid = typeof payload.sid === 'string' ? payload.sid : null;
      client.#dataLookupKey = payload.dataLookupKey;
      client.#credentialLookupKey = payload.credentialLookupKey;
      client.#signingKeyPair = { privateKey: signingPrivateKey, publicKey: signingPublicKey };
      client.#dekByGen = dekByGen;
      client.#currentGen = payload.currentGen;
      client.#username = payload.username;
      client.#sharingKeyPair = {
        privateKey: base64ToBytes(payload.sharingPrivateKey),
        publicKey: base64ToBytes(payload.sharingPublicKey),
      };
      client.#recoveryFactorMeta = recoveryFactorMeta;
      // Phase 3: rehydrate the Model B indicator. Pre-Phase-3 blobs lack
      // the field; coerce undefined → null so isStored() reads correctly.
      client.#accountKeyStored =
        typeof payload.accountKeyStored === 'boolean' ? payload.accountKeyStored : null;

      return client;
    } catch {
      // Catch-all for any unexpected failure (IndexedDB error, etc.) — null
      // is the recoverable signal so apps can uniformly fall back to login UI.
      return null;
    }
  }

  /**
   * Delete the IndexedDB wrapping key. Renders all previously-emitted session
   * blobs unreadable on this origin. Does not affect the in-memory client
   * state — the caller can keep using the live client until it's
   * garbage-collected. Side-effected from changeCredentials / recoverAccount /
   * deleteAccount so persisted blobs invalidate on key rotation.
   *
   * @returns {Promise<void>}
   */
  async clearSession() {
    await clearWrappingKey();
  }

  /**
   * Whether the client currently has the keys needed to perform authenticated
   * operations. True after a successful register / login / recoverAccount /
   * resumeSession; false on a freshly-constructed client or after clearSession
   * / deleteAccount.
   *
   * Note this reflects key material possession, not JWT freshness — if the JWT
   * has expired but signing keys are present, isLoggedIn() returns true and
   * the next authenticated call will silently re-authenticate. Apps treat
   * this as "the user is logged in," which matches user expectations.
   *
   * @returns {boolean}
   */
  isLoggedIn() {
    return (this.#dekByGen?.size ?? 0) > 0 && this.#signingKeyPair != null;
  }

  // ============ SERVER-SIDE SESSIONS (Section 7.5, issue #20) ============

  /**
   * List the active server-side sessions for the calling account. Each entry
   * is one device that has authenticated successfully and not been revoked.
   *
   * @returns {Promise<Array<{
   *   sid: string,
   *   createdAt: number,
   *   lastSeenAt: number,
   *   deviceLabel: string | null,
   *   viaRecovery: boolean,
   *   isCurrent: boolean,
   * }>>}
   */
  async listSessions() {
    await this.#requireAuth();
    const res = await this.#fetch('/api/v1/sessions', { method: 'GET', auth: true });
    if (res.status !== 200) {
      throw new Error(`listSessions failed: ${res.json?.error || res.status}`);
    }
    const rows = Array.isArray(res.json?.sessions) ? res.json.sessions : [];
    return rows.map((r: any) => ({
      sid: r.sid,
      createdAt: r.created_at,
      lastSeenAt: r.last_seen_at,
      deviceLabel: r.device_label,
      viaRecovery: !!r.via_recovery,
      isCurrent: !!r.is_current,
    }));
  }

  /**
   * Revoke a single session by sid. The next authenticated request from the
   * device that holds that JWT will fail with 401 (immediately on the same
   * isolate, within the 5s isolate-cache TTL elsewhere).
   *
   * @param {string} sid
   * @returns {Promise<void>}
   * @throws if the sid does not exist or does not belong to this account.
   */
  async revokeSession(sid: string): Promise<void> {
    if (!sid || typeof sid !== 'string') {
      throw new Error('revokeSession(): sid is required');
    }
    await this.#requireAuth();
    const res = await this.#fetchRaw(
      `/api/v1/sessions/${encodeURIComponent(sid)}`,
      { method: 'DELETE', headers: { Authorization: `Bearer ${this.#jwt}` } },
    );
    if (res.status === 204) return;
    let body = null;
    try { body = await res.json(); } catch {}
    throw new Error(`revokeSession failed: ${body?.error || res.status}`);
  }

  /**
   * Revoke EVERY session for this account, including the calling one. The
   * caller's JWT becomes useless on the next request — apps should treat this
   * as a sign-out and prompt re-auth.
   *
   * Also wipes the persisted session blob on this origin (clearSession) so a
   * subsequent resumeSession returns null.
   *
   * @returns {Promise<void>}
   */
  async revokeAllSessions() {
    await this.#requireAuth();
    const res = await this.#fetchRaw('/api/v1/sessions', {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${this.#jwt}` },
    });
    if (res.status !== 204) {
      let body = null;
      try { body = await res.json(); } catch {}
      throw new Error(`revokeAllSessions failed: ${body?.error || res.status}`);
    }
    try { await this.clearSession(); } catch {}
    this.#jwt = null;
    this.#sid = null;
  }

  /**
   * Revoke every session EXCEPT the calling one. Useful for "sign out all
   * other devices" UI. The calling device retains its JWT/sid.
   *
   * @returns {Promise<void>}
   */
  async revokeOtherSessions() {
    await this.#requireAuth();
    const res = await this.#fetchRaw('/api/v1/sessions?except=current', {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${this.#jwt}` },
    });
    if (res.status !== 204) {
      let body = null;
      try { body = await res.json(); } catch {}
      throw new Error(`revokeOtherSessions failed: ${body?.error || res.status}`);
    }
  }

  // ============ ACCESSORS ============

  get dataLookupKey() { return this.#dataLookupKey; }
  get appId() { return this.#appId; }
  /** True if the client has a session (JWT may auto-refresh transparently). */
  get isAuthenticated() { return !!(this.#jwt || this.#signingKeyPair); }

  /**
   * Test-only: expose the current JWT for deployed smoke tests that need to
   * hand-craft raw requests (e.g., idempotency testing). Do not use in
   * production code; call the public methods instead.
   */
  _testJwt() { return this.#jwt; }

  /**
   * Test-only: drop the in-memory JWT so the next API call must re-authenticate
   * via the signing keypair. Used by Section 7 resume-session tests to verify
   * the rehydrated keypair can drive a fresh challenge-response.
   */
  _testInvalidateJwt() { this.#jwt = null; }

  /**
   * Test-only: force a fresh challenge-response cycle from the cached signing
   * keys. Used by Section 7.5 tests to re-authenticate after revokeAllSessions
   * cleared the in-memory JWT/sid (the public path would normally require the
   * caller to login() again).
   */
  async _testForceReauth() {
    this.#jwt = null;
    await this.#authenticate();
  }

  /**
   * Test-only: lower the per-connection share-log snapshot compaction interval
   * so an integration test can trigger auto-compaction without publishing
   * 100 entries. Production code should leave this at the default.
   */
  _setShareLogCompactionIntervalForConnection(connectionSharePubBase64Url: string, interval: number): void {
    if (!Number.isInteger(interval) || interval < 1) {
      throw new Error('interval must be a positive integer');
    }
    const counters = this.#getOrInitCounters(connectionSharePubBase64Url);
    counters.compactionInterval = interval;
  }

  // ============ PRIVATE ============

  /**
   * Encrypt a payload for an outgoing write.
   *
   * Per-content CEK: produces a blob prefixed with the TARN magic, with a
   * fresh CEK wrapped under the current generation's DEK. The generation
   * indicator travels alongside as the Arweave `Gen` tag — keeping the blob
   * byte-layout stable so a recipient can skip bytes 5..44 without parsing
   * tags.
   *
   * The encryption call surfaces the raw CEK so the caller can publish it
   * through the share-log (see createEntry / updateEntry / shareEntry).
   *
   * @param {Object} plaintext - JSON-serializable payload
   * @returns {Promise<{ encrypted: Uint8Array, tags: Array<{name:string, value:string}>, shareKey: string }>}
   */
  async #encryptForWrite(plaintext: any): Promise<{ encrypted: Uint8Array; tags: Tag[]; shareKey: string }> {
    const dek = this.#dekByGen!.get(this.#currentGen!);
    if (!dek) {
      throw new Error(`Internal: no DEK for gen ${this.#currentGen}`);
    }
    const { blob, shareKey } = await encryptWithCEK(dek.kwKey, plaintext);
    return {
      encrypted: blob,
      tags: [
        { name: 'Enc', value: 'tarn-cek-1' },
        { name: 'Gen', value: String(this.#currentGen) },
      ],
      shareKey,
    };
  }

  /**
   * Decrypt a blob from a read. Every blob is the v1 per-content CEK shape:
   * 5-byte TARN magic prefix, 40-byte wrapped CEK slot, IV + AES-GCM
   * ciphertext. The generation that wrote it is declared in the `Gen` tag.
   *
   * @param {Uint8Array} blobBytes
   * @param {Array<{name: string, value: string}>} tags
   * @returns {Promise<Object>}
   */
  async #decryptBlob(blobBytes: Uint8Array, tags: Tag[]): Promise<any> {
    if (!hasTarnBlobMagic(blobBytes)) {
      throw new Error('Blob is missing the TARN magic prefix (legacy or corrupt)');
    }
    const gen = readGenTag(tags) ?? 1;
    const dek = this.#dekByGen!.get(gen);
    if (!dek) {
      throw new Error(`No DEK for blob generation ${gen} — chain has gens [${[...this.#dekByGen!.keys()].join(', ')}]`);
    }
    return await decryptWithCEK(dek.kwKey, blobBytes);
  }

  /**
   * Ensure we have a valid JWT. If expired but we have signing keys,
   * silently re-authenticate via challenge-response. If never logged in, throw.
   */
  async #requireAuth() {
    if (!this.#jwt && !this.#signingKeyPair) {
      throw new Error('Not authenticated — call register() or login() first');
    }

    // Check JWT expiry
    if (this.#jwt) {
      try {
        const parts = this.#jwt.split('.');
        const payload = JSON.parse(atob(parts[1]!.replace(/-/g, '+').replace(/_/g, '/')));
        // Refresh 30 seconds before expiry to avoid edge-case failures
        if (!payload.exp || payload.exp > Math.floor(Date.now() / 1000) + 30) {
          return; // JWT is still valid
        }
      } catch {
        // If decoding fails, try to refresh
      }
    }

    // JWT is missing or expired — re-authenticate if we have signing keys
    if (this.#signingKeyPair && this.#credentialLookupKey) {
      this.#jwt = null;
      await this.#authenticate();
      return;
    }

    throw new Error('JWT expired and no signing keys available — call login() to re-authenticate');
  }

  async #authenticate() {
    const challengeRes = await this.#fetch('/api/v1/auth/challenge', {
      method: 'POST',
      retry: true, // fresh nonce per call — safe to retry
      body: { credential_lookup_key: this.#credentialLookupKey },
    });

    if (challengeRes.status !== 200) {
      throw new Error(`Challenge failed: ${challengeRes.json?.error}`);
    }

    await this.#verifyChallenge(challengeRes.json.nonce);
  }

  async #verifyChallenge(nonce: string): Promise<void> {
    const signature = await signChallenge(this.#signingKeyPair!.privateKey, nonce);

    // Section 7.5: send the previous sid (if any) so the server reuses the
    // same sessions row across re-verify, plus an optional device label that
    // landed on listSessions output.
    const body: any = {
      credential_lookup_key: this.#credentialLookupKey,
      nonce,
      signature,
    };
    if (this.#sid) body.previous_sid = this.#sid;
    if (this.#pendingDeviceLabel != null) body.device_label = this.#pendingDeviceLabel;

    const verifyRes = await this.#fetch('/api/v1/auth/verify', {
      method: 'POST',
      body,
    });

    // The label is one-shot — even on failure we shouldn't reuse it on the
    // next call (the caller would supply it again).
    this.#pendingDeviceLabel = null;

    if (verifyRes.status !== 200) {
      throw new Error(`Verify failed: ${verifyRes.json?.error}`);
    }

    this.#jwt = verifyRes.json.jwt;
    this.#sid = this.#extractSidFromJwt(this.#jwt);
    // Phase 3: server returns account_key_stored on user-role verify so the
    // app can render Settings appropriately. Null for app-role JWTs.
    if (typeof verifyRes.json.account_key_stored === 'boolean') {
      this.#accountKeyStored = verifyRes.json.account_key_stored;
    }
  }

  /**
   * Whether the server stores a wrap of this account's account key
   * (Model B). Reflects the most recent /auth/verify response. Null before
   * the first verify (e.g., on a fresh, never-logged-in client).
   */
  isAccountKeyStored(): boolean | null {
    return this.#accountKeyStored;
  }

  /**
   * Decode the `sid` claim out of a HS256 JWT. Returns null if the token is
   * malformed or has no sid claim (pre-7.5 grandfather path).
   */
  #extractSidFromJwt(jwt: string | null): string | null {
    if (!jwt) return null;
    try {
      const parts = jwt.split('.');
      if (parts.length !== 3) return null;
      const payload = JSON.parse(atob(parts[1]!.replace(/-/g, '+').replace(/_/g, '/')));
      return payload.sid || null;
    } catch {
      return null;
    }
  }

  async #fetchBlob(txid: string): Promise<Uint8Array | null> {
    // Single source of truth: Tarn's per-entry endpoint. Tarn serves
    // blob_data from D1 (populated via write-through on writes, lazy-loaded
    // from a public Arweave gateway on cold-bootstrap reads), so it covers
    // both pending and confirmed entries with one round trip per blob.
    //
    // No client-side gateway fallback by design: the SDK already cannot
    // function without Tarn (the list of live entries lives there exclusively),
    // so a partial fallback for blobs only would mask Tarn outages without
    // delivering availability. A separate, deliberate "always access your
    // data" recovery path — direct GraphQL + gateway reads with no Tarn
    // dependency — belongs in its own artifact, not here.
    try {
      const res = await this.#fetchRaw(`/api/v1/entries/${txid}`, { method: 'GET' });
      if (res.status === 200) {
        const text = await res.text();
        try {
          const json = JSON.parse(text);
          if (json?.data) return base64ToBytes(json.data);
        } catch {}
      }
    } catch {}
    return null;
  }

  /**
   * Internal fetch wrapper with transparent retry on transient failures.
   *
   * Retry policy:
   *   - 5xx or 429 responses → retry (honoring Retry-After on 429)
   *   - Network errors (fetch throws) → retry
   *   - 4xx → do not retry (permanent answers: validation, auth, conflict, etc.)
   *
   * Retry is enabled by default for idempotent operations:
   *   - Any GET
   *   - POSTs explicitly marked retry-safe by the caller (retry: true)
   *     e.g. /auth/register (idempotent since #6), /auth/challenge (fresh nonce
   *     per call), or writes that set an X-Idempotency-Key (see #8).
   *
   * Retry is disabled for side-effectful operations without idempotency support
   * (/auth/verify, credential change, account delete) where a retry could
   * consume a now-invalid nonce or produce duplicate destructive effects.
   */
  async #fetch(path: string, opts: any = {}): Promise<{ status: number; json: any; text: string }> {
    const { method = 'GET', body = null, auth = false, retry = method === 'GET' } = opts;
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (auth && this.#jwt) headers['Authorization'] = `Bearer ${this.#jwt}`;

    const fetchOpts: any = { method, headers };
    if (body) fetchOpts.body = JSON.stringify(body);

    const res = await this.#executeFetch(`${this.#apiBase}${path}`, fetchOpts, retry);
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch { json = null; }
    return { status: res.status, json, text };
  }

  async #fetchRaw(path: string, opts: any, retryOpts: { retry?: boolean } = {}): Promise<Response> {
    const { retry = opts?.method === 'GET' } = retryOpts;
    return await this.#executeFetch(`${this.#apiBase}${path}`, opts, retry);
  }

  async #executeFetch(url: string, opts: any, allowRetry: boolean): Promise<Response> {
    const MAX_ATTEMPTS = allowRetry ? 3 : 1;
    let lastErr;

    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      try {
        const res = await fetch(url, opts);
        const isTransient = res.status >= 500 || res.status === 429;
        if (!isTransient || attempt === MAX_ATTEMPTS - 1) {
          return res;
        }

        const retryAfterSec = parseRetryAfter(res.headers.get('Retry-After'));
        // Don't honor Retry-After values longer than 60 seconds — the server
        // is telling us to back off for a budget window we can't realistically
        // wait for (e.g. the share-inbox fetch limit returns Retry-After: 3600).
        // Surface the 429 to the caller with
        // its body intact so they can decide what to do, rather than blocking
        // the test or the UX for an hour.
        //
        // (Body cancel must happen AFTER this early return — cancelling and
        // then returning the Response leaves the caller holding a consumed
        // body and `.text()` throws "Body has already been read". That bug
        // surfaced as cascading smoke-test failures whenever cumulative rate
        // limits on the share-inbox path drove the API into 429 territory.)
        if (retryAfterSec != null && retryAfterSec > 60) {
          return res;
        }

        // Committed to a retry — drain the body so the underlying connection
        // can be reused and undici can pool it cleanly.
        try { await res.body?.cancel(); } catch {}

        const waitMs = retryAfterSec != null ? retryAfterSec * 1000 : backoffMs(attempt);
        console.warn(`[TarnClient] ${res.status} on ${url} — retrying in ${Math.round(waitMs)}ms (attempt ${attempt + 1}/${MAX_ATTEMPTS})`);
        await sleep(waitMs);
      } catch (err: any) {
        // Network error (fetch threw: DNS, TLS, connection reset, etc).
        lastErr = err;
        if (attempt === MAX_ATTEMPTS - 1) throw err;
        const waitMs = backoffMs(attempt);
        console.warn(`[TarnClient] network error on ${url} (${err.message}) — retrying in ${Math.round(waitMs)}ms (attempt ${attempt + 1}/${MAX_ATTEMPTS})`);
        await sleep(waitMs);
      }
    }
    throw lastErr; // unreachable
  }
}

// ============ Tag helpers ============

/**
 * Read the integer value of a `Gen` tag from an Arweave tag list (issue #11).
 * Returns null if the tag is absent or malformed.
 *
 * @param {Array<{name: string, value: string}>|undefined} tags
 * @returns {number|null}
 */
function readGenTag(tags: Tag[] | undefined): number | null {
  if (!Array.isArray(tags)) return null;
  const tag = tags.find(t => t && t.name === 'Gen');
  if (!tag || typeof tag.value !== 'string') return null;
  const n = parseInt(tag.value, 10);
  if (!Number.isInteger(n) || n < 1) return null;
  return n;
}

// ============ Retry + idempotency helpers ============

/**
 * Generate a fresh idempotency key for a write. Clients include this in the
 * X-Idempotency-Key header; the server returns the original response on any
 * retry with the same key, preventing duplicate DataItems on Arweave.
 * See tarn #8.
 */
function generateIdempotencyKey(): string {
  // crypto.randomUUID is available in modern browsers and Node 15+.
  return crypto.randomUUID();
}

// share_pub fingerprint (Section 8): SHA-256 truncated to 4 bytes, formatted
// as colon-separated hex pairs (e.g. "a3:b9:c7:d4"). Short enough to fit in
// the server-side `redeemer_share_pub_fingerprint` column and recognizable
// in UI verification flows.
async function fingerprintSharePub(sharePub: Uint8Array | string): Promise<string> {
  const bytes = sharePub instanceof Uint8Array ? sharePub : base64UrlToBytes(sharePub);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bs(bytes)));
  const out = [];
  for (let i = 0; i < 4; i++) out.push(digest[i]!.toString(16).padStart(2, '0'));
  return out.join(':');
}

// Connection.label normalization (Section 8). null/undefined/'' all collapse
// to null so the persisted record stays clean. Strings are trimmed and
// bounded so an app can't accidentally write a multi-KB label.
const MAX_CONNECTION_LABEL_LEN = 256;
function normalizeConnectionLabel(label: unknown): string | null {
  if (label == null) return null;
  if (typeof label !== 'string') {
    throw new Error('connection label must be a string or null');
  }
  const trimmed = label.trim();
  if (trimmed.length === 0) return null;
  if (trimmed.length > MAX_CONNECTION_LABEL_LEN) {
    throw new Error(`connection label exceeds ${MAX_CONNECTION_LABEL_LEN} chars`);
  }
  return trimmed;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Exponential backoff with ±25% jitter.
 * Attempt 0 → ~500ms, attempt 1 → ~1500ms.
 */
function backoffMs(attempt: number): number {
  const base = 500 * Math.pow(3, attempt);
  const jitter = base * (Math.random() * 0.5 - 0.25);
  return base + jitter;
}

/**
 * Parse Retry-After header value. Returns seconds (number) or null if absent/invalid.
 * Supports both the delta-seconds form (e.g., "60") and the HTTP-date form.
 */
function parseRetryAfter(value: string | null): number | null {
  if (!value) return null;
  const n = parseInt(value, 10);
  if (!isNaN(n) && n >= 0) return n;
  const date = Date.parse(value);
  if (!isNaN(date)) {
    return Math.max(0, Math.floor((date - Date.now()) / 1000));
  }
  return null;
}
