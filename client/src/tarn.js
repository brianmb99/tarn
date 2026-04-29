// Tarn Client — JavaScript API client for the Tarn protocol
// Handles key derivation, encryption/decryption, and all API interactions.
// Works in browsers and Node.js 15+.
//
// Each TarnClient instance is scoped to one app. Same email+password with
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
  wrapDataKeyEnvelope,
  wrapDataKeyChainEnvelope,
  wrapDataKeyChainEnvelopeV4,
  buildV4Envelope,
  unwrapDataKeyChain,
  signChallenge,
  encrypt,
  decrypt,
  encryptWithCEK,
  decryptWithCEK,
  hasTarnBlobMagic,
  generateRandomDataKey,
  generateRecoverySalt,
  parseWrappedDataKey,
  base64ToBytes,
  bytesToBase64,
  bytesToBase64Url,
  KDF_V1_PBKDF2,
  KDF_V2_ARGON2ID,
  KDF_DEFAULT,
  FACTOR_PASSWORD,
  FACTOR_RECOVERY_PHRASE,
} from './crypto.js';
import {
  generateRecoveryPhrase,
  validateRecoveryPhrase,
  recoveryPhraseToEntropy,
  renderRecoveryPDF,
} from './recovery.js';
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

// Re-export the recovery-side surface so consumers can import them directly
// from the package root without reaching into ./recovery (private path).
export { generateRecoveryPhrase, validateRecoveryPhrase, renderRecoveryPDF };

export class TarnClient {
  #apiBase;
  #appId;
  #jwt = null;
  #dataLookupKey = null;
  #credentialLookupKey = null;
  #credentialEncryptionKey = null;
  #signingKeyPair = null;
  // KDF version this account was registered/logged in under. Set on register
  // (always KDF_DEFAULT for new accounts) and login (whichever path succeeded).
  // Used by changeCredentials() to preserve the original KDF — automatic
  // upgrade from PBKDF2 to Argon2id is intentionally out of scope.
  #kdfVersion = null;

  // DEK chain (issue #11). Always populated on a successful login/register,
  // even for legacy single-key (v1/v2) envelopes — those become a one-entry
  // chain at gen=1. Keys are {gcmKey, kwKey} pairs holding two WebCrypto
  // handles for the same 32 raw bytes (AES-GCM for direct legacy decryption,
  // AES-KW for wrapping per-content CEKs).
  #dekByGen = null;          // Map<gen:number, {gcmKey, kwKey}>
  #currentGen = null;        // number — gen used for new writes
  #envelopeVersion = null;   // 1 (bare base64), 2 (single), 3 (chain), 4 (multi-factor chain)

  // Sharing handshake state (issue #14, Section 5a). Populated on every
  // register/login/changeCredentials/recoverAccount path so the connection
  // handshake methods can HPKE-Open inbox blobs without re-deriving from
  // master_key on every call. share_priv NEVER leaves the device.
  #email = null;                     // string — caller-supplied normalized email
  #sharingKeyPair = null;            // {privateKey: Uint8Array, publicKey: Uint8Array}
  #replayNonceCache = makeReplayNonceCache(); // §13.8 in-memory recent-nonce cache

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
  #pairKeyCache = new Map();         // sharePubBase64Url -> { sharedSecret, outboundKey, inboundKey, outboundTagSeed, inboundTagSeed }
  #shareLogCounters = new Map();     // sharePubBase64Url -> { nextOutboundSeq, nonSnapshotsSinceLastSnapshot, compactionInterval }

  // Per-connection reconstructed inbound state (issue #16, Section 5c).
  // Keyed on the connection's `share_pub`, holds the application's view of
  // what the connection has shared with us — the result of replaying their
  // outbound log per §8.5. `lastSeqSeen` is the highest seq we've applied
  // (or -1 if no entries yet). In-memory only; on session restart
  // `readShareLog` re-bootstraps from Arweave. Wholly invalidated on
  // credential change / recovery / delete.
  #readStateCache = new Map();       // sharePubBase64Url -> { state: {[content_id]: {tx_id, cek}}, lastSeqSeen: number }

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
  #outboundStateCache = new Map();   // sharePubBase64Url -> { state: {[content_id]: {tx_id, cek}}, hydrated: boolean }

  // Per-connection set of outbound txids we've successfully published in
  // this session (issue #16, Section 5c). Used by the multi-device retry
  // path (§13.1) to detect "this 409 is reporting back my own previous
  // publish" (e.g., the SDK retried after a transient response loss). When
  // the 409's `existing_txid` is in this set, we treat the publish as
  // already-done rather than republishing at the next seq. Cleared with the
  // rest of the share-log caches on credential change / recovery / delete.
  #publishedTxidsByConnection = new Map(); // sharePubBase64Url -> Set<string>

  // Muted-connections record (issue #18, Section 6). Loaded on demand on
  // the first mute-related call per session and kept in sync with the
  // persisted `tarn-muted-connections-v1` blob across calls. The record
  // syncs across devices via the encrypted Tarn data blob; subsequent
  // sessions hydrate from Arweave. Wholly invalidated on credential change
  // / recovery / delete (re-hydrate on next mute-related call).
  #mutedConnectionsState = null;     // null | { record, txid }

  // v4 recovery-factor state (issue #12). Holds enough information to preserve
  // existing recovery wrappings across a credential change without requiring
  // the user to re-enter the phrase: the per-account salt + KDF params (so a
  // future write that DOES have the phrase can re-derive the same KEK), and
  // a snapshot of the existing wrapped recovery bytes per gen (so we can
  // re-emit them verbatim). Null for v1/v2/v3 accounts.
  #recoveryFactorMeta = null; // { salt: Uint8Array, kdfParams, wrappingsByGen: Map<gen, base64> } | null
  #recoveryLookupKey = null;  // 64-char hex (server-side) — populated on register/recover; null otherwise

  /**
   * @param {string} apiBaseUrl - Tarn API base URL (e.g., 'https://api.tarn.dev')
   * @param {string} appId - Registered app identifier (e.g., 'bookish')
   */
  constructor(apiBaseUrl, appId) {
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
   * BIP39 recovery phrase. The DEK is wrapped twice into a v4 envelope:
   *   - under the password-derived KEK (factor: "password")
   *   - under a phrase-derived KEK (factor: "recovery_phrase")
   * The envelope is opaque to the API (passes the existing length/type check).
   *
   * The caller MUST pass `recoveryAcknowledged: true` — without it, register
   * fails synchronously with no network call. This is the SDK enforcement of
   * the design-doc requirement that recovery is mandatory at signup.
   *
   * The phrase is returned to the caller in the result payload alongside the
   * rendered PDF bytes. The TarnClient instance does NOT cache the phrase —
   * the caller is responsible for handing it to the user (PDF download or
   * email forward) and dropping the in-memory copy promptly. Re-rendering a
   * fresh PDF later requires the user to provide the phrase again.
   *
   * @param {string} email
   * @param {string} password
   * @param {{
   *   recoveryAcknowledged: boolean,
   *   emailRecoveryKit?: boolean,         // default true
   *   recipientEmail?: string,            // defaults to email param
   *   appName?: string,                   // PDF + email branding
   * }} [opts]
   * @returns {Promise<{
   *   dataLookupKey: string,
   *   recoveryPhrase: string,
   *   pdfBytes: Uint8Array,
   *   emailDelivered: boolean,
   * }>}
   */
  async register(email, password, opts = {}) {
    if (!opts || opts.recoveryAcknowledged !== true) {
      throw new Error('register(): recoveryAcknowledged: true is required (issue #12)');
    }
    const emailRecoveryKit = opts.emailRecoveryKit !== false;
    const recipientEmail = opts.recipientEmail || email;
    const appName = opts.appName;
    // Sharing keypair publication (issue #13). Defaults to discoverable so a
    // new social-app user can connect by email out of the box. Apps that
    // want a "private by default" stance can pass `shareDiscoverable: false`.
    const shareDiscoverable = opts.shareDiscoverable !== false;

    const kdfVersion = KDF_DEFAULT; // New accounts always use Argon2id (v2).

    // Derive password-side keys + recovery-phrase-side keys + share-lookup
    // key in parallel — Argon2id calls dominate registration latency, so
    // overlap them. share_lookup_key is HKDF over SHA-256(email), independent
    // of the password.
    const phrase = generateRecoveryPhrase();
    const phraseEntropy = recoveryPhraseToEntropy(phrase);
    const recoverySalt = generateRecoverySalt();

    const [keys, recoveryKEK, recoveryLookupKey, recoverySigningKeyPair, shareLookupKey] = await Promise.all([
      deriveAllKeys(email, password, this.#appId, kdfVersion),
      deriveRecoveryKey(phrase, recoverySalt),
      deriveRecoveryLookupKey(phraseEntropy, this.#appId),
      deriveRecoverySigningKeyPair(phraseEntropy, this.#appId),
      deriveShareLookupKey(email, this.#appId),
    ]);

    const [publicKeyBase64, recoveryPublicKeyBase64] = await Promise.all([
      exportPublicKey(keys.signingKeyPair.publicKey),
      exportPublicKey(recoverySigningKeyPair.publicKey),
    ]);
    const sharePub = encodeSharePub(keys.sharingKeyPair.publicKey);

    // Random DEK at generation 1. Wrap under both password + recovery factors.
    const dek = await generateRandomDataKey();
    const wrappedDataKey = await wrapDataKeyChainEnvelopeV4(
      [{ gen: 1, key: dek.gcmKey }],
      [
        { name: FACTOR_PASSWORD,        wrappingKey: keys.credentialEncryptionKey.kwKey },
        { name: FACTOR_RECOVERY_PHRASE, wrappingKey: recoveryKEK.kwKey },
      ],
      { salt: recoverySalt },
    );

    const res = await this.#fetch('/api/v1/auth/register', {
      method: 'POST',
      retry: true, // idempotent since tarn #6 (envelope is byte-stable)
      body: {
        credential_lookup_key: keys.credentialLookupKey,
        public_key: publicKeyBase64,
        wrapped_data_key: wrappedDataKey,
        app: this.#appId,
        recovery_lookup_key: recoveryLookupKey,
        recovery_public_key: recoveryPublicKeyBase64,
        share_pub: sharePub,
        share_discoverable: shareDiscoverable,
        share_lookup_key: shareLookupKey,
      },
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
    this.#envelopeVersion = 4;
    this.#kdfVersion = kdfVersion;
    this.#email = email;
    this.#sharingKeyPair = keys.sharingKeyPair;
    // Snapshot the recovery wrapping bytes for the freshly-registered chain
    // so a subsequent changeCredentials() can preserve them without needing
    // the phrase. Re-parse the envelope (cheap — local JSON) to capture the
    // exact wire bytes after wrap.
    {
      const re = parseWrappedDataKey(wrappedDataKey);
      const wrappingsByGen = new Map();
      for (const entry of re.dekChain) {
        const w = entry.wrappings.find(w => w.factor === FACTOR_RECOVERY_PHRASE);
        if (w) wrappingsByGen.set(entry.gen, w.wrappedBase64);
      }
      this.#recoveryFactorMeta = re.recovery
        ? { salt: re.recovery.salt, kdfParams: re.recovery.kdfParams, wrappingsByGen }
        : null;
    }
    this.#recoveryLookupKey = recoveryLookupKey;

    await this.#authenticate();

    // Render the PDF after auth so the JWT is ready in case the caller wants
    // us to email it. PDF rendering is synchronous and cheap.
    const pdfBytes = renderRecoveryPDF({ phrase, appName });

    let emailDelivered = false;
    if (emailRecoveryKit) {
      try {
        await this.sendRecoveryKitEmail({ recipientEmail, pdfBytes, appName });
        emailDelivered = true;
      } catch (err) {
        // Surface but don't fail register: the caller still has phrase + PDF
        // bytes and can retry the email send later. The user has already
        // acknowledged saving the phrase, which is the gating requirement.
        console.warn(`[TarnClient] register: recovery email delivery failed: ${err.message}`);
      }
    }

    return {
      dataLookupKey: this.#dataLookupKey,
      recoveryPhrase: phrase,
      pdfBytes,
      emailDelivered,
    };
  }

  /**
   * Render a fresh recovery PDF for the same phrase the user already holds,
   * and (optionally) email it. The phrase is unchanged — Tarn does not store
   * it, so the caller must provide it.
   *
   * Requires an authenticated session if `emailRecoveryKit` is true (the
   * email forwarder endpoint is JWT-gated). Pure rendering (no email) does
   * not require a session.
   *
   * @param {{
   *   phrase: string,
   *   emailRecoveryKit?: boolean,        // default true
   *   recipientEmail?: string,           // required if emailRecoveryKit is true
   *   appName?: string,
   * }} opts
   * @returns {Promise<{ pdfBytes: Uint8Array, emailDelivered: boolean }>}
   */
  async regenerateRecoveryKit(opts = {}) {
    const { phrase, recipientEmail, appName } = opts;
    const emailRecoveryKit = opts.emailRecoveryKit !== false;

    const validation = validateRecoveryPhrase(phrase);
    if (!validation.valid) {
      throw new Error(`regenerateRecoveryKit(): ${validation.reason}`);
    }
    if (emailRecoveryKit && !recipientEmail) {
      throw new Error('regenerateRecoveryKit(): recipientEmail is required when emailRecoveryKit is true');
    }

    const pdfBytes = renderRecoveryPDF({ phrase: validation.normalized, appName });

    let emailDelivered = false;
    if (emailRecoveryKit) {
      await this.#requireAuth();
      await this.sendRecoveryKitEmail({ recipientEmail, pdfBytes, appName });
      emailDelivered = true;
    }
    return { pdfBytes, emailDelivered };
  }

  /**
   * Forward an already-rendered PDF to the named recipient via the Tarn
   * email-forwarder endpoint. Requires an authenticated session.
   *
   * @param {{ recipientEmail: string, pdfBytes: Uint8Array, appName?: string, subject?: string }} opts
   * @returns {Promise<void>}
   */
  async sendRecoveryKitEmail({ recipientEmail, pdfBytes, appName, subject }) {
    if (!recipientEmail) throw new Error('recipientEmail is required');
    if (!(pdfBytes instanceof Uint8Array) || pdfBytes.length === 0) {
      throw new Error('pdfBytes must be a non-empty Uint8Array');
    }
    await this.#requireAuth();
    const res = await this.#fetch('/api/v1/recovery/email', {
      method: 'POST',
      auth: true,
      body: {
        recipient_email: recipientEmail,
        pdf_base64: bytesToBase64(pdfBytes),
        ...(appName ? { app_name: appName } : {}),
        ...(subject ? { subject } : {}),
      },
    });
    if (res.status !== 200) {
      throw new Error(`Recovery email send failed: ${res.json?.error || res.status}`);
    }
  }

  /**
   * Recover an account using only the recovery phrase + new credentials.
   * Used when the user has lost their password (or wants a security-grade
   * reset that the design-doc positions as "the response to suspected
   * compromise").
   *
   * Flow:
   *   1. Derive recovery_lookup_key + recovery signing key from the phrase
   *   2. POST /auth/challenge { recovery_lookup_key } → get the existing
   *      credential blob's wrapped_data_key + a nonce
   *   3. Parse the v4 envelope, extract the recovery salt, derive recovery KEK
   *   4. Unwrap the DEK chain via the recovery factor
   *   5. Sign the nonce with the recovery signing private key → JWT (the API
   *      verifies against the stored recovery_public_key)
   *   6. Derive new password KEK from (newEmail, newPassword)
   *   7. Re-wrap the DEK chain under both new password KEK + (kept) recovery
   *      KEK and PUT /auth to publish the new credential blob
   *
   * On success the client is authenticated under the new credentials and
   * holds the full DEK chain — old data is still readable.
   *
   * @param {{ phrase: string, newEmail: string, newPassword: string }} opts
   * @returns {Promise<{dataLookupKey: string}>}
   */
  async recoverAccount({ phrase, newEmail, newPassword, ...opts } = {}) {
    const validation = validateRecoveryPhrase(phrase);
    if (!validation.valid) {
      throw new Error(`recoverAccount(): ${validation.reason}`);
    }
    if (!newEmail || !newPassword) {
      throw new Error('recoverAccount(): newEmail and newPassword are required');
    }

    const phraseEntropy = recoveryPhraseToEntropy(validation.normalized);
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
      throw new Error('recoverAccount(): no account found for this recovery phrase + app');
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
    if (parsed.envelopeVersion !== 4 || !parsed.recovery) {
      throw new Error('recoverAccount(): account is not v4 (no recovery factor enrolled)');
    }
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
    this.#dataLookupKey = data_lookup_key;
    // We do NOT yet have the password-side identity — those are derived next.

    // Steps 6-7: derive new password keys, re-wrap DEK chain under both
    // factors, publish via PUT /auth. The sharing keypair (issue #13) and
    // share_lookup_key are also rederived under the new credentials so the
    // recovered account stays discoverable post-recovery (or non-discoverable,
    // if the caller passed `shareDiscoverable: false`).
    const kdfVersion = KDF_DEFAULT;
    const [newKeys, newShareLookupKey] = await Promise.all([
      deriveAllKeys(newEmail, newPassword, this.#appId, kdfVersion),
      deriveShareLookupKey(newEmail, this.#appId),
    ]);
    const newPublicKey = await exportPublicKey(newKeys.signingKeyPair.publicKey);
    const newSharePub = encodeSharePub(newKeys.sharingKeyPair.publicKey);

    const chain = [];
    for (const [gen, pair] of unwrapped.dekByGen) {
      chain.push({ gen, key: pair.gcmKey });
    }
    chain.sort((a, b) => a.gen - b.gen);

    const newWrappedDataKey = await wrapDataKeyChainEnvelopeV4(
      chain,
      [
        { name: FACTOR_PASSWORD,        wrappingKey: newKeys.credentialEncryptionKey.kwKey },
        { name: FACTOR_RECOVERY_PHRASE, wrappingKey: recoveryKEK.kwKey },
      ],
      { salt: parsed.recovery.salt, kdfParams: parsed.recovery.kdfParams },
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

    let oldConnectionsState = { record: { connections: [] }, txid: null };
    const outboundStateByConnection = new Map();
    if (canAnnounce) {
      try {
        oldConnectionsState = await this.#loadConnectionsRecord();
      } catch (err) {
        console.warn(
          `[TarnClient] recoverAccount: connections record load failed (no rotation announce): ${err.message}`,
        );
      }
      for (const connection of oldConnectionsState.record.connections) {
        try {
          await this.#hydrateOutboundState(connection);
          outboundStateByConnection.set(connection.share_pub, this.#tentativeOutboundState(connection));
        } catch (err) {
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
      } catch (err) {
        console.warn(`[TarnClient] recoverAccount: rotation announce failed: ${err.message}`);
      }
    }

    // Update local state to the new identity.
    this.#credentialLookupKey = newKeys.credentialLookupKey;
    this.#credentialEncryptionKey = newKeys.credentialEncryptionKey;
    this.#signingKeyPair = newKeys.signingKeyPair;
    this.#dekByGen = unwrapped.dekByGen;
    this.#currentGen = unwrapped.currentGen;
    this.#envelopeVersion = 4;
    this.#kdfVersion = kdfVersion;
    this.#email = newEmail;
    this.#sharingKeyPair = newKeys.sharingKeyPair;
    // Pair-key cache is derived from share_priv; recovery rotates it.
    this.#pairKeyCache.clear();
    this.#shareLogCounters.clear();
    this.#readStateCache.clear();
    this.#outboundStateCache.clear();
    this.#publishedTxidsByConnection.clear();
    this.#mutedConnectionsState = null;
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
        } catch (err) {
          console.warn(
            `[TarnClient] recoverAccount: NEW-log seq=0 snapshot publish failed for ${connection.share_pub.slice(0, 8)}...: ${err.message}`,
          );
        }
      }
    }

    return { dataLookupKey: this.#dataLookupKey, rotationAnnouncements };
  }

  /**
   * Log in to an existing account for this app.
   * @param {string} email
   * @param {string} password
   * @returns {Promise<{dataLookupKey: string}>}
   */
  async login(email, password) {
    // KDF dispatch — chicken-and-egg problem: credential_lookup_key depends on
    // master_key, which depends on the KDF, which we don't know until we find
    // the account. Strategy: try the current default KDF (Argon2id v2) first;
    // on 404, fall back to legacy PBKDF2 (v1). New accounts pay only the v2
    // cost; legacy accounts pay v2 + v1 once per login (~2s worst case on a
    // representative slow device, well under acceptance bar).
    let keys = await deriveAllKeys(email, password, this.#appId, KDF_V2_ARGON2ID);
    let challengeRes = await this.#fetch('/api/v1/auth/challenge', {
      method: 'POST',
      retry: true, // generates a fresh nonce per call — safe to retry
      body: { credential_lookup_key: keys.credentialLookupKey },
    });

    if (challengeRes.status === 404) {
      // Fall back to legacy PBKDF2 path.
      keys = await deriveAllKeys(email, password, this.#appId, KDF_V1_PBKDF2);
      challengeRes = await this.#fetch('/api/v1/auth/challenge', {
        method: 'POST',
        retry: true,
        body: { credential_lookup_key: keys.credentialLookupKey },
      });
      if (challengeRes.status === 404) {
        throw new Error('Account not found');
      }
    }

    if (challengeRes.status !== 200) {
      throw new Error(`Challenge failed: ${challengeRes.json?.error || challengeRes.status}`);
    }

    this.#credentialLookupKey = keys.credentialLookupKey;
    this.#credentialEncryptionKey = keys.credentialEncryptionKey;
    this.#signingKeyPair = keys.signingKeyPair;
    this.#dataLookupKey = challengeRes.json.data_lookup_key;

    // Unwrap data encryption key chain — handles legacy bare-base64 (v1),
    // single-key v2 envelopes, and v3 chain envelopes uniformly. The
    // envelope's kdfVersion is a sanity check: an Argon2id-derived key
    // wrapping a v1 envelope (or vice versa) would indicate either tampering
    // or a server-side mix-up.
    const unwrapped = await unwrapDataKeyChain(
      challengeRes.json.wrapped_data_key,
      keys.credentialEncryptionKey.kwKey,
    );
    if (unwrapped.kdfVersion !== keys.kdfVersion) {
      throw new Error(
        `KDF mismatch: derived with v${keys.kdfVersion} but credential blob declares v${unwrapped.kdfVersion}`,
      );
    }
    this.#dekByGen = unwrapped.dekByGen;
    this.#currentGen = unwrapped.currentGen;
    this.#envelopeVersion = unwrapped.envelopeVersion;
    this.#kdfVersion = keys.kdfVersion;
    this.#email = email;
    this.#sharingKeyPair = keys.sharingKeyPair;
    // Capture the recovery-factor metadata (v4 only) so a subsequent
    // changeCredentials() can preserve existing recovery wrappings without
    // requiring the user to re-enter the phrase. Login does NOT reveal the
    // recovery_lookup_key (the server doesn't return it on the password-side
    // challenge); recoveryLookupKey stays null until the next register or
    // recoverAccount call repopulates it.
    if (unwrapped.recovery) {
      const reparsed = parseWrappedDataKey(challengeRes.json.wrapped_data_key);
      const wrappingsByGen = new Map();
      for (const entry of reparsed.dekChain) {
        const w = entry.wrappings.find(w => w.factor === FACTOR_RECOVERY_PHRASE);
        if (w) wrappingsByGen.set(entry.gen, w.wrappedBase64);
      }
      this.#recoveryFactorMeta = {
        salt: unwrapped.recovery.salt,
        kdfParams: unwrapped.recovery.kdfParams,
        wrappingsByGen,
      };
    } else {
      this.#recoveryFactorMeta = null;
    }
    this.#recoveryLookupKey = null;

    // Verify
    await this.#verifyChallenge(challengeRes.json.nonce);

    return { dataLookupKey: this.#dataLookupKey };
  }

  /**
   * Change credentials (email and/or password). Requires an active session.
   *
   * Forward-secret DEK rotation (issue #11): on every credential change for
   * an Argon2id account, mint a fresh random DEK at gen N+1 and append to
   * the chain. Existing gens stay accessible (re-wrapped under the new
   * credential_encryption_key) so prior data is still readable.
   *
   * Recovery factor handling (issue #12, v4 accounts):
   * - Old gens' recovery wrappings are PRESERVED verbatim — we don't have the
   *   recovery KEK in this code path (user is logged in via password), so we
   *   can't re-wrap. AES-KW is deterministic anyway: re-wrapping the same DEK
   *   under the same recovery KEK would produce identical bytes, so preserving
   *   is byte-equivalent.
   * - The NEW gen (N+1) gets a recovery wrapping when the caller passes
   *   `phrase`. **Required by default for v4 accounts** (issue #17 follow-up):
   *   without it, the new gen has only a password wrapping, and recovery for
   *   data written under that gen is not possible until the user runs
   *   `regenerateRecoveryKit` or `recoverAccount` to repair the gap. Apps that
   *   need to skip the prompt may pass `acceptRecoveryGap: true` to opt out;
   *   this is intended only for non-interactive flows where the gap is
   *   knowingly accepted.
   *
   * For PBKDF2 (KDF v1) accounts the rotation upgrade is intentionally not
   * applied — they stay on the legacy single-key envelope (issue #11 is
   * scoped to Argon2id accounts; legacy KDF migration is a separate concern).
   *
   * Connection-side identity rotation (issue #17, sharing §13.5): after the
   * credential blob is published, this method announces the new sharing +
   * signing pubkeys to every connection by publishing a `rotate_identity` entry
   * to each connection's OLD outbound log under OLD per-pair keys. Connections'
   * clients pick up the rotation on their next read/sync, update the connection
   * record, and switch to the new keys without user intervention. The known
   * limitation about rotation under compromised OLD keys (sharing §13.5) is
   * accepted for v1; out-of-band recovery is the documented response.
   *
   * @param {string} newEmail
   * @param {string} newPassword
   * @param {{
   *   phrase?: string,
   *   acceptRecoveryGap?: boolean,
   *   skipRotationAnnounce?: boolean,
   * }} [opts]
   *   - `phrase`: BIP39 recovery phrase. Required for v4 accounts unless
   *     `acceptRecoveryGap: true` is set. Extends the recovery wrapping to
   *     gen N+1.
   *   - `acceptRecoveryGap`: opt out of the v4 phrase requirement. The new
   *     gen ships without a recovery wrapping.
   *   - `skipRotationAnnounce`: skip the §13.5 rotation announcement to
   *     connections. Used by tests + low-level flows that intentionally manage
   *     identity rotation themselves; production callers should leave it
   *     unset (default false).
   */
  async changeCredentials(newEmail, newPassword, opts = {}) {
    await this.#requireAuth();

    // §17 follow-up: phrase is required by default for v4 accounts. Skipping
    // it leaves the new gen without a recovery wrapping; if the user later
    // forgets the password, data written under the new gen is lost. Apps
    // that have a knowing reason to skip can pass `acceptRecoveryGap: true`.
    if (this.#envelopeVersion === 4 && !opts.phrase && opts.acceptRecoveryGap !== true) {
      throw new Error(
        'changeCredentials(): v4 accounts must supply `phrase` (the recovery phrase) ' +
        'so the new generation gets a recovery wrapping. Pass `acceptRecoveryGap: true` ' +
        'to override (the new gen will be unrecoverable via phrase until repaired).',
      );
    }

    // Preserve the original KDF — silent upgrade from PBKDF2 to Argon2id is
    // out of scope for this issue (would be a separate migration concern).
    const kdfVersion = this.#kdfVersion ?? KDF_DEFAULT;
    const [newKeys, newShareLookupKey] = await Promise.all([
      deriveAllKeys(newEmail, newPassword, this.#appId, kdfVersion),
      deriveShareLookupKey(newEmail, this.#appId),
    ]);
    const newPublicKey = await exportPublicKey(newKeys.signingKeyPair.publicKey);
    // Sharing keypair (issue #13) rotates with master_key (depends on both
    // email and password). The discoverability flag is preserved by the API
    // when omitted; let `opts.shareDiscoverable` override it for callers that
    // also want to flip it as part of the credential change.
    const newSharePub = encodeSharePub(newKeys.sharingKeyPair.publicKey);

    let newWrappedDataKey;
    let newDekByGen;
    let newCurrentGen;
    let newEnvelopeVersion;
    let newRecoveryFactorMeta = this.#recoveryFactorMeta;

    if (kdfVersion === KDF_V1_PBKDF2) {
      // Legacy PBKDF2 path — keep the existing single-key envelope shape.
      // No forward-secret rotation for v1 accounts in this issue.
      const existing = this.#dekByGen.get(this.#currentGen);
      newWrappedDataKey = await wrapDataKeyEnvelope(
        existing.gcmKey,
        newKeys.credentialEncryptionKey.kwKey,
        KDF_V1_PBKDF2,
      );
      newDekByGen = this.#dekByGen;
      newCurrentGen = this.#currentGen;
      newEnvelopeVersion = 1;
    } else if (this.#envelopeVersion === 4) {
      // v4 path — multi-factor envelope. Re-wrap the entire chain under the
      // new password KEK; preserve recovery wrappings verbatim (we don't have
      // the recovery KEK without the phrase). New gen N+1 gets a password
      // wrapping always, and a recovery wrapping iff the caller supplied the
      // phrase (allowing recovery to remain complete after the change).
      const nextGen = this.#currentGen + 1;
      const newDek = await generateRandomDataKey();

      // Build chain of {gen, key} for password-side re-wrap.
      const chain = [];
      for (const [gen, pair] of this.#dekByGen) {
        chain.push({ gen, key: pair.gcmKey });
      }
      chain.push({ gen: nextGen, key: newDek.gcmKey });
      chain.sort((a, b) => a.gen - b.gen);

      // Re-wrap each chain entry under the new password KEK.
      const reWrappedPassword = new Map();
      for (const entry of chain) {
        const wrappedBase64 = await this.#wrapDekRaw(entry.key, newKeys.credentialEncryptionKey.kwKey);
        reWrappedPassword.set(entry.gen, wrappedBase64);
      }

      // Recovery wrappings: preserve existing per-gen bytes; optionally derive
      // a fresh wrapping for the new gen if a phrase was supplied.
      const recoveryWrappingsByGen = new Map();
      if (this.#recoveryFactorMeta) {
        for (const [gen, b64] of this.#recoveryFactorMeta.wrappingsByGen) {
          recoveryWrappingsByGen.set(gen, b64);
        }
      }
      if (opts.phrase && this.#recoveryFactorMeta) {
        const validation = validateRecoveryPhrase(opts.phrase);
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

      // Stitch the wire-format chain together.
      const wireChain = chain.map(({ gen }) => {
        const wrappings = [{ factor: FACTOR_PASSWORD, wrappedBase64: reWrappedPassword.get(gen) }];
        if (recoveryWrappingsByGen.has(gen)) {
          wrappings.push({
            factor: FACTOR_RECOVERY_PHRASE,
            wrappedBase64: recoveryWrappingsByGen.get(gen),
          });
        }
        return { gen, wrappings };
      });

      // buildV4Envelope is in crypto.js; call via a thin wrapper to avoid the
      // direct dependency on the build helper from this file.
      newWrappedDataKey = this.#buildV4FromWireChain(
        wireChain,
        this.#recoveryFactorMeta
          ? { salt: this.#recoveryFactorMeta.salt, kdfParams: this.#recoveryFactorMeta.kdfParams }
          : null,
      );

      newDekByGen = new Map(this.#dekByGen);
      newDekByGen.set(nextGen, { gcmKey: newDek.gcmKey, kwKey: newDek.kwKey });
      newCurrentGen = nextGen;
      newEnvelopeVersion = 4;
      if (this.#recoveryFactorMeta) {
        newRecoveryFactorMeta = {
          salt: this.#recoveryFactorMeta.salt,
          kdfParams: this.#recoveryFactorMeta.kdfParams,
          wrappingsByGen: recoveryWrappingsByGen,
        };
      }
    } else {
      // v2/v3 Argon2id path — single-factor chain envelope (issue #11).
      // v2 envelopes (single self-wrapped DEK, pre-issue-#11) are upgraded in
      // place to v3 here: the existing DEK becomes gen 1, the fresh random
      // DEK becomes gen 2.
      const nextGen = this.#currentGen + 1;
      const newDek = await generateRandomDataKey();

      const chain = [];
      for (const [gen, pair] of this.#dekByGen) {
        chain.push({ gen, key: pair.gcmKey });
      }
      chain.push({ gen: nextGen, key: newDek.gcmKey });

      newWrappedDataKey = await wrapDataKeyChainEnvelope(
        chain,
        newKeys.credentialEncryptionKey.kwKey,
      );

      newDekByGen = new Map(this.#dekByGen);
      newDekByGen.set(nextGen, { gcmKey: newDek.gcmKey, kwKey: newDek.kwKey });
      newCurrentGen = nextGen;
      newEnvelopeVersion = 3;
    }

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
    let oldConnectionsState = { record: { connections: [] }, txid: null };
    const outboundStateByConnection = new Map();
    if (!skipRotationAnnounce) {
      try {
        oldConnectionsState = await this.#loadConnectionsRecord();
      } catch (err) {
        console.warn(
          `[TarnClient] changeCredentials: connections record load failed (no rotation announce): ${err.message}`,
        );
      }
      for (const connection of oldConnectionsState.record.connections) {
        try {
          await this.#hydrateOutboundState(connection);
          outboundStateByConnection.set(connection.share_pub, this.#tentativeOutboundState(connection));
        } catch (err) {
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
      } catch (err) {
        console.warn(`[TarnClient] changeCredentials: rotation announce failed: ${err.message}`);
      }
    }

    this.#credentialLookupKey = newKeys.credentialLookupKey;
    this.#credentialEncryptionKey = newKeys.credentialEncryptionKey;
    this.#signingKeyPair = newKeys.signingKeyPair;
    this.#dekByGen = newDekByGen;
    this.#currentGen = newCurrentGen;
    this.#envelopeVersion = newEnvelopeVersion;
    this.#recoveryFactorMeta = newRecoveryFactorMeta;
    this.#email = newEmail;
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
        } catch (err) {
          console.warn(
            `[TarnClient] changeCredentials: NEW-log seq=0 snapshot publish failed for ${connection.share_pub.slice(0, 8)}...: ${err.message}`,
          );
        }
      }
    }

    return { rotationAnnouncements };
  }

  /**
   * Wrap a single DEK CryptoKey under an AES-KW wrapping key, returning the
   * raw base64 ciphertext. Thin convenience used by the v4 changeCredentials
   * path so we can build wrappings imperatively without the higher-level
   * envelope helpers.
   */
  async #wrapDekRaw(dekGcmKey, wrappingKey) {
    const wrapped = await crypto.subtle.wrapKey('raw', dekGcmKey, wrappingKey, 'AES-KW');
    return bytesToBase64(new Uint8Array(wrapped));
  }

  /**
   * Build a v4 envelope JSON string from a wire-shaped chain (each entry
   * already carrying base64-wrapped factor bytes). Defers to crypto.js's
   * buildV4Envelope to keep the JSON shape in one place.
   */
  #buildV4FromWireChain(wireChain, recovery) {
    return buildV4Envelope(wireChain, recovery);
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

    this.#jwt = null;
    this.#dataLookupKey = null;
    this.#dekByGen = null;
    this.#currentGen = null;
    this.#envelopeVersion = null;
    this.#credentialLookupKey = null;
    this.#credentialEncryptionKey = null;
    this.#signingKeyPair = null;
    this.#kdfVersion = null;
    this.#recoveryFactorMeta = null;
    this.#recoveryLookupKey = null;
    this.#email = null;
    this.#sharingKeyPair = null;
    this.#replayNonceCache = makeReplayNonceCache();
    this.#pairKeyCache.clear();
    this.#shareLogCounters.clear();
    this.#readStateCache.clear();
    this.#outboundStateCache.clear();
    this.#publishedTxidsByConnection.clear();
    this.#mutedConnectionsState = null;
  }

  // ============ DATA CRUD ============

  /**
   * Create a new data entry.
   * @param {string} type - Entry type (e.g., 'entry')
   * @param {Object} plaintext - JSON-serializable payload
   * @param {Array<{name: string, value: string}>} extraTags
   * @returns {Promise<{txid: string}>}
   */
  async createEntry(type, plaintext, extraTags = []) {
    await this.#requireAuth();

    const { encrypted, tags: cryptoTags } = await this.#encryptForWrite(plaintext);
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

    return { txid: json.id };
  }

  /**
   * Bulk import multiple entries in one request.
   * Counts as 1 rate-limit hit regardless of batch size. Max 100 entries per batch.
   * @param {string} type - Entry type for all entries
   * @param {Array<Object>} items - Array of JSON-serializable payloads
   * @returns {Promise<Array<{txid: string}>>}
   */
  async batchCreate(type, items) {
    await this.#requireAuth();

    if (!Array.isArray(items) || items.length === 0) {
      throw new Error('items must be a non-empty array');
    }
    if (items.length > 25) {
      throw new Error('items max 25 per batch');
    }

    // Encrypt each item and build the batch payload
    const entries = [];
    for (const item of items) {
      const { encrypted, tags: cryptoTags } = await this.#encryptForWrite(item);
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
    }

    // Batch idempotency: one key for the whole batch. Server stores the full
    // list of txids against it; retry returns the same list (#8).
    const idempotencyKey = generateIdempotencyKey();
    const res = await this.#fetchBatch(entries, idempotencyKey);

    if (res.status !== 200) {
      throw new Error(`Batch create failed: ${res.json?.error || res.status}`);
    }

    return res.json.entries;
  }

  async #fetchBatch(entries, idempotencyKey) {
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
  async getEntries(type) {
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

    // Decrypt all entries — use inline blob data from API when available,
    // fall back to gateway fetch only for entries without cached blobs
    const entries = [];
    const needsFetch = [];

    for (const entry of allRawEntries) {
      if (entry.data) {
        // Blob data returned inline from API (base64) — decrypt directly
        try {
          const blobBytes = base64ToBytes(entry.data);
          const data = await this.#decryptBlob(blobBytes, entry.tags);
          entries.push({ txid: entry.txid, data, tags: entry.tags });
        } catch (err) {
          console.warn(`Failed to decrypt inline entry ${entry.txid}:`, err.message);
        }
      } else {
        // No inline data — need to fetch from Arweave gateway (backfill not yet done)
        needsFetch.push(entry);
      }
    }

    // Fetch remaining entries from gateways in parallel
    if (needsFetch.length > 0) {
      const CONCURRENCY = 20;
      for (let i = 0; i < needsFetch.length; i += CONCURRENCY) {
        const batch = needsFetch.slice(i, i + CONCURRENCY);
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
  async updateEntry(priorTxid, type, plaintext) {
    await this.#requireAuth();

    const { encrypted, tags: cryptoTags } = await this.#encryptForWrite(plaintext);
    const tags = [
      { name: 'App', value: this.#appId },
      { name: 'Type', value: type },
      { name: 'Lk', value: this.#dataLookupKey },
      { name: 'Prev', value: priorTxid },
      ...cryptoTags,
      { name: 'V', value: '0.4.0' },
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

    return { txid: json.id };
  }

  /**
   * Delete an entry (tombstone).
   * @param {string} targetTxid
   * @param {string} type - Entry type
   * @returns {Promise<{txid: string}>}
   */
  async deleteEntry(targetTxid, type) {
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

  // ============ SHARING (issue #13) ============

  /**
   * Look up a recipient's published X25519 sharing public key by email + this
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
   * The lookup is unauthenticated and IP rate-limited at the API. Per-email
   * leakage ("Alice queried Bob's share key") is an accepted residual leak
   * (sharing §11.5) — once the handshake completes, all subsequent traffic is
   * unlinkable.
   *
   * @param {string} email
   * @returns {Promise<{
   *   sharePub: Uint8Array | null,
   *   sharePubBase64Url: string | null,
   *   discoverable: boolean,
   * }>}
   */
  async getRecipientShareKey(email) {
    if (!email) throw new Error('email is required');
    const shareLookupKey = await deriveShareLookupKey(email, this.#appId);
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
   *   2. Build the request payload (sender_email, sender_share_pub,
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
   * @param {string} recipientEmail
   * @param {{ message?: string }} [opts]
   * @returns {Promise<{
   *   txid: string,                    // Arweave tx_id of the published request
   *   requestNonce: string,            // base64url 16 bytes
   *   recipientSharePubBase64Url: string,
   * }>}
   */
  async sendConnectionRequest(recipientEmail, opts = {}) {
    await this.#requireAuth();
    if (!this.#sharingKeyPair) {
      throw new Error('sendConnectionRequest(): no sharing keypair — login as a v4 account first');
    }
    if (!this.#email) {
      throw new Error('sendConnectionRequest(): client missing sender email — re-login');
    }

    const { sharePub, sharePubBase64Url } = await this.getRecipientShareKey(recipientEmail);
    if (!sharePub) {
      // Three causes are indistinguishable to the caller (sharing §11.5): the
      // recipient doesn't exist, the recipient's account predates #13, or the
      // recipient has set discoverable=false. Surface a single-shape error
      // that callers can match on without knowing which one.
      const err = new Error('sendConnectionRequest(): recipient is not connectable (no share_pub published, or discoverable=false)');
      err.code = 'RECIPIENT_NOT_CONNECTABLE';
      throw err;
    }

    const senderSigningPubBase64 = await exportPublicKey(this.#signingKeyPair.publicKey);
    const payload = buildConnectionRequestPayload({
      senderEmail: this.#email,
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
      recipient_email: recipientEmail,
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
   *   senderEmail: string,
   *   senderSharePubBase64Url: string,
   *   senderSigningPubBase64: string,
   *   senderAppId: string,
   *   requestNonce: string,
   *   timestamp: number,
   *   message: string | null,
   *   txid: string,
   * }>>}
   */
  async listIncomingRequests(opts = {}) {
    await this.#requireAuth();
    if (!this.#sharingKeyPair) {
      throw new Error('listIncomingRequests(): no sharing keypair — login as a v4 account first');
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
      (connectionsState.record.connections || []).map(c => c.share_pub)
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
        if (pendingRecord.inbound.some(i => i.request_nonce === validation.normalized.nonceBase64Url)) {
          // Surface from existing record (so the caller sees a stable view)
          // but don't duplicate-write.
          surfaced.push({
            senderEmail: validation.normalized.senderEmail,
            senderSharePubBase64Url: validation.normalized.senderSharePubBase64Url,
            senderSigningPubBase64: validation.normalized.senderSigningPubBase64,
            senderAppId: validation.normalized.senderAppId,
            requestNonce: validation.normalized.nonceBase64Url,
            timestamp: validation.normalized.timestamp,
            message: validation.normalized.message,
            txid: blob.txid,
          });
          continue;
        }

        // Persist into inbound pending so the user can act on it later
        // (acceptConnectionRequest uses this list to find the matching request).
        pendingRecord = addInboundPending(pendingRecord, {
          sender_email: validation.normalized.senderEmail,
          sender_share_pub: validation.normalized.senderSharePubBase64Url,
          sender_signing_pub: validation.normalized.senderSigningPubBase64,
          sender_app_id: validation.normalized.senderAppId,
          request_nonce: validation.normalized.nonceBase64Url,
          message: validation.normalized.message,
          received_at: Math.floor(Date.now() / 1000),
        });
        pendingDirty = true;

        surfaced.push({
          senderEmail: validation.normalized.senderEmail,
          senderSharePubBase64Url: validation.normalized.senderSharePubBase64Url,
          senderSigningPubBase64: validation.normalized.senderSigningPubBase64,
          senderAppId: validation.normalized.senderAppId,
          requestNonce: validation.normalized.nonceBase64Url,
          timestamp: validation.normalized.timestamp,
          message: validation.normalized.message,
          txid: blob.txid,
        });
      }
    }

    if (pendingDirty) {
      await this.#savePendingRequestsRecord(pendingState, pendingRecord);
    }

    // Also poll for incoming ACCEPTS while we're at it — Bob's accept lands
    // in Alice's inbox, so Alice's listIncomingRequests is also Alice's
    // accept-poll. This keeps the SDK surface narrow (one polling primitive
    // per direction was overkill for v1). Returns surfaced connection-requests
    // only; processed accepts mutate the connections record + pending record
    // silently.
    await this.#pollAndProcessIncomingAccepts(myPriv, myPub);

    return surfaced;
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
   * @param {string} requestNonce - base64url nonce from the original request
   * @returns {Promise<{ txid: string }>}
   */
  async acceptConnectionRequest(requestNonce) {
    await this.#requireAuth();
    if (!this.#sharingKeyPair) {
      throw new Error('acceptConnectionRequest(): no sharing keypair — login as a v4 account first');
    }
    if (typeof requestNonce !== 'string' || requestNonce.length === 0) {
      throw new Error('requestNonce is required');
    }

    const pendingState = await this.#loadPendingRequestsRecord();
    const inbound = pendingState.record.inbound.find(i => i.request_nonce === requestNonce);
    if (!inbound) {
      throw new Error(`acceptConnectionRequest(): no inbound pending request with nonce ${requestNonce}`);
    }

    let senderSharePub;
    try {
      senderSharePub = decodeSharePub(inbound.sender_share_pub);
    } catch (err) {
      throw new Error(`acceptConnectionRequest(): inbound sender_share_pub is invalid: ${err.message}`);
    }

    const senderSigningPubBase64 = await exportPublicKey(this.#signingKeyPair.publicKey);
    const payload = buildConnectionAcceptPayload({
      senderEmail: this.#email,
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
      email: inbound.sender_email,
      share_pub: inbound.sender_share_pub,
      signing_pub: inbound.sender_signing_pub,
      established_at: payload.timestamp,
      initial_request_nonce: requestNonce,
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
    } catch (err) {
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
   * @returns {Promise<Array<{
   *   email: string,
   *   share_pub: string,
   *   signing_pub: string,
   *   established_at: number,
   *   initial_request_nonce: string,
   *   label?: string,
   * }>>}
   */
  async listConnections() {
    await this.#requireAuth();
    const state = await this.#loadConnectionsRecord();
    return state.record.connections.slice();
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
  async muteConnection(connection) {
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
  async unmuteConnection(connection) {
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
  async isMuted(connection) {
    await this.#requireAuth();
    if (!connection || typeof connection.share_pub !== 'string') {
      throw new Error('isMuted(): connection.share_pub is required');
    }
    const state = await this.#loadMutedConnectionsRecord();
    return isMutedInRecord(state.record, connection.share_pub);
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
  async #getPairKeysFor(connectionSharePubBase64Url) {
    if (!this.#sharingKeyPair) {
      throw new Error('share log: no sharing keypair — login as a v4 account first');
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

  #getOrInitCounters(connectionSharePubBase64Url) {
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
  async #findConnectionBySharePub(connectionSharePubBase64Url) {
    const connectionsState = await this.#loadConnectionsRecord();
    return connectionsState.record.connections.find(
      f => f.share_pub === connectionSharePubBase64Url,
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
  async _publishShareLogEntry(connection, operationFields, opts = {}) {
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
      const signed = await signOperation(operation, this.#signingKeyPair.privateKey);
      const blob = await encryptShareLogEntry(signed, pair.outboundKey);
      tag = await deriveLogTag(pair.outboundTagSeed, seq);

      try {
        txid = await this.#postShareLogPublish(tag, blob);
        break;
      } catch (err) {
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

    const out = { seq, tag, txid };
    if (attempts > 0) out.retried = attempts;
    if (alreadyPublished) out.alreadyPublished = true;
    if (compactionSnapshot) out.compactionSnapshot = compactionSnapshot;
    return out;
  }

  #recordPublishedTxid(sharePub, txid) {
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
  async #probeOutboundTagExists(pair, seq) {
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
  async #discoverOutboundHighestSeq(pair, opts = {}) {
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
  async _fetchShareLogEntry(connection, seq) {
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
    } catch (err) {
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
  async _publishInitialSnapshot(connection, opts = {}) {
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
  async readShareLog(connection, opts = {}) {
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
  async syncShareLog(connection) {
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
  async #probeInboundTagExists(pair, seq) {
    const tag = await deriveLogTag(pair.inboundTagSeed, seq);
    const blob = await this.#getShareLogBlobByTag(tag);
    return blob !== null;
  }

  /**
   * Test-only: peek at the read-state cache for a connection. Returns null if
   * no entry. Production code should not depend on this — it exists for
   * tests asserting cache-hit semantics.
   */
  _peekReadStateCache(connectionSharePubBase64Url) {
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
  async shareContent(connection, contentId, txId, cekBase64Url) {
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
  async updateShareContent(connection, contentId, newTxId) {
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
  async unshareContent(connection, contentId) {
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
  async snapshotShareLog(connection, state) {
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
  async removeConnection(connection, opts = {}) {
    await this.#requireAuth();
    if (!connection || typeof connection.share_pub !== 'string') {
      throw new Error('removeConnection(): connection.share_pub is required');
    }

    const connectionsState = await this.#loadConnectionsRecord();
    const present = connectionsState.record.connections.some(f => f.share_pub === connection.share_pub);
    if (!present) {
      this.#clearConnectionCaches(connection.share_pub);
      return { removed: false };
    }

    let notifications;
    if (opts.notify === true) {
      // Courtesy: publish a final `remove` per content_id we're currently
      // sharing with this connection. We need the outbound state to enumerate
      // the content_ids — hydrate from the existing log if not cached.
      const fullConnection = connectionsState.record.connections.find(f => f.share_pub === connection.share_pub) || connection;
      try {
        await this.#hydrateOutboundState(fullConnection);
      } catch (err) {
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
        } catch (err) {
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
  async revokeContentFromConnections(contentId, opts = {}) {
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
      } catch (err) {
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
      } catch (err) {
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
  async #announceIdentityRotationToConnections({
    oldSharingKeyPair,
    oldSigningKeyPair,
    oldConnectionsRecord,
    newSharingPublicKey,
    newSigningPublicKey,
    newCredentialLookupKey,
    rotatedAt,
  }) {
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
        } catch (err) {
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
      } catch (err) {
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
  async #discoverHighestSeqViaTagSeed(tagSeed, anchor = 0) {
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
  async #publishRotateIdentityAtSeq({
    connection, oldPair, oldSigningPrivateKey, startSeq, payload,
  }) {
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
      } catch (err) {
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
  async #processRotateIdentityEntry(connection, operation) {
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
  #clearConnectionCaches(connectionSharePubBase64Url) {
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
  async #hydrateOutboundState(connection) {
    const existing = this.#outboundStateCache.get(connection.share_pub);
    if (existing?.hydrated) return;

    const pair = await this.#getPairKeysFor(connection.share_pub);
    const ownSigningPubBase64 = await exportPublicKey(this.#signingKeyPair.publicKey);

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
  async #fetchOwnOutboundEntry(pair, seq, ownSigningPubBase64) {
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
  #tentativeOutboundState(connection) {
    const cached = this.#outboundStateCache.get(connection.share_pub);
    return cached ? { ...cached.state } : {};
  }

  #commitOutboundState(connection, newState) {
    this.#outboundStateCache.set(connection.share_pub, {
      state: { ...newState },
      hydrated: true,
    });
  }

  /**
   * Test-only: peek at the outbound state cache for a connection. Returns null
   * if not hydrated. Used by tests asserting outbound-snapshot semantics.
   */
  _peekOutboundStateCache(connectionSharePubBase64Url) {
    const e = this.#outboundStateCache.get(connectionSharePubBase64Url);
    if (!e) return null;
    return { state: { ...e.state }, hydrated: !!e.hydrated };
  }

  // ---- Private share-log helpers ----

  async #postShareLogPublish(tag, blob) {
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
      const err = new Error(
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

  async #getShareLogBlobByTag(tag) {
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

  async #fetchInboxBlobs(tag, type) {
    // Public endpoint — no auth needed. The recipient (us) is the only party
    // that can decrypt anyway; the API just acts as a tag-keyed cache.
    const url = `/api/v1/share/inbox/fetch?app=${encodeURIComponent(this.#appId)}&tag=${tag}&type=${encodeURIComponent(type)}`;
    const res = await this.#fetch(url);
    if (res.status !== 200) {
      console.warn(`[TarnClient] inbox fetch ${tag.slice(0, 8)}.../${type} failed: ${res.json?.error || res.status}`);
      return [];
    }
    const blobs = res.json?.blobs ?? [];
    return blobs.map(b => ({
      txid: b.txid,
      ciphertext: base64ToBytes(b.ciphertext_base64),
      published_at: b.published_at,
    }));
  }

  async #pollAndProcessIncomingAccepts(myPriv, myPub) {
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
        const existingConnection = connectionsState.record.connections.find(f => f.share_pub === v.normalized.senderSharePubBase64Url);
        if (existingConnection) {
          // Still clear the matched outbound — sender side already moved on.
          if (pendingState.record.outbound.some(o => o.request_nonce === outbound.request_nonce)) {
            pendingState = { ...pendingState, record: removeOutboundPending(pendingState.record, outbound.request_nonce) };
            pendingDirty = true;
          }
          continue;
        }

        const newConnection = {
          email: v.normalized.senderEmail,
          share_pub: v.normalized.senderSharePubBase64Url,
          signing_pub: v.normalized.senderSigningPubBase64,
          established_at: v.normalized.timestamp,
          initial_request_nonce: outbound.request_nonce,
        };
        connectionsState = {
          ...connectionsState,
          record: upsertConnection(connectionsState.record, newConnection),
        };
        connectionsDirty = true;

        pendingState = {
          ...pendingState,
          record: removeOutboundPending(pendingState.record, outbound.request_nonce),
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
        } catch (err) {
          console.warn(
            `[TarnClient] processing accept from ${v.normalized.senderEmail}: initial snapshot publish failed: ${err.message}`,
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
  async #loadConnectionsRecord() {
    const entry = await this.#findShareStateEntry(CONNECTIONS_CONTENT_ID);
    if (!entry) {
      return { record: emptyConnectionsRecord(this.#appId), txid: null };
    }
    return { record: entry.data, txid: entry.txid };
  }

  async #saveConnectionsRecord(state, newRecord) {
    return await this.#writeShareStateEntry(CONNECTIONS_CONTENT_ID, state, newRecord);
  }

  async #loadPendingRequestsRecord() {
    const entry = await this.#findShareStateEntry(PENDING_REQUESTS_CONTENT_ID);
    if (!entry) {
      return { record: emptyPendingRequestsRecord(this.#appId), txid: null };
    }
    return { record: entry.data, txid: entry.txid };
  }

  async #savePendingRequestsRecord(state, newRecord) {
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
  async #loadMutedConnectionsRecord() {
    if (this.#mutedConnectionsState) return this.#mutedConnectionsState;
    const entry = await this.#findShareStateEntry(MUTED_CONNECTIONS_CONTENT_ID);
    const state = entry
      ? { record: entry.data, txid: entry.txid }
      : { record: emptyMutedConnectionsRecord(this.#appId), txid: null };
    this.#mutedConnectionsState = state;
    return state;
  }

  async #saveMutedConnectionsRecord(state, newRecord) {
    return await this.#writeShareStateEntry(MUTED_CONNECTIONS_CONTENT_ID, state, newRecord);
  }

  /**
   * Find the latest (resolved) `tarn-share-state` entry for a given
   * content_id. Returns `{ txid, data }` or null if no entry exists yet.
   *
   * The connections + pending records use type='tarn-share-state' with
   * Eid=<content_id>. Resolution dedupes by Eid + Prev chain so we get the
   * single live version.
   */
  async #findShareStateEntry(contentId) {
    const entries = await this.getEntries('tarn-share-state');
    for (const e of entries) {
      const eid = e.tags?.find(t => t.name === 'Eid')?.value;
      if (eid === contentId) return e;
    }
    return null;
  }

  async #writeShareStateEntry(contentId, state, newRecord) {
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
   * Test-only: lower the per-connection share-log snapshot compaction interval
   * so an integration test can trigger auto-compaction without publishing
   * 100 entries. Production code should leave this at the default.
   */
  _setShareLogCompactionIntervalForConnection(connectionSharePubBase64Url, interval) {
    if (!Number.isInteger(interval) || interval < 1) {
      throw new Error('interval must be a positive integer');
    }
    const counters = this.#getOrInitCounters(connectionSharePubBase64Url);
    counters.compactionInterval = interval;
  }

  // ============ PRIVATE ============

  /**
   * Encrypt a payload for an outgoing write (issue #11).
   *
   * Per-content CEK pattern when the account has a v3 envelope: produces a
   * blob prefixed with the TARN magic, with a fresh CEK wrapped under the
   * current generation's DEK. The generation indicator travels alongside as
   * the Arweave `Gen` tag — keeping the blob byte-layout from the design doc
   * unchanged so a future recipient (Section 5) can skip bytes 5..44 without
   * parsing tags.
   *
   * For legacy single-key envelopes (v1/v2) the write stays in legacy format:
   * direct AES-GCM with the gen-1 DEK and `Enc: aes-256-gcm` tag, no `Gen`
   * tag, no magic prefix. v2 accounts upgrade to v3 on next changeCredentials.
   *
   * @param {Object} plaintext - JSON-serializable payload
   * @returns {Promise<{ encrypted: Uint8Array, tags: Array<{name:string, value:string}> }>}
   */
  async #encryptForWrite(plaintext) {
    const dek = this.#dekByGen.get(this.#currentGen);
    if (!dek) {
      throw new Error(`Internal: no DEK for gen ${this.#currentGen}`);
    }

    // v3 and v4 use the per-content CEK format with the same `Enc: tarn-cek-1`
    // tag and `Gen: N` indicator. The two versions differ only in the credential
    // envelope's wrapping shape — the on-the-wire blob layout is identical.
    if (this.#envelopeVersion === 3 || this.#envelopeVersion === 4) {
      const encrypted = await encryptWithCEK(dek.kwKey, plaintext);
      return {
        encrypted,
        tags: [
          { name: 'Enc', value: 'tarn-cek-1' },
          { name: 'Gen', value: String(this.#currentGen) },
        ],
      };
    }

    // Legacy v1/v2 envelope path — direct AES-GCM with the (only) DEK.
    const encrypted = await encrypt(dek.gcmKey, plaintext);
    return {
      encrypted,
      tags: [{ name: 'Enc', value: 'aes-256-gcm' }],
    };
  }

  /**
   * Decrypt a blob from a read. Dispatches on the 5-byte TARN magic prefix
   * (issue #11): new-format blobs use the per-content CEK path with the
   * generation indicated by the `Gen` tag; legacy blobs use direct AES-GCM
   * with the gen-1 DEK.
   *
   * @param {Uint8Array} blobBytes
   * @param {Array<{name: string, value: string}>} tags
   * @returns {Promise<Object>}
   */
  async #decryptBlob(blobBytes, tags) {
    if (hasTarnBlobMagic(blobBytes)) {
      const gen = readGenTag(tags) ?? 1;
      const dek = this.#dekByGen.get(gen);
      if (!dek) {
        throw new Error(`No DEK for blob generation ${gen} — chain has gens [${[...this.#dekByGen.keys()].join(', ')}]`);
      }
      return await decryptWithCEK(dek.kwKey, blobBytes);
    }

    // Legacy blob — decrypt directly with the gen-1 DEK. For v3 accounts that
    // were upgraded from v2, gen 1 holds the original (pre-issue-#11) DEK.
    const legacy = this.#dekByGen.get(1);
    if (!legacy) {
      throw new Error('No gen-1 DEK available for legacy blob decryption');
    }
    return await decrypt(legacy.gcmKey, blobBytes);
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
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
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

  async #verifyChallenge(nonce) {
    const signature = await signChallenge(this.#signingKeyPair.privateKey, nonce);

    const verifyRes = await this.#fetch('/api/v1/auth/verify', {
      method: 'POST',
      body: {
        credential_lookup_key: this.#credentialLookupKey,
        nonce,
        signature,
      },
    });

    if (verifyRes.status !== 200) {
      throw new Error(`Verify failed: ${verifyRes.json?.error}`);
    }

    this.#jwt = verifyRes.json.jwt;
  }

  async #fetchBlob(txid) {
    const gateways = [
      `https://turbo-gateway.com/${txid}`,
      `https://arweave.net/${txid}`,
    ];

    for (const url of gateways) {
      try {
        const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
        if (res.ok) return new Uint8Array(await res.arrayBuffer());
      } catch {}
    }
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
  async #fetch(path, { method = 'GET', body = null, auth = false, retry = method === 'GET' } = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (auth && this.#jwt) headers['Authorization'] = `Bearer ${this.#jwt}`;

    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);

    const res = await this.#executeFetch(`${this.#apiBase}${path}`, opts, retry);
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch { json = null; }
    return { status: res.status, json, text };
  }

  async #fetchRaw(path, opts, { retry = opts?.method === 'GET' } = {}) {
    return await this.#executeFetch(`${this.#apiBase}${path}`, opts, retry);
  }

  async #executeFetch(url, opts, allowRetry) {
    const MAX_ATTEMPTS = allowRetry ? 3 : 1;
    let lastErr;

    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      try {
        const res = await fetch(url, opts);
        const isTransient = res.status >= 500 || res.status === 429;
        if (!isTransient || attempt === MAX_ATTEMPTS - 1) {
          return res;
        }

        // Drain body before retry so the underlying connection can be reused.
        try { await res.body?.cancel(); } catch {}

        const retryAfterSec = parseRetryAfter(res.headers.get('Retry-After'));
        // Don't honor Retry-After values longer than 60 seconds — the server
        // is telling us to back off for a budget window we can't realistically
        // wait for (recovery email rate limit, share-inbox fetch limit, etc.
        // all return Retry-After: 3600). Surface the 429 to the caller instead
        // so they can decide what to do, rather than blocking the test or
        // the UX for an hour.
        if (retryAfterSec != null && retryAfterSec > 60) {
          return res;
        }
        const waitMs = retryAfterSec != null ? retryAfterSec * 1000 : backoffMs(attempt);
        console.warn(`[TarnClient] ${res.status} on ${url} — retrying in ${Math.round(waitMs)}ms (attempt ${attempt + 1}/${MAX_ATTEMPTS})`);
        await sleep(waitMs);
      } catch (err) {
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
function readGenTag(tags) {
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
function generateIdempotencyKey() {
  // crypto.randomUUID is available in modern browsers and Node 15+.
  return crypto.randomUUID();
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Exponential backoff with ±25% jitter.
 * Attempt 0 → ~500ms, attempt 1 → ~1500ms.
 */
function backoffMs(attempt) {
  const base = 500 * Math.pow(3, attempt);
  const jitter = base * (Math.random() * 0.5 - 0.25);
  return base + jitter;
}

/**
 * Parse Retry-After header value. Returns seconds (number) or null if absent/invalid.
 * Supports both the delta-seconds form (e.g., "60") and the HTTP-date form.
 */
function parseRetryAfter(value) {
  if (!value) return null;
  const n = parseInt(value, 10);
  if (!isNaN(n) && n >= 0) return n;
  const date = Date.parse(value);
  if (!isNaN(date)) {
    return Math.max(0, Math.floor((date - Date.now()) / 1000));
  }
  return null;
}
