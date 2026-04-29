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
  buildFriendRequestPayload,
  validateFriendRequestPayload,
  buildFriendAcceptPayload,
  validateFriendAcceptPayload,
  makeReplayNonceCache,
  checkAndRecordNonce,
  findOutboundForAccept,
  emptyFriendsRecord,
  emptyPendingRequestsRecord,
  upsertFriend,
  addOutboundPending,
  addInboundPending,
  removeOutboundPending,
  removeInboundPending,
  FRIENDS_CONTENT_ID,
  PENDING_REQUESTS_CONTENT_ID,
  INFO_FRIEND_REQUEST,
  INFO_FRIEND_ACCEPT,
  DEFAULT_POLL_WINDOWS,
} from './sharing.js';

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
  // register/login/changeCredentials/recoverAccount path so the friend
  // handshake methods can HPKE-Open inbox blobs without re-deriving from
  // master_key on every call. share_priv NEVER leaves the device.
  #email = null;                     // string — caller-supplied normalized email
  #sharingKeyPair = null;            // {privateKey: Uint8Array, publicKey: Uint8Array}
  #replayNonceCache = makeReplayNonceCache(); // §13.8 in-memory recent-nonce cache

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
    // new social-app user can be friended by email out of the box. Apps that
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
  async recoverAccount({ phrase, newEmail, newPassword }) {
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
    this.#jwt = null; // force re-auth under the new credentials
    await this.#authenticate();

    return { dataLookupKey: this.#dataLookupKey };
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
   * - The NEW gen (N+1) only gets a recovery wrapping if the caller passes
   *   `phrase`. Without it, the new gen has only a password wrapping, and
   *   recovery for that gen is not possible until the user runs
   *   `regenerateRecoveryKit` or `recoverAccount` to repair the gap.
   *
   * For PBKDF2 (KDF v1) accounts the rotation upgrade is intentionally not
   * applied — they stay on the legacy single-key envelope (issue #11 is
   * scoped to Argon2id accounts; legacy KDF migration is a separate concern).
   *
   * @param {string} newEmail
   * @param {string} newPassword
   * @param {{ phrase?: string }} [opts] - optional phrase to extend the
   *   recovery wrapping to gen N+1 (v4 accounts only)
   */
  async changeCredentials(newEmail, newPassword, opts = {}) {
    await this.#requireAuth();

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

    this.#credentialLookupKey = newKeys.credentialLookupKey;
    this.#credentialEncryptionKey = newKeys.credentialEncryptionKey;
    this.#signingKeyPair = newKeys.signingKeyPair;
    this.#dekByGen = newDekByGen;
    this.#currentGen = newCurrentGen;
    this.#envelopeVersion = newEnvelopeVersion;
    this.#recoveryFactorMeta = newRecoveryFactorMeta;
    this.#email = newEmail;
    this.#sharingKeyPair = newKeys.sharingKeyPair;

    await this.#authenticate();
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
   * client's app_id. Used by the friend-handshake bootstrap (Section 5 work)
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

  // ============ FRIEND HANDSHAKE (issue #14, Section 5a) ============

  /**
   * Send an HPKE-sealed friend request to the named recipient (sharing §6.2).
   *
   * Flow:
   *   1. Look up recipient's `share_pub` via `getRecipientShareKey`. If absent
   *      (pre-#13 account, or non-discoverable), fail with a recognizable
   *      error so the caller can surface "this person isn't friendable" UX.
   *   2. Build the request payload (sender_email, sender_share_pub,
   *      sender_signing_pub, sender_app_id, nonce, timestamp, optional message).
   *   3. HPKE_Seal to the recipient under info "tarn-friend-request-v1".
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
  async sendFriendRequest(recipientEmail, opts = {}) {
    await this.#requireAuth();
    if (!this.#sharingKeyPair) {
      throw new Error('sendFriendRequest(): no sharing keypair — login as a v4 account first');
    }
    if (!this.#email) {
      throw new Error('sendFriendRequest(): client missing sender email — re-login');
    }

    const { sharePub, sharePubBase64Url } = await this.getRecipientShareKey(recipientEmail);
    if (!sharePub) {
      // Three causes are indistinguishable to the caller (sharing §11.5): the
      // recipient doesn't exist, the recipient's account predates #13, or the
      // recipient has set discoverable=false. Surface a single-shape error
      // that callers can match on without knowing which one.
      const err = new Error('sendFriendRequest(): recipient is not friendable (no share_pub published, or discoverable=false)');
      err.code = 'RECIPIENT_NOT_FRIENDABLE';
      throw err;
    }

    const senderSigningPubBase64 = await exportPublicKey(this.#signingKeyPair.publicKey);
    const payload = buildFriendRequestPayload({
      senderEmail: this.#email,
      senderSharePub: this.#sharingKeyPair.publicKey,
      senderSigningPubBase64,
      senderAppId: this.#appId,
      message: opts.message,
    });

    const blob = await hpkeSeal({
      recipientSharePub: sharePub,
      info: INFO_FRIEND_REQUEST,
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
        type: 'friend-request-v1',
        ciphertext_base64: bytesToBase64(blob),
      },
    });
    if (publishRes.status !== 200) {
      throw new Error(`sendFriendRequest(): publish failed: ${publishRes.json?.error || publishRes.status}`);
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
   * Poll the inbox for incoming friend requests (sharing §6.3 + §13.8).
   *
   * Walks the recent N day-windows (default 30, per design), fetches all
   * blobs at each (recipient_inbox_tag, friend-request-v1) tuple, attempts
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
      tags.map(tag => this.#fetchInboxBlobs(tag, 'friend-request-v1')),
    );

    const surfaced = [];
    const pendingState = await this.#loadPendingRequestsRecord();
    let pendingRecord = pendingState.record;
    let pendingDirty = false;

    for (const blobs of fetched) {
      for (const blob of blobs) {
        let payload;
        try {
          const pt = await hpkeOpen({
            sharePriv: myPriv,
            info: INFO_FRIEND_REQUEST,
            blob: blob.ciphertext,
          });
          payload = JSON.parse(new TextDecoder().decode(pt));
        } catch {
          // Not for us, or tampered, or wrong info — silently skip (§6.3).
          continue;
        }
        const validation = validateFriendRequestPayload(payload, this.#appId);
        if (!validation.valid) continue;

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
        // (acceptFriendRequest uses this list to find the matching request).
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
    // per direction was overkill for v1). Returns surfaced friend-requests
    // only; processed accepts mutate the friends record + pending record
    // silently.
    await this.#pollAndProcessIncomingAccepts(myPriv, myPub);

    return surfaced;
  }

  /**
   * Accept a previously-received friend request (sharing §6.4).
   *
   * Looks up the inbound pending entry by `requestNonce`, builds an HPKE-
   * sealed accept blob targeted at the original sender's share_pub, and
   * publishes to the sender's inbox tag. On success, the sender is added to
   * our friends record and the inbound pending entry is removed. The sender
   * sees the accept on their next `listIncomingRequests` poll, which moves
   * the matching outbound pending into their friends record.
   *
   * @param {string} requestNonce - base64url nonce from the original request
   * @returns {Promise<{ txid: string }>}
   */
  async acceptFriendRequest(requestNonce) {
    await this.#requireAuth();
    if (!this.#sharingKeyPair) {
      throw new Error('acceptFriendRequest(): no sharing keypair — login as a v4 account first');
    }
    if (typeof requestNonce !== 'string' || requestNonce.length === 0) {
      throw new Error('requestNonce is required');
    }

    const pendingState = await this.#loadPendingRequestsRecord();
    const inbound = pendingState.record.inbound.find(i => i.request_nonce === requestNonce);
    if (!inbound) {
      throw new Error(`acceptFriendRequest(): no inbound pending request with nonce ${requestNonce}`);
    }

    let senderSharePub;
    try {
      senderSharePub = decodeSharePub(inbound.sender_share_pub);
    } catch (err) {
      throw new Error(`acceptFriendRequest(): inbound sender_share_pub is invalid: ${err.message}`);
    }

    const senderSigningPubBase64 = await exportPublicKey(this.#signingKeyPair.publicKey);
    const payload = buildFriendAcceptPayload({
      senderEmail: this.#email,
      senderSharePub: this.#sharingKeyPair.publicKey,
      senderSigningPubBase64,
      senderAppId: this.#appId,
      inReplyToNonceBase64Url: requestNonce,
    });

    const blob = await hpkeSeal({
      recipientSharePub: senderSharePub,
      info: INFO_FRIEND_ACCEPT,
      plaintext: new TextEncoder().encode(JSON.stringify(payload)),
    });

    const tag = await deriveInboxTag(senderSharePub, this.#appId, currentInboxWindow());
    const publishRes = await this.#fetch('/api/v1/share/inbox/publish', {
      method: 'POST',
      auth: true,
      body: {
        tag,
        type: 'friend-accept-v1',
        ciphertext_base64: bytesToBase64(blob),
      },
    });
    if (publishRes.status !== 200) {
      throw new Error(`acceptFriendRequest(): publish failed: ${publishRes.json?.error || publishRes.status}`);
    }

    // Move inbound → friends. Persist both updates as a (small) sequence:
    // friends record first (the durable record), then pending second. If the
    // pending update fails, the user has a duplicate inbound entry but the
    // friend was added — re-running accept idempotently fixes it (the
    // friends-record upsertFriend is keyed on share_pub).
    const friendsState = await this.#loadFriendsRecord();
    const friendsUpdated = upsertFriend(friendsState.record, {
      email: inbound.sender_email,
      share_pub: inbound.sender_share_pub,
      signing_pub: inbound.sender_signing_pub,
      established_at: payload.timestamp,
      initial_request_nonce: requestNonce,
    });
    await this.#saveFriendsRecord(friendsState, friendsUpdated);

    const pendingUpdated = removeInboundPending(pendingState.record, requestNonce);
    await this.#savePendingRequestsRecord(pendingState, pendingUpdated);

    return { txid: publishRes.json.txid };
  }

  /**
   * Read the friends record (sharing §7.1). Returns an empty list for users
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
  async listFriends() {
    await this.#requireAuth();
    const state = await this.#loadFriendsRecord();
    return state.record.friends.slice();
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
      tags.map(tag => this.#fetchInboxBlobs(tag, 'friend-accept-v1')),
    );

    let pendingState = await this.#loadPendingRequestsRecord();
    let friendsState = await this.#loadFriendsRecord();
    let pendingDirty = false;
    let friendsDirty = false;

    for (const blobs of fetched) {
      for (const blob of blobs) {
        let payload;
        try {
          const pt = await hpkeOpen({
            sharePriv: myPriv,
            info: INFO_FRIEND_ACCEPT,
            blob: blob.ciphertext,
          });
          payload = JSON.parse(new TextDecoder().decode(pt));
        } catch {
          continue;
        }
        const v = validateFriendAcceptPayload(payload, this.#appId);
        if (!v.valid) continue;

        // Forged-accept defense (§13.9): cross-reference against outbound
        // pending. Unmatched accepts are silently dropped — no friend record
        // entry created, no UI prompt. The user is not informed.
        const outbound = findOutboundForAccept(v.normalized.inReplyToNonceBase64Url, pendingState.record.outbound);
        if (!outbound) continue;

        // Replay protection on accepts: if we've already processed this
        // accept (it appears in friends already), skip without re-writing.
        const existingFriend = friendsState.record.friends.find(f => f.share_pub === v.normalized.senderSharePubBase64Url);
        if (existingFriend) {
          // Still clear the matched outbound — sender side already moved on.
          if (pendingState.record.outbound.some(o => o.request_nonce === outbound.request_nonce)) {
            pendingState = { ...pendingState, record: removeOutboundPending(pendingState.record, outbound.request_nonce) };
            pendingDirty = true;
          }
          continue;
        }

        friendsState = {
          ...friendsState,
          record: upsertFriend(friendsState.record, {
            email: v.normalized.senderEmail,
            share_pub: v.normalized.senderSharePubBase64Url,
            signing_pub: v.normalized.senderSigningPubBase64,
            established_at: v.normalized.timestamp,
            initial_request_nonce: outbound.request_nonce,
          }),
        };
        friendsDirty = true;

        pendingState = {
          ...pendingState,
          record: removeOutboundPending(pendingState.record, outbound.request_nonce),
        };
        pendingDirty = true;
      }
    }

    if (friendsDirty) await this.#saveFriendsRecord(friendsState, friendsState.record);
    if (pendingDirty) await this.#savePendingRequestsRecord(pendingState, pendingState.record);
  }

  /**
   * Load (or initialize) the friends record for the current app.
   * Returns `{ record, txid }` — `txid` is null if we're creating it for
   * the first time, or the prior version's txid if updating.
   */
  async #loadFriendsRecord() {
    const entry = await this.#findShareStateEntry(FRIENDS_CONTENT_ID);
    if (!entry) {
      return { record: emptyFriendsRecord(this.#appId), txid: null };
    }
    return { record: entry.data, txid: entry.txid };
  }

  async #saveFriendsRecord(state, newRecord) {
    return await this.#writeShareStateEntry(FRIENDS_CONTENT_ID, state, newRecord);
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
   * Find the latest (resolved) `tarn-share-state` entry for a given
   * content_id. Returns `{ txid, data }` or null if no entry exists yet.
   *
   * The friends + pending records use type='tarn-share-state' with
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
