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
  exportPublicKey,
  wrapDataKeyEnvelope,
  wrapDataKeyChainEnvelope,
  unwrapDataKeyChain,
  signChallenge,
  encrypt,
  decrypt,
  encryptWithCEK,
  decryptWithCEK,
  hasTarnBlobMagic,
  generateRandomDataKey,
  base64ToBytes,
  KDF_V1_PBKDF2,
  KDF_V2_ARGON2ID,
  KDF_DEFAULT,
} from './crypto.js';

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
  #envelopeVersion = null;   // 1 (bare base64), 2 (single), 3 (chain)

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
   * Register a new account for this app.
   *
   * Generates a fresh random 32-byte DEK at generation 1 (issue #11) — no
   * more self-wrapping. The DEK is wrapped under the credential_encryption_key
   * via AES-KW and packaged into a v3 envelope (`{v:3, dek_chain: [...]}`).
   * The envelope is opaque to the API (passes the existing length/type check).
   *
   * @param {string} email
   * @param {string} password
   * @returns {Promise<{dataLookupKey: string}>}
   */
  async register(email, password) {
    // New accounts always use the current default KDF (Argon2id v2). Existing
    // PBKDF2 accounts continue working via the login fallback path.
    const kdfVersion = KDF_DEFAULT;
    const keys = await deriveAllKeys(email, password, this.#appId, kdfVersion);
    const publicKeyBase64 = await exportPublicKey(keys.signingKeyPair.publicKey);

    // Random DEK at generation 1. Wrap under credential_encryption_key.
    const dek = await generateRandomDataKey();
    const wrappedDataKey = await wrapDataKeyChainEnvelope(
      [{ gen: 1, key: dek.gcmKey }],
      keys.credentialEncryptionKey.kwKey,
    );

    const res = await this.#fetch('/api/v1/auth/register', {
      method: 'POST',
      retry: true, // idempotent since tarn #6
      body: {
        credential_lookup_key: keys.credentialLookupKey,
        public_key: publicKeyBase64,
        wrapped_data_key: wrappedDataKey,
        app: this.#appId,
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
    this.#envelopeVersion = 3;
    this.#kdfVersion = kdfVersion;

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
   * credential_encryption_key) so prior data is still readable. Future
   * writes use the new gen, so an attacker who later compromises the OLD
   * credentials cannot decrypt data encrypted under gen N+1.
   *
   * For PBKDF2 (KDF v1) accounts the rotation upgrade is intentionally not
   * applied — they stay on the legacy single-key envelope (issue #11 is
   * scoped to Argon2id accounts; legacy KDF migration is a separate concern).
   *
   * @param {string} newEmail
   * @param {string} newPassword
   */
  async changeCredentials(newEmail, newPassword) {
    await this.#requireAuth();

    // Preserve the original KDF — silent upgrade from PBKDF2 to Argon2id is
    // out of scope for this issue (would be a separate migration concern).
    const kdfVersion = this.#kdfVersion ?? KDF_DEFAULT;
    const newKeys = await deriveAllKeys(newEmail, newPassword, this.#appId, kdfVersion);
    const newPublicKey = await exportPublicKey(newKeys.signingKeyPair.publicKey);

    let newWrappedDataKey;
    let newDekByGen;
    let newCurrentGen;
    let newEnvelopeVersion;

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
    } else {
      // Argon2id path — append a new DEK at gen N+1 and re-wrap the whole
      // chain under the new credential_encryption_key. v2 envelopes (single
      // self-wrapped DEK, pre-issue-#11) are upgraded in place to v3 here:
      // the existing DEK becomes gen 1, the fresh random DEK becomes gen 2.
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

    await this.#authenticate();
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

    if (this.#envelopeVersion === 3) {
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
