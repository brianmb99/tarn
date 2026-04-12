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
  wrapDataKey,
  unwrapDataKey,
  signChallenge,
  encrypt,
  decrypt,
  base64ToBytes,
} from './crypto.js';

export class TarnClient {
  #apiBase;
  #appId;
  #jwt = null;
  #dataLookupKey = null;
  #dataEncryptionKey = null;
  #credentialLookupKey = null;
  #credentialEncryptionKey = null;
  #signingKeyPair = null;

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
   * @param {string} email
   * @param {string} password
   * @returns {Promise<{dataLookupKey: string}>}
   */
  async register(email, password) {
    const keys = await deriveAllKeys(email, password, this.#appId);
    const publicKeyBase64 = await exportPublicKey(keys.signingKeyPair.publicKey);
    const wrappedDataKey = await wrapDataKey(keys.credentialEncryptionKey.gcmKey, keys.credentialEncryptionKey.kwKey);

    const res = await this.#fetch('/api/v1/auth/register', {
      method: 'POST',
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
    this.#dataEncryptionKey = keys.credentialEncryptionKey.gcmKey; // AES-GCM for data

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
    const keys = await deriveAllKeys(email, password, this.#appId);

    this.#credentialLookupKey = keys.credentialLookupKey;
    this.#credentialEncryptionKey = keys.credentialEncryptionKey;
    this.#signingKeyPair = keys.signingKeyPair;

    // Challenge
    const challengeRes = await this.#fetch('/api/v1/auth/challenge', {
      method: 'POST',
      body: { credential_lookup_key: keys.credentialLookupKey },
    });

    if (challengeRes.status === 404) {
      throw new Error('Account not found');
    }
    if (challengeRes.status !== 200) {
      throw new Error(`Challenge failed: ${challengeRes.json?.error || challengeRes.status}`);
    }

    this.#dataLookupKey = challengeRes.json.data_lookup_key;

    // Unwrap data encryption key (AES-KW)
    this.#dataEncryptionKey = await unwrapDataKey(
      challengeRes.json.wrapped_data_key,
      keys.credentialEncryptionKey.kwKey
    );

    // Verify
    await this.#verifyChallenge(challengeRes.json.nonce);

    return { dataLookupKey: this.#dataLookupKey };
  }

  /**
   * Change credentials (email and/or password).
   * Requires an active session.
   * @param {string} newEmail
   * @param {string} newPassword
   */
  async changeCredentials(newEmail, newPassword) {
    await this.#requireAuth();

    const newKeys = await deriveAllKeys(newEmail, newPassword, this.#appId);
    const newPublicKey = await exportPublicKey(newKeys.signingKeyPair.publicKey);
    const newWrappedDataKey = await wrapDataKey(this.#dataEncryptionKey, newKeys.credentialEncryptionKey.kwKey);

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
    this.#dataEncryptionKey = null;
    this.#credentialLookupKey = null;
    this.#credentialEncryptionKey = null;
    this.#signingKeyPair = null;
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

    const encrypted = await encrypt(this.#dataEncryptionKey, plaintext);
    const tags = [
      { name: 'App', value: this.#appId },
      { name: 'Type', value: type },
      { name: 'Lk', value: this.#dataLookupKey },
      { name: 'Enc', value: 'aes-256-gcm' },
      { name: 'V', value: '0.4.0' },
      ...extraTags,
    ];

    const res = await this.#fetchRaw('/api/v1/entries', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.#jwt}`,
        'X-Arweave-Tags': JSON.stringify(tags),
        'Content-Type': 'application/octet-stream',
      },
      body: encrypted,
    });

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
      const encrypted = await encrypt(this.#dataEncryptionKey, item);
      const tags = [
        { name: 'App', value: this.#appId },
        { name: 'Type', value: type },
        { name: 'Lk', value: this.#dataLookupKey },
        { name: 'Enc', value: 'aes-256-gcm' },
        { name: 'V', value: '0.4.0' },
      ];
      // Base64-encode the encrypted bytes for JSON transport
      const data = btoa(String.fromCharCode(...encrypted));
      entries.push({ data, tags });
    }

    const res = await this.#fetch('/api/v1/entries/batch', {
      method: 'POST',
      auth: true,
      body: { entries },
    });

    if (res.status !== 200) {
      throw new Error(`Batch create failed: ${res.json?.error || res.status}`);
    }

    return res.json.entries;
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
          const data = await decrypt(this.#dataEncryptionKey, blobBytes);
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
          const data = await decrypt(this.#dataEncryptionKey, blobBytes);
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

    const encrypted = await encrypt(this.#dataEncryptionKey, plaintext);
    const tags = [
      { name: 'App', value: this.#appId },
      { name: 'Type', value: type },
      { name: 'Lk', value: this.#dataLookupKey },
      { name: 'Prev', value: priorTxid },
      { name: 'Enc', value: 'aes-256-gcm' },
      { name: 'V', value: '0.4.0' },
    ];

    const res = await this.#fetchRaw(`/api/v1/entries/${priorTxid}`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${this.#jwt}`,
        'X-Arweave-Tags': JSON.stringify(tags),
        'Content-Type': 'application/octet-stream',
      },
      body: encrypted,
    });

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

    const encrypted = await encrypt(this.#dataEncryptionKey, { tombstone: true, ref: targetTxid });
    const tags = [
      { name: 'App', value: this.#appId },
      { name: 'Type', value: type },
      { name: 'Lk', value: this.#dataLookupKey },
      { name: 'Op', value: 'tombstone' },
      { name: 'Ref', value: targetTxid },
      { name: 'Enc', value: 'aes-256-gcm' },
      { name: 'V', value: '0.4.0' },
    ];

    const res = await this.#fetchRaw(`/api/v1/entries/${targetTxid}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${this.#jwt}`,
        'X-Arweave-Tags': JSON.stringify(tags),
        'Content-Type': 'application/octet-stream',
      },
      body: encrypted,
    });

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

  // ============ PRIVATE ============

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

  async #fetch(path, { method = 'GET', body = null, auth = false } = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (auth && this.#jwt) headers['Authorization'] = `Bearer ${this.#jwt}`;

    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(`${this.#apiBase}${path}`, opts);
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch { json = null; }
    return { status: res.status, json, text };
  }

  async #fetchRaw(path, opts) {
    return await fetch(`${this.#apiBase}${path}`, opts);
  }
}
