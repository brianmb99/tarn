// passkey-reg.js — Arweave wire format for passkey-credential metadata.
//
// Phase B of the Arweave-recoverability fix plan
// (`docs/ARWEAVE_RECOVERABILITY_FIX_PLAN.md`). The `passkey_credentials`
// D1 table — added in migration 0018 / Phase 6 — is mirrored to Arweave
// as `Type=passkey-reg` blobs so that an operator-driven D1 rebuild
// (Phase C) can reconstruct every registered passkey's `prf_salt` and
// `public_key` from Arweave alone. Without this mirror, a D1 wipe would
// permanently strand passkey-only authentication for every user.
//
// Wire format
// ===========
//
//   Tags:
//     App   = tarn
//     Type  = passkey-reg
//     Lk    = <data_lookup_key>      (account scope; allows enumeration per account)
//     CredId= <base64url credential_id>
//     [Op   = tombstone]             (only on remove)
//     V     = <PROTOCOL_VERSION>
//
//   Body (registration, JSON):
//     {
//       "v": 1,
//       "data_lookup_key": "<account dlk>",
//       "credential_id": "<base64url>",
//       "public_key": "<base64url COSE public key — same encoding stored in D1>",
//       "prf_salt": "<base64url 32-byte salt>",
//       "device_label": "iPhone 16" | null,
//       "created_at": <unix-ms>
//     }
//
//   Body (tombstone, JSON):
//     { "v": 1, "tombstone": true, "credential_id": "<base64url>" }
//
// What is NOT persisted
// =====================
// - `sign_count`: WebAuthn replay counter. Runtime state — defaults to 0
//   on rebuild. The first post-rebuild auth produces a benign update
//   (the verifier short-circuits when both stored and new counter are 0,
//   the dominant case for OS-synced passkeys).
// - `last_used_at`: UX scaffold only. Resets to NULL on rebuild.
//
// Tombstone semantics
// ===================
// We tombstone by `CredId`-by-tag rather than by `tombstone_ref=<txid>`.
// The rebuild logic walks `App=tarn, Type=passkey-reg`, groups by
// `CredId`, and excludes any group whose latest blob carries
// `Op=tombstone`. This avoids a schema change to `passkey_credentials`
// (no need to track the original txid) and keeps tombstone discovery
// symmetric with the live blob — the same `(App, Type, CredId)` query
// finds both. The downside (a tombstone "tombstones the credential id
// across all gens" rather than a specific txid) is the desired
// behavior: a removed passkey should stay removed.
//
// Ordering choice (D1 first, then Arweave)
// ========================================
// Mirrors the existing pattern in `auth.js` / `passkeys.js` for the
// credential mapping blob: the D1 batch (insert credential row + update
// envelope, or delete credential row + update envelope) is the
// authoritative atomic step; Arweave publish runs in `ctx.waitUntil`.
// Failure mode: if the worker dies between D1 commit and Turbo upload,
// D1 has the row but Arweave doesn't. On a future D1-rebuild this
// credential would be missing — the user would need to re-register the
// passkey. Symmetric with the existing credential-blob pattern; the
// alternative (Arweave-first) would risk a published-but-unrecorded
// credential leaking into a rebuilt D1 with no matching envelope wrapping.

import { buildSignedDataItem, uploadSignedDataItem } from '../turbo.js';
import { upsertWriteThrough } from '../cache.js';
import { PROTOCOL_VERSION } from '../constants.js';
import { mirrorUploadWithTracking } from '../observability/mirror-failures.js';

/**
 * Build the Arweave tag set for a passkey-registration blob.
 *
 * @param {string} dataLookupKey - account scope (accounts.data_lookup_key)
 * @param {string} credentialId - base64url WebAuthn credential ID
 * @param {Object} [opts]
 * @param {boolean} [opts.tombstone=false] - if true, adds `Op=tombstone`
 * @returns {Array<{name: string, value: string}>}
 */
export function buildPasskeyRegTags(dataLookupKey, credentialId, opts = {}) {
  if (typeof dataLookupKey !== 'string' || dataLookupKey.length === 0) {
    throw new TypeError('buildPasskeyRegTags: dataLookupKey must be a non-empty string');
  }
  if (typeof credentialId !== 'string' || credentialId.length === 0) {
    throw new TypeError('buildPasskeyRegTags: credentialId must be a non-empty string');
  }
  const tags = [
    { name: 'App', value: 'tarn' },
    { name: 'Type', value: 'passkey-reg' },
    { name: 'Lk', value: dataLookupKey },
    { name: 'CredId', value: credentialId },
  ];
  if (opts.tombstone) {
    tags.push({ name: 'Op', value: 'tombstone' });
  }
  tags.push({ name: 'V', value: PROTOCOL_VERSION });
  return tags;
}

/**
 * Build the JSON body of a passkey-registration blob.
 *
 * @param {Object} fields
 * @param {string} fields.dataLookupKey
 * @param {string} fields.credentialId
 * @param {string} fields.publicKey - base64url COSE-encoded public key
 * @param {string} fields.prfSalt - base64url 32-byte salt
 * @param {string|null} [fields.deviceLabel]
 * @param {number} [fields.createdAt] - unix-ms; defaults to Date.now()
 * @returns {string} JSON string ready to upload as the DataItem payload
 */
export function buildPasskeyRegBlob({
  dataLookupKey,
  credentialId,
  publicKey,
  prfSalt,
  deviceLabel = null,
  createdAt = null,
}) {
  if (typeof dataLookupKey !== 'string' || dataLookupKey.length === 0) {
    throw new TypeError('buildPasskeyRegBlob: dataLookupKey is required');
  }
  if (typeof credentialId !== 'string' || credentialId.length === 0) {
    throw new TypeError('buildPasskeyRegBlob: credentialId is required');
  }
  if (typeof publicKey !== 'string' || publicKey.length === 0) {
    throw new TypeError('buildPasskeyRegBlob: publicKey is required');
  }
  if (typeof prfSalt !== 'string' || prfSalt.length === 0) {
    throw new TypeError('buildPasskeyRegBlob: prfSalt is required');
  }
  const blob = {
    v: 1,
    data_lookup_key: dataLookupKey,
    credential_id: credentialId,
    public_key: publicKey,
    prf_salt: prfSalt,
    device_label: deviceLabel == null ? null : String(deviceLabel),
    created_at: typeof createdAt === 'number' ? createdAt : Date.now(),
  };
  return JSON.stringify(blob);
}

/**
 * Build the JSON body of a passkey-registration tombstone.
 *
 * The body is intentionally minimal — the discriminating information
 * (which credential is being removed) is in the tags. Including
 * `credential_id` in the body too is a defense-in-depth hedge for any
 * future reader that ingests bodies before tags.
 */
export function buildPasskeyRegTombstoneBlob(credentialId) {
  if (typeof credentialId !== 'string' || credentialId.length === 0) {
    throw new TypeError('buildPasskeyRegTombstoneBlob: credentialId is required');
  }
  return JSON.stringify({ v: 1, tombstone: true, credential_id: credentialId });
}

/**
 * Publish a passkey-registration blob to Arweave (non-blocking).
 *
 * Runs entirely inside `ctx.waitUntil` so the calling request returns
 * immediately. D1 is the authoritative source of truth for live state;
 * Arweave is the recoverability mirror. Errors are logged, not raised
 * — the user-visible operation already completed in D1.
 *
 * @param {ExecutionContext} ctx
 * @param {Object} env
 * @param {Object} blobFields - fields for buildPasskeyRegBlob
 */
export function persistPasskeyRegBlob(ctx, env, blobFields) {
  const blobBody = buildPasskeyRegBlob(blobFields);
  const tags = buildPasskeyRegTags(blobFields.dataLookupKey, blobFields.credentialId);

  ctx.waitUntil((async () => {
    try {
      const signingKey = env.APP_SIGNING_KEY;
      if (!signingKey) {
        console.warn('[tarn-api] APP_SIGNING_KEY not set — skipping passkey-reg upload');
        return;
      }
      const blobBytes = new TextEncoder().encode(blobBody);
      const { signedDataItem, txid } = await buildSignedDataItem(blobBytes, tags, signingKey);
      // Cache write-through into D1's entries table so the row is
      // discoverable to local rebuild / read paths immediately. Phase C
      // (rebuild tool) reads from Arweave directly, but having the
      // cached row is consistent with how every other write site
      // behaves.
      await upsertWriteThrough(env.DB, txid, tags);
      console.log(`[tarn-api] passkey-reg cached: ${txid} (cred ${blobFields.credentialId.slice(0, 8)})`);
      const turbo = await mirrorUploadWithTracking({
        uploadFn: () => uploadSignedDataItem(signedDataItem),
        db: env.DB,
        namespace: 'passkey-reg',
        intendedTxid: txid,
        tags,
        signedDataItem,
      });
      if (turbo.ok) {
        console.log(`[tarn-api] passkey-reg uploaded to Turbo: ${txid}`);
      } else {
        console.warn(`[tarn-api] passkey-reg Turbo upload failed: ${turbo.status} ${turbo.body}`);
      }
    } catch (err) {
      console.error('[tarn-api] passkey-reg upload error:', err.message);
    }
  })());
}

/**
 * Publish a passkey-registration tombstone to Arweave (non-blocking).
 *
 * Tombstones by `CredId`-by-tag (not by `tombstone_ref=<txid>`) — see
 * the module header for rationale.
 */
export function persistPasskeyRegTombstone(ctx, env, dataLookupKey, credentialId) {
  const blobBody = buildPasskeyRegTombstoneBlob(credentialId);
  const tags = buildPasskeyRegTags(dataLookupKey, credentialId, { tombstone: true });

  ctx.waitUntil((async () => {
    try {
      const signingKey = env.APP_SIGNING_KEY;
      if (!signingKey) {
        console.warn('[tarn-api] APP_SIGNING_KEY not set — skipping passkey-reg tombstone upload');
        return;
      }
      const blobBytes = new TextEncoder().encode(blobBody);
      const { signedDataItem, txid } = await buildSignedDataItem(blobBytes, tags, signingKey);
      await upsertWriteThrough(env.DB, txid, tags);
      console.log(`[tarn-api] passkey-reg tombstone cached: ${txid} (cred ${credentialId.slice(0, 8)})`);
      const turbo = await mirrorUploadWithTracking({
        uploadFn: () => uploadSignedDataItem(signedDataItem),
        db: env.DB,
        namespace: 'passkey-reg-tombstone',
        intendedTxid: txid,
        tags,
        signedDataItem,
      });
      if (turbo.ok) {
        console.log(`[tarn-api] passkey-reg tombstone uploaded to Turbo: ${txid}`);
      } else {
        console.warn(`[tarn-api] passkey-reg tombstone Turbo upload failed: ${turbo.status} ${turbo.body}`);
      }
    } catch (err) {
      console.error('[tarn-api] passkey-reg tombstone upload error:', err.message);
    }
  })());
}
