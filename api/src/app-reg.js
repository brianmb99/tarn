// app-reg.js — Wire format for `Type=app-reg` Arweave blobs.
//
// Closes the apps-table recoverability gap: every app registration and
// invite-template update is mirrored to Arweave so the operator can
// reconstruct the `apps` D1 table from gateway-only state.
//
// Tags:
//   App  = 'tarn'
//   Type = 'app-reg'
//   Lk   = <app_id>           — primary lookup; allows direct discovery
//                                 by app id and `App=tarn,Type=app-reg`
//                                 enumerates every registered app.
//   V    = <PROTOCOL_VERSION> — for forward-compat readers
//
// Body (JSON, UTF-8):
//   {
//     v: 1,                            — schema version (bump on incompatible change)
//     app_id: <string>,
//     public_key: <base64 SPKI>,       — ECDSA P-256 verifier for app-role JWTs
//     invite_url_template: <string|null>,
//     created_at: <unix-ms>            — operator-set wall-clock at registration
//   }
//
// Update behaviour: a fresh blob is published on each update (e.g. invite-
// template edit). Rebuild logic uses the most recent blob per `app_id`. No
// tombstones in v1 — app de-registration is future work; if needed, mirror
// the existing `Op=tombstone, Ref=<txid>` pattern used for credential blobs.

import { PROTOCOL_VERSION } from './constants.js';

export const APP_REG_BLOB_VERSION = 1;

/**
 * Build the Arweave tag set for an `app-reg` blob.
 *
 * @param {string} appId
 * @returns {Array<{name: string, value: string}>}
 */
export function buildAppRegTags(appId) {
  if (!appId || typeof appId !== 'string') {
    throw new Error('buildAppRegTags: app_id must be a non-empty string');
  }
  return [
    { name: 'App', value: 'tarn' },
    { name: 'Type', value: 'app-reg' },
    { name: 'Lk', value: appId },
    { name: 'V', value: PROTOCOL_VERSION },
  ];
}

/**
 * Build the JSON body for an `app-reg` blob.
 *
 * @param {Object} fields
 * @param {string} fields.app_id
 * @param {string} fields.public_key — base64 SPKI
 * @param {string|null} [fields.invite_url_template]
 * @param {number} [fields.created_at] — unix-ms; defaults to Date.now()
 * @returns {string} JSON-encoded body
 */
export function buildAppRegBody({ app_id, public_key, invite_url_template, created_at }) {
  if (!app_id || typeof app_id !== 'string') {
    throw new Error('buildAppRegBody: app_id must be a non-empty string');
  }
  if (!public_key || typeof public_key !== 'string') {
    throw new Error('buildAppRegBody: public_key must be a non-empty string');
  }
  if (invite_url_template != null && typeof invite_url_template !== 'string') {
    throw new Error('buildAppRegBody: invite_url_template must be a string or null/undefined');
  }
  const body = {
    v: APP_REG_BLOB_VERSION,
    app_id,
    public_key,
    invite_url_template: invite_url_template ?? null,
    created_at: Number.isFinite(created_at) ? created_at : Date.now(),
  };
  return JSON.stringify(body);
}
