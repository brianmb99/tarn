// turbo.js — Arweave upload via Turbo bundling service
// Constructs and signs ANS-104 DataItems server-side using the app's wallet,
// then forwards to Turbo for Arweave bundling.

import { createSignedDataItem } from './ans104.js';

const TURBO_UPLOAD_URL = 'https://upload.ardrive.io/v1/tx';
export const TURBO_GATEWAY = 'https://turbo-gateway.com';

/**
 * Build a signed DataItem from raw payload + tags, then upload to Turbo.
 * The DataItem is signed with the app's Ethereum-compatible wallet.
 *
 * @param {Uint8Array|ArrayBuffer} payload - Raw payload bytes (encrypted data or JSON)
 * @param {Array<{name: string, value: string}>} tags - Arweave tags
 * @param {string} signingKey - App wallet private key (hex)
 * @returns {Promise<{ok: boolean, txid?: string, result?: Object, status?: number, body?: string}>}
 */
export async function uploadToArweave(payload, tags, signingKey) {
  // Ensure payload is Uint8Array
  const data = payload instanceof Uint8Array ? payload : new Uint8Array(payload);

  // Add Content-Type tag if not present (required by ANS-104)
  const allTags = [...tags];
  if (!allTags.some(t => (t.name || '').toLowerCase() === 'content-type')) {
    allTags.unshift({ name: 'Content-Type', value: 'application/octet-stream' });
  }

  // Construct and sign the ANS-104 DataItem
  const signedDataItem = await createSignedDataItem(signingKey, data, allTags);

  // Forward to Turbo
  const res = await fetch(TURBO_UPLOAD_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: signedDataItem,
    signal: AbortSignal.timeout(30000),
  });

  const text = await res.text();
  if (!res.ok) {
    return { ok: false, status: res.status, body: text.slice(0, 500) };
  }

  let result;
  try { result = JSON.parse(text); } catch { result = { raw: text }; }
  return { ok: true, result, txid: result.id || result.dataItemId };
}

/**
 * Legacy: forward pre-signed DataItem bytes directly to Turbo.
 * Used when the client has already signed the DataItem (backward compat).
 * @param {ArrayBuffer|Uint8Array} signedBytes - Pre-signed ANS-104 DataItem
 * @returns {Promise<{ok: boolean, txid?: string, result?: Object, status?: number, body?: string}>}
 */
export async function forwardToTurbo(signedBytes) {
  const res = await fetch(TURBO_UPLOAD_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: signedBytes,
    signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();
  if (!res.ok) {
    return { ok: false, status: res.status, body: text.slice(0, 500) };
  }
  let result;
  try { result = JSON.parse(text); } catch { result = { raw: text }; }
  return { ok: true, result, txid: result.id || result.dataItemId };
}
