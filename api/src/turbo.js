// turbo.js — Arweave upload via Turbo bundling service
// Constructs and signs ANS-104 DataItems server-side using the app's wallet.
// Uses "sign-first, upload-in-background" pattern: the DataItem ID is computed
// locally from the signature, so D1 cache can be populated immediately.

import { createSignedDataItem, computeDataItemId } from './ans104.js';

const TURBO_UPLOAD_URL = 'https://upload.ardrive.io/v1/tx';
export const TURBO_GATEWAY = 'https://turbo-gateway.com';

/**
 * Build and sign a DataItem, compute its ID locally, and return it.
 * Does NOT upload to Turbo — caller decides whether to upload synchronously
 * or in background.
 *
 * @param {Uint8Array|ArrayBuffer} payload - Raw payload bytes
 * @param {Array<{name: string, value: string}>} tags - Arweave tags
 * @param {string} signingKey - App wallet private key (hex)
 * @returns {Promise<{signedDataItem: Uint8Array, txid: string}>}
 */
export async function buildSignedDataItem(payload, tags, signingKey) {
  const data = payload instanceof Uint8Array ? payload : new Uint8Array(payload);

  // Add Content-Type tag if not present (required by ANS-104)
  const allTags = [...tags];
  if (!allTags.some(t => (t.name || '').toLowerCase() === 'content-type')) {
    allTags.unshift({ name: 'Content-Type', value: 'application/octet-stream' });
  }

  const signedDataItem = await createSignedDataItem(signingKey, data, allTags);
  const txid = await computeDataItemId(signedDataItem);

  return { signedDataItem, txid };
}

/**
 * Upload a pre-built signed DataItem to Turbo.
 * @param {Uint8Array} signedDataItem
 * @returns {Promise<{ok: boolean, turboTxid?: string, status?: number, body?: string}>}
 */
export async function uploadSignedDataItem(signedDataItem) {
  try {
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
    return { ok: true, turboTxid: result.id || result.dataItemId };
  } catch (err) {
    return { ok: false, status: 0, body: err.message };
  }
}
