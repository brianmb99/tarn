// turbo.js — Arweave upload via Turbo bundling service
// Shared between auth routes (credential blobs) and write routes (data entries).

const TURBO_UPLOAD_SIGNED_URL = 'https://upload.ardrive.io/v1/tx';
export const TURBO_GATEWAY = 'https://turbo-gateway.com';

/**
 * Forward a signed DataItem to Turbo for Arweave bundling.
 * @param {ArrayBuffer|Uint8Array} body - Signed ANS-104 DataItem bytes
 * @returns {Promise<{ok: boolean, txid?: string, result?: Object, status?: number, body?: string}>}
 */
export async function forwardToTurbo(body) {
  const res = await fetch(TURBO_UPLOAD_SIGNED_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body,
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
