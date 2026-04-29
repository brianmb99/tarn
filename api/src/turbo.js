// turbo.js — Arweave upload via Turbo bundling service
// Constructs and signs ANS-104 DataItems server-side using the app's wallet.
// Uses "sign-first, upload-in-background" pattern: the DataItem ID is computed
// locally from the signature, so D1 cache can be populated immediately.

import { createSignedDataItem, computeDataItemId } from './ans104.js';

// Ethereum-signed DataItems must use the /ethereum token endpoint
const TURBO_UPLOAD_URL = 'https://upload.ardrive.io/v1/tx/ethereum';
export const TURBO_GATEWAY = 'https://turbo-gateway.com';

// Production hostnames where TARN_SKIP_TURBO must NEVER be honored, even if
// accidentally set as a Worker secret. Defense-in-depth on the local-dev
// escape hatch — if `wrangler secret put TARN_SKIP_TURBO` is ever run against
// production, we refuse the flag and log loudly so ops monitoring catches it.
const TARN_SKIP_TURBO_PRODUCTION_HOSTS = new Set([
  'api.tarn.dev',
  'api.getbookish.app',
]);

/**
 * Wire the `TARN_SKIP_TURBO` Worker env var into a process-global flag so
 * `uploadSignedDataItem` (called from many call sites) can consult it
 * without each site having to thread `env` through its signature. Called
 * once per request from `worker.js`.
 *
 * Defense-in-depth: if `TARN_SKIP_TURBO` is truthy AND the request hostname
 * is a known production host, we refuse to honor the flag and log a critical
 * error. This prevents a misconfigured production deploy from silently
 * skipping Arweave uploads.
 */
export function setSkipTurboFromEnv(env, request) {
  const skipRequested = !!(env && env.TARN_SKIP_TURBO);
  if (!skipRequested) {
    globalThis.__TARN_SKIP_TURBO__ = false;
    return;
  }

  if (request) {
    let hostname;
    try {
      hostname = new URL(request.url).hostname;
    } catch {
      hostname = null;
    }
    if (hostname && TARN_SKIP_TURBO_PRODUCTION_HOSTS.has(hostname)) {
      console.error(
        `[TARN CRITICAL] TARN_SKIP_TURBO=true detected on production host ${hostname}. ` +
        `REFUSING to skip Turbo uploads. Remove this Worker secret immediately ` +
        `(\`npx wrangler secret delete TARN_SKIP_TURBO --name tarn-api\`). ` +
        `If you see this in logs, writes have been bypassing Arweave on this host.`
      );
      globalThis.__TARN_SKIP_TURBO__ = false;
      return;
    }
  }

  // Local-dev path. Log noisily so any unexpected appearance in logs gets
  // noticed — this flag should ONLY be set in api/.dev.vars.
  console.warn('[TARN] TARN_SKIP_TURBO=true is active. Turbo uploads will be skipped (local-dev only).');
  globalThis.__TARN_SKIP_TURBO__ = true;
}

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
 *
 * Local-dev escape hatch: if `env.TARN_SKIP_TURBO` is truthy (set in
 * `api/.dev.vars`), the upload is short-circuited to `{ ok: true }`. This
 * lets integration tests run when the dev wallet has no Turbo balance
 * (Turbo returns 403, breaking every write path). The flag is read from a
 * Worker-scoped global because this function is called from many sites
 * without `env` in scope; the worker's startup wires it up via
 * `setSkipTurboFromEnv(env)`.
 *
 * @param {Uint8Array} signedDataItem
 * @returns {Promise<{ok: boolean, turboTxid?: string, status?: number, body?: string}>}
 */
export async function uploadSignedDataItem(signedDataItem) {
  if (globalThis.__TARN_SKIP_TURBO__) {
    return { ok: true, turboTxid: 'skipped-local-dev' };
  }
  try {
    // 20s ceiling (not 30s): Cloudflare Workers have a 30s wall-time limit on
    // the initial response. A 30s Turbo timeout would consume the entire budget
    // and leave no room for us to return an error response with CORS headers —
    // the CF edge would return a headerless 503 instead, which the browser
    // surfaces as a CORS error.
    const res = await fetch(TURBO_UPLOAD_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: signedDataItem,
      signal: AbortSignal.timeout(20000),
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
