#!/usr/bin/env node
/**
 * Register an app in Tarn using an existing app private key. Derives the
 * public key, publishes a Type=app-reg blob to Arweave, and prints the D1
 * seed SQL. Same Arweave-first ordering as generate-app-key.mjs.
 *
 * Usage:
 *   node tools/register-app-from-key.mjs <app_id> <private_key_hex> [options]
 *
 * Options:
 *   --signing-key <hex>   Operator's Tarn signing key (hex secp256k1).
 *                         Required unless --skip-arweave is set. May also
 *                         be supplied via the TARN_APP_SIGNING_KEY env var.
 *   --skip-arweave        Do NOT publish the app-reg blob (off-label;
 *                         leaves the apps row D1-only).
 *   --skip-turbo          Skip the Turbo HTTP upload (sign locally only).
 *
 * The private key is the per-app PKCS#8 hex (the same format
 * generate-app-key.mjs prints). The signing key is the OPERATOR's Arweave
 * wallet hex (same as APP_SIGNING_KEY) — distinct from the per-app key.
 *
 * Useful for:
 *   - Re-publishing a Type=app-reg blob for an existing app whose D1 row
 *     was created before this tool gained an Arweave publish step
 *     (republish-only flow — pass the existing app key + --signing-key,
 *     same SQL gets reprinted but D1 INSERT OR REPLACE is idempotent).
 *   - Bringing up a new environment with a known app key.
 */

import { buildSignedDataItem, uploadSignedDataItem } from '../api/src/turbo.js';
import { buildAppRegTags, buildAppRegBody } from '../api/src/app-reg.js';

// ============ Args ============

const argv = process.argv.slice(2);
const positional = [];
const flags = { signingKey: null, skipArweave: false, skipTurbo: false };

for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--signing-key') { flags.signingKey = argv[++i]; }
  else if (a === '--skip-arweave') { flags.skipArweave = true; }
  else if (a === '--skip-turbo') { flags.skipTurbo = true; }
  else if (a.startsWith('--')) { console.error(`Unknown flag: ${a}`); process.exit(1); }
  else { positional.push(a); }
}

const appId = positional[0];
const privateKeyHex = positional[1];

if (!appId || !privateKeyHex) {
  console.error('Usage: node tools/register-app-from-key.mjs <app_id> <private_key_hex> [--signing-key <hex>] [--skip-arweave] [--skip-turbo]');
  process.exit(1);
}

const signingKey = flags.signingKey || process.env.TARN_APP_SIGNING_KEY || null;
if (!flags.skipArweave && !signingKey) {
  console.error('Error: missing operator signing key.');
  console.error('  Pass --signing-key <hex> or set TARN_APP_SIGNING_KEY env var.');
  console.error('  (Same key as APP_SIGNING_KEY in api/.dev.vars / Worker secret.)');
  console.error('  To skip the Arweave publish entirely, pass --skip-arweave (NOT recommended).');
  process.exit(1);
}

// ============ Import private key, derive public key ============

const pkcs8Bytes = new Uint8Array(privateKeyHex.length / 2);
for (let i = 0; i < privateKeyHex.length; i += 2) {
  pkcs8Bytes[i / 2] = parseInt(privateKeyHex.substr(i, 2), 16);
}

const privateKey = await crypto.subtle.importKey(
  'pkcs8', pkcs8Bytes,
  { name: 'ECDSA', namedCurve: 'P-256' },
  true, ['sign']
);

// Derive public key via JWK round-trip
const jwk = await crypto.subtle.exportKey('jwk', privateKey);
delete jwk.d;
jwk.key_ops = ['verify'];
const publicKey = await crypto.subtle.importKey(
  'jwk', jwk,
  { name: 'ECDSA', namedCurve: 'P-256' },
  true, ['verify']
);

const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
const publicKeyBase64 = btoa(String.fromCharCode(...spki));

const testData = new TextEncoder().encode('test');
const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, testData);
const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, sig, testData);

console.log(`\nApp ID:     ${appId}`);
console.log(`Public Key: ${publicKeyBase64}`);
console.log(`Verify:     ${valid ? 'OK' : 'FAILED'}`);

if (!valid) {
  console.error('\nFATAL: keypair self-test failed; aborting.');
  process.exit(1);
}

// ============ Publish app-reg blob to Arweave ============

const createdAt = Date.now();
let arweaveTxid = null;

if (flags.skipArweave) {
  console.warn('\n[WARN] --skip-arweave set; NOT publishing Type=app-reg blob.');
} else {
  if (flags.skipTurbo) {
    globalThis.__TARN_SKIP_TURBO__ = true;
  }

  console.log(`\nPublishing Type=app-reg to Arweave...`);
  const tags = buildAppRegTags(appId);
  const body = buildAppRegBody({
    app_id: appId,
    public_key: publicKeyBase64,
    invite_url_template: null,
    created_at: createdAt,
  });
  const blobBytes = new TextEncoder().encode(body);

  let signed;
  try {
    signed = await buildSignedDataItem(blobBytes, tags, signingKey);
  } catch (err) {
    console.error(`FATAL: failed to sign app-reg DataItem: ${err.message}`);
    process.exit(1);
  }
  arweaveTxid = signed.txid;
  console.log(`  txid: ${arweaveTxid}`);

  const upload = await uploadSignedDataItem(signed.signedDataItem);
  if (!upload.ok) {
    console.error(`FATAL: Turbo upload failed (status ${upload.status}): ${upload.body}`);
    console.error('  The app row has NOT been published. D1 SQL has NOT been printed.');
    console.error('  Resolve the upload error and re-run the tool — re-running is safe.');
    process.exit(1);
  }
  console.log(`  Turbo:  ${upload.turboTxid || 'OK'}`);
}

// ============ Print D1 seed SQL ============

const sql = `INSERT OR REPLACE INTO apps (app_id, public_key, created_at) VALUES ('${appId}', '${publicKeyBase64}', ${createdAt})`;

console.log(`\nD1 command (run this):`);
console.log(`  cd api && npx wrangler d1 execute tarn-api --remote --command "${sql}"\n`);

if (arweaveTxid) {
  console.log(`Arweave txid (Type=app-reg, Lk=${appId}): ${arweaveTxid}`);
}
