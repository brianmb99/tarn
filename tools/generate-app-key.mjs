#!/usr/bin/env node
/**
 * Generate an ECDSA P-256 key pair for a Tarn app identity AND publish a
 * Type=app-reg blob to Arweave so the app row is rebuildable from
 * gateway-only state (closes the apps-table recoverability gap — see
 * docs/ARWEAVE_RECOVERABILITY_FIX_PLAN.md).
 *
 * Usage:
 *   node tools/generate-app-key.mjs <app_id> [options]
 *
 * Options:
 *   --signing-key <hex>   Operator's Tarn signing key (hex secp256k1).
 *                         Required unless --skip-arweave is set. May also
 *                         be supplied via the TARN_APP_SIGNING_KEY env var
 *                         (matches APP_SIGNING_KEY in api/.dev.vars).
 *   --skip-arweave        Do NOT publish the app-reg blob. Off-label;
 *                         leaves the apps row D1-only, recreating the
 *                         exact gap this tool exists to close. Use ONLY
 *                         for emergency operator-side workflows when the
 *                         operator wallet is unavailable.
 *   --skip-turbo          Skip the Turbo HTTP upload (sign locally only).
 *                         For local-dev environments where the operator
 *                         wallet has no Turbo balance.
 *
 * Outputs:
 *   - Private key (hex)        — save securely; used with set-rules.mjs / publish-schema.mjs.
 *   - Public key (base64 SPKI) — goes into the apps table.
 *   - Arweave txid             — the app-reg DataItem id (also derivable from gateway).
 *   - SQL to seed D1           — printed AFTER the Arweave publish succeeds.
 *
 * Ordering rationale (Arweave-first, D1-second): Arweave is the source of
 * truth for any Phase C rebuild. We publish first; only after the publish
 * succeeds do we print the D1 SQL. If the operator runs the SQL but the
 * publish failed, we'd recreate the recoverability gap — so we abort the
 * tool before printing SQL on Arweave failure. Re-running the tool on the
 * same app_id republishes a fresh blob (latest wins on rebuild) — safe.
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
if (!appId) {
  console.error('Usage: node tools/generate-app-key.mjs <app_id> [--signing-key <hex>] [--skip-arweave] [--skip-turbo]');
  console.error('Example: node tools/generate-app-key.mjs my-app --signing-key 2ea9...');
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

// ============ Generate keypair ============

const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true, // extractable
  ['sign', 'verify']
);

const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
const privateKeyHex = Array.from(pkcs8).map(b => b.toString(16).padStart(2, '0')).join('');

const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
const publicKeyBase64 = btoa(String.fromCharCode(...spki));

const testData = new TextEncoder().encode('test');
const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, testData);
const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.publicKey, sig, testData);

console.log(`\n=== Tarn App Key Pair: ${appId} ===\n`);
console.log(`App ID:      ${appId}`);
console.log(`Public Key:  ${publicKeyBase64}`);
console.log(`Private Key: ${privateKeyHex}`);
console.log(`Verify:      ${valid ? 'OK' : 'FAILED'}`);

if (!valid) {
  console.error('\nFATAL: keypair self-test failed; aborting.');
  process.exit(1);
}

console.log(`\n--- Save the private key securely. It is NOT stored by this script. ---`);

// ============ Publish app-reg blob to Arweave ============

const createdAt = Date.now();
let arweaveTxid = null;

if (flags.skipArweave) {
  console.warn('\n[WARN] --skip-arweave set; NOT publishing Type=app-reg blob.');
  console.warn('       The apps row will be D1-only — exactly the recoverability gap');
  console.warn('       this tool exists to close. Re-run without --skip-arweave when');
  console.warn('       the operator wallet is available.');
} else {
  if (flags.skipTurbo) {
    globalThis.__TARN_SKIP_TURBO__ = true;
  }

  console.log(`\n=== Publishing Type=app-reg to Arweave ===\n`);
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
  console.log(`  app-reg published.\n`);
}

// ============ Print D1 seed SQL ============

console.log(`=== D1 Seed Commands ===\n`);

const sql = `INSERT OR REPLACE INTO apps (app_id, public_key, created_at) VALUES ('${appId}', '${publicKeyBase64}', ${createdAt})`;

console.log(`Local dev:`);
console.log(`  cd api && npx wrangler d1 execute tarn-api --local --command "${sql}"\n`);

console.log(`Production:`);
console.log(`  cd api && npx wrangler d1 execute tarn-api --remote --command "${sql}"\n`);

console.log(`=== Environment Variable ===\n`);
console.log(`Add to .dev.vars (local) or wrangler secret (production):`);
console.log(`  TARN_APP_KEY_${appId.toUpperCase().replace(/-/g, '_')}=${privateKeyHex}\n`);

if (arweaveTxid) {
  console.log(`Arweave txid (Type=app-reg, Lk=${appId}): ${arweaveTxid}`);
}
