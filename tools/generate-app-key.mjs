#!/usr/bin/env node
/**
 * Generate an ECDSA P-256 key pair for a Tarn app identity.
 *
 * Usage:
 *   node tools/generate-app-key.mjs <app_id>
 *
 * Outputs:
 *   - Private key (hex) — save this securely, use it with set-rules.mjs
 *   - Public key (base64 SPKI) — this goes into the apps table
 *   - SQL to seed the app into D1
 *   - wrangler command to apply it
 *
 * The private key is NOT stored anywhere by this script. Print it once, save it yourself.
 */

const appId = process.argv[2];
if (!appId) {
  console.error('Usage: node tools/generate-app-key.mjs <app_id>');
  console.error('Example: node tools/generate-app-key.mjs bookish');
  process.exit(1);
}

// Generate key pair
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true, // extractable
  ['sign', 'verify']
);

// Export private key as PKCS#8 DER -> hex
const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
const privateKeyHex = Array.from(pkcs8).map(b => b.toString(16).padStart(2, '0')).join('');

// Export public key as SPKI -> base64
const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
const publicKeyBase64 = btoa(String.fromCharCode(...spki));

// Verify round-trip: sign + verify
const testData = new TextEncoder().encode('test');
const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, testData);
const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.publicKey, sig, testData);

console.log(`\n=== Tarn App Key Pair: ${appId} ===\n`);
console.log(`App ID:      ${appId}`);
console.log(`Public Key:  ${publicKeyBase64}`);
console.log(`Private Key: ${privateKeyHex}`);
console.log(`Verify:      ${valid ? 'OK' : 'FAILED'}`);

console.log(`\n--- Save the private key securely. It is NOT stored by this script. ---\n`);

console.log(`=== D1 Seed Commands ===\n`);

const sql = `INSERT OR REPLACE INTO apps (app_id, public_key, created_at) VALUES ('${appId}', '${publicKeyBase64}', ${Date.now()})`;

console.log(`Local dev:`);
console.log(`  cd api && npx wrangler d1 execute bookish-api-cache --local --command "${sql}"\n`);

console.log(`Production:`);
console.log(`  cd api && npx wrangler d1 execute bookish-api-cache --remote --command "${sql}"\n`);

console.log(`=== Environment Variable ===\n`);
console.log(`Add to .dev.vars (local) or wrangler secret (production):`);
console.log(`  TARN_APP_KEY_${appId.toUpperCase().replace(/-/g, '_')}=${privateKeyHex}\n`);
