#!/usr/bin/env node
/**
 * Register an app in Tarn D1 using an existing private key.
 * Derives the public key from the private key and prints the D1 seed SQL.
 *
 * Usage:
 *   node tools/register-app-from-key.mjs <app_id> <private_key_hex>
 */

const appId = process.argv[2];
const privateKeyHex = process.argv[3];

if (!appId || !privateKeyHex) {
  console.error('Usage: node tools/register-app-from-key.mjs <app_id> <private_key_hex>');
  process.exit(1);
}

// Import private key from hex
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

// Export public key as SPKI -> base64
const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
const publicKeyBase64 = btoa(String.fromCharCode(...spki));

// Verify round-trip
const testData = new TextEncoder().encode('test');
const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, testData);
const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, sig, testData);

console.log(`\nApp ID:     ${appId}`);
console.log(`Public Key: ${publicKeyBase64}`);
console.log(`Verify:     ${valid ? 'OK' : 'FAILED'}`);

const sql = `INSERT OR REPLACE INTO apps (app_id, public_key, created_at) VALUES ('${appId}', '${publicKeyBase64}', ${Date.now()})`;

console.log(`\nD1 command (run this):`);
console.log(`  cd api && npx wrangler d1 execute tarn-api-cache --remote --command "${sql}"\n`);
