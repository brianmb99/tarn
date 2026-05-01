#!/usr/bin/env node
/**
 * Publish an app schema to Arweave via Tarn.
 *
 * Authenticates as the app identity (using the same PKCS#8 hex private key
 * that set-rules.mjs and register-app-from-key.mjs use), then calls
 * `PUT /api/v1/apps/{app_id}/schema` with the schema JSON.
 *
 * Usage:
 *   node tools/publish-schema.mjs \
 *     --api  <url>            \
 *     --app  <app_id>         \
 *     --key  <pkcs8_hex_priv> \
 *     --schema <path-to-schema.json | path-to-schema.mjs>
 *
 * The --schema arg can point to either:
 *   - a .json file containing the serialized schema, OR
 *   - a .mjs file with a default export equal to the schema (the more
 *     ergonomic path: app-side `defineSchema()` modules export the value
 *     directly, no JSON serialization step in the build).
 *
 * Example:
 *   node tools/publish-schema.mjs \
 *     --api http://localhost:8787 \
 *     --app bookish \
 *     --key abc123... \
 *     --schema ../bookish/public/js/core/tarn-schema.mjs
 *
 * Run once per app release that bumps schema.version. Re-running with the
 * same (app, version, schema) is a safe no-op (Turbo dedups identical
 * uploads). Bumping `version` is how new schemas are released; old
 * versions remain on Arweave for historical entries to migrate from.
 */

import { readFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { pathToFileURL } from 'node:url';

// ============ Args ============

const args = {};
for (let i = 2; i < process.argv.length; i += 2) {
  const flag = process.argv[i].replace(/^--/, '');
  args[flag] = process.argv[i + 1];
}

const { api, app, key, schema: schemaPath } = args;

if (!api || !app || !key || !schemaPath) {
  console.error('Usage: node tools/publish-schema.mjs --api <url> --app <app_id> --key <private_key_hex> --schema <path>');
  console.error('  --schema accepts a .json file or a .mjs file with a default export');
  process.exit(1);
}

// ============ Load the schema ============

async function loadSchema(path) {
  const abs = resolve(path);
  const ext = extname(abs).toLowerCase();
  if (ext === '.json') {
    const text = await readFile(abs, 'utf8');
    return JSON.parse(text);
  }
  if (ext === '.mjs' || ext === '.js') {
    const mod = await import(pathToFileURL(abs).href);
    if (mod.default) return mod.default;
    // Allow `export const schema = defineSchema(...)` too.
    if (mod.schema) return mod.schema;
    throw new Error(
      `${path}: module must export the schema as default OR as a named export 'schema'`,
    );
  }
  throw new Error(`Unsupported schema file extension: ${ext} (expected .json, .mjs, or .js)`);
}

const schema = await loadSchema(schemaPath);

// ============ Validate (client-side, defensive) ============

if (!schema || typeof schema !== 'object') {
  console.error('Schema must be an object');
  process.exit(1);
}
if (typeof schema.appId !== 'string' || schema.appId.length === 0) {
  console.error('Schema.appId must be a non-empty string');
  process.exit(1);
}
if (schema.appId !== app) {
  console.error(`Schema.appId ('${schema.appId}') does not match --app ('${app}')`);
  process.exit(1);
}
if (!Number.isInteger(schema.version) || schema.version < 1) {
  console.error('Schema.version must be a positive integer');
  process.exit(1);
}
if (!schema.collections || typeof schema.collections !== 'object') {
  console.error('Schema.collections must be an object');
  process.exit(1);
}

console.log(`\nTarget:  ${api}`);
console.log(`App:     ${app}`);
console.log(`Version: ${schema.version}`);
console.log(`Collections: ${Object.keys(schema.collections).join(', ')}\n`);

// ============ Authenticate as the app ============

const pkcs8Bytes = new Uint8Array(key.length / 2);
for (let i = 0; i < key.length; i += 2) pkcs8Bytes[i / 2] = parseInt(key.substr(i, 2), 16);

const privateKey = await crypto.subtle.importKey(
  'pkcs8', pkcs8Bytes,
  { name: 'ECDSA', namedCurve: 'P-256' },
  false,
  ['sign'],
);

console.log('1. Requesting challenge...');
const challengeRes = await fetch(`${api}/api/v1/auth/challenge`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ credential_lookup_key: app }),
});
if (!challengeRes.ok) {
  const err = await challengeRes.text();
  console.error(`   Challenge failed (${challengeRes.status}): ${err}`);
  console.error('   Is the app registered? Run generate-app-key.mjs / register-app-from-key.mjs first.');
  process.exit(1);
}
const { nonce } = await challengeRes.json();
console.log(`   Nonce: ${nonce.slice(0, 16)}...`);

const nonceBytes = new Uint8Array(nonce.length / 2);
for (let i = 0; i < nonce.length; i += 2) nonceBytes[i / 2] = parseInt(nonce.substr(i, 2), 16);
const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, nonceBytes);
const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(sig)));

console.log('2. Verifying signature...');
const verifyRes = await fetch(`${api}/api/v1/auth/verify`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ credential_lookup_key: app, nonce, signature: sigBase64 }),
});
if (!verifyRes.ok) {
  const err = await verifyRes.text();
  console.error(`   Verify failed (${verifyRes.status}): ${err}`);
  process.exit(1);
}
const { jwt } = await verifyRes.json();
console.log('   JWT obtained.');

// ============ PUT schema ============

console.log('3. Publishing schema...');
const publishRes = await fetch(`${api}/api/v1/apps/${encodeURIComponent(app)}/schema`, {
  method: 'PUT',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${jwt}`,
  },
  body: JSON.stringify({ version: schema.version, schema }),
});

const responseBody = await publishRes.text();
if (publishRes.ok) {
  let parsed;
  try { parsed = JSON.parse(responseBody); } catch { parsed = null; }
  const txid = parsed?.txid;
  console.log(`   OK (${publishRes.status})`);
  console.log(`\n✓ Schema published`);
  console.log(`  app:     ${app}`);
  console.log(`  version: ${schema.version}`);
  if (txid) console.log(`  txid:    ${txid}`);
  console.log();
} else {
  console.error(`   Failed (${publishRes.status}): ${responseBody}`);
  process.exit(1);
}
