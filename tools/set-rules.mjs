#!/usr/bin/env node
/**
 * Set write authorization rules for a Tarn user account.
 * Authenticates as the app identity, then calls PUT /accounts/{dlk}/rules.
 *
 * Usage:
 *   node tools/set-rules.mjs --api <url> --app <app_id> --key <private_key_hex> --dlk <data_lookup_key> --plan <plan>
 *   node tools/set-rules.mjs --api <url> --app <app_id> --key <private_key_hex> --dlk <data_lookup_key> --rules '<json>'
 *
 * Plans (shortcuts):
 *   free     — max_entries=5 (app-wide, resolved live entries), max_bytes=102400
 *   annual   — max_entries=1000, max_bytes=102400, expires=+1 year from now
 *   clear    — [] (empty rules = unrestricted)
 *   deny     — null-like (sets a single unknown rule that fails closed)
 *
 * Note (tarn#65): plans no longer carry `entry_type: 'entry'` — that value was
 * pre-redesign residue. The schema-first SDK writes Type=<collection name>, so
 * the old filter matched nothing and the caps never bound. Plans now count all
 * of the app's entries; pass --rules with an explicit entry_type to scope a
 * cap to one collection.
 *
 * Examples:
 *   node tools/set-rules.mjs --api http://localhost:8787 --app bookish --key abc123... --dlk def456... --plan free
 *   node tools/set-rules.mjs --api http://localhost:8787 --app bookish --key abc123... --dlk def456... --rules '[{"type":"max_entries","limit":50}]'
 *
 * The --key is the PKCS#8 hex private key from generate-app-key.mjs.
 */

// Parse args
const args = {};
for (let i = 2; i < process.argv.length; i += 2) {
  const flag = process.argv[i].replace(/^--/, '');
  args[flag] = process.argv[i + 1];
}

const { api, app, key, dlk, plan, rules: rulesRaw } = args;

if (!api || !app || !key || !dlk || (!plan && !rulesRaw)) {
  console.error('Usage: node tools/set-rules.mjs --api <url> --app <app_id> --key <private_key_hex> --dlk <data_lookup_key> --plan <plan|--rules <json>');
  console.error('Plans: free, annual, clear, deny');
  process.exit(1);
}

// Resolve rules from plan or raw JSON
let rules;
if (rulesRaw) {
  try {
    rules = JSON.parse(rulesRaw);
  } catch {
    console.error('Invalid --rules JSON:', rulesRaw);
    process.exit(1);
  }
} else {
  const now = new Date();
  switch (plan) {
    case 'free':
      rules = [
        { type: 'max_entries', limit: 5, app },
        { type: 'max_bytes', limit: 102400 },
      ];
      break;
    case 'annual': {
      const expires = new Date(now);
      expires.setFullYear(expires.getFullYear() + 1);
      rules = [
        { type: 'max_entries', limit: 1000, app },
        { type: 'max_bytes', limit: 102400 },
        { type: 'expires', at: expires.toISOString() },
      ];
      break;
    }
    case 'clear':
      rules = [];
      break;
    case 'deny':
      rules = [{ type: '_denied', reason: 'Manually denied via set-rules' }];
      break;
    default:
      console.error('Unknown plan:', plan, '(options: free, annual, clear, deny)');
      process.exit(1);
  }
}

console.log(`\nTarget: ${api}`);
console.log(`App:    ${app}`);
console.log(`DLK:    ${dlk}`);
console.log(`Rules:  ${JSON.stringify(rules)}\n`);

// Import private key
const pkcs8Bytes = new Uint8Array(key.length / 2);
for (let i = 0; i < key.length; i += 2) pkcs8Bytes[i / 2] = parseInt(key.substr(i, 2), 16);

const privateKey = await crypto.subtle.importKey(
  'pkcs8', pkcs8Bytes,
  { name: 'ECDSA', namedCurve: 'P-256' },
  false,
  ['sign']
);

// Challenge
console.log('1. Requesting challenge...');
const challengeRes = await fetch(`${api}/api/v1/auth/challenge`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ credential_lookup_key: app }),
});
if (!challengeRes.ok) {
  const err = await challengeRes.text();
  console.error(`   Challenge failed (${challengeRes.status}): ${err}`);
  console.error('   Is the app registered in D1? Run generate-app-key.mjs first.');
  process.exit(1);
}
const { nonce } = await challengeRes.json();
console.log(`   Nonce: ${nonce.slice(0, 16)}...`);

// Sign
const nonceBytes = new Uint8Array(nonce.length / 2);
for (let i = 0; i < nonce.length; i += 2) nonceBytes[i / 2] = parseInt(nonce.substr(i, 2), 16);
const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, nonceBytes);
const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(sig)));

// Verify
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

// Set rules
console.log('3. Setting rules...');
const rulesRes = await fetch(`${api}/api/v1/accounts/${dlk}/rules`, {
  method: 'PUT',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${jwt}`,
  },
  body: JSON.stringify({ rules }),
});

const rulesBody = await rulesRes.text();
if (rulesRes.ok) {
  console.log(`   OK (${rulesRes.status})`);
  console.log(`\n✓ Rules set for ${dlk}\n`);
} else {
  console.error(`   Failed (${rulesRes.status}): ${rulesBody}`);
  process.exit(1);
}
