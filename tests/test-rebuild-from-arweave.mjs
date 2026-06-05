#!/usr/bin/env node
/**
 * tests/test-rebuild-from-arweave.mjs — operator-driven END-TO-END proof of
 * Phase C of the Arweave-recoverability fix (tarn#35 / folds in #36).
 *
 * **Status: implemented + runnable.** This is the single most load-bearing
 * validation of the "Tarn is rebuildable from Arweave" property. It is
 * operator-driven — it depends on a real Arweave gateway + Turbo, the
 * operator's signing wallet (APP_SIGNING_KEY), and a freshly-wipeable LOCAL
 * D1. It is NOT part of `npm run test:unit` because:
 *
 *   1. It writes REAL bytes to mainnet Arweave via Turbo (not idempotent;
 *      small blobs are free-tier, the >100KB blob costs Turbo credits).
 *   2. It wipes the LOCAL D1 — a destructive op the unit suite must not do.
 *   3. It needs a fresh app registration each run (uniqueness on app_id).
 *
 * Property tested
 * ===============
 *   Given a registered app + N accounts + K passkeys + setRules + entries,
 *   all written through the live local API so the canonical writers fire the
 *   Arweave mirror blobs (Type=app-reg / cred / passkey-reg / app-config),
 *   When we snapshot D1 (scoped to this run's app), WIPE local D1, and run
 *   tools/rebuild-from-arweave.mjs --confirm,
 *   Then the rebuilt D1 must equal the pre-wipe snapshot modulo the
 *   documented acceptable-loss columns:
 *       - accounts.created_at        — block-timestamp approximation
 *       - passkey_credentials.sign_count   — defaults to 0 on rebuild
 *       - passkey_credentials.last_used_at — defaults to NULL on rebuild
 *       - share_log.data_lookup_key  — sender attribution unrecoverable ('')
 *
 * Why scoped to one app
 * =====================
 * The local D1 accumulates rows across every prior integration run. The
 * rebuild tool walks Arweave GLOBALLY (every Type=cred / passkey-reg blob ever
 * published by this wallet), so a raw whole-table diff would be dominated by
 * historical noise. We therefore (a) register a FRESH app with a unique
 * app_id, (b) snapshot/diff only the rows belonging to that app, and (c) wipe
 * the whole local D1 (operator-acknowledged) so the rebuild starts from a true
 * cold cache. The proof is: "the rows for THIS app reconstructed identically
 * from Arweave alone."
 *
 * The >100KB paid path
 * ====================
 * The /api/v1/entries write endpoint hard-caps payloads at MAX_UPLOAD_BYTES
 * (100 KiB) and returns 413 above it — there is intentionally NO oversized
 * write path through the API. To exercise the Turbo PAID path we upload one
 * >100KB DataItem DIRECTLY via api/src/turbo.js (same signing wallet, tagged
 * as a Tarn entry) and confirm Turbo accepts it. If the wallet lacks credits
 * (402/403/insufficient balance) we record the leg as BLOCKED and continue —
 * an unfunded wallet is an operator step, not a test failure.
 *
 * Mainnet indexing latency
 * ========================
 * The rebuild reads via GraphQL; freshly-uploaded Turbo data items take time
 * to become queryable. After writing we POLL the gateway's GraphQL for the
 * written app-reg/cred/passkey-reg/app-config txids (up to --index-timeout-ms,
 * default 5 min). If they never index in the window we DO NOT fake a pass — we
 * report "blocked on mainnet indexing latency" plus exactly what we DID prove
 * (uploads accepted, blobs fetchable by txid) and do NOT wipe D1.
 *
 * Usage
 * =====
 *   # 1. Run wrangler dev with TARN_SKIP_TURBO UNSET so writes upload for real:
 *   #    (comment out TARN_SKIP_TURBO in api/.dev.vars, then)
 *   #    cd api && npx wrangler dev --port 8787
 *   # 2. Run the proof:
 *   node --import tsx tests/test-rebuild-from-arweave.mjs \
 *     --i-accept-destructive-wipe \
 *     --run-id <short-suffix> \
 *     --gateway https://arweave.net
 *
 * Safety guards (preserved from the scaffold):
 *   - Refuses to run without --i-accept-destructive-wipe.
 *   - LOCAL D1 only — never passes --remote to wrangler or the rebuild tool.
 *   - The wipe runs api/scripts/wipe-accounts.sql against --local only.
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { TarnClient } from '../client/src/tarn.js';
import {
  encrypt, deriveAllKeys, signChallenge, unwrapDataKeyChain,
} from '../client/src/crypto.js';
import { randomUsername, sleep } from './helpers.mjs';
import { VirtualAuthenticator, installPasskeyTestEnv } from './helpers/virtual-authenticator.mjs';
import { buildSignedDataItem, uploadSignedDataItem } from '../api/src/turbo.js';

// ============ ARG PARSING ============

const argv = process.argv.slice(2);
const opts = {
  // Gateway choice for the rebuild + index-poll: turbo-gateway.com indexes
  // Turbo bundles into its GraphQL within ~7-12 min, where arweave.net L1
  // GraphQL lags ~15-25 min. Since every Tarn write goes through Turbo, the
  // turbo gateway is what makes the rebuild queryable in a practical window.
  // Its indexer is occasionally circuit-open, so the poll falls back to a body
  // fetch (see gqlFindByTxids). NOTE: the worker's separate entries
  // cold-bootstrap path (api/src/arweave.js) is hardcoded to arweave.net, so
  // that leg lags independently — it's reported but does not gate the verdict.
  api: 'http://localhost:8787',
  gateway: 'https://turbo-gateway.com',
  numAccounts: 2,
  numPasskeys: 2,
  runId: null,
  indexTimeoutMs: 16 * 60 * 1000,
  iAcceptDestructiveWipe: false,
  skipBigUpload: false,
};

for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--api') opts.api = argv[++i];
  else if (a === '--gateway') opts.gateway = argv[++i];
  else if (a === '--num-accounts') opts.numAccounts = Number(argv[++i]);
  else if (a === '--num-passkeys') opts.numPasskeys = Number(argv[++i]);
  else if (a === '--run-id') opts.runId = argv[++i];
  else if (a === '--index-timeout-ms') opts.indexTimeoutMs = Number(argv[++i]);
  else if (a === '--i-accept-destructive-wipe') opts.iAcceptDestructiveWipe = true;
  else if (a === '--skip-big-upload') opts.skipBigUpload = true;
  else if (a === '--help' || a === '-h') { printHelp(); process.exit(0); }
  else { console.error(`Unknown flag: ${a}`); process.exit(1); }
}

function printHelp() {
  console.log(`
tests/test-rebuild-from-arweave.mjs (operator-driven, real Arweave)

Proves D1 reconstructs from Arweave end-to-end. Writes real bytes to mainnet
Arweave via Turbo and WIPES the local D1, so it must be invoked explicitly
with --i-accept-destructive-wipe.

Flags:
  --i-accept-destructive-wipe   REQUIRED. Acknowledges the local D1 wipe.
  --run-id <suffix>             Per-run app_id suffix (default: derived).
  --api URL                     Tarn API (default: http://localhost:8787)
  --gateway URL                 Arweave GraphQL+body gateway (default: arweave.net)
  --num-accounts N              Accounts to register (default: 2)
  --num-passkeys N              Passkeys to register (default: 2)
  --index-timeout-ms N          Max wait for GraphQL indexing (default: 300000)
  --skip-big-upload             Skip the >100KB Turbo paid-path leg.

Pre-reqs: wrangler dev running locally with TARN_SKIP_TURBO unset (so writes
actually upload via Turbo), and migrations applied.
`);
}

if (!opts.iAcceptDestructiveWipe) {
  console.error('Refusing to run without --i-accept-destructive-wipe (this script wipes local D1).');
  console.error('Run with --help for details.');
  process.exit(2);
}

// A unique app_id per run. process args win; else a stable-per-process suffix.
const RUN_ID = opts.runId || `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
const APP_ID = `rebuildtest-${RUN_ID}`;

// ============ INFRA: D1 via wrangler (LOCAL ONLY) ============

const API_CWD = new URL('../api', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1');
const ROOT_CWD = new URL('..', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1');

function d1(sql, { json = false } = {}) {
  // Build a single shell command string with the SQL wrapped in escaped
  // double-quotes — matching tools/rebuild-from-arweave.mjs. Passing an args
  // array with `shell:true` word-splits the SQL on Windows, so we don't.
  const quoted = `"${sql.replace(/"/g, '\\"')}"`;
  const cmd = `npx wrangler d1 execute tarn-api --local ${json ? '--json ' : ''}--command ${quoted}`;
  const res = spawnSync(cmd, { cwd: API_CWD, encoding: 'utf8', shell: true, timeout: 60000 });
  if (res.status !== 0) {
    throw new Error(`wrangler d1 failed (exit ${res.status}): ${res.stderr || res.stdout}`);
  }
  if (!json) return null;
  const out = res.stdout;
  const start = out.search(/[[{]/);
  if (start < 0) return [];
  const parsed = JSON.parse(out.slice(start));
  const block = Array.isArray(parsed) ? parsed[0] : parsed;
  return block?.results || [];
}

// ============ ARWEAVE GRAPHQL POLLING ============

async function gqlFindByTxids(txids) {
  // Readiness signal = the blob is GraphQL-discoverable by id AND body-fetchable
  // (the two things the rebuild tool needs: gqlPage discovers, fetchBlob pulls
  // the body). We probe ONE id per GraphQL query (multi-id arrays trip
  // turbo-gateway's parser) and treat any HTTP/parse error or empty result as
  // "not yet". If GraphQL flakes (turbo-gateway's indexer is sometimes
  // circuit-open) we fall back to a body fetch — a 200 body means the data
  // item is retrievable, the gating constraint for the rebuild's per-blob
  // fetch. Never a false-positive: only count ids we actually located.
  const url = opts.gateway.replace(/\/+$/, '') + '/graphql';
  const found = new Set();
  for (const id of txids) {
    let ok = false;
    const q = `query($id:ID!){ transactions(ids:[$id], first:1){ edges{ node{ id } } } }`;
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q, variables: { id } }),
        signal: AbortSignal.timeout(20000),
      });
      if (res.ok) {
        const json = await res.json().catch(() => null);
        if (json?.data?.transactions?.edges?.some((e) => e?.node?.id === id)) ok = true;
      }
    } catch { /* fall through to body probe */ }
    if (!ok && (await fetchBlobByTxid(id))) ok = true;
    if (ok) found.add(id);
  }
  return found;
}

async function pollUntilIndexed(label, txids, timeoutMs) {
  const want = [...new Set(txids.filter(Boolean))];
  if (want.length === 0) return { ok: true, indexed: new Set(), missing: [] };
  const deadline = Date.now() + timeoutMs;
  let indexed = new Set();
  let attempt = 0;
  while (Date.now() < deadline) {
    attempt++;
    indexed = await gqlFindByTxids(want);
    const missing = want.filter((t) => !indexed.has(t));
    console.log(`  [index-poll ${label}] attempt ${attempt}: ${indexed.size}/${want.length} indexed${missing.length ? ` (waiting on ${missing.length})` : ''}`);
    if (missing.length === 0) return { ok: true, indexed, missing: [] };
    await sleep(15000);
  }
  return { ok: false, indexed, missing: want.filter((t) => !indexed.has(t)) };
}

async function fetchBlobByTxid(txid) {
  for (const gw of ['https://turbo-gateway.com', opts.gateway, 'https://arweave.net']) {
    try {
      const res = await fetch(gw.replace(/\/+$/, '') + '/' + txid, { signal: AbortSignal.timeout(15000) });
      if (res.ok) return new Uint8Array(await res.arrayBuffer());
    } catch { /* next gateway */ }
  }
  return null;
}

// ============ FETCH WITH RETRY ============

// undici occasionally throws "fetch failed" on the first connection to a
// just-idle local server, and turbo-gateway intermittently 5xxs. Retry a few
// times with backoff so a transient blip doesn't abort the whole proof.
async function rfetch(url, init = {}, { retries = 4 } = {}) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(30000), ...init });
      return res;
    } catch (err) {
      lastErr = err;
      await sleep(500 * (attempt + 1));
    }
  }
  throw lastErr;
}

// ============ OPERATOR WALLET ============

function operatorSigningKey() {
  const vars = readFileSync(new URL('../api/.dev.vars', import.meta.url), 'utf8');
  const m = vars.match(/^APP_SIGNING_KEY=(\S+)/m);
  if (!m) throw new Error('APP_SIGNING_KEY not found in api/.dev.vars');
  return m[1];
}

// ============ APP REGISTRATION (canonical path, publishes app-reg) ============

let appPrivateKeyHex = null;
let appPublicKeyBase64 = null;
let appPrivateKeyCrypto = null;
let appRegTxid = null;

async function generateAppKeypair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'],
  );
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  appPrivateKeyHex = Array.from(pkcs8).map((b) => b.toString(16).padStart(2, '0')).join('');
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  appPublicKeyBase64 = btoa(String.fromCharCode(...spki));
  appPrivateKeyCrypto = keyPair.privateKey;
}

/**
 * Register the app via the CANONICAL operator tool register-app-from-key.mjs.
 * That tool publishes a Type=app-reg blob to Arweave (Arweave-first ordering)
 * and prints the D1 seed SQL. We capture the txid from stdout and run the SQL
 * locally. This directly answers tarn#36: does the registration path publish
 * app-reg? (It does — proven live here.)
 */
function registerAppViaTool(signingKey) {
  const res = spawnSync('node', [
    'tools/register-app-from-key.mjs', APP_ID, appPrivateKeyHex, '--signing-key', signingKey,
  ], { cwd: ROOT_CWD, encoding: 'utf8', shell: true, timeout: 120000 });
  const out = (res.stdout || '') + (res.stderr || '');
  console.log(out.split('\n').map((l) => '    ' + l).join('\n'));
  if (res.status !== 0) {
    throw new Error(`register-app-from-key.mjs failed (exit ${res.status})`);
  }
  const m = out.match(/Arweave txid \(Type=app-reg[^)]*\):\s*([A-Za-z0-9_-]{43})/);
  if (m) appRegTxid = m[1];
  // Run an equivalent of the printed D1 seed SQL locally (the tool prints a
  // --remote command; this proof is local-only).
  d1(`INSERT OR REPLACE INTO apps (app_id, public_key, created_at) VALUES ('${APP_ID}', '${appPublicKeyBase64}', ${Date.now()})`);
  return appRegTxid;
}

// ============ APP JWT (challenge/verify) ============

let appJwt = null;

function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substr(i, 2), 16);
  return b;
}

async function loginAsApp() {
  const cRes = await rfetch(`${opts.api}/api/v1/auth/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: APP_ID }),
  });
  const cJson = await cRes.json();
  if (cRes.status !== 200) throw new Error(`app challenge failed: ${cRes.status} ${JSON.stringify(cJson)}`);
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, appPrivateKeyCrypto, hexToBytes(cJson.nonce),
  );
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  const vRes = await rfetch(`${opts.api}/api/v1/auth/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: APP_ID, nonce: cJson.nonce, signature: sigB64 }),
  });
  const vJson = await vRes.json();
  if (vRes.status !== 200) throw new Error(`app verify failed: ${vRes.status} ${JSON.stringify(vJson)}`);
  appJwt = vJson.jwt;
}

// ============ USER JWT + DEK (raw wire flow, same as test-e2e) ============

async function deriveUserJwtAndDek(acct) {
  const keys = await deriveAllKeys(acct.username, acct.password, APP_ID);
  // JWT via challenge/verify.
  const cRes = await rfetch(`${opts.api}/api/v1/auth/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey }),
  }).then((r) => r.json());
  const sig = await signChallenge(keys.signingKeyPair.privateKey, cRes.nonce);
  const vRes = await rfetch(`${opts.api}/api/v1/auth/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey, nonce: cRes.nonce, signature: sig }),
  }).then((r) => r.json());
  if (!vRes.jwt) throw new Error(`user verify failed: ${JSON.stringify(vRes)}`);
  // DEK: unwrap the current-gen DEK from the account envelope via the password factor.
  const row = d1(`SELECT wrapped_data_key FROM accounts WHERE data_lookup_key='${acct.dlk}'`, { json: true })[0];
  const chain = await unwrapDataKeyChain(row.wrapped_data_key, keys.credentialEncryptionKey.kwKey);
  const dek = chain.dekByGen.get(chain.currentGen).gcmKey;
  acct.jwt = vRes.jwt;
  acct.dek = dek;
}

// ============ STATE ============

const writtenTxids = { appReg: [], cred: [], passkeyReg: [], appConfig: [], entries: [] };
let bigUpload = { attempted: false, ok: null, status: null, txid: null, note: null };
let entriesBootstrapResult = null;
let accounts = [];

// ============ MAIN ============

async function main() {
  console.log('================================================================');
  console.log(`Tarn rebuild-from-Arweave PROOF — app_id=${APP_ID}`);
  console.log(`  API: ${opts.api}   gateway: ${opts.gateway}`);
  console.log(`  accounts=${opts.numAccounts} passkeys=${opts.numPasskeys}`);
  console.log('================================================================\n');

  const signingKey = operatorSigningKey();

  // [0] Sanity: API up.
  console.log('[0] Checking API reachability...');
  const health = await fetch(`${opts.api}/api/v1/health`).then((r) => r.text()).catch(() => null);
  console.log(`    health: ${health ? health.slice(0, 160) : 'unreachable (start wrangler dev first!)'}`);
  if (!health) throw new Error('API unreachable — start wrangler dev on ' + opts.api);

  // [1] Generate per-app keypair + register via the canonical tool.
  console.log('\n[1] Registering fresh app via register-app-from-key.mjs (canonical path)...');
  await generateAppKeypair();
  registerAppViaTool(signingKey);
  if (!appRegTxid) {
    throw new Error('registration tool did not report an app-reg txid — registration does NOT publish app-reg (real gap; see #36)');
  }
  writtenTxids.appReg.push(appRegTxid);
  console.log(`    app-reg txid: ${appRegTxid}`);

  // [2] Login as the app.
  console.log('\n[2] Logging in as app (challenge/verify)...');
  await loginAsApp();
  console.log('    app JWT acquired.');

  // [3] Passkey env (virtual authenticator + fetch origin shim).
  const env = installPasskeyTestEnv({ origin: 'http://localhost:3000', rpId: 'localhost' });

  // [4] Register N accounts via the SDK (publishes Type=cred).
  console.log(`\n[3] Registering ${opts.numAccounts} accounts via SDK (publishes Type=cred)...`);
  for (let i = 0; i < opts.numAccounts; i++) {
    const client = new TarnClient(opts.api, APP_ID);
    const username = randomUsername();
    const password = `pw-${RUN_ID}-${i}-${Math.random().toString(36).slice(2, 8)}`;
    await client.register(username, password, { recoveryAcknowledged: true });
    accounts.push({ client, username, password, dlk: client.dataLookupKey, jwt: null, dek: null });
    console.log(`    account ${i}: dlk=${client.dataLookupKey.slice(0, 12)}…`);
  }

  // [5] Register K passkeys spread across accounts (publishes Type=passkey-reg).
  console.log(`\n[4] Registering ${opts.numPasskeys} passkeys (publishes Type=passkey-reg)...`);
  for (let i = 0; i < opts.numPasskeys; i++) {
    const acct = accounts[i % accounts.length];
    const auth = new VirtualAuthenticator();
    env.stageRegistration(auth);
    const result = await acct.client.registerPasskey({ deviceLabel: `pk-${i}` });
    console.log(`    passkey ${i}: cred=${result.credentialId.slice(0, 12)}… on dlk=${acct.dlk.slice(0, 12)}…`);
  }

  // [6] setRules per account via the app JWT (publishes Type=app-config).
  console.log('\n[5] setRules per account (publishes Type=app-config)...');
  for (let i = 0; i < accounts.length; i++) {
    const acct = accounts[i];
    const rules = i === 0 ? [] : [{ type: 'max_entries', limit: 50, app: APP_ID, entry_type: 'entry' }];
    const r = await rfetch(`${opts.api}/api/v1/accounts/${acct.dlk}/rules`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${appJwt}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ rules }),
    });
    if (r.status !== 200) throw new Error(`setRules failed for ${acct.dlk}: ${r.status} ${await r.text()}`);
    acct.rules = rules;
    console.log(`    rules set for account ${i}: ${JSON.stringify(rules)}`);
  }
  await sleep(1500); // let the app-config waitUntil uploads run

  // [7] Derive each account's user JWT + DEK, then write small (<100KiB) entries.
  console.log('\n[6] Writing small (<100KiB) entries through the API...');
  for (let i = 0; i < accounts.length; i++) {
    const acct = accounts[i];
    await deriveUserJwtAndDek(acct);
    for (let j = 0; j < 2; j++) {
      const payload = { run: RUN_ID, acct: i, idx: j, note: 'small entry', filler: 'x'.repeat(100) };
      const enc = await encrypt(acct.dek, payload);
      const tags = [
        { name: 'App', value: APP_ID }, { name: 'Type', value: 'entry' },
        { name: 'Lk', value: acct.dlk }, { name: 'Enc', value: 'aes-256-gcm' },
        { name: 'V', value: '0.4.0' },
      ];
      const res = await rfetch(`${opts.api}/api/v1/entries`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${acct.jwt}`, 'X-Arweave-Tags': JSON.stringify(tags), 'Content-Type': 'application/octet-stream' },
        body: enc,
      });
      const json = await res.json().catch(() => null);
      if (res.status !== 200) throw new Error(`entry write failed: ${res.status} ${JSON.stringify(json)}`);
      writtenTxids.entries.push(json.id);
      console.log(`    small entry acct${i}/${j}: ${json.id.slice(0, 12)}… (${enc.byteLength}B)`);
    }
  }

  // [8] >100KB paid-path leg — direct Turbo upload (the API caps at 100KiB).
  if (!opts.skipBigUpload) {
    console.log('\n[7] >100KB paid-path leg — direct Turbo upload (bypasses API 100KiB cap)...');
    bigUpload.attempted = true;
    try {
      const bigBytes = new Uint8Array(140 * 1024); // 140 KiB — above the 100 KiB free tier
      crypto.getRandomValues(bigBytes.subarray(0, 65536));
      const acct = accounts[0];
      const tags = [
        { name: 'App', value: APP_ID }, { name: 'Type', value: 'entry' },
        { name: 'Lk', value: acct.dlk }, { name: 'Enc', value: 'aes-256-gcm' },
        { name: 'Big', value: 'paid-path-proof' }, { name: 'V', value: '0.4.0' },
      ];
      const { signedDataItem, txid } = await buildSignedDataItem(bigBytes, tags, signingKey);
      bigUpload.txid = txid;
      globalThis.__TARN_SKIP_TURBO__ = false; // force a real upload
      const up = await uploadSignedDataItem(signedDataItem);
      bigUpload.ok = up.ok;
      bigUpload.status = up.status ?? null;
      if (up.ok) {
        console.log(`    >100KB upload ACCEPTED by Turbo: ${txid} (${bigBytes.byteLength}B)`);
        bigUpload.note = `paid-path (>100KB, ${bigBytes.byteLength}B) leg PROVEN — Turbo accepted the upload (txid ${txid})`;
      } else if (up.status === 402 || up.status === 403) {
        bigUpload.note = `paid-path (>100KB) leg BLOCKED — wallet needs Turbo credits (operator action). Turbo HTTP ${up.status}: ${(up.body || '').slice(0, 160)}`;
        console.warn(`    ${bigUpload.note}`);
      } else {
        bigUpload.note = `paid-path (>100KB) leg failed — Turbo HTTP ${up.status}: ${(up.body || '').slice(0, 160)}`;
        console.warn(`    ${bigUpload.note}`);
      }
    } catch (err) {
      bigUpload.ok = false;
      bigUpload.note = `paid-path (>100KB) leg errored: ${err.message}`;
      console.warn(`    ${bigUpload.note}`);
    }
  } else {
    console.log('\n[7] >100KB paid-path leg SKIPPED (--skip-big-upload).');
  }

  // [9] Collect the identity-plane txids from the D1 cache (every writer
  //     write-throughs the txid into `entries`).
  console.log('\n[8] Collecting written mirror-blob txids from D1 cache...');
  const myCredLks = d1(
    `SELECT credential_lookup_key FROM accounts WHERE app='${APP_ID}'`, { json: true },
  ).map((r) => r.credential_lookup_key);
  writtenTxids.cred = myCredLks.length
    ? d1(`SELECT txid FROM entries WHERE app='tarn' AND type='cred' AND lookup_key IN (${myCredLks.map((k) => `'${k}'`).join(',')})`, { json: true }).map((r) => r.txid)
    : [];
  const myDlks = accounts.map((a) => a.dlk);
  writtenTxids.passkeyReg = d1(
    `SELECT txid FROM entries WHERE app='tarn' AND type='passkey-reg' AND lookup_key IN (${myDlks.map((d) => `'${d}'`).join(',')})`,
    { json: true },
  ).map((r) => r.txid);
  writtenTxids.appConfig = d1(
    `SELECT txid FROM entries WHERE app='${APP_ID}' AND type='app-config'`, { json: true },
  ).map((r) => r.txid);
  console.log(`    app-reg: ${writtenTxids.appReg.length}, cred: ${writtenTxids.cred.length}, passkey-reg: ${writtenTxids.passkeyReg.length}, app-config: ${writtenTxids.appConfig.length}, entries: ${writtenTxids.entries.length}`);

  // [10] POLL the gateway GraphQL until ALL written blobs are indexed —
  // identity-plane mirrors (for the rebuild tool) AND the small entries (for
  // the cold-bootstrap read). Don't wipe until every one is queryable.
  console.log(`\n[9] Polling gateway GraphQL until mirror+entry blobs are indexed (timeout ${(opts.indexTimeoutMs / 1000).toFixed(0)}s)...`);
  const identityTxids = [
    ...writtenTxids.appReg, ...writtenTxids.cred, ...writtenTxids.passkeyReg,
    ...writtenTxids.appConfig, ...writtenTxids.entries,
  ];
  const indexResult = await pollUntilIndexed('identity', identityTxids, opts.indexTimeoutMs);
  if (!indexResult.ok) {
    console.error('\n================ INDEXING LATENCY BLOCKER ================');
    console.error(`Mirror blobs uploaded + confirmed-accepted by Turbo, but ${indexResult.missing.length}/${identityTxids.length} are NOT yet GraphQL-queryable on ${opts.gateway} within ${(opts.indexTimeoutMs / 1000).toFixed(0)}s.`);
    console.error('What WAS proven this run:');
    console.error(`  - app-reg published by the canonical registration path: YES (${appRegTxid})`);
    console.error(`  - Turbo accepted ${writtenTxids.cred.length} cred + ${writtenTxids.passkeyReg.length} passkey-reg + ${writtenTxids.appConfig.length} app-config + ${writtenTxids.entries.length} entry uploads`);
    let fetchable = 0;
    const sample = identityTxids.slice(0, 8);
    for (const t of sample) { if (await fetchBlobByTxid(t)) fetchable++; }
    console.error(`  - ${fetchable}/${sample.length} sampled blobs fetchable by txid (body retrievable even if not GraphQL-indexed)`);
    console.error(`  - >100KB paid path: ${bigUpload.note || 'not attempted'}`);
    console.error('NOT WIPING D1 (the rebuild would not see the un-indexed blobs).');
    console.error('Re-run later (Turbo→arweave.net GraphQL indexing can take minutes to hours).');
    console.error('==========================================================');
    env.restore();
    process.exit(3);
  }
  console.log('    all identity-plane mirror blobs are GraphQL-indexed.');

  // [11] SNAPSHOT (scoped to this app) BEFORE wipe.
  console.log('\n[10] Snapshotting D1 (scoped to this run\'s app) BEFORE wipe...');
  const before = snapshot();
  printSnapshot('BEFORE', before);

  // [12] WIPE local D1 (operator-acknowledged).
  console.log('\n[11] WIPING local D1 (wipe-accounts.sql + this-app apps row + cache_meta)...');
  runWipe();
  const afterWipe = snapshot();
  // Verify ALL three identity-plane tables are empty for this app so the
  // rebuild genuinely has to reconstruct each from Arweave.
  if (afterWipe.accounts.length !== 0 || afterWipe.apps.length !== 0 || afterWipe.passkeys.length !== 0 || afterWipe.entries.length !== 0) {
    throw new Error(`wipe did not fully clear this-app rows (apps=${afterWipe.apps.length} accounts=${afterWipe.accounts.length} passkeys=${afterWipe.passkeys.length} entries=${afterWipe.entries.length}) — aborting before rebuild`);
  }
  console.log('    D1 wiped (apps + accounts + passkeys + entries + share_* gone).');

  // [13] RUN the rebuild tool (LOCAL D1, --confirm, scoped to this app).
  console.log('\n[12] Running tools/rebuild-from-arweave.mjs --confirm (LOCAL D1)...');
  runRebuild();

  // [14] RE-SNAPSHOT + DIFF modulo acceptable losses.
  console.log('\n[13] Re-snapshotting + diffing (modulo documented acceptable losses)...');
  const after = snapshot();
  printSnapshot('AFTER', after);
  const verdict = diff(before, after);

  // [15] Entries cold-bootstrap proof (rebuild tool leaves entries to lazy refreshCache).
  console.log('\n[14] Proving entries recover via lazy cold-bootstrap read...');
  entriesBootstrapResult = await proveEntriesColdBootstrap(before.accounts[0]);
  console.log(`    cold-bootstrap read returned ${entriesBootstrapResult.count} entries (ok=${entriesBootstrapResult.ok})`);

  // [16] Report.
  report(verdict);
  env.restore();
  // The CORE proof (#35/#36) is the identity-plane rebuild: apps + accounts +
  // passkeys + rules reconstructed by the rebuild tool. Entries recovery via
  // lazy cold-bootstrap is a separate, already-tested mechanism (refreshCache)
  // that reads arweave.net (hardcoded in the worker) — its timing depends on
  // arweave.net's slower indexing, so a lag there does NOT invalidate the core
  // verdict. We report it but gate the exit on the core rebuild only.
  process.exit(verdict.clean ? 0 : 1);
}

// ============ SNAPSHOT / DIFF ============

function snapshot() {
  const apps = d1(`SELECT app_id, public_key, invite_url_template FROM apps WHERE app_id='${APP_ID}'`, { json: true });
  const accountsRows = d1(
    `SELECT credential_lookup_key, public_key, data_lookup_key, wrapped_data_key, app, rules_json, recovery_lookup_key, recovery_public_key, share_pub, share_discoverable, share_lookup_key, wrapped_account_key, created_at FROM accounts WHERE app='${APP_ID}' ORDER BY data_lookup_key`,
    { json: true },
  );
  const dlks = accountsRows.map((a) => a.data_lookup_key);
  const dlkFilter = dlks.length ? `account_id IN (${dlks.map((d) => `'${d}'`).join(',')})` : '0';
  const passkeys = d1(
    `SELECT account_id, credential_id, public_key, prf_salt, device_label, sign_count, last_used_at, created_at FROM passkey_credentials WHERE ${dlkFilter} ORDER BY credential_id`,
    { json: true },
  );
  const entries = d1(
    `SELECT txid, type, lookup_key, is_tombstone FROM entries WHERE app='${APP_ID}' ORDER BY txid`,
    { json: true },
  );
  return { apps, accounts: accountsRows, passkeys, entries };
}

function printSnapshot(label, s) {
  console.log(`    [${label}] apps=${s.apps.length} accounts=${s.accounts.length} passkeys=${s.passkeys.length} entries=${s.entries.length}`);
}

function runWipe() {
  const res = spawnSync('npx', ['wrangler', 'd1', 'execute', 'tarn-api', '--local', '--file', 'scripts/wipe-accounts.sql'], {
    cwd: API_CWD, encoding: 'utf8', shell: true, timeout: 120000,
  });
  if (res.status !== 0) throw new Error(`wipe failed: ${res.stderr || res.stdout}`);
  // wipe-accounts.sql predates migration 0018 and does NOT clear
  // `passkey_credentials` — wipe it explicitly so the rebuild has to
  // reconstruct passkeys from Arweave (otherwise the historical rows survive
  // and the passkey diff is a false pass). Also delete THIS app's `apps` row
  // (wipe-accounts.sql keeps `apps`) so the app-reg rebuild must reconstruct
  // it, and clear `cache_meta` so entry reads re-bootstrap.
  d1(`DELETE FROM passkey_credentials`);
  d1(`DELETE FROM apps WHERE app_id='${APP_ID}'`);
  d1(`DELETE FROM cache_meta`);
}

function runRebuild() {
  const res = spawnSync('node', [
    'tools/rebuild-from-arweave.mjs',
    '--confirm',
    '--app', APP_ID,
    '--arweave-gateway', opts.gateway,
  ], { cwd: ROOT_CWD, encoding: 'utf8', shell: true, timeout: opts.indexTimeoutMs + 120000 });
  const out = (res.stdout || '') + (res.stderr || '');
  console.log(out.split('\n').map((l) => '    ' + l).join('\n'));
  if (res.status !== 0) throw new Error(`rebuild tool exited ${res.status}`);
}

function rowsByKey(rows, key) {
  const m = new Map();
  for (const r of rows) m.set(r[key], r);
  return m;
}

function diff(before, after) {
  const issues = [];
  const tableVerdict = {};

  // ---- apps ----
  {
    const b = rowsByKey(before.apps, 'app_id');
    const a = rowsByKey(after.apps, 'app_id');
    let ok = true;
    for (const [id, br] of b) {
      const ar = a.get(id);
      if (!ar) { issues.push(`apps: ${id} MISSING after rebuild`); ok = false; continue; }
      if (ar.public_key !== br.public_key) { issues.push(`apps: ${id} public_key differs`); ok = false; }
      if ((ar.invite_url_template ?? null) !== (br.invite_url_template ?? null)) {
        issues.push(`apps: ${id} invite_url_template differs (before=${br.invite_url_template} after=${ar.invite_url_template})`); ok = false;
      }
    }
    tableVerdict.apps = { ok, before: before.apps.length, after: after.apps.length };
  }

  // ---- accounts ----
  {
    const b = rowsByKey(before.accounts, 'data_lookup_key');
    const a = rowsByKey(after.accounts, 'data_lookup_key');
    let ok = true;
    if (b.size !== a.size) { issues.push(`accounts: count ${b.size} -> ${a.size}`); ok = false; }
    const exactCols = [
      'credential_lookup_key', 'public_key', 'wrapped_data_key', 'app',
      'recovery_lookup_key', 'recovery_public_key', 'share_pub', 'share_discoverable',
      'share_lookup_key', 'wrapped_account_key', 'rules_json',
    ];
    for (const [dlk, br] of b) {
      const ar = a.get(dlk);
      if (!ar) { issues.push(`accounts: ${dlk.slice(0, 12)}… MISSING after rebuild`); ok = false; continue; }
      for (const col of exactCols) {
        if (norm(ar[col]) !== norm(br[col])) {
          issues.push(`accounts: ${dlk.slice(0, 12)}… ${col} differs (before=${trunc(br[col])} after=${trunc(ar[col])})`); ok = false;
        }
      }
      // created_at — acceptable loss (block-timestamp approximation); not checked.
    }
    tableVerdict.accounts = { ok, before: before.accounts.length, after: after.accounts.length };
  }

  // ---- passkey_credentials ----
  {
    const b = rowsByKey(before.passkeys, 'credential_id');
    const a = rowsByKey(after.passkeys, 'credential_id');
    let ok = true;
    if (b.size !== a.size) { issues.push(`passkeys: count ${b.size} -> ${a.size}`); ok = false; }
    const exactCols = ['account_id', 'public_key', 'prf_salt', 'device_label'];
    for (const [cid, br] of b) {
      const ar = a.get(cid);
      if (!ar) { issues.push(`passkeys: ${cid.slice(0, 12)}… MISSING after rebuild`); ok = false; continue; }
      for (const col of exactCols) {
        if (norm(ar[col]) !== norm(br[col])) { issues.push(`passkeys: ${cid.slice(0, 12)}… ${col} differs`); ok = false; }
      }
      // Acceptable losses: sign_count must be 0, last_used_at must be NULL.
      if (Number(ar.sign_count) !== 0) { issues.push(`passkeys: ${cid.slice(0, 12)}… sign_count not 0 after rebuild (${ar.sign_count})`); ok = false; }
      if (ar.last_used_at != null) { issues.push(`passkeys: ${cid.slice(0, 12)}… last_used_at not NULL after rebuild`); ok = false; }
    }
    tableVerdict.passkeys = { ok, before: before.passkeys.length, after: after.passkeys.length };
  }

  // ---- entries: verified separately via cold-bootstrap read, not the tool ----
  tableVerdict.entries = { note: 'verified via cold-bootstrap read, not the rebuild tool' };

  return { clean: issues.length === 0, issues, tableVerdict };
}

function norm(v) {
  if (v == null) return null;
  if (typeof v === 'number') return String(v);
  return v;
}
function trunc(v) {
  const s = v == null ? 'NULL' : String(v);
  return s.length > 40 ? s.slice(0, 40) + '…' : s;
}

// ============ ENTRIES COLD-BOOTSTRAP PROOF ============

async function proveEntriesColdBootstrap(account) {
  // After wipe + rebuild, accounts row exists but `entries` is empty. A list
  // read for (app, type=entry, dlk) must lazily cold-bootstrap from Arweave
  // (refreshCache) and return the previously-written entries.
  // NOTE: the worker's cold-bootstrap (api/src/cache.js refreshCache ->
  // arweave.js) queries arweave.net/graphql, which indexes Turbo bundles
  // ~15-25 min after upload — slower than the turbo-gateway index the rebuild
  // uses. So this read can lag; we poll up to ~6 min and report the result
  // without blocking the core verdict.
  const dlk = account.data_lookup_key;
  const url = `${opts.api}/api/v1/entries?app=${APP_ID}&type=entry&key=${dlk}`;
  const deadline = Date.now() + 6 * 60 * 1000;
  let lastCount = 0;
  while (Date.now() < deadline) {
    try {
      const res = await rfetch(url, {}, { retries: 2 });
      if (res.ok) {
        const json = await res.json();
        lastCount = json.entries?.length ?? 0;
        if (lastCount > 0) return { ok: true, count: lastCount };
      }
    } catch { /* retry */ }
    await sleep(12000);
  }
  return { ok: false, count: lastCount };
}

// ============ REPORT ============

function report(verdict) {
  console.log('\n================== REBUILD PROOF VERDICT ==================');
  console.log(`app_id: ${APP_ID}`);
  const tv = verdict.tableVerdict;
  const yn = (b) => (b ? 'YES' : 'NO');
  console.log(`apps:                ${yn(tv.apps.ok)}  (${tv.apps.before} -> ${tv.apps.after})`);
  console.log(`accounts:            ${yn(tv.accounts.ok)}  (${tv.accounts.before} -> ${tv.accounts.after})`);
  console.log(`passkey_credentials: ${yn(tv.passkeys.ok)}  (${tv.passkeys.before} -> ${tv.passkeys.after})`);
  if (entriesBootstrapResult) {
    console.log(`entries (cold-boot): ${yn(entriesBootstrapResult.ok)}  (${entriesBootstrapResult.count} entries re-bootstrapped on first read)`);
  }
  console.log(`>100KB paid path:    ${bigUpload.note || 'not attempted'}`);
  console.log(`app-reg published by registration path: ${appRegTxid ? 'YES (' + appRegTxid + ')' : 'NO — REAL GAP'}`);
  if (verdict.issues.length) {
    console.log('\nDIFF ISSUES (outside documented losses):');
    for (const i of verdict.issues) console.log(`  - ${i}`);
  } else {
    console.log('\nNo diffs outside the documented acceptable-loss set.');
  }
  const clean = verdict.clean && (entriesBootstrapResult?.ok ?? false);
  console.log(clean
    ? '\nRESULT: D1 RECONSTRUCTED CLEANLY FROM ARWEAVE — recoverability PROVEN.'
    : '\nRESULT: rebuild incomplete — see issues above.');
  console.log('===========================================================');
}

await main().catch((err) => {
  console.error('\nFATAL:', err.stack || err.message);
  process.exit(1);
});
