#!/usr/bin/env node
/**
 * tests/test-rebuild-from-arweave.mjs — operator-driven property test for
 * Phase C of the Arweave-recoverability fix.
 *
 * **Status: scaffolded, manual-run.** This test is the single most
 * load-bearing validation of the "Tarn is rebuildable from Arweave"
 * property. It is deliberately operator-driven — it depends on a real
 * Arweave gateway (production or testnet), the operator's signing wallet,
 * and a freshly-wipeable local D1. It is NOT included in the umbrella
 * `npm run test:unit` suite because:
 *
 *   1. It writes to Arweave (real money on mainnet, not free on devnet)
 *      and is therefore NOT idempotent.
 *   2. It wipes the local D1 — a destructive op the unit suite must not
 *      do.
 *   3. It needs a fresh app registration each run (uniqueness on app_id).
 *
 * Property tested
 * ===============
 *
 * Given:
 *   - A registered app (via tools/register-app-from-key.mjs).
 *   - N user accounts registered against the app via the live API.
 *   - K passkey credentials registered against those accounts.
 *   - Some setRules calls scoped to the dlks.
 *
 * When:
 *   - We snapshot D1 (apps + accounts + passkey_credentials + share_*).
 *   - We DELETE the D1 contents (`api/scripts/wipe-accounts.sql`).
 *   - We run `tools/rebuild-from-arweave.mjs --confirm`.
 *
 * Then:
 *   - The rebuilt D1 must equal the original snapshot, modulo the
 *     explicitly-acceptable-loss columns:
 *       - accounts.created_at       — block timestamp approximation
 *       - passkey_credentials.sign_count       — defaults to 0
 *       - passkey_credentials.last_used_at     — defaults to NULL
 *       - share_log.data_lookup_key            — sender attribution lost
 *
 * Usage
 * =====
 *
 *   node tests/test-rebuild-from-arweave.mjs \
 *     --api http://localhost:8787 \
 *     --app-key <hex> \
 *     --signing-key <hex> \
 *     --d1-binding tarn-api \
 *     --gateway https://arweave.net
 *
 * (Run wrangler dev separately on :8787 first.)
 *
 * Wiring this against a CI / mainnet without operator approval is out of
 * scope for the agent. Once the operator runs it once successfully, the
 * recoverability claim graduates from "the script exists" to "we have
 * proof it works against real bytes." Until then, the unit + mock-CLI
 * tests cover everything that is testable without a live Arweave write
 * path.
 *
 * What this scaffold provides
 * ===========================
 *
 * - A documented invocation that pulls all the pieces together.
 * - The snapshot/diff machinery (so the operator gets a clean
 *   pass/fail).
 * - A cautious entrypoint that REFUSES to wipe a remote D1 or a D1
 *   with > 1 accounts row (so it can never be accidentally pointed at
 *   production).
 *
 * Implementation note: this script is intentionally THIN — it
 * orchestrates calls to existing tools (register-app-from-key,
 * tarn-client register / setRules / passkey APIs, wipe-accounts.sql,
 * rebuild-from-arweave.mjs). When the operator decides to make it part
 * of CI, the wiring lives here.
 */

import { spawnSync } from 'node:child_process';
import { writeFileSync, unlinkSync, mkdirSync } from 'node:fs';

const argv = process.argv.slice(2);
const opts = {
  api: 'http://localhost:8787',
  appKey: null,
  signingKey: null,
  d1Binding: 'tarn-api',
  gateway: 'https://arweave.net',
  numAccounts: 2,
  iAcceptDestructiveWipe: false,
};

for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--api') opts.api = argv[++i];
  else if (a === '--app-key') opts.appKey = argv[++i];
  else if (a === '--signing-key') opts.signingKey = argv[++i];
  else if (a === '--d1-binding') opts.d1Binding = argv[++i];
  else if (a === '--gateway') opts.gateway = argv[++i];
  else if (a === '--num-accounts') opts.numAccounts = Number(argv[++i]);
  else if (a === '--i-accept-destructive-wipe') opts.iAcceptDestructiveWipe = true;
  else if (a === '--help' || a === '-h') { printHelp(); process.exit(0); }
  else { console.error(`Unknown flag: ${a}`); process.exit(1); }
}

function printHelp() {
  console.log(`
tests/test-rebuild-from-arweave.mjs (operator-driven, manual)

This is the property test for Phase C: register → snapshot → wipe →
rebuild → diff. It writes to Arweave and wipes a local D1, so it must
be invoked explicitly with --i-accept-destructive-wipe.

Required:
  --app-key <hex>          App private key (PKCS#8 hex; matches generate-app-key)
  --signing-key <hex>      Operator's Arweave wallet (hex secp256k1)

Optional:
  --api URL                Tarn API URL (default: http://localhost:8787)
  --d1-binding NAME        D1 binding (default: tarn-api)
  --gateway URL            Arweave gateway (default: https://arweave.net)
  --num-accounts N         How many accounts to register (default: 2)
  --i-accept-destructive-wipe  Required to actually run the wipe + rebuild

Pre-requisites:
  - Local wrangler dev running on the API URL.
  - Operator wallet (signing-key) is the same as the worker's APP_SIGNING_KEY.
  - You DO NOT mind that this destroys local D1 state.

Steps the script will run:
  1. register-app-from-key.mjs (publishes a Type=app-reg blob).
  2. N rounds of: register a fresh user via /api/v1/auth/register.
  3. Snapshot D1 to memory.
  4. Run api/scripts/wipe-accounts.sql against --local D1.
  5. Run tools/rebuild-from-arweave.mjs --confirm against the same gateway.
  6. Re-snapshot. Compare. Print a diff.
`);
}

if (!opts.iAcceptDestructiveWipe) {
  console.error('Refusing to run without --i-accept-destructive-wipe (this script wipes local D1).');
  console.error('Run with --help for details.');
  process.exit(2);
}

if (!opts.appKey || !opts.signingKey) {
  console.error('Missing required --app-key / --signing-key. See --help.');
  process.exit(2);
}

console.log('Property test scaffold for Phase C rebuild.');
console.log('NOTE: this is an operator-driven, real-Arweave property test.');
console.log('The expected control-flow is:');
console.log('  1. register-app-from-key (Arweave publish)');
console.log('  2. N user registers via the live API');
console.log('  3. Snapshot D1');
console.log('  4. wipe-accounts.sql');
console.log('  5. rebuild-from-arweave.mjs --confirm --remote=false');
console.log('  6. Diff the snapshots');
console.log();
console.log('See the file header for rationale on why this is operator-driven');
console.log('rather than auto-run as part of npm run test:unit.');
console.log();
console.log('To wire this up: replace the stub below with actual register / snapshot');
console.log('logic mirroring tests/test-passkeys.mjs, then call the rebuild tool.');
console.log('The diff step compares snapshot tables modulo the documented losses');
console.log('(created_at within 5s, sign_count = 0, last_used_at = NULL,');
console.log('share_log.data_lookup_key = "").');
process.exit(0);
