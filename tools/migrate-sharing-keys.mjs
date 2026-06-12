// tools/migrate-sharing-keys.mjs — one-shot tarn#73 migration.
//
// Upgrades a pre-#73 account to envelope-carried sharing keys by performing
// a same-credentials changeCredentials(): mints the random sharing identity
// (X25519 + dedicated share-signing keypair), announces the §13.5 rotation
// to every connection from the legacy password-derived keys, republishes
// outbound share-log snapshots on the new pair keys, and writes the upgraded
// envelope. Run ONCE per account; safe to re-run (an already-migrated
// account is detected and skipped).
//
// Usage:
//   node --import tsx tools/migrate-sharing-keys.mjs <apiBase> <appId> <username> [--check]
//
//   <apiBase>   e.g. https://api.tarn.dev (or http://localhost:8787)
//   <appId>     e.g. bookish
//   <username>  the account's sign-in email/username
//   --check     dry-run: report migrated/unmigrated and exit without changes
//
// Prompts for the password and (unless --check) the 24-word account key —
// the new DEK generation the migration creates needs a recovery wrapping,
// exactly like any other credential change.
//
// NOTE: if the account has registered passkeys, they go STALE on the new
// generation (no PRF output available here) and self-repair on the next
// passkey sign-in via the stale-credential flow (password prompt). The
// script warns when it cannot rule this out.

import readline from 'node:readline';
import { TarnClient } from '../client/src/tarn.js';

function prompt(question, { mask = false } = {}) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    if (!mask) {
      rl.question(question, (answer) => { rl.close(); resolve(answer); });
      return;
    }
    // Masked input: suppress echo by intercepting output writes after the
    // question renders.
    const onData = () => {};
    rl.question(question, (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
    rl._writeToOutput = function (stringToWrite) {
      if (stringToWrite.includes(question)) {
        rl.output.write(question);
      } else {
        rl.output.write('*');
      }
    };
    void onData;
  });
}

const args = process.argv.slice(2);
const flags = args.filter(a => a.startsWith('--'));
const [apiBase, appId, username] = args.filter(a => !a.startsWith('--'));
if (!apiBase || !appId || !username) {
  console.error('Usage: node --import tsx tools/migrate-sharing-keys.mjs <apiBase> <appId> <username> [--check] [--accept-recovery-gap]');
  process.exit(1);
}
const checkOnly = flags.includes('--check');
// Throwaway/test accounts whose 24-word key was never kept can migrate with
// --accept-recovery-gap: the new DEK generation gets no recovery wrapping
// (same semantics as changeCredentials' acceptRecoveryGap). NEVER use this
// for a real account.
const acceptRecoveryGap = flags.includes('--accept-recovery-gap');

const password = await prompt(`Password for ${username}: `, { mask: true });
if (!password) {
  console.error('Password is required.');
  process.exit(1);
}

console.log(`\n[1/4] Signing in to ${apiBase} (app: ${appId})…`);
const client = new TarnClient(apiBase, appId);
await client.login(username, password, { allowUnmigratedSharing: true });

// Detect migration state via the documented public signal: login WITHOUT
// the migration flag succeeds only on migrated envelopes.
let migrated = false;
try {
  const probeClient = new TarnClient(apiBase, appId);
  await probeClient.login(username, password);
  migrated = true;
} catch (err) {
  if (err?.name === 'TarnSharingKeysMissingError') {
    migrated = false;
  } else {
    throw err;
  }
}

if (migrated) {
  console.log('[done] Account is already migrated — envelope carries the sharing identity. Nothing to do.');
  process.exit(0);
}
console.log('[2/4] Account is PRE-#73 (no envelope-carried sharing identity).');

if (checkOnly) {
  console.log('[check] Migration NEEDED. Re-run without --check to migrate.');
  process.exit(2);
}

let ccOpts;
if (acceptRecoveryGap) {
  console.warn('      --accept-recovery-gap: the new DEK generation will have NO account-key wrapping.');
  ccOpts = { acceptRecoveryGap: true };
} else {
  const phrase = await prompt('24-word account key (needed so the new DEK generation stays recoverable): ');
  if (!phrase || phrase.trim().split(/\s+/).length !== 24) {
    console.error('A 24-word account key is required. (Settings → Account & Security → View account key)');
    process.exit(1);
  }
  ccOpts = { phrase: phrase.trim() };
}

console.log('[3/4] Migrating: minting sharing identity, announcing §13.5 rotation to connections…');
const result = await client.changeCredentials(username, password, ccOpts);

const announced = result.rotationAnnouncements?.length ?? 0;
const failed = result.failedConnections ?? [];
console.log(`      rotation announcements published: ${announced}`);
if (failed.length > 0) {
  console.warn(`      WARNING — ${failed.length} connection(s) could not be reached:`);
  for (const f of failed) console.warn(`        - ${JSON.stringify(f)}`);
  console.warn('      Re-run announce later via the SDK: tarn.reannounceRotationToConnections()');
}

console.log('[4/4] Verifying: fresh login must hydrate the sharing identity…');
const verify = new TarnClient(apiBase, appId);
await verify.login(username, password); // throws TarnSharingKeysMissingError if migration failed
console.log('\n[done] Migration complete. Friends will pick up the new identity on their next sync.');
process.exit(0);
