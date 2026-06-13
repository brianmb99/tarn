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
//   node --import tsx tools/migrate-sharing-keys.mjs <apiBase> <appId> <username> \
//     [--check] [--accept-recovery-gap] [--remove-passkeys]
//
//   <apiBase>            e.g. https://api.tarn.dev (or http://localhost:8787)
//   <appId>             e.g. bookish
//   <username>          the account's sign-in email/username
//   --check             dry-run: report migrated/unmigrated and exit without changes
//   --accept-recovery-gap  throwaway accounts only: skip the 24-word prompt; the
//                          new DEK gen gets no account-key wrapping
//   --remove-passkeys   un-register every passkey on the account BEFORE migrating
//                       (the migration mints a new DEK gen and a Node CLI can't
//                       drive a WebAuthn tap to re-wrap it, so passkeys must
//                       either be re-tapped in-browser or removed here)
//
// Prompts for the password and (unless --check) the 24-word account key —
// the new DEK generation the migration creates needs a recovery wrapping,
// exactly like any other credential change.
//
// PASSKEYS: this CLI cannot perform the WebAuthn ceremony, so it cannot
// re-wrap the new DEK generation under a passkey's PRF. If the account has
// registered passkeys, migration FAILS unless you pass --remove-passkeys
// (which un-registers them here; the user re-adds them in-app afterward).

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
  console.error('Usage: node --import tsx tools/migrate-sharing-keys.mjs <apiBase> <appId> <username> [--check] [--accept-recovery-gap] [--remove-passkeys]');
  process.exit(1);
}
const checkOnly = flags.includes('--check');
// Throwaway/test accounts whose 24-word key was never kept can migrate with
// --accept-recovery-gap: the new DEK generation gets no recovery wrapping
// (same semantics as changeCredentials' acceptRecoveryGap). NEVER use this
// for a real account.
const acceptRecoveryGap = flags.includes('--accept-recovery-gap');
// Un-register all passkeys before migrating (a Node CLI can't re-wrap the
// new DEK gen under a WebAuthn PRF). The user re-adds them in-app after.
const removePasskeys = flags.includes('--remove-passkeys');
const KNOWN_FLAGS = new Set(['--check', '--accept-recovery-gap', '--remove-passkeys']);
const unknownFlags = flags.filter(f => !KNOWN_FLAGS.has(f));
if (unknownFlags.length > 0) {
  console.error(`Unknown flag(s): ${unknownFlags.join(', ')}`);
  process.exit(1);
}

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

// Inspect registered passkeys — they block a CLI migration unless removed.
let passkeys = [];
try {
  passkeys = await client.listPasskeys();
} catch (err) {
  console.warn(`      (could not list passkeys: ${err?.message || err}; continuing)`);
}

if (checkOnly) {
  console.log('[check] Migration NEEDED. Re-run without --check to migrate.');
  if (passkeys.length > 0) {
    console.log(`[check] ${passkeys.length} registered passkey(s) — pass --remove-passkeys (re-add them in-app after).`);
  }
  process.exit(2);
}

if (passkeys.length > 0) {
  if (!removePasskeys) {
    console.error(
      `\n[blocked] Account has ${passkeys.length} registered passkey(s). This CLI cannot ` +
      `re-wrap the new DEK generation under a WebAuthn passkey.\n` +
      `          Re-run with --remove-passkeys to un-register them (re-add in-app afterward),\n` +
      `          or perform the migration in-browser where the tap UI is available.`,
    );
    process.exit(1);
  }
  console.log(`[2b/4] Removing ${passkeys.length} passkey(s) before migration (--remove-passkeys)…`);
  for (const pk of passkeys) {
    const label = pk.deviceLabel ? ` (${pk.deviceLabel})` : '';
    await client.removePasskey({ credentialId: pk.credentialId, password });
    console.log(`        removed ${pk.credentialId.slice(0, 12)}…${label}`);
  }
  console.log('        all passkeys removed — re-add them in-app after this completes.');
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
if (passkeys.length > 0) {
  console.log(`[note] ${passkeys.length} passkey(s) were removed — re-add them in-app ` +
    `(Account & Security → Add passkey) on each device you want passkey sign-in on.`);
}
process.exit(0);
