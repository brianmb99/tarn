// One-shot prod test: register a throwaway account, send the recovery PDF
// via the deployed /api/v1/recovery/email endpoint, then delete the account.
// Sends ONE real email.
//
// Run: node tests/prod-email-check.mjs <recipient-email>

import { TarnClient } from '../client/src/tarn.js';

const API = 'https://api.tarn.dev';
const APP = 'bookish';
const recipient = process.argv[2];
if (!recipient) {
  console.error('Usage: node tests/prod-email-check.mjs <recipient-email>');
  process.exit(2);
}

const email = `prod-email-${Date.now()}@example.com`;
const password = 'prod-email-test-2026';

console.log(`Registering throwaway account ${email} ...`);
const client = new TarnClient(API, APP);
const reg = await client.register(email, password, {
  recoveryAcknowledged: true,
  emailRecoveryKit: false,  // we'll send manually below so we can branch on the response
  appName: 'Bookish',
});
console.log(`  ✓ registered, dataLookupKey=${reg.dataLookupKey.slice(0, 16)}...`);
console.log(`  ✓ phrase first 3 words: ${reg.recoveryPhrase.split(' ').slice(0, 3).join(' ')}...`);
console.log(`  ✓ pdfBytes: ${reg.pdfBytes.length} bytes`);

console.log(`\nForwarding recovery PDF to ${recipient} via /api/v1/recovery/email ...`);
try {
  await client.sendRecoveryKitEmail({
    recipientEmail: recipient,
    pdfBytes: reg.pdfBytes,
    appName: 'Bookish',
    subject: 'Tarn recovery email forwarder — prod test',
  });
  console.log('  ✓ /recovery/email returned 200 — relay accepted the request');
  console.log(`  → Check ${recipient} inbox (and spam) for an email with subject:`);
  console.log(`    "Tarn recovery email forwarder — prod test"`);
  console.log(`    Attachment: bookish-recovery-kit.pdf (${reg.pdfBytes.length} bytes)`);
} catch (err) {
  console.error(`  ✗ email send failed: ${err.message}`);
  console.log('Cleaning up account before exiting ...');
  await client.deleteAccount();
  process.exit(1);
}

console.log(`\nCleaning up test account ...`);
await client.deleteAccount();
console.log('  ✓ account deleted');
console.log('\nDone.');
