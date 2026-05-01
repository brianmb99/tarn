/**
 * Sender side of the connection + sharing example.
 *
 * Flow:
 *   1. Register a fresh Tarn account.
 *   2. Create a few books.
 *   3. Generate a single-use invite token + URL. Print it for the recipient.
 *   4. Poll until the recipient redeems and the connection auto-accepts.
 *   5. Share-with-all, so the new connection sees every book.
 *
 * The auto-accept happens inside the underlying client's listIncomingRequests
 * (it processes the inbox each call, auto-accepting requests whose token
 * matches an issued invite). Until the typed namespace exposes a method for
 * this, we hold a reference to the underlying and poll it directly.
 */

// Note: this example uses the explicit `underlying` factory to keep a
// reference to the protocol-layer client. The typed `tarn.connections.*`
// namespace doesn't yet expose a method that triggers the inbox poll
// (where redeemed-invite auto-accepts happen). The reference lets us
// call `listIncomingRequests()` directly. This goes away once that
// method lands on `tarn.connections`.
import { TarnClient, TarnStorage, _LegacyTarnClient } from 'tarn-client';
import { schema } from './schema.js';

const API_BASE = process.env.TARN_API ?? 'http://localhost:8787';
const APP_ID   = 'bookish';

const email    = `sender+${Date.now()}@example.com`;
const password = 'p@ssw0rd-example-03-sender';

// Hold a reference to the underlying so we can call listIncomingRequests().
let underlyingRef = null;

const tarn = await TarnClient.create({
  apiBase: API_BASE,
  appId:   APP_ID,
  schema,
  storage: TarnStorage.memory(),
  underlying: (api, app) => {
    underlyingRef = new _LegacyTarnClient(api, app);
    return underlyingRef;
  },
});

console.log('[sender] registering', email);
await tarn.register(email, password, {
  recoveryAcknowledged: true,
  emailRecoveryKit: false,
});

console.log('[sender] creating books');
const titles = [
  ['b1', 'The Snow Leopard',       'Peter Matthiessen'],
  ['b2', 'Mountains of the Mind',  'Robert Macfarlane'],
  ['b3', 'Annapurna',              'Maurice Herzog'],
];
for (const [bookId, title, author] of titles) {
  await tarn.books.create({ bookId, title, author });
}
console.log('[sender] library:', (await tarn.books.list()).map((b) => b.title));

console.log('\n[sender] creating invite token');
const invite = await tarn.connections.createInvite({
  display_name: 'Sender',
  expiry_days:  1,
});
console.log('  token_id:   ', invite.token_id);
console.log('  invite_url: ', invite.invite_url);

console.log('\n=========================================================');
console.log('Run the recipient with this URL:');
console.log(`  TARN_INVITE_URL='${invite.invite_url}' node recipient.js`);
console.log('=========================================================\n');

console.log('[sender] polling for redemption (Ctrl-C to abort)...');
const start = Date.now();
const TIMEOUT_MS = 5 * 60 * 1000;
let connection = null;

while (Date.now() - start < TIMEOUT_MS) {
  // Trigger the inbox poll on the underlying client. Side effect: if a
  // connection-request matching an issued invite has arrived, auto-accept.
  try {
    await underlyingRef.listIncomingRequests();
  } catch (err) {
    console.warn('[sender] poll failed:', err.message);
  }
  const conns = await tarn.connections.list();
  if (conns.length > 0) {
    connection = conns[0];
    break;
  }
  await new Promise((r) => setTimeout(r, 2000));
}

if (!connection) {
  console.error('[sender] timed out waiting for redemption');
  process.exit(1);
}

console.log('[sender] connected to', connection.label ?? '(no label)');
console.log('[sender] sharing all books with the new connection');
const result = await tarn.books.shareWithAll('b1');
console.log('  b1 shareWithAll:', result);
const r2 = await tarn.books.shareWithAll('b2');
console.log('  b2 shareWithAll:', r2);
const r3 = await tarn.books.shareWithAll('b3');
console.log('  b3 shareWithAll:', r3);

console.log('\n[sender] done. Recipient can now run listShared.');
