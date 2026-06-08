// Typed-path sharing integration test (the layer that actually broke).
//
// The low-level test-share-log.mjs exercises the core
// _publishShareLogEntry / readShareLog path. THIS test drives the *typed*
// surface — `TarnClient.create({ schema })` → `tarn.<collection>.shareWithAll`
// (sender) and `tarn.<collection>.listShared(connection)` (recipient) — which
// is what apps (Bookish) actually call.
//
// Regression: a connected friend could not see shared content. Sender's
// shareWithAll reported {ok:1, failed:[]}; recipient's listShared returned [].
//
// Run: cd api && npx wrangler dev --port 8787 (in another terminal)
//      node --import tsx tests/test-share-typed.mjs [baseUrl]

import { TarnClient as TypedTarnClient, defineSchema, TarnStorage } from '../client/src/index.js';
import {
  seedTestApp, DEFAULT_APP_ID, randomUsername, forceAllowRulesForAccount, sleep,
} from './helpers.mjs';

const BASE_URL = process.argv[2] || 'http://localhost:8787';

await seedTestApp(DEFAULT_APP_ID);

let passed = 0;
let failed = 0;
const failures = [];

function log(status, name, detail = '') {
  const icon = status === 'PASS' ? '✓' : '✗';
  console.log(`  ${icon} ${name}${detail ? ': ' + detail : ''}`);
}

async function test(name, fn) {
  try {
    await fn();
    log('PASS', name);
    passed++;
  } catch (err) {
    log('FAIL', name, err.message);
    failed++;
    failures.push({ name, err });
    if (process.env.VERBOSE) console.error('    ', err.stack);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function makeSchema() {
  return defineSchema({
    appId: DEFAULT_APP_ID,
    version: 1,
    collections: {
      books: {
        primaryKey: 'bookId',
        fields: {
          bookId: 'string',
          title: 'string',
          author: 'string?',
        },
        shareable: true,
      },
    },
  });
}

async function makeTypedClient() {
  return await TypedTarnClient.create({
    apiBase: BASE_URL,
    appId: DEFAULT_APP_ID,
    schema: makeSchema(),
    storage: TarnStorage.memory(),
  });
}

console.log('\n=== Typed shareWithAll -> listShared (the bug) ===');

const senderUsername = randomUsername();
const senderPassword = 'pw-sender-' + Date.now();
const recipientUsername = randomUsername();
const recipientPassword = 'pw-recipient-' + Date.now();

const sender = await makeTypedClient();
const recipient = await makeTypedClient();

let senderConnOfRecipient; // the recipient as seen from the sender (sender writes to this)
let recipientConnOfSender; // the sender as seen from the recipient (recipient reads this)

await test('register both users (typed surface)', async () => {
  const s = await sender.register(senderUsername, senderPassword, { recoveryAcknowledged: true });
  await forceAllowRulesForAccount(s.dataLookupKey);
  const r = await recipient.register(recipientUsername, recipientPassword, { recoveryAcknowledged: true });
  await forceAllowRulesForAccount(r.dataLookupKey);
});

await test('handshake: sender invites, recipient accepts (typed connections namespace)', async () => {
  const send = await sender.connections.invite(recipientUsername);
  await sleep(300);
  const incoming = await recipient.connections.listIncomingRequests();
  const req = incoming.find(r => r.request_nonce === send.requestNonce);
  assert(req, 'recipient did not see the connection request');
  await recipient.connections.accept(req.request_nonce);
  await sleep(300);
  // Sender processes the accept (publishes its own seq=0 snapshot).
  await sender.connections.listIncomingRequests();

  const senderConns = await sender.connections.list();
  senderConnOfRecipient = senderConns.find(c => c.username === recipientUsername);
  assert(senderConnOfRecipient, 'recipient not in sender connections');

  const recipientConns = await recipient.connections.list();
  recipientConnOfSender = recipientConns.find(c => c.username === senderUsername);
  assert(recipientConnOfSender, 'sender not in recipient connections');
});

await test('sender creates a book in the typed collection', async () => {
  await sender.books.create({ bookId: 'b1', title: 'The Mountain', author: 'A. Climber' });
  await sleep(300);
});

// The live-repro trigger: a real app (Bookish) polls listShared on app-open,
// BEFORE the sender shares anything. That first read caches an empty state.
// listShared → readShareLog WITHOUT refresh, so every subsequent call returns
// the stale cached empty map and the freshly-shared book is never surfaced.
await test('recipient.books.listShared is empty BEFORE the share (seeds the cache)', async () => {
  const sharedBefore = await recipient.books.listShared(recipientConnOfSender);
  assert(Array.isArray(sharedBefore), 'listShared should return an array');
  assert(sharedBefore.length === 0, `expected 0 shared books pre-share, got ${sharedBefore.length}`);
});

await test('sender.books.shareWithAll reports SUCCESS', async () => {
  const res = await sender.books.shareWithAll('b1');
  assert(res.ok === 1, `expected ok:1, got ok:${res.ok} failed:${JSON.stringify(res.failed)}`);
  assert(res.failed.length === 0, `expected no failures, got ${JSON.stringify(res.failed)}`);
});

await test('recipient.books.listShared SEES the shared book (the regression)', async () => {
  await sleep(300);
  const shared = await recipient.books.listShared(recipientConnOfSender);
  assert(Array.isArray(shared), 'listShared should return an array');
  assert(shared.length === 1, `expected 1 shared book, got ${shared.length}: ${JSON.stringify(shared)}`);
  assert(shared[0].bookId === 'b1', `expected bookId b1, got ${shared[0]?.bookId}`);
  assert(shared[0].title === 'The Mountain', `title mismatch: ${shared[0]?.title}`);
});

await test('cleanup', async () => {
  await sender.account.delete();
  await recipient.account.delete();
});

console.log('\n=== Summary ===');
console.log(`  Passed: ${passed}`);
console.log(`  Failed: ${failed}`);
if (failed > 0) {
  console.log('\nFailed tests:');
  for (const { name, err } of failures) {
    console.log(`  - ${name}: ${err.message}`);
  }
  process.exit(1);
}
process.exit(0);
