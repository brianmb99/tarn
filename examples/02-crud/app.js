import { TarnClient, TarnStorage } from 'tarn-client';
import { schema } from './schema.js';

async function maybeGrantLocalRules(apiBase, dlk) {
  if (!/^http:\/\/(localhost|127\.0\.0\.1)/.test(apiBase)) return;
  if (!dlk) return;
  const { execSync } = await import('node:child_process');
  const sql = `UPDATE accounts SET rules_json = '[]' WHERE data_lookup_key = '${dlk}'`;
  execSync(`npx wrangler d1 execute tarn-api --local --command "${sql}"`, {
    cwd: new URL('../../api', import.meta.url),
    stdio: 'pipe',
  });
}

const API_BASE = process.env.TARN_API ?? 'http://localhost:8787';
const APP_ID   = 'bookish';

const email    = `crud+${Date.now()}@example.com`;
const password = 'p@ssw0rd-example-02';

const tarn = await TarnClient.create({
  apiBase: API_BASE,
  appId:   APP_ID,
  schema,
  storage: TarnStorage.memory(),
});

console.log('Registering', email);
const reg = await tarn.register(email, password, {
  recoveryAcknowledged: true,
  emailRecoveryKit: false,
});

await maybeGrantLocalRules(API_BASE, reg.dataLookupKey);

// ============ books — full CRUD ============

console.log('\n[books] create');
await tarn.books.create({
  bookId: 'b1',
  title:  'The Snow Leopard',
  author: 'Peter Matthiessen',
  status: 'unread',
});
await tarn.books.create({
  bookId: 'b2',
  title:  'Mountains of the Mind',
  author: 'Robert Macfarlane',
  status: 'reading',
});

console.log('[books] list');
console.log(await tarn.books.list());

console.log('\n[books] get b1');
console.log(await tarn.books.get('b1'));

// Partial update — pass only what's changing.
console.log('\n[books] update b1 (partial)');
await tarn.books.update('b1', { rating: 5, status: 'done' });
console.log(await tarn.books.get('b1'));

// Schema validation catches typos and bad enums synchronously.
console.log('\n[books] schema validation');
try {
  await tarn.books.create({
    bookId: 'b3',
    title:  'Bad Status',
    status: 'half-finished',
  });
} catch (err) {
  console.log('  caught:', err.message);
}

console.log('\n[books] delete b2');
await tarn.books.delete('b2');
console.log('  remaining:', (await tarn.books.list()).map((b) => b.bookId));

// ============ settings — k/v with json values ============

console.log('\n[settings] create theme=dark');
await tarn.settings.create({ key: 'theme', value: 'dark' });

console.log('[settings] create flags=<json blob>');
await tarn.settings.create({
  key:   'flags',
  value: { betaUI: true, telemetry: false, releaseChannel: 'stable' },
});

console.log('[settings] update flags');
await tarn.settings.update('flags', {
  value: { betaUI: true, telemetry: false, releaseChannel: 'beta' },
});

console.log('[settings] list');
console.log(await tarn.settings.list());

console.log('\nDone. Account:', email);
