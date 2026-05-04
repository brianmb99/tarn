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

// ============ notes — full CRUD ============

console.log('\n[notes] create');
await tarn.notes.create({
  noteId: 'n1',
  title:  'Quarterly review prep',
  body:   'Pull metrics, draft talking points, share deck by Friday.',
  status: 'draft',
});
await tarn.notes.create({
  noteId: 'n2',
  title:  'Refactor the share-log cache',
  body:   'Move per-pair derivations into a single LRU keyed on share_pub.',
  status: 'active',
});

console.log('[notes] list');
console.log(await tarn.notes.list());

console.log('\n[notes] get n1');
console.log(await tarn.notes.get('n1'));

// Partial update — pass only what's changing.
console.log('\n[notes] update n1 (partial)');
await tarn.notes.update('n1', { priority: 5, status: 'archived' });
console.log(await tarn.notes.get('n1'));

// Schema validation catches typos and bad enums synchronously.
console.log('\n[notes] schema validation');
try {
  await tarn.notes.create({
    noteId: 'n3',
    title:  'Bad Status',
    status: 'in-progress',
  });
} catch (err) {
  console.log('  caught:', err.message);
}

console.log('\n[notes] delete n2');
await tarn.notes.delete('n2');
console.log('  remaining:', (await tarn.notes.list()).map((n) => n.noteId));

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
