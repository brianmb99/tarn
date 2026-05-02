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

// Random suffix so re-runs don't collide on the email.
const email    = `hello+${Date.now()}@example.com`;
const password = 'p@ssw0rd-example-01';

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

// Local dev only: seed rules_json='[]' so writes aren't denied. In a real
// deployment the app server sets per-account rules after register (see
// tools/set-rules.mjs). Skipped automatically against non-local API bases.
await maybeGrantLocalRules(API_BASE, reg.dataLookupKey);

console.log('Creating one note...');
await tarn.notes.create({
  noteId: 'n1',
  title:  'Hello, Tarn',
  body:   'My first encrypted record.',
});

const all = await tarn.notes.list();
console.log('Listed notes:', all);
