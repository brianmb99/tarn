import { TarnClient, TarnStorage } from 'tarn-client';
import { schema } from './schema.js';

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
await tarn.register(email, password, {
  recoveryAcknowledged: true,
  emailRecoveryKit: false,
});

console.log('Creating one note...');
await tarn.notes.create({
  noteId: 'n1',
  title:  'Hello, Tarn',
  body:   'My first encrypted record.',
});

const all = await tarn.notes.list();
console.log('Listed notes:', all);
