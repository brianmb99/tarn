# Tarn Client

JavaScript client library for the Tarn protocol. Handles key derivation, encryption, and API interaction.

```javascript
import { TarnClient } from './src/tarn.js';

const tarn = new TarnClient('https://api.tarn.dev');

// Register
await tarn.register('user@example.com', 'password');

// Login (on another device)
await tarn.login('user@example.com', 'password');

// CRUD
await tarn.createEntry('myapp', 'note', { title: 'Hello', body: 'World' });
const entries = await tarn.getEntries('myapp', 'note');
```

See `docs/TARN_PROTOCOL.md` for the protocol spec.
