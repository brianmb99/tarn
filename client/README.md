# Tarn Client

JavaScript client library for [Tarn](https://github.com/brianmb99/tarn) — permanent, encrypted, user-owned data on Arweave.

WebCrypto for everything except the password→master-key KDF, which uses Argon2id via [`hash-wasm`](https://www.npmjs.com/package/hash-wasm) (~29 KB minified, lazy-loaded WASM). Works in browsers and Node.js 15+.

## Quick Start

```javascript
import { TarnClient } from 'tarn-client';

const tarn = new TarnClient('https://api.tarn.dev', 'your-app-id');

// Register a new user. recoveryAcknowledged: true is required — the SDK
// generates a 24-word BIP39 recovery phrase and (by default) emails the
// rendered PDF to the user. Returns the phrase + PDF bytes so the caller
// can also offer a download or display.
const { dataLookupKey, recoveryPhrase, pdfBytes, emailDelivered } =
  await tarn.register('user@example.com', 'password', {
    recoveryAcknowledged: true,
    emailRecoveryKit: true,    // default
    appName: 'Bookish',        // optional, used in PDF + email branding
  });

// Login (any device, same email+password)
await tarn.login('user@example.com', 'password');

// Create encrypted data
await tarn.createEntry('note', { title: 'Hello', body: 'World' });

// Read + decrypt
const entries = await tarn.getEntries('note');
console.log(entries[0].data); // { title: 'Hello', body: 'World' }

// Update
await tarn.updateEntry(entries[0].txid, 'note', { title: 'Updated', body: 'Content' });

// Delete
await tarn.deleteEntry(entries[0].txid, 'note');
```

## App Setup

Before users can register, your app must be registered with Tarn.

### 1. Generate an app key pair

```bash
node tools/generate-app-key.mjs your-app-id
```

This prints:
- **Private key** (hex) — save this securely. You'll need it to manage user subscriptions.
- **Public key** (base64) — registered in Tarn's database.
- **D1 seed SQL** — run this to register your app.

**Save the private key in your password manager.** It is printed once and not stored.

### 2. Register the app in Tarn

Run the D1 seed command printed by the key generator:

```bash
# Local development
cd api && npx wrangler d1 execute tarn-api-cache --local --command "<printed SQL>"

# Production
cd api && npx wrangler d1 execute tarn-api-cache --remote --command "<printed SQL>"
```

### 3. Set the app key as an environment variable

```bash
# Local: add to api/.dev.vars
TARN_APP_KEY_YOURAPP=<private key hex>

# Production: Cloudflare Worker secret
wrangler secret put TARN_APP_KEY_YOURAPP
```

## Managing User Subscriptions

After a user registers, their account has no write rules (writes are denied by default). Your app must set rules to enable writes.

### Using the CLI tool

```bash
# Free tier (5 entries, 100KB max per entry)
node tools/set-rules.mjs \
  --api https://api.tarn.dev \
  --app your-app-id \
  --key <private key hex> \
  --dlk <user's data_lookup_key> \
  --plan free

# Annual subscription (1000 entries, expires in 1 year)
node tools/set-rules.mjs \
  --api https://api.tarn.dev \
  --app your-app-id \
  --key <private key hex> \
  --dlk <user's data_lookup_key> \
  --plan annual

# Custom rules
node tools/set-rules.mjs \
  --api https://api.tarn.dev \
  --app your-app-id \
  --key <private key hex> \
  --dlk <user's data_lookup_key> \
  --rules '[{"type":"max_entries","limit":50},{"type":"max_bytes","limit":102400}]'

# Unrestricted (empty rules = allow all)
node tools/set-rules.mjs ... --plan clear

# Deny all writes
node tools/set-rules.mjs ... --plan deny
```

### Available rule types

| Type | Fields | Description |
|------|--------|-------------|
| `max_entries` | `limit`, `since?`, `app?`, `entry_type?` | Max number of entries matching filters |
| `max_bytes` | `limit` | Max payload size per entry (bytes) |
| `expires` | `at` (ISO 8601) | Deny writes after this timestamp |

Rules are AND logic — all must pass. Unknown rule types fail closed (deny).

## Per-App Isolation

Each `TarnClient` is scoped to one app. The same email+password with different app IDs produces completely independent accounts — different keys, different data, no cross-app visibility.

```javascript
const bookish = new TarnClient('https://api.tarn.dev', 'bookish');
const cellar = new TarnClient('https://api.tarn.dev', 'cellar');

// Same user, completely isolated data
await bookish.register('user@example.com', 'password');
await cellar.register('user@example.com', 'password');
// These are two separate accounts with separate encryption keys
```

## Credential Management

```javascript
// Change email and/or password (requires active session — for routine reasons
// like email change). Optionally pass `phrase` to extend the recovery factor
// to the new generation; without it, the new generation is password-only and
// recovery for that gen requires running recoverAccount or regenerateRecoveryKit.
await tarn.changeCredentials('new@example.com', 'new-password', { phrase });

// Delete account permanently
await tarn.deleteAccount();
```

Credential changes re-wrap the existing data encryption keys under the new credentials and (for Argon2id accounts) append a fresh DEK at the next generation. Future writes use the new generation; existing data stays decryptable. The old credentials stop working immediately.

## Account Recovery

For users who have lost their password (or want a security-grade reset). Requires only the recovery phrase. Issues a JWT via the recovery factor's signing key, re-wraps the entire DEK chain under the new password + the same recovery factor, and publishes a fresh credential blob. All pre-recovery data is decryptable under the new credentials.

```javascript
// User-typed phrase + new credentials
const { dataLookupKey } = await tarn.recoverAccount({
  phrase: '24 words ...',
  newEmail: 'me@example.com',
  newPassword: 'fresh-password',
});

// Re-render the PDF for the same phrase (e.g., user lost the original)
const { pdfBytes, emailDelivered } = await tarn.regenerateRecoveryKit({
  phrase: '24 words ...',
  emailRecoveryKit: true,
  recipientEmail: 'me@example.com',
  appName: 'Bookish',
});

// Forward an already-rendered PDF (e.g., from registration) by email
await tarn.sendRecoveryKitEmail({
  recipientEmail: 'me@example.com',
  pdfBytes,
  appName: 'Bookish',
});
```

**Trust framing.** Tarn never persists the recovery phrase or the PDF. The API briefly sees the PDF in memory during the email-forwarder request (necessary to relay it). The honest claim is "no storage, brief in-memory visibility during forward" — not "Tarn never sees the bytes."

## Security Model

- **Client-side encryption.** All data is AES-256-GCM encrypted before leaving the client. The server never sees plaintext.
- **Argon2id key derivation.** Memory-hard KDF (m=64 MiB, t=3, p=1) for the password→master-key step. Sub-keys derived via HKDF-Expand (RFC 5869). Legacy accounts on PBKDF2-SHA256 (600K iters) continue to log in via a fallback path.
- **ECDSA P-256 auth.** Challenge-response signing. No passwords transmitted. Server stores only the public key.
- **Per-content CEK + forward-secret DEK rotation.** Each blob is encrypted with its own random CEK, wrapped under a generation-indexed DEK chain (RFC 3394 AES-KW). Credential changes append a fresh DEK to the chain so post-rotation writes are not decryptable by an attacker holding the old credentials.
- **Multi-factor DEK chain (v4 envelope).** Each chain entry is wrapped twice: once under a password-derived KEK, once under a phrase-derived KEK (Argon2id over the BIP39 recovery phrase). Either factor independently unwraps the DEK — recovery via phrase works without the password.
- **Arweave permanence.** Data stored permanently on Arweave. Encrypted blobs are publicly visible but unreadable without the key.

See [TARN_PROTOCOL.md](../docs/TARN_PROTOCOL.md) for the full protocol specification.

## API

### `new TarnClient(apiBaseUrl, appId)`

### `tarn.register(email, password, opts)` → `{ dataLookupKey, recoveryPhrase, pdfBytes, emailDelivered }`

`opts` is required and must include `recoveryAcknowledged: true` (the SDK enforces the design-doc requirement that recovery is mandatory at signup). Other fields: `emailRecoveryKit` (default `true`), `recipientEmail` (defaults to `email`), `appName` (PDF + email branding).

### `tarn.login(email, password)` → `{ dataLookupKey }`

### `tarn.recoverAccount({ phrase, newEmail, newPassword })` → `{ dataLookupKey }`

### `tarn.regenerateRecoveryKit({ phrase, emailRecoveryKit?, recipientEmail?, appName? })` → `{ pdfBytes, emailDelivered }`

### `tarn.sendRecoveryKitEmail({ recipientEmail, pdfBytes, appName?, subject? })` → `void`

### `tarn.createEntry(type, plaintext, extraTags?)` → `{ txid }`

### `tarn.batchCreate(type, items)` → `[{ txid, gateway }]`

Bulk import up to 100 entries in one request. Counts as 1 rate-limit hit. Each item is encrypted individually and gets its own txid on Arweave.

```javascript
const results = await tarn.batchCreate('entry', [
  { title: 'Book 1', author: 'Author 1' },
  { title: 'Book 2', author: 'Author 2' },
  // ... up to 100 items
]);
// results: [{ txid: '...', gateway: 'https://...' }, ...]
```

### `tarn.getEntries(type)` → `[{ txid, data, tags }]`

### `tarn.updateEntry(priorTxid, type, plaintext)` → `{ txid }`

### `tarn.deleteEntry(targetTxid, type)` → `{ txid }`

### `tarn.changeCredentials(newEmail, newPassword, opts?)`

`opts.phrase` (optional) extends the recovery factor to the new generation.

### `tarn.deleteAccount()`

## Sharing — Connections + mute filter

Tarn ships a mutual-connection sharing primitive: two users mutually agree (HPKE handshake, then a per-pair stealth-addressed encrypted log), after which either side can share content with the other. The full protocol is in [TARN_PROTOCOL.md](../docs/TARN_PROTOCOL.md) and [the sharing design doc](../notes/2026-04-28-tarn-sharing-design.md).

The connection surface:

```javascript
const { txid, requestNonce } = await tarn.sendConnectionRequest('bob@example.com');
// Bob, on his own client:
const incoming = await tarn.listIncomingRequests();
await tarn.acceptConnectionRequest(incoming[0].requestNonce);
// Both sides:
const connections = await tarn.listConnections();
const bob = connections.find(c => c.email === 'bob@example.com');

await tarn.shareContent(bob, contentId, txId, cekBase64Url);
await tarn.updateShareContent(bob, contentId, newTxId);
await tarn.unshareContent(bob, contentId);

const state = await tarn.readShareLog(bob);          // bootstrap
await tarn.syncShareLog(bob);                        // incremental

await tarn.removeConnection(bob);                    // §10.1 unfollow
await tarn.revokeContentFromConnections(contentId);  // §10.3 CEK rotation
```

### Mute / visibility

The connection primitive is symmetric. Apps that want a Strava-style "I follow you, you don't follow me" feel build it on top of the mutual primitive plus a per-side mute filter:

```javascript
await tarn.muteConnection(bob);          // hide Bob's content from my feed
await tarn.unmuteConnection(bob);
await tarn.listMutedConnections();       // [{ share_pub, muted_at }, ...]
const muted = await tarn.isMuted(bob);
```

Mute is **per-side, per-user** — set by the muting party, invisible to the muted party, no protocol-level effect. Persisted as an encrypted Tarn blob (`tarn-muted-connections-v1`) so the state syncs across the user's own devices.

`readShareLog` / `syncShareLog` do **not** short-circuit on muted connections. Apps still need access to muted-connection state programmatically (e.g., to render a "Muted" tab), so the SDK exposes the toggle via `isMuted` and lets apps decide when to filter at the call sites that should filter — typically the main feed:

```javascript
const visible = [];
for (const c of await tarn.listConnections()) {
  if (!(await tarn.isMuted(c))) visible.push(c);
}
```

### `tarn.dataLookupKey` — the user's data lookup key (available after register/login)

### `tarn.appId` — the app this client is scoped to

### `tarn.isAuthenticated` — whether a valid JWT exists
