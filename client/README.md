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

## Session lifecycle

Tarn ships two complementary primitives for keeping users logged in across page reloads and across multiple devices.

### Persistence (single device, "remember me")

Opt-in. By default `new TarnClient(...)` + `login()` keeps everything in memory and the user re-enters their password on every tab. To persist, ask the SDK for an opaque blob and store it (typically in `localStorage`):

```javascript
const blob = await tarn.serializeSession();
localStorage.setItem('tarn-session', blob);

// Later, on a fresh page load:
const stored = localStorage.getItem('tarn-session');
const tarn = await TarnClient.resumeSession('https://api.tarn.dev', 'your-app-id', stored);
if (!tarn) {
  // Expired, tampered, or this is a different origin — fall back to login UI.
}

await tarn.clearSession();   // explicit logout: wipes the on-device wrapping key
```

The blob is encrypted under an AES-256-GCM key stored in IndexedDB with `extractable: false` — even an XSS on the origin cannot exfiltrate the raw key for offline replay. Hard 7-day max age, no refresh-on-use. `changeCredentials`, `recoverAccount`, and `deleteAccount` rotate the wrapping key as a side effect, so any persisted blob from before the rotation becomes unreadable.

**Threat-model note.** Persistence is a real escalation of same-origin XSS — an attacker with code execution on the origin gains pseudo-persistent access (up to 7 days) rather than session-only access. Apps with stricter postures should not opt in. See [TARN_PROTOCOL.md § Session persistence](../docs/TARN_PROTOCOL.md#session-persistence-section-7-issue-19) for the full breakdown.

### Server-side sessions (multi-device, "Manage devices")

Every `/auth/verify` issues a JWT carrying a `sid` claim backed by a server-side row. Apps can list active sessions and revoke them individually — the right primitive for a Settings → Manage devices page:

```javascript
// List sessions for the current account.
const sessions = await tarn.listSessions();
// [{ sid, createdAt, lastSeenAt, deviceLabel, viaRecovery, isCurrent }, ...]

// Revoke another device.
await tarn.revokeSession(sessions[1].sid);

// "Sign out everywhere except here".
await tarn.revokeOtherSessions();

// "Sign out everywhere including here". The SDK clears the persisted blob too.
await tarn.revokeAllSessions();
```

Apps can attach a human-readable `deviceLabel` at login time (`tarn.login(email, password, { deviceLabel: 'Chrome on MacBook' })` — also accepted on `register` and `recoverAccount`) which surfaces on `listSessions` so users can tell their devices apart.

Stateful auth: every authenticated request validates the `sid` against the server-side table, so revocation propagates within ~5 seconds (a short in-Worker isolate cache amortizes the D1 read). `changeCredentials` and `recoverAccount` revoke every OTHER session for the account but preserve the calling one — the SDK still has follow-up rotation announcements to publish under the same JWT before re-authenticating.

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

### Publicly observable metadata

Tarn protects content end-to-end, but a few metadata properties are visible to anyone who can derive them from public info. Apps building on Tarn should be honest with users about these:

- **Connection-request inbox volume + timing** is publicly observable to anyone who knows a user's `share_pub`. The `GET /api/v1/share/inbox/fetch` endpoint is unauthenticated by design (recipients on a fresh device need to poll without a JWT yet). The blobs at the inbox tag stay HPKE-encrypted, but their existence + timing is extractable. Bookish-class use is fine; sensitive contexts should consider `share_discoverable: false`.
- **Account existence via discoverability lookup** — a `share_discoverable: true` account leaks "this email is a Tarn user" to anyone who runs the email→share_pub lookup.
- **Once connected, all subsequent share-log traffic is unlinkable** — the per-pair tags are stealth-addressed; an Arweave observer cannot extract the connection graph from the protocol alone.

See [TARN_PROTOCOL.md § Publicly observable metadata](../docs/TARN_PROTOCOL.md#publicly-observable-metadata) for the full breakdown.

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

### `tarn.serializeSession()` → `string` (opaque base64url ciphertext)

Persistence opt-in. See [Session lifecycle](#session-lifecycle).

### `TarnClient.resumeSession(apiBase, appId, blob)` → `TarnClient | null`

Static. Returns null on expired / tampered / wrong-origin / schema-mismatch — never throws on a bad blob.

### `tarn.clearSession()`

Wipes the on-device wrapping key. Renders all previously-emitted blobs unreadable on this origin.

### `tarn.listSessions()` → `[{ sid, createdAt, lastSeenAt, deviceLabel, viaRecovery, isCurrent }]`

### `tarn.revokeSession(sid)` / `tarn.revokeAllSessions()` / `tarn.revokeOtherSessions()`

### `tarn.createInviteToken({ display_name?, expiry_days? })` → `{ token_id, invite_url, expires_at }`

### `TarnClient.previewInviteToken(apiBase, appId, token_id, payloadKey)` → `{ inviter_display_name, inviter_share_pub_fingerprint, app_id, issued_at, expires_at } | null`

Static. Unauthenticated — the recipient may not have a Tarn account yet at preview time.

### `tarn.redeemInviteToken(token_id, payloadKey)` → `Connection`

Authenticated. Atomically marks the token used server-side, sends the connection-request handshake.

### `tarn.listIssuedInvites()` / `tarn.revokeIssuedInvite(token_id)`

### `tarn.setConnectionLabel(connection, label)`

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

Each `Connection` carries an optional `label` that apps can use as a nickname / display name. Set at accept time or later:

```javascript
await tarn.acceptConnectionRequest(nonce, { label: 'Maya' });
await tarn.setConnectionLabel(connection, 'Maya from book club');
// listConnections() entries now include `label: string | null`.
```

Labels are local to the labeling user — the labeled party doesn't see what they were tagged. Persisted in the same encrypted connections record blob that syncs across the user's own devices.

### Invite tokens — connection bootstrap by link or QR

Email-based handshake (above) requires the sender to know the recipient's email AND the recipient to be a Tarn user with `share_discoverable: true`. For consumer-app UX where neither holds — "scan this QR to add me", "send my invite link in Slack", "register and click my invite" — Tarn ships an opaque single-use invite-token primitive.

```javascript
// 1. Inviter — generate a link.
const { token_id, invite_url, expires_at } = await tarn.createInviteToken({
  display_name: 'Maya',
  expiry_days: 7,        // default 7, server max 30
});
// invite_url is something like
//   https://app.bookish.example/invite/<token_id>#<base64url payload_key>
// Share it via QR / messenger / email / etc.

// 2. Recipient app handler at the URL — extract token_id (path) + key (URL fragment).
const tokenId = window.location.pathname.split('/').pop();
const payloadKey = window.location.hash.slice(1);

// Optional preview before login (unauthenticated path — recipient may not have an account yet).
const preview = await TarnClient.previewInviteToken(API_BASE, APP_ID, tokenId, payloadKey);
// { inviter_display_name, inviter_share_pub_fingerprint, app_id, issued_at, expires_at }

// 3. Recipient redeems (after register/login if needed).
await tarn.redeemInviteToken(tokenId, payloadKey);

// 4. Inviter — on next listIncomingRequests(), the SDK auto-accepts requests
//    whose token matches an issued invite. The new connection's label is
//    seeded from the inviter's display_name.

// Issued-invites surface (inviter side):
const outstanding = await tarn.listIssuedInvites();
await tarn.revokeIssuedInvite(token_id);
```

How it composes: redemption produces a normal connection-request HPKE-sealed back to the inviter, with an extra `via_invite_token` field. The inviter's SDK auto-accepts on its next poll. The end state is a regular connection — same record shape, same share-log mechanics, same mute / remove primitives. Apps consuming `listConnections()` cannot tell which path was used.

Privacy posture: the URL fragment carries the AES-256-GCM payload key and is never transmitted to the API (browsers don't send fragments). The Tarn server stores opaque ciphertext keyed on `token_id` and never sees the inviter's `share_pub`, signing key, or display name. Server learns metadata: `(inviter_dlk, time_of_issuance, redemption_time, redeemer_share_pub_fingerprint, redemption_IP)`. See [TARN_PROTOCOL.md § Invite tokens](../docs/TARN_PROTOCOL.md#invite-tokens-section-8-issue-22) for the full threat model.

App-hosted URLs: each registered app declares its own `invite_url_template` (e.g. `https://app.bookish.example/invite/{token_id}`) — Tarn does not host any landing page. The app's web handler reads the path + hash, calls the SDK, and renders whatever UX it wants.

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

## Integration patterns

This section captures patterns that come up when building real apps on Tarn — particularly useful for agentic dev tools that need a clear contract for each operation.

### Full lifecycle example

```javascript
import { TarnClient } from 'tarn-client';

const tarn = new TarnClient('https://api.tarn.dev', 'your-app-id');

// 1. New user signs up. The SDK generates a 24-word phrase + PDF and (by
//    default) emails the PDF. Caller gets the phrase + PDF in-memory too —
//    DO NOT persist either; hand off to the user and drop.
const reg = await tarn.register('sara@example.com', 'p@ssw0rd', {
  recoveryAcknowledged: true,  // REQUIRED — UI must surface the phrase
  emailRecoveryKit: true,
  appName: 'Bookish',
});
// reg.recoveryPhrase is a 24-word string; reg.pdfBytes is a Uint8Array.

// 2. User creates content.
const { txid } = await tarn.createEntry('book', { title: 'Mountains', read_at: Date.now() });

// 3. Later: user adds a connection.
await tarn.sendConnectionRequest('alice@example.com');
// Alice accepts on her end → tarn.acceptConnectionRequest(...)

// 4. Sara shares the book with Alice. CEK is in Sara's outbound state cache
//    after the createEntry call; the SDK pulls it automatically.
const alice = (await tarn.listConnections()).find(c => c.email === 'alice@example.com');
await tarn.shareContent(alice, 'book-mountains', txid, /*cek*/ undefined);

// 5. Alice, on her own client, reads what Sara has shared.
const aliceTarn = new TarnClient('https://api.tarn.dev', 'your-app-id');
await aliceTarn.login('alice@example.com', 'alice-password');
const sara = (await aliceTarn.listConnections()).find(c => c.email === 'sara@example.com');
const state = await aliceTarn.readShareLog(sara);
// state is { 'book-mountains': { tx_id, cek }, ... }

// 6. Sara loses her password. She enters her phrase to recover.
const recovery = new TarnClient('https://api.tarn.dev', 'your-app-id');
await recovery.recoverAccount({
  phrase: reg.recoveryPhrase,
  newEmail: 'sara@example.com',  // can be the same or different
  newPassword: 'new-password',
});
// All her data + connections are still there. Alice's client picks up the
// rotation announcement on next syncShareLog and updates Sara's keys
// transparently.
```

### Error handling

Tarn methods throw on failure. Common error categories:

- **Validation errors** (synchronous, no network): `register` throws if `recoveryAcknowledged !== true`; `acceptConnectionRequest` throws if the nonce doesn't match a pending request. These indicate a programming error in the calling code; do not retry.
- **Auth errors** (HTTP 401): the JWT expired or the user isn't authenticated. Call `tarn.login` (or `tarn.recoverAccount`) and retry the operation.
- **Conflict errors** (HTTP 409): a write collided with a concurrent write at the same tag. The SDK's `shareContent` / `updateShareContent` / `unshareContent` retry automatically with a higher seq. For lower-level `_publishShareLogEntry`, pass `{ retryOn409: true }` or handle the 409 in caller code.
- **Rate-limit errors** (HTTP 429): the per-session or per-IP rate limit was exceeded. Surface to the user; do not auto-retry tightly.
- **Server errors** (HTTP 5xx, network errors): generally retriable. The SDK has built-in retry with exponential backoff for idempotent operations; non-idempotent operations (e.g., raw register without an idempotency key) should be retried by the caller with care.

### Idempotency

Which operations are safe to retry blindly:

| Operation | Idempotent? | Notes |
|---|---|---|
| `login` | Yes | Same credentials → same DLK. |
| `register` (in-flight) | Yes (within one `register` call) | The SDK builds the body once before the retry loop. Cross-call retries are NOT idempotent — every fresh call mints a new random DEK + recovery phrase. |
| `recoverAccount` | Yes | Same phrase + new credentials → same final state. |
| `createEntry` | No (without an external idempotency key) | Each call mints a fresh CEK and creates a new Arweave tx. Caller-side dedup if needed. |
| `updateEntry` | Yes | The supplied prior tx_id pins the operation to a known state. |
| `deleteEntry` | Yes | Tombstone is content-addressed by ref. |
| `sendConnectionRequest` | Yes (modulo nonce uniqueness) | Each call generates a fresh nonce; calling twice creates two distinct pending requests. Caller-side dedup recommended. |
| `acceptConnectionRequest` | Yes | Re-accepting an already-accepted request is a no-op. |
| `shareContent` / `updateShareContent` / `unshareContent` | Yes | Built-in 409 retry; caller can replay safely. |
| `revokeContentFromConnections` | Yes | Repeated rotation produces successive CEKs; each is a no-op for connections that already received the previous rotate. |
| `muteConnection` / `unmuteConnection` | Yes | Set semantics — repeated calls converge. |
| `serializeSession` | Yes | Each call produces a fresh ciphertext (new IV) but they all decrypt to equivalent state on the same origin. |
| `resumeSession` | Yes | Pure read on a fixed input — no server-side mutation. |
| `clearSession` | Yes | Idempotent delete of the wrapping-key record. |
| `revokeSession` / `revokeAllSessions` / `revokeOtherSessions` | Yes | Server-side `DELETE WHERE`; replays converge. |
| `createInviteToken` | No (without external dedup) | Each call mints a fresh token_id + payload_key, server-side row keyed on the new token_id. |
| `previewInviteToken` | Yes | Pure read. |
| `redeemInviteToken` | Yes | Server enforces single-use atomically. Replays after the first success return 409. |
| `revokeIssuedInvite` | Yes | Idempotent delete on `(token_id, inviter_dlk)`. |
| `setConnectionLabel` | Yes | Last-write-wins on the connections record. |

### Multi-device considerations

Tarn supports multi-device usage natively, but apps need to be aware of a few things:

- **State that's per-device:** the in-memory replay-nonce cache (rebuilt on each session) and any local UI state.
- **State that's per-user, multi-device synced:** the connections record, the pending-requests record, the muted-connections record, the share-log content blobs themselves. All persisted as encrypted Tarn data blobs, picked up on next login.
- **Concurrent writes:** if two devices write to the same share-log seq simultaneously, one wins, the other gets a 409 and the SDK retries at the next seq. Total ordering is preserved.
- **Cache invalidation:** the SDK clears all per-friend caches (pair-keys, share-log counters, read-state, outbound-state, published-txids, muted-connections) on `changeCredentials`, `recoverAccount`, and `deleteAccount`. Apps don't need to manage this manually.

### For agentic dev tools

If you're an AI agent integrating Tarn:

- **The `recoveryAcknowledged: true` flag is mandatory at register.** This is a deliberate choice to force apps to surface the recovery phrase to the user. Bypassing this with a hardcoded `true` is a bug if the user hasn't actually seen the phrase.
- **Treat the recovery phrase + PDF bytes as ephemeral.** The SDK does not cache them; apps must NOT persist them. The user is the only durable store.
- **`shareContent` with `cek: undefined`** is the common case — the SDK automatically pulls the CEK from its outbound state cache (which it hydrates on first share-log call per session). Only pass an explicit CEK when you have a specific reason.
- **`readShareLog` returns the full state map.** For incremental sync after the first read, use `syncShareLog` to avoid replaying history.
- **Connections are the primitive; "follow" / "friend" / etc. are app-level UX.** The SDK is intentionally neutral. Apps should pick terminology and stick to it consistently in their own user-facing copy.

See [TARN_PROTOCOL.md](../docs/TARN_PROTOCOL.md) for the full protocol specification, and [docs/tarn-architecture-guide.pdf](../docs/tarn-architecture-guide.pdf) for the human-facing architecture overview.

### `tarn.dataLookupKey` — the user's data lookup key (available after register/login)

### `tarn.appId` — the app this client is scoped to

### `tarn.isAuthenticated` — whether a valid JWT exists
