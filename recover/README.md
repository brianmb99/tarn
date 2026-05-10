# `@tarn/recover`

> Standalone, server-free recovery package for Tarn-backed accounts. Given a
> user's account key (or username + password) and a working Arweave gateway,
> `recover()` reads their data straight from Arweave — no Tarn API in the
> loop, no backend to keep alive.

`@tarn/recover` is the artifact of Tarn's "permanent, encrypted, user-owned
data" promise. It is the companion to `tarn-client`, the live SDK: the live
SDK reads through the Tarn API (caching, indexing, share-routing); this
package reads through Arweave alone. If `api.tarn.dev` is gone tomorrow, the
user's saved kit + this package + a public Arweave gateway is enough.

The reason the package exists is the
[forward-compatibility contract](#4-the-forward-compatibility-contract): a
user's owned data, once written and confirmed-on-Arweave, must remain
decryptable by `@tarn/recover@vN` for any future `N`. That contract is
constitutional — every other choice in this package is downstream of it.

---

## Table of contents

1. [What this is](#1-what-this-is)
2. [Quick start](#2-quick-start)
3. [API reference](#3-api-reference)
4. [The forward-compatibility contract](#4-the-forward-compatibility-contract)
5. [Architecture](#5-architecture)
6. [Multi-gateway behavior](#6-multi-gateway-behavior)
7. [Edge cases and known constraints](#7-edge-cases-and-known-constraints)
8. [The reference forever-page](#8-the-reference-forever-page)
9. [Test the package](#9-test-the-package)
10. [Versioning and publish](#10-versioning-and-publish)
11. [Pointers](#11-pointers)

---

## 1. What this is

`@tarn/recover` is an ESM-only TypeScript/JavaScript package that performs
**read-only** recovery of a Tarn-backed account's data, given:

- a user's account key (the 24-word BIP39 phrase saved at account creation),
  or alternatively the user's `(username, password)`;
- the user's `appId` (the same `appId` the live writer used);
- the app's schema (the `defineSchema()` output the live SDK consumed);
- one or more Arweave gateway base URLs.

Everything else — locating the credential blob on Arweave, deriving the
factor's KEK, unwrapping the DEK chain, fetching content blobs by data-lookup
key, applying tombstone + Eid + Prev-chain resolution, decrypting, returning
typed plaintext — happens client-side. There is no Tarn server in the loop.

The package is strictly read-only. It does not write back to Arweave, does
not write back to the Tarn API, does not migrate the user's account, does
not modify the user's data. Apps that want to migrate data take a recovered
read and feed it back through the live SDK.

The package is browser-first. Every dependency
(`hash-wasm` for Argon2id, `@noble/curves` for X25519/ECDSA, `@hpke/core`
for HPKE, `@scure/bip39` for the account-key encoding) runs in modern
browsers without a build-time native step. The reference standalone HTML
page in `examples/forever/` is the existence proof.

---

## 2. Quick start

### Account-key factor (the durable kit path)

The account key is the 24-word phrase the user saved when they registered.
This is the path the
[reference forever-page](examples/forever/README.md) uses; it requires
nothing except the saved phrase and a working gateway.

```ts
import { recover } from '@tarn/recover';
import schema from './my-app-schema.js'; // defineSchema() output

const reader = await recover({
  appId: 'my-app',
  schema,
  arweaveGateways: ['https://arweave.net', 'https://g8way.io'],
  credentials: {
    type: 'accountKey',
    accountKey: 'word1 word2 ... word24',
  },
  onProgress: (stage, info) => console.log(stage, info),
});

for await (const item of reader.entries('items')) {
  console.log(item.txid, item.data);
}
```

### Password factor (live-context recovery)

The password factor lights up the **full** surface — owned content plus the
user's social graph (connections + per-pair share-log). Use this when you
have the user's live `(username, password)` and want everything they can
read in the SDK (e.g. an in-app "Settings → Export everything" button).

```ts
import { recover } from '@tarn/recover';
import schema from './my-app-schema.js';

const reader = await recover({
  appId: 'my-app',
  schema,
  arweaveGateways: ['https://arweave.net', 'https://g8way.io'],
  credentials: {
    type: 'password',
    username: 'alice',
    password: 'correct horse battery staple',
  },
});

// Owned content
for await (const item of reader.entries('items')) {
  render(item);
}

// Social graph (password factor only — see §7)
const peers = await reader.connections();
for await (const event of reader.shareLog({ direction: 'incoming' })) {
  // typed event union: add | update | rotate | remove | snapshot |
  // rotate_identity, with `connection`, `seq`, `verified` metadata
  handle(event);
}
```

The two factors land at the same credential blob via independent crypto
chains; the resulting DEK chain is identical. The only divergence is the
sharing surface (see §3 and §7).

---

## 3. API reference

Public exports from `@tarn/recover` (see `recover/src/index.ts`):

- [`recover(opts)`](#recoveropts)
- [`Reader`](#reader)
  - [`reader.collections`](#readercollections)
  - [`reader.account`](#readeraccount)
  - [`reader.tombstoneCount`](#readertombstonecount)
  - [`reader.entries(name)`](#readerentriesname)
  - [`reader.allEntries(name)`](#readerallentriesname)
  - [`reader.connections()`](#readerconnections)
  - [`reader.shareLog({ direction })`](#readersharelog-direction-)
  - [`reader.allShareLog({ direction })`](#readerallsharelog-direction-)
- [Sharing helpers](#sharing-helpers)
- [Lower-level primitives](#lower-level-primitives)
- [Errors](#errors)
- [Progress events](#progress-events)

### `recover(opts)`

```ts
function recover(opts: RecoverOptions): Promise<Reader>;

type RecoverOptions = {
  appId: string;
  schema: ReaderSchema;
  arweaveGateways: string[];
  credentials: RecoverCredentials;
  onProgress?: OnProgress;
};

type RecoverCredentials =
  | { type: 'password'; username: string; password: string }
  | { type: 'accountKey'; accountKey: string };

type ReaderSchema = {
  appId: string;       // must equal opts.appId
  version: number;     // positive integer
  collections: Record<string, unknown>;
};
```

Run the full recovery flow and return a {@link Reader} bound to the recovered
account.

**Parameters**

| Name              | Type                  | Description                                                                                                |
| ----------------- | --------------------- | ---------------------------------------------------------------------------------------------------------- |
| `appId`           | `string`              | App identifier. Must match the `appId` the live writer used at register time.                              |
| `schema`          | `ReaderSchema`        | The app's schema (`defineSchema()` output, or any object satisfying the minimal contract above).           |
| `arweaveGateways` | `string[]`            | Ordered list of gateway base URLs. Tried in order; on retryable failure the next gateway is consulted.     |
| `credentials`     | `RecoverCredentials`  | Exactly one factor block — `password` (with `username` + `password`) or `accountKey` (24-word BIP39).      |
| `onProgress`      | `OnProgress?`         | Optional diagnostic callback. Errors thrown from it are swallowed.                                         |

**Returns** — a `Promise<Reader>`. The promise resolves once the credential
blob is located, the envelope is parsed, and the DEK chain is fully
unwrapped. No content blobs have been fetched yet; that happens lazily via
the iterator surfaces.

**Throws**

- Validation errors on missing or malformed inputs (e.g.
  `recover: arweaveGateways must be a non-empty array of URLs`).
- `recover: no credential blob found on any configured gateway for ...` when
  the credential blob cannot be located on any gateway.
- `recover: credential blob {txid} body is not an object` /
  `... missing data_lookup_key` / `... missing wrapped_data_key` when the
  blob is corrupt.
- Envelope-parse errors thrown by the version-dispatched decoder
  (e.g. `wrapped_data_key: unsupported envelope version v=N`). The unsupported-
  version message tells the caller to upgrade `@tarn/recover` — old versions
  are never removed (forward-compat contract).
- Factor mismatch errors thrown by the unwrap step (e.g. wrong account key
  for the located envelope).
- `AllGatewaysFailedError` (re-exported from `gateway/`) when every
  configured gateway has failed for one underlying request.

### `Reader`

Returned by `recover()`. Holds the unwrapped DEK chain in memory plus a
multi-gateway client; iterators are lazy.

```ts
class Reader {
  readonly collections: string[];
  readonly account: ReaderAccount;
  tombstoneCount: number;

  entries(name: string): AsyncIterable<DecryptedEntry>;
  allEntries(name: string): Promise<DecryptedEntry[]>;

  connections(): Promise<Connection[]>;
  shareLog(opts: { direction: ShareLogDirection }): AsyncIterable<ShareLogEvent>;
  allShareLog(opts: { direction: ShareLogDirection }): Promise<ShareLogEvent[]>;
}
```

#### `reader.collections`

`string[]` — the names declared in the caller-supplied schema.

#### `reader.account`

```ts
type ReaderAccount = {
  appId: string;
  envelopeVersion: number; // 1 today
  totalGens: number;       // number of DEK generations in the unwrapped chain
  username?: string;       // present only on the password factor
};
```

Vintage / structural metadata. Useful for diagnostics; apps generally don't
need to act on these fields, but they're surfaced so debugging is possible
without inspecting raw blobs.

#### `reader.tombstoneCount`

`number` — count of distinct logical records that were tombstoned on the
**most recently iterated** collection. Zero before the first `entries()` /
`allEntries()` call. The field is intentionally a simple scalar that tracks
the most recent walk; callers that want per-collection counts should sum
them themselves.

#### `reader.entries(name)`

Async iterator over every live entry in a collection. Tombstoned records
are filtered out; superseded versions of records (Prev-chain) are filtered
out (only the live tip is yielded).

```ts
type DecryptedEntry = {
  txid: string;
  data: Record<string, unknown>;
  tags: { name: string; value: string }[];
  /** Present only when the entry was written under an older schema. */
  _schemaVersion?: number;
};
```

**Throws** if `name` is not a declared collection. Per-entry decryption
failures are **logged and skipped** rather than aborting the iterator —
this matches the live SDK's `getEntries` posture (callers usually want
partial results over an all-or-nothing failure). Skipped failures land in
`console.warn` with the txid and the underlying error.

**Field fidelity:** the reader yields each schema field's value verbatim
from the on-wire decrypted JSON. No re-encoding, no normalization. A field
that holds an opaque payload (e.g. base64-encoded image bytes in a string
field) round-trips byte-for-byte.

#### `reader.allEntries(name)`

Buffered convenience: drain the async iterator into an array. Use
`entries()` for streaming-friendly consumption (large collections,
progress UI, etc.).

#### `reader.connections()`

```ts
type Connection = {
  share_pub: string;        // peer X25519 sharing pub, base64url
  signing_pub: string;      // peer ECDSA P-256 signing pub, base64url
  username?: string;
  label?: string;
  muted?: boolean;
  established_at?: number;
  initial_request_nonce?: string;
  credential_lookup_key?: string;
  rotated_at?: number;
  prior_share_pub?: string;
};
```

Returns the user's accepted connections (peers + their stable identifiers).

**Best-effort, password-factor-only.** Returns `[]` when:

- the caller authenticated via the `accountKey` factor (the X25519 share
  keypair is derived from `master_key`, which is not derivable from the
  account key — see `src/crypto/share-key.ts` for the architectural
  reason);
- the user has never accepted a connection (no record exists yet).

Throws on decrypt failure of an existing record (the bytes are corrupt) —
intentionally distinct from the empty-array case so callers can tell the
two apart.

> Connections / share-log are **NOT under the forward-compatibility
> contract.** See [§4](#what-is-not-under-the-contract) for why and what
> that means in practice.

#### `reader.shareLog({ direction })`

```ts
type ShareLogDirection = 'incoming' | 'outgoing';

type ShareLogEvent =
  | { type: 'add';             content_id: string; tx_id: string; cek: string; shared_at: number; ... }
  | { type: 'update';          content_id: string; tx_id: string; updated_at: number; ... }
  | { type: 'rotate';          content_id: string; cek: string; rotated_at: number; ... }
  | { type: 'remove';          content_id: string; removed_at: number; ... }
  | { type: 'snapshot';        state: Record<string, { tx_id: string; cek: string }>; snapshot_at: number; prior_seq: number | null; ... }
  | { type: 'rotate_identity'; new_share_pub: string; new_signing_pub: string; new_credential_lookup_key: string; rotated_at: number; ... };

// All events also carry:
//   connection: Connection;     // the peer this event came from
//   seq: number;                // sequence number on the per-pair log
//   direction: 'incoming' | 'outgoing';
//   txid: string;               // Arweave tx id of the entry blob
//   verified: boolean;          // ECDSA signature validated?
```

Async iterator over share-log events for the requested direction.
`incoming` reads peers' outbound logs (events the user received);
`outgoing` reads the user's outbound logs (events the user emitted).

For each connection the iterator: derives the per-pair X25519 + HKDF keys,
discovers the highest seq via O(log N) stealth-tag probes, walks back to
the most recent snapshot, then walks forward yielding each entry.

**`verified: false`** on incoming events means the entry's ECDSA signature
did not validate against the connection's `signing_pub` — apps generally
treat unverified events as forgeries to ignore. On outgoing events,
`verified` requires the user's own signing public key (read from the
credential blob's `public_key` field); when that field is absent (very old
credential blobs), outgoing events surface as `verified: false`.

**Best-effort, password-factor-only.** Yields nothing when the share
keypair is unavailable. Per-entry decryption failures and unverifiable
entries are logged and surfaced (decrypt failures are skipped; unverified
entries are yielded with the flag).

The iterator stops at a `rotate_identity` event (terminal-on-old-log per
protocol §13.5); the rotated peer (if known) appears as its own
`Connection` and is walked independently.

> Like `connections()`, share-log is NOT under the forward-compatibility
> contract.

#### `reader.allShareLog({ direction })`

Buffered batch helper: drain `shareLog()` into a flat array. Returns `[]`
when the share keypair is unavailable.

### Sharing helpers

```ts
import { replayConnection } from '@tarn/recover';

const events = await reader.allShareLog({ direction: 'incoming' });
const finalState = replayConnection(events);
// finalState: Record<content_id, { tx_id, cek }>
```

`replayConnection(events)` rolls a list of `ShareLogEvent`s into the
"final state" map — the same shape the live SDK's `readShareLog` returns.
Events with `verified: false` are skipped (forgery-rejection).

### Lower-level primitives

For callers that need lower-level access (custom reader logic, fixture-vault
tooling, debugging), the package re-exports the gateway, crypto, decrypt,
and sharing modules:

```ts
// Gateway primitives
import {
  ArweaveClient, MultiGatewayClient, AllGatewaysFailedError,
  GatewayError, makeMultiGatewayClient,
  findCredentialBlob, findContentBlobs, findShareLogBlobs,
  findShareInboxBlobs, findAppBlob, findPasskeyCredentials,
} from '@tarn/recover';

// Crypto primitives (KDF, AES, envelope decoders, BIP39, share-key)
import {
  parseWrappedDataKey, unwrapDataKeyChain, readEnvelopeVersion,
  ENVELOPE_VERSION,
  // per-version pieces (pin to v1 explicitly)
  parseEnvelopeV1, unwrapEnvelopeV1,
} from '@tarn/recover';

// Factor-KEK + lookup-key derivations
import {
  derivePasswordKEK, deriveRecoveryKEK,
  deriveCredentialLookupKey, deriveRecoveryLookupKey,
  unwrapDekChain, parseEnvelope,
} from '@tarn/recover';

// Sharing primitives (HPKE, per-pair keys, share-log state machine)
import {
  derivePairKeys, deriveLogTag,
  encryptShareLogEntry, decryptShareLogEntry,
  signOperation, verifyOperationSignature,
  applyOperationToState, replayOperations,
  hpkeSeal, hpkeOpen,
  getPairKeysFor,
} from '@tarn/recover';
```

A subpath import `@tarn/recover/gateway` is also published for callers that
only want the gateway surface (smaller dependency graph at type-checking
time).

These are stable enough to use, but only the high-level surface
(`recover()` + `Reader`) is under the forward-compatibility contract.
Lower-level primitives may be reorganized between major versions provided
the high-level surface keeps working.

### Errors

| Error                                     | Where                              | When                                                                              |
| ----------------------------------------- | ---------------------------------- | --------------------------------------------------------------------------------- |
| `Error('recover: ...')`                   | `recover()` validation             | Missing or malformed `RecoverOptions` fields.                                     |
| `Error('recover: no credential blob ...')`| `recover()` orchestrator           | No blob found on any configured gateway for the supplied factor's lookup key.     |
| `Error('wrapped_data_key: ...')`          | Envelope decoder (`crypto/envelope`)| Malformed envelope, missing `v` field, or unsupported version (upgrade required). |
| `Error('No DEK for blob generation N ...')`| `Reader.entries` decrypt step      | Content blob carries a `Gen` tag the unwrapped chain doesn't cover (rare; suggests writer/reader version skew). |
| `GatewayError`                            | `gateway/arweave-client`           | One gateway failed; carries `kind`, `status?`, `gateway`, `cause?`.               |
| `AllGatewaysFailedError`                  | `gateway/multi-gateway`            | Every gateway exhausted on one underlying request; carries `errors: GatewayError[]` and `operation`. |

`GatewayError.kind` is one of `timeout | network | http_5xx | http_429 |
http_4xx | tx_not_found | graphql_error | bad_response`. The multi-gateway
client retries on every kind except `bad_response` and `http_4xx`-other-
than-429 (those would just repeat at the next gateway).

### Progress events

```ts
type RecoverStage =
  | 'deriving'           // KDF + key derivation in progress
  | 'locating-account'   // GraphQL query for credential blob
  | 'fetching-envelope'  // pulling credential blob body
  | 'walking-log'        // listing content blobs for a collection
  | 'decrypting'         // per-blob decrypt
  | 'done';              // collection / overall flow complete

type OnProgress = (stage: RecoverStage, info: Record<string, unknown>) => void;
```

The `info` object carries free-form context: collection name, current /
total counts, `failedGateway` + `nextGateway` on retries, etc. Apps render
spinners with it. Exceptions thrown from `onProgress` are swallowed — the
callback is purely diagnostic and never blocks recovery.

---

## 4. The forward-compatibility contract

This package's reason to exist is the constitutional commitment that
`@tarn/recover` keeps reading old data forever. Treat the four sub-sections
below as the package's central contract.

### What we promise

**A user's owned data, once written and confirmed-on-Arweave, must remain
decryptable by `@tarn/recover@vN` for any future `N`, given only:**

- the user's account key (or username + password),
- the user's `appId` and schema, and
- a working Arweave gateway.

This must hold across:

- KDF version upgrades (PBKDF2 legacy → Argon2id current → whatever's next).
- Envelope-format upgrades (current v1 → hypothetical v2 → ...).
- Schema evolution (apps bumping schemas with renamed/added/removed
  fields). Apps are responsible for their own migrations; the package
  surfaces `_schemaVersion` so they know when to run them.
- Tarn API changes — the contract is independent of the live API
  entirely.
- Account state — accounts that have rotated credentials, rotated their
  account key, or moved between Model A and Model B all recover the same
  way: account key (or password) + Arweave gateway is enough.

The contract covers **owned content only.** Connections, share-log, and
HPKE-handshake shapes are best-effort and explicitly NOT under the
contract — see [What's not under the contract](#what-is-not-under-the-contract).

### How we keep that promise

Five structural mechanisms enforce the contract:

1. **Envelope decoders are version-dispatched.**
   `recover/src/crypto/envelope/` holds one module per envelope wire
   version (`v1.ts` today). `index.ts` reads the envelope's `v` field
   and routes to the right decoder via the `DECODERS_BY_VERSION` table.
   Adding a new version is purely additive: drop a `vN.ts` and register
   it; old versions are never removed.

2. **KDF parameters live in the account record, not in code.**
   Every account record on Arweave carries the Argon2id parameters used
   to derive its recovery KEK (`m`, `t`, `p`, `salt`). The package picks
   the right KDF based on what the record says, not based on what's
   "current." Bumping defaults for new accounts cannot break old ones.

3. **Adding wire features is additive.**
   New optional fields in account records, new factor types in envelopes
   (e.g. `passkey_prf` is already partly threaded through the codebase
   for a future v2), new index strategies on Arweave — all coexist with
   old shapes. Removing or repurposing fields is forbidden.

4. **Fixture vault.**
   `recover/fixtures/envelope-vN/` holds frozen synthetic envelopes for
   every supported version. Files in the vault are
   **never deleted or modified** — only added to. The fixture-suite test
   (`tests/forward-compat.test.ts`) runs every fixture through the full
   pipeline on every release; the fixture-vault meta-test
   (`tests/fixture-vault.test.ts`) hashes the vault and fails if any
   tracked file is missing, modified, or unlisted. See
   [`fixtures/README.md`](fixtures/README.md) for the full vault rules.

5. **Cross-validate against the live writer.**
   `tests/recover-cross-validate.test.ts` runs the live SDK's writer
   against a real `wrangler dev`, captures the on-the-wire bytes, then
   feeds them through `recover()`. Any divergence between writer and
   reader fails the test.

### What this constrains us NOT to do

The contract is enforced as much by negative space as by positive
infrastructure. Specifically:

- **No legacy decoder removal.** "We're cleaning up the envelope" PRs
  that drop support for an older wire version are forbidden. Cleanup is
  allowed; legacy decoder removal is not.
- **No moving secrets to server-side storage.** Anything that breaks the
  "account key + Arweave = recovery" property is a contract violation
  regardless of how clever it is. Wrapped material may move (e.g.
  `wrapped_account_key` for Model B); the unwrapping factor must stay
  user-controlled.
- **No required Tarn-server roundtrips.** The package's promise is to
  be Tarn-server-independent. If a future feature requires a Tarn-server
  call to decrypt, that feature can ship in the live SDK but cannot
  replace something `@tarn/recover` already supports.
- **No required network besides Arweave gateways.** No CDN-loaded
  scripts at runtime, no third-party telemetry endpoints, no remote
  config. The reference forever-page runs from `file://`; the SDK runs
  in offline browsers as long as one gateway is reachable.

### What is not under the contract

Three surfaces in this package are **best-effort and explicitly NOT under
the forward-compatibility contract:**

- `reader.connections()`
- `reader.shareLog({ direction })`
- HPKE-handshake / inbox-protocol shapes (exposed via the lower-level
  `hpkeSeal` / `hpkeOpen` / `validateConnectionRequestPayload` / etc.
  primitives).

Why exclude them?

The forward-compat surface is scoped to the **durable kit-saving use
case**: a user who wrote down their account key years ago shows up with
nothing else, plugs the phrase into a saved HTML page, and recovers
their own data. That use case is well-served by owned content alone; it
does NOT require seeing who you ever shared things with or what events
flowed across those connections. Social data is a live-context surface
(in-app history views, debug tooling) where the user has their live
credentials anyway and Tarn is presumably alive.

A second reason falls out of the math: the `accountKey` factor cannot
derive the X25519 sharing keypair — that derivation routes through
`master_key`, which only the password factor produces. So the durable
kit path mathematically cannot reach connections data anyway. Promising
forward-compat for a surface only one of the two factors can reach
would be misleading.

In practice this means:

- The HPKE wire shapes, the per-pair derivation rules, the share-log
  signature scheme — all may be revised in a future `@tarn/recover`
  release without re-supporting the old shapes.
- Apps that surface social data via `@tarn/recover` should treat it as
  a live-only feature (Settings → Export, debug consoles, in-app
  history). Apps must **not** put it on their forever-page artifact.
- The reference forever-page in `examples/forever/` accordingly does
  not surface `connections()` or `shareLog()`. Its scope is owned
  content.

This separation is also documented in
[`docs/STANDALONE_RECOVERY_PLAN.md`](../docs/STANDALONE_RECOVERY_PLAN.md)
§1 (revised 2026-05-08) and the
[fixture-vault README](fixtures/README.md).

---

## 5. Architecture

`recover()` walks the following pipeline; pointers below are absolute
paths from the package root.

1. **Validate options.**
   `src/recover.ts` `validateOptions()`. Rejects malformed inputs early
   with descriptive errors.

2. **Build the multi-gateway client.**
   `src/gateway/multi-gateway.ts` `makeMultiGatewayClient()`. Wraps the
   per-gateway `ArweaveClient`s with the fallover policy from §6.

3. **Derive the lookup key for the chosen factor.**
   - Password factor → `deriveCredentialLookupKey(username, password, appId)`
     in `src/decrypt/derive-lookup-keys.ts`.
   - Account-key factor → `deriveRecoveryLookupKey(accountKey, appId)` in
     the same file.

4. **Locate the credential blob on Arweave.**
   `src/gateway/queries.ts` `findCredentialBlob()`. GraphQL by
   `App=tarn + Type=cred + (Lk|RLk)=<lookup_key>`. Parses the latest
   blob's body as JSON; throws on no-match.

5. **Pull `data_lookup_key`, `wrapped_data_key`, and `public_key` out of
   the credential body.**
   `src/recover.ts`. The orchestrator validates required fields and
   carries `public_key` through to the `Reader` for later signature
   verification on outgoing share-log entries.

6. **Parse the envelope.**
   `src/crypto/envelope/index.ts` `parseWrappedDataKey()` reads the
   `v` byte and routes to the matching version decoder
   (`v1.ts` today). The cross-version normalized shape is
   `ParsedWrappedDataKey`.

7. **Derive the factor's KEK.**
   - Password factor → `derivePasswordKEK(...)` in
     `src/decrypt/derive-keys.ts`. Internally:
     `deriveMasterKey(username, password)` (Argon2id) →
     `deriveCredentialEncryptionKey(masterKey, appId)` (HKDF) → AES-KW
     handle. The same `master_key` is also fed into
     `deriveSharingKeyPair(masterKey, appId)` (`src/crypto/share-key.ts`)
     to produce the X25519 share keypair for the social surface.
   - Account-key factor → `deriveRecoveryKEK(...)` in the same file.
     Internally: `accountKeyToEntropy(...)` (`src/crypto/bip39.ts`) →
     `deriveRecoveryKey(entropy, recoverySalt, kdfParams)` (Argon2id) →
     AES-KW handle.

8. **Unwrap the DEK chain.**
   `src/crypto/envelope/v1.ts` `unwrapEnvelopeV1()` (called via the
   dispatcher's `unwrap()`). For each generation in the envelope's
   chain: AES-KW unwrap → AES-GCM/AES-KW per-content key handles. The
   resulting `UnwrappedDekChain` is `Map<gen, DataKeyPair>`.

9. **Construct the `Reader`.**
   `src/reader/reader.ts`. Caches the gateway client, DEK chain,
   schema, and (when present) share keypair + own signing pub. No
   content fetches happen yet.

10. **Lazy entry walk per `reader.entries(name)` call.**
    - `findContentBlobs()` — GraphQL by `App + Type + Lk` returns every
      blob in the collection.
    - `resolveContentBlobs()` (`src/reader/resolve.ts`) — applies
      tombstone + Eid + Prev-chain semantics, mirroring the server-side
      `resolveEntries` logic in `api/src/cache.js`.
    - For each surviving blob: read `Gen` tag → look up DEK in the
      chain → `decryptWithCEK()` → wrap in `attachSchemaVersionMarker`
      (`src/reader/decode.ts`) → yield.

11. **Lazy share-log walk per `reader.shareLog(opts)` call** (composed
    `SharingReader` in `src/reader/sharing-reader.ts`):
    - Fetch + decrypt the connections record (`tarn-share-state` /
      `Eid=tarn-connections-v1`).
    - For each connection: derive per-pair X25519 + HKDF keys
      (`src/sharing/pair-keys.ts`), discover the highest seq via
      O(log N) stealth-tag probes (`discoverHighestSeq`), walk back to
      the most recent snapshot, then walk forward yielding events.

The full source tree:

```
recover/
├── src/
│   ├── index.ts                # public entry — recover() + re-exports
│   ├── recover.ts              # orchestrator
│   ├── progress.ts             # OnProgress / RecoverStage / RecoverProgress
│   ├── crypto/                 # KDF + envelope (borrowed from client/src/crypto.ts)
│   │   ├── envelope/           # version-dispatched decoder modules (v1.ts + index)
│   │   ├── kdf.ts              # Argon2id, HKDF, master key, recovery key, CEK
│   │   ├── aes.ts              # AES-GCM + AES-KW + decryptWithCEK
│   │   ├── share-key.ts        # X25519 sharing keypair (password factor only)
│   │   ├── bip39.ts            # account-key ↔ entropy
│   │   └── encoding.ts, constants.ts, types.ts
│   ├── decrypt/                # factor-KEK + lookup-key + DEK-chain unwrap
│   ├── gateway/                # multi-gateway client + tag-filtered queries
│   │   ├── arweave-client.ts   # single-gateway GraphQL + blob fetch
│   │   ├── multi-gateway.ts    # fallover policy + AllGatewaysFailedError
│   │   └── queries.ts          # findCredentialBlob, findContentBlobs, ...
│   ├── reader/                 # schema-aware Reader + SharingReader
│   │   ├── reader.ts           # owned-content surface (entries, allEntries)
│   │   ├── resolve.ts          # Eid + Prev + tombstone resolution
│   │   ├── decode.ts           # _schemaVersion marker
│   │   └── sharing-reader.ts   # connections + share-log walk (Phase 5)
│   └── sharing/                # share-log + HPKE primitives (borrowed)
├── examples/
│   └── forever/                # reference standalone HTML page (Phase 7)
├── fixtures/                   # forward-compat fixture vault (immutable)
│   ├── README.md               # vault rules / contract enforcement
│   ├── manifest.json           # SHA-256 manifest, source of truth
│   └── envelope-v1/            # frozen v1 fixtures
├── tests/                      # *.test.ts unit + integration tests
└── scripts/                    # build + test runners + fixture generator
```

---

## 6. Multi-gateway behavior

The `arweaveGateways` array is tried **in priority order**, not
round-robin. The first gateway in the list is preferred; gateways further
down are fallbacks. The plan calls this out explicitly: a slow-but-
eventually-correct gateway is preferable to splitting load randomly across
a list whose relative health we don't know.

Per-call timeout defaults to 30 seconds (configurable via
`new ArweaveClient({ timeoutMs })` if the lower-level primitives are used
directly).

### Retryable failure kinds

The multi-gateway wrapper falls over to the next gateway on any of:

| `GatewayError.kind` | Meaning                                                                      |
| ------------------- | ---------------------------------------------------------------------------- |
| `timeout`           | Per-call deadline exceeded.                                                  |
| `network`           | Connection error (DNS, TCP, TLS).                                            |
| `http_5xx`          | Server-side error.                                                           |
| `http_429`          | Rate-limited — common on public gateways under load.                         |
| `tx_not_found`      | 404 on a blob fetch where the TX is expected to exist (gateway behind on indexing). |
| `graphql_error`     | GraphQL returned an `errors` array — borderline; treated as retryable since gateways have been seen to return GraphQL errors during indexer hiccups. |

Non-retryable kinds (`bad_response`, `http_4xx` other than 429) stop the
fallover immediately — these would just repeat at the next gateway and
likely indicate a client bug.

### Surfacing retries

When the package retries on a gateway failure, it fires `onProgress` with
`stage: 'locating-account'` and an `info` object carrying:

```ts
{
  retry: true,
  failedGateway: string,   // URL of the gateway that just failed
  nextGateway: string,     // URL of the gateway about to be tried
  kind: GatewayErrorKind,  // failure category
}
```

Apps can use this to render "Trying next gateway..." UI. The lower-level
`MultiGatewayClient` exposes a richer `RetryProgress` shape (operation
name, indices, totals); see `src/gateway/multi-gateway.ts` if you're
constructing the client directly.

### Exhaustion semantics

When every gateway has failed for a single underlying operation, the
package throws `AllGatewaysFailedError`:

```ts
class AllGatewaysFailedError extends Error {
  readonly errors: GatewayError[]; // one per gateway, in attempt order
  readonly operation: string;       // 'queryTransactions' | 'fetchBlob'
}
```

Apps surface this as "Tried N gateways; all failed." The per-gateway
errors carry the structured `kind` / `status` / `gateway` / `cause` so
the failure message can be specific without parsing strings.

---

## 7. Edge cases and known constraints

### Account-key path doesn't expose social data

The `accountKey` factor returns an empty `connections()` array and an
empty `shareLog()` iterator. This is **architectural, not a bug.** The
X25519 sharing keypair is derived from `master_key`, which is derived
from `(username, password)` and is rotated on every credential change.
The recovery factor cannot reach `master_key`, so it cannot derive the
sharing keypair, so it cannot decrypt social data.

This matches an architectural property of the live SDK: `recoverAccount`
itself rotates `share_priv` — pre-rotation share-log entries become
unreadable to anyone who only has the account key. See
`src/crypto/share-key.ts` for the full explanation.

### Rotated account-key behavior

When a user rotates their account key (via the live SDK's
`rotateAccountKey`), only the **current** account key recovers. The old
key fails loudly with "no credential blob found" rather than silently
returning empty results. This is deliberate: a silent empty-result on
the wrong key would mask a real "user has the wrong phrase" condition.

### Model A vs Model B

Recovery works **identically** for both models. Model B (where Tarn
also stores a `wrapped_account_key`) is a convenience for retrieving
the account key while Tarn is alive; it does not change what
`@tarn/recover` does. The package always takes the account key (or
password) as input and reads from Arweave — Model B's server-side key
storage is irrelevant to the recovery path.

The implication for users: **users who never personally saved their
account key are NOT recoverable via `@tarn/recover`.** Model B users
who relied on Tarn-mediated retrieval and never wrote the phrase down
are dependent on Tarn being alive. This needs to be in app-side
user-facing copy too — the "have you actually saved your account key?"
prompt isn't UX polish, it's the gate between "your data is
permanently yours" and "your data is yours as long as Tarn is alive."

### Multi-app accounts

Each app is a separate `recover()` call. A user with data in `appId:
'app-a'` AND `appId: 'app-b'` recovers twice with two `appId`s; the two
calls land at independent credential blobs (each app has its own
`credential_lookup_key` derivation) and produce independent `Reader`
instances. There is no cross-app intermingling.

This also means there is no "discoverability" layer for finding which
Tarn apps an account has data in. Apps are addressed by `appId`
provided at recover time.

### Tombstones

Tombstones are applied **implicitly** — `entries()` yields the
post-delete view of the user's content. A given `Reader.entries(name)`
walk sets `reader.tombstoneCount` to the count of distinct logical
records that were tombstoned in that collection. `tombstoneCount` is a
single scalar that tracks the most recent walk; callers iterating
multiple collections should sum themselves.

There is no "include tombstones" option today. If a future use case
emerges (e.g. recovery from accidental deletion), it would be added as
a separate option or a separate iterator method without changing
`entries()` semantics.

### Schema evolution

Each yielded entry includes a `_schemaVersion` field IF the entry was
written under a schema older than the caller's. Apps detect "this
record needs migration" by checking for the property's presence:

```ts
for await (const item of reader.entries('items')) {
  if (item._schemaVersion !== undefined) {
    item.data = migrate(item.data, item._schemaVersion, schema.version);
  }
  render(item);
}
```

The package deliberately does NOT run apps' migrations automatically —
apps decide how to migrate / display.

### Field fidelity

The reader yields each schema field's value verbatim from the on-wire
decrypted JSON. No re-encoding, no normalization. A field that holds an
opaque payload (e.g. base64-encoded image bytes in a `coverImage:
'string?'` field) round-trips byte-for-byte.

### Per-entry decrypt failures don't abort the iterator

Mirrors the live SDK's `getEntries` posture: log + skip rather than
aborting the whole iterator on one bad entry. Skipped failures land in
`console.warn` with the txid and the underlying error. Callers
generally want partial results over an all-or-nothing failure.

### Partial / incremental recovery is NOT supported

The package does a full read of a user's history each time `recover()`
is called and the iterators walk. There is no "give me only items
written after timestamp X" — that's a Tarn-server-and-cache concern.
Apps that want partial recovery either use the live SDK or run the
full reader and filter app-side.

### Browser-only

The package targets modern browsers (with WebCrypto + WASM support).
No CLI tool is shipped — that's a future thing if a real use case
emerges. Node also works for testing but no node-specific affordances
are exposed.

---

## 8. The reference forever-page

[`examples/forever/`](examples/forever/README.md) ships a self-contained
HTML page that exercises `@tarn/recover` end-to-end in a browser. It is
the artifact of the permanent owned-content promise: given a user's
account key (or username + password), it locates their account on
Arweave, decrypts every collection in their app's schema, and hands the
data back as downloadable files. No backend, no Tarn API, no runtime
CDN dependency.

Build it with `npm run build:forever` (or `npm run build` to build the
SDK and the page together); the output is a single `dist/forever.html`
file with no external script tags, no remote stylesheet links, and no
runtime ESM-from-CDN imports.

The page is **app-agnostic.** Apps that ship their own copy (Bookish's
`forever.html`, etc.) typically pre-fill the `App ID` field, embed
their schema JSON directly in the page, restyle the CSS, and adjust
the copy. The recovery logic itself stays identical. See
[`examples/forever/README.md`](examples/forever/README.md) for hosting,
theming, scope-guard, and reproducibility notes.

The page surfaces only owned-content APIs (`recover()`,
`reader.entries`, `reader.allEntries`). It does **not** surface
`connections()` or `shareLog()` — that scope matches the
forward-compatibility contract.

### Publishing the page to Arweave (app-author workflow)

The publish tool exists for **app authors who want their themed forever page on Arweave**. Bookish themes this reference page to become `bookish/public/forever.html`, then publishes that themed copy with `recover/scripts/publish-forever.mjs`. The user's saved recovery kit references the app's themed-page txid.

Publishing the **unthemed reference page** is optional and mostly symbolic — end users wouldn't actually use it (it asks them to enter `appId` and paste a schema JSON, which isn't realistic recovery UX). The reference page's audience is app developers as a starting point.

Tool details: `dist/forever.html` is built deterministically (same input bytes → same output). The publish script is dry-run by default; `--confirm` enables real publish. Each publish writes the page (`Type=forever-page`) plus a tiny `Type=forever-page-pointer` blob whose body is the just-published page txid — Arweave-native "latest" discovery without needing a Tarn-side endpoint. See [`examples/forever/README.md` §"Arweave publish workflow"](examples/forever/README.md#arweave-publish-workflow) for the full flow (build, dry-run, confirm, tag scheme, idempotency, discovery query, sharing the txid with users).

---

## 9. Test the package

From the package root:

```sh
npm install
npm run typecheck    # tsc --noEmit
npm test             # node --import tsx --test on every tests/*.test.ts
npm run build        # SDK build + forever-page build
npm run build:forever  # just the page
```

Tests run via `node --import tsx --test`. Build emits ESM via esbuild
plus `.d.ts` files via `tsc --emitDeclarationOnly` — same pipeline as
`tarn-client`. The build is ESM-only; CJS is deliberately not shipped.

Notable test files:

- `tests/forward-compat.test.ts` — runs every fixture vault entry
  through the full pipeline. The structural enforcement of the
  forward-compatibility contract.
- `tests/fixture-vault.test.ts` — meta-test on the vault: hashes
  every tracked file and fails on any mismatch / missing / unlisted
  file. Catches accidental fixture mutation.
- `tests/forever-page.test.ts` — verifies the forever-page builds
  reproducibly and surfaces only the contracted owned-content API.
- `tests/recover-cross-validate.test.ts` — proves bytes the
  production SDK encrypts can be decrypted end-to-end by `recover()`.
  Boots a real `TarnClient` against a running `wrangler dev`, drives
  the full register/write path, then runs `recover()` against an
  in-process mock gateway populated from the captured bytes. The
  load-bearing cross-validate that catches writer/reader drift.
- `tests/sharing-cross-validate.test.ts` /
  `sharing-cross-validate-live.test.ts` — analogous cross-validates
  for the share-log + connections paths.
- `tests/multi-gateway.test.ts` / `tests/queries.test.ts` — Arweave-
  direct read primitives.
- `tests/resolve.test.ts` / `tests/unwrap-envelope.test.ts` /
  `tests/recover-synthetic.test.ts` /
  `tests/sharing-reader-synthetic.test.ts` — pure unit tests over the
  resolution, unwrap, and reader logic.

The cross-validate live tests require `wrangler dev` running on
`RECOVER_API_BASE` (defaults to `http://localhost:8788`) with the
migrations applied. They skip cleanly otherwise.

---

## 10. Versioning and publish

`@tarn/recover` follows semver, but the
[forward-compatibility contract](#4-the-forward-compatibility-contract)
puts an extra constraint on top:

> **No major-version bump may break envelope-vN decryption for any N
> that a previous release supported.**

Concretely:

- Breaking changes to lower-level primitive surfaces (gateway client,
  factor-KEK derivations, sharing primitives) MAY ship in a major
  version bump.
- Changes to the high-level `recover()` / `Reader` shape that reduce
  backwards compatibility for consumers MAY ship in a major version
  bump (with a migration guide).
- Changes that remove or alter the wire interpretation of any
  envelope version, drop content-blob decode support, or move
  unwrapping material out of the user-controlled chain MUST NOT ship
  in any version, major or otherwise. These are contract violations.

The package is published as ESM-only. The `package.json` `exports`
table publishes the root entry at `./dist/esm/index.js` and the
gateway subpath at `./dist/esm/gateway/index.js`; types live under
`./dist/types/`.

The reference `dist/forever.html` is shipped in the package tarball so
consumers can fork it without rebuilding. Source TS lives under `src/`
and is also shipped (`files: ['src/']`) for sourcemaps and debug
inspection.

---

## 11. Pointers

Documents in this repo that intersect with `@tarn/recover`:

- [`docs/STANDALONE_RECOVERY_PLAN.md`](../docs/STANDALONE_RECOVERY_PLAN.md)
  — the implementation plan this package was built against. Phase 8
  (this README) is the constitutional commitment; phases 1-7 are
  shipped infrastructure; Phase 9 (Arweave-publish) is upcoming.
- [`docs/STANDALONE_RECOVER_AUDIT.md`](../docs/STANDALONE_RECOVER_AUDIT.md)
  — Phase 1 audit of the live SDK's read path. Module-by-module
  classification of what was reusable vs net-new.
- [`docs/TARN_PROTOCOL.md`](../docs/TARN_PROTOCOL.md) — the wire-format
  truth. Envelope shape, KDF parameters, Arweave tag scheme, share-log
  semantics. The forward-compatibility contract is enforced against
  this document.
- [`docs/SDK_ARCHITECTURE.md`](../docs/SDK_ARCHITECTURE.md) — live-SDK
  implementation architecture. Useful when reasoning about why a
  given primitive is shaped the way it is in the recover package.
- [`fixtures/README.md`](fixtures/README.md) — fixture-vault rules.
  How adding a new envelope version works; what counts as a contract
  violation.
- [`examples/forever/README.md`](examples/forever/README.md) — the
  reference standalone HTML page: hosting, theming, scope guard,
  reproducibility.
- [`client/README.md`](../client/README.md) — the live SDK's
  app-developer reference. `@tarn/recover` is the read-only companion
  to that surface.
