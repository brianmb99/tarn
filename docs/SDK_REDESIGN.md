# Tarn SDK Redesign — Design Doc

**Status:** Draft for review (greenlit 2026-05-01)
**Owner:** Tarn maintainers
**Implements against:** Bookish (reference app), `examples/` (teaching app)
**Does NOT touch:** the on-wire protocol (Arweave tag scheme, encryption format, share-log seq mechanics, auth challenge-response). Those are stable.

---

## Why this exists

Tarn's pitch is "build apps on this and you don't have to think about encryption or storage." Today's SDK is mid-level — it hides crypto and signing, but it leaks Arweave concepts (txids, tags, transaction lifecycles), forces apps to track Prev-chains by hand, and pushes protocol-format details into app code when they want to share content with friends. The Bookish team filed a request (`SDK_SHARING_HELPERS.md`) flagging two specific seams; investigation revealed the seams are symptoms of the abstraction sitting at the wrong level.

This document specifies a deliberate redesign of the **client-side SDK API surface**. The wire protocol stays. The redesign is breaking — there is exactly one app to migrate (Bookish), and it's the reference app, so future apps will copy whatever pattern Bookish ends up with. Doing this once and doing it well is the highest-leverage move we have.

The design principle:

> **Public verbs match developer mental models. Protocol verbs are an implementation detail.**

Apps think in terms of typed records, collections, friends, and sharing. They should not think in terms of transaction ids, Prev tags, share-log sequence numbers, or content encryption keys. Everything below this line in the SDK is an opportunity to lift the abstraction.

---

## Top-level shape

```ts
import { TarnClient, defineSchema, TarnStorage } from '@tarn/sdk';
import { bookishSchema } from './schema.js';

const tarn = await TarnClient.create({
  apiBase: 'https://api.tarn.dev',
  appId:   'bookish',
  schema:  bookishSchema,
  storage: TarnStorage.localStorage(),  // .indexedDB() | .memory() | .custom(read, write)
});

await tarn.login(email, password);   // restores session if persisted; prompts auth otherwise

// Collections — typed, schema-validated, primary-key-addressed
await tarn.books.create({ bookId: 'b1', title: 'Foo', isPrivate: false });
await tarn.books.update('b1', { rating: 5 });
const all = await tarn.books.list();
const one = await tarn.books.get('b1');
await tarn.books.delete('b1');

// Connections — noun-namespaced
const conn = await tarn.connections.accept(inviteUrl);
await tarn.connections.list();
await tarn.connections.mute(conn);

// Sharing — verb on the collection
await tarn.books.share(conn, 'b1');
await tarn.books.shareWithAll('b1');
const friendsBooks = await tarn.books.listShared(conn);

// Lifecycle — noun-namespaced
await tarn.recovery.export({ format: 'pdf' });
await tarn.account.changeCredentials(newEmail, newPassword);
await tarn.session.clear();

// Power-user escape hatches
await tarn.advanced.entries.fetchBlob(txid);
await tarn.advanced.shareLog.snapshot(conn);
```

---

## Schemas

### Tier 1: Tarn base (SDK-internal, reserved)

The SDK reserves the following type names for its own use. App schemas declaring any of them throw at `defineSchema()`:

```
cred
connection
share-log-state
share-inbox
recovery-factor
app-config
app-schema
```

Apps interact with these only through SDK-provided primitives (`tarn.connections.*`, `tarn.recovery.*`, `tarn.account.*`, etc.). They are never exposed as collections.

### Tier 2: App schema

Apps declare their collections via `defineSchema()`. The DSL is pure data — no class hierarchies, no mixin syntax, no `extends` keyword. The base/app distinction is enforced by the runtime, not by syntactic inheritance.

```ts
import { defineSchema } from '@tarn/sdk';

export const bookishSchema = defineSchema({
  appId:   'bookish',
  version: 4,                              // bump on shape changes; drives migrations

  collections: {
    books: {
      primaryKey: 'bookId',                // app-stable id; SDK maps to Eid internally

      fields: {
        bookId:    { type: 'string', required: true },
        title:     { type: 'string', required: true },
        author:    'string?',              // shorthand for { type: 'string', required: false }
        rating:    'number?',
        readAt:    'date?',
        notes:     'string?',
        isPrivate: { type: 'boolean', default: false },
      },

      shareable: true,                     // collection can be shared via .share()
    },

    settings: {
      primaryKey: 'key',
      fields: {
        key:   { type: 'string', required: true },
        value: 'json',                     // any JSON value; SDK stores as-is
      },
      shareable: false,                    // .share() is not generated for this collection
    },
  },

  // Optional: per-version migration hooks, run on read for older entries
  migrations: {
    3: (old) => ({ ...old, /* v3 → v4 transform */ }),
    2: (old) => ({ ...old, /* v2 → v3 transform */ }),
  },
});
```

**Field type DSL:**

| Shorthand | Long form |
|-----------|-----------|
| `'string'` | `{ type: 'string', required: true }` |
| `'string?'` | `{ type: 'string', required: false }` |
| `'number'` / `'number?'` | float, native `number` |
| `'integer'` / `'integer?'` | rejects non-integers at validate |
| `'boolean'` / `'boolean?'` | |
| `'date'` / `'date?'` | accepts `Date` or ISO 8601 string; serialized to ISO |
| `'json'` | any JSON-serializable value, no shape enforcement |
| `{ type: '...', default: X }` | apply default on create if field absent |
| `{ type: 'string', enum: [...] }` | restricted set |

If a future field type is needed (`'binary'`, `'reference'`, etc.) we add it here. Avoid premature elaboration.

### Validation

- **At write time:** `tarn.books.create(payload)` validates `payload` against the `books` schema. Missing required fields, wrong types, or unknown fields throw `TarnSchemaError` synchronously, before any network or crypto work.
- **At read time:** `tarn.books.list()` and `.get()` apply per-version migrations from older schema versions if the entry's `SchemaV` tag indicates an older version. Records that fail validation after migration are logged and skipped (consistent with how `readShareLog` skips unverifiable entries).
- **Strictness:** unknown fields throw on write (typo protection). Missing optional fields are filled with `undefined` (not `null`) on read.

---

## Schema publication

Schemas are published to Arweave as public (unencrypted) entries, addressable by app and version. Publication goes **through the Tarn API**, not directly from the SDK — the API holds the app's signing key, pays for the Turbo upload, and write-throughs to D1 as it does for every other entry.

### API endpoint

```
PUT /api/v1/apps/{app_id}/schema
Authorization: Bearer <app-jwt>
Content-Type: application/json

{
  "version": 4,
  "schema": { ...defineSchema output, serialized... }
}
```

Server behavior (mirrors `apps.js` rules handler):

1. Authenticate via app JWT (existing app-role auth path).
2. Validate `app_id` matches the JWT's `app` claim.
3. Build an Arweave entry with tags `App=<app_id>, Type='app-schema', V=<version>`.
4. Sign with `APP_SIGNING_KEY` (existing Worker secret).
5. Write-through to D1, upload to Turbo via `ctx.waitUntil` (same fire-and-forget pattern as app-config).
6. Return `{ txid, version }`.

### Operator tool

`tools/publish-schema.mjs` — symmetric to `tools/set-rules.mjs`:

```bash
node tools/publish-schema.mjs --app=bookish --schema=./client/schema.js
```

It loads the schema module, authenticates as the app, calls the endpoint. Run once per app release that bumps `schema.version`.

### Discovery (recovery client)

The future "always access your data" recovery page reads schemas straight from Arweave gateways via GraphQL:

```
{ transactions(tags: [
    { name: "Type", values: ["app-schema"] },
    { name: "App", values: ["bookish"] }
  ], sort: HEIGHT_DESC, first: 1) { ... } }
```

Pick the most recent (or a specific `V` if requested), fetch the blob, parse JSON. Recovery client never talks to Tarn API.

### What the SDK does not do

- The SDK never publishes schemas. It accepts the schema as a value in `TarnClient.create({ schema })` and uses it locally. Schema publication is a deployment-time concern owned by the app — `tools/publish-schema.mjs` is a starting primitive, but apps may build custom flows (CI hooks, in-app admin UI for schema versioning, etc.).
- The SDK does not validate at runtime that its in-process schema matches what's on Arweave. Apps own that consistency.

---

## TypeScript strategy

The SDK is written in TypeScript with `strict: true` plus:

```jsonc
// tsconfig.json (selected fields)
{
  "compilerOptions": {
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitOverride": true,
    "noPropertyAccessFromIndexSignature": true,

    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "lib": ["ES2022", "DOM"]
  }
}
```

### Schema-derived types

The headline TS win is collection types derived from the schema declaration. `defineSchema()` is generic over its argument so the resulting object carries the declarative shape into the type system. Then `TarnClient.create({ schema })` specializes the client over that shape:

```ts
const tarn = await TarnClient.create({ /*...*/ schema: bookishSchema });

await tarn.books.create({
  bookId: 'b1',
  title: 'Foo',
  // ✗ TS error: missing 'isPrivate' (no default declared makes it required)
  // ✗ TS error: unknown field 'titel' (typo)
});

const book = await tarn.books.get('b1');
//    ^? { bookId: string; title: string; author?: string; rating?: number; ... }
```

The collections object on `tarn` is typed dynamically based on the schema, so `tarn.books`, `tarn.settings`, etc. exist iff declared.

### Branded types for crypto material

The crypto layer carries a fleet of distinct-but-string-shaped values: base64url CEK, base64 wrapped-CEK, hex lookup_key, base64 SPKI public key, JWT, etc. Branded types catch confusion at compile time:

```ts
type Brand<T, B> = T & { readonly __brand: B };

export type ShareKey       = Brand<string, 'ShareKey'>;       // base64url, 32 raw bytes
export type LookupKey      = Brand<string, 'LookupKey'>;      // hex, 32 bytes
export type WrappedCEK     = Brand<string, 'WrappedCEK'>;     // base64, 40 bytes
export type Txid           = Brand<string, 'Txid'>;
export type Eid            = Brand<string, 'Eid'>;
export type AppId          = Brand<string, 'AppId'>;
export type ContentId<C extends string = string> = Brand<string, ['ContentId', C]>;
```

Constructor functions live alongside their format validators (`asShareKey(s)` throws if `s` isn't valid base64url of correct length). These never escape to public API except where they were already public — `ShareKey` shows up on `shareEntry`, `Txid` only inside `tarn.advanced.*`.

### Build & package layout

```
client/
  src/
    schema/
      define.ts          # defineSchema, type derivation, validators
      reserved.ts        # base-tier reserved type names
    crypto/              # was crypto.js, now typed; same logic
    storage/
      adapters.ts        # localStorage, indexedDB, memory, custom
    collections/         # generated Collection<T> implementation
    sharing/             # was sharing.js + share-log.js, refactored
    advanced/            # escape hatches
    index.ts             # public API surface
  dist/                  # built; published to npm
    esm/
    cjs/
    types/
  package.json           # exports map: "." -> dist/esm/index.js, types -> dist/types/index.d.ts
  tsconfig.json
  build.config.ts        # esbuild config
```

Build: `esbuild` for ESM + CJS, `tsc --emitDeclarationOnly` for `.d.ts`. No webpack, no rollup. Single `npm run build` produces `dist/`.

---

## API surface in detail

### `TarnClient.create(config) → Promise<TarnClient<S>>`

```ts
type ClientConfig<S extends Schema> = {
  apiBase: string;
  appId: AppId;
  schema: S;
  storage: TarnStorageAdapter;        // required — no opinionated default
  // optional:
  fetchImpl?: typeof fetch;            // for testing
};
```

Restoring a persisted session is automatic: if `storage` returns a valid blob and JWT is unexpired, the client comes up logged-in. Otherwise the app calls `tarn.login()` or `tarn.register()`.

### Collection API (`tarn.<name>.*`)

For each `shareable: true` collection:

```ts
class Collection<T> {
  create(record: T): Promise<T>;
  update(id: PrimaryKeyOf<T>, patch: Partial<T>): Promise<T>;
  delete(id: PrimaryKeyOf<T>): Promise<void>;
  get(id: PrimaryKeyOf<T>): Promise<T | null>;
  list(opts?: ListOpts): Promise<T[]>;

  // Sharing — only present if shareable: true
  share(connection: Connection, id: PrimaryKeyOf<T>): Promise<void>;
  shareWithAll(id: PrimaryKeyOf<T>): Promise<{ ok: number; failed: ShareFailure[] }>;
  unshare(connection: Connection, id: PrimaryKeyOf<T>): Promise<void>;
  listShared(connection: Connection): Promise<T[]>;
}
```

**No txids in the public signature.** Apps work in primary-key space. The SDK maintains an in-memory `primaryKey → latest-txid` map per collection, populated on read and write. Updates use `Eid` tags so reads converge on the live record even across devices.

**`share()` has no `shareKey` parameter.** The SDK keeps a short-lived (~64 entry LRU) cache of recently-written `txid → shareKey`, populated by `create`/`update`. `share()` looks it up; on miss, falls back to fetch + AES-KW unwrap. The common Bookish flow (create-then-share-with-all) lands fully in the cache.

**`update(id, patch)` is a partial update.** SDK reads the current record, merges the patch, encrypts, writes a new entry with `Prev` pointing at the prior. Apps don't see the read-modify-write cycle.

### Connections (`tarn.connections.*`)

```ts
namespace tarn.connections {
  function invite(): Promise<{ url: string; expiresAt: Date }>;
  function accept(inviteUrl: string): Promise<Connection>;
  function list(): Promise<Connection[]>;
  function mute(c: Connection): Promise<void>;
  function unmute(c: Connection): Promise<void>;
  function remove(c: Connection): Promise<void>;
}

type Connection = {
  id: string;             // app-stable
  label?: string;         // optional human label
  mutedAt?: Date;
};
```

Internally these wrap the existing share-keypair / share-inbox / handshake plumbing. `share_pub`, `signing_pub`, etc. are not exposed.

### Lifecycle (`tarn.account.*`, `tarn.recovery.*`, `tarn.session.*`)

```ts
namespace tarn.account {
  function changeCredentials(newEmail: string, newPassword: string, opts?: ChangeOpts): Promise<void>;
  function delete(): Promise<void>;
}

namespace tarn.recovery {
  function export(opts: { format: 'pdf' | 'json' }): Promise<Blob | RecoveryData>;
  // Delivery (download/print/app-operated email/etc.) is the app's job;
  // Tarn never handles plaintext kit material.
}

namespace tarn.session {
  function isLoggedIn(): boolean;
  function clear(): Promise<void>;
  function listDevices(): Promise<Session[]>;
  function revokeDevice(sessionId: string): Promise<void>;
  function revokeAllOthers(): Promise<void>;
}
```

The recovery PDF rendering moves into the SDK (today it's app-side). The SDK supplies a default Tarn-branded layout. Custom layouts are not supported in this iteration; we add a renderer-injection hook only when an app actually needs to override the default. PDF library (likely `pdf-lib` — ESM-first, ~150KB minified) chosen at implementation time.

### `tarn.advanced.*`

Power-user escape hatches. Documented but not in the main README. Available without warning.

```ts
namespace tarn.advanced {
  namespace entries {
    function create(type: string, payload: unknown): Promise<{ txid: Txid; shareKey: ShareKey | null }>;
    function fetchBlob(txid: Txid): Promise<Uint8Array | null>;
    function decryptSharedBlob(blob: Uint8Array, key: ShareKey): Promise<unknown>;
  }
  namespace shareLog {
    function snapshot(connection: Connection, state?: object): Promise<void>;
    function readRaw(connection: Connection): Promise<ShareLogEntry[]>;
  }
}
```

Use cases: prototypes, debugging, integration tests, anything not covered by the typed collection API.

---

## Examples directory

```
tarn/examples/
  README.md                     # index, links to each example
  01-hello-world/
    schema.js
    app.js                      # 30 lines: register, create one record, list it
    README.md
  02-crud/
    schema.js
    app.js                      # ~80 lines: full CRUD with two collections
    README.md
  03-sharing/
    sender.js                   # ~120 lines: write + share with all
    recipient.js                # ~80 lines: accept invite, list friend's library
    schema.js
    README.md
  04-recovery/
    app.js                      # export PDF, simulate password reset
    README.md
```

Each example is runnable with `node app.js` (after a small `register-test-account.sh` setup script). Each example's README explains *why* it's structured the way it is, not just *what* it does. Bookish stays the production reference deployment; examples are the teaching reference.

---

## Migration plan

1. **Schema infrastructure** (~1 day) — `defineSchema`, reserved-namespace enforcement, validators, type derivation. Pure additive, no other SDK code touched.
2. **Collection API** (~2–3 days) — `Collection<T>` impl, primary-key-to-txid mapping, partial-update logic, `Eid` tag wiring. Old `createEntry`/`updateEntry`/`getEntries`/`deleteEntry` move to `tarn.advanced.entries.*` (renamed, semantics identical).
3. **Sharing rebuild** (~2 days) — `tarn.<collection>.share*`, internal CEK cache, `decryptSharedBlob`, `fetchBlob`, fixed `updateShareContent` semantics. Closes the original Bookish ask.
4. **Lifecycle namespaces** (~1–2 days) — `connections`, `recovery`, `account`, `session` reorganization. Mostly mechanical wrapping of existing methods.
5. **Schema publication endpoint + tool** (~1 day) — `PUT /api/v1/apps/{app_id}/schema`, `tools/publish-schema.mjs`. API server change.
6. **TypeScript conversion** (~3–4 days) — strict-from-day-one, branded types throughout. Done in parallel with steps 1–4 if practical (write new code in TS, leave existing JS alone until its module is rewritten).
7. **Build/package** (~0.5 day) — `tsconfig`, esbuild config, `package.json` exports map, `dist/` layout, npm publish dry-run.
8. **Bookish migration PR** (~2–3 days) — rewrite `book_repository.js`, `friends.js`, session bootstrap. Delete the CEK-capture interceptor and the manual blob-format parser. Net: probably -300/+150 lines.
9. **Documentation rewrite** (~1 day) — `client/README.md` becomes a 50-line "build an app on Tarn" tutorial. `TARN_PROTOCOL.md` gets a new top section: "what apps see (SDK API)" vs. "what wire format is (this document)."
10. **Examples directory** (~1 day) — write the four progressive examples.

**Rough total:** 12–17 days of focused work. SDK + API + Bookish + docs + examples.

No production deploys until the end. No protocol changes. Bookish stays on the current SDK until its migration PR lands.

---

## What this redesign does not do

- **No wire-protocol changes.** The Arweave tag scheme, encryption format, share-log mechanics, auth challenge-response, recovery factor protocol — all unchanged.
- **No API server rewrite.** One endpoint added (`PUT /api/v1/apps/{app_id}/schema`); everything else stays.
- **No deprecation overlap.** This is breaking; Bookish migrates in one PR. With one app to migrate and Bookish not in production, the cost of clean rip-and-replace is lower than the cost of carrying parallel APIs.
- **No opinionated session-storage default.** The SDK ships adapters; the app picks. Browser apps, mobile webviews, electron apps, SSR contexts all have legitimately different needs.
- **No app-specific Arweave indexing tags.** Considered, rejected — leaks user data via public tag values, and app-side filtering of decrypted records covers the actual use cases.

---

## Resolved decisions

Five questions surfaced during the design conversation. All are locked in; the doc above reflects the resolutions. Recorded here for traceability.

1. **Schema-mismatch detection at init: NO.** The SDK does not round-trip to Arweave on init to verify its in-process schema matches what's published. Schema publication is the app's responsibility — apps will likely build custom UI / CI flows around it (the `tools/publish-schema.mjs` script is a starting primitive, not a constraint). Revisit if a real "shipped v4 client but forgot to publish v4 schema" footgun materializes in practice.

2. **Recovery PDF rendering inside the SDK: YES.** `tarn.recovery.export({ format: 'pdf' })` returns a PDF Blob with a default Tarn-supplied layout. The PDF library cost (~150–250KB depending on choice) is accepted; rendering server-side is a non-starter because recovery PDFs contain master key material that must never leave the device unencrypted. Apps cannot customize the PDF layout in this iteration — if/when an app needs a custom layout, we add a renderer-injection hook. Library choice (likely `pdf-lib` for ESM-first + smaller bundle) decided at implementation time.

3. **`tools/publish-schema.mjs` ships as an operator-style tool.** Symmetric to `tools/set-rules.mjs`. App teams can wire it into CI as `npm run publish-schema` or run it manually from a workstation; the script doesn't care.

4. **`tarn.<collection>.update(id, patch)` is partial.** SDK reads the current record, merges the patch, encrypts, writes a new entry. Apps pass only what's changing. Full-replace is `update(id, { ...currentRecord, ...patch })` when explicitly wanted.

5. **TypeScript strictness:** SDK source enables `noPropertyAccessFromIndexSignature` along with the rest of the strictest sensible config. App `tsconfig`s are not required to inherit this — Bookish picks its own strictness level.
