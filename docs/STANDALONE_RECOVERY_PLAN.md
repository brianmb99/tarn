# Standalone recovery package — implementation plan

> **Status:** Approved direction. Scope converged with Bookish 2026-05-08; ready for phased implementation. This document is the working implementation guide for `@tarn/recover` — analogous to [RECOVERY_PLAN.md](RECOVERY_PLAN.md) for the recovery v2 work.
>
> **Source materials:**
> - Bookish's original ask: [STANDALONE_RECOVERY_PACKAGE.md](https://github.com/brianmb99/bookish/blob/dev/docs/tarn-requests/STANDALONE_RECOVERY_PACKAGE.md)
> - Bookish's reply confirming convergence: [STANDALONE_RECOVERY_REPLY.md](https://github.com/brianmb99/bookish/blob/dev/docs/tarn-requests/STANDALONE_RECOVERY_REPLY.md)

## Position on the ask: agree, build it

The architectural argument is correct. "Permanent, encrypted, user-owned" is the platform's core promise; without a packaged way for users to actually exercise it without Tarn being alive, the promise is technically true and practically unenforceable. Every Tarn app inherits the same need; building this once at the platform level is the right factoring.

This isn't a feature request — it's the load-bearing piece that makes Tarn's positioning honest. Worth doing now, before Bookish ships, so the promise is actually backed by a working artifact from day one.

## Decisions on open scope questions

### 1. Share-log and connection data — IN scope for v1

The user's social graph (connections, share-log entries, redeemed invites) is real data living on Arweave under the same architectural promise as the user's owned content. Excluding it would create the awkward state where "permanent recovery" returns books but not the friends the user shared with. Bookish's `forever.html` doesn't strictly need the connection data today, but other Tarn apps almost certainly will, and rebuilding that surface later means breaking the package's API.

V1 of `@tarn/recover` returns:
- All collection entries the user owns.
- The user's connection records (peers + their handshake material as decrypted by the user's keys).
- The user's incoming and outgoing share-log entries (subject to the same per-pair key derivations the live SDK uses).

This adds maybe 30-40% to the implementation effort, but the alternative (ship v1 without it, add it in v2) creates a worse migration story than just doing it once.

### 2. Username (not email) is the input field

Tarn renamed away from email throughout the SDK in Phase 1; using `email` in the recovery package would be the only place that reintroduces it. Bookish-internal mapping (where Bookish's "username" happens to be the user's email) stays a Bookish concern.

```js
recover({ username, accountKey, ... })  // not email
```

### 3. Username may or may not be cryptographically required — verify before locking

Plausible argument that account-key alone could suffice: `recovery_lookup_key` is derived from account-key entropy via HMAC with no salt. So the account record on Arweave is taggable by `recovery_lookup_key`, which is derivable from account-key alone.

But: the account's `recovery_salt` lives inside the wrapped envelope, and `recovery_KEK = Argon2id(accountKey, recovery_salt)` requires the salt to derive the wrapping key. If the salt is fetched from the envelope (which is fetched by `recovery_lookup_key`), then no username needed. If there's a username-bound derivation step somewhere in the chain that I'm forgetting, then yes needed.

**Action:** verify against current envelope shape before fixing the API. If username is genuinely optional crypto-wise, document it as such (and still ask for it in the UX as a weak identity verification — "this is your account, right?"). If required, the API stays as proposed.

### 4. Model B realism — needs explicit framing

Important subtlety the original proposal didn't quite name: **Model B users who never personally saved their account key are NOT recoverable via the standalone reader.** They're recoverable only via the live Tarn API. The standalone reader requires the account key as INPUT.

Implications:
- Model B is a convenience layer on top of Tarn-dependent retrieval, not a substitute for saving the key.
- The "your data is yours forever" promise applies to users who actually saved their account key. Users who relied on Model B retrieval and never saved the key elsewhere are dependent on Tarn being alive.
- This needs to be in the package README and ideally in app-side user-facing copy too.

For Bookish: the engagement-milestone reminders we recommended in TARN_RECOVERY_INTEGRATION.md become more important. The "have you actually saved your account key?" prompt isn't just UX polish — it's the gate between "your data is permanently yours" and "your data is yours as long as Tarn is alive."

### 5. Publish recovery page to Arweave — promoting from stretch to v1

If `forever.html` itself is on Arweave, the saved kit can include the Arweave URL of the recovery page. Even if `getbookish.app` AND `api.tarn.dev` AND `tarn.dev` are all dead, the user's saved kit still has a working recovery path. This is what makes the architectural promise actually durable across vendor death.

Tarn ships an example/reference standalone-exporter HTML in `tarn/examples/`, fully self-contained (no CDN deps, no external scripts). Bookish themes it as `forever.html`. Both are publishable to Arweave.

We'd recommend Bookish promote this from stretch to v1 — it's the difference between "we believe in permanent" and "the artifact proving permanent is itself permanent."

## Proposed API shape

```js
import { recover } from '@tarn/recover';

const reader = await recover({
  username,                    // string
  accountKey,                  // 24-word phrase
  appId: 'bookish',            // app whose data we're reading
  schema: bookishSchema,       // app's defineSchema() output
  arweaveGateways: [           // ordered fallback list
    'https://arweave.net',
    'https://g8way.io',
  ],
  onProgress: (stage, info) => {
    // stage: 'deriving' | 'locating-account' | 'fetching-envelope'
    //      | 'walking-log' | 'decrypting' | 'done'
    // info:  { current, total, message } where applicable
  },
});

// === Owned content ===

reader.collections;                   // ['books', 'authors', ...] — from schema
for await (const book of reader.entries('books')) {
  render(book);                       // typed plaintext per schema
}
const allBooks = await reader.allEntries('books');

// === Connections + sharing ===

const connections = await reader.connections();
// [{ peerUsername, peerAppId, peerSharePub, label, createdAt, ... }, ...]

for await (const event of reader.shareLog({ direction: 'incoming' })) {
  // each event is a typed payload (share, unshare, rotate-identity, etc.)
}

const outgoing = await reader.shareLog({ direction: 'outgoing' });

// === Metadata ===

reader.account;
// { username, appId, kdfVersion, envelopeVersion, schemaVersion, totalGens }

reader.tombstoneCount;                // entries deleted, applied to entries() output
```

Notes on the shape:

- Async iterators where streaming makes sense (`entries`, `shareLog`); awaitable batch helpers (`allEntries`) for callers that want everything in memory.
- `reader.account` exposes vintage metadata so apps can render "this account was created with KDF version X" if useful, but mostly so debugging is possible without inspecting raw blobs.
- Tombstone application is implicit — the iterator yields the post-delete view of the user's content. A `reader.includeTombstones()` option could be added later if a use case emerges, but the default is "show me what's still there."
- Schema-version handling: each yielded entry includes a `_schemaVersion` field if the entry was written under an older schema than the one the caller passed. App decides how to migrate / display.
- **Field fidelity:** the reader yields each schema field's value verbatim. No re-encoding, no normalization. For Bookish's `coverImage: 'string?'` (base64 PNG/JPEG), the original base64 string comes back exactly as written. Same for any other "string holding opaque payload" fields.

## Forward-compatibility contract

This is the load-bearing commitment. Promote to a top-level section in the package README, capitalized.

### What we promise

**A user's data, once written and confirmed-on-Arweave, must be decryptable by `@tarn/recover@vN` for any future N, given only:**
- The user's account key
- The user's username (if cryptographically required)
- A working Arweave gateway

This must hold across:
- KDF version upgrades (PBKDF2 legacy → Argon2id current → whatever's next).
- Envelope-format upgrades (current v1 → hypothetical v2 → ...).
- Schema evolution (apps bumping schemas with renamed/added/removed fields).
- Tarn API changes (the contract is independent of the live API entirely).

### How we keep that promise

- **Envelope format is wire-versioned.** Every wrapped_data_key has a `v` field. The package retains decoders for every version it has ever supported. Adding a new envelope format is additive (v2 coexists with v1 reading), never replacing.
- **KDF parameters live in the account record.** Already true. The package picks the right KDF based on what the record says, not based on what's "current."
- **Schema-evolution policy is explicit.** Old data tagged with schema-vN must come back legibly even if the app's current schema is vN+M. The package yields `_schemaVersion` so apps can route to the right migration code.
- **Adding new wire features is additive.** New optional fields in account records, new factor types in envelopes, new index strategies on Arweave — all coexist with old shapes.
- **Decoders are tested in CI against fixtures.** A "fixture vault" of synthetic Arweave-ish data in every supported envelope version, regenerated never (only added to). Each release of `@tarn/recover` runs the fixture suite to guarantee no decoding regression.

### What this constrains us NOT to do

- **No "we're cleaning up the envelope" PRs that drop legacy support.** Cleanup is allowed; legacy decoder removal is not.
- **No moving secrets out of the user-controlled chain into Tarn-server-controlled storage.** Anything that breaks the "account key + Arweave = recovery" property is a contract violation regardless of how clever it is.
- **No required dependencies on Tarn-server side endpoints.** The package's promise is to be Tarn-server-independent. If a future feature requires a Tarn-server roundtrip to decrypt, that feature can ship in the live SDK but cannot replace something `@tarn/recover` already supports.

This contract is the entire reason the package exists. Worth treating it as a constitutional commitment.

## Naming and packaging

**Package:** `@tarn/recover` published as a separate npm package.

Reasoning:
- Verb-not-noun reads better at call sites: `import { recover } from '@tarn/recover'`.
- Separate package decouples release semantics. The live SDK can ship breaking changes; `@tarn/recover` can stay locked into longer-lived versions reflecting the forward-compat contract.
- Explicit "I want recovery" import in user-facing apps signals intent — it's not part of the daily-use SDK.
- Allows different bundling strategies (browser-deliverable WASM-Argon2 included by default; live SDK doesn't pay that cost).

Sub-export of `tarn-client` was the alternative. We considered it; rejected because of the coupled-release-cadence problem.

## Implementation plan (phased)

Modeled on the RECOVERY_PLAN.md phasing that worked well for the recovery v2 work.

### Phase 1 — Audit existing read path; carve out reusable pieces

**Goal:** identify exactly what the live SDK does to read user data, and figure out what's reusable for an Arweave-direct reader vs what needs to be net-new.

Likely findings (to verify):
- KDF + envelope decryption: reusable verbatim.
- Wrapped-DEK chain unwrapping: reusable verbatim.
- Schema-driven decoding: reusable, but currently coupled to the SDK's collection-namespace abstractions; needs decoupling.
- Arweave reads: currently routed through the API cache. Net-new: gateway-direct read with appropriate tag indexing.
- Share-log / connection record parsing: partly reusable (the post-fetch decode); the fetch-from-Arweave-direct path is net-new.

Output: a list of "borrow these modules" + "new code for these layers" + a directory structure for `@tarn/recover`.

### Phase 2 — Gateway-direct read primitives

**Goal:** a minimal Arweave-gateway client with the tag queries needed to find:
- An account record by `recovery_lookup_key`
- A user's content blobs by data-lookup-key + collection-tag
- A user's share-log entries by stealth-tag

Multi-gateway fallback. GraphQL for queries (matching what arweave.net exposes), direct HTTP for blob fetches.

**Failure handling:** any of the following on a gateway → try the next one in the configured list, surface the retry via `onProgress`, only fail the whole `recover()` call when all gateways are exhausted:
- Connection error / timeout
- HTTP 5xx
- HTTP 429 (rate-limited) — common on public gateways under load
- "TX not found" responses where the TX is expected to exist (gateway behind on indexing)

Stale-data semantics aren't a real concern on Arweave once a TX is confirmed — but a slow-to-index gateway might return "not found" for a recently-confirmed TX. Treating that the same as a connection failure (try next) handles the case cleanly.

### Phase 3 — KDF + envelope unwrapping in browser

**Goal:** decoder-side crypto working in a browser context. WASM Argon2 (probably `hash-wasm`), PBKDF2 via WebCrypto, AES-GCM via WebCrypto, AES-KW via shim.

Verify against test fixtures: a known account-key + envelope produces the known DEK chain.

### Phase 4 — Schema-aware reader

**Goal:** given DEK chain + schema + Arweave-direct fetch, yield typed plaintext entries via async iterator. Tombstone application. Schema-version tagging.

### Phase 5 — Connection + share-log support

**Goal:** the social-graph data, with appropriate per-pair key derivations.

### Phase 6 — Forward-compat decoder framework + fixture suite

**Goal:** the structural commitment to the contract. Fixture vault, decoder dispatch by envelope version, CI matrix.

### Phase 7 — Reference HTML in `tarn/examples/`

**Goal:** an app-agnostic standalone exporter HTML page that uses `@tarn/recover`. Themed by Bookish to become `forever.html`.

### Phase 8 — Documentation, README, forward-compat contract

**Goal:** the package's README is the place the contract lives. Public docs covering API, contract, gateway-fallback model, edge cases (rotated keys, multi-app accounts, deleted entries, Model B caveat).

### Phase 9 — Publish to Arweave

**Goal:** the example HTML page itself published to Arweave. Bookish takes the same route for their themed `forever.html`.

## Timeline

Bookish's estimate: 1-2 weeks. Honest estimate: **3-5 weeks** of focused work, with the wider end accounting for share-log/connection scope and the forward-compat fixture infrastructure.

Phase breakdown:
- Phase 1 (audit): 2-3 days
- Phase 2 (Arweave-direct read): 4-5 days
- Phase 3 (browser crypto): 3-4 days
- Phase 4 (schema-aware reader): 3-4 days
- Phase 5 (sharing/connections): 4-5 days
- Phase 6 (forward-compat infrastructure): 3-4 days
- Phase 7 (reference HTML): 1-2 days
- Phase 8 (docs): 2-3 days
- Phase 9 (Arweave-publish): 1 day

Plus integration testing, edge cases, the inevitable surprises. ~4 weeks for confident shipping.

This is also the kind of work that benefits from getting the contract and fixture suite right in Phase 6 — that's the durable artifact, more so than any single decoder.

## Resolved scope decisions (from Bookish convergence)

The six questions from the original proposal phase have been answered. Captured here for reference; details in [STANDALONE_RECOVERY_REPLY.md](https://github.com/brianmb99/bookish/blob/dev/docs/tarn-requests/STANDALONE_RECOVERY_REPLY.md).

1. **Share-log + connection data — IN v1.** Confirmed.
2. **`username` not `email` in the API.** Confirmed.
3. **Whether username is cryptographically required** — to be answered in Phase 1 audit. UX takes it either way.
4. **`@tarn/recover` as a separate npm package.** Confirmed.
5. **Phase 9 (publish reference HTML to Arweave) in v1 scope.** Confirmed; Bookish accepts the 1-2 days of publish-script work to ship `forever.html` on Arweave alongside the bare reference.
6. **Timeline at 3-5 weeks is fine.** Bookish has no hard deadline; better to ship the right thing.

## Test matrix

Phase 6 (forward-compat decoder framework + fixture suite) builds the structural test infrastructure. Phases 4-5 build the per-feature integration tests. Required coverage:

- **Legacy KDF (PBKDF2) account** — recovery succeeds; correct decoder picked from account record.
- **Current KDF (Argon2id) account** — recovery succeeds.
- **Account that has been through `changeCredentials`** (multiple DEK gens) — all gens unwrap correctly; entries from every gen appear.
- **Account that has been through `rotateAccountKey`** — current account key recovers; old account key fails loudly (not silently with empty results).
- **Model A account** (no `wrapped_account_key` on server) — recovery succeeds via the user-supplied account key. (Server-side storage of the key is irrelevant to the recovery path; this just confirms both modes recover identically given the key as input.)
- **Multi-gateway fallback** — one gateway down (or 429-rate-limited, or returning "not found" for a known-confirmed TX) → next gateway used → recovery succeeds.
- **Tombstoned entries** — must NOT appear in `entries()` output. `tombstoneCount` reflects them.
- **Multi-app account** — user with data in `appId: 'bookish'` AND `appId: 'appX'` — recovering with `appId: 'bookish'` returns ONLY the Bookish data. No intermingling. Each app is a separate recovery call.
- **Connection records survive `recoverAccount` and `changeCredentials`** — peer relationships established before either operation are still readable post-operation.
- **Share-log replay** — incoming + outgoing entries decoded with correct per-pair derivations.

## What we don't intend to do

- Build a "discoverability" layer for finding which Tarn apps an account has data in. Apps are addressed by `appId` provided at recover time; if a user has data in three apps, they recover three times with three appIds.
- Ship a CLI version of the recovery tool. Browser-only for v1. CLI is a future thing if a real use case emerges.
- Build write paths into `@tarn/recover`. It's strictly read-only. Apps that want to migrate data go through the live SDK after recovery.
- Provide audit/forensics tools (e.g., "show me every credential change this account ever did"). Possible future package; out of scope here.
- **Support partial / incremental recovery.** The package does a full read of a user's history each time `recover()` is called. No "give me only books written after timestamp X" — that's a Tarn-server-and-cache concern. Apps that want partial recovery either use the live SDK or run the full reader and filter app-side.

## Sub-agent execution notes

When spawning agents to implement individual phases:

- **Always link to this doc** in the sub-agent prompt for full context.
- **One PR per phase** is the right granularity. Phase 1 (audit) is a special case — pure analysis, produces a report doc, no code.
- **Verify each phase before moving on.** Each phase has acceptance criteria specific to its scope.
- **Phase 6 (forward-compat infrastructure) deserves extra rigor.** Get the fixture vault and decoder dispatch right before adding new envelope versions. The contract is enforced by tests; tests are enforced by the fixtures.
- **Watch for the in-package vs SDK boundary.** Anything that already works in the live SDK and is purely client-side can be borrowed; anything that touches the live API must be replaced with Arweave-direct equivalents.

Bookish-side integration once `@tarn/recover` ships: their estimate of 3-5 days seems right, plus 1-2 days for the Arweave publish workflow.
