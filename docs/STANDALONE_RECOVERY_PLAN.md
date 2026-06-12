# Standalone recovery package — implementation plan

> **Status:** ✅ Implementation complete (2026-05-09). All phases (1-9) shipped to dev. `@tarn/recover` is functionally done; the operator publishes the forever page to Arweave when ready (Phase 9 deliverable: `recover/scripts/publish-forever.mjs`, dry-run by default). This document remains the canonical reference for the package's design and forward-compatibility contract.
>
> **Source materials:**
> - Bookish's original ask: [STANDALONE_RECOVERY_PACKAGE.md](https://github.com/brianmb99/bookish/blob/dev/docs/tarn-requests/STANDALONE_RECOVERY_PACKAGE.md)
> - Bookish's reply confirming convergence: [STANDALONE_RECOVERY_REPLY.md](https://github.com/brianmb99/bookish/blob/dev/docs/tarn-requests/STANDALONE_RECOVERY_REPLY.md)

## Position on the ask: agree, build it

The architectural argument is correct. "Permanent, encrypted, user-owned" is the platform's core promise; without a packaged way for users to actually exercise it without Tarn being alive, the promise is technically true and practically unenforceable. Every Tarn app inherits the same need; building this once at the platform level is the right factoring.

This isn't a feature request — it's the load-bearing piece that makes Tarn's positioning honest. Worth doing now, before Bookish ships, so the promise is actually backed by a working artifact from day one.

## Decisions on open scope questions

### 1. Share-log and connection data — IN the SDK; OUT of the forever-page promise

**Revised 2026-05-08, after the Phase 5 work surfaced an architectural fact and a positioning question.**

The earlier framing here was "social data in v1 because excluding it punts a worse migration story." That conflated two questions that should have been separated:

1. **What can the SDK read?** Whatever the protocol exposes. Useful surface for live-context apps.
2. **What does the permanent forever-page promise commit us to?** The user's owned data. Period.

The right answer:

- **The SDK (`@tarn/recover`) supports both surfaces.** Phase 5 ships connections + share-log readers. Live-context apps (Settings → Export, developer tools, etc.) can call them.
- **The forever-page artifact (Phase 7's reference HTML, and Bookish's `forever.html`) surfaces only owned content.** The permanent promise is scoped to the durable kit-saving use case.
- **Forward-compatibility contract is scoped to owned content.** Envelope-format-vN must decrypt with @tarn/recover@vM forever — for owned content. Share-log + HPKE protocol decoders are best-effort and may be revised in future versions; they are NOT under the contract.

This separation also falls out naturally from the math: the `accountKey` factor (the durable BIP39 phrase you save once) cannot derive the X25519 sharing keypair, so connections/share-log are mathematically inaccessible from that factor anyway. Only the `(username, password)` factor can read social data, and that's a "you still have your live credentials" recovery posture, not a "permanent durable kit" recovery posture.

V1 of `@tarn/recover` returns:
- **Always:** all collection entries the user owns.
- **Only via password+username factor (and best-effort, not under forward-compat contract):** connections + share-log.

The forever-page reference HTML in `tarn/examples/` (Phase 7) renders only owned content. Apps theming it (`forever.html` in Bookish) inherit that scope.

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

The reader accepts **either** factor — username + password, OR account key. Both factors independently locate the credential blob on Arweave (post-RLk dual-tag fix) and independently unwrap the DEK chain. Apps surface whichever inputs the user has on hand.

```js
import { recover } from '@tarn/recover';

const reader = await recover({
  appId: 'bookish',            // app whose data we're reading
  schema: bookishSchema,       // app's defineSchema() output
  arweaveGateways: [           // ordered fallback list
    'https://arweave.net',
    'https://permagate.io',
  ],

  // Provide ONE of the following auth blocks:
  credentials: { type: 'password', username, password },
  // OR:
  credentials: { type: 'accountKey', accountKey },

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

### Phase 1 — Audit existing read path; carve out reusable pieces ✅ done

**Goal:** identify exactly what the live SDK does to read user data, and figure out what's reusable for an Arweave-direct reader vs what needs to be net-new.

Likely findings (to verify):
- KDF + envelope decryption: reusable verbatim.
- Wrapped-DEK chain unwrapping: reusable verbatim.
- Schema-driven decoding: reusable, but currently coupled to the SDK's collection-namespace abstractions; needs decoupling.
- Arweave reads: currently routed through the API cache. Net-new: gateway-direct read with appropriate tag indexing.
- Share-log / connection record parsing: partly reusable (the post-fetch decode); the fetch-from-Arweave-direct path is net-new.

Output: a list of "borrow these modules" + "new code for these layers" + a directory structure for `@tarn/recover`.

### Phase 2 — Gateway-direct read primitives ✅ done

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

### Phase 3 — KDF + envelope unwrapping in browser ✅ done

**Goal:** decoder-side crypto working in a browser context. WASM Argon2 (probably `hash-wasm`), PBKDF2 via WebCrypto, AES-GCM via WebCrypto, AES-KW via shim.

Verify against test fixtures: a known account-key + envelope produces the known DEK chain.

### Phase 4 — Schema-aware reader ✅ done

**Goal:** given DEK chain + schema + Arweave-direct fetch, yield typed plaintext entries via async iterator. Tombstone application. Schema-version tagging.

### Phase 5 — Connection + share-log support ✅ done (in SDK; not surfaced on forever page)

**Goal:** the social-graph data, with appropriate per-pair key derivations.

### Phase 6 — Forward-compat decoder framework + fixture suite ✅ done

**Goal:** the structural commitment to the contract. Fixture vault, decoder dispatch by envelope version, CI matrix.

**Scoped to owned content only.** Per the revised decision in §1 above, the forward-compat contract covers the envelope formats and content-blob formats needed for owned-content recovery. Share-log and HPKE-inbox shapes are best-effort and explicitly NOT under the contract — no fixtures required for them in Phase 6.

### Phase 7 — Reference HTML in `tarn/examples/` ✅ done (`recover/examples/forever/`)

**Goal:** an app-agnostic standalone exporter HTML page that uses `@tarn/recover`. Themed by Bookish to become `forever.html`.

**Surfaces only owned-content APIs** — `recover()`, `reader.entries()`, `reader.allEntries()`. Does NOT surface `reader.connections()` or `reader.shareLog()`. The forever page is the artifact of the permanent promise; its scope matches that promise. Other apps that want to use the SDK's social capabilities do so from a live-context UI, not from a permanent-kit page.

### Phase 8 — Documentation, README, forward-compat contract ✅ done

**Goal:** the package's README is the place the contract lives. Public docs covering API, contract, gateway-fallback model, edge cases (rotated keys, multi-app accounts, deleted entries, Model B caveat).

### Phase 9 — Publish to Arweave ✅ done (tool ships; operator runs the publish)

**Goal:** the example HTML page itself published to Arweave. Bookish takes the same route for their themed `forever.html`.

**Tool:** `recover/scripts/publish-forever.mjs`. Dry-run by default (`--confirm` for real publish). Tags include `App=tarn-recover`, `Type=forever-page`, `Version`, `Sha256`. A companion `Type=forever-page-pointer` blob is published on each successful publish so users / apps can discover the latest published txid via Arweave-native query without needing a Tarn-side endpoint.

**Status:** the tool is shipped and tested in dry-run mode; the actual production Arweave publish is the operator's call (real cost). See `recover/examples/forever/README.md` "Arweave publish workflow" for the operator procedure.

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
3. **Whether username is cryptographically required** — answered by the Phase 1 audit: NO for the account-key path (account key alone is sufficient), YES for the password path (`master_key = Argon2id(password, SHA-256(normalizedUsername))` requires both). The reader takes whichever inputs the user has — either `(username, password)` or `accountKey` alone. See API shape above.
4. **`@tarn/recover` as a separate npm package.** Confirmed.
5. **Phase 9 (publish reference HTML to Arweave) in v1 scope.** Confirmed; Bookish accepts the 1-2 days of publish-script work to ship `forever.html` on Arweave alongside the bare reference.
6. **Timeline at 3-5 weeks is fine.** Bookish has no hard deadline; better to ship the right thing.

## Test matrix

Phase 6 (forward-compat decoder framework + fixture suite) builds the structural test infrastructure. Phases 4-5 build the per-feature integration tests. Required coverage:

- **Legacy KDF (PBKDF2) account** — recovery succeeds; correct decoder picked from account record.
- **Current KDF (Argon2id) account** — recovery succeeds.
- **Both auth paths** — every test scenario above must pass with BOTH `credentials: { type: 'password', username, password }` AND `credentials: { type: 'accountKey', accountKey }`. Same outcome via independent crypto chains.
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
