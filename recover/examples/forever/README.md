# `forever.html` — reference standalone recovery page

This is the reference HTML page that exercises `@tarn/recover` end-to-end
in a browser. It is the artifact of the permanent owned-content promise:
given a user's account key (or username + password), it locates their
account on Arweave, decrypts every collection in their app's schema, and
hands the data back as downloadable files. No backend, no Tarn API, no
runtime CDN dependency.

## What gets built

```
recover/
├── examples/forever/      ← source (HTML template, CSS, TS entry)
└── dist/forever.html      ← single self-contained file (built artifact)
```

Build:

```
cd recover
npm run build:forever      # just the page
npm run build              # full SDK build, then the page
```

The build script (`recover/scripts/build-forever.mjs`) bundles
`page.ts` (and the entire `@tarn/recover` SDK it imports) via esbuild,
then inlines the resulting JS + CSS into the HTML template. The output
is a single file with no external script tags, no remote stylesheet
links, and no runtime ESM-from-CDN imports.

Output size today: ~270 KB of HTML/CSS/JS. The bulk of that is
`hash-wasm` and `@noble/curves`, which are required for the in-browser
KDF and decryption.

## Scope: owned content only

The page surfaces only:

- `recover()` — the public entry point.
- `reader.collections` — names declared in the app's schema.
- `reader.entries(name)` / `reader.allEntries(name)` — typed plaintext
  records.

It does **not** surface `reader.connections()` or `reader.shareLog()`.
This is deliberate, per
[`docs/STANDALONE_RECOVERY_PLAN.md`](../../../docs/STANDALONE_RECOVERY_PLAN.md)
§1 (revised 2026-05-08): the forever-page artifact embodies the
permanent owned-content promise. Social capability (connections,
share-log) lives in the SDK for live-context apps to use; it is best-
effort and explicitly NOT under the forward-compatibility contract that
the forever page enforces.

The scope is guarded at CI by `tests/forever-page.test.ts`.

## Hosting

The built file works from any static host. Suggested:

- **Cloudflare Pages / GitHub Pages** — simplest origin, fine for a
  reference deployment.
- **Arweave** — the durable home. Once published, the page itself
  outlives any of these services. See
  [Arweave publish workflow](#arweave-publish-workflow) below for the
  operator script. Bookish (and other apps that fork the page) publish
  their themed copies the same way.

For air-gapped recovery (the limit case the page is designed for), users
can save the file locally and open it from disk. Modern browsers run it
fine — every dependency is already inlined.

## Arweave publish workflow

> **Who this is for:** **app authors publishing their themed forever page.** Bookish runs the publish script for `bookish/public/forever.html`; future Tarn apps run it for their themed copies. The end-user's saved recovery kit references their app's themed-page txid — not this generic reference page.
>
> Publishing this *unthemed reference* page is **optional** and mostly symbolic. End users wouldn't actually use it (it requires manually entering `appId` and pasting in a schema JSON — not realistic recovery UX). Treat the reference page as the source app developers fork. The publish tool is shipped so app authors can reuse the same workflow on their themed copy.

The publish script (`recover/scripts/publish-forever.mjs`) is the last step in the durability story for an app's themed page: once the themed forever page lives on Arweave too, the recovery path keeps working even if `tarn.dev`, the app's own domain, and every other piece of operator-controlled infrastructure is gone.

### Build, then dry-run

```sh
cd recover
npm run build:forever
node scripts/publish-forever.mjs --app-id <your app id>   # DRY RUN by default
```

`--app-id` is required: it stamps the `App-Id` tag on the page and its
pointer, giving each app its own pointer chain. Without it, two apps
publishing through this script would fight over the same "latest" slot.

The dry-run prints the size, sha256, and the Arweave tag set that
would be applied. It makes no network calls and does not sign anything.
Always run it first to confirm the page you're about to publish is the
one you actually built.

### Publish for real

```sh
TARN_OPERATOR_WALLET=<hex-secp256k1-key> \
  node scripts/publish-forever.mjs --app-id <your app id> --confirm
```

(Or `--signing-key <hex>` if you'd rather pass the key on the command
line. The key is the same *shape* as `APP_SIGNING_KEY` in `api/.dev.vars`
but must be a **different, dedicated key** — it is the root of trust for
the recovery-page update channel. See `docs/OPERATIONS.md` § "Operator
publish key".)

The script:

1. Re-runs the same pre-publish checks as the dry-run.
2. Signs the page bytes into an ANS-104 DataItem and uploads via Turbo.
3. Also publishes a tiny `Type=forever-page-pointer` blob whose body
   is the just-published page txid (the "latest" pointer — see
   [Discovery](#discovery-the-latest-pointer) below). Pass
   `--skip-pointer` to publish a release-candidate without promoting
   it to "latest."
4. Waits briefly for the gateway to index, then fetches the page and
   verifies its sha256 matches. Pass `--skip-verify` to trust the
   Turbo response and exit immediately.
5. Prints the txid and gateway URLs.

### Tag scheme

Every published forever-page carries:

| Tag            | Value                                  |
| -------------- | -------------------------------------- |
| `Content-Type` | `text/html`                            |
| `App`          | `tarn-recover`                         |
| `Type`         | `forever-page`                         |
| `App-Id`       | `<app id from --app-id>`               |
| `Version`      | `<version from recover/package.json>`  |
| `Sha256`       | `<sha256 of the published bytes, hex>` |

`App=tarn-recover,Type=forever-page,App-Id=<id>` (owner-pinned — see
below) enumerates every page published for one app across history.
`Sha256=<hex>` answers "has this exact byte-blob ever been published
before?" — useful for spotting re-publishes of unchanged content
(Arweave gives them new txids because data-item signatures embed a
timestamp, but the Sha256 tag matches).

### Discovery (the "latest" pointer)

A user with a saved kit that embeds a specific txid keeps working
forever — that's the durability point. But a user discovering the
recovery page for the first time needs a way to find the **latest**
published forever-page.

Each publish writes an additional tiny `Type=forever-page-pointer`
blob whose body is the just-published forever-page txid. Discovery is
a single GraphQL query — and it **must be owner-pinned**:

```
{
  transactions(
    owners: ["<operator owner address>"]
    tags: [
      { name: "App",    values: ["tarn-recover"] }
      { name: "Type",   values: ["forever-page-pointer"] }
      { name: "App-Id", values: ["<app id>"] }
    ]
    first: 1
    sort: HEIGHT_DESC
  ) {
    edges { node { id } }
  }
}
```

The `owners:` filter is not optional. Arweave tags are a free-for-all:
anyone can publish a blob carrying this tag set, and an unpinned
`HEIGHT_DESC` query would hand whoever published last the "latest"
slot — a phishing vector for a page users type credentials into. The
owner address is `base64url(sha256(uncompressed secp256k1 pubkey))` —
the normalized form gateways index for Ethereum-signed data items —
and is printed by the publish script on every run that has a signing
key. Record it with the txid.

The most recent confirmed entry's body is the txid of the latest
forever-page. The pointer is itself an Arweave blob, so this discovery
mechanism does not depend on any Tarn-operated service.

### The bootstrap page (the user-facing consumer of the pointer)

Users shouldn't run GraphQL queries. The
[forever-bootstrap](../bootstrap/README.md) is the user-facing half of
this mechanism: a tiny page, published once per app, that runs the
owner-pinned discovery query, verifies the result, and forwards the
user — its txid is the one permanent recovery URL an app puts in kits
and docs. Build it with `scripts/build-bootstrap.mjs`; publish it with
`publish-forever.mjs --bootstrap`.

### Recording and sharing the txid

After a successful publish, record the txid and owner address in
operator notes and include them in user-facing recovery copy:

- The headline link in kits should be the app's
  [bootstrap URL](../bootstrap/README.md) — it always reaches the
  newest page, and never changes across re-publishes.
- The just-published page txid (`https://arweave.net/<txid>`) goes in
  as the pinned fallback line: that exact copy works forever, no
  lookup involved, even if a fully compromised operator key publishes
  malicious "latest" pages later.

### Idempotency and re-publishes

Re-running the script publishes a new permanent record on Arweave
every time. Two byte-identical publishes get two different txids
because data-item signatures embed a timestamp; the `Sha256` tag is
stable across them. The script prints a `[NOTE]` warning before
every publish to make this obvious. Operators who want byte-stable
discovery pin a known-good txid in their docs and only re-publish on
substantive changes.

### Out of scope (operator-driven, not automated)

- A continuous-deployment pipeline that publishes on every change is
  out of scope for v1. Real Arweave writes cost real money; promotion
  to "latest" is an explicit operator decision.
- A kit-side fingerprint that proves the published page hasn't been
  swapped behind the user's back. The forward-compatibility contract
  scopes integrity to the user's data, not to the page itself; users
  who want certainty can verify the page's sha256 against a value
  printed by the publish script (or rebuild from source).

## Theming

Apps that ship their own copy (e.g. Bookish's `forever.html`) typically:

1. Pre-fill the `App ID` field with their constant.
2. Pre-fill or hide the schema textarea, embedding their schema JSON
   directly in the page.
3. Restyle the CSS to match their brand.
4. Adjust the copy under "What is this page?" for app-specific
   reassurance ("This is the Bookish recovery page; …").

The recovery logic itself stays identical. Forks should re-build using
this build script (or an equivalent that bundles the SDK source)
whenever they pick up a new `@tarn/recover` release; the SDK is the
load-bearing piece.

## Reproducibility

The build is deterministic — same input bytes produce the same output
bytes. This is enforced by `tests/forever-page.test.ts`. Reproducible
builds matter for the Arweave publish workflow: the publish script
records a `Sha256` tag on every upload, so byte-identical re-publishes
are detectable as such (even though they get new txids — see
[Idempotency and re-publishes](#idempotency-and-re-publishes)).

If reproducibility ever flakes:

- Look for `Date.now()` / `Math.random()` / non-deterministic env
  variables that crept into the bundle.
- Confirm esbuild options haven't grown a randomising minifier.
- Confirm the `@tarn/recover` source itself doesn't embed a build
  timestamp.
