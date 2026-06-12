# `bootstrap.html` — the permanent recovery URL

Arweave is immutable: every published [forever-page](../forever/README.md)
gets a new txid, so a user who bookmarks one specific page can never be
moved to an improved version. The **forever-bootstrap** is the fix — a
tiny, logic-frozen page whose only job is to find the latest published
forever-page for one app and forward the user to it. Its txid is the one
URL an app puts in recovery kits, docs, and bookmarks. Publishing a new
forever-page changes what the bootstrap *finds*, never what the bootstrap
*is*, so the bookmarked URL stays valid forever.

There is **one bootstrap per app**, shared by every user of that app.
Nothing user-specific is in the URL or the page; users enter credentials
only on the (verified, immutable) destination page, never here.

## How discovery works

The page runs one owner-pinned GraphQL query against an ordered gateway
list:

```graphql
{
  transactions(
    owners: ["<operator owner address>"]        # ← the security boundary
    tags: [
      { name: "App",    values: ["tarn-recover"] }
      { name: "Type",   values: ["forever-page-pointer"] }
      { name: "App-Id", values: ["<app id>"] }
    ]
    first: 20
    sort: HEIGHT_DESC
  ) { edges { node { id tags { name value } block { height timestamp } } } }
}
```

The `owners:` filter is load-bearing. Arweave tags are a free-for-all —
anyone can publish a blob carrying this tag set, and without the pin a
`HEIGHT_DESC` query would hand an attacker the "latest" slot, redirecting
users to a credential-phishing clone. With the pin, "latest" means
"latest **signed by the operator's key**". The owner address —
`base64url(sha256(uncompressed secp256k1 pubkey))`, the normalized form
every gateway indexes for Ethereum-signed data items — is baked into the
page at build time and printed by `publish-forever.mjs` on every run that
has a signing key.

Each pointer's body is the txid of a forever-page. Before offering it,
the bootstrap verifies the target really is an owner-signed
`Type=forever-page` blob with the matching `App-Id` (one more cheap
query); pointers that fail any step are skipped, newest-first, up to
five deep.

The page then shows — it does **not** auto-redirect — the latest
version, its publish date, a one-click continue link, the pinned
destination URL (for users who prefer an immutable bookmark), and a
collapsible list of every published version. The version list is the
escape hatch if a new page ships broken: every old version keeps working
forever.

If every gateway fails, the page degrades to a static link to the
`fallbackTxid` baked in at build time — the newest page known when the
bootstrap was built. Raw txid fetch is the weakest possible gateway
dependency; any future gateway can serve it.

## What the bootstrap's txid freezes forever

Because the bootstrap's own txid must never change, everything baked
into it becomes a protocol constant:

- the **operator owner address** (rotating the publish key strands every
  bookmarked bootstrap — see `docs/OPERATIONS.md` on key handling);
- the **tag scheme** (`App=tarn-recover`, `Type=forever-page-pointer`,
  `App-Id=<id>`);
- the gateway list and fallback txid — lower stakes than the two above:
  discovery only needs *one* listed gateway alive, and a dead fallback
  txid still resolves on any future gateway that serves Arweave data.
  Stale entries here degrade convenience, not the trust model.

That is why the page is deliberately dumb: vanilla JS, no SDK, no
dependencies, no inputs, no eval, ~19 KB. The recursion of "who updates
the updater?" terminates at an artifact too simple to ever need updating.
A v2 bootstrap *can* be published if ever needed — old bootstraps keep
working, since they run the same discovery against the same tag scheme
and find every future page.

## Build

```sh
cd recover
node scripts/build-bootstrap.mjs \
  --app-id example-app \
  --app-name "Example App" \
  --owner-address <printed by publish-forever.mjs> \
  --fallback-txid <txid of the newest published forever-page> \
  [--gateway https://arweave.net] [--gateway https://permagate.io] \
  [--out dist/bootstrap.html]
```

The build is deterministic (same inputs → same bytes) and does not
bundle: `bootstrap.js` is inlined verbatim, so the published artifact is
the audited source, character for character.

Order of operations for a new app: publish the app's themed forever-page
first (`publish-forever.mjs --app-id <id> --confirm`), note the printed
page txid (→ `--fallback-txid`) and owner address (→ `--owner-address`),
then build and publish the bootstrap.

## Publish

```sh
TARN_OPERATOR_WALLET=<hex> node scripts/publish-forever.mjs \
  --bootstrap --app-id example-app --confirm
```

`--bootstrap` stamps `Type=forever-bootstrap` (so bootstraps never
pollute forever-page enumeration), applies bootstrap-sized preflight
bounds, and publishes **no pointer** — the bootstrap's txid is itself the
stable entry point. Record the txid: it is the app's permanent recovery
URL.

Republishing the bootstrap is almost never warranted. The only changes
that require it are changes to the frozen constants above; cosmetic or
copy changes are not worth stranding bookmarks for (old bootstraps keep
working either way).

## What apps put in their recovery kit

1. **Headline link:** the bootstrap URL (`https://arweave.net/<bootstrap txid>`)
   — "always takes you to the newest recovery page."
2. **Pinned fallback:** the concrete forever-page txid current at kit
   creation — "this exact copy works forever, no lookup involved."

The pinned txid is the forward-compatibility contract artifact; the
bootstrap is convenience layered on top. Present them in that spirit.

## Scope guard

The bootstrap takes **no input**. It has no form elements and must never
grow any — credentials belong on the destination forever-page. This and
the owner-pinning of every query are enforced by
`tests/bootstrap-page.test.ts`.
