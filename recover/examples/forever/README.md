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
- **Arweave** (Phase 9) — the durable home. Once published, the page
  itself outlives any of these services. The Tarn project plans to
  publish this reference page to Arweave; Bookish (and other apps that
  fork it) will publish their themed copies the same way.

For air-gapped recovery (the limit case the page is designed for), users
can save the file locally and open it from disk. Modern browsers run it
fine — every dependency is already inlined.

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
bytes. This is enforced by `tests/forever-page.test.ts` and matters for
the Phase 9 Arweave publish (re-publishes of an unchanged page should
be cheap no-ops with stable txids).

If reproducibility ever flakes:

- Look for `Date.now()` / `Math.random()` / non-deterministic env
  variables that crept into the bundle.
- Confirm esbuild options haven't grown a randomising minifier.
- Confirm the `@tarn/recover` source itself doesn't embed a build
  timestamp.
