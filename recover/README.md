# `@tarn/recover`

> Standalone, server-free recovery package for Tarn-backed accounts. A user
> with their account key (or username + password) can read their data
> directly from Arweave gateways, with no Tarn API in the loop.

## Status

Phases 2–6 of the
[Standalone Recovery Plan](../docs/STANDALONE_RECOVERY_PLAN.md) are
landed. The package is **usable end-to-end** for owned-collection content
plus the user's social graph (connections + per-pair share-log), and the
forward-compatibility decoder framework + fixture vault are in place. The
reference HTML (Phase 7), full README polish (Phase 8), and
Arweave-publish (Phase 9) remain.

## What ships through Phase 5

```js
import { recover } from '@tarn/recover';

const reader = await recover({
  appId: 'bookish',
  schema: bookishSchema,
  arweaveGateways: ['https://arweave.net', 'https://g8way.io'],
  credentials: { type: 'password', username, password },
  // OR: credentials: { type: 'accountKey', accountKey },
  onProgress: (stage, info) => console.log(stage, info),
});

// Owned content
for await (const book of reader.entries('books')) render(book);

// Social graph (Phase 5 — password factor only; see caveat below)
const peers = await reader.connections();
for await (const event of reader.shareLog({ direction: 'incoming' })) {
  // typed event union: add | update | rotate | remove | snapshot |
  // rotate_identity, with `connection`, `seq`, `verified` metadata
}
```

The `gateway/` module exposes the lower-level primitives later phases /
custom callers can use directly: `ArweaveClient`, `MultiGatewayClient`
(multi-gateway fallback on connection error / timeout / HTTP 5xx / 429 /
"TX not found"), and tag-filtered queries
(`findCredentialBlob`, `findContentBlobs`, `findShareLogBlobs`,
`findShareInboxBlobs`, etc.).

### Account-key vs password factor

The `password` factor lights up the **full** surface: owned content +
connections + share-log. The `accountKey` factor lights up owned content
only — `connections()` returns `[]` and the share-log iterators yield
nothing. The reason: the X25519 sharing keypair is derived from
`master_key`, which is derived from `(username, password)` and is rotated
on every credential change. The recovery factor cannot reach it. This
matches an architectural property of the live SDK: `recoverAccount`
itself rotates `share_priv` — pre-rotation share-log entries become
unreadable to anyone who only has the account key. See
`src/crypto/share-key.ts` for the full explanation.

## Forward-compatibility contract

This package's reason to exist is the constitutional commitment that **a
user's data, once written and confirmed-on-Arweave, must remain
decryptable by `@tarn/recover@vN` for any future `N`** — given only the
account key (or username + password) and a working Arweave gateway.

The full contract is in
[`docs/STANDALONE_RECOVERY_PLAN.md`](../docs/STANDALONE_RECOVERY_PLAN.md)
"Forward-compatibility contract" section. The structural enforcement
lives in this package:

- **Envelope decoders are version-dispatched.** `src/crypto/envelope/`
  contains one module per envelope wire version (`v1.ts` today).
  `index.ts` reads the `v` field and routes to the right decoder.
  Adding `v2` is purely additive — drop a `v2.ts` and register it; old
  versions are never removed or modified.
- **Fixture vault.** `fixtures/envelope-vN/` holds frozen synthetic
  envelopes for every supported version. They are immutable artifacts;
  the only allowed change is adding new files. See
  [`fixtures/README.md`](fixtures/README.md) for the rules.
- **CI enforcement.** `tests/forward-compat.test.ts` runs every fixture
  through the full pipeline on every release. `tests/fixture-vault.test.ts`
  hashes the vault and fails if any tracked file is missing, modified,
  or unlisted.

Scope: the contract covers **owned content only.** Share-log and HPKE
shapes are best-effort and explicitly NOT under contract — see the plan
doc §1 (revised 2026-05-08) for the rationale.

## Layout

```
recover/
├── src/
│   ├── index.ts                # public entry — recover() + re-exports
│   ├── recover.ts              # orchestrator
│   ├── crypto/                 # KDF + envelope (borrowed from client/src/crypto.ts)
│   │   └── envelope/           # version-dispatched decoder modules (v1.ts + index)
│   ├── decrypt/                # factor-KEK + DEK-chain unwrap
│   ├── gateway/                # multi-gateway client + tag-filtered queries
│   ├── reader/                 # schema-aware Reader + SharingReader
│   └── sharing/                # share-log / HPKE primitives (borrowed)
├── fixtures/                   # forward-compat fixture vault (immutable)
│   ├── README.md               # vault rules / contract enforcement
│   ├── manifest.json           # SHA-256 manifest, source of truth for meta-test
│   └── envelope-v1/            # frozen v1 fixtures (never deleted/modified)
├── tests/                      # *.test.ts unit + integration tests
│                                #   ├── forward-compat.test.ts (fixture suite)
│                                #   └── fixture-vault.test.ts  (manifest meta-test)
└── scripts/                    # build + test runners + fixture generator
```

## Development

From the package root:

```
npm install
npm run typecheck
npm test
npm run build
```

Tests run via `node --import tsx --test`. Build emits ESM via esbuild
plus `.d.ts` files via `tsc --emitDeclarationOnly` — same pipeline as
`tarn-client`.

The cross-validate live tests
(`tests/recover-cross-validate.test.ts`,
`tests/sharing-cross-validate-live.test.ts`) require `wrangler dev`
running on `RECOVER_API_BASE` (defaults to `http://localhost:8788`) with
the migrations applied. They skip cleanly otherwise.
