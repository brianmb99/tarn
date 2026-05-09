# `@tarn/recover`

> Standalone, server-free recovery package for Tarn-backed accounts. A user
> with their account key (or username + password) can read their data
> directly from Arweave gateways, with no Tarn API in the loop.

## Status

Phases 2–5 of the
[Standalone Recovery Plan](../docs/STANDALONE_RECOVERY_PLAN.md) are
landed. The package is **usable end-to-end** for owned-collection content
plus the user's social graph (connections + per-pair share-log).
Forward-compatibility fixtures (Phase 6), the reference HTML (Phase 7),
the full forward-compat contract (Phase 8), and Arweave-publish (Phase 9)
remain.

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

## Layout

```
recover/
├── src/
│   ├── index.ts                # public entry — recover() + re-exports
│   ├── recover.ts              # orchestrator
│   ├── crypto/                 # KDF + envelope (borrowed from client/src/crypto.ts)
│   ├── decrypt/                # factor-KEK + DEK-chain unwrap
│   ├── gateway/                # multi-gateway client + tag-filtered queries
│   ├── reader/                 # schema-aware Reader + SharingReader
│   └── sharing/                # share-log / HPKE primitives (borrowed)
├── tests/                      # *.test.ts unit + integration tests
└── scripts/                    # build + test runners (mirror tarn-client)
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
