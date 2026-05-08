# `@tarn/recover`

> Standalone, server-free recovery package for Tarn-backed accounts. A user
> with their account key can read their data directly from Arweave gateways,
> with no Tarn API in the loop.

## Status

This is **Phase 2 scaffolding** of the
[Standalone Recovery Plan](../docs/STANDALONE_RECOVERY_PLAN.md). Phase 2
delivers the package layout plus the gateway-direct read primitives that
later phases will orchestrate. Public API, KDF/envelope decoders, the
schema-aware reader, sharing/connections, the forward-compatibility
fixture suite, and the reference HTML are all later phases. The package
is **not yet usable end-to-end**.

Full README + forward-compatibility contract land in Phase 8.

## What ships in Phase 2

The `gateway/` module:

- `ArweaveClient` — single-gateway HTTP/GraphQL client (HTTP fetches for
  blob bodies, POST for GraphQL queries, configurable per-call timeout).
- `MultiGatewayClient` — wraps an ordered list of `ArweaveClient`s with
  fallback on connection error / timeout / HTTP 5xx / HTTP 429 / "TX not
  found." Surfaces retry attempts via an optional `onProgress` callback.
- `queries.ts` — the high-level tag-filtered queries the later phases need:
  `findCredentialBlob`, `findAppBlob`, `findContentBlobs`,
  `findShareLogBlobs`, `findShareInboxBlobs`, `findPasskeyCredentials`.

These are intentionally low-level; they return rich objects (parsed body
JSON, tag map, txid, block height) so later phases can decide what to
keep.

## Layout

```
recover/
├── src/
│   ├── index.ts             # public entry — currently re-exports gateway/
│   └── gateway/
│       ├── arweave-client.ts
│       ├── multi-gateway.ts
│       ├── queries.ts
│       └── index.ts
├── tests/                   # *.test.ts unit + integration tests
└── scripts/                 # build + test runners (mirror tarn-client)
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
