# Changelog

All notable changes to Tarn — API, SDK (`tarn-client`), and the wire protocol.
The Tarn SDK is consumed by apps via the `tarn-client` package; the API is
deployed independently at api.tarn.dev. Both move forward on the `dev` branch.

Format roughly follows [Keep a Changelog](https://keepachangelog.com). The
`Unreleased` section accumulates changes between tagged SDK releases.

## [Unreleased]

### Invariant

- **Protocol:** Every data-bearing write to a defined collection MUST carry
  an `Eid` tag. The SDK now upholds this through every public write path
  (typed Collection, advanced escape hatch); the wire protocol and the
  delta-sync surface assume it. "Orphan" entries (rows without an Eid
  tag for a defined collection) are not a valid steady state — the SDK
  no longer produces them.

  Apps with pre-existing orphan data (e.g., entries written via
  `advanced.entries.batchCreate` before this fix, or by SDK versions
  prior to Eid support) won't see those entries through
  `tarn.<collection>.getEntriesSince()`. They still render via the
  lenient `tarn.<collection>.list()` path. To repair: re-upload affected
  entries through the post-fix typed path (`Collection.create` /
  `Collection.batchCreate`), or write a one-off migration that calls
  `tarn.advanced.entries.update(orphan.txid, type, record, [])` per
  orphan — the advanced surface now auto-stamps Eid when `type` matches
  a defined collection, so a same-data update chains a properly-Eid'd
  version via Prev and the resolver picks it as head.

### Fixed

- **SDK:** Orphan-creation through `advanced.entries.*`. Before this
  change, `advanced.entries.{create, update, batchCreate}` accepted a
  `type` string and never auto-stamped Eid + SchemaV — so writes to
  defined collections through the escape hatch silently produced
  orphans. Now: when `type` matches a defined collection, the advanced
  surface derives Eid from the record's primaryKey and stamps Eid +
  SchemaV (in addition to any caller-supplied `extraTags`). Throws if
  the record is missing its primaryKey under that type. Schema-less
  types (e.g., `tarn-share-state`, app-internal) are unchanged — the
  caller still manages tags. `delete` is unchanged because it has no
  payload to derive from; callers writing tombstones for a defined
  collection through the escape hatch must supply Eid themselves or
  use `Collection<T>.delete(primaryKey)`.

- **SDK:** `getEntriesSince` is now reachable from the public typed
  client. The original commit added the method to the bundled legacy
  underlying class but didn't bridge it through the `TarnClient`
  wrapper, so apps that consume the SDK via the typed surface
  (`TarnClient.create(...)` → `tarn.<collection>` / `tarn.advanced`)
  couldn't call it.

  The method is now exposed in two places:
    - `tarn.<collection>.getEntriesSince()` — typed, returns
      `{ entries: Array<{ record, eid }>, deleted: string[] }`. Each
      entry carries its Eid alongside the typed record so callers
      can index local state by Eid (matching the `deleted` shape) or
      by primary key with Eid as the bridge.
    - `tarn.advanced.entries.getEntriesSince(type)` — escape hatch,
      returns the raw shape (untyped `data`, with txid + tags).

  Same cursor underlies both — persisted per `(appId, dlk, type)`.

- **SDK:** `getEntriesSince` now deduplicates events by Eid across server
  pages (last event wins). Without this, an Eid whose multiple rows
  straddled a 25-row page cut could surface as both a live event and a
  delete event in the same call, leaving the consumer's reducer
  dependent on apply-order. Contract is now: **at most one event per
  Eid per `getEntriesSince()` call**.

### Added

- **SDK:** `tarn.<collection>.batchCreate(items)` — typed bulk create.
  Validates every item against the schema, derives Eid per item, stamps
  Eid + SchemaV on every wire-level entry. One rate-limit hit for up to
  25 items. The typed entry point for bulk writes; apps doing imports
  should prefer this over `tarn.advanced.entries.batchCreate`.

  Validation is atomic across the batch: if any record fails, the
  thrown `TarnCollectionError` lists every failing index with its
  reason — and nothing is written. Callers see all-or-nothing
  semantics on the wire (closes #33).

- **SDK:** Per-item `extraTags` support in the underlying `batchCreate`.
  The legacy `extraTags: Tag[]` shape on `advanced.entries.batchCreate`
  still works (applied to every item); the new internal contract is
  `extraTagsPerItem: Tag[][]` for per-item Eid + SchemaV stamping.

- **SDK / API:** Eid-narrowed single-record read path.
  - New API filter `GET /api/v1/entries?…&eid=<eid>` returns at most one live
    entry (the resolved head) with blob bytes inlined as base64.
  - New SDK method `tarn.getEntryByEid(type, eid)` decrypts inline, returns
    `{ txid, data, tags } | null`. Single round trip end-to-end.

- **SDK / API:** Delta-sync polling (`?since=<cursor>` + `tarn.getEntriesSince(type)`).
  - API emits semantic events per Eid: `{ eid, txid, tags, data }` for live
    state and `{ eid, deleted: true }` for removals. Blob bytes inlined,
    25-event page cap.
  - SDK persists the cursor per `(appId, dlk, type)` in IndexedDB and
    paginates internally. Callers get a single `{ entries, deleted }`
    result regardless of how many server pages were drained.
  - Composite cursor `(cached_at, txid)` backed by new D1 index
    `idx_entries_since` (migration `0019_delta_sync_index.sql`).

- **SDK:** Ciphertext blob cache in IndexedDB
  ([client/src/blob-cache.ts](client/src/blob-cache.ts)).
  - Keyed by `(appId, dlk, txid)`. Stores encrypted bytes only — plaintext
    never lands on disk, preserving at-rest encryption properties.
  - Consulted by `#fetchBlob`; pre-populated by `createEntry`, `updateEntry`,
    `batchCreate`, and `getEntryByEid` (inline blob).
  - Same-device read-after-write now requires zero blob network round trips.

- **Protocol doc:** [docs/TARN_PROTOCOL.md](docs/TARN_PROTOCOL.md) documents
  the new `&eid=` and `&since=` query parameters on the entries endpoint.

### Changed

- **SDK:** `Collection.delete(primaryKey)` is now **idempotent**. A delete on
  a primary key with no live entry returns silently instead of throwing
  `TarnCollectionError`. Matches REST DELETE semantics; prevents
  retry-loop bugs from latching into permanent errors when the work has
  already been done. Consumers that wrap delete in try/catch to swallow
  "already gone" errors can simplify.

- **SDK:** `Collection.get` / `Collection.update` / `Collection.delete` /
  `Collection.share` / `Collection.shareWithAll` no longer fan out across
  the whole collection to locate one record's txid. Each issues a single
  Eid lookup. Same fix applied to all internal share-state lookups
  (`#findShareStateEntry` — connections, pending requests, muted
  connections, issued invites).

- **API:** Tombstones never cross the wire as protocol-level rows. The
  delta endpoint resolves them server-side and emits a semantic
  `{ eid, deleted: true }` event. The wire-format "tombstone" vocabulary
  stays inside the server.

### Fixed

- **SDK:** Throttling on routine Collection operations. Before this change,
  any single-record op (`delete`, `update`, `get`, single-record share)
  fetched every entry in the collection and decrypted each blob just to
  locate the target's txid. For a 200-entry collection that meant 201
  reads per op against the 300/hr IP rate-limit bucket — a couple of
  deletes could trip throttling and break dependent flows (the trigger
  was Bookish's `replayPending` death-loop).

### Performance

- Single-record Collection ops: from O(N) reads + decrypts to 1 round trip.
- Warm `list()` reads: from 1 metadata + N blob fetches to 1 metadata + 0
  blob fetches (cache hits).
- Sustained multi-device polling: from O(N) reads per poll to 1 read per
  warm poll + 1 read per actual change. A 200-entry library polling every
  minute fits comfortably inside the 300/hr budget indefinitely.

### Upgrade notes (consumers)

The wire-level changes are additive — old SDK builds continue to work
against the new API. To pick up the SDK benefits:

```
cd <tarn-checkout> && git pull origin dev
cd client && npm install && npm run build
# then rebuild downstream bundles that consume ../tarn/client/dist/esm/
```

No version bump on `tarn-client` (still `0.3.0`) for this batch — the
next tag will roll this in.
