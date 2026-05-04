# 02 — CRUD on two collections

Full create / read / update / delete on a `notes` collection (with an enum field) plus a generic key/value `settings` collection. Demonstrates schema validation, partial-merge updates, and multiple collections in one schema.

## Setup

```bash
# In a separate terminal, start a local Tarn API.
cd ../../api
npx wrangler d1 migrations apply tarn-api --local
npx wrangler dev --port 8787
```

```bash
# In this directory:
npm install
```

## Run

```bash
npm start
# or override the API base:
TARN_API=https://api.tarn.dev npm start
```

## What to look for

- After `[notes] create`, two records appear in `[notes] list`.
- `[notes] update n1 (partial)` adds a `priority` and changes `status` without touching `title` or `body` — the SDK reads the current record and merges the patch.
- `[notes] schema validation` shows a synchronous error from passing an invalid enum value (`'in-progress'`). No network call is made — the schema rejects the write before encryption.
- `[settings] update flags` shows that `value` can be any JSON-serializable object, not just a string.
- The `settings` collection has no `share()` / `listShared()` method because `shareable` defaults to false. Try calling `tarn.settings.share(...)` and you'll get a `TarnCollectionError`.

## Note

Uses `TarnStorage.memory()` — nothing persists across runs. Constructs the client via the clean `TarnClient.create({ apiBase, appId, schema, storage })` shape; no `underlying` factory needed.
