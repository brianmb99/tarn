# 01 — Hello, Tarn

The smallest runnable Tarn app: declare a schema with one collection, register a fresh account, write one record, list it back. About 30 lines.

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

- A `Registering hello+<timestamp>@example.com` log line — the email is timestamped so re-runs don't collide.
- A `Creating one note...` log line.
- A `Listed notes: [{ noteId: 'n1', title: 'Hello, Tarn', body: '...' }]` final line — proof that the record round-tripped through Arweave-via-Tarn and decrypted back to plaintext.

## Note

Uses `TarnStorage.memory()` — nothing is persisted across runs. Each invocation creates a fresh account.
