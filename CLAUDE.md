# Tarn — Claude Code Project Instructions

## Project Overview

**Tarn** is the permanent, encrypted, user-owned data backend. It's the platform layer — app-agnostic infrastructure that any application can build on. Tarn handles:

- **Storage:** Arweave (permanent, immutable)
- **Encryption:** Client-side AES-256-GCM (zero-knowledge — server never sees plaintext)
- **Identity:** PBKDF2-derived keys + ECDSA P-256 signing (challenge-response auth)
- **API/caching:** Cloudflare Workers + D1 cache over Arweave

Tarn is NOT an app. It is infrastructure. Apps are clients of Tarn. The first app built on Tarn is [Bookish](https://github.com/brianmb99/bookish).

**Important:** Tarn is app-agnostic. Nothing in this repo should reference Bookish, reading lists, or any specific app. If you find yourself writing Bookish-specific logic, it belongs in the Bookish repo, not here.

## Key Documents

The three canonical docs live as markdown; nicely-formatted PDFs in `docs/` are generated from them. Markdown is always the source of truth — edit the `.md`, then re-run the generator if you also need the PDF refreshed.

- `docs/TARN_PROTOCOL.md` — The complete wire-protocol spec: key hierarchy, auth flows, data CRUD, Arweave tag scheme. **Read this first** when working on any protocol/API issue.
- `docs/SDK_ARCHITECTURE.md` — Implementation architecture of the SDK: how the typed surface is built, what the type system is doing, build pipeline, what's deferred.
- `client/README.md` — App-developer reference: defineSchema, collections, sharing, recovery, sessions, security model. **Read this first** when working on SDK ergonomics.

PDFs (regenerable via `python tools/generate-docs-pdf.py`):
- `docs/tarn-sdk-guide.pdf` ← `client/README.md`
- `docs/tarn-architecture-guide.pdf` ← `docs/SDK_ARCHITECTURE.md`
- `docs/tarn-protocol.pdf` ← `docs/TARN_PROTOCOL.md`

The generator requires Python with `reportlab` and `markdown-it-py` (`python -m pip install reportlab markdown-it-py`).

## Git Workflow

- **Two branches:** `main` (stable) and `dev` (all development work).
- All work goes on `dev`. **Never push to `main`** — merging is a human decision.
- Do not create feature branches.

## Repo Structure

- `api/` — Cloudflare Worker API (D1 cache + Arweave write proxy)
- `client/` — JavaScript client library (see `client/README.md` for usage)
- `docs/` — Protocol spec and design documents
- `tools/` — CLI tools (app key generation, subscription management)
- `tests/` — Test suites (unit, integration, E2E, security, deployment)

## Development

- API local dev: `cd api && npx wrangler dev --port 8787`
- Unit tests: `npm run test:unit` (routes through `tsx` so JS test files can import the in-progress `.ts` source modules in `client/src/`)
- Integration tests: `npm run test:e2e -- http://localhost:8787` (and `test:client`, `test:auth`, `test:apps-e2e`, `test:security`, `test:share`, `test:share-log`, `test:handshake`, `test:recovery`, `test:sessions`, `test:invites`)
- All local tests require wrangler dev running and D1 migrations applied (`cd api && npx wrangler d1 migrations apply tarn-api --local`)

## Deployment

- Deploy: `cd api && npx wrangler deploy`
- Apply remote migrations: `cd api && npx wrangler d1 migrations apply tarn-api --remote`
- **After every deploy, run the post-deployment smoke test:**
  ```
  node tests/test-deployed.mjs https://api.tarn.dev bookish <TARN_APP_KEY_BOOKISH>
  ```
  This tests the full lifecycle (health, register, app auth, set rules, login, write, read, Turbo gateway, status, delete) against the live API. Do not consider a deploy complete until this passes.
- The bookish app private key (`TARN_APP_KEY_BOOKISH`) is in `api/.dev.vars` (local) and Cloudflare Worker secrets (production).

### Recovery-kit format and delivery are an app concern, not a Tarn concern

Tarn deliberately has no endpoint that handles an account key, recovery PDF, or any other plaintext kit material — even ephemerally. The SDK itself also no longer renders kits: `tarn.register()` returns the 24-word account-key string and nothing else, and apps build their own kit (downloadable PDF, printable HTML, clipboard copy, etc.) using whatever rendering toolchain fits. The platform's job ends at producing the account-key string on the user's device. If you find yourself adding a route under `/api/v1/recovery/*` that takes account-key or kit material as input — or reintroducing a PDF generator into `client/src/` — stop. Either is a zero-knowledge boundary violation.

## D1 Database

The Cloudflare D1 database is named `tarn-api`. All CLI commands use this name:
```
cd api && npx wrangler d1 execute tarn-api --remote --command "SELECT ..."
cd api && npx wrangler d1 migrations apply tarn-api --remote
```

## Issue Workflow

- Work is tracked via **GitHub Issues** on the [Tarn repo](https://github.com/brianmb99/tarn/issues).
- Issues use two types: `bug` and `feature`.
- When Brian references a GitHub Issue, **always run `gh issue view N --comments` first** to read all comments. The most recent comment is the active request.

## Supply Chain Security

- **npm:** `.npmrc` should enforce `min-release-age=10080` (7 days). No package version published less than 7 days ago will be installed or updated. Do not bypass this setting.

## Working Style

The human operator is an accomplished engineer who works via chat only. They do not code directly — they direct work through conversation. Be direct, assume strong technical literacy, focus on decisions and trade-offs.
