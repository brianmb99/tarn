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

- `docs/TARN_PROTOCOL.md` — The complete protocol spec: key hierarchy, auth flows, data CRUD, Arweave tag scheme. **Read this first** when working on any Tarn issue.

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
- Unit tests: `node --test tests/unit/*.test.js`
- Integration tests: `node tests/test-auth.mjs http://localhost:8787` (and test-e2e, test-apps-e2e, test-security, test-client)
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

### Worker secrets (issue #12 — recovery email forwarder)

The `POST /api/v1/recovery/email` endpoint forwards client-rendered recovery PDFs through Resend. Two Worker secrets must be set in production:

```
npx wrangler secret put EMAIL_FORWARDER_API_KEY  # Resend API key (re_...)
npx wrangler secret put EMAIL_FORWARDER_FROM     # e.g. "Tarn <recovery@tarn.dev>"
```

If either is missing the endpoint returns 503 (apps can still let the user download the PDF locally — the `emailRecoveryKit: false` SDK path skips the network call entirely). The endpoint never persists the PDF; it only forwards.

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
