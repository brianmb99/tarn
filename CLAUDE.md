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

## Repo Structure

- `api/` — Cloudflare Worker API (D1 cache + Arweave write proxy)
- `client/` — JavaScript client library (not yet implemented)
- `docs/` — Protocol spec and design documents
- `tests/` — Test suites

## Git Workflow

- **Two branches:** `main` (stable) and `dev` (all development work).
- All work goes on `dev`. **Never push to `main`** — merging is a human decision.
- Do not create feature branches.

## Development

- API local dev: `cd api && wrangler dev`
- API tests: `cd api && node test.mjs`
- API deployment: `cd api && wrangler deploy` (Cloudflare Workers)

## Issue Workflow

- Work is tracked via **GitHub Issues** on the [Tarn repo](https://github.com/brianmb99/tarn/issues).
- Issues use two types: `bug` and `feature`.
- When Brian references a GitHub Issue, **always run `gh issue view N --comments` first** to read all comments. The most recent comment is the active request.

## Supply Chain Security

- **npm:** `.npmrc` should enforce `min-release-age=10080` (7 days). No package version published less than 7 days ago will be installed or updated. Do not bypass this setting.

## Working Style

The human operator is an accomplished engineer who works via chat only. They do not code directly — they direct work through conversation. Be direct, assume strong technical literacy, focus on decisions and trade-offs.
