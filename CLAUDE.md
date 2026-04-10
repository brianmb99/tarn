# Tarn — Claude Code Project Instructions

## Project Overview

**Tarn** is the permanent, encrypted, user-owned data backend. It's the platform layer — app-agnostic infrastructure that any application can build on. Tarn handles:

- **Storage:** Arweave (permanent, immutable)
- **Encryption:** Client-side AES-256-GCM (zero-knowledge — server never sees plaintext)
- **Identity:** PBKDF2-derived keys + ECDSA P-256 signing (challenge-response auth)
- **API/caching:** Cloudflare Workers + D1 cache over Arweave

Tarn is NOT an app. It is infrastructure. The first app built on Tarn is [Bookish](https://github.com/brianmb99/bookish).

## Key Documents

- `docs/TARN_PROTOCOL.md` — The complete protocol spec: key hierarchy, auth flows, data CRUD, Arweave tag scheme
- `api/` — Cloudflare Worker API (D1 cache + Arweave proxy)
- `client/` — JavaScript client library (not yet implemented)
- `tests/` — Test suites

## Git Workflow

- **Two branches:** `main` (stable) and `dev` (all development work)
- All work goes on `dev`. Do not push to `main` — merging is a human decision.
- Do not create feature branches.

## Development

- API: `cd api && wrangler dev` for local development
- Tests: `cd api && node test.mjs`

## Working Style

The human operator is an accomplished engineer who works via chat only. They do not code directly — they direct work through conversation. Be direct, assume strong technical literacy, focus on decisions and trade-offs.
