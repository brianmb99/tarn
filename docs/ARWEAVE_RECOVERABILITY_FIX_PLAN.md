# Arweave-recoverability fix plan

> **Status:** Ready for phased implementation. Closes the three load-bearing gaps identified in [ARWEAVE_RECOVERABILITY_AUDIT.md](ARWEAVE_RECOVERABILITY_AUDIT.md). Last updated 2026-05-08.
>
> **Source:** the audit found three load-bearing gaps in Tarn's "rebuildable from Arweave" claim:
> 1. The `apps` table has no Arweave write path — protocol doc claims `Type=app-reg` blobs exist; they don't.
> 2. The `passkey_credentials` table (Phase 6) is D1-only.
> 3. No D1-rebuild tooling exists at all — even where data is on Arweave, there's no script to walk it and reconstruct D1.

## Approach

Three phases, mostly independent:

- **Phase A:** add `Type=app-reg` Arweave writes to app registration and updates.
- **Phase B:** add `Type=passkey-reg` Arweave writes to passkey lifecycle.
- **Phase C:** build `tools/rebuild-from-arweave.mjs`, the operational rebuild tool that walks Arweave and reconstructs D1.

Phases A and B can run in parallel (different code paths, no overlap). Phase C waits for both to land — it consumes the new wire formats.

## Phase A — app-reg Arweave writes

### Wire format

New Arweave blob type: `Type=app-reg`. Tags:

- `App=tarn`
- `Type=app-reg`
- `Lk=<app_id>` — the app id is the lookup key; allows direct discovery by app id, and `App=tarn,Type=app-reg` enumerates all apps for rebuild scans.

Body (JSON):

```json
{
  "v": 1,
  "app_id": "bookish",
  "public_key": "<base64 ECDSA P-256 SPKI>",
  "invite_url_template": "https://example.com/invite?token={token}" | null,
  "created_at": <unix-ms>
}
```

### Write sites

Two paths today both write to D1 only; both need to also publish to Arweave:

1. **`tools/generate-app-key.mjs`** — generates a fresh keypair, registers the app. Add Arweave publish using the operator's Arweave wallet (script is operator-run; wallet is available locally to the operator). After successful Arweave write, insert into D1 (or insert first, publish after — pick the more idempotent ordering).

2. **`tools/register-app-from-key.mjs`** — registers an existing keypair. Same treatment.

3. **`PUT /apps/:app_id/invite-template`** (find the actual route — likely in `api/src/routes/`). Updates `invite_url_template`. Should publish a new `Type=app-reg` blob (latest wins) reflecting the updated template. The worker has the operator wallet (Turbo bundler), so this is straightforward.

### Update behavior

`invite_url_template` updates produce a new blob; rebuild logic uses the most recent `Type=app-reg` blob per `app_id`. No tombstones for app-reg in v1 (app deregistration is a future concern; if needed, add `Type=app-reg-tombstone` or use the existing `is_tombstone` mechanism).

### Doc updates

- `docs/TARN_PROTOCOL.md`: the existing claim that apps are persisted as `Type=app-reg` blobs becomes accurate. Document the wire format and write sites.

## Phase B — passkey-reg Arweave writes

### Wire format

New Arweave blob type: `Type=passkey-reg`. Tags:

- `App=tarn`
- `Type=passkey-reg`
- `Lk=<data_lookup_key>` — associates with account
- `CredId=<credential_id>` — direct lookup by credential

Body (JSON):

```json
{
  "v": 1,
  "data_lookup_key": "<account dlk>",
  "credential_id": "<base64url>",
  "public_key": "<base64 COSE key or SPKI>",
  "prf_salt": "<base64 32-byte salt>",
  "device_label": "iPhone 16" | null,
  "created_at": <unix-ms>
}
```

Notes on what's NOT persisted to Arweave:
- `sign_count` — runtime state, recoverable from 0 on rebuild (any sign_count regression check on first post-rebuild auth will be benign because the stored value is 0).
- `last_used_at` — runtime UX metadata, acceptable loss.

### Write sites

- `POST /api/v1/auth/passkey/register` — after successful D1 insert, publish to Arweave.
- `DELETE /api/v1/account/passkeys/:credential_id` — publish a tombstone (`is_tombstone=true`, `tombstone_ref=<original credential blob's txid>`). On rebuild, tombstoned credentials are excluded.

### Doc updates

- `docs/TARN_PROTOCOL.md`: document `Type=passkey-reg`, the wire format, the write sites, and the tombstone semantics.

## Phase C — rebuild-from-arweave tool

### Goal

A standalone Node.js script that reconstructs Tarn's D1 state from Arweave. Operator-runnable. Idempotent (running twice is safe).

### Inputs

```
node tools/rebuild-from-arweave.mjs \
  --d1-binding tarn-api \
  --arweave-gateway https://arweave.net \
  --confirm   # safety flag; without it, dry-run mode
```

Optional flags:
- `--app=<app_id>` — rebuild only data for one app
- `--gateways="https://a.io,https://b.io"` — fallback list
- `--skip=apps,accounts` — comma-separated tables to skip (mostly for testing)

### What it rebuilds

In dependency order (apps → accounts → passkey_credentials → entries cache → others):

1. **`apps` table.** GraphQL query: `App=tarn, Type=app-reg`. For each unique `app_id`, take the most recent blob, parse, insert.
2. **`accounts` table.** GraphQL query: `App=tarn, Type=cred`. For each unique `credential_lookup_key`, take the most recent blob (excluding tombstones), parse, insert. Also reads `RLk` to populate `recovery_lookup_key` (since 2026-05).
3. **`passkey_credentials` table.** GraphQL query: `App=tarn, Type=passkey-reg`. For each unique `credential_id`, take the most recent (excluding tombstones), parse, insert. `sign_count` defaults to 0; `last_used_at` defaults to NULL.
4. **`accounts.rules_json`.** GraphQL query: `App=tarn, Type=app-config`. For each `data_lookup_key`, take the most recent. Update `accounts.rules_json` for matching DLKs.
5. **`entries` cache** (lazy). The script doesn't pre-populate the entries cache. The existing single-tuple cold-bootstrap (`refreshCache`) handles this on demand. The script optionally accepts `--prefetch-content` for an exhaustive walk.
6. **`share_inbox`, `share_log`** — same pattern; query by `App=tarn-share` and reconstruct.

### What it doesn't rebuild

- `cache_meta` bootstrap markers — start empty; first read re-bootstraps.
- `sessions`, `step_up_tokens`, `webauthn_challenges` — transient by design; users re-auth.
- `pending_txs`, `idempotency_keys`, `write_rate_limits` — transient.
- `account_key_fetch_log` — D1-only audit log; lost on wipe (acceptable).

### Output

Structured progress output. On completion, prints a summary:
```
apps:               1 rebuilt
accounts:          12 rebuilt
passkey_credentials: 3 rebuilt
app-config rules:   8 applied
share_inbox:       42 rebuilt
share_log:        103 rebuilt
total time:       12.4s
```

### Tests

- Unit test against a synthetic Arweave fixture: known blobs → expected D1 state.
- Integration test: spin up local wrangler dev with empty D1, run the script against a recorded Arweave snapshot (or a real test gateway), verify rebuilt D1 matches the original snapshot.
- Property test: register app + accounts + passkeys via normal flows → wipe D1 → run rebuild → verify state matches pre-wipe.

### Doc updates

- New section in `docs/TARN_PROTOCOL.md` titled "Operational rebuild from Arweave" — documents the tool, its usage, what it does and doesn't rebuild, the dependency order, and how to verify post-rebuild.
- Update the existing claim "all tables fully rebuildable from Arweave" to be accurate, citing the tool.

## Order of operations

1. Phase A and Phase B in parallel (different agents, both based off current dev).
2. Verify both, merge to dev.
3. Deploy (Phase A's `PUT /apps/:app_id/invite-template` change + Phase B's passkey-register/remove changes are worker-side; need a deploy).
4. Phase C — rebuild tool, after the wire formats are in production.
5. Run a property test: register a fresh app + a fresh user with passkey on a clean D1 against the live API, then test the rebuild tool against that real production state.

## Sub-agent execution notes

- Each phase commits to a worktree branch — no direct commits to dev. Verify with the same scripts (`npm run test:unit`, `npm run typecheck`, `npm run build`, relevant integration suites).
- **Verify worktree base before starting work.** The Agent tool has been spawning some worktrees off the wrong commit ("Initial commit"). First action: `git log --oneline -3` in the worktree; if HEAD isn't recent, `git reset --hard dev`.
- **Commit incrementally.** Don't accumulate hours of work in an uncommitted state.
- Phase A wallet handling: the operator's Arweave wallet is in `bookish_wallet.json` at the repo root (sibling concept; reuse Tarn's existing wallet-loading patterns from `api/src/turbo.js`). For the CLI tools, accept the wallet path as an argument.
- Phase C: this is a real piece of work; don't compress. ~1-2 days of agent time. If the agent runs into ambiguity about the Arweave query patterns, look at the existing `api/src/arweave.js` and `api/src/cache.js` for conventions.

## Deferred / out of scope

- Backfilling `Type=app-reg` for apps registered before this change (e.g., the existing Bookish app). The migration story is "re-run the registration tool with `--republish-only` flag once Phase A ships." Document but don't automate.
- `Type=passkey-reg` backfill for any pre-existing passkeys. Bookish has no users yet so this is moot.
- Rate-limit / sessions / etc. recovery — explicitly acceptable losses per the audit.
- Continuous Arweave-mirroring of the audit log table — separate question, not in this plan.
