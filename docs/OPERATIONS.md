# Tarn Operations Runbook

One page for the operator (or a future Claude session): how alerting works, what each
alert means and what to do about it, how to deploy/roll back, and where the disaster
recovery procedures live. Written for tarn#68.

## How you find out something is wrong

Three layers, all of which must be configured (the hourly report flags
`ALERTING_UNCONFIGURED` / `HEARTBEAT_UNCONFIGURED` / `FUNDING_FLOOR_UNSET` and reports
unhealthy until they are):

1. **Alert webhook** — the hourly cron (`api/src/observability/scheduled.js`) POSTs the
   full report JSON to `ALERT_WEBHOOK_URL` whenever any check fails. Point it at
   something that reaches a human (Slack incoming webhook, ntfy.sh topic, a
   Resend-backed relay — anything that accepts `{text, report}` JSON).

   ```
   npx wrangler secret put ALERT_WEBHOOK_URL --name tarn-api
   ```

   **Verify it end-to-end after setting** (don't trust an unfired alert path): with the
   heartbeat or floor still unset the next hourly tick is unhealthy and will fire it —
   or temporarily set `TURBO_MIN_BALANCE_WINC` above the current balance, wait one
   tick, confirm the message arrived, and restore the value.

2. **Dead-man heartbeat** — the cron GETs `HEARTBEAT_URL` on *every* tick, healthy or
   not. Use a monitor that alerts on **silence** (healthchecks.io: create a check with
   a 1 h period / ~15 min grace; UptimeRobot heartbeat works too). This is the only
   layer that catches a dead worker, a stopped cron, or a botched deploy — the worker
   cannot report its own death.

   ```
   npx wrangler secret put HEARTBEAT_URL --name tarn-api
   ```

3. **External uptime probe** (operator-side, not in this repo) — a probe on
   `GET https://api.tarn.dev/api/v1/health` (alert on non-200/timeout) catches serving
   failures between cron ticks. Free tier of any uptime service is fine.

Read the current and historical reports any time:

- `GET /api/v1/health` — liveness with real 503 semantics.
- `GET /api/v1/status` — wallet balance, user counts, pending txs.
- `GET /api/v1/admin/health-report` (app-role JWT; lockable via `ADMIN_APP_ID`) — the
  latest persisted hourly report, including flags.

## Alert flags → what to do

| Flag | Meaning | Response |
|---|---|---|
| `NOT_READY` | `APP_SIGNING_KEY` missing/unparseable, or Turbo unreachable | If signing key: check the secret (`wrangler secret list --name tarn-api`), restore from backup (see Secrets below). If Turbo: check https://status.ardrive.io — usually wait it out; writes fail loudly client-side meanwhile. |
| `LOW_FUNDING` | Turbo balance under the runway floor (`TURBO_RUNWAY_FLOOR_DAYS`, default 14 d) or under the absolute floor (`TURBO_MIN_BALANCE_WINC`) | Top up: https://turbo-topup.com (or ArDrive app → Turbo credits), paying to the **app wallet address** shown in `/api/v1/status` (`wallet.address`) / the funding section of the health report. Card payments accepted; credits land in minutes. |
| `STUCK_MIRRORS` | Background Arweave mirror uploads failed AND the cron's automatic retry could not drain them | Usually transient Turbo trouble — check the next tick. If it persists: inspect `arweave_mirror_failures` (`wrangler d1 execute tarn-api --remote --command "SELECT id, namespace, intended_txid, attempt_count, last_error FROM arweave_mirror_failures WHERE resolved_at IS NULL"`). Rows with stored bytes retry automatically; rows without bytes need a manual re-publish of the source record. |
| `DRIFT` | An identity-plane namespace has settled Arweave rows missing from D1 | Run the non-destructive checker: `node tools/rebuild-from-arweave.mjs --check`. If real, rebuild that plane per the runbook in `docs/ARWEAVE_RECOVERABILITY_AUDIT.md` §6. |
| `ALERTING_UNCONFIGURED` / `HEARTBEAT_UNCONFIGURED` / `FUNDING_FLOOR_UNSET` | Operability config missing | Set the var per the section above. For the floor: pick roughly “a few thousand paid 100 KB uploads” of buffer — current price per 100 KB is in the health report (`funding.winc_per_100kb`); e.g. `5000 × winc_per_100kb`. |

## Deploy / rollback

Deploy (full procedure also in `CLAUDE.md`):

```
cd api
npx wrangler d1 migrations apply tarn-api --remote   # if there are new migrations
npx wrangler deploy
node ../tests/test-deployed.mjs https://api.tarn.dev bookish <TARN_APP_KEY_BOOKISH>
```

A deploy is **not complete** until the smoke test passes (full lifecycle: health,
register, app auth, rules, login, write, read, gateway, status, delete).

Rollback — Workers keep prior versions:

```
npx wrangler deployments list --name tarn-api     # find the last good version
npx wrangler rollback --name tarn-api             # interactive; picks a version
```

Caveat: D1 migrations are forward-only (no down scripts). If a bad deploy depended on a
new migration, rolling back the worker is safe only if the old code tolerates the new
schema — additive migrations (the norm here) are fine; destructive ones need a
roll-forward fix instead.

## Disaster recovery

- **D1 lost/corrupted** → rebuild from Arweave. Proven procedure (exercised against
  mainnet): `docs/ARWEAVE_RECOVERABILITY_AUDIT.md` §6, tool
  `tools/rebuild-from-arweave.mjs` (dry-run by default; `--check` for non-destructive
  drift inspection). Entries cold-bootstrap lazily on read (paginated since tarn#64).
- **Tarn entirely gone** → users self-recover from Arweave with `@tarn/recover`
  (`recover/README.md`) — no Tarn server involved.

## Secrets inventory

Set via `wrangler secret put <NAME> --name tarn-api`; values are write-only in
Cloudflare. **Each must also exist in exactly one durable place outside this machine**
(password manager / printed escrow) — `api/.dev.vars` on a single laptop does not
count as a backup:

| Secret | Loss consequence |
|---|---|
| `APP_SIGNING_KEY` | **Permanent.** It IS the Arweave wallet: signs every DataItem and owns the Turbo balance. No rotation path preserves the wallet — losing it loses the funds and the upload identity. Back this one up first. |
| `JWT_SECRET` | Recoverable: rotate → all sessions invalidated, users re-login. |
| `TARN_APP_KEY_BOOKISH` | Recoverable: re-issue via `tools/generate-app-key.mjs` + update the app row and Bookish's worker secret. |
| `ALERT_WEBHOOK_URL`, `HEARTBEAT_URL` | Trivial: re-create at the provider. |

Never set `TARN_SKIP_TURBO` outside `api/.dev.vars` (production hosts refuse it and
log critically — see `api/src/turbo.js`).
