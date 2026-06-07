# Arweave-only Recoverability Audit

**Question:** If Tarn's D1 database disappeared tomorrow, could every piece of Tarn state be reconstructed by reading Arweave alone?

**Scope:** ALL supporting state (account records, app records, sharing material, etc.) — not just user data, which is well-known to be on Arweave.

**Working state:** Branch `dev`, audited at commit `9ad8d6a` ("tests: fix rotateAccountKey RLk assertion semantics").

---

> **VERIFICATION STATUS (updated 2026-06-05, tarn#35).** The two load-bearing
> gaps this audit flagged — `apps` (no `app-reg` mirror) and `passkey_credentials`
> (D1-only) — have since been **closed** (Phases A/B of
> `ARWEAVE_RECOVERABILITY_FIX_PLAN.md`: `api/src/app-reg.js`,
> `api/src/routes/passkey-reg.js`, the writers in `routes/apps.js` /
> `routes/passkeys.js`, and the Phase-C reader `tools/rebuild-from-arweave.mjs`).
> The end-to-end rebuild has now been **run against mainnet Arweave** and
> verified: a fresh app + 2 accounts + 2 passkeys + per-account rules were
> registered through the live API (real Turbo uploads), D1 was wiped, and
> `tools/rebuild-from-arweave.mjs --confirm` reconstructed `apps`, `accounts`,
> `passkey_credentials`, and `accounts.rules_json` **identically** modulo the
> documented acceptable-loss columns. The §1 "PARTIAL" verdict below is the
> ORIGINAL pre-fix finding, retained for provenance. See **§6. Operational
> verification** for the proven procedure, the acceptable-loss list, and the
> mainnet-indexing caveat.

## 1. TL;DR

**Verdict (original, pre-fix): PARTIAL — recoverability holds for user data, credential blobs, app rules, app schemas, share-inbox blobs, and share-log blobs. It does NOT hold for app registrations, account-key audit logs, passkey credentials, or any transient/session/rate-limit state.**

*(Superseded — see the VERIFICATION STATUS banner above and §6. The app-registration and passkey-credential gaps are closed and the rebuild is proven.)*

The architectural promise stated in `docs/TARN_PROTOCOL.md` line 866 — "All tables fully rebuildable from Arweave. Entries self-heal on cache miss. Accounts rebuilt from `Type=cred` blobs. Apps rebuilt from `Type=app-reg` blobs." — is OVERSTATED in two ways:

1. **There is no `Type=app-reg` write path anywhere in `api/src/`.** App registration is D1-only, performed out-of-band by `tools/generate-app-key.mjs` / `tools/register-app-from-key.mjs` via `wrangler d1 execute`. If D1 is lost, every registered app's `(app_id, public_key, invite_url_template)` is also lost; no users can authenticate (their accounts depend on `app_id` being present in the `apps` table) and no app can mint app-role JWTs.
2. **Phase 6 added passkey credentials with no Arweave mirror.** `passkey_credentials` rows are D1-only. Passkey-based authentication and the per-credential `prf_salt` needed to derive PRF wrappings are unrecoverable.

Within the recoverable set, the actual reconstruction logic is **partially absent in code** — `api/src/cache.js` only knows how to backfill `entries` rows for a known `(app, type, lookup_key)` tuple via `searchEntriesByLookupKey`. No code path scans Arweave for unknown DLKs, walks all `Type=cred` blobs to rebuild `accounts`, ingests `share_inbox` / `share_log` from `App=tarn-share` queries, or backfills `app-config` rules into `accounts.rules_json`. Recoverability is a property of the data layout (the bytes are on Arweave with discoverable tags), not an implemented operational procedure.

### Gaps by severity

| Severity | Gap | Notes |
|---|---|---|
| **load-bearing** | `apps` table has no Arweave mirror | Documented as `Type=app-reg` in protocol doc; not implemented |
| **load-bearing** | `passkey_credentials` is D1-only | Phase 6 addition; PRF salts cannot be reconstructed → users with only passkeys cannot recover |
| **load-bearing** | No D1-rebuild tooling exists | The data is on Arweave, but there is no `rebuild-from-arweave.mjs` script. `cache.js` only does single-tuple cold bootstrap. |
| **minor** | `account_key_fetch_log` audit-log is D1-only | Cosmetic — audit history ("when did the account key last get viewed") is lost on D1 wipe; no security impact |
| **minor** | `accounts.rules_json` rebuild requires walking app-config blobs | Persisted to Arweave with `Type=app-config, Lk=dlk` but the rebuild is not implemented; rules effectively reset to NULL (deny) until the app re-issues `setRules` |
| **minor** | `apps.invite_url_template` is D1-only | A per-app field set via `PUT /apps/:app_id/invite-template`; never written to Arweave |
| **acceptable** | Sessions, nonces, step-up tokens, WebAuthn challenges | Transient by design; loss = users re-log in |
| **acceptable** | Rate-limit counters (`write_rate_limits`, KV) | Transient; loss = budget resets |
| **acceptable** | `idempotency_keys` (24h TTL) | Transient; loss = potential duplicate writes during retry storm following the wipe |
| **acceptable** | `pending_txs` | Liveness hint only; reconstructible by tx confirmation polling |
| **acceptable** | `cache_meta` bootstrap markers | Documented as cleared on rebuild (TARN_PROTOCOL.md line 680); subsequent reads re-bootstrap |
| **acceptable** | `sessions.via_recovery`, `sessions.device_label` | Per-device session UI metadata; lost on wipe but inherent to session-loss |

**The single most important finding:** the "Tarn infra is rebuildable from Arweave" property currently has TWO load-bearing holes — apps (which the protocol doc claims are recoverable but aren't) and passkey credentials (added in Phase 6 with no Arweave-side mirror). For Bookish (sole consumer, no production users yet) the practical impact is bounded; the principle of the platform layer's claim is broken.

---

## 2. Per-table walkthrough

Migration files: `api/migrations/0001_initial.sql` … `0018_passkey_credentials.sql`.

### 2.1 `entries` (migration 0001 + 0006 added `blob_data`)

1. **What is it?** All user data writes. Rows are `(txid, app, type, wallet_addr, lookup_key, eid, prev_txid, is_tombstone, tombstone_ref, block_timestamp, tags_json, blob_data)`. Also includes credential blobs (`Type='cred'`), app-config rules (`Type='app-config'`), app schemas (`Type='app-schema'`), and tombstones.
2. **Where does it live?** Both. Every row corresponds 1:1 to an Arweave DataItem; `blob_data` is the encrypted payload.
3. **Rebuildable?** YES. Each row has a `txid`; the metadata is reconstructible by re-running an Arweave GraphQL query and `blob_data` by fetching from a gateway.
4. **Mechanism?** `api/src/cache.js:230` (`refreshCache`) and `cache.js:254` (`refreshLookupCache`) — but **only for a known `(app, type, dlk)` or `(app, type, lookupKey)` tuple**. There is no code path that enumerates all DLKs/lookupKeys to drive a wholesale rebuild. `tools/backfill-blobs.mjs` only refills `blob_data` for rows that already exist in D1.
5. **Loss?** None at the data layer. But the operational rebuild is not implemented; reconstructing requires (a) knowing which DLKs exist and (b) running `refreshCache` for each.

### 2.2 `cache_meta` (migration 0001)

1. Bootstrap markers — `bootstrap:data:<dlk>:<app>:<type>` and `bootstrap:lookup:<lk>:<app>:<type>`.
2. D1 only.
3. Acceptable loss. Documented (`TARN_PROTOCOL.md:680`): markers are cleared on rebuild and the next read re-bootstraps from Arweave.
4. N/A.
5. Acceptable.

### 2.3 `pending_txs` (migration 0002)

1. Track pending tx confirmation status per `(wallet_addr|dlk, app, type)`.
2. D1 only.
3. Acceptable loss. Liveness/UX hint; not authoritative.
4. N/A.
5. Acceptable.

### 2.4 `accounts` (migration 0003 + 0004 + 0008 + 0009 + 0016)

1. Per-user account record: `credential_lookup_key` (PK), `public_key`, `data_lookup_key`, `wrapped_data_key` (envelope), `app`, `rules_json`, `created_at`, `recovery_lookup_key`, `recovery_public_key`, `share_pub`, `share_discoverable`, `share_lookup_key`, `wrapped_account_key`.
2. Both — D1 columns plus a corresponding Arweave `Type=cred, App=tarn` blob (with secondary `RLk` tag when recovery factor present, since commit `d34ab6e`).
3. **YES for everything except `rules_json`.** Credential blob persists `data_lookup_key`, `wrapped_data_key`, `public_key`, `app`, recovery fields, share fields, and `wrapped_account_key`. See `routes/auth.js:29-51` `buildCredentialBlob`.
4. **Mechanism:** GraphQL query `App=tarn, Type=cred` (no Lk filter) walks every credential blob ever published. Tombstones (Op=tombstone, Ref=<credtxid>) handle deleted accounts. Latest non-tombstone wins per `data_lookup_key`. `routes/auth.js:71-82` `buildCredentialTags` confirms tag scheme.
5. **`rules_json` is NOT in the credential blob.** It's persisted SEPARATELY as a `Type=app-config, App=<app_id>, Lk=<dlk>` blob (see `routes/apps.js:75-86`). Rebuild requires walking `app-config` blobs and joining by `Lk` to repopulate `accounts.rules_json`. Until then, `rules_json` is NULL and all writes are denied. Minor — apps can re-call `setRules`.

Note on `share_discoverable`: the credential blob only writes `share_discoverable` when `share_pub` is also present (see `auth.js:47`). Since the column has `DEFAULT 1`, a rebuild of an account with no share keypair correctly defaults to discoverable.

### 2.5 `apps` (migration 0003 + 0015 added `invite_url_template`)

1. Per-app record: `app_id`, `public_key`, `created_at`, `invite_url_template`.
2. **D1 only.** No Arweave write path. Documented as `Type=app-reg` in `TARN_PROTOCOL.md:477` but never implemented.
3. **NO.** App registration is performed via SQL by `tools/generate-app-key.mjs:54` and `tools/register-app-from-key.mjs:53` — both INSERT directly into D1 via `wrangler d1 execute`.
4. N/A.
5. **Load-bearing loss.** Without the `apps` row, `routes/auth.js:168-172` rejects every register call (`Unregistered app`), and `routes/apps.js:150-153` rejects every `setInviteTemplate`. No JWT can be minted for app role since challenge/verify look up the `apps` table. Recovery requires re-registering each app from out-of-band private-key custody. The `invite_url_template` is doubly unrecoverable — there's no Arweave record at all.

### 2.6 `write_rate_limits` (migration 0005)

1. Atomic per-bucket counters `(key, count, expires_at)`. Used for write-budget rate limits, share-inbox publish rate limits, invite create/redeem rate limits.
2. D1 only.
3. Acceptable loss. Counters reset.
4. N/A.
5. Acceptable.

### 2.7 `idempotency_keys` (migration 0007)

1. Cached responses for retry-safe writes, keyed by `(dlk, client_key)`. 24-hour TTL.
2. D1 only.
3. Acceptable loss. Worst case: a client retrying through the wipe gets a duplicate Arweave DataItem (same content, new signature → distinct txid). Same content though, so resolution semantics handle it.
4. N/A.
5. Acceptable.

### 2.8 `share_inbox` (migration 0010)

1. HPKE-sealed connection-handshake blobs (`connection-request-v1`, `connection-accept-v1`) addressed by 43-char base64url inbox tag. Many writers per (tag, type).
2. Both — D1 row plus Arweave write under `App=tarn-share, Type=<type>, To=<tag>, AppScope=<app>` (`routes/share-inbox.js:151-157`).
3. YES.
4. **Mechanism:** GraphQL query for `App=tarn-share, Type=connection-request-v1|connection-accept-v1` enumerates every inbox blob ever published. Re-insert by `(txid, app_id=AppScope, inbox_tag=To, blob_type=Type, ciphertext, published_at)`. `published_at` is best-effort — Arweave's `block.timestamp` is the available proxy.
5. None at data layer. **No rebuild code path exists** — `cache.js` knows nothing about `share_inbox`.

### 2.9 `share_log` (migration 0011)

1. Per-pair stealth-addressed, AES-GCM encrypted log entries. Per-tag uniqueness on `(app_id, log_tag, blob_type)`.
2. Both — D1 row plus Arweave write under `App=tarn-share, Type=share-log-v1, To=<tag>, AppScope=<app>` (`routes/share-log.js:116-122`).
3. YES.
4. **Mechanism:** GraphQL `App=tarn-share, Type=share-log-v1` walk; same shape as `share_inbox` rebuild. `data_lookup_key` (sender's DLK) is NOT a tag on Arweave — it's only in the D1 row for operator scoping. Rebuild loses the `data_lookup_key` column unless the protocol extends to write it as a tag (or recovers it from cross-referencing the published_at against accounts/sessions).
5. **Partial:** the column `data_lookup_key` (used for "scope deletion / abuse handling per account" per migration comment) is unrecoverable from Arweave alone. Material is recoverable; sender-attribution is not. Since this is operator metadata and not user-facing semantics, classify as minor.

### 2.10 `auth_nonces` (migration 0012)

1. Single-use challenge nonces, 5-minute TTL.
2. D1 only.
3. Acceptable loss. In-flight auth flows fail; users re-issue.
4. N/A.
5. Acceptable.

### 2.11 `sessions` (migration 0013)

1. Server-side session rows: `sid` (PK), `data_lookup_key`, `app`, `created_at`, `last_seen_at`, `device_label`, `via_recovery`.
2. D1 only.
3. Acceptable loss. JWTs continue to verify cryptographically but fail the sid-presence check in middleware → users re-log in.
4. N/A.
5. Acceptable.

### 2.12 `invites` (migration 0014)

1. Opaque AES-GCM ciphertext invite payloads, single-use, time-limited (≤30 days).
2. D1 only.
3. **Loss is partial-acceptable.** The payload is encrypted client-side; the inviter holds the payload key in the URL fragment. If D1 is wiped, all outstanding invites become "not found" 404s. Unredeemed invitees lose access to the invite payload (which contains the inviter's `share_pub`); the inviter can re-issue.
4. N/A.
5. Acceptable — invites are by design a transient short-lived primitive.

### 2.13 `step_up_tokens` (migration 0016)

1. Single-use, 60-second-TTL tokens authorizing privileged ops (account-key fetch/enable/disable/rotate, passkey delete).
2. D1 only.
3. Acceptable loss. In-flight step-up flows fail; user re-enters password.
4. N/A.
5. Acceptable.

### 2.14 `account_key_fetch_log` (migration 0016 + 0017 added `op`)

1. Append-only audit log: `(data_lookup_key, fetched_at, ip_hash, user_agent, op)` for `op ∈ {fetch, enable, disable, rotate, passkey_register, passkey_authenticate, passkey_refresh_credential, passkey_remove}`.
2. D1 only. The `op` discriminator was added precisely to consolidate audit signal in this single table.
3. **NO.** Audit history is lost on wipe.
4. N/A.
5. **Minor gap.** The audit table is a UX scaffold for transparency ("your account key was last viewed at X"); migration 0016 explicitly notes it's "NOT a security mechanism on its own (the fetch is already gated by JWT + step-up)." Acceptable on a security-critical reading; minor on a "promised functionality" reading.

### 2.15 `passkey_credentials` (migration 0018)

1. Per-passkey row: `(account_id, credential_id, public_key, prf_salt, sign_count, device_label, created_at, last_used_at)`. Phase 6 of the recovery roadmap.
2. **D1 only.** No code path writes a passkey-credential blob to Arweave. The only Arweave-side passkey artifact is the `passkey_prf` wrapping inside `wrapped_data_key.dek_chain[].wrappings`, which is part of the credential blob — it provides the wrapping ciphertext but NOT the per-credential `prf_salt` or `public_key` needed to reconstruct the WebAuthn flow.
3. **NO.** Loss of D1 = loss of all registered passkeys' `prf_salt` and `public_key`. The user can still authenticate via password (the password wrapping survives in the credential blob) but every registered passkey is irrecoverable.
4. N/A.
5. **Load-bearing.** A user whose primary auth path is a passkey loses the ability to derive the PRF wrapping key (no `prf_salt`) AND the ability to verify a WebAuthn assertion (no `public_key`, `sign_count`). Recovery requires falling back to password or the recovery-phrase factor. For a passkey-only user (not currently a real configuration since Phase 6 always preserves a password wrapping per `passkeys.js:891-894`), this would be terminal. With password preserved, classify as load-bearing for the passkey-as-auth promise but recoverable via password.

### 2.16 `webauthn_challenges` (migration 0018)

1. Single-use 60s-TTL WebAuthn challenges.
2. D1 only.
3. Acceptable loss. Same shape as nonces.
4. N/A.
5. Acceptable.

### 2.17 KV: `RATE_KV`

1. Hourly per-IP and per-DLK counters for register, share-lookup, inbox-fetch, share-log-fetch, lookup, invite-preview.
2. KV only.
3. Acceptable loss. Counters reset.
4. N/A.
5. Acceptable.

---

## 3. Per-data-kind summary (skim view)

| Kind | Storage | Recoverable from Arweave? | Notes |
|---|---|---|---|
| **User content** (encrypted blobs) | Arweave + D1 cache | YES — well-known | `entries` table |
| **Credential blobs** (envelope, share keys, recovery, account-key wrap) | Arweave + D1 | YES | `Type=cred, App=tarn, Lk=clk[, RLk=rlk]` |
| **Account write rules** (`rules_json`) | Arweave + D1 | YES (separate blob) | `Type=app-config, App=<app_id>, Lk=<dlk>` |
| **App schemas** | Arweave + D1 entries | YES | `Type=app-schema, App=<app_id>, V=<version>` |
| **App registrations** (`apps.public_key`) | **D1 only** | **NO** | Out-of-band SQL via `tools/generate-app-key.mjs` |
| **App invite URL template** | D1 only | NO | `apps.invite_url_template` |
| **Share-inbox blobs** | Arweave + D1 | YES | `App=tarn-share, Type=connection-{request,accept}-v1, To=<tag>` |
| **Share-log blobs** | Arweave + D1 | YES (sender DLK lost) | `App=tarn-share, Type=share-log-v1, To=<tag>` |
| **Passkey credentials** | **D1 only** | **NO** | `passkey_credentials` |
| **Passkey wrapping ciphertext** | Arweave (in cred blob) | YES | Inside `wrapped_data_key.dek_chain[].wrappings` |
| **Sessions** | D1 only | NO (transient) | Acceptable |
| **Auth nonces** | D1 only | NO (transient) | Acceptable |
| **Step-up tokens** | D1 only | NO (transient) | Acceptable |
| **WebAuthn challenges** | D1 only | NO (transient) | Acceptable |
| **Idempotency cache** | D1 only | NO (transient) | Acceptable |
| **Pending tx hints** | D1 only | NO | Acceptable — derivable from gateway polling |
| **Cache bootstrap markers** | D1 only | NO | Acceptable — re-set on rebuild |
| **Rate-limit counters** | D1 + KV | NO (transient) | Acceptable |
| **Account-key audit log** | D1 only | NO | Minor — UX, not security |
| **Invite tokens** (opaque ciphertext) | D1 only | NO | Acceptable — short-lived |
| **Account tombstones** | Arweave + D1 entries | YES | `Type=cred, Op=tombstone, Ref=<txid>, Lk=<clk>[, RLk=<rlk>]` |

---

## 4. Recovery mechanism details (for the recoverable kinds)

For each recoverable kind: the Arweave query and the D1 backfill needed.

### 4.1 `entries` (user content + credentials + app-config + app-schema)

- **Query:** GraphQL filter on `App` + `Type` + (`Lk` for lookup-keyed types | `Addr` for wallet-addressed types).
- **Implemented:** `cache.js:30 searchEntriesByAddr` + `cache.js:59 searchEntriesByLookupKey` + `cache.js:88 fetchAllPages`. `cache.js:229 refreshCache` ingests metadata into D1 via `upsertEntries`. `cache.js:287 fetchBlobFromGateway` lazily backfills `blob_data` per-txid on miss; `tools/backfill-blobs.mjs` does it in bulk for already-indexed rows.
- **Wholesale-rebuild gap:** No code knows how to enumerate all `(app, type, dlk)` tuples to drive `refreshCache` from scratch. The path that exists is "I know I'm looking for X" not "rediscover everything." A real D1-wipe rebuild would require a new tool that:
  1. Queries `App=tarn, Type=cred` (no Lk filter) → all credential blobs → reconstruct `accounts`.
  2. For each rebuilt account row's DLK, queries `App=<app>, Type=*, Lk=<dlk>` → user entries.
  3. Queries `App=<app>, Type=app-config, Lk=<dlk>` → backfill `accounts.rules_json`.

### 4.2 Credential blobs → `accounts`

- **Query:** GraphQL `App=tarn, Type=cred`. Optionally filter by `Lk=<credential_lookup_key>` for a single account, or `RLk=<recovery_lookup_key>` for a recovery-flow lookup (the dual-tag was added in commit `d34ab6e`).
- **Reconstruction:** Parse blob JSON (`auth.js:29-51`); columns map directly: `data_lookup_key`, `wrapped_data_key`, `public_key`, `app`, `recovery_lookup_key`, `recovery_public_key`, `share_pub`, `share_discoverable`, `share_lookup_key`, `wrapped_account_key`. `created_at` is approximated by `block.timestamp`.
- **Tombstones:** `Op=tombstone, Ref=<live txid>` records mark deleted accounts; rebuild must filter them out.
- **Multiple gens:** Per credential rotation, multiple `Type=cred` blobs share the same `data_lookup_key` (each with the then-current `credential_lookup_key`). Latest non-tombstone wins (TARN_PROTOCOL.md:1715 documents this).

### 4.3 App-config blobs → `accounts.rules_json`

- **Query:** GraphQL `App=<app_id>, Type=app-config, Lk=<dlk>`.
- **Reconstruction:** `routes/apps.js:82-86` writes `JSON.stringify({ rules, set_by, timestamp })`. Latest blob's `rules` is what `accounts.rules_json` should be set to.

### 4.4 App-schema blobs → `entries` (and presumably client-visible)

- **Query:** GraphQL `App=<app_id>, Type=app-schema`. Rows are versioned via `V=<version>` tag.
- **Reconstruction:** Just re-ingest into `entries` (it's a regular entry row); the SDK reads it via the existing entries endpoint.

### 4.5 Share-inbox / share-log blobs

- **Query:** GraphQL `App=tarn-share, Type=connection-request-v1` (and `-accept-v1`, `share-log-v1`).
- **Reconstruction:** Re-insert into `share_inbox` / `share_log` keyed by `txid`, with `app_id=AppScope`, `inbox_tag` or `log_tag = To`, `ciphertext` from gateway fetch, `published_at` from `block.timestamp`.
- **Note:** `share_log.data_lookup_key` (sender's DLK) is NOT a tag on Arweave — it would be reconstructible only by cross-referencing against `accounts` by sign-in IP or by accepting the column's loss.

### 4.6 Account tombstones → already covered above (live in `entries`)

---

## 5. Gaps and recommendations

### 5.1 Load-bearing

#### G1. App registrations (`apps` table) have no Arweave mirror

- **Evidence:** `routes/auth.js:168-172` blocks every registration when the `apps` row is missing. Searched `api/src/` for any `Type=app-reg` write — none exist. Tools (`generate-app-key.mjs`, `register-app-from-key.mjs`) write SQL via `wrangler d1 execute`.
- **What's lost:** Every `(app_id, public_key, invite_url_template, created_at)`. Without these, no user account can authenticate (challenge/verify check `apps`), no app-role JWT can be minted, no invite-create can succeed.
- **Documentation mismatch:** `docs/TARN_PROTOCOL.md:477` and `:866` both claim Arweave-recoverability via `Type=app-reg`. Neither claim matches the code.

#### G2. Passkey credentials (`passkey_credentials` table) are D1-only

- **Evidence:** `migration 0018` adds the table; `routes/passkeys.js:418-429` is the only writer; no `buildSignedDataItem` call for passkey credential metadata anywhere.
- **What's lost:** `prf_salt` (the deterministic input WebAuthn-PRF needs to derive the wrapping key), `public_key` (needed to verify assertions), `sign_count`, `device_label`, `created_at`, `last_used_at`. The corresponding `passkey_prf` wrapping inside `wrapped_data_key.dek_chain[].wrappings` survives — but useless without `prf_salt`.
- **Effect:** A user with registered passkeys loses every passkey on D1 wipe. They retain password access (because every passkey gets registered alongside an existing password wrapping per `passkeys.js:889-894`). For a future "password-less" mode this would be terminal.

#### G3. No D1-rebuild tooling exists

- **Evidence:** `cache.js` only does single-tuple cold bootstrap given a known `(app, type, lookupKey)`. `tools/backfill-blobs.mjs` only refills `blob_data` for already-indexed rows. There is no tool that enumerates all credential blobs, then walks each account's data, then walks share-inbox + share-log namespaces.
- **What's lost:** Operationally, even for the kinds that ARE on Arweave, restoring D1 requires writing the rebuild tool. The "rebuildability" is a layout property, not a runnable procedure.

### 5.2 Minor

#### G4. `account_key_fetch_log` audit history is D1-only

- See §2.14. UX scaffold; migration 0016 acknowledges it's "NOT a security mechanism on its own."

#### G5. `apps.invite_url_template` is D1-only

- Set via `PUT /apps/:app_id/invite-template`; never written to Arweave. Recoverable only by re-running the setter.

#### G6. `share_log.data_lookup_key` column has no Arweave tag

- Operator-scoped sender attribution is lost. Material is intact.

#### G7. `accounts.rules_json` requires a separate Arweave query to rebuild

- Persisted as `app-config` blobs (a different lookup-key tuple than the credential blob). Rebuild needs to walk `Type=app-config` and join. Without it, every user's writes are denied until the app re-issues `setRules` per user.

### 5.3 Acceptable

All transient kinds: `auth_nonces`, `step_up_tokens`, `webauthn_challenges`, `sessions`, `pending_txs`, `cache_meta`, `write_rate_limits`, `RATE_KV`, `idempotency_keys`, `invites`. Loss = clients re-derive / re-authenticate / retry. Documented as such in their respective migrations.

---

## Closing note

The protocol doc's claim "All tables fully rebuildable from Arweave" should be revised to reflect reality: credential blobs + share blobs + user data are recoverable, but app-registration and passkey-credential tables — added after the original claim was written — are not. The audit log gap is minor; the rebuild-tooling gap is operational rather than architectural (the bytes are there, the script isn't).

> The above closing note is the ORIGINAL pre-fix conclusion. As of the Phase
> A/B/C work and the tarn#35 verification, the app-registration and
> passkey-credential mirrors exist and the rebuild is proven. See §6.

---

## 6. Operational verification (tarn#35 + #41) — VERIFIED on real messy data 2026-06-05

> **RESOLVED (tarn#41 fixed 2026-06-05).** An earlier global rebuild aborted partway through accounts with `UNIQUE constraint failed: accounts.share_lookup_key` — real history has multiple `Type=cred` blobs with distinct `data_lookup_key` but the same `share_lookup_key` (re-registrations + legacy two-accounts-same-email predating #30). tarn#41 added a `share_lookup_key` dedup pass (latest cred per key by block timestamp wins; NULL keys never deduped) plus an `ON CONFLICT(share_lookup_key) DO NOTHING` backstop. **A full global `rebuild-from-arweave --confirm` now runs to completion against the entire dev Arweave history.** From a wiped-to-zero local D1, reconstructed purely from Arweave: **7 apps / 352 accounts (1346 cred blobs found; 292 tombstoned, 288 skipped, 1 share-key-superseded) / 21 passkey_credentials (50 found, 15 tombstoned) / 6 app-config rules / 171 share_inbox (1 body-miss) / 500 share_log**, ~28 min. So recoverability is now **proven on real production-scale messy data**, not just a clean fixture — the identity plane (apps + accounts + passkeys + rules) and share state all reconstruct. The single `share-key-superseded` is the exact collision that aborted the prior run, now handled.

> **>100 KB paid path — PROVEN 2026-06-05.** A direct 140 KiB Turbo upload with the operator wallet was accepted (`turboTxid 6Ppp7ykUYOq5_u5VUNBEdvdKShxBXfbcPKfsirK3bZ4`), confirming the wallet holds Turbo credits and the above-free-tier write path works end-to-end. (The API itself caps inline writes at 100 KiB / 413; this leg validates the underlying Turbo paid path for future large-object use.)

The "Tarn is rebuildable from Arweave" property has been exercised end-to-end
against **mainnet Arweave** (Turbo uploads, real bytes) by
`tests/test-rebuild-from-arweave.mjs`. This section records the proven
procedure, the acceptable-loss list it asserts, and the operational caveats.

### What was proven

A FRESH app (`rebuildtest-<run-id>`, unique per run) was registered via the
canonical `tools/register-app-from-key.mjs` path, then 2 accounts, 2 passkeys
(virtual-authenticator harness), and per-account write rules were created
through the LIVE local API so the real Arweave-mirror writers fired. The full
identity plane was then reconstructed from Arweave alone:

| Table | Rebuilt from | Result |
|---|---|---|
| `apps` | `App=tarn, Type=app-reg, Lk=<app_id>` | identical (`public_key`, `invite_url_template`) |
| `accounts` | `App=tarn, Type=cred, Lk=<clk>[, RLk=<rlk>]` | identical on every exact column (`credential_lookup_key`, `public_key`, `wrapped_data_key`, `app`, recovery fields, share fields, `wrapped_account_key`) |
| `passkey_credentials` | `App=tarn, Type=passkey-reg, CredId=<id>` | identical on `account_id`, `public_key`, `prf_salt`, `device_label` |
| `accounts.rules_json` | `App=<app_id>, Type=app-config, Lk=<dlk>` | identical (per-account rules restored) |
| `entries` | lazy `refreshCache` cold-bootstrap on first read | recovered on read (not pre-populated by the tool — by design) |

The **tarn#36 question is answered YES**: the canonical app-registration path
(`tools/generate-app-key.mjs` / `tools/register-app-from-key.mjs`) publishes a
`Type=app-reg` blob to Arweave (Arweave-first ordering — it publishes, then
prints the D1 seed SQL; it aborts before printing SQL if the publish fails).
The invite-template-update path (`routes/apps.js`) republishes a fresh
`app-reg` blob too. So `apps` is recoverable from registration onward, not only
after an invite-template edit.

### Proven procedure (operator runbook)

1. **Disable the Turbo skip** so writes upload for real: comment out
   `TARN_SKIP_TURBO` in `api/.dev.vars`, then start `cd api && npx wrangler dev
   --port 8787`. (CRITICAL: if a stale `workerd` from a prior `wrangler dev` is
   still running, it keeps the old `TARN_SKIP_TURBO=true` and silently no-ops
   every upload — kill all `workerd` processes before starting.)
2. Run `node --import tsx tests/test-rebuild-from-arweave.mjs
   --i-accept-destructive-wipe --run-id <suffix> --gateway
   https://turbo-gateway.com`.
3. The test: registers app+accounts+passkeys+rules+entries → polls the gateway
   until the mirror blobs are GraphQL/body queryable → snapshots the
   this-app-scoped rows → wipes local D1 (`api/scripts/wipe-accounts.sql` +
   this-app `apps` row + `cache_meta`) → runs `tools/rebuild-from-arweave.mjs
   --confirm` → re-snapshots → diffs modulo the acceptable losses below.
4. **Restore `TARN_SKIP_TURBO=true` in `api/.dev.vars`** after the run so the
   normal integration suites (which assume the skip) keep working.

### Acceptable-loss list (asserted by the diff)

The rebuilt rows must match the pre-wipe snapshot EXCEPT these columns, which
are documented runtime/metadata state deliberately not mirrored to Arweave:

- `accounts.created_at` — block-timestamp approximation; the credential blob
  carries no wall-clock, so the rebuild uses `block.timestamp` (or `Date.now()`
  for not-yet-mined bundles).
- `passkey_credentials.sign_count` — WebAuthn replay counter; resets to `0`.
  The first post-rebuild assertion is benign (the verifier short-circuits when
  stored and presented counters are both 0, the dominant OS-synced-passkey
  case).
- `passkey_credentials.last_used_at` — UX scaffold; resets to `NULL`.
- `share_log.data_lookup_key` — sender attribution is not an Arweave tag;
  rebuilt as the empty-string sentinel `''`.

Also NOT rebuilt (transient/by-design, per the tool's `--help`): `cache_meta`
bootstrap markers, `sessions`, `step_up_tokens`, `webauthn_challenges`,
`pending_txs`, `idempotency_keys`, `write_rate_limits`,
`account_key_fetch_log`, `RATE_KV`.

### Mainnet indexing-latency caveat

The rebuild reads via GraphQL, so freshly-uploaded Turbo data items must first
be indexed. Observed latency:

- **`turbo-gateway.com`** — indexes its own Turbo bundles in ~7–12 min. Its
  GraphQL indexer is occasionally `UPSTREAM_CIRCUIT_OPEN`; the test's poll
  falls back to a body fetch as the readiness signal.
- **`arweave.net`** — L1 GraphQL lags ~15–25 min (bundle must confirm → post to
  L1 → mine → index). More reliable, slower. This is the gateway the worker's
  `entries` cold-bootstrap (`api/src/arweave.js`) is hardcoded to, so the
  `entries` recovery leg lags independently of the identity-plane rebuild.

The test polls (with a generous `--index-timeout-ms`) and, if blobs never index
in the window, reports a precise "indexing latency" blocker and does NOT wipe
D1 or fake a pass.

### >100 KB Turbo paid path

The `/api/v1/entries` endpoint hard-caps payloads at `MAX_UPLOAD_BYTES`
(100 KiB) and returns 413 above it — there is no oversized write path through
the API. The test exercises the Turbo PAID path by uploading one 140 KiB
DataItem directly via `api/src/turbo.js` with the operator wallet, confirming
Turbo accepts it (a 402/403 would be recorded as "BLOCKED — wallet needs Turbo
credits", an operator action, not a test failure).
