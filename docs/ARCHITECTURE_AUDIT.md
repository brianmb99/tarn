# Tarn architecture audit — back-end + SDK + seam reconciliation

Date: 2026-06-04. Scope: Tarn repo (API/Worker/D1/Arweave back-end + client SDK).
Companion: `../bookish/docs/ARCHITECTURE_AUDIT.md` (Bookish data-flow layer).
Method: three parallel read-only audits (back-end, SDK, Bookish), each owning one inter-layer seam, then a synthesis pass. Findings below are **normalized for severity across all three** and tagged with my confidence (verified-by-review vs. agent-claim-pending-verification).

This is a findings record, not a work order. Issues are filed separately after triage.

---

## The one-paragraph story

The **implementations are sound** — write-ordering, idempotency, atomic rate limits, JWT validation, CORS, per-app isolation, typed-collection validation, Eid determinism are all confirmed healthy and tested. The risk is concentrated in **two places, both structural, neither a code-quality problem**:

1. **The recoverability promise is unverified and partially unimplemented.** "Arweave is the source of truth; D1 is a disposable cache" holds for the *data plane* (entries) but breaks for the *identity plane*: app registrations and passkey credentials live only in D1, and the rebuild path has never been run end-to-end.
2. **Schema versioning is a no-op end-to-end.** The `SchemaV` tag is stamped on every write and read by nothing — not the API (correct, zero-knowledge) and not the SDK (a latent landmine). The first schema version bump has no defined behavior.

Everything else is medium/low hardening.

---

## Severity scale (uniform across all three audits)

- **CRITICAL** — data loss, unrecoverable state, or security-boundary violation
- **HIGH** — user-facing breakage, or a real-but-recoverable integrity problem
- **MEDIUM** — latent bug currently masked, or missing enforcement/test for a real risk
- **LOW** — nit, cosmetic, defensive nice-to-have

---

## Back-end findings (API ↔ Arweave/D1)

### Headline: D1 cannot currently be proven rebuildable from Arweave; the identity plane can't be rebuilt at all.

| ID | Title | Severity | Status | Confidence |
|----|-------|----------|--------|-----------|
| BE-1 | D1-rebuild-from-Arweave never run end-to-end | CRITICAL | untested | verified (scaffold + pre-existing `ARWEAVE_RECOVERABILITY_AUDIT.md` confirm) |
| BE-2 | `apps` table has no Arweave mirror — app reg unrecoverable on D1 loss; protocol doc falsely claims `Type=app-reg` blobs | CRITICAL | enforced-but-unrecoverable | verified |
| BE-3 | Passkey credentials (PRF salt + pubkey) are D1-only — passkeys dead on D1 loss (password survives) | CRITICAL | untested | verified |
| BE-4 | Turbo upload: 20s timeout, no retry, no fallback gateway (single point of failure for writes) | MEDIUM | healthy-but-SPOF | verified |
| BE-5 | Registration rate-limit fails open during KV outage (by design) | MEDIUM | by-design | agent-claim |
| BE-6 | `share_lookup_key` NOT-NULL enforced at API boundary + partial index, but legacy NULL rows persist and a non-register insert path could re-introduce NULLs | MEDIUM | enforced (register path) | verified |

**BE-1 (CRITICAL).** `tests/test-rebuild-from-arweave.mjs` exists but is a scaffold: explicitly excluded from the suite (it writes to Arweave / destroys local D1), ends in `process.exit(0)` after printing instructions, and has never been run. A pre-existing `docs/ARWEAVE_RECOVERABILITY_AUDIT.md` confirms the team already knows: "the actual reconstruction logic is partially absent — `api/src/cache.js` only knows how to backfill `entries` rows for a known `(app, type, lookup_key)` tuple." Until this runs green once, "Arweave is the source of truth" is aspiration, not fact. *This is the single highest-leverage finding in the entire audit.*

**BE-2 (CRITICAL).** `apps` table is populated only via `tools/generate-app-key.mjs` / `register-app-from-key.mjs` doing direct `wrangler d1 execute` inserts. No route writes an `app-reg` blob to Arweave. `TARN_PROTOCOL.md:866` claims "Apps rebuilt from `Type=app-reg` blobs" — **that code path does not exist.** Spec/impl mismatch. On D1 loss: every `register` returns "Unregistered app," nobody can auth. For Bookish specifically (single app, private key in custody) this is recoverable by re-running the registration tool; for the platform claim it's load-bearing.

**BE-3 (CRITICAL).** `passkey_credentials` (migration 0018) stores `prf_salt` + WebAuthn `public_key` in D1 only. No Arweave mirror. On D1 loss every passkey is unusable (the credential's wrapping ciphertext survives inside the on-chain credential blob, but the plaintext salt/pubkey needed to *verify* an assertion does not). Password auth survives because the password wrapping is preserved on-chain. Net: D1 loss = "all your passkeys are dead, log in with your password" — acceptable IF documented and IF passkey-only accounts are truly prevented (they are, today).

**Verified healthy (back-end):** write returns success only after Turbo accepts *and* D1 write-through commits (no split-brain); `X-Idempotency-Key` dedup with 24h TTL; atomic per-account write limit (100/hr) and read limit (1000/hr) via `INSERT…ON CONFLICT…RETURNING` (no TOCTOU); JWT signature+expiry+session checks on all authed routes; per-app key isolation enforced on register+write; CORS on all responses incl. errors (issue #2 fixed); additive-only migrations; `TARN_SKIP_TURBO` refused on production hosts; full integration-test coverage of every endpoint **except** D1-rebuild.

---

## SDK findings (SDK ↔ API)

### Headline: SchemaV is write-only (versioning landmine); two unproven-correctness areas (JWT refresh race, delta cursor).

| ID | Title | Severity | Status | Confidence |
|----|-------|----------|--------|-----------|
| SDK-1 | `SchemaV` stamped on write, never read — no migration dispatch; detonates on first schema bump | CRITICAL | assumed-not-enforced, untested | verified (independently corroborated by back-end audit: API also ignores SchemaV) |
| SDK-2 | Concurrent JWT refresh race — no pending-refresh guard | MEDIUM (↓ from agent's HIGH) | masked by API nonce check | verified |
| SDK-3 | Delta-sync cursor: no documented monotonicity / gap-recovery; could silently miss entries | HIGH | assumed-not-enforced, untested | agent-claim-pending-verification |
| SDK-4 | Session serialize/resume field-fidelity not asserted test | MEDIUM | healthy-but-untested | verified |
| SDK-5 | Recovery-flow *combinations* untested (recovery×passkey, changeCreds×recovery, rotate×passkey) | MEDIUM | untested | verified |
| SDK-6 | `primaryKey` immutability not enforced in `Collection.update` | MEDIUM | assumed-not-enforced | verified |
| SDK-7 | Typed vs untyped read divergence (typed drops orphans, untyped returns them) — undocumented | LOW | by-design, undocumented | verified |
| SDK-8 | System-type writes (share-log, share-state) bypass Eid/SchemaV — correct but undocumented | LOW | by-design | agent-claim |
| SDK-9 | Error taxonomy incomplete — many generic `throw new Error` where typed errors exist | LOW | incomplete | verified |
| SDK-10 | Passkey `changeCredentials` throws indirect "corrupt session?" instead of `TarnPasskeyOnlyError` | LOW | by-design, poor-message | verified |

**SDK-1 (CRITICAL).** `SchemaV` is stamped at `collection.ts:416`, `advanced.ts:150`, `tarn.ts:2827`. A grep of all of `client/src/` finds **zero** read-side consumers (`readSchemaV`/`getSchemaV`/version-dispatch — none). The only tag read on the read path is `Gen` (for DEK selection). So when you bump the schema to v2, a v1 client reading v2 entries has no branch: strict validation either silently strips unknown fields or throws on missing required fields. **This is a designed-in landmine that goes off the first time you change the schema** — which you will. Independently corroborated by the back-end audit (BE: "API does not validate SchemaV, trusting the SDK") — so SchemaV is inert across the *entire stack*.

**SDK-3 (HIGH, pending verification).** The delta cursor is opaque server state, persisted verbatim, fallback `'0:'`. No documented guarantee of monotonicity or behavior under Arweave confirmation reordering. If an earlier entry confirms *after* the client advances its cursor, that entry could be permanently skipped (IndexedDB persistence means no from-scratch re-sync). This is the SDK↔API assumption most worth nailing down — it's the difference between "eventually consistent" and "silently drops a book." Needs confirmation with the API's actual cursor semantics before filing severity.

**SDK-2 (MEDIUM, downgraded).** The agent rated this HIGH; I'm downgrading. Two concurrent ops both seeing an expired JWT will both null it and re-`#authenticate()` with no mutex. But the agent's *own* evidence notes the API rejects mismatched nonce+signature, so the real-world impact is confusing transient 401s that resolve on retry — not data loss or session corruption. Worth fixing (a `#jwtRefreshPromise` guard is cheap) but not HIGH.

**Verified healthy (SDK):** Eid determinism; primaryKey extraction+validation on create; batch-create atomicity (all-or-nothing); JWT expiry+refresh on the happy path; passkey-only `isLoggedIn` correctness (post-#27); credential-rotation state machine; account-key pinning (`AccountKeyPinningError`); 429→`TarnRateLimitError` (no auto-retry, post-#29). The duality map shows **write paths and auth/session paths are converged+tested** (the #32/#33/#34 work); the *unconverged-or-untested* dualities are the recovery-flow combinations (SDK-5) and the intentional-but-undocumented orphan read divergence (SDK-7).

---

## Seam reconciliation (cross-layer findings only the synthesis pass reveals)

These are the findings no single-layer audit could see — they live in the contracts *between* layers.

### S-1 — SchemaV is inert end-to-end (elevates SDK-1 confidence to CRITICAL-certain)
Back-end and SDK audits independently found SchemaV unread on their side. Combined: the tag is written by the SDK, ignored by the API (correctly), and never read back by the SDK. Versioning is **completely unimplemented across the whole stack**, not just under-implemented in one layer. Two independent confirmations → this is real, not an audit artifact.

### S-2 — Idempotency mechanism exists but isn't wired through to offline replay
The back-end provides `X-Idempotency-Key` dedup (BE: verified healthy). But the Bookish audit found offline-create-replay can **double-write** (BOOKISH-2: crash between `books.create()` and `removeOp()` → retry creates a second remote entry). The seam: **the durability mechanism the API offers is not used by the replay path.** Fix is cheap and high-value — thread a stable idempotency key (keyed on the local op id) through `create()` on replay, and the API's existing dedup eliminates the duplicate. This finding only exists at the seam; neither single audit framed it.

### S-3 — The passkey "second-class citizen" cluster spans all three layers
- Back-end: passkey credentials unrecoverable on D1 loss (BE-3)
- SDK: passkey `changeCredentials` throws an indirect error (SDK-10); recovery×passkey combinations untested (SDK-5)
- Bookish: passkey sharing fails silently (BOOKISH-1); passkey auth error boundary unverified (BOOKISH-4)

The #32 work fixed in-memory *state* symmetry. What remains is **recoverability** (back-end) and **error-surfacing** (Bookish + SDK error taxonomy). A coherent "passkey is a full citizen end-to-end" follow-up would close all five at once.

### S-4 — The orphan story is now fully closed (causal chain confirmed across layers)
SDK-7 (typed reads drop orphans) + Bookish import tooling writing untyped (`audible-tarn-import.mjs:316`, the existence of `repair_audible_orphans.mjs`) + back-end entries-are-recoverable = complete chain: **the Audible importer wrote books via the untyped batch path without per-item Eids → orphans on Arweave → typed reads dropped them → missing books in the app.** "An African History of Africa" was an Audible import, not a ghost. #34 has already defanged the SDK path; the remaining action is migrating the importer to the typed surface (Bookish-side).

---

## Master triage table (all three audits, my recommendations)

| # | Finding(s) | Sev | Repo | Recommendation |
|---|-----------|-----|------|----------------|
| 1 | BE-1: run D1-rebuild-from-Arweave end-to-end, prove it | CRITICAL | tarn | **file** |
| 2 | BE-2 + BE-3: mirror `apps` + passkey credentials to Arweave; fix protocol doc's false `app-reg` claim | CRITICAL | tarn | **file** (1 issue, 2 parts) |
| 3 | SDK-1 + S-1: implement SchemaV read-side dispatch before any schema bump | CRITICAL | tarn | **file** |
| 4 | SDK-3: document + test delta-cursor monotonicity / gap-recovery | HIGH | tarn | **verify-then-file** |
| 5 | S-2 + BOOKISH-2: thread idempotency key through offline replay (kills double-write) | HIGH | bookish (+maybe sdk) | **file** |
| 6 | BOOKISH-1: passkey sharing fails silently — surface the error | MEDIUM | bookish | **file** |
| 7 | BOOKISH-3: offline-edit clobbered by stale delta | MEDIUM | bookish | **file** |
| 8 | Audible importer uses untyped write — migrate to typed `books.batchCreate` (S-4) | MEDIUM | bookish | **file** (cheap) |
| 9 | SDK-5: recovery-flow combination tests | MEDIUM | tarn | **file** |
| 10 | SDK-6: primaryKey-immutability guard in `Collection.update` | MEDIUM | tarn | **file** |
| 11 | SDK-2: serialize concurrent JWT refresh | MEDIUM | tarn | defer (cheap, low impact) |
| 12 | SDK-4: session round-trip field-fidelity test | LOW | tarn | defer |
| 13 | SDK-9 + SDK-10: complete error taxonomy (typed errors for generic throws) | LOW | tarn | defer |
| 14 | SDK-7 + SDK-8: document orphan semantics + reserved system types | LOW | tarn | doc-only |
| 15 | BE-4/BE-5/BE-6: document Turbo SPOF, KV fail-open, audit non-register insert paths | MEDIUM/LOW | tarn | doc + 1 verify |
| 16 | BOOKISH-4/5: verify passkey auth error boundary; improve dedup hash | LOW | bookish | defer |

**The four that matter:** rows 1–3 (the two CRITICAL recoverability gaps + the SchemaV landmine) and row 5 (the cheap double-write fix). Everything else is hardening that can be sequenced behind them.
