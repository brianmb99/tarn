# Recovery system implementation plan

> **Status:** approved direction, ready for phased implementation. This doc is the working guide for executing the work — what to build, in what order, where each piece lives. Last updated 2026-05-06.
>
> **Companion docs:**
> - [RECOVERY_ONBOARDING_BRIEF.md](RECOVERY_ONBOARDING_BRIEF.md) — paradigm framing
> - [PHRASE_RETRIEVAL_BRIEF.md](PHRASE_RETRIEVAL_BRIEF.md) — retrieval issue + outer-encryption pushback
> - [EXTERNAL_FEEDBACK_GROK.md](EXTERNAL_FEEDBACK_GROK.md) — Grok response (passkeys idea sourced from here)

## Decisions made

After extended discussion, the following are settled:

1. **Default model is Model B** (phrase ciphertext stored on Tarn, retrievable by logged-in user via DEK).
2. **Model A is exposed as user opt-in** (toggle in app settings; Bookish surfaces this as something like "extra security mode" with plain-English consequence statement).
3. **Step-up auth required on phrase fetch** (re-derived password proof, JWT alone insufficient).
4. **OOB challenge gating is Bookish-side, not a Tarn primitive** (Bookish builds it on their email infra; Tarn doesn't need an attestation primitive yet).
5. **`rotateRecoveryPhrase` ships as a Tarn primitive** (real eviction tool, independent of Model A/B choice).
6. **wrapped_phrase is published to Arweave** as part of the account record, preserving the "Tarn infra is transient/rebuildable" property.
7. **Existing `regenerateRecoveryKit` / `tarn.recovery.export` / PDF generator are removed** (apps render their own kits; Tarn returns the phrase, not bytes).
8. **Passkey support is planned but deferred**, optional for apps when shipped. Not blocking launch.
9. **Rename: "recovery phrase" → "account key"** (current term implies optional fallback; new term reflects that it IS the access). This needs final sign-off but is the working assumption.
10. **Bookish positioning:** lead with privacy (architecture warrants it), build for personal-utility growth via word-of-mouth, defend Signal-grade property when growth conflicts with it.

## Explicitly out of scope (do not build)

These were considered and rejected. If a sub-agent's work suggests building any of these, escalate first:

- **Outer encryption with per-app key.** Doesn't defend the threat we care about; adds runtime key management for narrow defense in depth.
- **2-of-2 client/Tarn key split.** Same reasoning as above.
- **Time-delayed reveal with cancel window.** Wrong default UX for the product.
- **Threshold/social recovery (Shamir among trusted contacts).** UX cost too high for casual users; can revisit later if needed.
- **OOB challenge as a Tarn primitive.** Belongs in Bookish for v1.
- **Signup-time saved-phrase-proof gates** (type-back, forced download to continue, etc.). Friction without solving the real problem.
- **Email/PDF delivery from Tarn.** Already removed; do not reintroduce.
- **Automatic phrase rotation on credential rotation.** Disarms the lifeline; user-initiated rotation only via `rotateRecoveryPhrase`.

## Phase ordering

Roughly sequential, but phases 2 and 3 can be parallel work streams. Phase 1 must come first (naming decision affects everything downstream). Phases 5 (Bookish) waits on phase 3+4 to land in Tarn first.

---

## Phase 1 — Naming decision and protocol doc update

**Goal:** lock the user-facing term and document the Model A/B distinction in the protocol spec before any code changes use new vocabulary.

### 1.1 Confirm the rename

- **Working assumption:** "recovery phrase" → "account key"
- Rationale: "recovery" implies fallback/optional/recoverable-by-other-means. "account key" reflects that this *is* the access credential, not a backup.
- Alternatives considered: "master key" (too technical), "vault key" (unfamiliar), "access key" (slightly technical).
- **Action:** confirm with user, then thread through.
- **Where it changes:** TARN_PROTOCOL.md, client/README.md, all SDK method names, all error messages, all log strings, all tests. Sub-agents doing this should grep for "recovery phrase", "recoveryPhrase", "RECOVERY_PHRASE" and update consistently. The protocol-level identifier (`recovery_lookup_key`, `FACTOR_RECOVERY_PHRASE`) can stay as-is to avoid wire-compat breaks — only user-facing strings and SDK surface change.

### 1.2 Document Model A vs Model B in TARN_PROTOCOL.md

- Add a section on the security-model choice.
- Model A: phrase-as-independent-lifeline (no wrap stored). Model B: phrase-as-credential-recoverable-item (wrap stored, retrievable).
- Document what each implies about credential-compromise consequences.
- Make clear apps choose by sending or not sending `wrapped_phrase` at registration; users can switch later.

**Acceptance:** TARN_PROTOCOL.md reads coherently with the new vocabulary; the Model A/B distinction is explicit; future app authors can read it cold and pick correctly.

---

## Phase 2 — Cleanup of existing PDF/export code

**Goal:** remove the in-SDK PDF generator and `tarn.recovery.export` before adding new primitives. Decided in earlier discussion (the email-forwarder logic — Tarn returns words, not rendered bytes).

### 2.1 Remove `renderRecoveryPDF` from the SDK

- **Files:** `client/src/recovery.ts` (delete the PDF generator section), `client/src/tarn.ts` (remove import + re-export at lines 48 and 147).
- Keep: `generateRecoveryPhrase`, `validateRecoveryPhrase`, `recoveryPhraseToEntropy` — these are protocol-correct primitives apps still need.

### 2.2 Remove `TarnClient.regenerateRecoveryKit`

- **Files:** `client/src/tarn.ts` (method at line 424), `client/src/client/tarn-client.ts` (interface), `client/src/client/namespaces/recovery.ts` (the namespace's `export()` method calls this).

### 2.3 Remove `RecoveryNamespace.export` and the `tarn.recovery.export` SDK call

- **Files:** `client/src/client/namespaces/recovery.ts` — the `export()` method goes; the namespace can either be removed entirely or kept as a stub for future methods (`view`, `rotate`).

### 2.4 Stop returning `pdfBytes` from `register`

- **Files:** `client/src/tarn.ts` around line 400-406 — register returns `{ dataLookupKey, accountKey }` (renamed from `recoveryPhrase`); drop `pdfBytes`. App is responsible for any rendering.

### 2.5 Remove tests for the deleted code

- **Files:** `tests/unit/client-recovery.test.js` (lines 494-565), `client/tests/client.test.ts` (lines 836-846 and stub at 49, 120-121).

### 2.6 Update docs

- **Files:** `client/README.md` (lines 257-259), TARN_PROTOCOL.md line 635 reference, line 133 reference to `regenerateRecoveryKit` closing the recovery gap (replace with reference to `rotateRecoveryPhrase`).

**Acceptance:** all PDF-rendering code gone from SDK; `register()` returns just the phrase string; existing test suite still passes after deletions; no references to `regenerateRecoveryKit` or `renderRecoveryPDF` remain.

---

## Phase 3 — Core Model B primitives (storage, fetch, step-up)

**Goal:** the minimum primitives for "logged-in user retrieves their account key in Settings."

### 3.1 `wrapped_phrase` storage at registration

- **API:** `POST /api/v1/auth/register` accepts optional `wrapped_phrase` field (base64 AES-GCM ciphertext encrypted under DEK_gen1).
- **D1:** add `wrapped_phrase` column to `accounts` table (nullable). Add migration.
- **Arweave:** include `wrapped_phrase` in the account record published to Arweave so the "Tarn infra rebuildable from Arweave" property holds.
- **Client SDK:** at registration, compute `wrapped_phrase = AES-GCM(key=DEK_gen1, plaintext=phrase_utf8, aad="tarn-wrapped-phrase-v1")` and include it in the register payload IF the calling app passes a `storeAccountKey: true` option (default true; apps that want strict Model A pass false).
- **Acceptance:** registering with the option produces a `wrapped_phrase` in D1 and on Arweave; registering without the option leaves the column null.

### 3.2 Step-up auth endpoint

- **API:** `POST /api/v1/auth/step-up` — accepts a fresh password proof (re-derive credential against a server challenge, sign with the password-derived signing key), returns a short-lived single-use token (`phrase_fetch_token`, ~60s TTL, scope = "phrase_fetch").
- **D1:** ephemeral storage for the token (KV or short-lived row in a `step_up_tokens` table; can also be JWT-encoded with a server-side revocation list if simpler).
- **Acceptance:** valid challenge response yields a token; token is single-use; expired/used tokens are rejected; token works only for the phrase-fetch endpoint.

### 3.3 Phrase fetch endpoint

- **API:** `GET /api/v1/account/account-key` (or `/recovery-phrase-wrap` — pick name during phase 1). Requires both a valid session JWT *and* a valid `phrase_fetch_token`. Returns `{ wrapped_phrase, recovery_salt, kdf_params }` so the client can pin and decrypt.
- **Auth:** rejects with 401 if either auth element missing.
- **Audit log:** every fetch should log (account_id, timestamp, ip) so we can later surface "phrase last viewed at X" in account settings.
- **Acceptance:** authenticated + stepped-up request returns the wrap; either auth missing yields 401; audit row created.

### 3.4 SDK: `tarn.recovery.view()` (or `tarn.account.viewKey()`)

- Method orchestrates: prompt for password (caller-supplied callback), call `/auth/step-up` with the proof, call `/account/account-key` with the token, decrypt with DEK in memory, derive `recovery_lookup_key` from the decrypted phrase and compare to the account's known `recovery_lookup_key` (wrap-pinning check), return the phrase.
- Throws on pin mismatch with a security-warning error type that the caller can surface differently from a normal failure.
- **Acceptance:** end-to-end flow works against local wrangler dev; pinning check fires on tampered wrap; SDK doesn't retain the phrase after returning it.

### 3.5 Auth/verify response includes wrap presence indicator

- **API:** `/auth/verify` response includes `account_key_stored: boolean` so the app can render the appropriate Settings UI (show "View your account key" vs "Account key is not stored — save it at signup or enable storage").
- Does NOT return the wrap itself (that's behind step-up).
- **Acceptance:** field present in response; reflects D1 state.

---

## Phase 4 — Toggle and rotation

**Goal:** users can switch between Model A and Model B; users can rotate the account key when they suspect compromise.

### 4.1 Toggle: Model B → Model A (delete the wrap)

- **API:** `DELETE /api/v1/account/account-key` — removes `wrapped_phrase` from D1, publishes a new account-record version to Arweave reflecting the deletion (the old Arweave record remains, but the current account state shows no wrap; clients reading Arweave honor the latest record).
- **Auth:** requires JWT + step-up token (same as fetch — this is a security-affecting change).
- **Acceptance:** after the call, fetch returns 404 / "no wrap stored"; subsequent re-additions work via 4.2.

### 4.2 Toggle: Model A → Model B (add the wrap)

- **API:** `PUT /api/v1/account/account-key` with `{ wrapped_phrase }` body — caller must have re-entered the phrase to compute the wrap (the SDK orchestrates this).
- **Auth:** JWT + step-up token + the wrap itself proves possession of the phrase (decrypt-check happens client-side; server just stores).
- **Acceptance:** call with a valid wrap stores it; subsequent fetch returns it; pin check passes when client decrypts.

### 4.3 SDK: toggle methods

- `tarn.account.enableKeyStorage({ phrase })` — adds the wrap.
- `tarn.account.disableKeyStorage()` — removes it.
- Both run the step-up flow internally.
- **Acceptance:** round-trip works; Settings UI in Bookish can call these directly.

### 4.4 `rotateRecoveryPhrase` primitive

- **API:** `POST /api/v1/account/rotate-account-key` — body carries `{ new_envelope, new_recovery_lookup_key, new_recovery_public_key, new_wrapped_phrase? }` (the wrap is included only if storage is enabled).
- **Atomicity:** D1 transaction updates all four fields together; partial states not allowed. Arweave publication of the new account record happens after D1 commit (eventual consistency is fine since clients read D1 first, Arweave as fallback).
- **Auth:** JWT-authed (no step-up required since it's a write that requires the user to have generated and confirmed a new phrase — the friction is on the client side).
- **Client orchestration:** generate new phrase → derive new recovery KEK + lookup key + signing key + public key → re-wrap every gen of the DEK chain under {existing password KEKs, new recovery KEK} → compute new `wrapped_phrase` if storage is on → submit.
- **Acceptance:** post-call, old phrase no longer authenticates; new phrase does; data still decryptable; if storage was on, fetching the wrap yields the new phrase.

### 4.5 SDK: `tarn.recovery.rotate()`

- Method handles all the orchestration.
- Returns the new phrase to the caller (so the app can present it for the user to save).
- **Acceptance:** round-trip flow works locally; old phrase rejected by `recoverAccount` post-rotation.

### 4.6 Update `recoverAccount` to optionally piggyback rotation

- Add `{ rotatePhrase: true }` option that runs the rotation as part of the recovery completion. Default false.
- **Acceptance:** opted-in recovery yields a new phrase the user must save; default recovery preserves the existing phrase.

---

## Phase 5 — Bookish onboarding and settings UX

**Goal:** Bookish surfaces all of the above in user-facing flows. This work is in the Bookish repo, not Tarn.

### 5.1 Signup flow

- Show the account key once, calmly. No scary one-time warning. Frame: "This is your account key. Save it now, or anytime in Settings. We can't reset your account for you — that's the point."
- No save-proof gating. User can dismiss and continue.
- Default Model B — wrap is stored on Tarn.

### 5.2 Settings → Account & Security

- "View account key" — triggers step-up (password re-entry) → phrase displayed in modal.
- "Rotate account key" — confirmation dialog with consequence statement → new phrase generated and shown to save → confirm before completing.
- "Extra security mode" toggle — plain-English copy explaining: "When on, your account key isn't stored on our servers. You'll need to have saved it elsewhere, or you can permanently lose access to your library if you forget your password." Toggle on = Model A; toggle off = Model B.
- "Account key was last viewed: [date]" — surfaces audit info from Tarn.

### 5.3 Engagement-milestone reminders

- At configurable points (e.g., 30 books added, 60 days post-signup), check if user has confirmed they saved the key. If not, surface a gentle prompt: "Your library is growing. Make sure you can keep it forever — view and save your account key now."
- "I've saved it" confirmation persists in Bookish localStorage; banner stops appearing after confirmation.

### 5.4 OOB challenge for view (Bookish-side, optional for v1)

- When user clicks "View account key," before triggering Tarn step-up, send a code to the user's registered email; require code entry as a Bookish-layer gate.
- Defends against phished-password attackers.
- **Optional in v1** — can be added post-launch.

---

## Phase 6 — Passkey support (deferred, optional for apps when shipped)

**Goal:** add WebAuthn-PRF-based passkey as a third auth factor in Tarn's envelope. Not blocking launch; specced here so the work is scoped when picked up.

### 6.1 Envelope shape change

- Add a third factor type: `factor: 'passkey_prf'` alongside `'password'` and `'recovery_phrase'`.
- Each `dek_chain` entry's `wrappings` array can now carry up to three wrappings; passkey is opt-in per account.

### 6.2 Registration: `tarn.auth.registerPasskey({ deviceLabel })`

- Calls `navigator.credentials.create()` with PRF extension.
- Derives a wrapping key from the PRF output.
- Re-wraps the DEK chain under {existing password KEK, existing recovery KEK, new passkey-PRF KEK}.
- Stores the passkey credential ID + public key + PRF salt on the account record.

### 6.3 Authentication: `tarn.auth.authenticateWithPasskey()`

- Calls `navigator.credentials.get()` with PRF extension.
- Derives the wrapping key from PRF output.
- Unwraps the DEK chain.
- Establishes session.

### 6.4 Management: `tarn.auth.listPasskeys()`, `tarn.auth.removePasskey(id)`

- Standard device management.

### 6.5 Fallback handling

- Detect PRF support; if unavailable, the SDK does not offer passkey registration to that device.
- Apps surface passkey as one auth option among several.

**Note:** scope this carefully when the work is picked up. PRF extension support varies; need to check 2026 browser landscape at the time.

---

## Sub-agent execution notes

When spawning sub-agents to implement individual phases:

- **Always link to this doc** in the sub-agent prompt so they have the full context.
- **One PR per phase** is the right granularity; 3.1 + 3.2 + 3.3 + 3.4 + 3.5 belong together because they're a single coherent feature (Phase 3). The 4.x items can split into two PRs (toggle vs rotation) if useful.
- **Phase 1 (naming) must be a separate, first PR** — don't bundle with code changes. It's a pure rename + doc update.
- **Phase 2 (cleanup) is independent** — can be a separate PR, can land before or in parallel with Phase 3.
- **Verify each phase** before moving on. Local wrangler dev + the post-deployment smoke test (`tests/test-deployed.mjs`) both need to pass.
- **The supply-chain rule applies** (`min-release-age=10080`). Don't bypass.
- **Watch for Bookish-specific terms creeping into Tarn code** — Tarn is app-agnostic. Wrap-storage is a primitive, not a "Bookish feature."

## Open items requiring user sign-off before Phase 1 starts

- ✅ **Rename target:** "account key" (confirmed).
- **Mode name for the Model A/B toggle:** deferred to Phase 5 (Bookish UX). Tarn-side endpoints and SDK methods are named after the action (`enable/disableKeyBackup`), not the mode, so the protocol work doesn't depend on this decision. The Bookish UX team picks the user-facing framing when they get to settings copy.
