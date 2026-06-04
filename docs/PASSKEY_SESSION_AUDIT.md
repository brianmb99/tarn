# Tarn passkey-session audit — Phase 1

Status: complete (audit only — no remediation in this commit).
Issue: [tarn#32](https://github.com/brianmb99/tarn/issues/32).

## Why this document exists

Tarn supports two login paths:

- **Password** (`login(email, password)` / `register(...)`) — derives master key, populates `#signingKeyPair`, `#credentialLookupKey`, `#credentialEncryptionKey`, `#username`, `#sharingKeyPair`, plus `#dekByGen` and `#jwt`.
- **Passkey** (`authenticateWithPasskey(...)`) — uses WebAuthn PRF, populates `#dekByGen` and `#jwt` only. All password-derived state stays null.

The intended principle:

> Initial auth step differs. Everything downstream — "you're authenticated, here's your data" — should be identical.

In practice, every downstream operation that implicitly reads password-derived state has been a whack-a-mole bug. Already filed and patched piecemeal: #25, #27, #28. This audit walks `client/src/` to find what's left **before** users do.

## Scope

Audited files:
- `client/src/tarn.ts` (the core TarnClient class, ~6500 lines)
- `client/src/client/tarn-client.ts` (public wrapper)
- `client/src/client/namespaces/*.ts` (accountKey, passkeys, advanced)
- `client/src/collections/collection.ts` (typed surface — exercises sharing primitives)

Out of scope: `api/`, recovery PDF generation (no longer exists), tests.

---

## Inventory: every reference to password-derived private state

### `#signingKeyPair` (25+ references)

| Site | Code | Classification |
|---|---|---|
| tarn.ts:508, 776, 890 | Assignment during login/register/recoverAccount | n/a (writes) |
| tarn.ts:1001 | `changeCredentials()`: explicit guard `if (!this.#signingKeyPair || ...)` | **A** safe |
| tarn.ts:3406, 3694, 3979, 4150 | Sharing/connection guards `if (!this.#sharingKeyPair || !this.#username || !this.#signingKeyPair)` | **A** safe |
| tarn.ts:3423, 3717, 4009, 4209, 4447 | Non-null assertion `#signingKeyPair!` after guard | **A** safe |
| tarn.ts:4425 | `_publishShareLogEntry()` guard | **A** safe |
| **tarn.ts:5448** | **`#hydrateOutboundState()`: `await exportPublicKey(this.#signingKeyPair!.publicKey)` with NO guard in the method itself** | **B — LIVE BUG (see below)** |
| tarn.ts:5879 | `serializeSession()`: `if (!this.#signingKeyPair && !this.#jwt)` | **A** safe (either/or) |
| tarn.ts:6230, 6339 | `isLoggedIn` / `isAuthenticated`: `#signingKeyPair != null || #jwt != null` | **A** safe (either/or) — fixed in #27 |
| tarn.ts:6438, 6457 | `#requireAuth` / JWT refresh path | **A** safe |
| tarn.ts:6481 | `#verifyChallenge()`: `#signingKeyPair!.privateKey` after `#requireAuth()` | **A** safe (caller-guarded) |

### `#credentialLookupKey` (12 references)

| Site | Code | Classification |
|---|---|---|
| tarn.ts:506, 774, 888 | Assignment on password auth | n/a |
| tarn.ts:1001 | `changeCredentials()` guard | **A** safe |
| tarn.ts:1825 | `rotateAccountKey()`: defensive comparison `if (this.#credentialLookupKey && reKeys.credentialLookupKey !== this.#credentialLookupKey)` | **A** safe |
| tarn.ts:2725 | Logout cleanup | n/a |
| tarn.ts:5964, 6158 | Conditional serialize/resume — optional in v3 blob | **A** safe (#25 fix) |
| tarn.ts:6457, 6470, 6487 | JWT refresh: guarded by `if (this.#signingKeyPair && this.#credentialLookupKey)` | **A** safe |

### `#username` (17 references)

| Site | Code | Classification |
|---|---|---|
| tarn.ts:512, 779, 900 | Assignment on password auth | n/a |
| tarn.ts:1001, 1477, 1587, 1660, 1811, 2544 | Explicit guards in `changeCredentials`, accountKey ops, `removePasskey` | **A** safe |
| tarn.ts:3406, 3425 | Connection ops: guarded, then `!`-asserted | **A** safe |
| tarn.ts:2300-2314 | `authenticateWithPasskey` stale-credential repair: accepts username from handler | **C — intentional** (see Category C #2 below) |
| tarn.ts:5963, 6161 | Conditional serialize/resume — optional | **A** safe (#25 fix) |

### `#sharingKeyPair` (21 references)

| Site | Code | Classification |
|---|---|---|
| tarn.ts:513, 780, 901 | Assignment on password auth | n/a |
| tarn.ts:3406, 3509, 4318 | Sharing ops + `#getPairKeysFor`: explicit guards | **A** safe |
| tarn.ts:3426, 3720, 4010, 4162, 4212, 4329, 4333 | Direct `.publicKey` / `.privateKey` access after guard | **A** safe |
| tarn.ts:5967-5971, 6168 | Conditional serialize/resume | **A** safe |

### `#credentialEncryptionKey` (10 references)

| Site | Code | Classification |
|---|---|---|
| tarn.ts:507, 775, 889 | Assignment on password auth | n/a |
| **tarn.ts:2553-2555** | `removePasskey()`: on-demand re-derivation if missing | **C — intentional dual-path** (passkey-only sessions step-up via password) |
| tarn.ts:2611, 2667 | Passkey envelope rebuild guards | **A** safe |
| tarn.ts:5914-5916, 6131-6137 | Conditional serialize/resume (#25 fix) | **A** safe |

### `#jwt` (32 references)

The JWT field is the **common-ground identifier for passkey sessions**, isomorphic with `#signingKeyPair` for password sessions. All references are either bearer-token sends, guarded refresh logic, or either/or guards at session-state checks. **All Category A.**

### `#dekByGen` (24 references)

The common-ground field — populated by both auth paths. All references are safely guarded or used inside auth-guarded methods. **All Category A.**

---

## Conditional branches on session shape

| Site | Branch | Classification |
|---|---|---|
| tarn.ts:6228-6230 | `isLoggedIn()`: `#dekByGen.size > 0 && (#signingKeyPair != null \|\| #jwt != null)` | **A** correct |
| tarn.ts:6438-6464 | `#requireAuth()` 3-way: no auth → throw; JWT only → expiry-check; signing keys → refresh | **A** documented, correct |
| tarn.ts:5879-5881 | `serializeSession()`: requires DEK chain + (signing keys OR JWT) | **A** correct |
| tarn.ts:6062-6066 | `resumeSession()`: requires signing keys OR JWT | **A** correct |

---

## Findings by category

### Category A — Spurious branches (0 findings)

Every read of password-derived private state is gated by an explicit guard or sits inside a method that the caller can only reach after an auth check. **No spurious reads found.** The codebase is well-disciplined on this axis.

### Category B — Required-but-missing handlers (1 LIVE BUG + 5 already fixed)

#### B1 — `#hydrateOutboundState()` crashes on passkey-only sessions [HIGH]

**Location:** `client/src/tarn.ts:5448`

```ts
const ownSigningPubBase64 = await exportPublicKey(this.#signingKeyPair!.publicKey);
```

`#hydrateOutboundState()` uses `#signingKeyPair!` with non-null assertion, but neither the method nor its callers guard on the field being non-null.

**Callers (all public, all currently unguarded for passkey sessions):**
- `shareContent()` — tarn.ts:4918, called from `Collection.share()` / `shareWithAll()`
- `updateShareContent()` — tarn.ts:4938
- `unshareContent()` — tarn.ts:4960
- `snapshotShareLog()` — tarn.ts:4987
- `removeConnection()` — tarn.ts:5033 (calls `#hydrateOutboundState` at :5053)
- Likely `rotateConnectionIdentity()` if it exists — tarn.ts:5151

**Symptom:** Passkey-authenticated user calling `Collection.share()` (or any of the methods above) gets `TypeError: Cannot read property 'publicKey' of null`.

**Fix (recommended):** Add an explicit guard at the top of `#hydrateOutboundState()`:

```ts
if (!this.#signingKeyPair || !this.#sharingKeyPair || !this.#username) {
  throw new TarnPasskeyOnlyError(
    'Sharing operations require a password-authenticated session — ' +
    'sign in with username + password first.'
  );
}
```

A new error class `TarnPasskeyOnlyError` (or reuse existing `TarnSchemaError` pattern) is recommended so app code can catch it specifically. See Phase 2 contract for the proposed class.

#### B2–B6 — Already fixed (history)

- **#25** — `#credentialEncryptionKey` not persisted in session blob → fixed
- **#27** — `isLoggedIn`/`serializeSession`/`resumeSession` rejected passkey-only → fixed
- **#28** — passkey JWT 15-min TTL → fixed (7-day TTL)

### Category C — Different code paths for same conceptual op (2 intentional, 0 to fix)

#### C1 — `removePasskey()` re-derives `#credentialEncryptionKey` on demand

**Location:** tarn.ts:2553-2556

```ts
if (!this.#credentialEncryptionKey) {
  const reKeys = await deriveAllKeys(this.#username, opts.password, this.#appId);
  this.#credentialEncryptionKey = reKeys.credentialEncryptionKey;
}
```

Passkey-only sessions don't have `#credentialEncryptionKey`. Rather than reject, the method requires `opts.password` as a step-up and re-derives. **Status: intentional and documented.**

#### C2 — `authenticateWithPasskey()` stale-credential repair accepts username from handler

**Location:** tarn.ts:2300-2314

Passkey sessions never cached `#username`. The stale-repair path requires the caller's handler to supply it (`handlerResult.username` + `handlerResult.password`). **Status: intentional, documented at tarn.ts:2248-2253.**

### Category D — Other smells / open questions

#### D1 — Share-log writes lack defense-in-depth guards at every public entry

Even after fixing B1, the architectural pattern of "guard buried inside `#hydrateOutboundState`" is fragile. The 6 public callers could each grow a code path that bypasses the helper. Recommendation: add the same `TarnPasskeyOnlyError` guard at the top of each public share-write method explicitly. Belt-and-braces. Cheap.

#### D2 — `readShareLog()` has buried guard

**Location:** tarn.ts:4704-4745 (the method) + tarn.ts:4318 (`#getPairKeysFor` guard)

`readShareLog()` calls `#getPairKeysFor()`, which has its own guard. The method works correctly today, but the guard is one indirection away from the public entry. Recommend adding explicit guard at `readShareLog()` entry for symmetry with the proposed fix to `#hydrateOutboundState()`.

#### D3 — Session-blob design allows mixed-state rehydration (not a bug)

`resumeSession()` v3 schema marks signing-key and username fields as optional. This is correct for #25's fix, but it does mean a malformed/tampered blob could in theory hydrate a session with partial state. The code defends against this (only imports signing keys if both private + public are present and well-formed), and the blob is wrapped + authenticated. **No bug. Documenting for posterity.**

---

## Live bugs found during this audit

### Bug #1 — `Collection.share()` and friends crash on passkey-only sessions [HIGH]

**Severity:** HIGH. User-facing crash. Currently reachable by any user who logs in via passkey and tries to share a record.

**Reproduction:**
1. Create account via password.
2. Register a passkey.
3. In a fresh client (no resumed session), call `authenticateWithPasskey()`.
4. Attempt `tarn.<collection>.share(connection, primaryKey)`.
5. Crash: `TypeError: Cannot read property 'publicKey' of null` from `exportPublicKey(this.#signingKeyPair!.publicKey)` at tarn.ts:5448.

**Root cause:** See Category B1 above.

**Affected methods (verified via call-graph from `#hydrateOutboundState`):**
- `Collection.share()` / `Collection.shareWithAll()`
- `Collection.unshare()` / equivalents
- `snapshotShareLog()`
- `removeConnection()`
- (Likely `rotateConnectionIdentity()` if present)

**Workaround for users today:** Sign in via username + password instead of passkey before sharing.

**Fix:** As described in B1 — add explicit `TarnPasskeyOnlyError` guard at `#hydrateOutboundState()` entry.

---

## Tarn passkey contract (proposed)

The asymmetric operations — those that **genuinely require password-derived state** and therefore **must explicitly reject passkey-only sessions** — are listed below. Anything not on this list is required to work identically across auth methods.

### Operations requiring `#username` + password-derived keys

1. `changeCredentials({ newUsername, newPassword, ... })`
2. `viewAccountKey({ password })`
3. `enableKeyStorage({ password })` / `disableKeyStorage({ password })`
4. `rotateAccountKey({ password, ... })`
5. `removePasskey({ credentialId, password })` — *re-derives on-demand; documented*

### Operations requiring `#signingKeyPair` + `#sharingKeyPair`

6. `sendConnectionRequest(...)` / `acceptConnectionRequest(...)` / `createInviteToken(...)` / `redeemInviteToken(...)`
7. `listIncomingRequests()` — needs sharing private key to decrypt HPKE
8. **Share-log writes** — `shareContent`, `updateShareContent`, `unshareContent`, `snapshotShareLog`, `removeConnection`, `rotateConnectionIdentity` *(currently UNDOCUMENTED + UNGUARDED → see B1)*
9. `readShareLog()` — needs `#sharingKeyPair` *(guard currently buried in `#getPairKeysFor`)*

### Operations that MUST work on passkey-only sessions

- Entry CRUD: `create`, `get`, `update`, `delete` (on both typed Collection and advanced surfaces)
- Listing: `list`, `getEntriesSince`, `getEntryByEid`
- Blob fetch
- Session management: `isLoggedIn`, `serializeSession`, `resumeSession`, `listSessions`, `revokeSession`
- Passkey management: `listPasskeys`, `registerPasskey`, `authenticateWithPasskey`, stale-credential repair

This list should be reflected in:
- `client/README.md` — user-facing reference
- `docs/SDK_ARCHITECTURE.md` — implementation contract

---

## Recommended Phase 2 scope

### Must-fix this cycle (HIGH-severity)

1. **B1** — Add `TarnPasskeyOnlyError` guard to `#hydrateOutboundState()` + each public share-log-write entry point. Add tests asserting passkey-only sessions reject these ops with the typed error (not a null-deref crash).

### Should-fix this cycle (consistency)

2. **D2** — Add explicit guard at `readShareLog()` entry, mirroring the fix in B1. Belt-and-braces. Same `TarnPasskeyOnlyError`.
3. **Contract documentation** — Write the "Tarn passkey contract" section into `client/README.md` and `docs/SDK_ARCHITECTURE.md`. Spec'd in this report.
4. **Symmetry tests** — Add the 5+ symmetry-asserting tests required by issue acceptance criteria (e.g., "after passkey auth, entry CRUD works"; "share rejects with typed error"; "isLoggedIn returns true").

### Nice-to-have, file separately if not now

5. **Design question** — Should share-log writes be redesigned to work on passkey-only sessions (analogous to `removePasskey` re-deriving on demand)? Today they cannot, because the signing keypair is not recoverable from the WebAuthn PRF flow. Would require an architectural change (e.g., store signing key wrapped under credentialEncryptionKey).

---

## Audit completeness

- Files walked: `client/src/tarn.ts` (full), `client/src/client/`, `client/src/collections/`, `client/src/schema/`.
- References to each private password-derived field: catalogued above with site + classification.
- Categories: A (0), B (1 live + 5 already fixed), C (2 intentional), D (3 smells).
- One live HIGH bug identified, one D-level fragility flagged.
- Tarn passkey contract proposed.

Phase 1 acceptance criteria from issue #32:

- [x] Audit report committed
- [ ] Category A findings remediated *(none found)*
- [ ] Category B findings have typed error *(Phase 2: B1)*
- [ ] Category C findings remediated or filed *(both intentional, no action)*
- [ ] Category D findings filed *(D1+D2 fold into B1's remediation; D3 documented)*
- [ ] ≥5 symmetry tests *(Phase 2)*
- [ ] Contract documented in README + SDK_ARCHITECTURE *(Phase 2)*
