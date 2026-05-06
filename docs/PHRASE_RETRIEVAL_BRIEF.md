# Design brief: post-signup recovery-phrase retrieval

> **Status:** open design discussion. Captures a specific proposal, the pushback on it, and the alternatives that surfaced in conversation. Companion to [RECOVERY_ONBOARDING_BRIEF.md](RECOVERY_ONBOARDING_BRIEF.md), which addresses the broader paradigm question this proposal is one possible response to. Last updated 2026-05-06.

## What this doc captures

A specific question that came up in design discussion: should Tarn provide a way for an already-logged-in user to retrieve their recovery phrase after the signup session has ended? It also captures one specific implementation proposal and the technical pushback on that proposal.

This is a narrower question than the broader onboarding paradigm brief. It assumes the broader paradigm question is unresolved and addresses a specific tactic that may or may not end up being part of the answer.

## Background: the recovery phrase today

(See [TARN_PROTOCOL.md](TARN_PROTOCOL.md) for full detail.)

At account registration, the Tarn client generates a 24-word BIP39 recovery phrase. The phrase is the user's permanent vault key — it independently derives a key chain that can decrypt the user's data and authenticate to the API for credential rotation when the password is lost. The phrase is meant to be stored offline by the user (printed, password manager, written down).

**Crucially: the phrase is only in memory during the signup session.** It's returned by `register()` to the application, presented to the user, and then discarded. After that session, neither Tarn nor the SDK retains it. The only copies that exist are wherever the user chose to put it.

If the user closes their browser without saving the phrase — and most casual users will, no matter how the prompt is worded — there is no way to retrieve it later. They can continue using the app indefinitely on their password alone. But the moment they hit any credential issue (forgotten password, switched device, password manager corruption), they discover they have no fallback. Their account, and all data in it, is permanently inaccessible.

## The issue

The phrase being session-only at signup is the right model for the *security-aware user* who saves it on the spot. It is the wrong model for the *casual user who didn't think to save it at signup but later wants to*.

Concretely, we want a user to be able to do this:

1. Sign up casually three months ago.
2. Become engaged with the product over time.
3. Realize they should probably make sure they can recover this account.
4. Open Settings → "Show my recovery phrase."
5. See the phrase, save it properly this time.

Today, step 4 is impossible. The phrase no longer exists anywhere except wherever (if anywhere) they saved it at signup. If they didn't save it, it is mathematically gone.

This isn't a Tarn bug — it's a direct consequence of the architecture. But the user reaction is "the app failed me," not "I failed to save my phrase three months ago."

## Proposed solution

Store the recovery phrase, encrypted client-side, on Tarn's servers, so that a logged-in user can retrieve it later from any authenticated session.

The specific variation that prompted this brief: **wrap the phrase first under a user-derived key (the data encryption key, DEK, which is stable across credential rotations), then re-wrap that ciphertext under a Tarn-held app-specific key before persistence.** The app-specific key would live in Cloudflare Worker secrets (separate trust domain from the D1 database).

Properties this is meant to give us:

- The phrase ciphertext, at rest, requires both user credentials (to derive DEK) and Tarn cooperation (to peel the outer app-key layer) to recover.
- The phrase doesn't need to rotate when the user rotates credentials, because the inner wrap is anchored to the DEK, which is itself stable across credential rotations.
- A pure database breach (D1 read) doesn't leak the phrase, because the outer key is in Worker secrets.
- A pure Tarn-runtime breach doesn't leak the phrase, because the inner wrap is under DEK, which Tarn never sees.
- Compromise requires both: user credentials AND Tarn-side cooperation.

The intuition: this re-encryption doesn't violate Tarn's zero-knowledge boundary because Tarn is only re-encrypting already-encrypted data; Tarn never sees the phrase plaintext. And the recovery phrase is a fundamentally different kind of data from user content — it doesn't need permanence guarantees, it just needs to be retrievable for a logged-in user.

## The pushback

The outer encryption layer does not deliver the property it appears to deliver against the threat we actually care about (credential compromise).

**Walk the credential-compromise scenario:**

1. Attacker phishes the user's password.
2. Attacker authenticates to Tarn normally — they have valid credentials, the auth flow gives them a session.
3. Attacker calls the phrase-fetch endpoint. Tarn sees a valid session and dutifully decrypts the outer (app-key) layer, returning the inner ciphertext.
4. Attacker derives the DEK from the phished password (via the existing key chain).
5. Attacker decrypts the inner ciphertext.
6. Attacker has the phrase.

The outer layer adds nothing to this scenario, because **Tarn is the entity that peels the outer layer, and Tarn peels it for any authenticated request.** The attacker doesn't need to compromise Tarn's app key — they just need Tarn to do its normal job for an authenticated session. The session is what authorizes the peel; the attacker has a session.

**On the Tarn-compromise-only scenario:** the claim was "if Tarn is compromised it still doesn't leak the phrase without also compromising user creds." This is true — but it's *already true* of the simpler version that doesn't have the outer layer. Without the outer layer, a Tarn breach yields the inner ciphertext, which is DEK-wrapped; the attacker still needs DEK to decrypt; DEK requires user credentials, which Tarn never has. The DEK is the binding constraint either way. The outer layer is redundant against this threat.

**What the outer layer does protect against:** a narrow operational scenario where an attacker reads the D1 database (e.g., SQL injection, leaked backup) but does not have access to Worker secrets. Real, but already mostly handled by the inner DEK-wrap (database leak yields ciphertext under a 256-bit random DEK that the attacker doesn't have; brute force is infeasible). So the outer layer is defense-in-depth against a backup-leak scenario, not net-new defense against credential compromise.

**Costs of the outer layer:**

- Per-app key lifecycle: generation, rotation, backup, secure storage in Worker secrets.
- Key rotation requires mass re-wrap of every user's phrase ciphertext for that app.
- The app key becomes a critical dependency: lose it (Cloudflare incident, accidental deletion, wrong env in production) and every user of that app loses phrase retrieval permanently.
- Adds encryption/decryption to the API hot path for every phrase-fetch.
- Brings per-app encryption logic back into Tarn's runtime, which is exactly the boundary we've been working to keep clean.

**The fundamental observation that came out of this:** encryption alone never closes the credential-compromise gap. If the decryption depends only on something a session can produce, an authenticated attacker is by definition that session. To make compromise meaningfully harder, the retrieval step must require something *beyond a valid session*. That "something" is what each alternative below provides differently — and it lives at the authorization layer, not the encryption layer.

## Alternatives explored

The deeper question — "if we want to defend phrase retrieval against credential compromise, what mechanisms are available?" — surfaces a menu of options. They mostly live in the authorization layer rather than the encryption layer. Brief summary; depth available in conversation history.

1. **Tarn-side outer encryption (the proposal above).** D1-only breach defense. Doesn't address credential compromise.
2. **2-of-2 client/Tarn key split.** Cleaner cryptographic version of #1 — phrase requires both client and Tarn to cooperate, mathematically not just by policy. Same gap on credential compromise.
3. **Step-up auth on the phrase-fetch endpoint.** Fetch requires fresh password re-derivation; JWT alone is insufficient. Cheap, removes the "ride a session, silently grab the phrase" attack class. Doesn't defend against an attacker who has the password.
4. **Out-of-band challenge gate (app-mediated).** Fetch requires the app (Bookish) to attest "user just proved possession of an out-of-band channel" — typically email or SMS code. Real defense against pure credential compromise; user needs to control two channels.
5. **Time-delayed reveal with cancel window.** Phrase reveal scheduled 24h ahead, with notification and cancel link. Maximum compromise containment, very poor UX for a casual product.
6. **Passkey / WebAuthn second factor.** Strongest cryptographic defense; coverage and durability problems for a casual user base.

The shape of the recommendation that came out of the discussion: ship step-up auth (#3) as the always-on baseline, make OOB challenge (#4) the default for apps like Bookish. Skip the outer-encryption ideas (#1, #2) — they defend a different threat than the one we care about and the cost-to-benefit is poor.

## Where we landed

We agreed:

- The simpler version of the proposal — store the phrase ciphertext encrypted under the DEK, no outer layer — is mechanically sound and would solve the casual-user-engaged-later case.
- That version still has a real cost: it shifts the security model from "phrase is the password-independent lifeline" to "phrase is a credential-recoverable item." Credential compromise becomes phrase compromise (modulo whatever authorization gate sits in front of fetch). This is a real semantic change in what the phrase means, not just an implementation detail.
- The outer-encryption variation does not fix this. The credential-compromise gap is structural to "retrievable via credentials" and cannot be closed by additional encryption layers, only by additional authorization gates.
- The right place to add resistance is at the authorization layer (step-up auth, OOB challenge), not at the encryption layer.
- This whole discussion is downstream of the broader paradigm question (see [RECOVERY_ONBOARDING_BRIEF.md](RECOVERY_ONBOARDING_BRIEF.md)). If we find a paradigm-level solution to the onboarding problem, the post-signup retrieval question may no longer matter — most users would have saved the phrase properly at signup.

## Open

- Whether to ship the simpler DEK-wrap variant at all, given the security-model shift it implies. Defer until the onboarding brief produces a direction.
- If we do ship it: confirm the authorization-side gates (step-up at minimum, OOB as recommended-default for consumer apps).
- Whether the outer-encryption idea has a different home — e.g., as a future hardening pass against backend leak scenarios independent of phrase storage.
