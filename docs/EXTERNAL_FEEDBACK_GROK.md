# External feedback: Grok response to recovery briefs

> **Source:** Grok, 2026-05-06. Response to [RECOVERY_ONBOARDING_BRIEF.md](RECOVERY_ONBOARDING_BRIEF.md) and [PHRASE_RETRIEVAL_BRIEF.md](PHRASE_RETRIEVAL_BRIEF.md). Saved verbatim (with garbled markdown link artifacts cleaned up). Not endorsed — captured for reference and consideration.

---

# Design brief: Updated recovery paradigm for Tarn/Bookish (post-signup retrieval + paradigm shift)

> **Status:** Proposed direction. Companion / evolution of [RECOVERY_ONBOARDING_BRIEF.md](RECOVERY_ONBOARDING_BRIEF.md) and [PHRASE_RETRIEVAL_BRIEF.md](PHRASE_RETRIEVAL_BRIEF.md). Last updated 2026-05-06.

## Summary of user priority (new clarifying requirement)

The absolute must-have is simple and non-negotiable:

- A logged-in user must be able to retrieve their recovery phrase (or whatever we ultimately call it) **later**, once they are more engaged with the product.
- Tarn must **never** see the plaintext phrase (or the DEK that protects it).

This requirement sits on top of the broader onboarding and zero-knowledge constraints in the two existing briefs. It rules out any solution where the phrase is permanently lost after signup, and it rules out any retrieval mechanism that would require Tarn to see plaintext.

## Does this change the full recommendation?

**No — it strengthens and clarifies it.**

The simpler DEK-wrapped storage approach (phrase ciphertext stored on Tarn, encrypted client-side under the stable Data Encryption Key) already satisfies the must-have perfectly:
- Logged-in user → fetches ciphertext → client decrypts with DEK → shows phrase.
- Tarn only ever stores and returns ciphertext; it never sees plaintext or DEK.
- Zero-knowledge boundary is preserved.
- It directly solves the exact casual-user scenario described in PHRASE_RETRIEVAL_BRIEF.md: signup three months ago → become engaged → "Settings → Show my recovery phrase."

The outer app-key re-wrap layer discussed in the retrieval brief adds no meaningful protection against credential compromise and introduces unnecessary complexity. We should drop it.

This tactical retrieval primitive is now a **required building block** in any final design. It can coexist with — and is even more powerful inside — the broader paradigm shift I originally proposed.

## Recommended direction (updated Path 4)

**Hybrid model: Passkeys as the everyday primary credential + recovery phrase as demoted catastrophic backup + optional social recovery as the scalable safety net for Population B.**

This direction fully satisfies the new must-have while addressing the core tension in RECOVERY_ONBOARDING_BRIEF.md: making the "you hold the keys" model work for casual consumers without relying on them behaving like security-aware users at signup.

### Core flows

1. **Signup (feels like a normal modern consumer app)**
   - User creates username (or uses email purely as identifier — no reset power).
   - Immediately prompted to create a **passkey** ("Sign in with Face ID / Touch ID / Windows Hello — your library stays yours forever").
   - Passkey private key lives in the device's secure enclave and is synced via the OS (iCloud Keychain or Google Password Manager — both E2EE).
   - Client still generates the 24-word BIP39 recovery phrase at signup.
   - Phrase is **presented gently**, not as a scary one-time warning: "For full control across any device or if you ever lose all your synced devices, here's your permanent master key. Save it now or retrieve it anytime later in Settings."
   - User can skip saving it at signup with zero friction — the system no longer depends on them doing so.

2. **Post-signup recovery phrase retrieval (the must-have, now implemented)**
   - In Settings → "Account & Recovery" there is always a "Show my recovery phrase" option for any logged-in session.
   - Implementation: Tarn stores the phrase as ciphertext encrypted under the stable DEK (exactly the simpler version from PHRASE_RETRIEVAL_BRIEF.md).
   - Client fetches ciphertext → decrypts locally with DEK → displays phrase.
   - Tarn never sees plaintext. Zero-knowledge is intact.
   - Optional one-time verification (type a few words back) the first time they retrieve it, to reinforce importance without being punitive.
   - This can be surfaced at engagement milestones ("Your library now has 30 books — want to make sure you can keep it forever?") or on demand.

3. **Everyday login & multi-device use**
   - Primary path: biometric passkey (no password to forget for most users).
   - Password + username remains available as a fallback for power users or cross-platform edge cases.
   - Passkey sync handles device switches, new phones, etc., for the vast majority of Population B.

4. **Social recovery (optional, progressive, first-class Tarn primitive)**
   - After user has built value (e.g., added 10+ books), gentle prompt: "Want to protect your library like a family heirloom? Add 3–5 trusted friends/family as guardians."
   - Client-side Shamir secret sharing (or threshold scheme) of the recovery key (or DEK).
   - Shares distributed to guardians (encrypted to their public keys or simple one-time codes).
   - Recovery: user initiates → guardians approve via simple in-app or out-of-band request → quorum reconstructs access client-side with time-delay cancel window.
   - Tarn primitive only — fully app-agnostic and zero-knowledge.

5. **Permanent library export (value-tied safety net)**
   - One-click "Download forever backup" that bundles encrypted data + recovery phrase + restore instructions.
   - Users understand "back up my books" far better than abstract security phrases.

### Why this satisfies all constraints and success criteria

- **Tarn never sees plaintext phrase** — satisfied by DEK-wrapped storage + all crypto happening client-side.
- **Logged-in users can retrieve phrase later when engaged** — satisfied by the retrieval primitive.
- **Population B friendly** — passkeys + OS sync handle most real-world loss scenarios without any user action at signup. Social recovery and retrieval handle the rest via natural behaviors.
- **Zero-knowledge & no platform-controlled recovery** — preserved.
- **App-agnostic Tarn primitives** — passkey support, DEK-wrapped phrase storage/retrieval, Shamir/threshold sharing APIs, export bundles.
- **Survives long absences** — OS sync is passive; guardians don't expire; phrase retrieval is always available when logged in; export is tangible.
- **Feels natural** — "Sign in with Face ID" is already how users expect apps to work in 2026. Retrieval and guardians feel like sensible product features, not adversarial security warnings.

### Tradeoffs (accepted)

- Slight increase in primitive complexity (passkeys + retrieval endpoint + optional social recovery).
- Passkeys have excellent but not 100% coverage — mitigated by password fallback and phrase retrieval/export.
- Social recovery introduces mild social dependency — mitigated by quorum, time-delay, and phrase as ultimate backup.

### Next steps if we adopt this direction

1. Implement the simpler DEK-wrapped phrase storage + retrieval endpoint in Tarn (drop outer app-key layer).
2. Add passkey support as first-class credential option.
3. Ship social recovery primitives.
4. Update Bookish onboarding and Settings flows accordingly.
5. Test with real users on the retrieval experience and guardian setup.

This is not "more warnings" or "more friction." It's a reframing that makes recoverability an emergent property of normal product use while keeping the architectural promise intact.

The two existing briefs remain correct in their diagnosis. This proposal simply supplies the missing paradigm-level move they were asking for, with the user's clarified must-have now explicitly designed in from the start.

— Grok (updated 2026-05-06)
