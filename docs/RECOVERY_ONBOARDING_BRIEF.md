# Design brief: onboarding casual users into a "you hold the keys" account model

> **Status:** open design problem. This brief is intended to be read by people (or AIs) with no prior context on Tarn or Bookish. It frames a specific UX/paradigm problem and invites broad thinking. Last updated 2026-05-06.

## What we're building

We operate two products in concert:

**Tarn** is infrastructure: a zero-knowledge encrypted data backend that stores user data on Arweave (a permanent, immutable storage network). All encryption happens client-side. Tarn's servers never see plaintext data, never see user credentials, and have no ability to reset accounts or recover data on a user's behalf. Tarn is app-agnostic — it provides primitives that any application can build on.

**Bookish** is the first consumer application built on Tarn. It's a reading list / personal library app. Its brand promise is permanence: a library you build over years that no platform shutdown, account ban, or vendor pivot can take from you. Bookish is positioned as a normal consumer app, not a security tool.

## The account model

Every Tarn account has two access factors:

1. **Username + password** — the everyday login. Derives a key chain that decrypts the user's data.
2. **Recovery phrase** — a 24-word BIP39 mnemonic, generated client-side at signup, that independently derives a parallel key chain. The phrase is the lifeline: if the user loses their password, the phrase lets them authenticate to the server, decrypt their data, and set new credentials. The phrase is meant to be saved offline (printed, password manager, written down).

Critically, **there is no third recovery channel**. No "click here to reset via email." No "answer security questions." No customer-support backdoor. If a user loses both the password and the phrase, the account and all its data are mathematically unrecoverable — even by us. This is a property of the architecture, not a policy choice. The underlying keys exist only on the user's devices and (derived form) in the user's head/safe/password-manager.

## Why this is the right architecture

Tarn's value proposition is genuine user ownership of data. If we held a recovery email or a customer-support reset, we'd be a normal SaaS that *says* it's user-owned but really owns the keys itself. The whole model only holds if there's no path back through us.

This is the same architecture used by:
- Cryptocurrency wallets (MetaMask, Phantom, etc.) — "save your seed phrase or lose everything"
- Password managers (1Password, Bitwarden) — emergency kits, master passwords
- Signal — PIN + phone-based recovery (a closer-to-mainstream variant, but still narrower than email reset)

What's distinctive about our situation is **applying this model to a casual consumer-app context**. Crypto wallets and password managers work because users self-selected for caring about security before they showed up. Reading-list users did not. They showed up wanting an app for reading lists.

## The problem

Twenty years of consumer software has trained users into a single recovery pattern: *forgot password → email reset link → back in*. This is so deeply internalized that most users don't think of it as a feature — it's just "how login works." When a user signs up for a Tarn-based app, they apply this prior automatically. They believe, without thinking about it, that if they forget their password they'll be able to recover.

When we present a 24-word recovery phrase at signup with instructions to save it, the user's reaction is predictable:
- They mentally classify it as a security warning, like cookie banners or terms-of-service.
- They click through without saving it.
- Or they "save" it casually (screenshot to camera roll, copy-paste into Notes), satisfying the prompt without actually achieving the goal.
- They proceed to use the app, and the warning fades from memory within days.

Months or years later, they hit a credential issue — forgot the password, switched devices, password manager corruption, anything. They click "forgot password," expecting the standard reset. Instead they see "enter your 24-word recovery phrase." They have no recovery phrase. Their library — months or years of accumulated data — is permanently inaccessible. Even we can't help them.

This is brutal, and the user we lose this way is exactly the user the product is for: someone who built up a library because they came to value it, and now loses the thing they came to value.

## Two distinct user populations

We've come to think of our target user space as splitting cleanly into two:

**Population A: "Security-aware" users.** Use a password manager. Understand recovery codes, 2FA backup codes, seed phrases. When prompted to save a recovery phrase, they put it in their password manager without complaint. They rarely "lose" passwords because their passwords live somewhere durable. The Tarn model works for them out of the box. But this is a small slice of consumers — maybe 10-20% in optimistic estimates.

**Population B: "Standard consumer" users.** Don't use a password manager. Reuse passwords across sites. "Forgot password" is a regular part of their workflow. The phrase prompt at signup will not be saved meaningfully. They are the user the casual reading-list app is *trying to serve* (it's a casual reading-list app, not a security tool), and they are the user who will most often need recovery and most often not have the phrase.

The architectural model and Population B are incompatible by default. No clever onboarding flow makes a non-password-manager user reliably save a 24-word phrase, because that's not who they are. They optimize for "deal with it later if it happens." They've been trained to expect that "later" is fine because reset-by-email exists. Removing reset-by-email, even for excellent reasons, doesn't update their priors.

## What we're trying to figure out

We have several non-trivial paths forward, and we want to find the right one — or invent something better.

**Path 1: Accept Population A as the addressable market.** Lean into the privacy/permanence positioning. Aim onboarding at the user who already gets it. Accept that we are a smaller-market product, like password managers themselves. Honest, principled, leaves money on the table.

**Path 2: Build aggressive UX scaffolding for Population B.** Forced multi-modality save at signup (must download AND paste-back AND mark in password manager). Persistent unconfirmed-phrase banners until verified. Engagement-milestone re-prompts ("you've added 50 books — let's verify your phrase"). Renaming the phrase from "recovery phrase" (implies optional fallback) to something like "vault key" or "account key" (implies primary credential). All of these are real and worth doing, but they feel like *trying harder at the same thing* — louder warnings, more friction. We don't believe at-scale this gets Population B to meaningfully high save-rates. It's incremental, not paradigm-changing.

**Path 3: Soften the architectural model.** Add server-side storage of the recovery phrase (encrypted under a key derived from the user's password) so that a logged-in user can retrieve their phrase later. This works mechanically. It also degrades the security model: the phrase is no longer the password-independent lifeline — it's a credential-recoverable item like everything else, and a password compromise effectively yields the phrase. We've explored this at depth and believe it's a real cost, not a free win. It also still doesn't help the user who lost the password — they can't retrieve the phrase via the password they lost.

**Path 4 (what we're looking for): a paradigm-changing move that we haven't thought of yet.**

The reference point we keep returning to is PayPal's tiny-deposits idea for linking a bank account. Before PayPal, "give a website your bank credentials" was either impossible or terrifying. PayPal's insight — send two micro-deposits, ask the user to confirm the amounts — sidestepped the whole problem in a way that felt elegant rather than secure-by-friction. It didn't make linking a bank account "less scary by adding warnings." It changed the shape of what the user was being asked to do.

We're looking for the equivalent insight for "you and only you hold the keys to your account." Some way to either:

- Reframe what we're asking the user to do, so it doesn't feel like the thing they've trained themselves to skip, or
- Distribute the recovery responsibility across mechanisms that fit how users *actually* behave, rather than how we wish they behaved, or
- Tie the recovery affordance to something the user is going to do anyway as part of using the product, so that "saving the phrase" isn't a separate adversarial step.

Or something else we haven't seen yet.

## Constraints we want to respect

- **Zero-knowledge stays.** Tarn must not see plaintext data, plaintext phrase, or user passwords. Any mechanism that requires Tarn to see one of these is a non-starter.
- **No platform-controlled recovery channel.** No "email us at support to recover" — that's a single point of social-engineering failure and undermines the user-ownership claim.
- **Email-based reset is out.** Same reason: it would mean the email provider effectively owns the account, which is what most consumer SaaS already does and what we're explicitly not building.
- **Tarn stays app-agnostic.** Tarn's role is primitives. Any UX innovation has to be either expressible at the app layer (Bookish), or generalizable into a primitive that other apps can use without Bookish-specific assumptions baked in.
- **The eventual "recovery" must really work.** Whatever the mechanism is, when the user actually needs it (months or years later, in a stressed moment), it should reliably get them back into their account. Mechanisms that work for engaged users but fail for the user who's been away from the app for two years are not solving the right problem.
- **Don't just copy crypto wallets.** The crypto-wallet pattern (seed phrase, "your keys, your coins") works for self-selected users. We've already established it doesn't generalize to casual consumers without modification.
- **Don't compromise the security model for UX.** We're willing to accept some user-loss-rate as the cost of doing this principled-ly. We're not willing to add "but actually we have a backdoor" because that defeats the architecture's purpose.

## What "success" looks like

We'd consider a solution successful if it:

- Makes the *typical* (not security-aware) consumer user end up in a recoverable state within their first few sessions, without requiring them to act adversarially against their own habits.
- Doesn't depend on the user having a password manager, technical sophistication, or a pre-existing security mindset.
- Survives long absences (a user comes back after a year and can still recover) without the user having had to do something specific to maintain recoverability.
- Preserves the architectural property that nobody but the user can access their account.
- Feels, in the user's experience, like a small natural step rather than a security warning.

The PayPal frame: it should not feel like "they made the scary thing less scary." It should feel like "oh, that's clever, that's how this should always have worked."

## Adjacent ideas we've considered

Listed here so you can see what's already been on the table — not to rule them out, but as starting context. Push back on any of these if you think we've underrated them.

- **Social recovery (Shamir secret sharing among trusted contacts).** Real defense, very high UX cost, high cognitive load on the user to designate contacts and ensure they understand their role. Used by Vitalik's smart-contract wallets and a few crypto experiments; hasn't broken into consumer software for a reason.
- **Hardware-token based recovery (passkeys, FIDO2).** Strong cryptographically. Coverage problem (many users don't have a durable hardware token), durability problem (lose the token, lose the recovery), and onboarding friction.
- **Time-delayed reveal with cancel window.** Cool defensive primitive, wrong default UX for a reading-list product.
- **Layered server-side encryption with per-app keys.** Useful for defense-in-depth against backend leaks, doesn't address the core onboarding problem.
- **Step-up auth gates / out-of-band challenges.** Reduce attack surface during retrieval, don't address whether the user has the thing to retrieve in the first place.
- **Better signup-time confirmation flows (type-back, forced download, etc.).** Worth doing, but feel incremental. They make the existing prompt sharper; they don't change what the user is being asked to do.

## What we'd find genuinely valuable

All thinking welcome. We want to broaden and sharpen our options before committing to a direction. Useful contributions could include any of:

- **Genuinely new ideas** we haven't considered — particularly ones that reframe what we're asking of the user, use side effects of normal product use to establish recovery, borrow from non-software domains (banking, physical security, mail, identity, social structures), or take advantage of infrastructure users already have (their phone's secure enclave, their existing accounts elsewhere, their social graph, their physical possessions) without recreating the email-reset problem.
- **Sharper or hybrid versions of ideas already in the brief** — including the "adjacent ideas we've considered" list. If you think we've dismissed something too quickly, or if there's a combination that's stronger than any single piece, that's valuable.
- **Portfolio thinking** — the answer may not be a single mechanism. A set of small interventions that collectively cover enough of the user space to make the residual loss rate acceptable could be the right shape.
- **Honest pushback on our framing.** If you think one of the four paths above is actually right and we're underrating it, make the case. If you think the two-population split is wrong, or the constraints are too rigid, or the success criteria are off, say so. We'd rather get our framing corrected than get clever ideas built on the wrong frame.
- **Pointers to prior art.** If something similar to this problem has been solved in another domain — even imperfectly — we want to know about it.

The goal is to come away from this with either a clear direction we hadn't seen, or a sharper understanding of why one of the directions we already see is right.
