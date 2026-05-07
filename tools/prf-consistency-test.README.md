# PRF consistency test

A standalone HTML page that validates a load-bearing assumption in the Tarn passkey design (Phase 6.1): **an OS-synced passkey produces the same PRF output on every device that shares the credential.**

## Why this matters

When a user changes their password (`tarn.changeCredentials`), the SDK re-wraps the new DEK gen under their passkey's PRF output. If that PRF output is the same across all the user's synced devices (iCloud Keychain on Apple, Google Password Manager on Android/Chrome), the re-wrap propagates automatically — the user only has to tap once on the device they're changing the password from, and all their other synced devices can decrypt new data.

If the assumption fails — same credential, different PRF output across devices — multi-device users would have to re-register their passkey on each device after every password change. The current Phase 6.1 design assumes this isn't the case. This test verifies it on real hardware.

## When to run it

Before relying on the assumption in user-facing UX copy or shipping passkey support broadly. Specifically:

- After deploying Tarn-side passkey work to production.
- Before Bookish surfaces passkeys to end users.
- Whenever a major OS or browser update changes WebAuthn behavior.

Not a blocker for the Tarn deploy itself — just for confidently building UX on top.

## How to host

WebAuthn requires HTTPS or `localhost`. Easiest options:

**Option A: Cloudflare tunnel (zero hosting setup).**
```
cd tools
python -m http.server 8000
# in another terminal:
cloudflared tunnel --url http://localhost:8000
```
Temporary HTTPS URL like `https://<random>.trycloudflare.com`. Open on each device.

**Option B: GitHub Pages.** Drop `prf-consistency-test.html` into a public repo, enable Pages in repo settings. Get a `<user>.github.io/<repo>` URL.

**Option C: Cloudflare Pages.** Drop the file into a Cloudflare Pages project. Get a `*.pages.dev` URL.

The test page is fully static — no backend, no API calls.

## How to run

For each device pair under test (e.g., Mac↔iPhone, Windows↔Android):

1. **Device A:** open the URL, click **Register passkey**, approve the platform-authenticator prompt (Touch ID / Face ID / Windows Hello). Note the printed credential ID.
2. Wait ~1 minute for OS sync to propagate the credential to Device B.
3. **Device A:** click **Authenticate (PRF)**. Note the credential ID and PRF hex output.
4. **Device B (same OS account):** open the same URL, click **Authenticate (PRF)**. The synced passkey should be offered — pick it. Note the credential ID and PRF hex.
5. Compare the two outputs.

## How to interpret results

| Device A credId | Device B credId | Device A PRF hex | Device B PRF hex | Meaning |
|---|---|---|---|---|
| Same | Same | Same | Same | ✅ Assumption holds. Phase 6.1 design works as intended. |
| Same | Same | Same | Different | ❌ Assumption fails. Synced credential, but PRF varies. Need to revisit Phase 6.1 — multi-device users will hit the stale-passkey refresh path more often than expected. |
| Same | Different | — | — | The wrong passkey was selected on Device B. Retry, picking the synced credential. |
| (Other) | | | | The credential didn't sync to Device B at all. Wait longer, check OS sync settings. |

## Device pairs to test (recommended)

- **Apple ecosystem:** Mac ↔ iPhone (or iPad), both signed into the same Apple ID with iCloud Keychain enabled.
- **Google ecosystem:** Windows + Chrome ↔ Android phone, both with Google Password Manager and the same Google account.
- **Edge cases worth checking** (lower priority): cross-ecosystem (Apple ↔ Google), security keys (each USB key is a separate credential — different PRF outputs are *expected*, not a failure).

## Recording results

When you run the tests, record the outcome somewhere persistent (a comment in `RECOVERY_PLAN.md` follow-ups section, a Tarn GitHub issue, etc.) so future Tarn work can rely on or revise the assumption with confidence.
