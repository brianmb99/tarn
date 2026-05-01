# 04 — Account recovery

Register a Tarn account, capture the 24-word recovery phrase + rendered PDF, simulate password loss, and recover the account on a fresh client. Demonstrates the full recovery lifecycle without touching the email forwarder.

## Setup

```bash
# In a separate terminal, start a local Tarn API.
cd ../../api
npx wrangler d1 migrations apply tarn-api --local
npx wrangler dev --port 8787
```

```bash
# In this directory:
npm install
```

## Run

```bash
npm start
# or override the API base:
TARN_API=https://api.tarn.dev npm start
```

## What to look for

- `phase 1` writes `recovery-kit.pdf` to the current directory — open it to see what users will receive at registration. The phrase is captured in memory only, never logged.
- `phase 1` writes one note under the original account.
- `phase 2` constructs a brand-new `TarnClient` (simulating a different device with no session state), calls `recoverAccount({ phrase, newEmail, newPassword })`, and reads the same note back. This proves the recovery factor independently unwraps the DEK chain.
- `phase 3` constructs a third fresh client and logs in with the **new password**, demonstrating the credential rotation took effect.

## Note on the email path

This example passes `emailRecoveryKit: false` to skip the Resend-based email forwarder. To enable it in production you must configure two Worker secrets (`EMAIL_FORWARDER_API_KEY`, `EMAIL_FORWARDER_FROM`) — see the main [Tarn CLAUDE.md](../../CLAUDE.md#worker-secrets-issue-12--recovery-email-forwarder). When configured, `emailRecoveryKit: true` (the default) forwards the rendered PDF without persisting it; the `pdfBytes` field is still returned so apps can offer a download as well.

The `underlying` factory is the same transitional pattern as the other examples and goes away in a later SDK step.
