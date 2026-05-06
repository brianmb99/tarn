# 04 — Account recovery

Register a Tarn account, capture the 24-word account key, simulate password loss, and recover the account on a fresh client. Demonstrates the full recovery lifecycle.

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

- `phase 1` captures the 24-word account key in memory only and never logs it. A real app would immediately render a recovery kit (PDF, printable HTML, etc.) from that string and surface it to the user — Tarn returns only the string and leaves kit format + delivery to the application.
- `phase 1` writes one note under the original account.
- `phase 2` constructs a brand-new `TarnClient` (simulating a different device with no session state), calls `recoverAccount({ phrase, newUsername, newPassword })`, and reads the same note back. This proves the recovery factor independently unwraps the DEK chain.
- `phase 3` constructs a third fresh client and logs in with the **new password**, demonstrating the credential rotation took effect.

## Note on kit delivery

Tarn returns the 24-word account key as a string (`reg.accountKey`) and nothing else — no PDF, no rendered bytes. Kit format and delivery are entirely the application's responsibility: a downloadable PDF (rendered with the app's PDF library of choice), a printable HTML page, a clipboard copy, or any transport the application itself operates. Tarn does not host an email forwarder for account-key material and the SDK no longer ships an in-bundle PDF renderer, because routing plaintext kit bytes through Tarn-operated infrastructure (or even bundling a renderer that other apps would have to inherit) would weaken the zero-knowledge guarantee that applies to everything else in the protocol.

This example uses the clean `TarnClient.create({ apiBase, appId, schema, storage })` shape — no `underlying` factory needed. (Example 03 still threads `underlying` to reach `listIncomingRequests()`; everything else is on the typed surface.)
