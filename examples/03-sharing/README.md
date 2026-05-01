# 03 — Connections and sharing

Two clients form a connection via the invite-token flow, the sender shares its library, the recipient lists what was shared. Demonstrates the full sharing surface end-to-end without requiring discoverable email addresses.

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

This example needs **two terminals**.

Terminal A — sender:
```bash
node sender.js
```

The sender registers, creates three books, prints an invite URL, and starts polling. Copy the URL line from its output.

Terminal B — recipient (using the URL from terminal A):
```bash
TARN_INVITE_URL='<url from sender>' node recipient.js
```

The recipient registers a separate account, redeems the invite, then waits for the sender's auto-accept + share-with-all to land.

## What to look for

- The sender prints an invite URL like `tarn:invite/<token_id>#<payload_key>`. The fragment after `#` is the AES-GCM payload key — it never leaves the recipient's device.
- After the recipient redeems, the sender's polling loop finds a new connection and runs `tarn.books.shareWithAll(...)` for each book.
- The recipient's `tarn.books.listShared(sender)` returns the decrypted books — proof the per-pair share-log + per-content CEK round-trip works end-to-end.
- The auto-acceptance is handled by the underlying client's `listIncomingRequests()` poll. The new typed `connections` namespace doesn't yet expose this method directly, so both scripts hold a reference to the underlying client and call it from there. This goes away in a later SDK step.

## Note

Both scripts use `TarnStorage.memory()` — accounts and connections vanish when the processes exit. Re-running creates fresh accounts on each side. The transitional `underlying` factory pattern is the same as in the other examples.
