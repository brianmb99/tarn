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
- The recipient calls `tarn.connections.previewInvite(...)` first. That's a non-consuming peek — it returns the inviter's display name and expiry without burning the redemption.
- After the recipient redeems, the sender's polling loop (`tarn.connections.listIncomingRequests()`) auto-accepts the matching request and surfaces the new connection in `tarn.connections.list()`. The sender then runs `tarn.books.shareWithAll(...)` for each book.
- The recipient's `tarn.books.listShared(sender)` returns the decrypted books — proof the per-pair share-log + per-content CEK round-trip works end-to-end.

## Note

Both scripts use `TarnStorage.memory()` — accounts and connections vanish when the processes exit. Re-running creates fresh accounts on each side. All four examples now use the same `TarnClient.create({ apiBase, appId, schema, storage })` shape; this one is just the only one with a two-terminal flow.
