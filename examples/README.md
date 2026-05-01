# Tarn examples

Four progressive examples for the [Tarn client SDK](../client/README.md). Each is a standalone Node.js package that links to the local SDK via `file:../../client`. They run against a local `wrangler dev` instance by default; set `TARN_API` to point elsewhere.

| # | Path | What it demonstrates |
|---|------|----------------------|
| 1 | [`01-hello-world/`](./01-hello-world/) | The smallest possible Tarn app — register, create one record, list it. ~30 lines. |
| 2 | [`02-crud/`](./02-crud/) | Full CRUD on two collections (`books` + `settings`). Shows partial-merge updates, schema validation, multiple collections in one schema. |
| 3 | [`03-sharing/`](./03-sharing/) | Two clients form a connection via the invite-token flow, sender shares its library with all connections, recipient lists shared records. |
| 4 | [`04-recovery/`](./04-recovery/) | Register, capture the recovery phrase, simulate password loss, recover the account on a fresh client. |

## Setup (once)

1. Start a local Tarn API:

   ```bash
   cd ../api
   npx wrangler d1 migrations apply tarn-api --local
   npx wrangler dev --port 8787
   ```

   Examples target `http://localhost:8787` by default. Override with `TARN_API` if needed.

2. Each example is its own npm package — install per example:

   ```bash
   cd 01-hello-world
   npm install
   npm start
   ```

   The `tarn-client` dependency uses `file:../../client`, so npm symlinks the local SDK source. There is no published-to-npm step.

## Note on example 03 (sharing)

The sharing example uses an `_LegacyTarnClient` import — that's a transitional escape hatch for one specific gap: the typed `tarn.connections.*` namespace doesn't yet expose a method that triggers the inbox poll where redeemed-invite auto-accepts happen. The example holds a reference to the protocol-layer client and calls `listIncomingRequests()` on it directly. Examples 01, 02, and 04 don't need this — they use the clean `TarnClient.create({ apiBase, appId, schema, storage })` shape with no `underlying` factory.

When the typed namespace gets the missing method, example 03 collapses to the same shape as the others and the `_LegacyTarnClient` export goes away.

## App registration

Examples assume the `bookish` app is already registered in your local D1 (it is by default in the workspace's local wrangler dev setup, since Bookish is the reference app). If you want to run examples against a different app, follow the [App registration](../client/README.md#app-registration) section of the SDK README.
