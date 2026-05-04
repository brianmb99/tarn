-- One-shot wipe for the single-envelope cleanup migration (2026-05-04).
--
-- Purpose: clear every per-user row in D1 so the only existing account
-- (brian's) can re-register cleanly under the new protocol. The legacy
-- v1/v2/v3 envelope shapes and the PBKDF2 KDF were dropped from the SDK;
-- previously-registered accounts can no longer log in (their wrapped_data_key
-- is no longer parseable). This is intentional — back-compat was cut while
-- there was still only one user.
--
-- What stays:
--   apps                — registered apps + their public keys
--   cache_meta          — blob-cache bookkeeping (no user data)
--
-- What gets wiped (all per-user state):
--   accounts            — the credential-mapping rows
--   sessions            — server-side session ids
--   share_log           — per-pair sharing logs
--   share_inbox         — HPKE-sealed connection-request blobs
--   invites             — outstanding invite tokens
--   write_rate_limits   — per-account rate counters
--   idempotency_keys    — per-account idempotency cache
--   auth_nonces         — in-flight challenge nonces
--   entries             — cached content-blob rows (no account → orphaned anyway)
--   pending_txs         — in-flight Arweave uploads (no owner → orphaned anyway)
--
-- Run locally:
--   cd api && npx wrangler d1 execute tarn-api --local --file=scripts/wipe-accounts.sql
--
-- Run against production (after confirming you really mean it):
--   cd api && npx wrangler d1 execute tarn-api --remote --file=scripts/wipe-accounts.sql
--
-- After running: re-register from a fresh client via tarn.register(...). Your
-- old data on Arweave is still there but unreachable without the credential
-- row (the API has no way to find your data_lookup_key from your email).

DELETE FROM sessions;
DELETE FROM share_log;
DELETE FROM share_inbox;
DELETE FROM invites;
DELETE FROM write_rate_limits;
DELETE FROM idempotency_keys;
DELETE FROM auth_nonces;
DELETE FROM entries;
DELETE FROM pending_txs;
DELETE FROM accounts;
