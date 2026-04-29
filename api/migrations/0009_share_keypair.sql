-- Sharing keypair publication (issue #13).
--
-- New accounts (and any account that runs credential change after this rolls
-- out) publish a per-app X25519 share_pub in the credential mapping blob so
-- that other users can bootstrap a connection handshake (sharing design §4 + §9.6).
-- share_discoverable controls whether the public lookup endpoint returns
-- share_pub to non-connections — defaults to TRUE for new accounts; existing
-- connections already have share_pub cached locally and aren't affected by the
-- gate (Section 5 work).
--
-- share_lookup_key is a per-app HKDF derived from the (normalized) email
-- alone. It lets a connection look up share_pub knowing only the recipient's
-- email + app_id (no password). Lookup-by-email leaks "Alice is interested in
-- Bob" at handshake time — accepted residual leak per sharing §11.5.
--
-- All three columns are nullable so accounts created before this migration
-- continue to function. Pre-#13 accounts return share_pub: null until they
-- re-register or run changeCredentials, at which point the SDK populates the
-- new fields.
--
-- share_pub is stored as base64url-encoded 32 raw X25519 bytes (sharing
-- design's `B(...)` encoding) — 43 chars, no padding.
-- share_lookup_key is 64-char lowercase hex (matches the existing
-- credential_lookup_key shape).
-- share_discoverable uses INTEGER (0/1) — D1's SQLite has no native BOOL.
-- Default TRUE matches the design doc's recommendation for social apps.

ALTER TABLE accounts ADD COLUMN share_pub TEXT;
ALTER TABLE accounts ADD COLUMN share_discoverable INTEGER NOT NULL DEFAULT 1;
ALTER TABLE accounts ADD COLUMN share_lookup_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_share_lookup_key
  ON accounts(share_lookup_key)
  WHERE share_lookup_key IS NOT NULL;
