-- 0014_invites.sql
--
-- Invite tokens (Section 8, issue #22).
--
-- Background: Sections 5a–5d let two users connect when the sender knows the
-- recipient's email AND the recipient is share_discoverable. Section 8 adds a
-- complementary primitive — opaque, single-use, time-limited tokens — for the
-- "scan this QR / send this link / sign-up-and-click" flows where neither
-- precondition holds. The inviter generates `token_id` (256-bit URL-safe
-- random) + `payload_key` (AES-256-GCM key), encrypts a payload bound to the
-- inviter's identity client-side, and POSTs (token_id, ciphertext) here. The
-- payload_key never reaches the server — it lives in the URL fragment.
--
-- Atomic single-use semantics are enforced via the `used_at IS NULL` predicate
-- on the redeem UPDATE; concurrent redeemers race for `affected_rows == 1`,
-- and the loser disambiguates 409 vs 410 vs 404 with a follow-up SELECT.
-- Lazy cleanup follows the same pattern as auth_nonces / write_rate_limits:
-- expired rows filtered on read, opportunistic DELETE on ~5% of redeems.

CREATE TABLE IF NOT EXISTS invites (
  token_id TEXT PRIMARY KEY,
  app_id TEXT NOT NULL,
  inviter_dlk TEXT NOT NULL,
  payload BLOB NOT NULL,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  redeemer_share_pub_fingerprint TEXT
);
CREATE INDEX IF NOT EXISTS idx_invites_expires ON invites(expires_at);
CREATE INDEX IF NOT EXISTS idx_invites_inviter ON invites(inviter_dlk);
