-- 0016_account_key_storage.sql
--
-- Phase 3 of the recovery roadmap (RECOVERY_PLAN.md). Adds the wire-level
-- support for Model B account-key storage:
--
--   1. `accounts.wrapped_account_key` (TEXT, nullable) — opaque base64
--      AES-GCM ciphertext of the user's account key, encrypted under the
--      user's gen-1 DEK with AAD `"tarn-wrapped-account-key-v1"`. The wrap
--      is computed entirely client-side; the server never sees the
--      account-key plaintext or the DEK. NULL for Model A accounts (no
--      backup stored). Set at registration when the SDK is invoked with
--      `storeAccountKey: true`.
--
--   2. `step_up_tokens` — short-lived, single-use tokens issued by
--      POST /api/v1/auth/step-up after a fresh password proof. Required
--      (alongside the session JWT) to fetch the wrap. The chosen mechanism
--      is opaque random tokens stored in D1: simpler than JWT + revocation
--      list, no extra crypto config to thread through, and the table stays
--      tiny (60-second TTL with single-use semantics keeps row count low).
--      `consumed_at` is the single-use guard — flip it from NULL to a
--      timestamp on first use so a second presentation hits "already
--      consumed" without depending on row deletion ordering.
--
--   3. `account_key_fetch_log` — append-only audit trail. Every successful
--      fetch of a wrap writes a row here so the SDK / app surface can later
--      render "your account key was last viewed at X". NOT a security
--      mechanism on its own (the fetch is already gated by JWT + step-up);
--      this is a UX scaffold for transparency.
--
-- All three are nullable / standalone: existing accounts continue to work
-- unchanged; the new behaviors are opt-in per registration / per request.

ALTER TABLE accounts ADD COLUMN wrapped_account_key TEXT;

CREATE TABLE IF NOT EXISTS step_up_tokens (
  token TEXT PRIMARY KEY,
  data_lookup_key TEXT NOT NULL,
  scope TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_step_up_tokens_dlk ON step_up_tokens(data_lookup_key);
CREATE INDEX IF NOT EXISTS idx_step_up_tokens_expires ON step_up_tokens(expires_at);

CREATE TABLE IF NOT EXISTS account_key_fetch_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  data_lookup_key TEXT NOT NULL,
  fetched_at INTEGER NOT NULL,
  ip_hash TEXT,
  user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_account_key_fetch_log_dlk ON account_key_fetch_log(data_lookup_key);
CREATE INDEX IF NOT EXISTS idx_account_key_fetch_log_fetched_at ON account_key_fetch_log(fetched_at);
