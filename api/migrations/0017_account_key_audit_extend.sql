-- 0017_account_key_audit_extend.sql
--
-- Phase 4 of the recovery roadmap (RECOVERY_PLAN.md). Extends the existing
-- `account_key_fetch_log` table (added in 0016) so it can also record the
-- new account-key write operations introduced in Phase 4:
--
--   - `fetch`   — successful GET /account/account-key (Phase 3, default)
--   - `enable`  — PUT /account/account-key (Model A → B)
--   - `disable` — DELETE /account/account-key (Model B → A)
--   - `rotate`  — POST /account/rotate-account-key
--
-- Choice: extend the existing table rather than introduce a sibling
-- `account_key_audit_log`. The two would carry identical columns
-- (data_lookup_key, when, ip_hash, user_agent) plus an op discriminator;
-- splitting the rows across two tables would force every "show recent
-- account-key activity" UI query to UNION the two and re-merge by timestamp,
-- with no schema clarity in return. A single audit table keyed by `op`
-- matches the existing convention (`apps`, `entries`, etc. all carry op
-- discriminators on shared rows).
--
-- Defaults preserve Phase 3 semantics: existing rows have `op = 'fetch'`,
-- and the Phase 3 fetch handler does not need to be updated to write the
-- column (the DEFAULT covers it). Phase 4 handlers explicitly write `op`.
--
-- The table is renamed conceptually ("fetch log" → "audit log") but the
-- physical name stays `account_key_fetch_log` to avoid breaking any out-of-
-- band tooling or queries pointed at it. Documented in TARN_PROTOCOL.md.

ALTER TABLE account_key_fetch_log ADD COLUMN op TEXT NOT NULL DEFAULT 'fetch';
CREATE INDEX IF NOT EXISTS idx_account_key_fetch_log_op ON account_key_fetch_log(op);
