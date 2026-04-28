-- Recovery factor (issue #12).
--
-- v4 accounts publish a recovery_lookup_key + recovery_public_key alongside
-- the password-derived credential_lookup_key + public_key. Both keys are
-- derived from the user's BIP39 recovery phrase (independent of email and
-- password) and let the user authenticate to the API for credential rotation
-- without knowing their old password. See docs/TARN_PROTOCOL.md § Recovery.
--
-- Both columns are nullable so v3 (and earlier) accounts continue to function
-- without a recovery factor. UNIQUE on recovery_lookup_key prevents two
-- accounts from sharing the same phrase-derived lookup key (collision is
-- 2^-256 with a 24-word phrase but the constraint surfaces a configuration
-- bug if anything goes wrong).

ALTER TABLE accounts ADD COLUMN recovery_lookup_key TEXT;
ALTER TABLE accounts ADD COLUMN recovery_public_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_recovery_lookup_key
  ON accounts(recovery_lookup_key)
  WHERE recovery_lookup_key IS NOT NULL;
