-- Tarn Protocol v0.3.0: PBKDF2 identity + ECDSA P-256 auth
-- Replaces wallet-based identity with credential_lookup_key + signing key pair.

-- User accounts: identity, auth, and write rules
CREATE TABLE IF NOT EXISTS accounts (
  credential_lookup_key TEXT PRIMARY KEY,
  public_key            TEXT NOT NULL,
  data_lookup_key       TEXT NOT NULL UNIQUE,
  wrapped_data_key      TEXT NOT NULL,
  rules_json            TEXT,
  created_at            INTEGER NOT NULL
);

CREATE INDEX idx_accounts_dlk ON accounts (data_lookup_key);

-- Registered apps: app identity for managing user write rules
CREATE TABLE IF NOT EXISTS apps (
  app_id     TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- Add data_lookup_key column to pending_txs for new tracking
ALTER TABLE pending_txs ADD COLUMN data_lookup_key TEXT;
CREATE INDEX idx_pending_dlk ON pending_txs (data_lookup_key, created_at);

-- New composite index for lookup_key-based entry queries (replaces wallet_addr pattern)
CREATE INDEX idx_entries_lookup_app_type ON entries (app, type, lookup_key);
