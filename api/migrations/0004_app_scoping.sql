-- Tarn Protocol v0.4.0: Per-app account isolation
-- Accounts are scoped to a registered app.
-- HKDF-Expand replaces SHA-256 concatenation for key derivation.
-- AES-KW replaces AES-GCM for key wrapping.

ALTER TABLE accounts ADD COLUMN app TEXT NOT NULL DEFAULT '';
CREATE INDEX idx_accounts_app ON accounts (app);
