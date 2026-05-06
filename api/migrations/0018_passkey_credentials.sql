-- 0018_passkey_credentials.sql
--
-- Phase 6 of the recovery roadmap (RECOVERY_PLAN.md, docs/TARN_PROTOCOL.md).
-- Adds the wire-level support for WebAuthn-PRF passkey credentials as a
-- third independent encryption factor alongside `password` and
-- `recovery_phrase`.
--
-- Two new tables:
--
--   1. `passkey_credentials` — one row per registered passkey. The `prf_salt`
--      is the deterministic input the SDK feeds into the PRF extension on
--      every assertion to derive the wrapping key for this credential. The
--      DEK chain in `accounts.wrapped_data_key` carries one
--      `factor: 'passkey_prf'` wrapping per credential, keyed by
--      `credential_id`. Removing a passkey deletes both the row here and the
--      matching wrappings in the envelope.
--
--      `sign_count` is the WebAuthn replay counter. We store it but treat
--      a stalled or non-incrementing counter as a soft signal (some
--      authenticators legitimately keep it at 0); enforcing strict
--      monotonicity would lock out cross-device synced passkeys.
--
--      `device_label` is an optional human-readable label the user sets at
--      registration so a Settings UI can disambiguate "Brian's iPhone" from
--      "MacBook Pro" without leaking platform fingerprints to Tarn.
--
--   2. `webauthn_challenges` — short-lived (60 s TTL) one-shot challenges
--      issued by `/auth/passkey/{register,authentication}-options`. Stored
--      in D1 rather than KV because:
--        - register-options is JWT-authed (we already have D1 in scope) and
--          authentication-options needs to bind the challenge to the eventual
--          credential lookup.
--        - The table stays tiny (60s TTL plus single-use guard).
--        - Same shape and clean-up cadence as `step_up_tokens` from 0016 —
--          the dedup logic is symmetric and easy to reason about.
--
--      `data_lookup_key` is nullable: registration challenges are bound to
--      the calling account (caller is logged in), but authentication
--      challenges are issued before we know which account is signing in
--      (discoverable / usernameless flow). The verifier resolves the
--      account from the credential_id presented in the assertion.
--
-- Both tables are additive — accounts with no registered passkeys continue
-- to work unchanged (no rows here, no `passkey_prf` wrappings in the
-- envelope, all existing flows untouched).

CREATE TABLE IF NOT EXISTS passkey_credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id TEXT NOT NULL,
  credential_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  prf_salt TEXT NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  device_label TEXT,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_passkey_credentials_account ON passkey_credentials(account_id);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
  challenge TEXT PRIMARY KEY,
  data_lookup_key TEXT,
  purpose TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires ON webauthn_challenges(expires_at);
