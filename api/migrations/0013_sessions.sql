-- 0013_sessions.sql
--
-- Server-side session management (Section 7.5, issue #20).
--
-- Background: Section 7 (issue #19) gave a single device persistent sessions
-- but left no way to revoke a JWT before its 15-minute TTL. Section 7.5
-- attaches a per-session identifier (`sid`) to user-role JWTs and tracks them
-- in this table — revocation = DELETE FROM sessions, enforced at the auth
-- middleware via a stateful D1 lookup (amortized by a 5-second isolate cache).
--
-- Rows are written by /auth/verify (lazy-prune of stale rows on each call,
-- then INSERT for new sids or update of last_seen_at for reused ones), updated
-- on authenticated requests via ctx.waitUntil (throttled to ≥60s), and deleted
-- by the revoke endpoints + changeCredentials / recoverAccount / deleteAccount.
-- App-role JWTs stay stateless and have no row here.

CREATE TABLE IF NOT EXISTS sessions (
  sid TEXT PRIMARY KEY,
  data_lookup_key TEXT NOT NULL,
  app TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  device_label TEXT,
  via_recovery INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_dlk ON sessions(data_lookup_key);
CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON sessions(last_seen_at);
