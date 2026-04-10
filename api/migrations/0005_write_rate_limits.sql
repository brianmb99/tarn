-- Atomic write rate limiting via D1 (replaces KV get-then-put which has TOCTOU race)
-- Uses INSERT ... ON CONFLICT DO UPDATE SET count = count + 1 for atomicity.

CREATE TABLE IF NOT EXISTS write_rate_limits (
  key TEXT PRIMARY KEY,           -- 'write:{data_lookup_key}:{hour}'
  count INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL     -- unix ms, for cleanup
);
