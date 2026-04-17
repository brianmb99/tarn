-- Idempotency keys for retry-safe writes (#8).
-- Client sends X-Idempotency-Key; server stores response for TTL so a
-- retry with the same key returns the original response without creating
-- a duplicate DataItem on Arweave.

CREATE TABLE IF NOT EXISTS idempotency_keys (
  scoped_key TEXT PRIMARY KEY,   -- "${data_lookup_key}:${client_key}"
  response_json TEXT NOT NULL,    -- full response body (JSON), returned verbatim on retry
  status_code INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_idempotency_created_at ON idempotency_keys(created_at);
