-- 0012_auth_nonces.sql
--
-- Move challenge-response auth nonces from Cloudflare KV (AUTH_KV) to D1.
--
-- Background: AUTH_KV had been hitting the free-tier daily put limit during
-- testing-heavy days, taking down the entire auth flow (every challenge
-- request 500s when KV.put exhausts). D1 has no equivalent daily-write cap
-- for a workload of this size, so moving nonces here removes the operational
-- failure mode. Schema is small + writes are short-lived so the table stays
-- bounded.
--
-- Rows are written by storeNonce, deleted by consumeNonce (single-use), and
-- additionally pruned by lazy SELECT-side filtering on expires_at.

CREATE TABLE IF NOT EXISTS auth_nonces (
  nonce TEXT PRIMARY KEY,
  credential_lookup_key TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_nonces_expires ON auth_nonces(expires_at);
