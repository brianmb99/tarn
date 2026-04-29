-- Per-pair share log storage (issue #15, Section 5b).
--
-- The share log (sharing design §8) is a sequence of stealth-addressed,
-- end-to-end encrypted entries that one user publishes for one specific
-- connection. Each entry's tag is HMAC-SHA-256 over a per-pair seed and a
-- monotonically increasing seq, so tag values are pseudorandom from Tarn's
-- perspective (Tarn cannot enumerate user-pairs from its own state).
--
-- Tag uniqueness: the design (§9.1) requires 409 Conflict when a publish
-- attempts to write at a tag that already holds a blob. Multi-device clients
-- depend on this invariant for total ordering of their outbound stream
-- (5c work). We enforce it as a SQLite UNIQUE constraint on (app_id,
-- log_tag, blob_type) — narrow enough that two apps' or two protocol
-- versions' tag namespaces don't collide.
--
-- Distinct from share_inbox: inbox blobs (handshake) have many writers per
-- tag (per recipient/window), while share-log blobs have at most one per tag.
-- Different access pattern → different table.
--
-- Columns:
--   txid          - Arweave DataItem id (PK).
--   app_id        - App that produced/consumes this blob (per-app isolation).
--   log_tag       - 43-char base64url HMAC-SHA-256 output (sharing §4.4).
--   blob_type     - 'share-log-v1' (sharing §8.1 + §9.1). Versioned for
--                   forward compat — new versions get distinct namespaces.
--   ciphertext    - AES-GCM-encrypted (iv || ct+tag); opaque to the API.
--   data_lookup_key - Sender's DLK; lets the operator scope deletion / abuse
--                   handling per account without depending on tag enumeration.
--   published_at  - unix ms; useful for forward debugging + future TTL sweeps.

CREATE TABLE IF NOT EXISTS share_log (
  txid             TEXT PRIMARY KEY,
  app_id           TEXT NOT NULL,
  log_tag          TEXT NOT NULL,
  blob_type        TEXT NOT NULL,
  ciphertext       BLOB NOT NULL,
  data_lookup_key  TEXT NOT NULL,
  published_at     INTEGER NOT NULL
);

-- Per-tag uniqueness within (app, type) — the §9.1 collision check fires
-- against this index. The tag value is already pseudorandom; collisions are
-- expected only on legitimate multi-device races (handled by the 5c retry
-- path) or rare birthday accidents at astronomical seq counts.
CREATE UNIQUE INDEX IF NOT EXISTS idx_share_log_tag_unique
  ON share_log (app_id, log_tag, blob_type);

-- Lookup path mirrors the inbox table: client fetches by (app, tag, type).
-- A unique index already covers this query, but a non-unique covering index
-- would not help further; keep it implicit via the unique above.

-- Eviction path: same nightly-sweep pattern as share_inbox. Permanence is on
-- Arweave; D1 is the cache.
CREATE INDEX IF NOT EXISTS idx_share_log_age
  ON share_log (published_at);

-- Per-account scoping for operator tasks (delete-on-account-deletion,
-- audit). Account-level row counts can be expensive without this.
CREATE INDEX IF NOT EXISTS idx_share_log_account
  ON share_log (data_lookup_key);
