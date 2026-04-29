-- Friend-handshake inbox storage (issue #14, Section 5a).
--
-- The friend-handshake protocol (sharing design §6) publishes HPKE-sealed
-- request + accept blobs to a publicly-derivable per-recipient inbox tag.
-- The tag is shared across all senders writing to the same recipient in a
-- given day window, so unlike normal Tarn entries — which are scoped by
-- (app, type, lookup_key) — these blobs can have many writers per tag.
--
-- A dedicated table keeps the lookup index narrow and avoids polluting the
-- per-user `entries` semantics. Inbox blobs are also durable on Arweave (the
-- API signs + uploads via Turbo, same as any other write); this table is the
-- D1 cache that fetches see.
--
-- Columns:
--   txid          - Arweave DataItem id (PK).
--   app_id        - App that produced/consumes this blob (per-app isolation).
--   inbox_tag     - 43-char base64url (HMAC-SHA-256 output, sharing §6.1).
--   blob_type     - 'friend-request-v1' or 'friend-accept-v1' (sharing §6.2/§6.4).
--   ciphertext    - HPKE-sealed bytes (enc || ct+tag); opaque to the API.
--   published_at  - unix ms; used both for ordering and TTL eviction.

CREATE TABLE IF NOT EXISTS share_inbox (
  txid          TEXT PRIMARY KEY,
  app_id        TEXT NOT NULL,
  inbox_tag     TEXT NOT NULL,
  blob_type     TEXT NOT NULL,
  ciphertext    BLOB NOT NULL,
  published_at  INTEGER NOT NULL
);

-- Lookup path: client polls (app_id, inbox_tag, blob_type). Multiple rows
-- per (tag, type) are expected (multiple senders per recipient per window).
CREATE INDEX IF NOT EXISTS idx_share_inbox_lookup
  ON share_inbox (app_id, inbox_tag, blob_type);

-- Eviction path: nightly sweep deletes rows older than the recipient polling
-- window (~30 days) — keeps the cache from growing unbounded. The sweep is
-- not implemented yet; the index is here so it's a one-line query when added.
CREATE INDEX IF NOT EXISTS idx_share_inbox_age
  ON share_inbox (published_at);
