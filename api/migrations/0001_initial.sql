-- Bookish API Phase 1: Read-only cache layer
-- All entries from Arweave are cached here for fast reads.
-- This entire database is disposable — nuke and rebuild from Arweave.

CREATE TABLE IF NOT EXISTS entries (
  txid           TEXT PRIMARY KEY,
  app            TEXT NOT NULL,
  type           TEXT NOT NULL,
  wallet_addr    TEXT,
  lookup_key     TEXT,
  eid            TEXT,
  prev_txid      TEXT,
  is_tombstone   INTEGER NOT NULL DEFAULT 0,
  tombstone_ref  TEXT,
  block_timestamp INTEGER,
  tags_json      TEXT,
  cached_at      INTEGER NOT NULL
);

CREATE INDEX idx_entries_wallet ON entries (app, type, wallet_addr);
CREATE INDEX idx_entries_lookup ON entries (lookup_key) WHERE lookup_key IS NOT NULL;
CREATE INDEX idx_entries_eid ON entries (eid) WHERE eid IS NOT NULL;
CREATE INDEX idx_entries_tombstone ON entries (tombstone_ref) WHERE is_tombstone = 1;
CREATE INDEX idx_entries_prev ON entries (prev_txid) WHERE prev_txid IS NOT NULL;

CREATE TABLE IF NOT EXISTS cache_meta (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
