-- Phase 2: Pending transaction tracking for write-through cache
-- Tracks recently uploaded txids per wallet for sync status.
-- Cleanup by timestamp on read: WHERE created_at > datetime('now', '-6 hours')

CREATE TABLE IF NOT EXISTS pending_txs (
  txid        TEXT PRIMARY KEY,
  wallet_addr TEXT NOT NULL,
  app         TEXT NOT NULL,
  type        TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_pending_wallet ON pending_txs (wallet_addr, created_at);
