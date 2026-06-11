-- 0024_rules_resolution_indexes.sql — tarn#65
--
-- evaluateMaxEntries now counts RESOLVED live entries (excluding superseded
-- Prev-chain versions and tombstoned targets) instead of raw rows. Its two
-- NOT EXISTS probes look up entries by tombstone_ref and prev_txid; these
-- partial indexes keep each probe O(log n) instead of a table scan.

CREATE INDEX IF NOT EXISTS idx_entries_tombstone_ref
  ON entries(tombstone_ref) WHERE tombstone_ref IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_entries_prev_txid
  ON entries(prev_txid) WHERE prev_txid IS NOT NULL;
