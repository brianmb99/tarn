-- 0019_delta_sync_index.sql
--
-- Composite index supporting the delta-sync read path
-- (GET /api/v1/entries?...&since=<cursor>).
--
-- The cursor is (cached_at, txid); the scan is:
--   WHERE lookup_key = ? AND type = ? AND (cached_at, txid) > (?, ?)
--   ORDER BY cached_at, txid
--   LIMIT 25
--
-- Without this index the scan falls back to idx_entries_lookup (a single-
-- column partial index on lookup_key) and filters in memory — fine for
-- small accounts, but it scales O(N) per poll. A user polling every 60s
-- against a 5000-entry account would burn the budget on full scans even
-- if nothing has changed.
--
-- The column order matches the WHERE/ORDER BY: lookup_key + type narrow
-- the row set to one account+collection, then cached_at + txid serve both
-- the range predicate and the ORDER BY. txid as the tiebreak guarantees
-- stable pagination when multiple rows share a cached_at (batch writes
-- land in the same millisecond on D1).
CREATE INDEX IF NOT EXISTS idx_entries_since
  ON entries (lookup_key, type, cached_at, txid)
  WHERE lookup_key IS NOT NULL;
