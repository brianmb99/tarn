-- 0021_health_reports.sql
--
-- CORE observability subsystem. The hourly cron (`scheduled()` in
-- api/src/worker.js) runs a health/drift/balance/cleanup sweep and persists a
-- report row here. The authenticated admin endpoint
-- `GET /api/v1/admin/health-report` returns the most recent row.
--
-- This table is OPERATIONAL state, not user data, and is deliberately NOT
-- rebuilt from Arweave (it is a log of cache-vs-permanent-storage health, which
-- only makes sense relative to a specific D1 instance). Like sessions /
-- step_up_tokens it is transient-by-design.
--
-- Columns:
--   id          - autoincrement PK.
--   created_at  - unix ms the report was written (cron tick time).
--   healthy     - 0/1 rollup: 1 iff no drift, no LOW_FUNDING, readiness OK.
--   report_json - the full structured report (drift per namespace, funding,
--                 cleanup counts, readiness). Opaque JSON; the endpoint returns
--                 it verbatim. Contains NO plaintext / key / kit material —
--                 only counts, timestamps, namespace names, and a winc balance.
--
-- Zero-knowledge note: report_json carries only aggregate counts and the
-- operator wallet's winc balance. It must never include account-key, DEK, or
-- any ciphertext body — the scheduled handler only ever reads counts and
-- block timestamps from Arweave GraphQL, never blob bodies.

CREATE TABLE IF NOT EXISTS health_reports (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at  INTEGER NOT NULL,
  healthy     INTEGER NOT NULL DEFAULT 1,
  report_json TEXT NOT NULL
);

-- Latest-report lookup (the admin endpoint does ORDER BY created_at DESC LIMIT 1)
-- and the self-pruning retention sweep both scan by created_at.
CREATE INDEX IF NOT EXISTS idx_health_reports_created_at ON health_reports(created_at);
