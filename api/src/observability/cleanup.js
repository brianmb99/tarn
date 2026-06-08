// cleanup.js — aux-table pruning for the CORE observability subsystem.
//
// Several D1 tables accumulate short-lived or audit rows that nothing else
// reaps. Left unbounded they grow forever (D1 has no TTL). The scheduled
// handler runs this conservative sweep each tick.
//
// Tables and their reap rules (column names VERIFIED against migrations):
//
//   step_up_tokens (0016): token, data_lookup_key, scope, issued_at,
//       expires_at, consumed_at. 60s TTL single-use. Reap: rows whose
//       expires_at < now (expired) OR consumed_at IS NOT NULL (already used).
//       A consumed token is dead the instant it's used; an expired one is dead
//       at expiry. Both are clearly-dead.
//
//   webauthn_challenges (0018): challenge, data_lookup_key, purpose,
//       issued_at, expires_at, consumed_at. Same shape/lifecycle as
//       step_up_tokens. Reap: expires_at < now OR consumed_at IS NOT NULL.
//
//   auth_nonces (0012): nonce, credential_lookup_key, created_at, expires_at.
//       Single-use but DELETED on consume (no consumed_at column). Reap: rows
//       whose expires_at < now (the lazy SELECT-side filter already ignores
//       these at read time; this just removes the dead rows).
//
//   account_key_fetch_log (0016/0017): id, data_lookup_key, fetched_at,
//       ip_hash, user_agent, op. Append-only audit trail. Reap: a RETENTION
//       cutoff — rows older than `retentionDays` (default 90). This is NOT a
//       liveness reap (the rows are all "live"); it's a privacy/retention
//       cutoff. 90 days is long enough for "your account key was last viewed
//       at X" UX and abuse review, short enough to bound the table.
//
// Design: `buildCleanupPlan` is PURE — given `now` it returns the exact SQL +
// bind params for each table, so a unit test can assert the right cutoffs and
// predicates without a DB. `runCleanup` executes the plan against D1 and
// returns per-table deleted counts. Everything is wrapped so one failing
// statement never aborts the others (and never breaks the cron).

// Retention for the account-key audit log, in days.
export const DEFAULT_AUDIT_RETENTION_DAYS = 90;

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * Build the conservative cleanup plan. Pure: returns an array of
 * { table, sql, params, kind } describing each DELETE. Timestamps in these
 * tables are stored as unix MILLISECONDS (verified: storeNonce/step-up/
 * challenge writers and the fetch-log all use Date.now()).
 *
 * @param {Object} args
 * @param {number} args.now - unix ms (injectable for tests)
 * @param {number} [args.auditRetentionDays]
 * @returns {Array<{table: string, sql: string, params: any[], kind: string}>}
 */
export function buildCleanupPlan({ now, auditRetentionDays = DEFAULT_AUDIT_RETENTION_DAYS }) {
  const auditCutoff = now - auditRetentionDays * MS_PER_DAY;

  return [
    {
      table: 'step_up_tokens',
      kind: 'expired_or_consumed',
      sql: 'DELETE FROM step_up_tokens WHERE expires_at < ?1 OR consumed_at IS NOT NULL',
      params: [now],
    },
    {
      table: 'webauthn_challenges',
      kind: 'expired_or_consumed',
      sql: 'DELETE FROM webauthn_challenges WHERE expires_at < ?1 OR consumed_at IS NOT NULL',
      params: [now],
    },
    {
      table: 'auth_nonces',
      kind: 'expired',
      sql: 'DELETE FROM auth_nonces WHERE expires_at < ?1',
      params: [now],
    },
    {
      table: 'account_key_fetch_log',
      kind: 'retention',
      sql: 'DELETE FROM account_key_fetch_log WHERE fetched_at < ?1',
      params: [auditCutoff],
    },
  ];
}

/**
 * Execute a cleanup plan against D1. Each statement is independent; a failure
 * on one table is recorded and the rest still run. Returns per-table results.
 *
 * D1's prepared-statement .run() returns { meta: { changes } } on Workers;
 * we read `changes` when available so the report shows how many rows each reap
 * removed.
 *
 * @param {Object} db - D1Database binding (env.DB)
 * @param {Array} plan - output of buildCleanupPlan
 * @returns {Promise<{tables: Object, totalDeleted: number, errors: Object}>}
 */
export async function runCleanup(db, plan) {
  const tables = {};
  const errors = {};
  let totalDeleted = 0;

  for (const step of plan) {
    try {
      const stmt = db.prepare(step.sql).bind(...step.params);
      const res = await stmt.run();
      const changes = res?.meta?.changes ?? res?.changes ?? 0;
      tables[step.table] = { deleted: changes, kind: step.kind };
      totalDeleted += Number(changes) || 0;
    } catch (err) {
      errors[step.table] = err?.message || String(err);
      tables[step.table] = { deleted: 0, kind: step.kind, error: errors[step.table] };
    }
  }

  return { tables, totalDeleted, errors };
}
