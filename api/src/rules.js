// rules.js — Write authorization rule evaluation
// All rules must pass for a write to be allowed. Unknown rule types fail closed.

/**
 * Evaluate write authorization rules for a user.
 * @param {Object} db - D1 database binding
 * @param {string|null} rulesJson - JSON string of rules array.
 *   null = DENY (app must set rules before user can write).
 *   '[]' (empty array) = ALLOW (app explicitly set no restrictions).
 * @param {Object} context - Write context
 * @param {string} context.data_lookup_key - The user's data lookup key
 * @param {string} context.app - App identifier from tags
 * @param {string} context.type - Entry type from tags
 * @param {number} context.payloadBytes - Size of the encrypted payload in bytes (largest in batch)
 * @param {number} [context.batchSize=1] - Number of entries being written (for batch imports)
 * @returns {Promise<{allowed: boolean, failedRule?: string}>}
 */
export async function evaluateRules(db, rulesJson, context) {
  // Null = DENY. App must explicitly set rules (even empty array) before user can write.
  if (rulesJson === null || rulesJson === undefined) {
    return { allowed: false, failedRule: 'No rules set — app must configure write rules for this account' };
  }

  // Empty string = DENY (malformed)
  if (rulesJson === '') {
    return { allowed: false, failedRule: 'Empty rules — app must configure write rules' };
  }

  let rules;
  try {
    rules = JSON.parse(rulesJson);
  } catch {
    return { allowed: false, failedRule: 'Invalid rules JSON' };
  }

  if (!Array.isArray(rules) || rules.length === 0) return { allowed: true };

  for (const rule of rules) {
    const result = await evaluateRule(db, rule, context);
    if (!result.allowed) return result;
  }

  return { allowed: true };
}

async function evaluateRule(db, rule, context) {
  if (!rule || typeof rule.type !== 'string') {
    return { allowed: false, failedRule: 'Rule missing type field' };
  }

  switch (rule.type) {
    case 'max_entries':
      return await evaluateMaxEntries(db, rule, context);
    case 'max_bytes':
      return evaluateMaxBytes(rule, context);
    case 'expires':
      return evaluateExpires(rule);
    default:
      // Fail closed: unknown rule types deny
      return { allowed: false, failedRule: `Unknown rule type: ${rule.type}` };
  }
}

/**
 * max_entries: user has fewer than N RESOLVED live entries matching optional
 * filters (app, entry_type, since).
 *
 * "Resolved" mirrors cache.js resolveEntries (tarn#65): edits are Prev-chained
 * appends and deletes are separate tombstone rows, so a raw is_tombstone=0
 * row count grows with every edit and never shrinks on delete. This count
 * excludes superseded versions (another row's prev_txid points at them) and
 * tombstoned targets (a tombstone row's tombstone_ref points at them), and
 * collapses Eid duplicates — i.e. it counts what the user actually sees.
 * The NOT EXISTS probes are served by the partial indexes from migration 0024.
 */
async function evaluateMaxEntries(db, rule, context) {
  if (typeof rule.limit !== 'number' || rule.limit < 0) {
    return { allowed: false, failedRule: 'max_entries: invalid limit' };
  }

  // Build query with optional filters
  let sql = 'SELECT COUNT(DISTINCT COALESCE(e.eid, e.txid)) as count FROM entries e'
    + ' WHERE e.lookup_key = ?1 AND e.is_tombstone = 0'
    + ' AND NOT EXISTS (SELECT 1 FROM entries t WHERE t.lookup_key = e.lookup_key AND t.is_tombstone = 1 AND t.tombstone_ref = e.txid)'
    + ' AND NOT EXISTS (SELECT 1 FROM entries s WHERE s.lookup_key = e.lookup_key AND s.prev_txid = e.txid)';
  const bindings = [context.data_lookup_key];
  let bindIndex = 2;

  if (rule.app) {
    sql += ` AND e.app = ?${bindIndex}`;
    bindings.push(rule.app);
    bindIndex++;
  }

  if (rule.entry_type) {
    sql += ` AND e.type = ?${bindIndex}`;
    bindings.push(rule.entry_type);
    bindIndex++;
  }

  if (rule.since) {
    const sinceMs = new Date(rule.since).getTime();
    if (isNaN(sinceMs)) {
      return { allowed: false, failedRule: 'max_entries: invalid since timestamp' };
    }
    sql += ` AND e.cached_at > ?${bindIndex}`;
    bindings.push(sinceMs);
    bindIndex++;
  }

  const stmt = db.prepare(sql);
  const result = await stmt.bind(...bindings).first();
  const count = result?.count ?? 0;
  const batchSize = context.batchSize || 1;

  if (count + batchSize > rule.limit) {
    return { allowed: false, failedRule: `max_entries: limit ${rule.limit} would be exceeded (${count} existing + ${batchSize} new)` };
  }

  return { allowed: true };
}

/**
 * max_bytes: this individual entry is smaller than N bytes.
 */
function evaluateMaxBytes(rule, context) {
  if (typeof rule.limit !== 'number' || rule.limit < 0) {
    return { allowed: false, failedRule: 'max_bytes: invalid limit' };
  }

  if (context.payloadBytes > rule.limit) {
    return { allowed: false, failedRule: `max_bytes: payload ${context.payloadBytes} exceeds limit ${rule.limit}` };
  }

  return { allowed: true };
}

/**
 * expires: current time is before the expiry timestamp.
 */
function evaluateExpires(rule) {
  if (!rule.at) {
    return { allowed: false, failedRule: 'expires: missing at timestamp' };
  }

  const expiresAt = new Date(rule.at).getTime();
  if (isNaN(expiresAt)) {
    return { allowed: false, failedRule: 'expires: invalid at timestamp' };
  }

  if (Date.now() >= expiresAt) {
    return { allowed: false, failedRule: `expires: subscription expired at ${rule.at}` };
  }

  return { allowed: true };
}
