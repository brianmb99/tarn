// rules.js — Write authorization rule evaluation
// All rules must pass for a write to be allowed. Unknown rule types fail closed.

/**
 * Evaluate write authorization rules for a user.
 * @param {Object} db - D1 database binding
 * @param {string|null} rulesJson - JSON string of rules array (null = unrestricted)
 * @param {Object} context - Write context
 * @param {string} context.data_lookup_key - The user's data lookup key
 * @param {string} context.app - App identifier from tags
 * @param {string} context.type - Entry type from tags
 * @param {number} context.payloadBytes - Size of the encrypted payload in bytes
 * @returns {Promise<{allowed: boolean, failedRule?: string}>}
 */
export async function evaluateRules(db, rulesJson, context) {
  // Null or empty rules = unrestricted
  if (!rulesJson) return { allowed: true };

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
 * max_entries: user has fewer than N entries matching optional filters.
 * Optional filters: app, entry_type, since
 */
async function evaluateMaxEntries(db, rule, context) {
  if (typeof rule.limit !== 'number' || rule.limit < 0) {
    return { allowed: false, failedRule: 'max_entries: invalid limit' };
  }

  // Build query with optional filters
  let sql = 'SELECT COUNT(*) as count FROM entries WHERE lookup_key = ?1 AND is_tombstone = 0';
  const bindings = [context.data_lookup_key];
  let bindIndex = 2;

  if (rule.app) {
    sql += ` AND app = ?${bindIndex}`;
    bindings.push(rule.app);
    bindIndex++;
  }

  if (rule.entry_type) {
    sql += ` AND type = ?${bindIndex}`;
    bindings.push(rule.entry_type);
    bindIndex++;
  }

  if (rule.since) {
    const sinceMs = new Date(rule.since).getTime();
    if (isNaN(sinceMs)) {
      return { allowed: false, failedRule: 'max_entries: invalid since timestamp' };
    }
    sql += ` AND cached_at > ?${bindIndex}`;
    bindings.push(sinceMs);
    bindIndex++;
  }

  const stmt = db.prepare(sql);
  const result = await stmt.bind(...bindings).first();
  const count = result?.count ?? 0;

  if (count >= rule.limit) {
    return { allowed: false, failedRule: `max_entries: limit ${rule.limit} reached (${count} entries)` };
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
