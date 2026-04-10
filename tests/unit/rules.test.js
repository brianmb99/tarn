// Unit tests for api/src/rules.js — write authorization rule evaluation
// Run: node --test tests/unit/rules.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateRules } from '../../api/src/rules.js';

// ============ Mock D1 ============

function createMockDB(entryCount = 0) {
  return {
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async first() {
              // Return configured count for any COUNT(*) query
              return { count: entryCount };
            }
          };
        }
      };
    }
  };
}

// Configurable mock: returns different counts based on query filters
function createFilteredMockDB(counts = {}) {
  return {
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async first() {
              // Use the data_lookup_key + any app filter to look up count
              const key = args.join('|');
              return { count: counts[key] ?? counts['default'] ?? 0 };
            }
          };
        }
      };
    }
  };
}

const baseContext = {
  data_lookup_key: 'a'.repeat(64),
  app: 'bookish',
  type: 'entry',
  payloadBytes: 1000,
};

// ============ Null / empty rules ============

describe('evaluateRules — null/empty', () => {
  it('should allow when rules is null', async () => {
    const result = await evaluateRules(createMockDB(), null, baseContext);
    assert.equal(result.allowed, true);
  });

  it('should allow when rules is empty string', async () => {
    const result = await evaluateRules(createMockDB(), '', baseContext);
    assert.equal(result.allowed, true);
  });

  it('should allow when rules is empty array', async () => {
    const result = await evaluateRules(createMockDB(), '[]', baseContext);
    assert.equal(result.allowed, true);
  });

  it('should deny on invalid JSON', async () => {
    const result = await evaluateRules(createMockDB(), '{broken', baseContext);
    assert.equal(result.allowed, false);
    assert.ok(result.failedRule.includes('Invalid'));
  });
});

// ============ max_entries ============

describe('evaluateRules — max_entries', () => {
  it('should allow when below limit', async () => {
    const rules = JSON.stringify([{ type: 'max_entries', limit: 10 }]);
    const result = await evaluateRules(createMockDB(5), rules, baseContext);
    assert.equal(result.allowed, true);
  });

  it('should deny when at limit', async () => {
    const rules = JSON.stringify([{ type: 'max_entries', limit: 10 }]);
    const result = await evaluateRules(createMockDB(10), rules, baseContext);
    assert.equal(result.allowed, false);
    assert.ok(result.failedRule.includes('max_entries'));
  });

  it('should deny when above limit', async () => {
    const rules = JSON.stringify([{ type: 'max_entries', limit: 5 }]);
    const result = await evaluateRules(createMockDB(7), rules, baseContext);
    assert.equal(result.allowed, false);
  });

  it('should deny with limit 0 (no quota, even with 0 entries)', async () => {
    // Edge case: limit=0, count=0. Since count(0) >= limit(0) is true, this denies.
    // A limit of 0 means "no writes allowed."
    const rules = JSON.stringify([{ type: 'max_entries', limit: 0 }]);
    const result = await evaluateRules(createMockDB(0), rules, baseContext);
    assert.equal(result.allowed, false);
  });

  it('should deny with invalid limit', async () => {
    const rules = JSON.stringify([{ type: 'max_entries', limit: 'abc' }]);
    const result = await evaluateRules(createMockDB(0), rules, baseContext);
    assert.equal(result.allowed, false);
    assert.ok(result.failedRule.includes('invalid limit'));
  });

  it('should deny with negative limit', async () => {
    const rules = JSON.stringify([{ type: 'max_entries', limit: -1 }]);
    const result = await evaluateRules(createMockDB(0), rules, baseContext);
    assert.equal(result.allowed, false);
  });
});

// ============ max_bytes ============

describe('evaluateRules — max_bytes', () => {
  it('should allow when below limit', async () => {
    const rules = JSON.stringify([{ type: 'max_bytes', limit: 102400 }]);
    const result = await evaluateRules(createMockDB(), rules, { ...baseContext, payloadBytes: 50000 });
    assert.equal(result.allowed, true);
  });

  it('should allow at exact limit', async () => {
    const rules = JSON.stringify([{ type: 'max_bytes', limit: 102400 }]);
    const result = await evaluateRules(createMockDB(), rules, { ...baseContext, payloadBytes: 102400 });
    assert.equal(result.allowed, true);
  });

  it('should deny above limit', async () => {
    const rules = JSON.stringify([{ type: 'max_bytes', limit: 102400 }]);
    const result = await evaluateRules(createMockDB(), rules, { ...baseContext, payloadBytes: 102401 });
    assert.equal(result.allowed, false);
    assert.ok(result.failedRule.includes('max_bytes'));
  });

  it('should allow 0-byte payload with positive limit', async () => {
    const rules = JSON.stringify([{ type: 'max_bytes', limit: 100 }]);
    const result = await evaluateRules(createMockDB(), rules, { ...baseContext, payloadBytes: 0 });
    assert.equal(result.allowed, true);
  });

  it('should deny with invalid limit', async () => {
    const rules = JSON.stringify([{ type: 'max_bytes', limit: 'big' }]);
    const result = await evaluateRules(createMockDB(), rules, baseContext);
    assert.equal(result.allowed, false);
    assert.ok(result.failedRule.includes('invalid limit'));
  });
});

// ============ expires ============

describe('evaluateRules — expires', () => {
  it('should allow when not expired (future timestamp)', async () => {
    const future = new Date(Date.now() + 3600000).toISOString(); // +1 hour
    const rules = JSON.stringify([{ type: 'expires', at: future }]);
    const result = await evaluateRules(createMockDB(), rules, baseContext);
    assert.equal(result.allowed, true);
  });

  it('should deny when expired (past timestamp)', async () => {
    const past = new Date(Date.now() - 3600000).toISOString(); // -1 hour
    const rules = JSON.stringify([{ type: 'expires', at: past }]);
    const result = await evaluateRules(createMockDB(), rules, baseContext);
    assert.equal(result.allowed, false);
    assert.ok(result.failedRule.includes('expires'));
  });

  it('should deny at exact expiry time (>= comparison)', async () => {
    // Set expiry to "now" — should deny (>= means expired at exact time)
    const now = new Date().toISOString();
    const rules = JSON.stringify([{ type: 'expires', at: now }]);
    const result = await evaluateRules(createMockDB(), rules, baseContext);
    assert.equal(result.allowed, false);
  });

  it('should deny with missing at field', async () => {
    const rules = JSON.stringify([{ type: 'expires' }]);
    const result = await evaluateRules(createMockDB(), rules, baseContext);
    assert.equal(result.allowed, false);
    assert.ok(result.failedRule.includes('missing'));
  });

  it('should deny with invalid timestamp', async () => {
    const rules = JSON.stringify([{ type: 'expires', at: 'not-a-date' }]);
    const result = await evaluateRules(createMockDB(), rules, baseContext);
    assert.equal(result.allowed, false);
    assert.ok(result.failedRule.includes('invalid'));
  });
});

// ============ Unknown rule types ============

describe('evaluateRules — unknown types', () => {
  it('should deny unknown rule type (fail closed)', async () => {
    const rules = JSON.stringify([{ type: 'quantum_entanglement', power: 9000 }]);
    const result = await evaluateRules(createMockDB(), rules, baseContext);
    assert.equal(result.allowed, false);
    assert.ok(result.failedRule.includes('Unknown rule type'));
    assert.ok(result.failedRule.includes('quantum_entanglement'));
  });

  it('should deny rule with missing type field', async () => {
    const rules = JSON.stringify([{ limit: 10 }]);
    const result = await evaluateRules(createMockDB(), rules, baseContext);
    assert.equal(result.allowed, false);
    assert.ok(result.failedRule.includes('missing type'));
  });
});

// ============ Multiple rules (AND logic) ============

describe('evaluateRules — multiple rules', () => {
  it('should allow when all rules pass', async () => {
    const future = new Date(Date.now() + 3600000).toISOString();
    const rules = JSON.stringify([
      { type: 'max_entries', limit: 100 },
      { type: 'max_bytes', limit: 102400 },
      { type: 'expires', at: future },
    ]);
    const result = await evaluateRules(createMockDB(5), rules, baseContext);
    assert.equal(result.allowed, true);
  });

  it('should deny when first rule fails', async () => {
    const rules = JSON.stringify([
      { type: 'max_entries', limit: 3 },
      { type: 'max_bytes', limit: 102400 },
    ]);
    const result = await evaluateRules(createMockDB(5), rules, baseContext);
    assert.equal(result.allowed, false);
    assert.ok(result.failedRule.includes('max_entries'));
  });

  it('should deny when second rule fails', async () => {
    const past = new Date(Date.now() - 1000).toISOString();
    const rules = JSON.stringify([
      { type: 'max_entries', limit: 100 },
      { type: 'expires', at: past },
    ]);
    const result = await evaluateRules(createMockDB(5), rules, baseContext);
    assert.equal(result.allowed, false);
    assert.ok(result.failedRule.includes('expires'));
  });

  it('should short-circuit on first failure', async () => {
    const rules = JSON.stringify([
      { type: 'max_bytes', limit: 1 },  // will fail (payload is 1000)
      { type: 'unknown_type' },          // would also fail
    ]);
    const result = await evaluateRules(createMockDB(), rules, baseContext);
    assert.equal(result.allowed, false);
    assert.ok(result.failedRule.includes('max_bytes'), 'Should fail on first rule, not reach second');
  });
});
