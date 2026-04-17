// Unit tests for api/src/idempotency.js (tarn #8).
// Run: node --test tests/unit/idempotency.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  readIdempotencyKey,
  lookupIdempotentResponse,
  storeIdempotentResponse,
} from '../../api/src/idempotency.js';

function mockRequest(headerValue) {
  return {
    headers: {
      get: (name) => (name.toLowerCase() === 'x-idempotency-key' ? headerValue : null),
    },
  };
}

// ============ readIdempotencyKey ============

describe('readIdempotencyKey', () => {
  it('returns {key: null, error: null} when header absent', () => {
    const { key, error } = readIdempotencyKey(mockRequest(null));
    assert.equal(key, null);
    assert.equal(error, null);
  });

  it('accepts a valid UUID-shaped key', () => {
    const uuid = '550e8400-e29b-41d4-a716-446655440000';
    const { key, error } = readIdempotencyKey(mockRequest(uuid));
    assert.equal(key, uuid);
    assert.equal(error, null);
  });

  it('rejects a key shorter than 16 chars', () => {
    const { key, error } = readIdempotencyKey(mockRequest('short'));
    assert.equal(key, null);
    assert.match(error, /16/);
  });

  it('rejects a key longer than 128 chars', () => {
    const tooLong = 'x'.repeat(129);
    const { key, error } = readIdempotencyKey(mockRequest(tooLong));
    assert.equal(key, null);
    assert.match(error, /128/);
  });

  it('rejects non-printable-ASCII characters', () => {
    const bad = 'abcdefghij\x00klmnop';
    const { key, error } = readIdempotencyKey(mockRequest(bad));
    assert.equal(key, null);
    assert.match(error, /ASCII/);
  });

  it('accepts typical client-generated UUIDs (36 chars)', () => {
    const uuid = crypto.randomUUID();
    const { key, error } = readIdempotencyKey(mockRequest(uuid));
    assert.equal(key, uuid);
    assert.equal(error, null);
  });
});

// ============ lookup + store (with in-memory DB mock) ============

function mockDB() {
  const rows = new Map();
  return {
    _rows: rows,
    prepare(sql) {
      return {
        _sql: sql,
        _params: [],
        bind(...params) {
          this._params = params;
          return this;
        },
        async first() {
          if (/SELECT response_json/.test(this._sql)) {
            const [scopedKey] = this._params;
            const row = rows.get(scopedKey);
            return row ? { response_json: row.response_json, status_code: row.status_code } : null;
          }
          return null;
        },
        async run() {
          if (/INSERT INTO idempotency_keys/.test(this._sql)) {
            const [scopedKey, responseJson, statusCode, createdAt] = this._params;
            rows.set(scopedKey, { response_json: responseJson, status_code: statusCode, created_at: createdAt });
          } else if (/DELETE FROM idempotency_keys/.test(this._sql)) {
            const [cutoff] = this._params;
            for (const [k, v] of rows) {
              if (v.created_at < cutoff) rows.delete(k);
            }
          }
          return { success: true };
        },
      };
    },
  };
}

describe('idempotency store + lookup', () => {
  it('returns null for unknown key', async () => {
    const db = mockDB();
    const res = await lookupIdempotentResponse(db, 'dlk1', 'key1');
    assert.equal(res, null);
  });

  it('round-trips: store then lookup returns the same response', async () => {
    const db = mockDB();
    const body = { id: 'txid-abc', status: 'pending' };
    await storeIdempotentResponse(db, 'dlk1', 'key1', 200, body);

    const res = await lookupIdempotentResponse(db, 'dlk1', 'key1');
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, body);
  });

  it('scopes keys by dlk (no cross-user collision)', async () => {
    const db = mockDB();
    const bodyA = { txid: 'a' };
    const bodyB = { txid: 'b' };
    await storeIdempotentResponse(db, 'dlk1', 'shared', 200, bodyA);
    await storeIdempotentResponse(db, 'dlk2', 'shared', 200, bodyB);

    const resA = await lookupIdempotentResponse(db, 'dlk1', 'shared');
    const resB = await lookupIdempotentResponse(db, 'dlk2', 'shared');
    assert.deepEqual(resA.body, bodyA);
    assert.deepEqual(resB.body, bodyB);
  });

  it('purges expired rows during lookup', async () => {
    const db = mockDB();
    // Manually insert an expired row (>24h old)
    const scopedKey = 'dlk1:old-key';
    const dayAgo = Date.now() - (25 * 60 * 60 * 1000);
    db._rows.set(scopedKey, { response_json: '{}', status_code: 200, created_at: dayAgo });
    assert.equal(db._rows.size, 1);

    const res = await lookupIdempotentResponse(db, 'dlk1', 'old-key');
    assert.equal(res, null, 'expired row should be treated as miss');
    assert.equal(db._rows.size, 0, 'expired row should be purged');
  });
});
