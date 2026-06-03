// Unit tests for the per-account read rate limit (tarn#31).
//
// Verifies:
//   - The bucket key is shaped `read:<data_lookup_key>:<hour>` (mirroring the
//     write path's `write:<dlk>:<hour>` — explicitly NOT keyed on IP).
//   - Two accounts sharing the same simulated client IP each get their own
//     1000/hr bucket (the noisy-neighbor scenario from the issue body).
//   - The per-IP helper, kept for the txid-only metadata-lookup case, uses
//     a distinct `read-ip:<ipHash>:<hour>` keyspace so it can't collide with
//     account buckets.
//
// Run: node --test tests/unit/rate-limit-reads.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkReadRateLimitByAccount,
  checkReadRateLimitByIp,
  _testing,
} from '../../api/src/rate_limit.js';

// ============ KV mock ============
//
// Mirrors the shape used by rate-limit.js: get(key) -> string|null,
// put(key, value, options). Keys are stored in a Map so tests can inspect
// what got written (and assert which key was hit).

function mockKV() {
  const store = new Map();
  return {
    _store: store,
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, value /*, options */) {
      store.set(key, value);
    },
  };
}

function mockEnv() {
  return { RATE_KV: mockKV() };
}

function mockRequest(ip) {
  return {
    headers: {
      get(name) {
        return name === 'CF-Connecting-IP' ? ip : null;
      },
    },
  };
}

// Bucket-key shape mirrors rate_limit.js exactly. Used to assert the right
// key was written for each call site without relying on internal export.
function expectedAccountKey(dlk) {
  const hour = new Date().toISOString().slice(0, 13);
  return `read:${dlk}:${hour}`;
}

// ============ Tests ============

describe('checkReadRateLimitByAccount', () => {
  it('buckets reads under read:<dlk>:<hour>, mirroring the write path', async () => {
    const env = mockEnv();
    const dlk = 'a'.repeat(32);
    const result = await checkReadRateLimitByAccount(env, dlk);

    assert.equal(result.allowed, true);
    assert.equal(result.remaining, _testing.MAX_READS_PER_HOUR_PER_ACCOUNT - 1);

    // The KV write must use the per-account key shape (no IP hash anywhere).
    const writtenKeys = Array.from(env.RATE_KV._store.keys());
    assert.equal(writtenKeys.length, 1);
    assert.equal(writtenKeys[0], expectedAccountKey(dlk));
    assert.ok(!writtenKeys[0].includes('ip'), 'account-keyed bucket must not contain "ip"');
  });

  it('increments the same bucket on repeated calls for the same dlk', async () => {
    const env = mockEnv();
    const dlk = 'b'.repeat(32);
    const r1 = await checkReadRateLimitByAccount(env, dlk);
    const r2 = await checkReadRateLimitByAccount(env, dlk);
    const r3 = await checkReadRateLimitByAccount(env, dlk);

    assert.equal(r1.remaining, _testing.MAX_READS_PER_HOUR_PER_ACCOUNT - 1);
    assert.equal(r2.remaining, _testing.MAX_READS_PER_HOUR_PER_ACCOUNT - 2);
    assert.equal(r3.remaining, _testing.MAX_READS_PER_HOUR_PER_ACCOUNT - 3);
    // Single bucket, regardless of call count.
    assert.equal(env.RATE_KV._store.size, 1);
  });

  it('returns allowed=false once the per-account cap is hit', async () => {
    const env = mockEnv();
    const dlk = 'c'.repeat(32);
    // Pre-seed the counter at the cap.
    env.RATE_KV._store.set(
      expectedAccountKey(dlk),
      String(_testing.MAX_READS_PER_HOUR_PER_ACCOUNT),
    );
    const result = await checkReadRateLimitByAccount(env, dlk);
    assert.equal(result.allowed, false);
    assert.equal(result.remaining, 0);
  });

  // The headline tarn#31 scenario: two users behind the same NAT must NOT
  // share a bucket. Per-IP keying made every customer in a coffee shop
  // share one 300/hr quota. Per-account keying restores isolation.
  it('two accounts on the same simulated IP get independent buckets', async () => {
    const env = mockEnv();
    const dlkA = 'aaaa'.repeat(8);
    const dlkB = 'bbbb'.repeat(8);

    // Burn 500 reads on account A. If we were keyed on IP, this would
    // consume half of B's budget too.
    for (let i = 0; i < 500; i++) {
      const r = await checkReadRateLimitByAccount(env, dlkA);
      assert.equal(r.allowed, true);
    }

    // First read for account B should see a fresh budget — none of A's
    // 500 reads count against it.
    const firstForB = await checkReadRateLimitByAccount(env, dlkB);
    assert.equal(firstForB.allowed, true);
    assert.equal(
      firstForB.remaining,
      _testing.MAX_READS_PER_HOUR_PER_ACCOUNT - 1,
      'account B must start with a full bucket regardless of account A traffic',
    );

    // Two distinct buckets in KV — one per account.
    const keys = Array.from(env.RATE_KV._store.keys()).sort();
    assert.equal(keys.length, 2);
    assert.deepEqual(keys, [expectedAccountKey(dlkA), expectedAccountKey(dlkB)].sort());
  });
});

describe('checkReadRateLimitByIp', () => {
  it('uses a distinct keyspace (read-ip:*) from the per-account path', async () => {
    const env = mockEnv();
    const result = await checkReadRateLimitByIp(env, mockRequest('203.0.113.1'));

    assert.equal(result.allowed, true);
    const keys = Array.from(env.RATE_KV._store.keys());
    assert.equal(keys.length, 1);
    assert.ok(
      keys[0].startsWith('read-ip:'),
      `expected read-ip: prefix, got "${keys[0]}"`,
    );
    // Must not collide with an account-keyed bucket of the form read:<dlk>:<hour>
    assert.ok(!keys[0].match(/^read:[^-]/), 'must not look like read:<dlk>:<hour>');
  });

  it('hashes the IP so the raw address is not stored as the key', async () => {
    const env = mockEnv();
    const ip = '198.51.100.42';
    await checkReadRateLimitByIp(env, mockRequest(ip));
    const [key] = Array.from(env.RATE_KV._store.keys());
    assert.ok(!key.includes(ip), 'raw IP must not appear in the bucket key');
  });

  it('falls back to "unknown" when CF-Connecting-IP is absent', async () => {
    const env = mockEnv();
    // No header → IP is "unknown" — same digest for every such caller, which
    // is the existing behavior. Just confirm we don't crash.
    const result = await checkReadRateLimitByIp(env, mockRequest(null));
    assert.equal(result.allowed, true);
  });
});

describe('cap constants (tarn#31 acceptance)', () => {
  it('per-account read cap is at least 1000/hr', () => {
    // Issue body suggests 1000–3000 to start. Lock the floor so we don't
    // accidentally regress below the documented value.
    assert.ok(
      _testing.MAX_READS_PER_HOUR_PER_ACCOUNT >= 1000,
      `per-account cap is ${_testing.MAX_READS_PER_HOUR_PER_ACCOUNT}, expected ≥ 1000`,
    );
  });

  it('write cap is unchanged at 100/hr', () => {
    // The read change must not have touched the write side.
    assert.equal(_testing.MAX_WRITES_PER_HOUR, 100);
  });
});
