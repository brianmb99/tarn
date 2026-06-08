// Unit tests for api/src/observability/funding.js — Turbo balance fetch
// (mocked) + the runway / LOW_FUNDING threshold logic.
//
// Run: node --test tests/unit/observability-funding.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  fetchTurboBalance,
  assessRunway,
  DEFAULT_RUNWAY_FLOOR_DAYS,
} from '../../api/src/observability/funding.js';

// ============ fetchTurboBalance (mocked fetch) ============

function mockFetch(handler) {
  return async (url, opts) => handler(url, opts);
}

describe('fetchTurboBalance', () => {
  it('returns no_address when address is missing', async () => {
    const r = await fetchTurboBalance(null, { fetchImpl: mockFetch(() => { throw new Error('should not call'); }) });
    assert.equal(r.ok, false);
    assert.equal(r.error, 'no_address');
  });

  it('parses effectiveBalance preferentially', async () => {
    const r = await fetchTurboBalance('0xabc', {
      fetchImpl: mockFetch(async () => ({
        ok: true,
        status: 200,
        json: async () => ({ winc: '999', controlledWinc: '1000', effectiveBalance: '750' }),
      })),
    });
    assert.equal(r.ok, true);
    assert.equal(r.winc, 750);
  });

  it('falls back to winc when effectiveBalance absent', async () => {
    const r = await fetchTurboBalance('0xabc', {
      fetchImpl: mockFetch(async () => ({ ok: true, status: 200, json: async () => ({ winc: '4242' }) })),
    });
    assert.equal(r.ok, true);
    assert.equal(r.winc, 4242);
  });

  it('treats a 404 (never-funded wallet) as zero balance, not an error', async () => {
    const r = await fetchTurboBalance('0xnew', {
      fetchImpl: mockFetch(async () => ({ ok: false, status: 404, json: async () => ({}) })),
    });
    assert.equal(r.ok, true);
    assert.equal(r.winc, 0);
  });

  it('reports http_<status> for other non-OK responses', async () => {
    const r = await fetchTurboBalance('0xabc', {
      fetchImpl: mockFetch(async () => ({ ok: false, status: 500, json: async () => ({}) })),
    });
    assert.equal(r.ok, false);
    assert.equal(r.error, 'http_500');
  });

  it('never throws on a network failure — returns ok:false', async () => {
    const r = await fetchTurboBalance('0xabc', {
      fetchImpl: mockFetch(async () => { throw new Error('boom'); }),
    });
    assert.equal(r.ok, false);
    assert.equal(r.error, 'boom');
  });

  it('reports unparseable_balance when the field is not numeric', async () => {
    const r = await fetchTurboBalance('0xabc', {
      fetchImpl: mockFetch(async () => ({ ok: true, status: 200, json: async () => ({ winc: 'not-a-number' }) })),
    });
    assert.equal(r.ok, false);
    assert.equal(r.error, 'unparseable_balance');
  });
});

// ============ assessRunway (pure threshold logic) ============

describe('assessRunway', () => {
  it('flags LOW_FUNDING when runway < floor', () => {
    // burn: 10 writes * 100 winc / 7 days = ~142.86 winc/day.
    // balance 1000 winc => runway ~7 days, under the 14-day floor.
    const r = assessRunway({
      balanceWinc: 1000,
      wincPer100kb: 100,
      recentPaidWrites: 10,
      windowDays: 7,
      runwayFloorDays: 14,
    });
    assert.equal(r.lowFunding, true);
    assert.ok(r.runwayDays < 14, `runway ${r.runwayDays} should be < 14`);
    assert.match(r.reason, /runway/);
  });

  it('does NOT flag when runway comfortably exceeds the floor', () => {
    // Same burn (~142.86/day) but balance 1,000,000 => runway ~7000 days.
    const r = assessRunway({
      balanceWinc: 1_000_000,
      wincPer100kb: 100,
      recentPaidWrites: 10,
      windowDays: 7,
      runwayFloorDays: 14,
    });
    assert.equal(r.lowFunding, false);
    assert.ok(r.runwayDays > 14);
  });

  it('with zero recent writes, runway is Infinity and runway-floor does not fire', () => {
    const r = assessRunway({
      balanceWinc: 1, // tiny balance...
      wincPer100kb: 100,
      recentPaidWrites: 0, // ...but no burn
      windowDays: 7,
      runwayFloorDays: 14,
    });
    assert.equal(r.dailyBurnWinc, 0);
    assert.equal(r.runwayDays, Infinity);
    assert.equal(r.lowFunding, false, 'no burn => runway floor cannot fire');
  });

  it('the absolute minBalance floor fires even when burn is zero', () => {
    const r = assessRunway({
      balanceWinc: 50,
      wincPer100kb: 100,
      recentPaidWrites: 0,
      windowDays: 7,
      runwayFloorDays: 14,
      minBalanceWinc: 100, // absolute floor
    });
    assert.equal(r.lowFunding, true, 'balance below absolute floor must fire');
    assert.match(r.reason, /floor/);
  });

  it('minBalance floor of 0 (default) is disabled', () => {
    const r = assessRunway({
      balanceWinc: 0,
      wincPer100kb: 100,
      recentPaidWrites: 0,
      windowDays: 7,
      runwayFloorDays: 14,
      minBalanceWinc: 0,
    });
    // Balance is 0 but no burn and no absolute floor => not flagged.
    assert.equal(r.lowFunding, false);
  });

  it('treats unknown price (null) as zero burn (no runway alarm)', () => {
    const r = assessRunway({
      balanceWinc: 1,
      wincPer100kb: null, // price endpoint failed
      recentPaidWrites: 1000,
      windowDays: 7,
      runwayFloorDays: 14,
    });
    assert.equal(r.dailyBurnWinc, 0);
    assert.equal(r.runwayDays, Infinity);
    assert.equal(r.lowFunding, false);
  });

  it('handles a non-finite balance defensively as 0', () => {
    const r = assessRunway({
      balanceWinc: NaN,
      wincPer100kb: 100,
      recentPaidWrites: 10,
      windowDays: 7,
      runwayFloorDays: 14,
    });
    assert.equal(r.balanceWinc, 0);
    assert.equal(r.runwayDays, 0);
    assert.equal(r.lowFunding, true);
  });

  it('uses DEFAULT_RUNWAY_FLOOR_DAYS when floor omitted', () => {
    // burn ~142.86/day, balance sized to land just under the default floor.
    const dailyBurn = (100 * 10) / 7;
    const balanceWinc = dailyBurn * (DEFAULT_RUNWAY_FLOOR_DAYS - 1);
    const r = assessRunway({ balanceWinc, wincPer100kb: 100, recentPaidWrites: 10, windowDays: 7 });
    assert.equal(r.lowFunding, true);
    assert.ok(r.runwayDays < DEFAULT_RUNWAY_FLOOR_DAYS);
  });
});
