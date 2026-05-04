// Unit tests for TarnClient retry behavior (tarn #7).
// Run: node --test tests/unit/client-retry.test.js

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient } from '../../client/src/tarn.js';

// ============ Fetch mocking ============

const originalFetch = globalThis.fetch;
let fetchCalls = [];
let fetchResponses = [];

function mockFetch(responses) {
  fetchCalls = [];
  fetchResponses = responses.slice();
  globalThis.fetch = async (url, opts) => {
    fetchCalls.push({ url, method: opts?.method || 'GET' });
    const next = fetchResponses.shift();
    if (!next) throw new Error(`mockFetch: no response queued for ${url}`);
    if (next instanceof Error) throw next;
    return {
      status: next.status,
      headers: { get: (name) => next.headers?.[name.toLowerCase()] ?? null },
      text: async () => next.body ?? '',
    };
  };
}

function restoreFetch() {
  globalThis.fetch = originalFetch;
  fetchCalls = [];
  fetchResponses = [];
}

// Canned auth-flow responses to complete the register → authenticate sequence
// after a successful /auth/register 201.
function authFlowSuccessResponses() {
  return [
    // challenge
    { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
    // verify
    { status: 200, body: JSON.stringify({ jwt: 'fake.jwt.token' }) },
  ];
}

function registerCountFrom(calls) {
  return calls.filter(c => c.url.endsWith('/auth/register') && c.method === 'POST').length;
}

// ============ Tests ============

describe('TarnClient retry — register (POST, retry:true)', () => {
  afterEach(restoreFetch);

  it('retries 503 then succeeds on 2nd attempt', async () => {
    mockFetch([
      { status: 503, body: '' },
      { status: 201, body: JSON.stringify({ data_lookup_key: 'a'.repeat(64) }) },
      ...authFlowSuccessResponses(),
    ]);

    const client = new TarnClient('https://api.tarn.dev', 'bookish');
    const result = await client.register('test@example.com', 'pw12345678', { recoveryAcknowledged: true });
    assert.equal(result.dataLookupKey.length, 64);
    assert.equal(registerCountFrom(fetchCalls), 2, 'register should retry exactly once');
  });

  it('does NOT retry 400 (permanent client error)', async () => {
    mockFetch([{ status: 400, body: JSON.stringify({ error: 'bad payload' }) }]);

    const client = new TarnClient('https://api.tarn.dev', 'bookish');
    await assert.rejects(() => client.register('test@example.com', 'pw12345678', { recoveryAcknowledged: true }));
    assert.equal(registerCountFrom(fetchCalls), 1, 'should not retry 400');
  });

  it('does NOT retry 409 (permanent conflict)', async () => {
    mockFetch([{ status: 409, body: JSON.stringify({ error: 'in use' }) }]);

    const client = new TarnClient('https://api.tarn.dev', 'bookish');
    await assert.rejects(() => client.register('test@example.com', 'pw12345678', { recoveryAcknowledged: true }));
    assert.equal(registerCountFrom(fetchCalls), 1, 'should not retry 409');
  });

  it('gives up after 3 attempts on persistent 503', async () => {
    mockFetch([
      { status: 503, body: '' },
      { status: 503, body: '' },
      { status: 503, body: '' },
    ]);

    const client = new TarnClient('https://api.tarn.dev', 'bookish');
    await assert.rejects(() => client.register('test@example.com', 'pw12345678', { recoveryAcknowledged: true }));
    assert.equal(registerCountFrom(fetchCalls), 3, 'should stop at MAX_ATTEMPTS');
  });

  it('retries on network error', async () => {
    mockFetch([
      new Error('ECONNRESET'),
      { status: 201, body: JSON.stringify({ data_lookup_key: 'b'.repeat(64) }) },
      ...authFlowSuccessResponses(),
    ]);

    const client = new TarnClient('https://api.tarn.dev', 'bookish');
    const result = await client.register('test@example.com', 'pw12345678', { recoveryAcknowledged: true });
    assert.equal(result.dataLookupKey.length, 64);
    assert.equal(registerCountFrom(fetchCalls), 2, 'should retry after network error');
  });

  it('honors Retry-After on 429', async () => {
    mockFetch([
      { status: 429, headers: { 'retry-after': '1' }, body: '' },
      { status: 201, body: JSON.stringify({ data_lookup_key: 'c'.repeat(64) }) },
      ...authFlowSuccessResponses(),
    ]);

    const client = new TarnClient('https://api.tarn.dev', 'bookish');
    const t0 = Date.now();
    const result = await client.register('test@example.com', 'pw12345678', { recoveryAcknowledged: true });
    const elapsed = Date.now() - t0;
    assert.equal(result.dataLookupKey.length, 64);
    assert.ok(elapsed >= 900, `should wait ≥1s per Retry-After (waited ${elapsed}ms)`);
  });
});
