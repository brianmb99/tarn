// Unit tests for TarnClient retry behavior (tarn #7, tarn #29).
// Run: node --test tests/unit/client-retry.test.js

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient, TarnRateLimitError } from '../../client/src/tarn.js';

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

  // tarn#29: 429 must NOT retry. The SDK throws TarnRateLimitError on the
  // first response so the caller can schedule a retry per Retry-After
  // instead of amplifying the rate-limit hit 3x.
  it('does NOT retry on 429 and throws TarnRateLimitError with Retry-After', async () => {
    mockFetch([
      { status: 429, headers: { 'retry-after': '42' }, body: JSON.stringify({ error: 'rate-limited' }) },
    ]);

    const client = new TarnClient('https://api.tarn.dev', 'bookish');
    let caught;
    try {
      await client.register('test@example.com', 'pw12345678', { recoveryAcknowledged: true });
    } catch (err) {
      caught = err;
    }
    assert.ok(caught instanceof TarnRateLimitError, `expected TarnRateLimitError, got ${caught?.name}: ${caught?.message}`);
    assert.equal(caught.retryAfterSeconds, 42);
    assert.equal(caught.status, 429);
    assert.equal(registerCountFrom(fetchCalls), 1, '429 must NOT be retried (tarn#29)');
  });

  it('does NOT retry on 429 and surfaces null retryAfterSeconds when header is absent', async () => {
    mockFetch([
      { status: 429, body: JSON.stringify({ error: 'rate-limited' }) },
    ]);

    const client = new TarnClient('https://api.tarn.dev', 'bookish');
    let caught;
    try {
      await client.register('test@example.com', 'pw12345678', { recoveryAcknowledged: true });
    } catch (err) {
      caught = err;
    }
    assert.ok(caught instanceof TarnRateLimitError);
    assert.equal(caught.retryAfterSeconds, null);
    assert.equal(registerCountFrom(fetchCalls), 1);
  });

  it('does NOT retry on 429 with HTTP-date Retry-After (parsed to seconds)', async () => {
    const future = new Date(Date.now() + 30_000).toUTCString();
    mockFetch([
      { status: 429, headers: { 'retry-after': future }, body: '' },
    ]);

    const client = new TarnClient('https://api.tarn.dev', 'bookish');
    let caught;
    try {
      await client.register('test@example.com', 'pw12345678', { recoveryAcknowledged: true });
    } catch (err) {
      caught = err;
    }
    assert.ok(caught instanceof TarnRateLimitError);
    // ~30s; allow 5s of slack for clock drift in CI.
    assert.ok(caught.retryAfterSeconds >= 25 && caught.retryAfterSeconds <= 35,
      `expected ~30s, got ${caught.retryAfterSeconds}`);
    assert.equal(registerCountFrom(fetchCalls), 1);
  });

  it('5xx retry behavior unchanged when interleaved with 429-like setup (sanity)', async () => {
    // Ensure removing 429 from the retry path did not regress 5xx retries.
    mockFetch([
      { status: 503, body: '' },
      { status: 201, body: JSON.stringify({ data_lookup_key: 'd'.repeat(64) }) },
      ...authFlowSuccessResponses(),
    ]);

    const client = new TarnClient('https://api.tarn.dev', 'bookish');
    const result = await client.register('test@example.com', 'pw12345678', { recoveryAcknowledged: true });
    assert.equal(result.dataLookupKey.length, 64);
    assert.equal(registerCountFrom(fetchCalls), 2);
  });
});
