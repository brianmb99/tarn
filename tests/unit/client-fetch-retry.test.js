// Regression + 429-no-retry tests for the executeFetch helper.
//
// History:
//   - Original bug (pre-tarn#29): executeFetch retried 429 with body-cancel
//     happening BEFORE the long-Retry-After short-circuit, which left
//     callers holding a consumed body. The first fix moved the cancel
//     below the early return.
//   - tarn#29: stopped retrying 429 entirely — retrying a rate-limit signal
//     amplifies the problem. The SDK now throws `TarnRateLimitError`
//     directly from #executeFetch with any Retry-After value attached.
//
// These tests pin the post-tarn#29 contract: any 429 → exactly one fetch,
// typed error reaches the caller, body of the 429 is captured into the
// error; 5xx and 4xx behavior is unchanged.
//
// Run: node --test tests/unit/client-fetch-retry.test.js

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient, TarnRateLimitError } from '../../client/src/tarn.js';

const originalFetch = globalThis.fetch;

function mockFetch(handler) {
  globalThis.fetch = handler;
}
function restoreFetch() {
  globalThis.fetch = originalFetch;
}

function makeResponse(body, status = 200, headers = {}) {
  return new Response(body, { status, headers });
}

describe('executeFetch — 429 handling (tarn#29)', () => {
  afterEach(restoreFetch);

  it('throws TarnRateLimitError on first 429 with Retry-After captured', async () => {
    // login() drives #executeFetch through the GET-eligible path. The first
    // call (auth/challenge) is retry-safe; we make it return 429 + Retry-After
    // 3600. Per tarn#29 the SDK must not retry: exactly one network call
    // and the caller gets a typed TarnRateLimitError carrying the seconds.
    let challengeCalls = 0;
    mockFetch(async (url) => {
      if (url.endsWith('/auth/challenge')) {
        challengeCalls++;
        return makeResponse(
          JSON.stringify({ error: 'rate-limited', retry_after: 3600 }),
          429,
          { 'Retry-After': '3600', 'Content-Type': 'application/json' },
        );
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    const client = new TarnClient('https://api.tarn.dev', 'bookish');
    let caught;
    try {
      await client.login('rate-limit-test@example.com', 'pw-2026');
    } catch (err) {
      caught = err;
    }

    assert.ok(caught instanceof TarnRateLimitError,
      `expected TarnRateLimitError, got ${caught?.name}: ${caught?.message}`);
    assert.equal(caught.retryAfterSeconds, 3600);
    assert.equal(caught.status, 429);
    assert.match(caught.responseBody, /rate-limited/);
    // Regression guard: the old body-cancel bug surfaced as this string.
    assert.doesNotMatch(
      caught.message,
      /body is unusable|already been read/i,
      `error message must not be the body-already-consumed bug; got: ${caught.message}`,
    );
    assert.equal(challengeCalls, 1, '429 must NOT be retried (tarn#29)');
  });

  it('throws TarnRateLimitError on 429 without Retry-After (retryAfterSeconds: null)', async () => {
    let challengeCalls = 0;
    mockFetch(async (url) => {
      if (url.endsWith('/auth/challenge')) {
        challengeCalls++;
        return makeResponse(
          JSON.stringify({ error: 'rate-limited' }),
          429,
          { 'Content-Type': 'application/json' },
        );
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    const client = new TarnClient('https://api.tarn.dev', 'bookish');
    let caught;
    try {
      await client.login('rate-limit-test@example.com', 'pw-2026');
    } catch (err) {
      caught = err;
    }

    assert.ok(caught instanceof TarnRateLimitError);
    assert.equal(caught.retryAfterSeconds, null);
    assert.equal(challengeCalls, 1, '429 still must not be retried');
  });

  it('still retries 5xx responses (sanity — fix did not regress the retry path)', async () => {
    // Three 503s in a row should produce three calls (initial + 2 retries),
    // each with its body cancelled cleanly. The third (final) response is
    // returned and the caller can .text() it without throwing.
    let challengeCalls = 0;
    mockFetch(async (url) => {
      if (url.endsWith('/auth/challenge')) {
        challengeCalls++;
        return makeResponse(
          JSON.stringify({ error: 'service unavailable' }),
          503,
          { 'Content-Type': 'application/json' },
        );
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    const client = new TarnClient('https://api.tarn.dev', 'bookish');
    let caught;
    try {
      await client.login('retry-test@example.com', 'pw-2026');
    } catch (err) {
      caught = err;
    }

    assert.ok(caught, 'login should surface an error after retries exhaust');
    assert.doesNotMatch(caught.message, /body is unusable/i);
    assert.equal(challengeCalls, 3, '5xx should produce 3 attempts (initial + 2 retries)');
  }).slow = true;

  it('non-retry status (4xx other than 429) returns Response with body intact', async () => {
    // A 404 is not transient — return immediately, body untouched.
    let challengeCalls = 0;
    mockFetch(async (url) => {
      if (url.endsWith('/auth/challenge')) {
        challengeCalls++;
        return makeResponse(
          JSON.stringify({ error: 'not_found' }),
          404,
          { 'Content-Type': 'application/json' },
        );
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    const client = new TarnClient('https://api.tarn.dev', 'bookish');
    let caught;
    try {
      await client.login('not-a-user@example.com', 'pw-2026');
    } catch (err) {
      caught = err;
    }

    assert.ok(caught);
    assert.doesNotMatch(caught.message, /body is unusable/i);
    assert.match(caught.message, /not found/i);
    assert.equal(challengeCalls, 1);
  });
});
