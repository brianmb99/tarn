// Regression test for the executeFetch retry-loop body-cancellation bug.
//
// Before the fix: when the server returned 429 with Retry-After > 60 seconds,
// executeFetch cancelled the response body BEFORE checking the long-retry
// short-circuit. That meant the Response handed back to the caller had a
// consumed body, and the next .text() / .json() call threw
// "Body is unusable: Body has already been read".
//
// After the fix: cancel only fires when we're committed to a retry. The
// Retry-After-too-long path returns the Response with its body intact.
//
// We exercise this through TarnClient's auth-challenge endpoint, which runs
// through #executeFetch with retry-eligible status. A 429 with Retry-After:
// 3600 is the smallest reproducer that both proves the bug existed and that
// the fix sticks.
//
// Run: node --test tests/unit/client-fetch-retry.test.js

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient } from '../../client/src/tarn.js';

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

describe('executeFetch — retry body handling (regression)', () => {
  afterEach(restoreFetch);

  it('returns a body-readable Response on 429 with Retry-After > 60s', async () => {
    // login() drives #executeFetch through the GET-eligible path. The first
    // call (auth/challenge) is retry-safe; we make it return 429 + Retry-After
    // 3600. Pre-fix, the long-retry path cancelled the body before the early
    // return, and the Body.text() inside #fetch threw "Body has already been
    // read". Post-fix, the body stays readable, the JSON parse succeeds, and
    // login surfaces the 429 as a normal error.
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

    assert.ok(caught, 'login should surface an error on 429');
    // The CRITICAL assertion: the error is the upstream 429 message, NOT
    // "Body is unusable". Pre-fix this would be "Body is unusable: Body has
    // already been read".
    assert.doesNotMatch(
      caught.message,
      /body is unusable|already been read/i,
      `error message must not be the body-already-consumed bug; got: ${caught.message}`,
    );
    // And the retry didn't kick in (Retry-After 3600 short-circuits the loop).
    assert.equal(challengeCalls, 1, 'long Retry-After should NOT trigger a retry');
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
