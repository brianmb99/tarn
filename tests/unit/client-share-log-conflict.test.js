// Unit tests for tarn#52 — multi-device share-log write race resilience.
//
// _publishShareLogEntry seeds nextOutboundSeq once per session then increments
// locally. Two devices on the same connection both target seq_max+1; one wins,
// the loser gets a 409 (SHARE_LOG_TAG_CONFLICT), re-discovers the highest seq,
// and retries. A burst could exhaust the retry budget and throw a GENERIC
// Error, so callers couldn't tell a recoverable conflict storm apart from a
// hard failure.
//
// After (tarn#52):
//   - Bounded exponential backoff + full jitter between conflict retries (so
//     concurrent writers de-sync instead of retrying in lockstep). The sleep
//     is injectable via opts._sleep for deterministic tests.
//   - The retry budget is configurable (opts.maxRetries) and the default was
//     raised 5 → 8.
//   - Genuine exhaustion throws a TYPED TarnShareLogConflictError carrying
//     attempts / operationType / lastConflictSeq, with a message stating the
//     publish is safe to retry (no seq reused).
//   - Correctness preserved: the local counter advances past every lost slot,
//     so a subsequent publish reuses no seq.
//
// Run: node --import tsx --test tests/unit/client-share-log-conflict.test.js

import '../indexeddb-shim.mjs';
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  TarnClient,
  TarnShareLogConflictError,
} from '../../client/src/tarn.js';
import { bytesToBase64Url, deriveSharingKeyPair } from '../../client/src/crypto.js';

const APP = 'bookish';
const PASSWORD = 'share-log-conflict-pass-2026';

const originalFetch = globalThis.fetch;

function fakeJwt(label = 'jwt') {
  const b64url = (s) => btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const header = b64url('{"alg":"none"}');
  const payload = b64url(JSON.stringify({ sub: label, exp: Math.floor(Date.now() / 1000) + 3600 }));
  return `${header}.${payload}.`;
}

function uniqueDlk() {
  return Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
}

// A valid 32-byte base64url CEK (buildOperationUnsigned validates the shape).
function fakeCek(fill = 1) {
  return bytesToBase64Url(new Uint8Array(32).fill(fill));
}

// A well-formed `add` operation (omit seq — _publishShareLogEntry assigns it).
function addOp(contentId, txId, cekFill) {
  return {
    type: 'add',
    content_id: contentId,
    tx_id: txId,
    cek: fakeCek(cekFill),
    shared_at: Math.floor(Date.now() / 1000),
  };
}

function restoreFetch() {
  globalThis.fetch = originalFetch;
}

function mockQueue(responses) {
  const q = responses.slice();
  const calls = [];
  globalThis.fetch = async (url, opts) => {
    calls.push({ url, method: opts?.method || 'GET', body: opts?.body });
    const next = q.shift();
    if (!next) throw new Error(`mockQueue: no response queued for ${url}`);
    return {
      status: next.status,
      headers: { get: () => null },
      text: async () => next.body ?? '',
      json: async () => { try { return JSON.parse(next.body ?? ''); } catch { return null; } },
    };
  };
  return calls;
}

async function registerClient() {
  mockQueue([
    { status: 201, body: JSON.stringify({ data_lookup_key: uniqueDlk() }) },
    { status: 200, body: JSON.stringify({ nonce: 'a'.repeat(64) }) },
    { status: 200, body: JSON.stringify({ jwt: fakeJwt('reg') }) },
  ]);
  const client = new TarnClient('https://api.tarn.dev', APP);
  await client.register(`conflict-${Date.now()}-${Math.random().toString(16).slice(2)}@example.com`, PASSWORD, {
    recoveryAcknowledged: true,
  });
  return client;
}

// A real connection peer keypair, so #getPairKeysFor can derive S_AB without
// throwing. The signing_pub is unimportant for the WRITE path (only reads
// verify it), so a placeholder is fine.
async function makeConnection() {
  const mk = new Uint8Array(32).fill(9);
  const { publicKey } = await deriveSharingKeyPair(mk, 'peer-for-conflict-test');
  return {
    share_pub: bytesToBase64Url(publicKey),
    signing_pub: bytesToBase64Url(new Uint8Array(65).fill(4)),
  };
}

// Router that always 409s the publish (with a winner txid we never published,
// so the own-publish short-circuit does NOT fire) and 404s every discovery
// probe (so re-discovery resolves to "highest = anchor-1" and the counter
// advances by exactly 1 each retry — deterministic).
function mockConflictRouter() {
  let publishCalls = 0;
  let probeCalls = 0;
  globalThis.fetch = async (url, opts) => {
    if (url.includes('/api/v1/share/log/publish')) {
      publishCalls++;
      return {
        status: 409,
        headers: { get: () => null },
        text: async () => JSON.stringify({ existing_txid: `winner-tx-${publishCalls}` }),
        json: async () => ({ existing_txid: `winner-tx-${publishCalls}` }),
      };
    }
    if (url.includes('/api/v1/share/log/fetch')) {
      probeCalls++;
      return {
        status: 404,
        headers: { get: () => null },
        text: async () => JSON.stringify({ error: 'not_found' }),
        json: async () => ({ error: 'not_found' }),
      };
    }
    throw new Error(`mockConflictRouter: unexpected ${url}`);
  };
  return { stats: () => ({ publishCalls, probeCalls }) };
}

describe('tarn#52 — share-log conflict-storm resilience', () => {
  afterEach(restoreFetch);

  it('applies backoff between retries and throws TarnShareLogConflictError on exhaustion', async () => {
    const client = await registerClient();
    const connection = await makeConnection();
    const router = mockConflictRouter();

    const sleeps = [];
    const spySleep = async (ms) => { sleeps.push(ms); };

    const maxRetries = 4;
    let caught;
    try {
      await client._publishShareLogEntry(
        connection,
        addOp('book:1', 'tx-1', 1),
        { retryOn409: true, maxRetries, _sleep: spySleep },
      );
    } catch (err) {
      caught = err;
    }

    // Typed terminal error, not a generic Error.
    assert.ok(caught, '_publishShareLogEntry must throw on a sustained conflict storm');
    assert.ok(
      caught instanceof TarnShareLogConflictError,
      `expected TarnShareLogConflictError, got ${caught?.name}: ${caught?.message}`,
    );
    assert.equal(caught.attempts, maxRetries);
    assert.equal(caught.operationType, 'add');
    assert.equal(typeof caught.lastConflictSeq, 'number');
    assert.match(caught.message, /safe to retry/i);
    assert.match(caught.message, /multi-device write race/i);

    // Backoff fired once per retry (exactly maxRetries pauses before the
    // budget-exhaustion throw on attempt maxRetries+1).
    assert.equal(sleeps.length, maxRetries, `expected ${maxRetries} backoff pauses, got ${sleeps.length}`);
    for (const ms of sleeps) {
      assert.ok(ms >= 0, 'backoff must be non-negative');
    }
    // Bounded: full-jitter curve caps at SHARE_LOG_CONFLICT_MAX_MS (3000).
    for (const ms of sleeps) {
      assert.ok(ms <= 3000, `backoff ${ms}ms exceeds the 3s cap`);
    }

    // Sanity: the publish was attempted maxRetries+1 times (initial + retries).
    assert.equal(router.stats().publishCalls, maxRetries + 1);
  });

  it('respects a custom maxRetries budget', async () => {
    const client = await registerClient();
    const connection = await makeConnection();
    const router = mockConflictRouter();

    const sleeps = [];
    await assert.rejects(
      () => client._publishShareLogEntry(
        connection,
        addOp('book:2', 'tx-2', 2),
        { retryOn409: true, maxRetries: 2, _sleep: async (ms) => { sleeps.push(ms); } },
      ),
      (err) => err instanceof TarnShareLogConflictError && err.attempts === 2,
    );
    assert.equal(sleeps.length, 2);
    assert.equal(router.stats().publishCalls, 3); // initial + 2 retries
  });

  it('advances the local seq past every lost slot — no seq reuse across retries', async () => {
    // Capture the seq baked into each publish attempt by deriving the seq from
    // discovery: with 404 probes, re-discovery yields highest=anchor-1 so the
    // counter advances by exactly 1 per retry. We assert the publish tag is
    // distinct each attempt (a tag is derived from seq), proving no reuse.
    const client = await registerClient();
    const connection = await makeConnection();

    const tags = [];
    globalThis.fetch = async (url, opts) => {
      if (url.includes('/api/v1/share/log/publish')) {
        const body = JSON.parse(opts.body);
        tags.push(body.tag);
        return {
          status: 409,
          headers: { get: () => null },
          text: async () => JSON.stringify({ existing_txid: `winner-${tags.length}` }),
          json: async () => ({ existing_txid: `winner-${tags.length}` }),
        };
      }
      if (url.includes('/api/v1/share/log/fetch')) {
        return {
          status: 404,
          headers: { get: () => null },
          text: async () => JSON.stringify({ error: 'not_found' }),
          json: async () => ({ error: 'not_found' }),
        };
      }
      throw new Error(`unexpected ${url}`);
    };

    await assert.rejects(
      () => client._publishShareLogEntry(
        connection,
        addOp('book:3', 'tx-3', 3),
        { retryOn409: true, maxRetries: 3, _sleep: async () => {} },
      ),
      (err) => err instanceof TarnShareLogConflictError,
    );

    // 4 publish attempts (initial + 3 retries), each at a strictly increasing
    // seq → 4 DISTINCT tags. A reused seq would repeat a tag.
    assert.equal(tags.length, 4);
    assert.equal(new Set(tags).size, 4, 'every retry must publish at a fresh seq (distinct tag) — no reuse');
  });

  it('succeeds on the first try with no backoff when there is no conflict', async () => {
    const client = await registerClient();
    const connection = await makeConnection();

    mockQueue([
      { status: 200, body: JSON.stringify({ txid: 'tx-clean' }) },
    ]);
    const sleeps = [];
    const res = await client._publishShareLogEntry(
      connection,
      addOp('book:4', 'tx-4', 4),
      { retryOn409: true, maxRetries: 5, _sleep: async (ms) => { sleeps.push(ms); }, skipCompaction: true },
    );
    assert.equal(res.txid, 'tx-clean');
    assert.equal(sleeps.length, 0, 'no backoff when the first publish succeeds');
  });
});
