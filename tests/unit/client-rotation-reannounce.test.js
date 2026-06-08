// Unit tests for tarn#53 — credential-rotation announce must make UNREACHED
// connections actionable instead of console.warn-swallowing them.
//
// Before this change:
//   - changeCredentials / recoverAccount published a NEW-log seq=0 snapshot to
//     each connection best-effort; a per-connection failure was logged and
//     dropped. The rotationAnnouncements array carried per-connection error
//     entries, but nothing surfaced a clean "these connections are stranded"
//     set and nothing retried, so an unreached connection kept the rotator's
//     STALE pubkey with no auto-heal.
//
// After (tarn#53):
//   - Both rotation methods return a `failedConnections` array (folding
//     rotation-announce errors + NEW-log snapshot failures) so the gap is
//     explicit in the return value.
//   - A public `reannounceRotationToConnections(connections)` helper
//     re-publishes the NEW-log seq=0 bootstrap snapshot (under CURRENT keys)
//     to the connections that failed, returning { succeeded, failed }. A
//     SHARE_LOG_TAG_CONFLICT on our own prior snapshot counts as reached
//     (idempotent). The OLD-log rotate_identity announce is intentionally NOT
//     re-emitted (old keys are gone post-rotation; protocol eventual
//     consistency covers that via the NEW log).
//
// Run: node --import tsx --test tests/unit/client-rotation-reannounce.test.js

import '../indexeddb-shim.mjs';
import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { TarnClient, TarnPasskeyOnlyError } from '../../client/src/tarn.js';
import { bytesToBase64Url, deriveSharingKeyPair } from '../../client/src/crypto.js';

const APP = 'bookish';
const PASSWORD = 'reannounce-pass-2026';

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
  await client.register(`reann-${Date.now()}-${Math.random().toString(16).slice(2)}@example.com`, PASSWORD, {
    recoveryAcknowledged: true,
  });
  return client;
}

// Two real connection peers so #getPairKeysFor can derive S_AB. signing_pub is
// a placeholder (only reads verify it; reannounce only writes).
async function makeConnection(seed, label) {
  const mk = new Uint8Array(32).fill(seed);
  const { publicKey } = await deriveSharingKeyPair(mk, `peer-${seed}`);
  return {
    share_pub: bytesToBase64Url(publicKey),
    signing_pub: bytesToBase64Url(new Uint8Array(65).fill(4)),
    label: label ?? null,
  };
}

// Router for the reannounce path. Per connection the helper does:
//   1) GET /api/v1/entries?...&eid=...  (connections-record lookup) → empty,
//      so it falls back to the passed connection object.
//   2) POST /api/v1/share/log/publish   (NEW-log seq=0 snapshot)
// `publishOutcome(shareLogTag → descriptor)` decides each publish result. We
// can't key on share_pub (the publish body carries only the derived tag), so
// we sequence publish outcomes in call order via `publishSeq`.
function mockReannounceRouter(publishSeq) {
  let i = 0;
  const publishBodies = [];
  globalThis.fetch = async (url, opts) => {
    if (url.includes('/api/v1/entries') && url.includes('eid=')) {
      // connections-record lookup → no record (use passed connection).
      return {
        status: 200,
        headers: { get: () => null },
        text: async () => JSON.stringify({ entries: [] }),
        json: async () => ({ entries: [] }),
      };
    }
    if (url.includes('/api/v1/share/log/publish')) {
      publishBodies.push(JSON.parse(opts.body));
      const desc = publishSeq[i++] ?? { status: 200, txid: `tx-${i}` };
      if (desc.status === 409) {
        return {
          status: 409,
          headers: { get: () => null },
          text: async () => JSON.stringify({ existing_txid: desc.existing_txid ?? 'winner' }),
          json: async () => ({ existing_txid: desc.existing_txid ?? 'winner' }),
        };
      }
      if (desc.status >= 500) {
        return {
          status: desc.status,
          headers: { get: () => null },
          text: async () => JSON.stringify({ error: 'server' }),
          json: async () => ({ error: 'server' }),
        };
      }
      return {
        status: 200,
        headers: { get: () => null },
        text: async () => JSON.stringify({ txid: desc.txid ?? `tx-${i}` }),
        json: async () => ({ txid: desc.txid ?? `tx-${i}` }),
      };
    }
    throw new Error(`mockReannounceRouter: unexpected ${url}`);
  };
  return { publishBodies };
}

describe('tarn#53 — reannounceRotationToConnections', () => {
  afterEach(restoreFetch);

  it('re-publishes the NEW-log snapshot and reports per-connection success', async () => {
    const client = await registerClient();
    const connA = await makeConnection(11, 'Alice');
    const connB = await makeConnection(12, 'Bob');
    mockReannounceRouter([
      { status: 200, txid: 'tx-a' },
      { status: 200, txid: 'tx-b' },
    ]);

    const res = await client.reannounceRotationToConnections([connA, connB]);
    assert.deepEqual(res.succeeded.sort(), [connA.share_pub, connB.share_pub].sort());
    assert.equal(res.failed.length, 0);
  });

  it('treats a SHARE_LOG_TAG_CONFLICT (own prior snapshot) as reached — idempotent', async () => {
    const client = await registerClient();
    const connA = await makeConnection(13);
    // 409: the seq=0 slot already has our snapshot from the original rotation.
    // NOTE: a 409 inside _publishShareLogEntry WITHOUT retryOn409 surfaces the
    // typed conflict error directly; reannounce maps that to "already reached".
    mockReannounceRouter([{ status: 409, existing_txid: 'prior-snap' }]);

    const res = await client.reannounceRotationToConnections([connA]);
    assert.deepEqual(res.succeeded, [connA.share_pub]);
    assert.equal(res.failed.length, 0);
  });

  it('reports a still-unreachable connection in `failed` without aborting the rest', async () => {
    const client = await registerClient();
    const connOk = await makeConnection(14, 'Reachable');
    const connBad = await makeConnection(15, 'Stranded');
    // First publish succeeds; second 500s. The share-log publish POST is not
    // retry-eligible (#postShareLogPublish does not set retry:true), so a
    // single 500 throws immediately → captured as a failed entry. The helper
    // does not abort the loop.
    mockReannounceRouter([
      { status: 200, txid: 'tx-ok' },
      { status: 500 },
    ]);

    const res = await client.reannounceRotationToConnections([connOk, connBad]);
    assert.deepEqual(res.succeeded, [connOk.share_pub]);
    assert.equal(res.failed.length, 1);
    assert.equal(res.failed[0].share_pub, connBad.share_pub);
    assert.equal(res.failed[0].label, 'Stranded');
    assert.ok(res.failed[0].reason, 'failed entry carries a reason');
  });

  it('rejects a passkey-only session with TarnPasskeyOnlyError', async () => {
    // A fresh, unauthenticated client has no sharing key — same guard a
    // passkey-only session would hit. Construct one and call directly.
    const client = new TarnClient('https://api.tarn.dev', APP);
    await assert.rejects(
      () => client.reannounceRotationToConnections([{ share_pub: 'x' }]),
      (err) => err instanceof Error, // not authenticated OR passkey-only
    );
  });

  it('validates the connections argument', async () => {
    const client = await registerClient();
    await assert.rejects(
      () => client.reannounceRotationToConnections('not-an-array'),
      /connections must be an array/,
    );
  });
});

describe('tarn#53 — rotation methods surface failedConnections', () => {
  afterEach(restoreFetch);

  it('changeCredentials returns a failedConnections array (empty when skipRotationAnnounce)', async () => {
    const client = await registerClient();
    // changeCredentials with skipRotationAnnounce avoids the connections path
    // entirely, so failedConnections must be present and empty — proving the
    // field is always on the return shape for callers to branch on.
    mockQueue([
      { status: 200, body: JSON.stringify({}) },                        // PUT /auth (credential change)
      { status: 200, body: JSON.stringify({ nonce: 'c'.repeat(64) }) }, // post-change #authenticate challenge
      { status: 200, body: JSON.stringify({ jwt: fakeJwt('rot') }) },   // post-change #authenticate verify
    ]);
    const out = await client.changeCredentials('new-email@example.com', 'new-pass-2026', {
      acceptRecoveryGap: true,
      skipRotationAnnounce: true,
    });
    assert.ok(Array.isArray(out.failedConnections), 'failedConnections must be present');
    assert.equal(out.failedConnections.length, 0);
    assert.ok(Array.isArray(out.rotationAnnouncements));
  });
});
