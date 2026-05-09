/**
 * Cross-validate `recover()` against the live SDK.
 *
 * The load-bearing test for Phase 4: it proves that bytes the production
 * SDK encrypts can be decrypted end-to-end by the standalone recover
 * package. If wire formats drift between the writer and reader, this
 * test fails.
 *
 * Flow:
 *   1. Boot a real `TarnClient` against a running `wrangler dev`.
 *   2. `register()` an account, `createEntry()` content blobs.
 *      The SDK runs the production envelope + AES-KW + per-content-CEK
 *      paths and the bytes land in D1 via the write-through.
 *   3. Pull the encrypted bytes + tags back via the public unauthenticated
 *      `/api/v1/entries/{txid}` endpoint, and the wrapped envelope via
 *      the recovery-flow `/api/v1/auth/challenge` endpoint.
 *   4. Stage everything into an in-process mock Arweave gateway.
 *   5. Run `recover()` against the mock with both credential factors.
 *   6. Assert byte-equal plaintext.
 *
 * Why not wait for actual Arweave indexing? The Worker uploads to Turbo
 * asynchronously via `ctx.waitUntil` and indexing can take minutes. We
 * already cache the bytes in D1's `blob_data` column at write-through
 * time — same byte stream, same tag set as what would later land on
 * Arweave. Reading from D1 closes the loop without test-time flakiness.
 *
 * Skipped automatically when `wrangler dev` isn't running on port 8787.
 */

import { afterEach, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

// IndexedDB shim — TarnClient's session-persistence layer touches it.
import '../../tests/indexeddb-shim.mjs';

import { recover, type RecoverCredentials } from '../src/index.js';
import { TarnClient } from '../../client/src/tarn.js';
// JS helper module (no .d.ts) — load via dynamic import + cast to keep tsc happy.
const helpers: {
  seedTestApp: () => Promise<unknown>;
  DEFAULT_APP_ID: string;
  forceAllowRulesForAccount: (dlk: string) => Promise<void>;
} = await import('../../tests/helpers.mjs' as any);
const { seedTestApp, DEFAULT_APP_ID, forceAllowRulesForAccount } = helpers;
import {
  deriveCredentialLookupKey,
  deriveRecoveryLookupKey,
} from '../src/decrypt/derive-lookup-keys.js';

// Default to a worktree-local wrangler (port 8788) so the cross-validate test
// doesn't share state with whatever else is running on 8787. Override via
// `RECOVER_API_BASE=http://localhost:8787 npm test` if you've started
// wrangler dev from this worktree on the standard port.
const API_BASE = process.env['RECOVER_API_BASE'] ?? 'http://localhost:8788';
const TEST_PASSWORD = 'phase4-cross-pw-2026';

// ============ Health check (skip when wrangler dev is not up) ============

async function wranglerDevReachable(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/api/v1/health`, {
      signal: AbortSignal.timeout(2000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

const wranglerUp = await wranglerDevReachable();
if (wranglerUp) {
  await seedTestApp();
}

// ============ Mock Arweave gateway (replays SDK-produced blobs) ============

type Edge = {
  cursor: string;
  node: {
    id: string;
    tags: { name: string; value: string }[];
    block: { timestamp: number; height: number };
  };
};

interface MockState {
  edges: Edge[];
  bodies: Record<string, Uint8Array>;
}

interface MockGateway {
  url: string;
  state: MockState;
  close: () => Promise<void>;
}

async function startMockGateway(): Promise<MockGateway> {
  const state: MockState = { edges: [], bodies: {} };
  const server = http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/graphql') {
      let raw = '';
      req.on('data', (chunk) => (raw += chunk.toString()));
      req.on('end', () => {
        let payload: any;
        try {
          payload = JSON.parse(raw);
        } catch {
          res.statusCode = 400;
          res.end('bad json');
          return;
        }
        const variables = payload.variables ?? {};
        const filters: { name: string; values: string[] }[] = variables.tags ?? [];
        const sort: string = variables.sort ?? 'HEIGHT_DESC';
        const first: number = variables.first ?? 100;
        const matched = state.edges.filter((edge) => {
          for (const f of filters) {
            const tagVals = edge.node.tags.filter((t) => t.name === f.name).map((t) => t.value);
            if (!f.values.some((v) => tagVals.includes(v))) return false;
          }
          return true;
        });
        matched.sort((a, b) => {
          const ha = a.node.block.height;
          const hb = b.node.block.height;
          return sort === 'HEIGHT_DESC' ? hb - ha : ha - hb;
        });
        const page = matched.slice(0, first);
        res.statusCode = 200;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({
          data: {
            transactions: {
              pageInfo: {
                hasNextPage: matched.length > first,
                endCursor: page[page.length - 1]?.cursor,
              },
              edges: page,
            },
          },
        }));
      });
      return;
    }
    const txid = decodeURIComponent((req.url ?? '').replace(/^\//, ''));
    const body = state.bodies[txid];
    if (!body) {
      res.statusCode = 404;
      res.end('not found');
      return;
    }
    res.statusCode = 200;
    res.setHeader('content-type', 'application/octet-stream');
    res.end(Buffer.from(body));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const addr = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${addr.port}`,
    state,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function randomUsername(): string {
  return `recover-cross-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
}

/** Decode the base64 body the API returns for `/api/v1/entries/{txid}`. */
function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ============ Tests ============

describe('cross-validate: live SDK write → recover() read', { skip: !wranglerUp }, () => {
  let gw: MockGateway;
  beforeEach(async () => {
    gw = await startMockGateway();
  });
  afterEach(async () => {
    await gw.close();
  });

  it('round-trips owned content via both credential factors', async () => {
    // === Step 1: register + write via the live SDK ===
    const username = randomUsername();
    const client: any = new (TarnClient as any)(API_BASE, DEFAULT_APP_ID);
    const reg = await client.register(username, TEST_PASSWORD, { recoveryAcknowledged: true });
    const dataLookupKey: string = reg.dataLookupKey;
    const accountKey: string = reg.accountKey;
    assert.ok(dataLookupKey, 'register should return dataLookupKey');
    assert.ok(accountKey, 'register should return accountKey');

    // Allow writes against this fresh account without app-JWT plumbing.
    // `forceAllowRulesForAccount` runs `wrangler d1 execute --local` from
    // this worktree's `api/` cwd. If wrangler dev was started from a
    // different worktree (or the main workspace) it has a different D1
    // file, the UPDATE no-ops, and createEntry then fails with
    // "Write denied by authorization rules". We skip cleanly in that
    // case rather than masquerade as a recover-package bug.
    await forceAllowRulesForAccount(dataLookupKey);

    const PAYLOADS = [
      { id: 'cv1', name: 'live-write-1', n: 11 },
      { id: 'cv2', name: 'live-write-2', n: 22 },
      { id: 'cv3', name: 'live-write-3' },
    ];
    const writtenTxids: string[] = [];
    try {
      for (const p of PAYLOADS) {
        const r = await client.createEntry('items-cv', p);
        writtenTxids.push(r.txid);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('Write denied by authorization rules')) {
        // eslint-disable-next-line no-console
        console.log(
          '  (cross-validate skipped: rules-seed D1 differs from wrangler-dev D1 — start wrangler dev from this worktree, then re-run)',
        );
        return;
      }
      throw err;
    }

    // === Step 2: capture envelope + lookup keys ===
    // Re-derive the lookup keys client-side (deterministic) so we can
    // tag the credential blob in the mock the same way the live API does.
    const credentialLookupKey = await deriveCredentialLookupKey(
      username,
      TEST_PASSWORD,
      DEFAULT_APP_ID,
    );
    const recoveryLookupKey = await deriveRecoveryLookupKey(accountKey, DEFAULT_APP_ID);

    // The wrapped envelope is exposed by the recovery-flow challenge.
    const challengeRes = await fetch(`${API_BASE}/api/v1/auth/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recovery_lookup_key: recoveryLookupKey }),
    });
    if (!challengeRes.ok) {
      throw new Error(`challenge failed: HTTP ${challengeRes.status}`);
    }
    const challenge: any = await challengeRes.json();
    const envelope: string = challenge.wrapped_data_key;
    assert.ok(envelope, 'recovery challenge should return wrapped_data_key');
    assert.equal(challenge.data_lookup_key, dataLookupKey);

    // === Step 3: pull each entry's encrypted bytes + tags ===
    interface EntryFixture {
      txid: string;
      tags: { name: string; value: string }[];
      bytes: Uint8Array;
    }
    const entryFixtures: EntryFixture[] = [];
    for (const txid of writtenTxids) {
      const res = await fetch(`${API_BASE}/api/v1/entries/${txid}?key=${dataLookupKey}`);
      if (!res.ok) throw new Error(`fetch ${txid} failed: HTTP ${res.status}`);
      const json: any = await res.json();
      entryFixtures.push({ txid, tags: json.tags, bytes: base64ToBytes(json.data) });
    }

    // === Step 4: stage credential blob + content blobs into mock gateway ===
    const credTxid = 'cred-cross';
    gw.state.bodies[credTxid] = new TextEncoder().encode(
      JSON.stringify({
        data_lookup_key: dataLookupKey,
        wrapped_data_key: envelope,
        public_key: 'cross-test-public-key',
        app: DEFAULT_APP_ID,
        recovery_lookup_key: recoveryLookupKey,
      }),
    );
    gw.state.edges.push({
      cursor: credTxid,
      node: {
        id: credTxid,
        tags: [
          { name: 'App', value: 'tarn' },
          { name: 'Type', value: 'cred' },
          { name: 'Lk', value: credentialLookupKey },
          { name: 'RLk', value: recoveryLookupKey },
        ],
        block: { timestamp: 1700000000, height: 1 },
      },
    });
    let height = 100;
    for (const e of entryFixtures) {
      gw.state.bodies[e.txid] = e.bytes;
      gw.state.edges.push({
        cursor: e.txid,
        node: {
          id: e.txid,
          tags: e.tags,
          block: { timestamp: 1700000000 + height, height: height++ },
        },
      });
    }

    // === Step 5: run recover() via both factors and assert byte-equal ===
    const schema = {
      appId: DEFAULT_APP_ID,
      version: 1,
      collections: {
        'items-cv': { primaryKey: 'id', fields: { id: 'string', name: 'string', n: 'integer?' } },
      },
    };

    async function readAndAssert(credentials: RecoverCredentials, label: string): Promise<void> {
      const reader = await recover({
        appId: DEFAULT_APP_ID,
        schema,
        arweaveGateways: [gw.url],
        credentials,
      });
      const all = await reader.allEntries('items-cv');
      assert.equal(all.length, PAYLOADS.length, `${label}: entry count mismatch`);
      const byId = new Map<string, any>(all.map((entry) => [(entry.data as any).id, entry.data]));
      for (const p of PAYLOADS) {
        assert.deepEqual(byId.get(p.id), p, `${label}: payload mismatch for ${p.id}`);
      }
    }

    await readAndAssert(
      { type: 'accountKey', accountKey },
      'accountKey factor',
    );
    await readAndAssert(
      { type: 'password', username, password: TEST_PASSWORD },
      'password factor',
    );
  });
});

if (!wranglerUp) {
  describe('cross-validate: live SDK write → recover() read (skipped)', () => {
    it('skipped — wrangler dev not reachable on http://localhost:8787', () => {
      // eslint-disable-next-line no-console
      console.log('  (start `cd api && npx wrangler dev --port 8787` and re-run)');
    });
  });
}
