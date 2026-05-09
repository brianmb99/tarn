/**
 * End-to-end synthetic-data tests for `recover()`.
 *
 * Stands up an in-process mock Arweave gateway that:
 *   - Responds to GraphQL `transactions` queries with tag-filtered edges
 *     drawn from a per-test fixture set.
 *   - Serves blob bodies via `GET /<txid>`.
 *
 * Each test:
 *   1. Builds an account-shaped fixture: derives the account's lookup
 *      keys + envelope using the live client-side writer, encrypts a
 *      handful of content blobs against the chain's current DEK, and
 *      registers everything with the mock gateway.
 *   2. Runs `recover()` against the mock gateway with one of the two
 *      credential factors.
 *   3. Asserts the reader yields the exact records that were written,
 *      with tombstones filtered, and `_schemaVersion` markers attached
 *      where applicable.
 *
 * Runs every assertion via BOTH `password` and `accountKey` factors so
 * we catch any factor-specific divergence (e.g., wrong KDF salt scope,
 * wrong factor name on the wrapping).
 */

import { afterEach, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { recover, type RecoverCredentials } from '../src/index.js';
import {
  deriveCredentialLookupKey,
  deriveRecoveryLookupKey,
} from '../src/decrypt/derive-lookup-keys.js';

import * as clientCrypto from '../../client/src/crypto.js';

// ============ Test inputs (deterministic) ============

const TEST_USERNAME = 'phase4-synth@example.com';
const TEST_PASSWORD = 'phase4-synth-pw-2026';
const TEST_APP = 'recover-test';

// Pre-pinned 24-word account key (any valid one — checksums are validated).
const TEST_ACCOUNT_KEY =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';

// Synthetic schema mimicking what `defineSchema()` produces. The recover
// package only inspects `appId`, `version`, and `Object.keys(collections)`.
const TEST_SCHEMA = {
  appId: TEST_APP,
  version: 2,
  collections: {
    items: {
      primaryKey: 'id',
      fields: { id: 'string', name: 'string', n: 'integer?' },
    },
  },
};

// ============ Mock Arweave gateway ============

type Edge = {
  cursor: string;
  node: {
    id: string;
    tags: { name: string; value: string }[];
    block: { timestamp: number; height: number };
  };
};

interface MockState {
  /** All edges; queried via tag filters. */
  edges: Edge[];
  /** Bodies indexed by txid. */
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
            const tagVals = edge.node.tags
              .filter((t) => t.name === f.name)
              .map((t) => t.value);
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
              pageInfo: { hasNextPage: matched.length > first, endCursor: page[page.length - 1]?.cursor },
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

// ============ Fixture builders ============

interface AccountFixture {
  dataLookupKey: string;
  credentialLookupKey: string;
  recoveryLookupKey: string;
  /** Per-gen DEK kwKey — used to encrypt content blobs and assert post-recovery. */
  dekByGen: Map<number, { kwKey: CryptoKey; gcmKey: CryptoKey }>;
  envelope: string;
  recoverySalt: Uint8Array;
}

async function buildAccountFixture(args: { genCount: number }): Promise<AccountFixture> {
  const recoverySalt = clientCrypto.generateRecoverySalt();
  const masterKey = await clientCrypto.deriveMasterKey(TEST_USERNAME, TEST_PASSWORD);
  const cek = await clientCrypto.deriveCredentialEncryptionKey(masterKey, TEST_APP);
  const recoveryKEK = await clientCrypto.deriveRecoveryKey(TEST_ACCOUNT_KEY, recoverySalt);

  const dekByGen = new Map<number, { kwKey: CryptoKey; gcmKey: CryptoKey }>();
  const chain: { gen: number; key: CryptoKey }[] = [];
  for (let gen = 1; gen <= args.genCount; gen++) {
    const dek = await clientCrypto.generateRandomDataKey();
    dekByGen.set(gen, { kwKey: dek.kwKey, gcmKey: dek.gcmKey });
    chain.push({ gen, key: dek.gcmKey });
  }

  const envelope = await clientCrypto.wrapDataKeyChainEnvelope(
    chain,
    [
      { name: clientCrypto.FACTOR_PASSWORD, wrappingKey: cek.kwKey },
      { name: clientCrypto.FACTOR_RECOVERY_PHRASE, wrappingKey: recoveryKEK.kwKey },
    ],
    { salt: recoverySalt },
  );

  // 64-hex deterministic dataLookupKey — the test only needs it to match
  // across credential blob + content blob tags.
  const dataLookupKey = '0123456789abcdef'.repeat(4);

  const credentialLookupKey = await deriveCredentialLookupKey(TEST_USERNAME, TEST_PASSWORD, TEST_APP);
  const recoveryLookupKey = await deriveRecoveryLookupKey(TEST_ACCOUNT_KEY, TEST_APP);

  return {
    dataLookupKey,
    credentialLookupKey,
    recoveryLookupKey,
    dekByGen,
    envelope,
    recoverySalt,
  };
}

function publishCredentialBlob(state: MockState, fixture: AccountFixture): void {
  const txid = `cred-${state.edges.length + 1}`;
  const body = JSON.stringify({
    data_lookup_key: fixture.dataLookupKey,
    wrapped_data_key: fixture.envelope,
    public_key: 'test-public-key',
    app: TEST_APP,
    recovery_lookup_key: fixture.recoveryLookupKey,
  });
  state.bodies[txid] = new TextEncoder().encode(body);
  state.edges.push({
    cursor: txid,
    node: {
      id: txid,
      tags: [
        { name: 'App', value: 'tarn' },
        { name: 'Type', value: 'cred' },
        { name: 'Lk', value: fixture.credentialLookupKey },
        { name: 'RLk', value: fixture.recoveryLookupKey },
      ],
      block: { timestamp: 1700000000, height: 1 },
    },
  });
}

interface ContentBlobOpts {
  collection: string;
  payload: Record<string, unknown>;
  gen: number;
  height: number;
  eid?: string;
  prev?: string;
  schemaVersion?: number;
}

async function publishContentBlob(
  state: MockState,
  fixture: AccountFixture,
  opts: ContentBlobOpts,
): Promise<{ txid: string }> {
  const dek = fixture.dekByGen.get(opts.gen);
  if (!dek) throw new Error(`fixture has no DEK for gen ${opts.gen}`);
  const { blob } = await clientCrypto.encryptWithCEK(dek.kwKey, opts.payload);
  const txid = `tx-${state.edges.length + 1}-${Math.random().toString(36).slice(2, 6)}`;
  state.bodies[txid] = blob;
  const tags: { name: string; value: string }[] = [
    { name: 'App', value: TEST_APP },
    { name: 'Type', value: opts.collection },
    { name: 'Lk', value: fixture.dataLookupKey },
    { name: 'Enc', value: 'tarn-cek-1' },
    { name: 'Gen', value: String(opts.gen) },
  ];
  if (opts.eid) tags.push({ name: 'Eid', value: opts.eid });
  if (opts.prev) tags.push({ name: 'Prev', value: opts.prev });
  if (opts.schemaVersion !== undefined) {
    tags.push({ name: 'SchemaV', value: String(opts.schemaVersion) });
  }
  state.edges.push({
    cursor: txid,
    node: {
      id: txid,
      tags,
      block: { timestamp: 1700000000 + opts.height, height: opts.height },
    },
  });
  return { txid };
}

async function publishTombstoneBlob(
  state: MockState,
  fixture: AccountFixture,
  opts: { collection: string; ref: string; gen: number; height: number; eid?: string },
): Promise<{ txid: string }> {
  const dek = fixture.dekByGen.get(opts.gen);
  if (!dek) throw new Error(`fixture has no DEK for gen ${opts.gen}`);
  const { blob } = await clientCrypto.encryptWithCEK(dek.kwKey, {
    tombstone: true,
    ref: opts.ref,
  });
  const txid = `tomb-${state.edges.length + 1}`;
  state.bodies[txid] = blob;
  const tags: { name: string; value: string }[] = [
    { name: 'App', value: TEST_APP },
    { name: 'Type', value: opts.collection },
    { name: 'Lk', value: fixture.dataLookupKey },
    { name: 'Op', value: 'tombstone' },
    { name: 'Ref', value: opts.ref },
    { name: 'Enc', value: 'tarn-cek-1' },
    { name: 'Gen', value: String(opts.gen) },
  ];
  if (opts.eid) tags.push({ name: 'Eid', value: opts.eid });
  state.edges.push({
    cursor: txid,
    node: {
      id: txid,
      tags,
      block: { timestamp: 1700000000 + opts.height, height: opts.height },
    },
  });
  return { txid };
}

// Both credentials shapes a test should run through.
function bothFactors(): { name: string; credentials: RecoverCredentials }[] {
  return [
    { name: 'password', credentials: { type: 'password', username: TEST_USERNAME, password: TEST_PASSWORD } },
    { name: 'accountKey', credentials: { type: 'accountKey', accountKey: TEST_ACCOUNT_KEY } },
  ];
}

// ============ Tests ============

describe('recover(): happy path with both factors', () => {
  let gw: MockGateway;
  beforeEach(async () => {
    gw = await startMockGateway();
  });
  afterEach(async () => {
    await gw.close();
  });

  for (const { name, credentials } of bothFactors()) {
    it(`reads owned content via ${name} factor`, async () => {
      const fixture = await buildAccountFixture({ genCount: 1 });
      publishCredentialBlob(gw.state, fixture);

      const records = [
        { id: 'r1', name: 'first', n: 1 },
        { id: 'r2', name: 'second', n: 2 },
        { id: 'r3', name: 'third' },
      ];
      let h = 10;
      for (const rec of records) {
        await publishContentBlob(gw.state, fixture, {
          collection: 'items',
          payload: rec,
          gen: 1,
          height: h++,
          eid: `eid-${rec.id}`,
          schemaVersion: 2,
        });
      }

      const reader = await recover({
        appId: TEST_APP,
        schema: TEST_SCHEMA,
        arweaveGateways: [gw.url],
        credentials,
      });

      assert.deepEqual(reader.collections, ['items']);
      assert.equal(reader.account.appId, TEST_APP);
      assert.equal(reader.account.envelopeVersion, 1);
      assert.equal(reader.account.totalGens, 1);

      const all = await reader.allEntries('items');
      assert.equal(all.length, 3);
      const byId = new Map(all.map((e) => [(e.data as { id: string }).id, e.data]));
      assert.deepEqual(byId.get('r1'), records[0]);
      assert.deepEqual(byId.get('r2'), records[1]);
      assert.deepEqual(byId.get('r3'), records[2]);
      assert.equal(reader.tombstoneCount, 0);
    });
  }
});

describe('recover(): tombstones are excluded from entries()', () => {
  let gw: MockGateway;
  beforeEach(async () => {
    gw = await startMockGateway();
  });
  afterEach(async () => {
    await gw.close();
  });

  for (const { name, credentials } of bothFactors()) {
    it(`excludes tombstoned records via ${name} factor; tombstoneCount reflects them`, async () => {
      const fixture = await buildAccountFixture({ genCount: 1 });
      publishCredentialBlob(gw.state, fixture);

      const live1 = await publishContentBlob(gw.state, fixture, {
        collection: 'items',
        payload: { id: 'live1', name: 'kept' },
        gen: 1,
        height: 10,
        eid: 'eid-live1',
        schemaVersion: 2,
      });
      const dead = await publishContentBlob(gw.state, fixture, {
        collection: 'items',
        payload: { id: 'dead', name: 'doomed' },
        gen: 1,
        height: 11,
        eid: 'eid-dead',
        schemaVersion: 2,
      });
      await publishTombstoneBlob(gw.state, fixture, {
        collection: 'items',
        ref: dead.txid,
        gen: 1,
        height: 12,
        eid: 'eid-dead',
      });

      const reader = await recover({
        appId: TEST_APP,
        schema: TEST_SCHEMA,
        arweaveGateways: [gw.url],
        credentials,
      });

      const all = await reader.allEntries('items');
      assert.equal(all.length, 1);
      assert.equal((all[0]!.data as { id: string }).id, 'live1');
      assert.equal(all[0]!.txid, live1.txid);
      assert.equal(reader.tombstoneCount, 1);
    });
  }
});

describe('recover(): multi-gen DEK chain', () => {
  let gw: MockGateway;
  beforeEach(async () => {
    gw = await startMockGateway();
  });
  afterEach(async () => {
    await gw.close();
  });

  for (const { name, credentials } of bothFactors()) {
    it(`decrypts content from every gen via ${name} factor`, async () => {
      const fixture = await buildAccountFixture({ genCount: 3 });
      publishCredentialBlob(gw.state, fixture);

      // Each record was written under a different gen (mimicking
      // an account that's been through changeCredentials twice between
      // record creations).
      await publishContentBlob(gw.state, fixture, {
        collection: 'items',
        payload: { id: 'old', name: 'gen1', n: 1 },
        gen: 1,
        height: 10,
        eid: 'eid-old',
        schemaVersion: 2,
      });
      await publishContentBlob(gw.state, fixture, {
        collection: 'items',
        payload: { id: 'mid', name: 'gen2', n: 2 },
        gen: 2,
        height: 11,
        eid: 'eid-mid',
        schemaVersion: 2,
      });
      await publishContentBlob(gw.state, fixture, {
        collection: 'items',
        payload: { id: 'new', name: 'gen3', n: 3 },
        gen: 3,
        height: 12,
        eid: 'eid-new',
        schemaVersion: 2,
      });

      const reader = await recover({
        appId: TEST_APP,
        schema: TEST_SCHEMA,
        arweaveGateways: [gw.url],
        credentials,
      });

      assert.equal(reader.account.totalGens, 3);
      const all = await reader.allEntries('items');
      assert.equal(all.length, 3);
      const names = all.map((e) => (e.data as { name: string }).name).sort();
      assert.deepEqual(names, ['gen1', 'gen2', 'gen3']);
    });
  }
});

describe('recover(): _schemaVersion marker', () => {
  let gw: MockGateway;
  beforeEach(async () => {
    gw = await startMockGateway();
  });
  afterEach(async () => {
    await gw.close();
  });

  it('attaches _schemaVersion when entry was written under older schema', async () => {
    const fixture = await buildAccountFixture({ genCount: 1 });
    publishCredentialBlob(gw.state, fixture);

    await publishContentBlob(gw.state, fixture, {
      collection: 'items',
      payload: { id: 'oldsk', name: 'v1-data' },
      gen: 1,
      height: 10,
      eid: 'eid-oldsk',
      schemaVersion: 1, // caller schema is v2 → marker should be attached
    });
    await publishContentBlob(gw.state, fixture, {
      collection: 'items',
      payload: { id: 'cursk', name: 'v2-data' },
      gen: 1,
      height: 11,
      eid: 'eid-cursk',
      schemaVersion: 2, // matches caller — no marker
    });

    const reader = await recover({
      appId: TEST_APP,
      schema: TEST_SCHEMA,
      arweaveGateways: [gw.url],
      credentials: { type: 'accountKey', accountKey: TEST_ACCOUNT_KEY },
    });

    const all = await reader.allEntries('items');
    const old = all.find((e) => (e.data as { id: string }).id === 'oldsk');
    const cur = all.find((e) => (e.data as { id: string }).id === 'cursk');
    assert.ok(old);
    assert.ok(cur);
    assert.equal(old!._schemaVersion, 1);
    assert.equal(cur!._schemaVersion, undefined);
  });

  it('does not attach _schemaVersion when SchemaV tag is absent', async () => {
    const fixture = await buildAccountFixture({ genCount: 1 });
    publishCredentialBlob(gw.state, fixture);

    await publishContentBlob(gw.state, fixture, {
      collection: 'items',
      payload: { id: 'no-sv', name: 'preschema' },
      gen: 1,
      height: 10,
      eid: 'eid-nosv',
      // no schemaVersion → no SchemaV tag
    });

    const reader = await recover({
      appId: TEST_APP,
      schema: TEST_SCHEMA,
      arweaveGateways: [gw.url],
      credentials: { type: 'accountKey', accountKey: TEST_ACCOUNT_KEY },
    });

    const all = await reader.allEntries('items');
    assert.equal(all.length, 1);
    assert.equal(all[0]!._schemaVersion, undefined);
  });
});

describe('recover(): input validation', () => {
  let gw: MockGateway;
  beforeEach(async () => {
    gw = await startMockGateway();
  });
  afterEach(async () => {
    await gw.close();
  });

  it('rejects mismatched appId / schema.appId', async () => {
    await assert.rejects(
      recover({
        appId: 'one',
        schema: { appId: 'two', version: 1, collections: { x: {} } },
        arweaveGateways: [gw.url],
        credentials: { type: 'accountKey', accountKey: TEST_ACCOUNT_KEY },
      }),
      /schema\.appId/,
    );
  });

  it('rejects empty arweaveGateways', async () => {
    await assert.rejects(
      recover({
        appId: TEST_APP,
        schema: TEST_SCHEMA,
        arweaveGateways: [],
        credentials: { type: 'accountKey', accountKey: TEST_ACCOUNT_KEY },
      }),
      /arweaveGateways/,
    );
  });

  it('rejects missing username on the password factor', async () => {
    await assert.rejects(
      recover({
        appId: TEST_APP,
        schema: TEST_SCHEMA,
        arweaveGateways: [gw.url],
        credentials: { type: 'password', username: '', password: TEST_PASSWORD },
      }),
      /username/,
    );
  });

  it('throws when no credential blob exists at any gateway', async () => {
    // Empty mock state — nothing to find.
    await assert.rejects(
      recover({
        appId: TEST_APP,
        schema: TEST_SCHEMA,
        arweaveGateways: [gw.url],
        credentials: { type: 'accountKey', accountKey: TEST_ACCOUNT_KEY },
      }),
      /no credential blob found/,
    );
  });

  it('rejects access to undeclared collections', async () => {
    const fixture = await buildAccountFixture({ genCount: 1 });
    publishCredentialBlob(gw.state, fixture);
    const reader = await recover({
      appId: TEST_APP,
      schema: TEST_SCHEMA,
      arweaveGateways: [gw.url],
      credentials: { type: 'accountKey', accountKey: TEST_ACCOUNT_KEY },
    });
    await assert.rejects(reader.allEntries('not-a-collection'), /not a declared collection/);
  });
});

describe('recover(): onProgress callback', () => {
  let gw: MockGateway;
  beforeEach(async () => {
    gw = await startMockGateway();
  });
  afterEach(async () => {
    await gw.close();
  });

  it('fires the documented stage names; never throws when callback errors', async () => {
    const fixture = await buildAccountFixture({ genCount: 1 });
    publishCredentialBlob(gw.state, fixture);
    await publishContentBlob(gw.state, fixture, {
      collection: 'items',
      payload: { id: 'p1', name: 'progress' },
      gen: 1,
      height: 10,
      eid: 'eid-p1',
      schemaVersion: 2,
    });

    const seen: string[] = [];
    const reader = await recover({
      appId: TEST_APP,
      schema: TEST_SCHEMA,
      arweaveGateways: [gw.url],
      credentials: { type: 'password', username: TEST_USERNAME, password: TEST_PASSWORD },
      onProgress: (stage) => {
        seen.push(stage);
        if (stage === 'walking-log') throw new Error('callback intentionally throws');
      },
    });
    // Drain so the reader's emit() stages fire.
    await reader.allEntries('items');
    assert.ok(seen.includes('deriving'));
    assert.ok(seen.includes('locating-account'));
    assert.ok(seen.includes('fetching-envelope'));
    assert.ok(seen.includes('walking-log'));
    assert.ok(seen.includes('done'));
  });
});
