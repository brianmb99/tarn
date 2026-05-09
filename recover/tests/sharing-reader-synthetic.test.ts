/**
 * Synthetic-data tests for the Phase 5 SharingReader surface.
 *
 * Stands up a mock Arweave gateway with two users (Alice and Bob),
 * synthesizes a connections record + per-pair share-log entries on each
 * side, and asserts that `reader.connections()` and
 * `reader.shareLog({ direction })` see exactly the events that were
 * published.
 *
 * The synthesis path uses the BORROWED encrypt/sign primitives (so test
 * fixtures don't depend on the live SDK, and so the round-trip itself
 * exercises both code paths). The cross-validate tests in
 * `sharing-cross-validate.test.ts` separately prove byte-equality between
 * the borrowed and original code, so a passing test here implies the
 * recover-package flow handles real bytes.
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
import {
  deriveSharedSecret,
  derivePairKeys,
  deriveLogTag,
  encryptShareLogEntry,
  signOperation,
  OP_ADD,
  OP_SNAPSHOT,
} from '../src/sharing/share-log-primitives.js';
import { CONNECTIONS_CONTENT_ID } from '../src/sharing/hpke-primitives.js';

import * as clientCrypto from '../../client/src/crypto.js';

// ============ Test inputs ============

const TEST_APP = 'sharing-reader-test';

// Alice (the recovered user) — pinned credentials.
const ALICE_USERNAME = 'alice@example.com';
const ALICE_PASSWORD = 'alice-pw-2026';
const ALICE_ACCOUNT_KEY =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';

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
        try { payload = JSON.parse(raw); } catch {
          res.statusCode = 400; res.end('bad json'); return;
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
    if (!body) { res.statusCode = 404; res.end('not found'); return; }
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

// ============ Account fixture (mirrors recover-synthetic.test.ts) ============

interface AccountFixture {
  dataLookupKey: string;
  credentialLookupKey: string;
  recoveryLookupKey: string;
  /** Per-gen DEK kwKey (gen 1 only here). */
  dek: { kwKey: CryptoKey; gcmKey: CryptoKey };
  envelope: string;
  recoverySalt: Uint8Array;
  /** The user's signing keypair (for synthesizing share-log signatures). */
  signingKeyPair: CryptoKeyPair;
  signingPubBase64: string;
  /** The user's X25519 sharing keypair. */
  shareKeyPair: { privateKey: Uint8Array; publicKey: Uint8Array };
  shareSubBase64Url: string;
  username: string;
}

async function buildAccountFixture(args: {
  username: string;
  password: string;
  accountKey: string;
  dataLookupKey: string;
}): Promise<AccountFixture> {
  const recoverySalt = clientCrypto.generateRecoverySalt();
  const masterKey = await clientCrypto.deriveMasterKey(args.username, args.password);
  const cek = await clientCrypto.deriveCredentialEncryptionKey(masterKey, TEST_APP);
  const recoveryKEK = await clientCrypto.deriveRecoveryKey(args.accountKey, recoverySalt);
  const sharingKeyPair = await clientCrypto.deriveSharingKeyPair(masterKey, TEST_APP);
  const signingKeyPair = await clientCrypto.deriveSigningKeyPair(masterKey, TEST_APP);
  const signingPubBytes = new Uint8Array(await crypto.subtle.exportKey('spki', signingKeyPair.publicKey));
  const signingPubBase64 = btoa(String.fromCharCode(...signingPubBytes));

  const dek = await clientCrypto.generateRandomDataKey();
  const envelope = await clientCrypto.wrapDataKeyChainEnvelope(
    [{ gen: 1, key: dek.gcmKey }],
    [
      { name: clientCrypto.FACTOR_PASSWORD, wrappingKey: cek.kwKey },
      { name: clientCrypto.FACTOR_RECOVERY_PHRASE, wrappingKey: recoveryKEK.kwKey },
    ],
    { salt: recoverySalt },
  );

  const credentialLookupKey = await deriveCredentialLookupKey(args.username, args.password, TEST_APP);
  const recoveryLookupKey = await deriveRecoveryLookupKey(args.accountKey, TEST_APP);

  return {
    dataLookupKey: args.dataLookupKey,
    credentialLookupKey,
    recoveryLookupKey,
    dek: { kwKey: dek.kwKey, gcmKey: dek.gcmKey },
    envelope,
    recoverySalt,
    signingKeyPair,
    signingPubBase64,
    shareKeyPair: sharingKeyPair,
    shareSubBase64Url: clientCrypto.bytesToBase64Url(sharingKeyPair.publicKey),
    username: args.username,
  };
}

function publishCredentialBlob(state: MockState, fix: AccountFixture, height: number): void {
  const txid = `cred-${fix.username}-${state.edges.length + 1}`;
  state.bodies[txid] = new TextEncoder().encode(JSON.stringify({
    data_lookup_key: fix.dataLookupKey,
    wrapped_data_key: fix.envelope,
    // Publish the real signing pub so the SharingReader can verify the
    // user's own outgoing share-log entries.
    public_key: fix.signingPubBase64,
    app: TEST_APP,
    recovery_lookup_key: fix.recoveryLookupKey,
  }));
  state.edges.push({
    cursor: txid,
    node: {
      id: txid,
      tags: [
        { name: 'App', value: 'tarn' },
        { name: 'Type', value: 'cred' },
        { name: 'Lk', value: fix.credentialLookupKey },
        { name: 'RLk', value: fix.recoveryLookupKey },
      ],
      block: { timestamp: 1700000000, height },
    },
  });
}

async function publishConnectionsRecord(
  state: MockState,
  fix: AccountFixture,
  connections: Array<{ share_pub: string; signing_pub: string; username?: string; label?: string; established_at?: number }>,
  height: number,
): Promise<void> {
  const record = { app_id: TEST_APP, version: 1, connections };
  const { blob } = await clientCrypto.encryptWithCEK(fix.dek.kwKey, record);
  const txid = `share-state-${fix.username}-${state.edges.length + 1}`;
  state.bodies[txid] = blob;
  state.edges.push({
    cursor: txid,
    node: {
      id: txid,
      tags: [
        { name: 'App', value: TEST_APP },
        { name: 'Type', value: 'tarn-share-state' },
        { name: 'Lk', value: fix.dataLookupKey },
        { name: 'Eid', value: CONNECTIONS_CONTENT_ID },
        { name: 'Enc', value: 'tarn-cek-1' },
        { name: 'Gen', value: '1' },
      ],
      block: { timestamp: 1700000000 + height, height },
    },
  });
}

interface PairContext {
  // From the writer's side.
  outboundKey: CryptoKey;
  outboundTagSeed: Uint8Array;
  // For per-entry metadata.
  selfFix: AccountFixture;
  peerFix: AccountFixture;
}

async function buildPairContext(self: AccountFixture, peer: AccountFixture): Promise<PairContext> {
  const sharedSecret = deriveSharedSecret(self.shareKeyPair.privateKey, peer.shareKeyPair.publicKey);
  const keys = await derivePairKeys({
    sharedSecret,
    appId: TEST_APP,
    selfSharePub: self.shareKeyPair.publicKey,
    peerSharePub: peer.shareKeyPair.publicKey,
  });
  return { outboundKey: keys.outboundKey, outboundTagSeed: keys.outboundTagSeed, selfFix: self, peerFix: peer };
}

async function publishShareLogEntry(
  state: MockState,
  pair: PairContext,
  op: any,
  height: number,
): Promise<void> {
  const signed = await signOperation(op, pair.selfFix.signingKeyPair.privateKey);
  const blob = await encryptShareLogEntry(signed, pair.outboundKey);
  const tag = await deriveLogTag(pair.outboundTagSeed, op.seq);
  const txid = `share-log-${state.edges.length + 1}-seq${op.seq}`;
  state.bodies[txid] = blob;
  state.edges.push({
    cursor: txid,
    node: {
      id: txid,
      tags: [
        { name: 'App', value: 'tarn-share' },
        { name: 'Type', value: 'share-log-v1' },
        { name: 'To', value: tag },
        { name: 'AppScope', value: TEST_APP },
      ],
      block: { timestamp: 1700000000 + height, height },
    },
  });
}

// ============ Tests ============

describe('SharingReader synthetic: connections() + shareLog() round-trip', () => {
  let gw: MockGateway;
  beforeEach(async () => { gw = await startMockGateway(); });
  afterEach(async () => { await gw.close(); });

  it('alice sees bob in connections() after the connections record is published', async () => {
    const alice = await buildAccountFixture({
      username: ALICE_USERNAME,
      password: ALICE_PASSWORD,
      accountKey: ALICE_ACCOUNT_KEY,
      dataLookupKey: 'aaaa'.repeat(16),
    });
    const bob = await buildAccountFixture({
      username: 'bob@example.com',
      password: 'bob-pw-2026',
      accountKey: ALICE_ACCOUNT_KEY, // any valid mnemonic; we only need the keypair derivation to succeed
      dataLookupKey: 'bbbb'.repeat(16),
    });

    publishCredentialBlob(gw.state, alice, 1);
    await publishConnectionsRecord(gw.state, alice, [{
      share_pub: bob.shareSubBase64Url,
      signing_pub: bob.signingPubBase64,
      username: bob.username,
      label: 'Bob',
      established_at: 1700000050,
    }], 10);

    const reader = await recover({
      appId: TEST_APP,
      schema: { appId: TEST_APP, version: 1, collections: { 'tarn-share-state': {} } },
      arweaveGateways: [gw.url],
      credentials: { type: 'password', username: alice.username, password: ALICE_PASSWORD },
    });

    const conns = await reader.connections();
    assert.equal(conns.length, 1, 'should see exactly one connection');
    assert.equal(conns[0]!.share_pub, bob.shareSubBase64Url);
    assert.equal(conns[0]!.username, bob.username);
    assert.equal(conns[0]!.label, 'Bob');
    assert.equal(conns[0]!.established_at, 1700000050);
  });

  it('account-key path returns [] for connections() (share keypair unavailable)', async () => {
    const alice = await buildAccountFixture({
      username: ALICE_USERNAME,
      password: ALICE_PASSWORD,
      accountKey: ALICE_ACCOUNT_KEY,
      dataLookupKey: 'aaaa'.repeat(16),
    });
    const bob = await buildAccountFixture({
      username: 'bob@example.com',
      password: 'bob-pw-2026',
      accountKey: ALICE_ACCOUNT_KEY,
      dataLookupKey: 'bbbb'.repeat(16),
    });

    publishCredentialBlob(gw.state, alice, 1);
    await publishConnectionsRecord(gw.state, alice, [{
      share_pub: bob.shareSubBase64Url,
      signing_pub: bob.signingPubBase64,
      username: bob.username,
    }], 10);

    const reader = await recover({
      appId: TEST_APP,
      schema: { appId: TEST_APP, version: 1, collections: { 'tarn-share-state': {} } },
      arweaveGateways: [gw.url],
      credentials: { type: 'accountKey', accountKey: ALICE_ACCOUNT_KEY },
    });

    const conns = await reader.connections();
    assert.deepEqual(conns, [], 'account-key path: connections() should be empty');
    const events = await reader.allShareLog({ direction: 'incoming' });
    assert.deepEqual(events, [], 'account-key path: shareLog() should yield nothing');
  });

  it('outgoing share-log: alice sees the events she published to bob', async () => {
    const alice = await buildAccountFixture({
      username: ALICE_USERNAME,
      password: ALICE_PASSWORD,
      accountKey: ALICE_ACCOUNT_KEY,
      dataLookupKey: 'aaaa'.repeat(16),
    });
    const bob = await buildAccountFixture({
      username: 'bob@example.com',
      password: 'bob-pw-2026',
      accountKey: ALICE_ACCOUNT_KEY,
      dataLookupKey: 'bbbb'.repeat(16),
    });

    publishCredentialBlob(gw.state, alice, 1);
    await publishConnectionsRecord(gw.state, alice, [{
      share_pub: bob.shareSubBase64Url,
      signing_pub: bob.signingPubBase64,
      username: bob.username,
    }], 10);

    // Alice publishes a snapshot at seq=0 (the handshake bootstrap), then an
    // add at seq=1 and a remove at seq=2 — typical share-log shape.
    const aliceToBob = await buildPairContext(alice, bob);
    await publishShareLogEntry(gw.state, aliceToBob, {
      type: OP_SNAPSHOT, seq: 0, state: {}, snapshot_at: 1700000100, prior_seq: null,
    }, 20);
    await publishShareLogEntry(gw.state, aliceToBob, {
      type: OP_ADD, seq: 1, content_id: 'C1', tx_id: 'tx-content-1',
      cek: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      shared_at: 1700000200,
    }, 21);
    await publishShareLogEntry(gw.state, aliceToBob, {
      type: 'remove', seq: 2, content_id: 'C1', removed_at: 1700000300,
    }, 22);

    const reader = await recover({
      appId: TEST_APP,
      schema: { appId: TEST_APP, version: 1, collections: { 'tarn-share-state': {} } },
      arweaveGateways: [gw.url],
      credentials: { type: 'password', username: alice.username, password: ALICE_PASSWORD },
    });

    const events = await reader.allShareLog({ direction: 'outgoing' });
    assert.equal(events.length, 3, 'should see all 3 entries Alice published');
    assert.equal(events[0]!.type, 'snapshot');
    assert.equal(events[1]!.type, 'add');
    assert.equal(events[2]!.type, 'remove');
    // Every event is verified — alice signs with her own key, which the
    // connections record (synthesized above) lists as bob's signing_pub
    // (we used alice's keypair to sign, so verifiable bytes-wise the test
    // is symmetric).
    for (const e of events) {
      assert.equal(e.connection.share_pub, bob.shareSubBase64Url);
      assert.equal(e.direction, 'outgoing');
    }
  });

  it('rotate_identity terminates the walk on the OLD log', async () => {
    const alice = await buildAccountFixture({
      username: ALICE_USERNAME,
      password: ALICE_PASSWORD,
      accountKey: ALICE_ACCOUNT_KEY,
      dataLookupKey: 'aaaa'.repeat(16),
    });
    const bob = await buildAccountFixture({
      username: 'bob@example.com',
      password: 'bob-pw-2026',
      accountKey: ALICE_ACCOUNT_KEY,
      dataLookupKey: 'bbbb'.repeat(16),
    });

    publishCredentialBlob(gw.state, alice, 1);
    await publishConnectionsRecord(gw.state, alice, [{
      share_pub: bob.shareSubBase64Url,
      signing_pub: bob.signingPubBase64,
      username: bob.username,
    }], 10);

    const aliceToBob = await buildPairContext(alice, bob);
    await publishShareLogEntry(gw.state, aliceToBob, {
      type: OP_SNAPSHOT, seq: 0, state: {}, snapshot_at: 1700000100, prior_seq: null,
    }, 20);
    await publishShareLogEntry(gw.state, aliceToBob, {
      type: 'rotate_identity', seq: 1,
      new_share_pub: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      new_signing_pub: 'CCCCCCCCC',
      new_credential_lookup_key: 'a'.repeat(64),
      rotated_at: 1700000200,
    }, 21);
    // An entry past the rotation that should NOT be yielded.
    await publishShareLogEntry(gw.state, aliceToBob, {
      type: OP_ADD, seq: 2, content_id: 'POST-ROT', tx_id: 'tx-x',
      cek: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      shared_at: 1700000300,
    }, 22);

    const reader = await recover({
      appId: TEST_APP,
      schema: { appId: TEST_APP, version: 1, collections: { 'tarn-share-state': {} } },
      arweaveGateways: [gw.url],
      credentials: { type: 'password', username: alice.username, password: ALICE_PASSWORD },
    });

    const events = await reader.allShareLog({ direction: 'outgoing' });
    assert.equal(events.length, 2, 'rotate_identity is terminal — POST-ROT add must be absent');
    assert.equal(events[0]!.type, 'snapshot');
    assert.equal(events[1]!.type, 'rotate_identity');
  });
});
