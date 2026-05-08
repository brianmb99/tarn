/**
 * Unit tests for the high-level tag-filtered queries.
 *
 * Stands up a single in-process mock gateway that:
 *   - For `POST /graphql`: inspects the requested tag filters and returns
 *     a scripted set of edges keyed by (App, Type, Lk/RLk/...). This
 *     exercises the actual GraphQL request shape this package emits, not
 *     a stubbed `queryTransactions`.
 *   - For `GET /<txid>`: returns the body bytes from a fixture map.
 *
 * We rely on the same fetch path as production (real HTTP, real JSON
 * serialization) so the test catches request-shape regressions, not just
 * higher-level wiring.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

import {
  ArweaveClient,
  MultiGatewayClient,
  findCredentialBlob,
  findAppBlob,
  findContentBlobs,
  findShareLogBlobs,
  findShareInboxBlobs,
  findPasskeyCredentials,
  type ArweaveEdge,
  type ArweaveTag,
} from '../src/gateway/index.js';

// ============ Fixture helpers ============

function tag(name: string, value: string): ArweaveTag {
  return { name, value };
}

function edge(id: string, tags: ArweaveTag[], height: number): ArweaveEdge {
  return {
    cursor: id,
    node: { id, tags, block: { timestamp: 1700000000 + height, height } },
  };
}

interface MockState {
  /** Returns the edges for a given tag filter map (name → first value). */
  edgesFor: (filters: Record<string, string>, allFilters: Record<string, string[]>) => ArweaveEdge[];
  /** Bodies keyed by txid. */
  bodies: Record<string, string | Uint8Array>;
}

interface MockGateway {
  url: string;
  close: () => Promise<void>;
  graphqlRequests: { tags: { name: string; values: string[] }[]; first?: number; sort?: string }[];
}

async function startMockGateway(state: MockState): Promise<MockGateway> {
  const gqlRequests: MockGateway['graphqlRequests'] = [];
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
        gqlRequests.push({
          tags: variables.tags ?? [],
          first: variables.first,
          sort: variables.sort,
        });
        const filters: Record<string, string> = {};
        const allFilters: Record<string, string[]> = {};
        for (const t of variables.tags ?? []) {
          if (t.values?.[0]) filters[t.name] = t.values[0];
          allFilters[t.name] = t.values ?? [];
        }
        const edges = state.edgesFor(filters, allFilters);
        res.statusCode = 200;
        res.setHeader('content-type', 'application/json');
        res.end(
          JSON.stringify({
            data: { transactions: { pageInfo: { hasNextPage: false }, edges } },
          }),
        );
      });
      return;
    }
    // body fetch — /<txid>
    const txid = decodeURIComponent((req.url ?? '').replace(/^\//, ''));
    const body = state.bodies[txid];
    if (body == null) {
      res.statusCode = 404;
      res.end('not found');
      return;
    }
    res.statusCode = 200;
    res.setHeader('content-type', 'application/octet-stream');
    res.end(body instanceof Uint8Array ? Buffer.from(body) : Buffer.from(String(body)));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const addr = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${addr.port}`,
    graphqlRequests: gqlRequests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function makeClient(gw: MockGateway): MultiGatewayClient {
  return new MultiGatewayClient({
    clients: [new ArweaveClient({ gateway: gw.url, timeoutMs: 1000 })],
  });
}

// ============ findCredentialBlob ============

describe('findCredentialBlob', () => {
  it('queries by RLk tag when given recoveryLookupKey', async () => {
    const RLK = 'r'.repeat(64);
    const txid = 'cred-tx-1';
    const body = JSON.stringify({ data_lookup_key: 'd'.repeat(64), wrapped_data_key: 'wrapped' });
    const gw = await startMockGateway({
      edgesFor: (f) => {
        if (f['App'] === 'tarn' && f['Type'] === 'cred' && f['RLk'] === RLK) {
          return [edge(txid, [tag('App', 'tarn'), tag('Type', 'cred'), tag('RLk', RLK)], 100)];
        }
        return [];
      },
      bodies: { [txid]: body },
    });
    try {
      const result = await findCredentialBlob(makeClient(gw), { recoveryLookupKey: RLK });
      assert.ok(result);
      assert.equal(result.txid, txid);
      assert.deepEqual(result.body, JSON.parse(body));
      assert.equal(result.tagMap['RLk'], RLK);
      // Verify the actual request shape — sort=HEIGHT_DESC, first=1.
      const req = gw.graphqlRequests[0];
      assert.equal(req?.first, 1);
      assert.equal(req?.sort, 'HEIGHT_DESC');
    } finally {
      await gw.close();
    }
  });

  it('queries by Lk tag when given credentialLookupKey', async () => {
    const CLK = 'c'.repeat(64);
    const txid = 'cred-tx-2';
    const body = JSON.stringify({ data_lookup_key: 'd'.repeat(64) });
    const gw = await startMockGateway({
      edgesFor: (f) => {
        if (f['App'] === 'tarn' && f['Type'] === 'cred' && f['Lk'] === CLK) {
          return [edge(txid, [tag('App', 'tarn'), tag('Type', 'cred'), tag('Lk', CLK)], 100)];
        }
        return [];
      },
      bodies: { [txid]: body },
    });
    try {
      const result = await findCredentialBlob(makeClient(gw), { credentialLookupKey: CLK });
      assert.ok(result);
      assert.equal(result.txid, txid);
    } finally {
      await gw.close();
    }
  });

  it('returns null when no credential blob matches', async () => {
    const gw = await startMockGateway({ edgesFor: () => [], bodies: {} });
    try {
      const result = await findCredentialBlob(makeClient(gw), { recoveryLookupKey: 'r'.repeat(64) });
      assert.equal(result, null);
    } finally {
      await gw.close();
    }
  });

  it('throws when neither lookup key is supplied', async () => {
    const gw = await startMockGateway({ edgesFor: () => [], bodies: {} });
    try {
      await assert.rejects(
        findCredentialBlob(makeClient(gw), {}),
        /must supply/,
      );
    } finally {
      await gw.close();
    }
  });
});

// ============ findAppBlob ============

describe('findAppBlob', () => {
  it('queries by App=tarn, Type=app-reg, Lk=<appId>', async () => {
    const txid = 'app-reg-tx';
    const body = JSON.stringify({ v: 1, app_id: 'bookish', public_key: 'spki-base64' });
    const gw = await startMockGateway({
      edgesFor: (f) => {
        if (f['App'] === 'tarn' && f['Type'] === 'app-reg' && f['Lk'] === 'bookish') {
          return [edge(txid, [tag('App', 'tarn'), tag('Type', 'app-reg'), tag('Lk', 'bookish')], 50)];
        }
        return [];
      },
      bodies: { [txid]: body },
    });
    try {
      const result = await findAppBlob(makeClient(gw), { appId: 'bookish' });
      assert.ok(result);
      assert.equal(result.txid, txid);
      assert.deepEqual(result.body, JSON.parse(body));
    } finally {
      await gw.close();
    }
  });
});

// ============ findContentBlobs ============

describe('findContentBlobs', () => {
  it('returns all matching blobs sorted ascending by block height', async () => {
    const DLK = 'd'.repeat(64);
    const e1 = edge('blob-1', [tag('App', 'app1'), tag('Type', 'books'), tag('Lk', DLK)], 200);
    const e2 = edge('blob-2', [tag('App', 'app1'), tag('Type', 'books'), tag('Lk', DLK)], 100);
    const e3 = edge('blob-3', [tag('App', 'app1'), tag('Type', 'books'), tag('Lk', DLK)], 300);
    const gw = await startMockGateway({
      edgesFor: (f) => {
        if (f['App'] === 'app1' && f['Type'] === 'books' && f['Lk'] === DLK) {
          return [e1, e2, e3]; // intentionally out of order
        }
        return [];
      },
      bodies: { 'blob-1': 'body1', 'blob-2': 'body2', 'blob-3': 'body3' },
    });
    try {
      const blobs = await findContentBlobs(makeClient(gw), { app: 'app1', type: 'books', dataLookupKey: DLK });
      assert.equal(blobs.length, 3);
      // Ascending by height: 100, 200, 300.
      assert.equal(blobs[0]?.txid, 'blob-2');
      assert.equal(blobs[1]?.txid, 'blob-1');
      assert.equal(blobs[2]?.txid, 'blob-3');
      // Body fetch is lazy — verify it works.
      const body = await blobs[0]!.loadBody();
      assert.equal(new TextDecoder().decode(body), 'body2');
    } finally {
      await gw.close();
    }
  });

  it('caches body fetches per BlobRecord', async () => {
    const DLK = 'd'.repeat(64);
    let bodyFetchCount = 0;
    const server = http.createServer((req: http.IncomingMessage, res: http.ServerResponse) => {
      if (req.method === 'POST' && req.url === '/graphql') {
        let raw = '';
        req.on('data', (c: Buffer) => (raw += c.toString()));
        req.on('end', () => {
          res.statusCode = 200;
          res.setHeader('content-type', 'application/json');
          res.end(
            JSON.stringify({
              data: {
                transactions: {
                  pageInfo: { hasNextPage: false },
                  edges: [edge('only', [tag('App', 'a'), tag('Type', 't'), tag('Lk', DLK)], 1)],
                },
              },
            }),
          );
        });
        return;
      }
      bodyFetchCount++;
      res.statusCode = 200;
      res.end('hello');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    try {
      const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      const client = new MultiGatewayClient({ clients: [new ArweaveClient({ gateway: url, timeoutMs: 1000 })] });
      const blobs = await findContentBlobs(client, { app: 'a', type: 't', dataLookupKey: DLK });
      assert.equal(blobs.length, 1);
      await blobs[0]!.loadBody();
      await blobs[0]!.loadBody();
      await blobs[0]!.loadBody();
      assert.equal(bodyFetchCount, 1, 'body should be fetched once and cached');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

// ============ findShareLogBlobs ============

describe('findShareLogBlobs', () => {
  it('queries by App=tarn-share, Type=share-log-v1, To=<logTag>, AppScope=<app>', async () => {
    const LOG_TAG = 'log-tag-abc';
    const APP = 'bookish';
    const txid = 'sl-1';
    const gw = await startMockGateway({
      edgesFor: (f) => {
        if (
          f['App'] === 'tarn-share' &&
          f['Type'] === 'share-log-v1' &&
          f['To'] === LOG_TAG &&
          f['AppScope'] === APP
        ) {
          return [
            edge(
              txid,
              [
                tag('App', 'tarn-share'),
                tag('Type', 'share-log-v1'),
                tag('To', LOG_TAG),
                tag('AppScope', APP),
              ],
              42,
            ),
          ];
        }
        return [];
      },
      bodies: { [txid]: 'opaque-ciphertext' },
    });
    try {
      const blobs = await findShareLogBlobs(makeClient(gw), { logTag: LOG_TAG, appScope: APP });
      assert.equal(blobs.length, 1);
      assert.equal(blobs[0]?.txid, txid);
      assert.equal(blobs[0]?.tagMap['To'], LOG_TAG);
    } finally {
      await gw.close();
    }
  });
});

// ============ findShareInboxBlobs ============

describe('findShareInboxBlobs', () => {
  it('queries both connection-request-v1 and connection-accept-v1 in one call', async () => {
    const INBOX = 'inbox-tag-xyz';
    const gw = await startMockGateway({
      edgesFor: (_f, allF) => {
        const types = allF['Type'] ?? [];
        if (
          allF['App']?.[0] === 'tarn-share' &&
          types.includes('connection-request-v1') &&
          types.includes('connection-accept-v1') &&
          allF['To']?.[0] === INBOX
        ) {
          return [
            edge('req-1', [tag('App', 'tarn-share'), tag('Type', 'connection-request-v1'), tag('To', INBOX)], 1),
            edge('acc-1', [tag('App', 'tarn-share'), tag('Type', 'connection-accept-v1'), tag('To', INBOX)], 2),
          ];
        }
        return [];
      },
      bodies: { 'req-1': 'r', 'acc-1': 'a' },
    });
    try {
      const blobs = await findShareInboxBlobs(makeClient(gw), { inboxTag: INBOX });
      assert.equal(blobs.length, 2);
      assert.equal(blobs[0]?.txid, 'req-1'); // height 1, first
      assert.equal(blobs[1]?.txid, 'acc-1'); // height 2, second
    } finally {
      await gw.close();
    }
  });
});

// ============ findPasskeyCredentials ============

describe('findPasskeyCredentials', () => {
  it('returns live credentials and excludes those with Op=tombstone (any blob)', async () => {
    const DLK = 'd'.repeat(64);
    // Three credentials registered; cred-B is tombstoned (a later blob with
    // Op=tombstone for the same CredId); cred-C is registered twice (latest
    // wins).
    const eCredA = edge('reg-A-1', [tag('App', 'tarn'), tag('Type', 'passkey-reg'), tag('Lk', DLK), tag('CredId', 'A')], 10);
    const eCredB1 = edge('reg-B-1', [tag('App', 'tarn'), tag('Type', 'passkey-reg'), tag('Lk', DLK), tag('CredId', 'B')], 11);
    const eCredBTomb = edge('tomb-B', [tag('App', 'tarn'), tag('Type', 'passkey-reg'), tag('Lk', DLK), tag('CredId', 'B'), tag('Op', 'tombstone')], 20);
    const eCredC1 = edge('reg-C-1', [tag('App', 'tarn'), tag('Type', 'passkey-reg'), tag('Lk', DLK), tag('CredId', 'C')], 5);
    const eCredC2 = edge('reg-C-2', [tag('App', 'tarn'), tag('Type', 'passkey-reg'), tag('Lk', DLK), tag('CredId', 'C')], 30);

    const gw = await startMockGateway({
      edgesFor: (f) => {
        if (f['App'] === 'tarn' && f['Type'] === 'passkey-reg' && f['Lk'] === DLK) {
          return [eCredA, eCredB1, eCredBTomb, eCredC1, eCredC2];
        }
        return [];
      },
      bodies: {
        'reg-A-1': JSON.stringify({ v: 1, credential_id: 'A', public_key: 'pkA' }),
        'reg-B-1': JSON.stringify({ v: 1, credential_id: 'B', public_key: 'pkB' }),
        'reg-C-1': JSON.stringify({ v: 1, credential_id: 'C', public_key: 'pkC-old' }),
        'reg-C-2': JSON.stringify({ v: 1, credential_id: 'C', public_key: 'pkC-new' }),
      },
    });
    try {
      const live = await findPasskeyCredentials(makeClient(gw), { dataLookupKey: DLK });
      // A is live; B is tombstoned (excluded); C: latest registration (reg-C-2) wins.
      const credIds = new Set(live.map((b) => b.tagMap['CredId']));
      assert.equal(credIds.has('A'), true);
      assert.equal(credIds.has('B'), false, 'tombstoned credential B should be excluded');
      assert.equal(credIds.has('C'), true);
      const credC = live.find((b) => b.tagMap['CredId'] === 'C');
      assert.equal(credC?.txid, 'reg-C-2', 'latest registration per CredId should win');
      const bodyC = credC?.body as { public_key: string };
      assert.equal(bodyC.public_key, 'pkC-new');
    } finally {
      await gw.close();
    }
  });

  it('returns empty array when no passkeys registered', async () => {
    const gw = await startMockGateway({ edgesFor: () => [], bodies: {} });
    try {
      const live = await findPasskeyCredentials(makeClient(gw), { dataLookupKey: 'd'.repeat(64) });
      assert.deepEqual(live, []);
    } finally {
      await gw.close();
    }
  });
});
