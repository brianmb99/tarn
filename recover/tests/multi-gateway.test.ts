/**
 * Unit tests for the multi-gateway fallback orchestration.
 *
 * Each test stands up an in-process HTTP server per "gateway" (we run real
 * fetches against `127.0.0.1:0` ports rather than swapping the fetch
 * implementation; this exercises the `AbortController` / `Response.json`
 * paths the same way the production code will). The servers respond with
 * scripted status codes / bodies / delays so we can verify each retry
 * case end-to-end.
 *
 * The plan calls out four retry triggers:
 *   - Connection error / timeout
 *   - HTTP 5xx
 *   - HTTP 429
 *   - "TX not found" for confirmed-but-not-yet-indexed transactions
 *
 * Plus the all-exhausted case and the onProgress signalling.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

import {
  ArweaveClient,
  GatewayError,
  MultiGatewayClient,
  AllGatewaysFailedError,
  type RetryProgress,
} from '../src/gateway/index.js';

// ============ Mock-server helpers ============

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

interface MockGateway {
  url: string;
  close: () => Promise<void>;
  readonly hits: number;
}

async function startGateway(handler: Handler): Promise<MockGateway> {
  const ref: { hits: number } = { hits: 0 };
  const server = http.createServer((req, res) => {
    ref.hits++;
    handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const addr = server.address() as AddressInfo;
  const gw: MockGateway = {
    url: `http://127.0.0.1:${addr.port}`,
    get hits(): number {
      return ref.hits;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
  return gw;
}

function jsonResp(status: number, body: unknown): Handler {
  return (_req, res) => {
    res.statusCode = status;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(body));
  };
}

function statusResp(status: number, body = ''): Handler {
  return (_req, res) => {
    res.statusCode = status;
    res.end(body);
  };
}

/** Hangs forever, never responding (forces client-side timeout). */
function hangResp(): Handler {
  return () => {
    // intentionally do nothing — the server never responds.
  };
}

function emptyTxnsBody() {
  return { data: { transactions: { pageInfo: { hasNextPage: false }, edges: [] } } };
}

function makeClient(gateways: MockGateway[], opts: { timeoutMs?: number; onProgress?: (info: RetryProgress) => void } = {}): MultiGatewayClient {
  return new MultiGatewayClient({
    clients: gateways.map(
      (g) =>
        new ArweaveClient({
          gateway: g.url,
          timeoutMs: opts.timeoutMs ?? 1000,
        }),
    ),
    ...(opts.onProgress !== undefined ? { onProgress: opts.onProgress } : {}),
  });
}

// ============ Tests ============

describe('MultiGatewayClient.queryTransactions — fallover', () => {
  it('uses the first gateway on success', async () => {
    const g1 = await startGateway(jsonResp(200, emptyTxnsBody()));
    const g2 = await startGateway(jsonResp(200, emptyTxnsBody()));
    try {
      const client = makeClient([g1, g2]);
      const result = await client.queryTransactions({ tags: [{ name: 'App', values: ['tarn'] }] });
      assert.equal(result.edges.length, 0);
      assert.equal(g1.hits, 1, 'first gateway should be called exactly once');
      assert.equal(g2.hits, 0, 'second gateway should not be called');
    } finally {
      await g1.close();
      await g2.close();
    }
  });

  it('falls over on HTTP 5xx', async () => {
    const g1 = await startGateway(statusResp(503, 'service unavailable'));
    const g2 = await startGateway(jsonResp(200, emptyTxnsBody()));
    try {
      const client = makeClient([g1, g2]);
      const result = await client.queryTransactions({ tags: [{ name: 'App', values: ['tarn'] }] });
      assert.deepEqual(result.edges, []);
      assert.equal(g1.hits, 1);
      assert.equal(g2.hits, 1);
    } finally {
      await g1.close();
      await g2.close();
    }
  });

  it('falls over on HTTP 429', async () => {
    const g1 = await startGateway(statusResp(429, 'rate limited'));
    const g2 = await startGateway(jsonResp(200, emptyTxnsBody()));
    try {
      const client = makeClient([g1, g2]);
      await client.queryTransactions({ tags: [{ name: 'App', values: ['tarn'] }] });
      assert.equal(g1.hits, 1);
      assert.equal(g2.hits, 1);
    } finally {
      await g1.close();
      await g2.close();
    }
  });

  it('falls over on timeout', async () => {
    const g1 = await startGateway(hangResp());
    const g2 = await startGateway(jsonResp(200, emptyTxnsBody()));
    try {
      const client = makeClient([g1, g2], { timeoutMs: 80 });
      await client.queryTransactions({ tags: [{ name: 'App', values: ['tarn'] }] });
      assert.equal(g1.hits, 1);
      assert.equal(g2.hits, 1);
    } finally {
      await g1.close();
      await g2.close();
    }
  });

  it('falls over on GraphQL error', async () => {
    const g1 = await startGateway(jsonResp(200, { errors: [{ message: 'indexer hiccup' }] }));
    const g2 = await startGateway(jsonResp(200, emptyTxnsBody()));
    try {
      const client = makeClient([g1, g2]);
      await client.queryTransactions({ tags: [{ name: 'App', values: ['tarn'] }] });
      assert.equal(g1.hits, 1);
      assert.equal(g2.hits, 1);
    } finally {
      await g1.close();
      await g2.close();
    }
  });

  it('does NOT fall over on bad JSON (non-retryable)', async () => {
    const g1 = await startGateway((_req, res) => {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end('this is not json {{{{');
    });
    const g2 = await startGateway(jsonResp(200, emptyTxnsBody()));
    try {
      const client = makeClient([g1, g2]);
      await assert.rejects(
        client.queryTransactions({ tags: [{ name: 'App', values: ['tarn'] }] }),
        AllGatewaysFailedError,
      );
      assert.equal(g1.hits, 1);
      assert.equal(g2.hits, 0, 'bad_response is non-retryable; g2 should not be tried');
    } finally {
      await g1.close();
      await g2.close();
    }
  });

  it('exhausts the list and throws AllGatewaysFailedError carrying every error', async () => {
    const g1 = await startGateway(statusResp(500));
    const g2 = await startGateway(statusResp(429));
    const g3 = await startGateway(statusResp(503));
    try {
      const client = makeClient([g1, g2, g3]);
      try {
        await client.queryTransactions({ tags: [{ name: 'App', values: ['tarn'] }] });
        assert.fail('should have thrown');
      } catch (err) {
        assert.ok(err instanceof AllGatewaysFailedError);
        assert.equal(err.errors.length, 3);
        assert.equal(err.errors[0]?.kind, 'http_5xx');
        assert.equal(err.errors[1]?.kind, 'http_429');
        assert.equal(err.errors[2]?.kind, 'http_5xx');
      }
      assert.equal(g1.hits, 1);
      assert.equal(g2.hits, 1);
      assert.equal(g3.hits, 1);
    } finally {
      await g1.close();
      await g2.close();
      await g3.close();
    }
  });

  it('invokes onProgress on every retry, with index + URL info', async () => {
    const g1 = await startGateway(statusResp(503));
    const g2 = await startGateway(statusResp(429));
    const g3 = await startGateway(jsonResp(200, emptyTxnsBody()));
    const events: RetryProgress[] = [];
    try {
      const client = makeClient([g1, g2, g3], { onProgress: (e) => events.push(e) });
      await client.queryTransactions({ tags: [{ name: 'App', values: ['tarn'] }] });
      assert.equal(events.length, 2);
      assert.equal(events[0]?.failedIndex, 0);
      assert.equal(events[0]?.failedGateway, g1.url);
      assert.equal(events[0]?.nextIndex, 1);
      assert.equal(events[0]?.nextGateway, g2.url);
      assert.equal(events[0]?.totalGateways, 3);
      assert.equal(events[0]?.operation, 'queryTransactions');
      assert.ok(events[0]?.error instanceof GatewayError);
      assert.equal(events[1]?.failedIndex, 1);
      assert.equal(events[1]?.nextIndex, 2);
    } finally {
      await g1.close();
      await g2.close();
      await g3.close();
    }
  });
});

describe('MultiGatewayClient.fetchBlob — fallover', () => {
  it('falls over on 404 (TX not found — gateway behind on indexing)', async () => {
    const g1 = await startGateway(statusResp(404));
    const expectedBody = new Uint8Array([1, 2, 3, 4]);
    const g2 = await startGateway((_req, res) => {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/octet-stream');
      res.end(Buffer.from(expectedBody));
    });
    try {
      const client = makeClient([g1, g2]);
      const bytes = await client.fetchBlob('abcd1234');
      assert.deepEqual(Array.from(bytes), Array.from(expectedBody));
      assert.equal(g1.hits, 1);
      assert.equal(g2.hits, 1);
    } finally {
      await g1.close();
      await g2.close();
    }
  });

  it('returns blob bytes from the first gateway on success', async () => {
    const expected = new TextEncoder().encode('hello world');
    const g1 = await startGateway((_req, res) => {
      res.statusCode = 200;
      res.end(Buffer.from(expected));
    });
    const g2 = await startGateway(statusResp(503));
    try {
      const client = makeClient([g1, g2]);
      const bytes = await client.fetchBlob('xxxx');
      assert.deepEqual(Array.from(bytes), Array.from(expected));
      assert.equal(g1.hits, 1);
      assert.equal(g2.hits, 0);
    } finally {
      await g1.close();
      await g2.close();
    }
  });
});

describe('MultiGatewayClient — config validation', () => {
  it('throws on empty client list', () => {
    assert.throws(() => new MultiGatewayClient({ clients: [] }), /at least one/);
  });

  it('exposes gateway URLs in priority order', async () => {
    const g1 = await startGateway(jsonResp(200, emptyTxnsBody()));
    const g2 = await startGateway(jsonResp(200, emptyTxnsBody()));
    try {
      const client = makeClient([g1, g2]);
      assert.deepEqual([...client.gateways], [g1.url, g2.url]);
    } finally {
      await g1.close();
      await g2.close();
    }
  });
});
