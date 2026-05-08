// Integration-style unit test for tools/rebuild-from-arweave.mjs.
//
// Spawns the CLI as a child process against a mocked Arweave HTTP server
// (GraphQL + gateway body fetches), in dry-run mode. Verifies the
// CLI parses queries correctly, paginates, fetches bodies, and prints
// a coherent summary with non-zero rebuild counts.
//
// We don't exercise the wrangler / D1 path here — that's covered by
// tests/test-rebuild-from-arweave.mjs (true end-to-end against a local
// wrangler dev). The dry-run mode is exactly the right surface to
// validate plumbing without needing Cloudflare in scope.
//
// Run: node --test tests/unit/rebuild-cli-mock.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(here, '..', '..');
const CLI = resolve(REPO_ROOT, 'tools', 'rebuild-from-arweave.mjs');

// ============ MOCK ARWEAVE ============

function makeEdge(id, tags, blockTimestamp = 1700000000) {
  return { cursor: id, node: { id, tags, block: { timestamp: blockTimestamp, height: 1 } } };
}

function tag(name, value) { return { name, value }; }

function appRegEdge(txid, appId, ts) {
  return makeEdge(txid, [
    tag('App', 'tarn'), tag('Type', 'app-reg'), tag('Lk', appId), tag('V', '1'),
  ], ts);
}

function credEdge(txid, lk, ts) {
  return makeEdge(txid, [
    tag('App', 'tarn'), tag('Type', 'cred'), tag('Lk', lk), tag('V', '1'),
  ], ts);
}

function passkeyEdge(txid, lk, credId, ts, isTombstone = false) {
  const tags = [
    tag('App', 'tarn'), tag('Type', 'passkey-reg'), tag('Lk', lk), tag('CredId', credId),
  ];
  if (isTombstone) tags.push(tag('Op', 'tombstone'));
  tags.push(tag('V', '1'));
  return makeEdge(txid, tags, ts);
}

function startMockGateway(fixtures) {
  // fixtures: { edgesByTagFilter: (vars) => edges[], bodies: { txid -> Uint8Array|string } }
  return new Promise((resolveServer) => {
    const server = http.createServer((req, res) => {
      if (req.method === 'POST' && req.url === '/graphql') {
        let body = '';
        req.on('data', (c) => body += c.toString());
        req.on('end', () => {
          let payload;
          try { payload = JSON.parse(body); } catch { res.statusCode = 400; res.end('bad json'); return; }
          const variables = payload.variables || {};
          const filtersByName = Object.fromEntries((variables.tags || []).map((t) => [t.name, t.values?.[0]]));
          const edges = fixtures.edgesFor(filtersByName);
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({
            data: { transactions: { pageInfo: { hasNextPage: false }, edges } },
          }));
        });
        return;
      }
      // gateway body fetch — path is /<txid>
      const txid = req.url.replace(/^\//, '');
      const body = fixtures.bodies[txid];
      if (body == null) {
        res.statusCode = 404;
        res.end('not found');
        return;
      }
      const buf = body instanceof Uint8Array ? Buffer.from(body) : Buffer.from(String(body));
      res.statusCode = 200;
      res.setHeader('content-type', 'application/octet-stream');
      res.end(buf);
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolveServer({ url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

function runCli(args, env = {}) {
  return new Promise((res, rej) => {
    const p = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '', stderr = '';
    p.stdout.on('data', (c) => stdout += c.toString());
    p.stderr.on('data', (c) => stderr += c.toString());
    p.on('close', (code) => res({ code, stdout, stderr }));
    p.on('error', rej);
  });
}

// ============ TESTS ============

describe('rebuild-from-arweave CLI (dry-run, mocked gateway)', () => {
  it('runs end-to-end against a mock and prints a coherent summary', async () => {
    const APP_ID = 'bookish';
    const DLK = 'd'.repeat(64);
    const CLK = 'a'.repeat(64);
    const CRED_ID = 'cred-1';

    const fixtures = {
      edgesFor(filters) {
        // Returns edges depending on which (App,Type) combo is being queried.
        if (filters.App === 'tarn' && filters.Type === 'app-reg') {
          return [appRegEdge('tx-app', APP_ID, 1700000000)];
        }
        if (filters.App === 'tarn' && filters.Type === 'cred') {
          return [credEdge('tx-cred', CLK, 1700000000)];
        }
        if (filters.App === 'tarn' && filters.Type === 'passkey-reg') {
          return [passkeyEdge('tx-pk', DLK, CRED_ID, 1700000000)];
        }
        if (filters.App === APP_ID && filters.Type === 'app-config') {
          return [makeEdge('tx-cfg', [tag('App', APP_ID), tag('Type', 'app-config'), tag('Lk', DLK)], 1700000000)];
        }
        // share-inbox / share-log / etc → none in this fixture
        return [];
      },
      bodies: {
        'tx-app': JSON.stringify({ v: 1, app_id: APP_ID, public_key: 'pk-app', invite_url_template: null, created_at: 1 }),
        'tx-cred': JSON.stringify({
          data_lookup_key: DLK,
          wrapped_data_key: 'wrap',
          public_key: 'pub',
          app: APP_ID,
        }),
        'tx-pk': JSON.stringify({
          v: 1,
          data_lookup_key: DLK,
          credential_id: CRED_ID,
          public_key: 'pk-cred',
          prf_salt: 'salt',
          device_label: null,
          created_at: 100,
        }),
        'tx-cfg': JSON.stringify({ rules: [{ allow: 'all' }], set_by: APP_ID, timestamp: 'now' }),
      },
    };

    const gw = await startMockGateway(fixtures);
    try {
      const { code, stdout, stderr } = await runCli([
        '--arweave-gateway', gw.url,
        '--gateways', gw.url,
        '--max-pages', '2',
        '--quiet',
        // No --confirm → dry-run; no wrangler invocation will happen.
      ]);
      assert.equal(code, 0, `CLI exited ${code}\nSTDOUT:\n${stdout}\nSTDERR:\n${stderr}`);
      // Summary must report at least the apps + accounts + passkeys + app-config rebuilds.
      assert.match(stdout, /apps:\s+1 rebuilt/);
      assert.match(stdout, /accounts:\s+1 rebuilt/);
      assert.match(stdout, /passkey_credentials:\s+1 rebuilt/);
      assert.match(stdout, /app-config rules:\s+1 applied/);
      assert.match(stdout, /share_inbox:\s+0 rebuilt/);
      assert.match(stdout, /share_log:\s+0 rebuilt/);
      // Dry-run footer must be present.
      assert.match(stdout, /DRY-RUN: no D1 writes applied/);
    } finally {
      await gw.close();
    }
  });

  it('skips steps named in --skip', async () => {
    const fixtures = { edgesFor: () => [], bodies: {} };
    const gw = await startMockGateway(fixtures);
    try {
      const { code, stdout } = await runCli([
        '--arweave-gateway', gw.url,
        '--gateways', gw.url,
        '--skip', 'apps,accounts,passkeys,app-config,share_inbox,share_log',
        '--quiet',
      ]);
      assert.equal(code, 0);
      assert.match(stdout, /apps:\s+SKIPPED/);
      assert.match(stdout, /accounts:\s+SKIPPED/);
      assert.match(stdout, /passkey_credentials:\s+SKIPPED/);
      assert.match(stdout, /app-config rules:\s+SKIPPED/);
      assert.match(stdout, /share_inbox:\s+SKIPPED/);
      assert.match(stdout, /share_log:\s+SKIPPED/);
    } finally {
      await gw.close();
    }
  });

  it('exits non-zero and prints partial summary on GraphQL failure', async () => {
    // Server that returns 500 — every query fails.
    const server = http.createServer((req, res) => {
      res.statusCode = 500;
      res.end('boom');
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;
    const url = `http://127.0.0.1:${port}`;
    try {
      const { code, stdout } = await runCli([
        '--arweave-gateway', url,
        '--gateways', url,
        '--quiet',
      ]);
      assert.notEqual(code, 0, 'CLI should exit non-zero on GraphQL failure');
      assert.match(stdout, /SUMMARY/);
    } finally {
      await new Promise((r) => server.close(r));
    }
  });
});
