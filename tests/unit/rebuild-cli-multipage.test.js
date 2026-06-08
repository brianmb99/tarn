// Multi-page GraphQL pagination guard for tools/rebuild-from-arweave.mjs (tarn#61).
//
// The existing rebuild-cli-mock.test.js exercises the CLI end-to-end against a
// mock, but every fixture returns a SINGLE page (pageInfo.hasNextPage=false)
// with one edge per type. That leaves the CLI's real pagination loop
// (`gqlPage`: collect edges, follow `pageInfo.hasNextPage`, advance `after` to
// the last edge's cursor, cap at --max-pages) UNcovered — a regression that
// dropped page 2+ or mis-threaded the cursor would not be caught.
//
// This test drives that REAL wiring: it spawns the CLI (dry-run) against a mock
// Arweave that paginates the Type=cred (accounts) and Type=passkey-reg
// (passkeys) queries across multiple pages, with cross-page latest-wins and
// cross-page tombstoning. It then asserts the SUMMARY counts reflect edges
// collected from ALL pages and reducer semantics applied across the page
// boundary — proving pagination + gateway-body-fetch + rebuild-core reducers
// are wired together correctly, not just the single-page happy path.
//
// Run: node --test tests/unit/rebuild-cli-multipage.test.js
//   or via the umbrella: npm run test:unit

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(here, '..', '..');
const CLI = resolve(REPO_ROOT, 'tools', 'rebuild-from-arweave.mjs');

function tag(name, value) { return { name, value }; }
function makeEdge(id, tags, ts = 1700000000) {
  return { cursor: id, node: { id, tags, block: { timestamp: ts, height: 1 } } };
}
function credEdge(txid, lk, ts, { tombstoneRef = null } = {}) {
  const tags = [tag('App', 'tarn'), tag('Type', 'cred'), tag('Lk', lk)];
  if (tombstoneRef) { tags.push(tag('Op', 'tombstone')); tags.push(tag('Ref', tombstoneRef)); }
  tags.push(tag('V', '1'));
  return makeEdge(txid, tags, ts);
}
function credBody(dlk, app = 'bookish') {
  return JSON.stringify({ data_lookup_key: dlk, wrapped_data_key: `wrap-${dlk}`, public_key: `pub-${dlk}`, app });
}
function passkeyEdge(txid, lk, credId, ts, { tombstone = false } = {}) {
  const tags = [tag('App', 'tarn'), tag('Type', 'passkey-reg'), tag('Lk', lk), tag('CredId', credId)];
  if (tombstone) tags.push(tag('Op', 'tombstone'));
  tags.push(tag('V', '1'));
  return makeEdge(txid, tags, ts);
}
function passkeyBody(dlk, credId) {
  return JSON.stringify({
    v: 1, data_lookup_key: dlk, credential_id: credId,
    public_key: `pk-${credId}`, prf_salt: `salt-${credId}`, device_label: null, created_at: 100,
  });
}

// A paginating mock Arweave. `pagesByType` maps a Type tag value to an array of
// pages, each page an array of edges. The server honours the `after` cursor the
// CLI sends (the cursor of the last edge on the prior page) and sets
// pageInfo.hasNextPage accordingly. Body GETs are served from `bodies`.
function startPaginatingMock({ pagesByType, bodies }) {
  return new Promise((resolveServer) => {
    const server = http.createServer((req, res) => {
      if (req.method === 'POST' && req.url === '/graphql') {
        let body = '';
        req.on('data', (c) => body += c.toString());
        req.on('end', () => {
          let payload;
          try { payload = JSON.parse(body); } catch { res.statusCode = 400; res.end('bad json'); return; }
          const vars = payload.variables || {};
          const filters = Object.fromEntries((vars.tags || []).map((t) => [t.name, t.values?.[0]]));
          const pages = pagesByType[filters.Type] || [[]];
          // Resolve which page the `after` cursor points past. after=null → page 0.
          let pageIdx = 0;
          if (vars.after != null) {
            // Find the page whose LAST edge cursor === after, serve the NEXT page.
            for (let i = 0; i < pages.length; i++) {
              const last = pages[i][pages[i].length - 1];
              if (last && last.cursor === vars.after) { pageIdx = i + 1; break; }
            }
          }
          const edges = pages[pageIdx] || [];
          const hasNextPage = pageIdx < pages.length - 1 && (pages[pageIdx + 1]?.length ?? 0) > 0;
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({ data: { transactions: { pageInfo: { hasNextPage }, edges } } }));
        });
        return;
      }
      const txid = req.url.replace(/^\//, '');
      const b = bodies[txid];
      if (b == null) { res.statusCode = 404; res.end('not found'); return; }
      res.statusCode = 200;
      res.setHeader('content-type', 'application/octet-stream');
      res.end(Buffer.from(String(b)));
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
      env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '', stderr = '';
    p.stdout.on('data', (c) => stdout += c.toString());
    p.stderr.on('data', (c) => stderr += c.toString());
    p.on('close', (code) => res({ code, stdout, stderr }));
    p.on('error', rej);
  });
}

describe('rebuild CLI — multi-page GraphQL pagination (tarn#61)', () => {
  it('collects edges across 3 pages and applies latest-wins + tombstone across the page boundary', async () => {
    // accounts (Type=cred): three pages.
    //  - dlk-A: created page1 (tx-a1), rotated page3 (tx-a2) → latest wins (1 row)
    //  - dlk-B: created page1 (tx-b1), tombstoned page2 (tx-b1tomb Ref=tx-b1) → 0 rows
    //  - dlk-C: created page2 (tx-c1) → 1 row
    //  - dlk-D: created page3 (tx-d1) → 1 row
    // Total found across pages = 6 edges (incl. the tombstone edge, which the
    // reducer counts in `found`); rebuilt = 3 (A,C,D); tombstoned = 1.
    const credPages = [
      [ // page 1
        credEdge('tx-a1', 'clk-A', 1700000000),
        credEdge('tx-b1', 'clk-B', 1700000000),
      ],
      [ // page 2
        credEdge('tx-b1tomb', 'clk-B', 1700000100, { tombstoneRef: 'tx-b1' }),
        credEdge('tx-c1', 'clk-C', 1700000100),
      ],
      [ // page 3
        credEdge('tx-a2', 'clk-A', 1700000200), // newer rotation of dlk-A
        credEdge('tx-d1', 'clk-D', 1700000200),
      ],
    ];
    // passkeys (Type=passkey-reg): two pages, cross-page tombstone.
    //  - cred-1: reg page1 (tx-p1), tombstone page2 (tx-p1tomb) → group dropped
    //  - cred-2: reg page2 (tx-p2) → 1 row
    // found = 3 edges; rebuilt = 1; tombstoned = 1.
    const pkPages = [
      [ passkeyEdge('tx-p1', 'dlk-A', 'cred-1', 1700000000) ],
      [
        passkeyEdge('tx-p1tomb', 'dlk-A', 'cred-1', 1700000100, { tombstone: true }),
        passkeyEdge('tx-p2', 'dlk-A', 'cred-2', 1700000100),
      ],
    ];

    const bodies = {
      'tx-a1': credBody('dlk-A'), 'tx-a2': credBody('dlk-A'),
      'tx-b1': credBody('dlk-B'),
      'tx-c1': credBody('dlk-C'), 'tx-d1': credBody('dlk-D'),
      // tombstone bodies are never parsed (excluded before body fetch) but the
      // gateway may still be asked; serve something harmless.
      'tx-b1tomb': credBody('dlk-B'),
      'tx-p1': passkeyBody('dlk-A', 'cred-1'),
      'tx-p2': passkeyBody('dlk-A', 'cred-2'),
      'tx-p1tomb': passkeyBody('dlk-A', 'cred-1'),
    };

    const mock = await startPaginatingMock({
      pagesByType: { cred: credPages, 'passkey-reg': pkPages },
      bodies,
    });
    try {
      const { code, stdout, stderr } = await runCli([
        '--arweave-gateway', mock.url,
        '--gateways', mock.url,
        '--max-pages', '10',
        '--skip', 'apps,app-config,share_inbox,share_log',
        '--quiet',
      ]);
      assert.equal(code, 0, `CLI exited ${code}\nSTDOUT:\n${stdout}\nSTDERR:\n${stderr}`);

      // accounts: all 6 cred edges found across 3 pages; 3 rebuilt; 1 tombstoned.
      assert.match(stdout, /accounts:\s+3 rebuilt \(6 found, 1 tombstoned/,
        `accounts summary did not reflect cross-page collection.\n${stdout}`);
      // passkeys: 3 edges across 2 pages; 1 rebuilt; 1 tombstoned (cred-1 group).
      assert.match(stdout, /passkey_credentials:\s+1 rebuilt \(3 found, 1 tombstoned/,
        `passkeys summary did not reflect cross-page collection.\n${stdout}`);
      assert.match(stdout, /DRY-RUN: no D1 writes applied/);
    } finally {
      await mock.close();
    }
  });

  it('respects --max-pages: stops paginating at the cap even if hasNextPage is still true', async () => {
    // Build 5 pages of cred edges, each with one fresh dlk. With --max-pages 2,
    // the CLI must collect ONLY pages 1 and 2 (2 edges), not all 5.
    const credPages = [];
    for (let i = 0; i < 5; i++) {
      credPages.push([ credEdge(`tx-${i}`, `clk-${i}`, 1700000000 + i) ]);
    }
    const bodies = {};
    for (let i = 0; i < 5; i++) bodies[`tx-${i}`] = credBody(`dlk-${i}`);

    const mock = await startPaginatingMock({ pagesByType: { cred: credPages }, bodies });
    try {
      const { code, stdout } = await runCli([
        '--arweave-gateway', mock.url,
        '--gateways', mock.url,
        '--max-pages', '2',
        '--skip', 'apps,passkeys,app-config,share_inbox,share_log',
        '--quiet',
      ]);
      assert.equal(code, 0);
      // Exactly 2 edges found (the cap), 2 rebuilt. NOT 5.
      assert.match(stdout, /accounts:\s+2 rebuilt \(2 found,/, `--max-pages cap not honoured.\n${stdout}`);
    } finally {
      await mock.close();
    }
  });
});
