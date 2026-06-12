/**
 * forever-bootstrap page tests.
 *
 * The bootstrap is the one permanent URL an app's users bookmark, so two
 * property sets matter:
 *
 *   1. Artifact properties — self-contained single file, deterministic
 *      build, config baked in correctly, and (the load-bearing scope
 *      guard) NO credential inputs and NO dynamic code paths. The page
 *      forwards users to a page that takes credentials; it must never
 *      take any itself.
 *
 *   2. Discovery logic — every query is owner-pinned (the security
 *      boundary against tag-squatting), pointer targets are verified
 *      before being offered, bad pointers are skipped, and total failure
 *      degrades to the static fallback rather than an unpinned guess.
 *
 * The logic tests import the page source directly (it is a plain ES
 * module; the browser auto-run is inert under Node) and drive it with a
 * stub fetch.
 */

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  isValidTxid,
  readConfig,
  buildPointerQuery,
  buildPageVerifyQuery,
  tagValue,
  parsePointerEdges,
  orderPointers,
  resolvePointer,
  discover,
} from '../examples/bootstrap/bootstrap.js';
import { parseArgs, buildConfig, renderPage } from '../scripts/build-bootstrap.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const builderPath = resolve(root, 'scripts', 'build-bootstrap.mjs');
const distPath = resolve(root, 'dist', 'bootstrap.html');

// 43-char base64url values for fixtures.
const OWNER = 'W4fhwtd8U1SIPCf5zT7CZ5McISfQ-jWtG99vWXolY-I';
const FALLBACK = 'F'.repeat(43);
const POINTER_1 = 'P1'.padEnd(43, 'x');
const POINTER_2 = 'P2'.padEnd(43, 'y');
const PAGE_1 = 'PAGE1'.padEnd(43, 'a');
const PAGE_2 = 'PAGE2'.padEnd(43, 'b');

const REFERENCE_FLAGS = [
  '--app-id', 'example-app',
  '--app-name', 'Example App',
  '--owner-address', OWNER,
  '--fallback-txid', FALLBACK,
];

function buildArtifact(extraFlags: string[] = []) {
  return spawnSync(process.execPath, [builderPath, ...REFERENCE_FLAGS, ...extraFlags], {
    cwd: root,
    encoding: 'utf8',
  });
}

let cachedHtml: string | null = null;

before(async () => {
  if (cachedHtml !== null) return;
  const result = buildArtifact();
  if (result.status !== 0) {
    throw new Error(`build-bootstrap failed (exit ${result.status}):\n${result.stdout}\n${result.stderr}`);
  }
  cachedHtml = await readFile(distPath, 'utf8');
});

function html(): string {
  if (cachedHtml === null) throw new Error('cachedHtml not initialised');
  return cachedHtml;
}

// ============ Artifact properties ============

test('bootstrap: build produces a single self-contained HTML file', () => {
  assert.ok(existsSync(distPath));
  const body = html();
  assert.ok(body.startsWith('<!DOCTYPE html>'));
  assert.match(body, /<\/html>\s*$/);
  assert.equal(/<script\b[^>]*\bsrc\s*=/i.test(body), false, 'no external scripts');
  assert.equal(/<link\b[^>]*\brel\s*=\s*["']?stylesheet/i.test(body), false, 'no external stylesheets');
  assert.equal(/\bimport\s*(?:\([^)]*|[^;]*from\s*)["']https?:\/\//.test(body), false, 'no remote imports');
});

test('bootstrap: config block carries the baked-in pin', () => {
  const m = html().match(/<script type="application\/json" id="bootstrap-config">([\s\S]*?)<\/script>/);
  assert.ok(m, 'config block present');
  const cfg = JSON.parse(m![1]!);
  assert.equal(cfg.appId, 'example-app');
  assert.equal(cfg.appName, 'Example App');
  assert.equal(cfg.ownerAddress, OWNER);
  assert.equal(cfg.fallbackTxid, FALLBACK);
  assert.deepEqual(cfg.gateways, ['https://arweave.net', 'https://permagate.io']);
});

test('bootstrap: page takes NO input — no form elements of any kind', () => {
  // The scope guard. The bootstrap forwards to a page where users type
  // credentials; the bootstrap itself must never grow an input. If this
  // test fails, someone is about to create a phishing-shaped artifact.
  assert.equal(/<(input|textarea|form|select)\b/i.test(html()), false);
});

test('bootstrap: no dynamic code paths', () => {
  const body = html();
  assert.equal(/\beval\s*\(/.test(body), false, 'no eval');
  assert.equal(/new\s+Function\s*\(/.test(body), false, 'no Function constructor');
  assert.equal(/\bimport\s*\(/.test(body), false, 'no dynamic import');
  assert.equal(/\binnerHTML\b/.test(body), false, 'no innerHTML sinks');
});

test('bootstrap: every GraphQL query in the artifact is owner-pinned', () => {
  // Belt-and-braces textual check on the shipped bytes: each
  // `transactions(` call site in the inlined JS must carry an `owners:`
  // filter within its argument window. Catches a refactor that drops
  // the pin from one query.
  const body = html();
  const sites: number[] = [];
  for (let idx = body.indexOf('transactions('); idx !== -1; idx = body.indexOf('transactions(', idx + 1)) {
    sites.push(idx);
  }
  assert.ok(sites.length >= 2, `expected at least 2 query sites, found ${sites.length}`);
  for (const idx of sites) {
    const window = body.slice(idx, idx + 300);
    assert.ok(/owners:/.test(window), `unpinned transactions() query at offset ${idx}: ${window.slice(0, 120)}`);
  }
});

test('bootstrap: build is byte-stable (same input → same output)', async () => {
  const first = html();
  const result = buildArtifact();
  assert.equal(result.status, 0, `rebuild failed: ${result.stderr}`);
  const second = await readFile(distPath, 'utf8');
  assert.equal(second, first, 'rebuild produced different bytes');
});

test('bootstrap: app name is HTML-escaped wherever it lands', async () => {
  const tmp = await mkdtemp(join(tmpdir(), 'bootstrap-escape-'));
  const out = join(tmp, 'evil.html');
  try {
    const result = spawnSync(process.execPath, [
      builderPath,
      '--app-id', 'example-app',
      '--app-name', '<Evil> & "Co"',
      '--owner-address', OWNER,
      '--fallback-txid', FALLBACK,
      '--out', out,
    ], { cwd: root, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    const body = await readFile(out, 'utf8');
    assert.equal(body.includes('<Evil>'), false, 'raw app name must not reach markup');
    assert.ok(body.includes('&lt;Evil&gt; &amp; &quot;Co&quot;'), 'escaped form present');
    // The JSON config block escapes < as < so it cannot close the script tag.
    assert.ok(body.includes('\\u003cEvil>'), 'config JSON neutralizes <');
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});

test('bootstrap: build fails loudly on missing or malformed flags', () => {
  const cases: string[][] = [
    [], // everything missing
    ['--app-name', 'X', '--owner-address', OWNER, '--fallback-txid', FALLBACK], // no app-id
    [...REFERENCE_FLAGS.slice(0, 6), '--fallback-txid', 'not-a-txid'],
    [...REFERENCE_FLAGS, '--gateway', 'http://insecure.example'],
    [...REFERENCE_FLAGS, '--gateway', 'https://has.a/path'],
  ];
  for (const args of cases) {
    const result = spawnSync(process.execPath, [builderPath, ...args], { cwd: root, encoding: 'utf8' });
    assert.equal(result.status, 1, `expected failure for args: ${args.join(' ')}`);
  }
});

// ============ Build helpers ============

describe('build-bootstrap helpers', () => {
  test('parseArgs defaults gateways', () => {
    const flags = parseArgs(REFERENCE_FLAGS);
    assert.deepEqual(flags.gateways, ['https://arweave.net', 'https://permagate.io']);
  });

  test('buildConfig trims trailing slashes off gateways', () => {
    const flags = parseArgs([...REFERENCE_FLAGS, '--gateway', 'https://gw.example']);
    flags.gateways = ['https://gw.example'];
    const cfg = buildConfig(flags);
    assert.deepEqual(cfg.gateways, ['https://gw.example']);
  });

  test('renderPage throws if a marker is missing', () => {
    const cfg = buildConfig(parseArgs(REFERENCE_FLAGS));
    assert.throws(
      () => renderPage({ template: '<html>no markers</html>', css: '', js: '', config: cfg }),
      /missing __INLINE_CSS__ marker/,
    );
  });
});

// ============ Pure discovery helpers ============

describe('bootstrap pure helpers', () => {
  test('isValidTxid', () => {
    assert.equal(isValidTxid(PAGE_1), true);
    assert.equal(isValidTxid('short'), false);
    assert.equal(isValidTxid('x'.repeat(44)), false);
    assert.equal(isValidTxid('!'.padEnd(43, 'a')), false);
    assert.equal(isValidTxid(undefined), false);
  });

  test('buildPointerQuery pins owner and App-Id', () => {
    const q = buildPointerQuery({ appId: 'example-app', ownerAddress: OWNER });
    assert.ok(q.includes(`owners: ["${OWNER}"]`));
    assert.ok(q.includes('values: ["tarn-recover"]'));
    assert.ok(q.includes('values: ["forever-page-pointer"]'));
    assert.ok(q.includes('values: ["example-app"]'));
    assert.ok(q.includes('sort: HEIGHT_DESC'));
  });

  test('buildPageVerifyQuery pins id, owner, Type and App-Id', () => {
    const q = buildPageVerifyQuery({ pageTxid: PAGE_1, appId: 'example-app', ownerAddress: OWNER });
    assert.ok(q.includes(`ids: ["${PAGE_1}"]`));
    assert.ok(q.includes(`owners: ["${OWNER}"]`));
    assert.ok(q.includes('values: ["forever-page"]'));
    assert.ok(q.includes('values: ["example-app"]'));
  });

  test('parsePointerEdges normalizes and drops malformed nodes', () => {
    const json = {
      data: {
        transactions: {
          edges: [
            { node: { id: POINTER_1, tags: [{ name: 'Version', value: '0.2.0' }], block: { height: 2, timestamp: 1700000100 } } },
            { node: { id: 'bad-id', tags: [], block: null } },
            { node: { id: POINTER_2, tags: [{ name: 'Version', value: '0.1.0' }], block: null } },
          ],
        },
      },
    };
    const pointers = parsePointerEdges(json);
    assert.equal(pointers.length, 2);
    assert.deepEqual(pointers[0], { pointerTxid: POINTER_1, version: '0.2.0', confirmed: true, timestamp: 1700000100 });
    assert.deepEqual(pointers[1], { pointerTxid: POINTER_2, version: '0.1.0', confirmed: false, timestamp: null });
  });

  test('parsePointerEdges throws on malformed response', () => {
    assert.throws(() => parsePointerEdges({}), /malformed/);
    assert.throws(() => parsePointerEdges({ data: { transactions: {} } }), /malformed/);
  });

  test('orderPointers puts confirmed first, preserving order within groups', () => {
    const a = { pointerTxid: 'a', confirmed: false };
    const b = { pointerTxid: 'b', confirmed: true };
    const c = { pointerTxid: 'c', confirmed: true };
    assert.deepEqual(orderPointers([a, b, c]).map((p: any) => p.pointerTxid), ['b', 'c', 'a']);
  });

  test('tagValue', () => {
    const tags = [{ name: 'Version', value: '1.0.0' }];
    assert.equal(tagValue(tags, 'Version'), '1.0.0');
    assert.equal(tagValue(tags, 'Missing'), null);
    assert.equal(tagValue(null, 'Version'), null);
  });

  test('readConfig validates every field', () => {
    const good = {
      appId: 'example-app', appName: 'Example App', ownerAddress: OWNER,
      gateways: ['https://arweave.net'], fallbackTxid: FALLBACK,
    };
    const docFor = (cfg: unknown) => ({
      getElementById: () => ({ textContent: JSON.stringify(cfg) }),
    });
    assert.deepEqual(readConfig(docFor(good)), good);
    assert.throws(() => readConfig(docFor({ ...good, appId: 'Bad Id' })), /bad appId/);
    assert.throws(() => readConfig(docFor({ ...good, ownerAddress: 'nope' })), /bad ownerAddress/);
    assert.throws(() => readConfig(docFor({ ...good, fallbackTxid: 'nope' })), /bad fallbackTxid/);
    assert.throws(() => readConfig(docFor({ ...good, gateways: [] })), /gateways/);
    assert.throws(() => readConfig(docFor({ ...good, gateways: ['http://insecure.example'] })), /gateways/);
    assert.throws(() => readConfig({ getElementById: () => null }), /missing/);
  });
});

// ============ Discovery flow (stub fetch) ============

const CONFIG = {
  appId: 'example-app',
  appName: 'Example App',
  ownerAddress: OWNER,
  gateways: ['https://stub.example'],
  fallbackTxid: FALLBACK,
};

type StubRoutes = {
  pointers?: unknown;
  bodies?: Record<string, string>;
  verify?: Record<string, unknown>;
};

/** Stub fetch routing GraphQL pointer queries, verify queries, and raw body fetches. */
function makeFetchStub(routes: StubRoutes, log: string[] = []) {
  return async (url: string, opts?: { body?: string }) => {
    log.push(url);
    if (url.endsWith('/graphql')) {
      const query = JSON.parse(opts!.body!).query as string;
      // Owner pin must be present on EVERY query this page makes.
      assert.ok(query.includes(`owners: ["${OWNER}"]`), `unpinned query: ${query}`);
      const payload = query.includes('ids:')
        ? routes.verify?.[query.match(/ids: \["([^"]+)"\]/)![1]!] ?? { data: { transactions: { edges: [] } } }
        : routes.pointers;
      return { ok: true, status: 200, json: async () => payload, text: async () => JSON.stringify(payload) };
    }
    const txid = url.split('/').pop()!;
    const body = routes.bodies?.[txid];
    if (body === undefined) return { ok: false, status: 404, json: async () => ({}), text: async () => '' };
    return { ok: true, status: 200, json: async () => JSON.parse(body), text: async () => body };
  };
}

const POINTER_RESPONSE = {
  data: {
    transactions: {
      edges: [
        { node: { id: POINTER_1, tags: [{ name: 'Version', value: '0.2.0' }], block: { height: 2, timestamp: 1700000100 } } },
        { node: { id: POINTER_2, tags: [{ name: 'Version', value: '0.1.0' }], block: { height: 1, timestamp: 1700000000 } } },
      ],
    },
  },
};

function verifyResponseFor(pageTxid: string, version: string) {
  return {
    data: {
      transactions: {
        edges: [{ node: { id: pageTxid, tags: [{ name: 'Version', value: version }, { name: 'Sha256', value: 'c'.repeat(64) }] } }],
      },
    },
  };
}

describe('bootstrap discovery flow', () => {
  test('happy path: newest pointer resolves to a verified page URL', async () => {
    const fetchImpl = makeFetchStub({
      pointers: POINTER_RESPONSE,
      bodies: { [POINTER_1]: PAGE_1 },
      verify: { [PAGE_1]: verifyResponseFor(PAGE_1, '0.2.0') },
    });
    const { resolved, pointer, gateway } = await discover({ config: CONFIG, fetchImpl });
    assert.equal(resolved.pageTxid, PAGE_1);
    assert.equal(resolved.url, `https://stub.example/${PAGE_1}`);
    assert.equal(resolved.pageVersion, '0.2.0');
    assert.equal(pointer.pointerTxid, POINTER_1);
    assert.equal(gateway, 'https://stub.example');
  });

  test('a pointer whose body is not a txid is skipped; the next one wins', async () => {
    const fetchImpl = makeFetchStub({
      pointers: POINTER_RESPONSE,
      bodies: { [POINTER_1]: 'this is not a txid', [POINTER_2]: PAGE_2 },
      verify: { [PAGE_2]: verifyResponseFor(PAGE_2, '0.1.0') },
    });
    const { resolved, errors } = await discover({ config: CONFIG, fetchImpl });
    assert.equal(resolved.pageTxid, PAGE_2);
    assert.ok(errors.some((e: string) => e.includes('body is not a txid')));
  });

  test('a pointer whose target fails owner/App-Id verification is skipped', async () => {
    // PAGE_1 verify returns empty edges (e.g. tag-squatted target);
    // PAGE_2 verifies fine.
    const fetchImpl = makeFetchStub({
      pointers: POINTER_RESPONSE,
      bodies: { [POINTER_1]: PAGE_1, [POINTER_2]: PAGE_2 },
      verify: { [PAGE_2]: verifyResponseFor(PAGE_2, '0.1.0') },
    });
    const { resolved, errors } = await discover({ config: CONFIG, fetchImpl });
    assert.equal(resolved.pageTxid, PAGE_2);
    assert.ok(errors.some((e: string) => e.includes('failed owner/App-Id verification')));
  });

  test('gateway fallover: dead first gateway, healthy second', async () => {
    const healthy = makeFetchStub({
      pointers: POINTER_RESPONSE,
      bodies: { [POINTER_1]: PAGE_1 },
      verify: { [PAGE_1]: verifyResponseFor(PAGE_1, '0.2.0') },
    });
    const fetchImpl = async (url: string, opts?: { body?: string }) => {
      if (url.startsWith('https://dead.example')) throw new Error('connection refused');
      return healthy(url, opts);
    };
    const config = { ...CONFIG, gateways: ['https://dead.example', 'https://stub.example'] };
    const { resolved, errors } = await discover({ config, fetchImpl });
    assert.equal(resolved.url, `https://stub.example/${PAGE_1}`);
    assert.ok(errors.some((e: string) => e.includes('dead.example')));
  });

  test('zero pointers on every gateway throws with per-gateway errors', async () => {
    const fetchImpl = makeFetchStub({ pointers: { data: { transactions: { edges: [] } } } });
    await assert.rejects(
      discover({ config: CONFIG, fetchImpl }),
      (err: Error & { errors: string[] }) => {
        assert.match(err.message, /discovery failed/);
        assert.ok(err.errors.some((e) => e.includes('no published recovery pages')));
        return true;
      },
    );
  });

  test('resolvePointer rejects an unverified target outright', async () => {
    const fetchImpl = makeFetchStub({ bodies: { [POINTER_1]: PAGE_1 }, verify: {} });
    await assert.rejects(
      resolvePointer({
        pointer: { pointerTxid: POINTER_1, version: '0.2.0' },
        config: CONFIG,
        gateway: 'https://stub.example',
        fetchImpl,
      }),
      /failed owner\/App-Id verification/,
    );
  });
});
