/**
 * Phase 9 — publish-forever script tests.
 *
 * Coverage:
 *   - parseArgs: flag parsing, defaults, validation.
 *   - preflightCheck: file-exists, size sanity, HTML head/tail check, sha256.
 *   - tag builders: shape + invariants (sha256 hex, version present).
 *   - run() in dry-run mode: no signing, no network, prints intent only.
 *   - run() in dry-run with --skip-pointer: pointer not promised.
 *   - End-to-end "would publish these exact bytes": hash from preflight
 *     matches a freshly-built dist/forever.html.
 *   - verifyPublished: gateway-fetch + hash-match using a stub fetch.
 *
 * Real-publish (--confirm with a real signing key) is intentionally NOT
 * exercised — that costs money and the operator runs it manually. The
 * pre/post wiring around the publish call IS exercised end-to-end via the
 * dry-run path and the verifyPublished helper.
 *
 * This file is .mjs (not .test.ts) because the script under test is .mjs;
 * keeping the test in plain JS avoids hoisting the script through the TS
 * type-checker which would force it to be re-typed. The recover test
 * runner picks up *.test.js too (see scripts/run-tests.mjs).
 */

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

import {
  parseArgs,
  preflightCheck,
  buildForeverPageTags,
  buildPointerTags,
  verifyPublished,
  run,
} from '../scripts/publish-forever.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const builderPath = resolve(root, 'scripts', 'build-forever.mjs');
const distPath = resolve(root, 'dist', 'forever.html');

// A buffer that satisfies preflight: starts with <!DOCTYPE html>, ends
// with </html>, sized comfortably above the 50KB minimum. Repeating
// padding fills the middle.
function makeValidPage(extraKb = 80) {
  const head = '<!DOCTYPE html>\n<html><head><title>t</title></head><body>\n';
  const tail = '\n</body></html>\n';
  const padBlock = 'x'.repeat(1024);
  const blocks = Math.max(1, Math.ceil(extraKb));
  return Buffer.from(head + padBlock.repeat(blocks) + tail, 'utf8');
}

// Quiet logger so the test output stays focused on assertions; tests
// that need to introspect output capture into an array.
function makeCapturingLogger() {
  const logs = [];
  const errors = [];
  return {
    logger: {
      log: (...args) => logs.push(args.join(' ')),
      error: (...args) => errors.push(args.join(' ')),
    },
    logs,
    errors,
    text() { return [...logs, ...errors].join('\n'); },
  };
}

// ============ parseArgs ============

describe('parseArgs', () => {
  test('default flags', () => {
    const flags = parseArgs([]);
    assert.equal(flags.signingKey, null);
    assert.equal(flags.file, null);
    assert.equal(flags.confirm, false);
    assert.equal(flags.skipPointer, false);
    assert.equal(flags.skipVerify, false);
    assert.deepEqual(flags.gateways, ['https://arweave.net']);
  });

  test('--confirm sets confirm true', () => {
    assert.equal(parseArgs(['--confirm']).confirm, true);
  });

  test('--signing-key consumes next arg', () => {
    const flags = parseArgs(['--signing-key', 'abc123']);
    assert.equal(flags.signingKey, 'abc123');
  });

  test('multiple --gateway flags accumulate', () => {
    const flags = parseArgs([
      '--gateway', 'https://a.net',
      '--gateway', 'https://b.net',
    ]);
    assert.deepEqual(flags.gateways, ['https://a.net', 'https://b.net']);
  });

  test('unknown flag throws', () => {
    assert.throws(() => parseArgs(['--bogus']), /Unknown flag: --bogus/);
  });

  test('positional arg throws', () => {
    assert.throws(() => parseArgs(['something']), /Unexpected positional/);
  });

  test('--help is recognised', () => {
    assert.equal(parseArgs(['--help']).help, true);
    assert.equal(parseArgs(['-h']).help, true);
  });
});

// ============ preflightCheck ============

describe('preflightCheck', () => {
  let tmpDir;
  before(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'publish-forever-test-'));
  });

  test('rejects missing file', async () => {
    const path = join(tmpDir, 'does-not-exist.html');
    await assert.rejects(preflightCheck(path), /not found/);
  });

  test('rejects too-small file', async () => {
    const path = join(tmpDir, 'small.html');
    await writeFile(path, '<!DOCTYPE html><html></html>');
    await assert.rejects(preflightCheck(path), /suspiciously small/);
  });

  test('rejects too-large file', async () => {
    const path = join(tmpDir, 'huge.html');
    // 6MB > 5MB cap. Build a buffer rather than read disk to keep test fast.
    const huge = Buffer.alloc(6 * 1024 * 1024, 'x');
    huge.write('<!DOCTYPE html><html>', 0);
    huge.write('</html>', huge.length - 7);
    await writeFile(path, huge);
    await assert.rejects(preflightCheck(path), /suspiciously large/);
  });

  test('rejects file without doctype', async () => {
    const path = join(tmpDir, 'no-doctype.html');
    const body = makeValidPage();
    // Replace doctype with garbage prefix.
    const broken = Buffer.concat([
      Buffer.from('garbage prefix\n', 'utf8'),
      body.subarray('<!DOCTYPE html>\n'.length),
    ]);
    await writeFile(path, broken);
    await assert.rejects(preflightCheck(path), /<!DOCTYPE html>/i);
  });

  test('rejects file without </html> tail', async () => {
    const path = join(tmpDir, 'no-html-tail.html');
    const body = makeValidPage();
    // Strip the </body></html> tail.
    const broken = body.subarray(0, body.length - 100);
    await writeFile(path, broken);
    await assert.rejects(preflightCheck(path), /<\/html>/i);
  });

  test('passes a valid page; returns size + sha256', async () => {
    const path = join(tmpDir, 'valid.html');
    const body = makeValidPage(80);
    await writeFile(path, body);
    const result = await preflightCheck(path);
    assert.equal(result.size, body.length);
    const expectedSha = createHash('sha256').update(body).digest('hex');
    assert.equal(result.sha256, expectedSha);
    assert.match(result.sha256, /^[0-9a-f]{64}$/);
  });
});

// ============ Tag builders ============

describe('buildForeverPageTags', () => {
  const goodSha = 'a'.repeat(64);

  test('produces tag set in expected order', () => {
    const tags = buildForeverPageTags({ version: '1.2.3', sha256: goodSha });
    const names = tags.map(t => t.name);
    assert.deepEqual(names, ['Content-Type', 'App', 'Type', 'Version', 'Sha256']);
    const byName = Object.fromEntries(tags.map(t => [t.name, t.value]));
    assert.equal(byName['Content-Type'], 'text/html');
    assert.equal(byName['App'], 'tarn-recover');
    assert.equal(byName['Type'], 'forever-page');
    assert.equal(byName['Version'], '1.2.3');
    assert.equal(byName['Sha256'], goodSha);
  });

  test('rejects empty version', () => {
    assert.throws(() => buildForeverPageTags({ version: '', sha256: goodSha }), /version/);
  });

  test('rejects malformed sha256', () => {
    assert.throws(() => buildForeverPageTags({ version: '1', sha256: 'short' }), /sha256/);
    assert.throws(() => buildForeverPageTags({ version: '1', sha256: 'g'.repeat(64) }), /sha256/);
  });
});

describe('buildPointerTags', () => {
  test('produces tag set with correct App + Type', () => {
    const tags = buildPointerTags({ version: '0.1.0' });
    const byName = Object.fromEntries(tags.map(t => [t.name, t.value]));
    assert.equal(byName['App'], 'tarn-recover');
    assert.equal(byName['Type'], 'forever-page-pointer');
    assert.equal(byName['Version'], '0.1.0');
    assert.equal(byName['Content-Type'], 'text/plain');
  });

  test('rejects empty version', () => {
    assert.throws(() => buildPointerTags({ version: '' }), /version/);
  });
});

// ============ verifyPublished ============

describe('verifyPublished', () => {
  test('returns ok when first gateway serves matching bytes', async () => {
    const body = Buffer.from('hello permanent world', 'utf8');
    const sha = createHash('sha256').update(body).digest('hex');
    const fetchStub = async (url) => {
      assert.match(url, /https:\/\/g\.example\/test-txid/);
      return {
        ok: true,
        async arrayBuffer() { return body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength); },
      };
    };
    // Override the initial sleep + retry sleeps via a custom fetchImpl that
    // resolves immediately. The implementation still awaits a 5s sleep at
    // the start; we fast-path that by patching globalThis.setTimeout.
    const origSetTimeout = globalThis.setTimeout;
    globalThis.setTimeout = (cb) => { cb(); return 0; };
    try {
      const result = await verifyPublished({
        txid: 'test-txid',
        expectedSha256: sha,
        gateways: ['https://g.example'],
        fetchImpl: fetchStub,
      });
      assert.equal(result.ok, true);
      assert.equal(result.gateway, 'https://g.example');
    } finally {
      globalThis.setTimeout = origSetTimeout;
    }
  });

  test('falls over to second gateway on 404', async () => {
    const body = Buffer.from('payload', 'utf8');
    const sha = createHash('sha256').update(body).digest('hex');
    const calls = [];
    const fetchStub = async (url) => {
      calls.push(url);
      if (url.startsWith('https://broken')) {
        return { ok: false, status: 404, async arrayBuffer() { return new ArrayBuffer(0); } };
      }
      return {
        ok: true,
        async arrayBuffer() { return body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength); },
      };
    };
    const origSetTimeout = globalThis.setTimeout;
    globalThis.setTimeout = (cb) => { cb(); return 0; };
    try {
      const result = await verifyPublished({
        txid: 'tx',
        expectedSha256: sha,
        gateways: ['https://broken.net', 'https://good.net'],
        fetchImpl: fetchStub,
      });
      assert.equal(result.ok, true);
      assert.equal(result.gateway, 'https://good.net');
      // 6 retries on broken + 1 success on good = 7 calls.
      assert.equal(calls.length, 7);
    } finally {
      globalThis.setTimeout = origSetTimeout;
    }
  });

  test('returns ok:false when hash mismatches', async () => {
    const fetchStub = async () => ({
      ok: true,
      async arrayBuffer() { return Buffer.from('other').buffer; },
    });
    const origSetTimeout = globalThis.setTimeout;
    globalThis.setTimeout = (cb) => { cb(); return 0; };
    try {
      const result = await verifyPublished({
        txid: 'tx',
        expectedSha256: 'a'.repeat(64),
        gateways: ['https://g.net'],
        fetchImpl: fetchStub,
      });
      assert.equal(result.ok, false);
      assert.ok(result.errors.some(e => e.includes('hash mismatch')));
    } finally {
      globalThis.setTimeout = origSetTimeout;
    }
  });

  test('returns ok:false when all gateways exhausted', async () => {
    const fetchStub = async () => { throw new Error('connection refused'); };
    const origSetTimeout = globalThis.setTimeout;
    globalThis.setTimeout = (cb) => { cb(); return 0; };
    try {
      const result = await verifyPublished({
        txid: 'tx',
        expectedSha256: 'a'.repeat(64),
        gateways: ['https://a.net', 'https://b.net'],
        fetchImpl: fetchStub,
      });
      assert.equal(result.ok, false);
      // 6 retries × 2 gateways = 12 errors.
      assert.equal(result.errors.length, 12);
      assert.ok(result.errors.every(e => e.includes('connection refused')));
    } finally {
      globalThis.setTimeout = origSetTimeout;
    }
  });
});

// ============ run() — dry-run path ============

describe('run() — dry-run', () => {
  before(async () => {
    // Ensure dist/forever.html exists. If a previous test run left one,
    // reuse it; otherwise build it once. The script's default file path
    // points at dist/forever.html so we need it on disk.
    if (!existsSync(distPath)) {
      const result = spawnSync(process.execPath, [builderPath], {
        cwd: root, encoding: 'utf8',
      });
      if (result.status !== 0) {
        throw new Error(`build-forever failed: ${result.stderr}`);
      }
    }
  });

  test('dry-run prints intent and reports the would-publish hash', async () => {
    const cap = makeCapturingLogger();
    const result = await run([], { logger: cap.logger });
    assert.equal(result.ok, true);
    assert.equal(result.exitCode, 0);
    assert.equal(result.dryRun, true);
    assert.match(result.sha256, /^[0-9a-f]{64}$/);
    assert.equal(result.size, (await readFile(distPath)).byteLength);

    const text = cap.text();
    assert.match(text, /DRY RUN/);
    assert.match(text, /Re-run with --confirm to publish for real\./);
    assert.match(text, /forever-page-pointer/);
    assert.match(text, /Would also publish/);
  });

  test('dry-run with --skip-pointer omits the pointer-publish promise', async () => {
    const cap = makeCapturingLogger();
    const result = await run(['--skip-pointer'], { logger: cap.logger });
    assert.equal(result.ok, true);
    assert.equal(result.dryRun, true);
    const text = cap.text();
    assert.match(text, /DRY RUN/);
    assert.equal(/Would also publish/.test(text), false);
  });

  test('dry-run rejects bogus --file path', async () => {
    const cap = makeCapturingLogger();
    const result = await run(['--file', '/no/such/path.html'], { logger: cap.logger });
    assert.equal(result.ok, false);
    assert.equal(result.exitCode, 1);
    assert.match(cap.text(), /not found/);
  });

  test('dry-run uses the provided --file', async () => {
    const tmp = await mkdtemp(join(tmpdir(), 'publish-forever-run-'));
    const path = join(tmp, 'fake.html');
    const body = makeValidPage(80);
    await writeFile(path, body);
    const cap = makeCapturingLogger();
    try {
      const result = await run(['--file', path], { logger: cap.logger });
      assert.equal(result.ok, true);
      assert.equal(result.dryRun, true);
      assert.equal(result.size, body.length);
      const expectedSha = createHash('sha256').update(body).digest('hex');
      assert.equal(result.sha256, expectedSha);
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  });

  test('dry-run never prints "Publishing forever-page" headers', async () => {
    // Defensive sentinel: real publish writes "=== Publishing
    // forever-page ===". Dry-run must never print that. If this check
    // ever flips, the script accidentally took the real-publish path.
    const cap = makeCapturingLogger();
    await run([], { logger: cap.logger });
    assert.equal(/=== Publishing forever-page ===/.test(cap.text()), false);
    assert.equal(/=== Verifying published page ===/.test(cap.text()), false);
  });

  test('--confirm without a key fails with usage error (does NOT publish)', async () => {
    // Defense-in-depth: even if a test machine has TARN_OPERATOR_WALLET
    // exported, this test must not actually publish. We unset it
    // locally for the duration of the call.
    const orig = process.env.TARN_OPERATOR_WALLET;
    delete process.env.TARN_OPERATOR_WALLET;
    const cap = makeCapturingLogger();
    try {
      const result = await run(['--confirm'], { logger: cap.logger });
      assert.equal(result.ok, false);
      assert.equal(result.exitCode, 1);
      assert.match(cap.text(), /Missing operator signing key/);
    } finally {
      if (orig !== undefined) process.env.TARN_OPERATOR_WALLET = orig;
    }
  });
});

// ============ End-to-end byte equivalence ============

describe('build → preflight byte equivalence', () => {
  test('preflight hash equals a fresh hash of dist/forever.html', async () => {
    if (!existsSync(distPath)) {
      const result = spawnSync(process.execPath, [builderPath], {
        cwd: root, encoding: 'utf8',
      });
      if (result.status !== 0) throw new Error(`build-forever failed: ${result.stderr}`);
    }
    const onDisk = await readFile(distPath);
    const expected = createHash('sha256').update(onDisk).digest('hex');
    const preflight = await preflightCheck(distPath);
    assert.equal(preflight.sha256, expected);
    assert.equal(preflight.size, onDisk.byteLength);
    // The bytes returned by preflight must be byte-identical to what
    // the publish step would sign.
    assert.equal(Buffer.compare(preflight.bytes, onDisk), 0);
  });
});
