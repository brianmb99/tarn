/**
 * Phase 7 — reference standalone HTML page.
 *
 * These tests guard the structural and scoping properties of the
 * `examples/forever/` page bundle, separate from the SDK's behavioural
 * tests. Two things matter here:
 *
 *   1. The built artifact (`dist/forever.html`) is genuinely
 *      self-contained — no `<script src=…>`, no `<link rel="stylesheet" href=…>`,
 *      no remote `import` URLs. The page must keep working when every
 *      external service is dead, including any CDN.
 *
 *   2. The page source itself surfaces ONLY owned-content APIs. Per
 *      `docs/STANDALONE_RECOVERY_PLAN.md` §1 (revised 2026-05-08), the
 *      forever page is the artifact of the permanent owned-content
 *      promise; social capability lives in the SDK for live-context
 *      apps but must not appear on the page. We can't grep the bundle
 *      for `connections()` / `shareLog()` because the SDK itself
 *      defines those methods on `Reader`; instead we lint the page's
 *      TypeScript source.
 *
 * Build is on-demand: each test that needs the artifact runs the
 * builder once and caches the path. Cheap (esbuild bundles in a few
 * hundred ms) and avoids relying on a separate build step having run.
 */

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const builderPath = resolve(root, 'scripts', 'build-forever.mjs');
const pageSourcePath = resolve(root, 'examples', 'forever', 'page.ts');
const distPath = resolve(root, 'dist', 'forever.html');

let cachedHtml: string | null = null;

before(async () => {
  // Build once, share across tests.
  if (cachedHtml !== null) return;
  const result = spawnSync(process.execPath, [builderPath], {
    cwd: root,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(
      `build-forever failed (exit ${result.status}):\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
  }
  if (!existsSync(distPath)) {
    throw new Error(`build-forever ran but ${distPath} does not exist`);
  }
  cachedHtml = await readFile(distPath, 'utf8');
});

function html(): string {
  if (cachedHtml === null) throw new Error('cachedHtml not initialised');
  return cachedHtml;
}

// ============ Structural assertions ============

test('forever-page: build produces a single HTML file', () => {
  assert.ok(existsSync(distPath), `expected ${distPath} to exist`);
  const body = html();
  assert.ok(body.startsWith('<!DOCTYPE html>'), 'expected HTML doctype');
  assert.match(body, /<\/html>\s*$/);
});

test('forever-page: no external <script src> tags', () => {
  // Allow `<script type="module">` (the inline bundle); reject any
  // `src="…"` form regardless of attribute order.
  const re = /<script\b[^>]*\bsrc\s*=/i;
  const match = html().match(re);
  assert.equal(match, null, `unexpected external <script src>: ${match?.[0]}`);
});

test('forever-page: no external stylesheet links', () => {
  const re = /<link\b[^>]*\brel\s*=\s*["']?stylesheet["']?[^>]*>/i;
  const match = html().match(re);
  assert.equal(match, null, `unexpected <link rel=stylesheet>: ${match?.[0]}`);
});

test('forever-page: no remote ESM imports', () => {
  // Any `import … from "https://"` or `import("https://…")` would mean
  // the bundle pulls live code at runtime, defeating the permanence goal.
  const re = /\bimport\s*(?:\([^)]*|[^;]*from\s*)["']https?:\/\//;
  const match = html().match(re);
  assert.equal(match, null, `unexpected remote import: ${match?.[0]}`);
});

test('forever-page: bundles the recover SDK', () => {
  // Marker strings present in the SDK source but very unlikely to
  // appear by chance anywhere else. If tree-shaking ever removes one,
  // pick another marker that survives.
  const markers = [
    'deriveCredentialLookupKey',
    'deriveRecoveryLookupKey',
    'unwrapDekChain',
    'findCredentialBlob',
  ];
  const body = html();
  for (const marker of markers) {
    assert.ok(body.includes(marker), `expected SDK marker '${marker}' in bundle`);
  }
});

test('forever-page: build is byte-stable (same input → same output)', async () => {
  // Reproducibility matters for Phase 9 (publish to Arweave) — a stable
  // hash means re-publishes of an unchanged page are cheap no-ops. If
  // this ever flakes, look for a Date.now()/Math.random() that crept
  // into the bundle, or an esbuild option that introduced randomness.
  const first = html();
  const result = spawnSync(process.execPath, [builderPath], {
    cwd: root,
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, `rebuild failed: ${result.stderr}`);
  const second = await readFile(distPath, 'utf8');
  assert.equal(second.length, first.length, 'rebuild produced a different size');
  assert.equal(second, first, 'rebuild produced different bytes');
});

// ============ Scope guard: owned-content APIs only ============

test('forever-page source: imports only the public recover entry', async () => {
  const src = await readFile(pageSourcePath, 'utf8');
  // The page must not reach into deep paths like reader/sharing-reader.
  // Allowed: '../../src/index.js' (the public entry).
  const importRe = /^\s*import\s+[^;]*from\s+['"]([^'"]+)['"];?\s*$/gm;
  const allowedSdkPaths = new Set(['../../src/index.js']);
  const offending: string[] = [];
  for (const match of src.matchAll(importRe)) {
    const spec = match[1]!;
    if (spec.startsWith('.') && !allowedSdkPaths.has(spec)) {
      offending.push(spec);
    }
  }
  assert.deepEqual(
    offending,
    [],
    `page imports relative paths other than the public entry: ${offending.join(', ')}`,
  );
});

test('forever-page source: does NOT call connections()', async () => {
  const src = await readFile(pageSourcePath, 'utf8');
  // We allow textual mentions inside comments/strings (the file
  // documents the scope guard itself), but reject any actual call
  // expression like `.connections(`. Strip comments first to keep the
  // documentation block from tripping us up.
  const stripped = stripCommentsAndStrings(src);
  assert.equal(
    /\.connections\s*\(/.test(stripped),
    false,
    'forever page must not call reader.connections() — owned content only',
  );
});

test('forever-page source: does NOT call shareLog() or allShareLog()', async () => {
  const src = await readFile(pageSourcePath, 'utf8');
  const stripped = stripCommentsAndStrings(src);
  assert.equal(
    /\.shareLog\s*\(/.test(stripped),
    false,
    'forever page must not call reader.shareLog() — owned content only',
  );
  assert.equal(
    /\.allShareLog\s*\(/.test(stripped),
    false,
    'forever page must not call reader.allShareLog() — owned content only',
  );
});

test('forever-page source: only Reader methods called are entries / allEntries / collections', async () => {
  const src = await readFile(pageSourcePath, 'utf8');
  const stripped = stripCommentsAndStrings(src);
  // Match `reader.<name>` (after we've stripped comments/strings).
  const re = /\breader\.([A-Za-z_$][\w$]*)/g;
  const allowed = new Set(['collections', 'entries', 'allEntries', 'account', 'tombstoneCount']);
  const seen = new Set<string>();
  for (const match of stripped.matchAll(re)) {
    seen.add(match[1]!);
  }
  for (const name of seen) {
    assert.ok(
      allowed.has(name),
      `forever page calls reader.${name} — not in the owned-content allowlist (${[
        ...allowed,
      ].join(', ')})`,
    );
  }
});

// ============ Helpers ============

/**
 * Naively strip block + line comments and string literals from TS source
 * so call-site greps don't false-positive on commentary or substrings
 * inside template literals. Good enough for a single hand-written file
 * we control; not a real parser.
 */
function stripCommentsAndStrings(src: string): string {
  let out = '';
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i]!;
    const next = src[i + 1];
    // Block comment
    if (c === '/' && next === '*') {
      const end = src.indexOf('*/', i + 2);
      i = end === -1 ? n : end + 2;
      out += ' ';
      continue;
    }
    // Line comment
    if (c === '/' && next === '/') {
      const nl = src.indexOf('\n', i + 2);
      i = nl === -1 ? n : nl;
      out += ' ';
      continue;
    }
    // String literal (single, double, backtick — no escape handling beyond \\)
    if (c === '"' || c === "'" || c === '`') {
      const quote = c;
      i++;
      while (i < n) {
        const ch = src[i]!;
        if (ch === '\\') {
          i += 2;
          continue;
        }
        if (ch === quote) {
          i++;
          break;
        }
        i++;
      }
      out += ' ';
      continue;
    }
    out += c;
    i++;
  }
  return out;
}
