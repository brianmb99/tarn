#!/usr/bin/env node
/**
 * Build the reference standalone recovery page.
 *
 * Bundles `examples/forever/page.ts` (which imports `@tarn/recover` from
 * the local `src/index.ts`), inlines the resulting JS + CSS into
 * `examples/forever/page.html`, and writes the single-file artifact to
 * `dist/forever.html`.
 *
 * The output is intentionally self-contained — no CDN scripts, no
 * external CSS, no fetch-this-at-runtime payloads. The point of the
 * page is permanence (Phase 9 publishes it to Arweave); a single file
 * with the recovery SDK fully inlined is the cheapest way to guarantee
 * the page keeps working after every other piece of infrastructure
 * dies. See `docs/STANDALONE_RECOVERY_PLAN.md` §"Publish recovery page
 * to Arweave" for the rationale.
 *
 * Reproducibility: esbuild's deterministic output + literal string
 * substitution + no minifier randomness means identical inputs produce
 * identical output bytes. Phase 9 (Arweave publish) relies on this so
 * re-publishes of an unchanged page are no-ops.
 */

import { build as esbuild } from 'esbuild';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const exampleDir = resolve(root, 'examples', 'forever');
const distDir = resolve(root, 'dist');
const outPath = resolve(distDir, 'forever.html');

console.log('[build-forever] bundling page.ts via esbuild');
const entryPoint = resolve(exampleDir, 'page.ts');
const result = await esbuild({
  entryPoints: [entryPoint],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  write: false,
  // Deterministic output. No minifier, no name-mangling — easy to
  // diff, easy to reproduce, easy to audit ("does this byte-blob
  // really only do what the source claims?").
  minify: false,
  legalComments: 'inline',
  // No source maps in the inlined output; auditors can rebuild from
  // source if they want them. Keeps the artifact's size honest and the
  // bytes free of base64 noise that would obscure the actual code.
  sourcemap: false,
  // The recover package only depends on libraries that are pure JS or
  // ship their own WASM; everything bundles cleanly into the browser.
  define: {
    // Neutralise any accidental Node.process references in deps.
    'process.env.NODE_ENV': '"production"',
  },
});

if (result.outputFiles.length !== 1) {
  console.error(`[build-forever] expected 1 output file, got ${result.outputFiles.length}`);
  process.exit(1);
}
const bundledJs = result.outputFiles[0].text;

console.log('[build-forever] reading template assets');
const htmlTemplate = await readFile(resolve(exampleDir, 'page.html'), 'utf8');
const css = await readFile(resolve(exampleDir, 'page.css'), 'utf8');

if (!htmlTemplate.includes('__INLINE_CSS__')) {
  throw new Error('template missing __INLINE_CSS__ marker');
}
if (!htmlTemplate.includes('__INLINE_JS__')) {
  throw new Error('template missing __INLINE_JS__ marker');
}

// Substitute literally (no template-string interpolation) so any `$&`
// or backreference characters in the bundled JS pass through unharmed.
const html = htmlTemplate
  .replace('__INLINE_CSS__', () => css)
  .replace('__INLINE_JS__', () => bundledJs);

await mkdir(distDir, { recursive: true });
await writeFile(outPath, html, 'utf8');

const sizeKb = (Buffer.byteLength(html, 'utf8') / 1024).toFixed(1);
console.log(`[build-forever] wrote ${outPath} (${sizeKb} KB)`);
