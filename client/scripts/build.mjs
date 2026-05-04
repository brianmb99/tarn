#!/usr/bin/env node
/**
 * Build the Tarn SDK: esbuild for ESM, tsc for .d.ts files.
 *
 * ESM-only — Tarn ships exclusively as ESM. CJS was dropped because every
 * supported runtime (Node 20+, modern browsers, Vite/Webpack/Rollup) handles
 * ESM natively, and the `.js` ↔ `.cjs` extension juggling was non-trivial
 * code on the build path that bought nothing.
 *
 * Outputs:
 *   dist/esm/   — ESM with .js extensions, source maps
 *   dist/types/ — .d.ts declaration files
 */

import { build } from 'esbuild';
import { rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { glob } from 'glob';

const here = fileURLToPath(new URL('.', import.meta.url));
const root = resolve(here, '..');
const srcDir = resolve(root, 'src');
const distDir = resolve(root, 'dist');

console.log('[build] cleaning dist/');
await rm(distDir, { recursive: true, force: true });

const entryPoints = await glob('src/**/*.ts', { cwd: root, absolute: true });
console.log(`[build] found ${entryPoints.length} entry points`);

console.log('[build] esbuild ESM → dist/esm/');
await build({
  entryPoints,
  outdir: resolve(distDir, 'esm'),
  format: 'esm',
  platform: 'neutral',
  target: 'es2022',
  bundle: false,
  sourcemap: true,
  outbase: srcDir,
  // .ts → .js (default for esbuild)
});

console.log('[build] tsc --emitDeclarationOnly → dist/types/');
const tscResult = spawnSync('npx', ['tsc', '-p', 'tsconfig.build.json'], {
  cwd: root,
  stdio: 'inherit',
  shell: true,
});
if (tscResult.status !== 0) {
  console.error('[build] tsc failed');
  process.exit(tscResult.status ?? 1);
}

console.log('[build] done');
