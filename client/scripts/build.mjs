#!/usr/bin/env node
/**
 * Build the Tarn SDK: esbuild for ESM + CJS, tsc for .d.ts files.
 * Outputs:
 *   dist/esm/   — ESM with .js extensions (import specifiers stay as ./X.js)
 *   dist/cjs/   — CJS with .cjs extensions (require specifiers rewritten to ./X.cjs)
 *   dist/types/ — .d.ts declaration files
 */

import { build } from 'esbuild';
import { rm, readFile, writeFile } from 'node:fs/promises';
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

console.log('[build] esbuild CJS → dist/cjs/');
await build({
  entryPoints,
  outdir: resolve(distDir, 'cjs'),
  format: 'cjs',
  platform: 'neutral',
  target: 'es2022',
  bundle: false,
  sourcemap: true,
  outbase: srcDir,
  outExtension: { '.js': '.cjs' },
});

// CJS post-process: source uses `from './X.js'` ESM-style specifiers; esbuild
// transpiles those to `require("./X.js")`. But we emit files as `.cjs`, so the
// require targets don't exist. Rewrite ./X.js → ./X.cjs in every .cjs file.
console.log('[build] post-processing CJS require() specifiers (.js → .cjs)');
const cjsFiles = await glob('dist/cjs/**/*.cjs', { cwd: root, absolute: true });
const requireRe = /require\("(\.\.?\/[^"]*?)\.js"\)/g;
let rewritten = 0;
for (const file of cjsFiles) {
  const text = await readFile(file, 'utf8');
  const fixed = text.replace(requireRe, 'require("$1.cjs")');
  if (fixed !== text) {
    await writeFile(file, fixed);
    rewritten += 1;
  }
}
console.log(`[build] rewrote require() specifiers in ${rewritten} CJS file(s)`);

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
