#!/usr/bin/env node
/**
 * Find every *.test.ts under tests/ and run them via `node --import tsx --test`.
 * Mirrors the tarn-client and root scripts/run-unit-tests.mjs runners.
 */

import { readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const testsDir = resolve(here, '..', 'tests');

function findTestFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      out.push(...findTestFiles(full));
    } else if (entry.endsWith('.test.ts') || entry.endsWith('.test.js')) {
      out.push(full);
    }
  }
  return out;
}

const files = findTestFiles(testsDir);
if (files.length === 0) {
  console.error('No *.test.ts files found under tests/');
  process.exit(1);
}

const result = spawnSync(
  process.execPath,
  ['--import', 'tsx', '--test', ...files],
  { stdio: 'inherit' },
);
process.exit(result.status ?? 1);
