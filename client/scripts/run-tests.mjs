#!/usr/bin/env node
/**
 * Find every *.test.ts under tests/ and run them via `node --import tsx --test`.
 *
 * Avoids depending on shell glob expansion (varies by platform / npm-script
 * invocation) and Node 22+ native globbing. Stays useful as we add more test
 * files in step 2 onward — drop a new `*.test.ts` under tests/ and the runner
 * picks it up.
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
    } else if (entry.endsWith('.test.ts')) {
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
