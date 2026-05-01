#!/usr/bin/env node
/**
 * Walk tests/unit/ for *.test.js / *.test.ts and run them via
 * `node --import tsx --test`. Avoids depending on shell glob expansion
 * (varies by platform / npm-script invocation) and Node 22+ native globbing.
 *
 * Becomes useful as step 6 of the SDK redesign converts JS modules to TS
 * — tsx resolves '.js' import specifiers in JS test files to '.ts' source
 * when present, so the same test runner works through the migration.
 */

import { readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const testsDir = resolve(here, '..', 'tests', 'unit');

function findTestFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      out.push(...findTestFiles(full));
    } else if (entry.endsWith('.test.js') || entry.endsWith('.test.ts')) {
      out.push(full);
    }
  }
  return out;
}

const files = findTestFiles(testsDir);
if (files.length === 0) {
  console.error('No *.test.js / *.test.ts files found under tests/unit/');
  process.exit(1);
}

const result = spawnSync(
  process.execPath,
  ['--import', 'tsx', '--test', ...files],
  { stdio: 'inherit' },
);
process.exit(result.status ?? 1);
