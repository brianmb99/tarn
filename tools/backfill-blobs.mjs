#!/usr/bin/env node
/**
 * One-shot backfill for entries missing blob_data in D1.
 *
 * Runs against a deployed tarn-api's D1 via `wrangler d1 execute`.
 * Fetches each missing blob from Turbo gateway (primary) or Arweave (fallback)
 * and UPDATEs the row with the encrypted bytes.
 *
 * Usage:
 *   node tools/backfill-blobs.mjs [--remote|--local]
 *
 * Default: --remote (production D1).
 *
 * Context: before issue #4 ("D1 as authoritative"), blob backfill ran lazily
 * in every refresh cycle. #4 removes that hot-path behavior, so any entry
 * cached before blob caching was added must be filled in once.
 */

import { spawnSync } from 'node:child_process';
import { writeFileSync, unlinkSync } from 'node:fs';

const TURBO_GW = 'https://turbo-gateway.com';
const ARWEAVE_GW = 'https://arweave.net';
const FETCH_TIMEOUT_MS = 15_000;

const target = process.argv.includes('--local') ? '--local' : '--remote';

const API_CWD = new URL('../api', import.meta.url).pathname.replace(/^\/(\w:)/, '$1');

// Use --command for SELECTs (returns row data). Shell-quote the SQL.
function d1Query(sql) {
  const quoted = `"${sql.replace(/"/g, '\\"')}"`;
  const cmd = `npx wrangler d1 execute tarn-api ${target} --json --command ${quoted}`;
  const result = spawnSync(cmd, { cwd: API_CWD, encoding: 'utf8', shell: true });
  if (result.status !== 0) {
    console.error('d1 error:', result.stderr);
    throw new Error(`wrangler d1 exit ${result.status}`);
  }
  const out = result.stdout;
  const start = out.search(/[[{]/);
  if (start < 0) throw new Error('no JSON in wrangler output');
  const parsed = JSON.parse(out.slice(start));
  return Array.isArray(parsed) ? parsed[0] : parsed;
}

// Use --file for UPDATEs (avoids shell argv limits with large hex blobs).
function d1Exec(sql) {
  const tmp = new URL('.backfill-blobs.sql.tmp', import.meta.url).pathname.replace(/^\/(\w:)/, '$1');
  writeFileSync(tmp, sql);
  const result = spawnSync('npx', ['wrangler', 'd1', 'execute', 'tarn-api', target, '--file', tmp], {
    cwd: API_CWD, encoding: 'utf8', shell: true,
  });
  try { unlinkSync(tmp); } catch {}
  if (result.status !== 0) {
    console.error('d1 error:', result.stderr);
    throw new Error(`wrangler d1 exit ${result.status}`);
  }
}

async function fetchBlob(txid) {
  for (const gw of [TURBO_GW, ARWEAVE_GW]) {
    try {
      const res = await fetch(`${gw}/${txid}`, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
      if (res.ok) return new Uint8Array(await res.arrayBuffer());
    } catch {}
  }
  return null;
}

function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function main() {
  console.log(`Backfilling against ${target} D1...`);

  const selectRes = d1Query("SELECT txid FROM entries WHERE blob_data IS NULL AND is_tombstone = 0");
  const rows = selectRes?.results || [];
  console.log(`Found ${rows.length} entries needing blob_data.`);

  if (rows.length === 0) return;

  let filled = 0;
  let skipped = 0;

  for (const { txid } of rows) {
    const blob = await fetchBlob(txid);
    if (!blob) {
      console.warn(`  ✗ ${txid} — not available on any gateway`);
      skipped++;
      continue;
    }
    const hex = toHex(blob);
    d1Exec(`UPDATE entries SET blob_data = X'${hex}' WHERE txid = '${txid}';`);
    console.log(`  ✓ ${txid} — ${blob.length} bytes`);
    filled++;
  }

  console.log(`\nDone. Filled ${filled}, skipped ${skipped}.`);
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
