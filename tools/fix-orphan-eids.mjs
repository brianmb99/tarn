#!/usr/bin/env node
/**
 * One-off repair: walk a defined collection, find entries without an Eid
 * tag (orphans — usually produced by batchCreate before the post-Eid-invariant
 * SDK fix), and rewrite them in batches via the bulk-create endpoint so
 * each new entry carries a properly-derived Eid + SchemaV plus a Prev tag
 * pointing to its orphan predecessor. The server's resolver picks the new
 * entry as the live head and supersedes the orphan via the Prev chain.
 *
 * Why batching (not per-item update)
 *   The write rate limit is 100 calls/hour per account. A single-item
 *   update path means 1 hit per orphan — a 266-orphan account would need
 *   3 hours of carefully-paced writes. Batched create counts as 1 hit per
 *   batch regardless of batch size (up to 25 items), so 266 orphans
 *   fits in 11 hits.
 *
 * Rate-limit handling
 *   If a batch returns 429, the script sleeps until the top of the next
 *   clock hour (with a small safety margin) and retries the same batch.
 *   The rate-limit bucket is calendar-hour keyed, so the next-hour
 *   transition guarantees a fresh budget. Retries are unbounded by
 *   default — the script keeps trying until the work is done or a
 *   non-rate-limit error surfaces.
 *
 * Idempotency + resumability
 *   Each successful batch appends every title in it to a processed-titles
 *   file. Reruns skip those titles. Independently, the orphan filter
 *   (eid === null) excludes any entry whose Eid has been written —
 *   so even if the skip file is wiped, the script won't double-fix
 *   anything that already has an Eid on Arweave.
 *
 * Already-superseded skip
 *   Before fixing, the script also skips any orphan whose primaryKey
 *   value matches an existing Eid'd entry in the same collection. This
 *   covers the case where the user already did a manual delete-and-
 *   recreate of the same logical record — the orphan version is dead
 *   data; rewriting it would resurrect a duplicate that the user has
 *   intentionally deleted from their app view.
 *
 * Usage (run via tsx so it picks up the TS source — no SDK build required):
 *   node --import tsx tools/fix-orphan-eids.mjs \
 *     --email <email> \
 *     --password <pw>
 *
 * Optional args:
 *   --api-base <url>         Default: https://api.tarn.dev
 *   --app-id <appId>         Default: bookish
 *   --collection <name>      Default: books
 *   --primary-key <field>    Default: bookId
 *   --title-field <field>    Default: title  (used for skip-file matching)
 *   --schema-version <n>     Default: 5      (SchemaV tag value on the new entry)
 *   --skip-file <path>       Default: tools/fix-orphan-eids.<collection>.processed.txt
 *   --batch-size <n>         Default: 25     (server max)
 *   --max-rate-limit-waits   Default: 24     (give up after this many hour-boundary waits)
 *   --dry-run                Report what would be done without writing
 *
 * Heads-up: max_entries
 *   Each fix adds one new entry while leaving the orphan in D1 (superseded,
 *   not tombstoned). If the account's `max_entries` rule is tight, the
 *   batch will fail with "Write denied by authorization rules". Bump the
 *   limit on the account before running, or accept partial completion
 *   and rerun after raising it.
 */

import { TarnClient, defineSchema, TarnStorage } from '../client/src/index.js';
import { readFileSync, appendFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ============ Args ============

const argv = process.argv.slice(2);
function arg(name, fallback = null) {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : fallback;
}
function flag(name) {
  return argv.includes(name);
}

const apiBase = arg('--api-base', 'https://api.tarn.dev');
const appId = arg('--app-id', 'bookish');
const email = arg('--email');
const password = arg('--password');
const collectionName = arg('--collection', 'books');
const primaryKeyField = arg('--primary-key', 'bookId');
const titleField = arg('--title-field', 'title');
const schemaVersion = parseInt(arg('--schema-version', '5'), 10);
const skipFile = arg(
  '--skip-file',
  resolve(__dirname, `fix-orphan-eids.${collectionName}.processed.txt`),
);
const batchSize = Math.min(25, Math.max(1, parseInt(arg('--batch-size', '25'), 10)));
const maxRateLimitWaits = parseInt(arg('--max-rate-limit-waits', '24'), 10);
const dryRun = flag('--dry-run');

if (!email || !password) {
  console.error('Missing required --email and/or --password.');
  console.error('Run with no args to see usage in the file header.');
  process.exit(1);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ============ Helpers ============

function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

function msUntilNextHour() {
  const now = new Date();
  const next = new Date(now);
  next.setHours(next.getHours() + 1, 0, 0, 0);
  return next.getTime() - now.getTime();
}

function formatDuration(ms) {
  const totalSec = Math.ceil(ms / 1000);
  const min = Math.floor(totalSec / 60);
  const sec = totalSec % 60;
  if (min === 0) return `${sec}s`;
  return `${min}m${String(sec).padStart(2, '0')}s`;
}

// ============ Skip file ============

function loadSkipTitles(path) {
  const set = new Set();
  if (!existsSync(path)) return set;
  const content = readFileSync(path, 'utf8');
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    set.add(line);
  }
  return set;
}

function appendProcessed(path, title) {
  if (!existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(
      path,
      `# fix-orphan-eids: titles processed successfully (newline-separated).\n` +
      `# Manually-edited entries above the marker are pre-existing skip rules.\n`,
    );
  }
  appendFileSync(path, title + '\n');
}

const skipTitles = loadSkipTitles(skipFile);
console.log(`Skip file: ${skipFile}`);
console.log(`  → ${skipTitles.size} title(s) loaded (will be skipped).`);

// ============ SDK setup ============

// Minimal schema — only `primaryKey` matters for Eid derivation. Field-level
// validation isn't invoked by advanced.entries.batchCreate; primaryKey is
// what the auto-stamp code reads off each item.
const schema = defineSchema({
  appId,
  version: schemaVersion,
  collections: {
    [collectionName]: {
      primaryKey: primaryKeyField,
      fields: { [primaryKeyField]: { type: 'string', required: true } },
    },
  },
});

console.log(`Connecting to ${apiBase} as ${email} (app: ${appId})...`);
const tarn = await TarnClient.create({
  apiBase,
  appId,
  schema,
  storage: TarnStorage.memory(),
});
await tarn.login(email, password);
console.log('Logged in.');

// ============ Fetch entries ============

console.log(`Fetching all live entries for type '${collectionName}'...`);
const { entries: allEvents } = await tarn.advanced.entries.getEntriesSince(collectionName);
const orphans = allEvents.filter((e) => e.eid === null);
const withEid = allEvents.filter((e) => e.eid !== null);
const okCount = withEid.length;
console.log(`  → ${allEvents.length} total live entries; ${orphans.length} orphans (no Eid).`);
console.log(`  → ${okCount} already have Eid — leaving those alone.`);

if (orphans.length === 0) {
  console.log('Nothing to fix. Exiting.');
  process.exit(0);
}

// Build a set of primaryKey values that are ALREADY covered by an Eid'd
// entry. Any orphan whose primaryKey lands in this set is "already
// superseded" — the user has done a delete-and-recreate (or the Eid'd
// version arrived via some other path), so rewriting the orphan would
// resurrect a duplicate. Skip it.
const livePkValues = new Set();
for (const e of withEid) {
  const pk = e.data?.[primaryKeyField];
  if (typeof pk === 'string' && pk.length > 0) livePkValues.add(pk);
}

// ============ Filter ============

const toFix = [];
const skipped = [];
const supersededByLive = [];
const unfixable = [];
for (const orphan of orphans) {
  const title = orphan.data?.[titleField] ?? '(no title)';
  if (skipTitles.has(title)) {
    skipped.push({ title, txid: orphan.txid });
    continue;
  }
  const pkValue = orphan.data?.[primaryKeyField];
  if (typeof pkValue !== 'string' || pkValue.length === 0) {
    unfixable.push({ title, txid: orphan.txid });
    continue;
  }
  if (livePkValues.has(pkValue)) {
    supersededByLive.push({ title, txid: orphan.txid, pk: pkValue });
    continue;
  }
  toFix.push(orphan);
}

console.log(
  `  → ${toFix.length} to fix; ${skipped.length} skipped (in skip file); ` +
  `${supersededByLive.length} already superseded by an Eid'd record (same ${primaryKeyField}); ` +
  `${unfixable.length} unfixable (no primaryKey).`,
);
if (supersededByLive.length > 0) {
  console.log('Already-superseded orphans (will NOT be rewritten):');
  for (const s of supersededByLive) {
    console.log(`    ${s.title.padEnd(56)} → ${s.txid.slice(0, 14)}  (pk ${s.pk.slice(0, 10)}...)`);
  }
}
if (unfixable.length > 0) {
  console.log('Unfixable entries:');
  for (const u of unfixable) console.log(`    ${u.title.padEnd(56)} → ${u.txid.slice(0, 14)}`);
}

if (toFix.length === 0) {
  console.log('Nothing to fix after filtering. Exiting.');
  process.exit(0);
}

// ============ Repair loop ============

const batches = chunk(toFix, batchSize);
console.log(`Processing ${toFix.length} orphan(s) in ${batches.length} batch(es) of up to ${batchSize}.`);
console.log();

let fixedCount = 0;
let failedCount = 0;
let bucketWaitsSpent = 0;

for (let bi = 0; bi < batches.length; bi++) {
  const batch = batches[bi];
  const batchLabel = `[batch ${bi + 1}/${batches.length}] ${batch.length} entries`;

  if (dryRun) {
    console.log(`${batchLabel}  WOULD FIX (dry run)`);
    for (const o of batch) {
      const title = o.data?.[titleField] ?? '(no title)';
      console.log(`    ${title.padEnd(56)} → ${o.txid.slice(0, 14)}`);
    }
    continue;
  }

  // Build per-item Prev tags. Each new entry chains via Prev to its
  // orphan predecessor so the server's resolver picks the new (with-Eid)
  // version as the live head and treats the orphan as superseded.
  const records = batch.map((o) => o.data);
  const perItemTags = batch.map((o) => [{ name: 'Prev', value: o.txid }]);

  let success = false;
  while (!success) {
    try {
      await tarn.advanced.entries.batchCreate(collectionName, records, [], perItemTags);
      success = true;
      // Persist titles only after the wire write succeeded.
      for (const o of batch) {
        const title = o.data?.[titleField] ?? '(no title)';
        appendProcessed(skipFile, title);
      }
      fixedCount += batch.length;
      console.log(`${batchLabel}  FIXED`);
    } catch (err) {
      const msg = err?.message ?? String(err);
      if (/rate limit/i.test(msg)) {
        if (bucketWaitsSpent >= maxRateLimitWaits) {
          console.log(`${batchLabel}  GIVE UP — rate-limited and out of retry budget (${maxRateLimitWaits} waits used)`);
          failedCount += batch.length;
          break; // exit inner retry loop, continue to next batch
        }
        const waitMs = msUntilNextHour() + 10_000;
        bucketWaitsSpent++;
        console.log(
          `${batchLabel}  RATE LIMITED — sleeping ${formatDuration(waitMs)} until next-hour budget reset ` +
          `(retry ${bucketWaitsSpent}/${maxRateLimitWaits})...`,
        );
        await sleep(waitMs);
        // Loop back and retry the same batch.
      } else {
        // Non-rate-limit error: log and move on. The batch is NOT marked
        // processed, so a rerun will retry it.
        console.log(`${batchLabel}  FAIL — ${msg}`);
        failedCount += batch.length;
        break;
      }
    }
  }
}

// ============ Summary ============

console.log();
console.log('========== Summary ==========');
console.log(`  Total orphans:           ${orphans.length}`);
console.log(`  Skipped (in skip file):  ${skipped.length}`);
console.log(`  Already superseded:      ${supersededByLive.length}`);
console.log(`  Unfixable (no PK):       ${unfixable.length}`);
console.log(`  Fixed:                   ${fixedCount}`);
console.log(`  Failed:                  ${failedCount}`);
console.log(`  Rate-limit waits used:   ${bucketWaitsSpent}`);
if (dryRun) console.log('  (dry run — no actual writes)');
console.log();
console.log(`Skip file: ${skipFile}`);
console.log();
if (failedCount > 0) {
  console.log('Some entries failed. Rerun the script to retry — failed entries are NOT in the skip file.');
  process.exit(1);
}
