#!/usr/bin/env node
/**
 * One-off repair: walk a defined collection, find entries without an Eid
 * tag (orphans — usually produced by batchCreate before the post-Eid-invariant
 * SDK fix), and re-write each one through the typed update path so the new
 * entry carries a properly-derived Eid + SchemaV. The original orphan stays
 * on Arweave (immutable) but becomes a superseded leaf in the Prev chain;
 * the server's resolver picks the new entry as the live head.
 *
 * Idempotent + resumable: titles successfully fixed are appended to a
 * processed-titles file (one title per line, `#` for comments). Subsequent
 * runs read that file and skip those titles. The file is pre-populatable
 * for cases where you've already fixed some entries through another path.
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
 *   --sleep-ms <n>           Default: 200    (between writes, to stay polite)
 *   --dry-run                Report what would be done without writing
 *
 * Behavior:
 *   - Auto-detects orphans (eid === null). Already-Eid'd entries are silently
 *     skipped — they're correct.
 *   - Also skips any orphan whose title appears in the skip file.
 *   - For each orphan to fix: preserves non-protocol tags (e.g., Src) on the
 *     rewrite, lets the SDK auto-stamp Eid + SchemaV.
 *   - On success, appends the title to the skip file so reruns don't re-do work.
 *
 * Safety:
 *   - --dry-run prints intended actions, no writes.
 *   - Failures on individual books don't abort the run — the script logs and
 *     continues. The failed book is NOT added to the skip file, so the next
 *     run retries it.
 */

import { TarnClient } from '../client/src/tarn.js';
import { defineSchema } from '../client/src/schema/define.js';
import { TarnStorage } from '../client/src/storage/index.js';
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
const sleepMs = parseInt(arg('--sleep-ms', '200'), 10);
const dryRun = flag('--dry-run');

if (!email || !password) {
  console.error('Missing required --email and/or --password.');
  console.error('Run with no args to see usage in the file header.');
  process.exit(1);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
// validation isn't invoked by advanced.entries.update, so the actual record
// shape can be arbitrary; we just declare the primaryKey field.
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

// advanced.entries.getEntriesSince is exactly the right read path here: it
// returns events shaped as { eid, txid, data, tags } with eid set to null
// for orphan entries. In Node (no IndexedDB), the cursor isn't persisted —
// so each invocation returns the full live state for the type, paginated
// internally up to the SDK's safety cap. Tombstoned entries don't surface.
console.log(`Fetching all live entries for type '${collectionName}'...`);
const { entries: allEvents } = await tarn.advanced.entries.getEntriesSince(collectionName);
const orphans = allEvents.filter((e) => e.eid === null);
const okCount = allEvents.length - orphans.length;
console.log(`  → ${allEvents.length} total live entries; ${orphans.length} orphans (no Eid).`);
console.log(`  → ${okCount} already have Eid — leaving those alone.`);

if (orphans.length === 0) {
  console.log('Nothing to fix. Exiting.');
  process.exit(0);
}

// ============ Repair loop ============

const PROTOCOL_TAGS = new Set(['App', 'Type', 'Lk', 'Prev', 'Eid', 'SchemaV', 'V', 'Enc', 'Gen', 'Ref', 'Op']);

let fixed = 0;
let skipped = 0;
let failed = 0;
let idx = 0;
for (const orphan of orphans) {
  idx++;
  const record = orphan.data;
  const title = record?.[titleField] ?? '(no title)';
  const txidPrefix = orphan.txid.slice(0, 14);
  const label = `[${idx}/${orphans.length}] ${String(title).padEnd(56)} → ${txidPrefix}`;

  if (skipTitles.has(title)) {
    console.log(`${label}  SKIP (in skip file)`);
    skipped++;
    continue;
  }

  // Sanity: the record must carry the primaryKey field for Eid derivation
  // to succeed on the SDK side.
  const pkValue = record?.[primaryKeyField];
  if (typeof pkValue !== 'string' || pkValue.length === 0) {
    console.log(`${label}  SKIP (no usable primaryKey '${primaryKeyField}' on record)`);
    failed++;
    continue;
  }

  // Preserve non-protocol tags from the orphan (e.g., a `Src: audible-import`
  // tag survives the rewrite). The SDK auto-stamps Eid + SchemaV on top.
  const preservedTags = orphan.tags.filter((t) => !PROTOCOL_TAGS.has(t.name));

  if (dryRun) {
    console.log(`${label}  WOULD FIX (dry run; preserved tags: ${preservedTags.map((t) => t.name).join(',') || 'none'})`);
    continue;
  }

  try {
    await tarn.advanced.entries.update(orphan.txid, collectionName, record, preservedTags);
    appendProcessed(skipFile, title);
    fixed++;
    console.log(`${label}  FIXED`);
  } catch (err) {
    failed++;
    console.log(`${label}  FAIL — ${err?.message ?? err}`);
  }

  if (sleepMs > 0) await sleep(sleepMs);
}

// ============ Summary ============

console.log();
console.log('========== Summary ==========');
console.log(`  Total orphans: ${orphans.length}`);
console.log(`  Fixed:         ${fixed}`);
console.log(`  Skipped:       ${skipped}`);
console.log(`  Failed:        ${failed}`);
if (dryRun) console.log('  (dry run — no actual writes)');
console.log();
console.log(`Skip file now contains entries to skip on future runs:`);
console.log(`  ${skipFile}`);
console.log();
if (failed > 0) {
  console.log('Some entries failed. Rerun the script to retry — failed entries are NOT added to the skip file.');
  process.exit(1);
}
