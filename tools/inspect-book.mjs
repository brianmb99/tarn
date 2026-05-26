#!/usr/bin/env node
/**
 * Diagnostic: dump every version of a single record from Tarn so we can
 * see exactly what's in the user's account end-to-end.
 *
 * Use this to investigate "I made a change but it's not showing up" —
 * the output reveals which combinations of (orphan / Eid'd, live /
 * superseded, with or without a given field) are actually on Arweave,
 * which the server resolver picks as the head, and what the typed
 * surface (Collection.get) returns.
 *
 * The Tarn write path uploads to Turbo (Arweave bundling) SYNCHRONOUSLY:
 * a 200 response means the bytes are in the pipeline. If a write isn't
 * visible here, it never reached Tarn — investigate the client side
 * (network errors, swallowed exceptions, wrong account, etc.).
 *
 * Usage:
 *   # via env vars (preferred — keeps creds out of shell history)
 *   $env:TARN_EMAIL = "you@example.com"
 *   $env:TARN_PASSWORD = "..."
 *   node --import tsx tools/inspect-book.mjs --title "The Road to Oxiana"
 *
 *   # or via CLI
 *   node --import tsx tools/inspect-book.mjs \
 *     --email <email> --password <pw> --title "The Road to Oxiana"
 *
 *   # filter by primaryKey instead of title
 *   node --import tsx tools/inspect-book.mjs --book-id <bookId>
 *
 *   # dump ALL books with their tags (no filter)
 *   node --import tsx tools/inspect-book.mjs --all
 *
 * Optional args:
 *   --api-base <url>       Default: https://api.tarn.dev
 *   --app-id <appId>       Default: bookish
 *   --collection <name>    Default: books
 *   --primary-key <field>  Default: bookId
 *   --title-field <field>  Default: title
 *   --schema-version <n>   Default: 5
 *   --status-fields <csv>  Default: status,completed,isComplete,completedAt
 *     Comma-separated field names to highlight on each version. The
 *     script prints these alongside each entry's metadata so it's
 *     immediately obvious whether the "completed" state is on the
 *     latest version, an older version, or nowhere.
 */

import { TarnClient, defineSchema, TarnStorage } from '../client/src/index.js';

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
const email = arg('--email', process.env.TARN_EMAIL);
const password = arg('--password', process.env.TARN_PASSWORD);
const collectionName = arg('--collection', 'books');
const primaryKeyField = arg('--primary-key', 'bookId');
const titleField = arg('--title-field', 'title');
const schemaVersion = parseInt(arg('--schema-version', '5'), 10);
const titleFilter = arg('--title');
const bookIdFilter = arg('--book-id');
const statusFields = (arg('--status-fields', 'status,completed,isComplete,completedAt') || '')
  .split(',').map((s) => s.trim()).filter(Boolean);
const showAll = flag('--all');

if (!email || !password) {
  console.error('Missing credentials. Set TARN_EMAIL + TARN_PASSWORD env vars or pass --email + --password.');
  process.exit(1);
}
if (!titleFilter && !bookIdFilter && !showAll) {
  console.error('Specify one of --title <name>, --book-id <id>, or --all.');
  process.exit(1);
}

// ============ SDK setup ============

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
console.log();

// ============ Pull all entries (live set only — server-resolved) ============

console.log(`Fetching live entries for type '${collectionName}' (server-resolved, latest per Eid)...`);
const { entries: liveEvents } = await tarn.advanced.entries.getEntriesSince(collectionName);
console.log(`  → ${liveEvents.length} live entries returned by the server resolver.`);
console.log();

// ============ Match ============

function matches(event) {
  if (showAll) return true;
  const rec = event.data ?? {};
  if (bookIdFilter && rec[primaryKeyField] === bookIdFilter) return true;
  if (titleFilter && rec[titleField] === titleFilter) return true;
  return false;
}

const matched = liveEvents.filter(matches);
console.log(`Matched ${matched.length} live entr${matched.length === 1 ? 'y' : 'ies'}.`);
console.log();

if (matched.length === 0) {
  console.log('No live entry matched the filter. Either:');
  console.log('  - The record was never written to this account.');
  console.log('  - The record exists but the filter field (title / bookId) is different.');
  console.log('  - The record is tombstoned (server filters it out of live set).');
  console.log();
  console.log('Try --all to see every live record, or check the exact spelling.');
  process.exit(0);
}

// ============ Render ============

function formatEid(eid) {
  if (eid === null || eid === undefined) return 'ORPHAN (no Eid tag)';
  return eid;
}

function formatTags(tags) {
  // Sort tags by name for readable diffing.
  const sorted = [...tags].sort((a, b) => a.name.localeCompare(b.name));
  return sorted.map((t) => `${t.name}=${t.value.length > 50 ? t.value.slice(0, 50) + '…' : t.value}`).join(', ');
}

function tag(tags, name) {
  return tags.find((t) => t.name === name)?.value ?? null;
}

for (const event of matched) {
  const rec = event.data ?? {};
  const title = rec[titleField] ?? '(no title)';
  const bookId = rec[primaryKeyField] ?? '(no primaryKey)';

  console.log('='.repeat(72));
  console.log(`Title:      ${title}`);
  console.log(`PrimaryKey: ${primaryKeyField}=${bookId}`);
  console.log();

  console.log('--- Live (server-resolved head) ---');
  console.log(`  txid:       ${event.txid}`);
  console.log(`  Eid (tag):  ${formatEid(event.eid)}`);
  console.log(`  Prev (tag): ${tag(event.tags, 'Prev') ?? '(none)'}`);
  console.log(`  SchemaV:    ${tag(event.tags, 'SchemaV') ?? '(none)'}`);
  console.log(`  Gateway:    https://arweave.net/${event.txid}`);
  console.log(`  Tags:       ${formatTags(event.tags)}`);

  if (statusFields.length > 0) {
    console.log(`  Status fields on decoded record:`);
    for (const field of statusFields) {
      const value = rec[field];
      const display = value === undefined
        ? '(absent)'
        : (typeof value === 'object' ? JSON.stringify(value) : String(value));
      console.log(`    ${field}: ${display}`);
    }
  }
  console.log();

  // Also show what the typed surface would return for this record. If it
  // differs from the raw event, that's a resolution bug.
  try {
    const typed = await tarn[collectionName].get(bookId);
    if (typed === null) {
      console.log('--- Typed Collection.get() ---');
      console.log('  null — typed surface does NOT see this record.');
      console.log('  This is the bug if you expected the record to surface in Bookish.');
    } else {
      const typedMatchesLive = JSON.stringify(typed) === JSON.stringify(rec);
      console.log(`--- Typed Collection.get('${bookId}') ---`);
      console.log(`  matches live: ${typedMatchesLive}`);
      if (!typedMatchesLive) {
        console.log('  ⚠ DIFFERS from getEntriesSince live event — investigate resolution path.');
        if (statusFields.length > 0) {
          for (const field of statusFields) {
            const a = rec[field];
            const b = typed[field];
            if (JSON.stringify(a) !== JSON.stringify(b)) {
              console.log(`    ${field}: live=${JSON.stringify(a)}  typed=${JSON.stringify(b)}`);
            }
          }
        }
      }
    }
  } catch (err) {
    console.log(`--- Typed Collection.get('${bookId}') ---`);
    console.log(`  error: ${err?.message ?? err}`);
  }
  console.log();
}

// ============ Summary diagnostic ============

console.log('='.repeat(72));
console.log('Diagnostic notes:');
console.log();
console.log(`  • The "live" section above is what the server's resolver picks as the head version`);
console.log(`    after applying tombstone + Prev-chain + Eid-dedup rules. This is the version`);
console.log(`    Bookish *should* be reading via tarn.<collection>.getEntriesSince() — assuming`);
console.log(`    the entry has an Eid tag (orphans are dropped by the typed delta surface).`);
console.log();
console.log(`  • If a status field (e.g., "completed") is absent above but you expected it,`);
console.log(`    Bookish's "mark complete" write never reached Tarn. Check the network in the`);
console.log(`    app at the moment of the action.`);
console.log();
console.log(`  • If the status field IS present in the live event but Bookish renders the book as`);
console.log(`    not-complete, Bookish's read code is using a stale local copy or wrong path.`);
console.log();
console.log(`  • The "Live" section uses tarn.advanced.entries.getEntriesSince which surfaces`);
console.log(`    orphans too. If Eid shows "ORPHAN", Bookish's typed sync (Collection.getEntriesSince)`);
console.log(`    will DROP this entry — that's a known fix-orphan-eids.mjs target.`);
