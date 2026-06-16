// Cold-bootstrap integration tests for the delta-sync fast path.
//
// On a cold sync (no cursor — fresh device, cleared site data, first login)
// `getEntriesSince` no longer walks the entire event history serially at ~25
// inline-blob events per page. Instead it pulls the resolved live state in
// BULK (metadata pages + concurrent per-account blob fan-out) and SEEDS the
// delta cursor to max(cached_at, txid) over the live heads, so subsequent
// warm polls resume from the end of history with no replay.
//
// These tests drive the real SDK `TarnClient` (with the in-memory IndexedDB
// shim) against local wrangler, exercising:
//   1. cold bootstrap returns the full live state, decrypted, exactly once;
//   2. the seed cursor is correct — a warm poll sees nothing, a later write
//      is caught (seed neither overshoots nor undershoots);
//   3. the delta path resumes correctly after a bootstrap (deletes surface);
//   4. an empty / all-deleted account bootstraps to nothing and still tracks
//      subsequent writes (graceful fall-through to the delta loop).
//
// Run: node --import tsx tests/test-cold-bootstrap.mjs [apiBaseUrl]
// Requires: cd api && npx wrangler dev --port 8787
//           cd api && npx wrangler d1 migrations apply tarn-api --local

import './indexeddb-shim.mjs';
import { TarnClient } from '../client/src/tarn.js';
import { clearBlobsForScope } from '../client/src/blob-cache.js';
import { seedTestApp, DEFAULT_APP_ID, forceAllowRulesForAccount, randomUsername, sleep } from './helpers.mjs';

const API_BASE = process.argv[2] || 'http://localhost:8787';

await seedTestApp();

let passed = 0;
let failed = 0;

function log(status, name, detail = '') {
  const icon = status === 'PASS' ? '✓' : '✗';
  console.log(`  ${icon} ${name}${detail ? ': ' + detail : ''}`);
}

async function test(name, fn) {
  try {
    await fn();
    log('PASS', name);
    passed++;
  } catch (err) {
    log('FAIL', name, err.message);
    failed++;
    if (process.env.VERBOSE) console.error('    ', err.stack);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

// Register a fresh account via the SDK and grant write rules (mirrors the raw
// tests' forceAllowRulesForAccount). Returns the authenticated client + dlk.
async function freshClient() {
  const client = new TarnClient(API_BASE, DEFAULT_APP_ID);
  await client.register(randomUsername(), 'cold-boot-pass-123', { recoveryAcknowledged: true });
  await forceAllowRulesForAccount(client.dataLookupKey);
  return { client, dlk: client.dataLookupKey };
}

// ============ 1. FULL-STATE BOOTSTRAP + SEED CORRECTNESS ============

console.log('\n=== 1. Cold bootstrap returns full live state and seeds the cursor ===');

await test('Cold getEntriesSince bulk-bootstraps all live entries; warm poll replays nothing', async () => {
  const { client, dlk } = await freshClient();
  const type = `cold-${Date.now()}`;

  // Write enough entries to cross the bulk fan-out CONCURRENCY=20 boundary so
  // a second concurrent wave runs. Each carries a distinct Eid.
  const N = 22;
  const eids = [];
  for (let i = 0; i < N; i++) {
    const eid = `cb-${i}-${crypto.randomUUID()}`;
    eids.push(eid);
    await client.createEntry(type, { idx: i, marker: `v${i}` }, [{ name: 'Eid', value: eid }]);
  }
  await sleep(800); // let cached_at settle past the write burst

  // createEntry pre-populates the blob cache for the writing device, which
  // would make the bootstrap's blob fan-out a pure cache hit. Clear it so the
  // fan-out actually goes to the network — exercising the per-account
  // (accountKey) blob-read path the cold sign-in uses on a fresh device.
  await clearBlobsForScope(DEFAULT_APP_ID, dlk);

  // COLD sync — no cursor for this type → bulk bootstrap path.
  const cold = await client.getEntriesSince(type);
  assert(cold.deleted.length === 0, `cold bootstrap should have 0 deletes, got ${cold.deleted.length}`);
  assert(cold.entries.length === N, `cold bootstrap should return all ${N} live entries, got ${cold.entries.length}`);

  // Data integrity: every entry decrypted correctly, every Eid present once.
  const seen = new Map();
  for (const e of cold.entries) {
    assert(e.data && typeof e.data.idx === 'number', `entry ${e.eid} missing decrypted data`);
    assert(e.data.marker === `v${e.data.idx}`, `entry ${e.eid} decrypted data mismatch`);
    seen.set(e.eid, (seen.get(e.eid) || 0) + 1);
  }
  for (const eid of eids) assert(seen.get(eid) === 1, `Eid ${eid} not returned exactly once (got ${seen.get(eid) || 0})`);

  // WARM poll immediately after — the seed cursor must sit at the end of
  // history, so nothing replays.
  const warm = await client.getEntriesSince(type);
  assert(warm.entries.length === 0, `warm poll after bootstrap should see 0 entries, got ${warm.entries.length}`);
  assert(warm.deleted.length === 0, `warm poll should see 0 deletes, got ${warm.deleted.length}`);
});

await test('Seed does not overshoot: a write after bootstrap is caught exactly once', async () => {
  const { client } = await freshClient();
  const type = `cold-after-${Date.now()}`;

  const eids = [];
  for (let i = 0; i < 5; i++) {
    const eid = `ca-${i}-${crypto.randomUUID()}`;
    eids.push(eid);
    await client.createEntry(type, { idx: i }, [{ name: 'Eid', value: eid }]);
  }
  await sleep(600);

  const cold = await client.getEntriesSince(type);
  assert(cold.entries.length === 5, `cold should see 5, got ${cold.entries.length}`);

  // Write AFTER the seed — proves the seed didn't overshoot the true end of
  // history (which would skip this) nor undershoot (which would replay originals).
  const newEid = `ca-new-${crypto.randomUUID()}`;
  await client.createEntry(type, { idx: 999 }, [{ name: 'Eid', value: newEid }]);
  await sleep(500);

  const catchUp = await client.getEntriesSince(type);
  assert(catchUp.entries.length === 1, `catch-up should return exactly the 1 new entry, got ${catchUp.entries.length}`);
  assert(catchUp.entries[0].eid === newEid, `catch-up returned wrong entry: ${catchUp.entries[0].eid}`);
  for (const eid of eids) {
    assert(!catchUp.entries.some(e => e.eid === eid), `original ${eid} was replayed after seed`);
  }
});

// ============ 2. DELTA RESUMES AFTER BOOTSTRAP (deletes surface) ============

console.log('\n=== 2. Delete after a cold bootstrap surfaces on the next poll ===');

await test('A delete after bootstrap surfaces as a deletion event', async () => {
  const { client } = await freshClient();
  const type = `cold-del-${Date.now()}`;

  const victimEid = `cd-victim-${crypto.randomUUID()}`;
  const { txid: victimTxid } = await client.createEntry(type, { idx: 0 }, [{ name: 'Eid', value: victimEid }]);
  await client.createEntry(type, { idx: 1 }, [{ name: 'Eid', value: `cd-keep-${crypto.randomUUID()}` }]);
  await sleep(600);

  const cold = await client.getEntriesSince(type);
  assert(cold.entries.length === 2, `cold should see 2, got ${cold.entries.length}`);

  // Tombstone the victim, then poll: the delta path (resumed from the bootstrap
  // seed) must surface the deletion by Eid.
  await client.deleteEntry(victimTxid, type, [{ name: 'Eid', value: victimEid }]);
  await sleep(500);

  const afterDel = await client.getEntriesSince(type);
  assert(afterDel.deleted.includes(victimEid), `delete of ${victimEid} should surface (got deleted=${JSON.stringify(afterDel.deleted)})`);
  assert(!afterDel.entries.some(e => e.eid === victimEid), `deleted entry should not also appear live`);
});

// ============ 3. EMPTY / ALL-DELETED ACCOUNT FALLS THROUGH ============

console.log('\n=== 3. Empty account bootstraps to nothing and still tracks writes ===');

await test('Cold bootstrap on an empty type returns nothing, then catches a first write', async () => {
  const { client } = await freshClient();
  const type = `cold-empty-${Date.now()}`;

  // No entries written. Cold bootstrap finds 0 live → falls through to the
  // delta loop, which also returns nothing and leaves the cursor at start.
  const cold = await client.getEntriesSince(type);
  assert(cold.entries.length === 0, `empty cold should see 0, got ${cold.entries.length}`);
  assert(cold.deleted.length === 0, `empty cold should see 0 deletes, got ${cold.deleted.length}`);

  // A first write must still be caught by the next poll (the fall-through must
  // not have wedged the cursor past it).
  const eid = `ce-first-${crypto.randomUUID()}`;
  await client.createEntry(type, { idx: 7 }, [{ name: 'Eid', value: eid }]);
  await sleep(500);

  const next = await client.getEntriesSince(type);
  assert(next.entries.length === 1, `first write should be caught, got ${next.entries.length}`);
  assert(next.entries[0].eid === eid, `wrong entry caught: ${next.entries[0].eid}`);
});

// ============ SUMMARY ============

console.log(`\n=== Cold-bootstrap results: ${passed} passed, ${failed} failed ===\n`);
process.exit(failed > 0 ? 1 : 0);
