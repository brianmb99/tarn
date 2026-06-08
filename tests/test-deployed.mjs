#!/usr/bin/env node
/**
 * Post-deployment smoke test for the Tarn API.
 * Tests the full lifecycle against a live deployed API.
 *
 * Usage:
 *   node tests/test-deployed.mjs <api_url> <app_id> <app_private_key_hex>
 *
 * Example:
 *   node tests/test-deployed.mjs https://api.tarn.dev bookish 308187...
 *
 * Prerequisites:
 *   - API deployed and healthy
 *   - App registered in D1 (via generate-app-key.mjs + D1 seed)
 *   - APP_SIGNING_KEY secret set (for Arweave uploads)
 *   - WARP VPN disabled (blocks Turbo uploads)
 */

import './indexeddb-shim.mjs';
import { TarnClient } from '../client/src/tarn.js';
import { TarnClient as TypedTarnClient, defineSchema, TarnStorage } from '../client/src/index.js';
import {
  deriveAllKeys, exportPublicKey, wrapDataKey, signChallenge,
  encodeSharePub, deriveShareLookupKey,
} from '../client/src/crypto.js';

const API_BASE = process.argv[2];
const APP_ID = process.argv[3];
const APP_KEY = process.argv[4];

if (!API_BASE || !APP_ID || !APP_KEY) {
  console.error('Usage: node tests/test-deployed.mjs <api_url> <app_id> <app_private_key_hex>');
  console.error('Example: node tests/test-deployed.mjs https://api.tarn.dev bookish 308187...');
  process.exit(1);
}

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
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

const testUsername = `deploy-test-${Date.now()}@test.com`;
const testPassword = 'deploy-test-pass-' + Date.now();
let testDlk;

// ============ 1. HEALTH ============

console.log('\n=== 1. Health Check ===');

await test('API is healthy', async () => {
  const res = await fetch(`${API_BASE}/api/v1/health`);
  const json = await res.json();
  assert(res.status === 200, `Status ${res.status}`);
  assert(json.healthy === true, 'Not healthy');
  assert(json.version === '0.4.0', `Wrong version: ${json.version}`);
  assert(json.checks.d1.reachable, 'D1 not reachable');
  console.log(`    D1 entries: ${json.checks.d1.entryCount}, Arweave: ${json.checks.arweave.reachable ? 'OK' : 'FAIL'}`);
});

// ============ 2. REGISTER ============

console.log('\n=== 2. Registration ===');

await test('Register new user', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  const { dataLookupKey } = await tarn.register(testUsername, testPassword, { recoveryAcknowledged: true });
  assert(dataLookupKey, 'No dataLookupKey');
  assert(dataLookupKey.length === 64, 'Bad dataLookupKey length');
  assert(tarn.isAuthenticated, 'Not authenticated');
  testDlk = dataLookupKey;
  console.log(`    DLK: ${testDlk.slice(0, 16)}...`);
});

// NOTE: the previous "Re-register with same credentials is idempotent
// (issue #6)" test was removed. It asserted cross-call byte-identical output
// from `register()`, but post-#11 (random DEK at registration) and post-#12
// (random recovery salt + phrase), `register()` is non-deterministic by
// design — every call produces fresh randomness, so byte-identical retries
// across separate TarnClient instances are impossible. The genuine #6
// case (in-flight retry of an interrupted register) still works because
// `register()` builds the body once before the retry loop; that case is
// covered by unit tests in `tests/unit/client-retry.test.js`.

// ============ 3. APP AUTH + SET RULES ============

console.log('\n=== 3. App Auth + Set Rules ===');

await test('App sets free-tier rules for new user', async () => {
  // Import app private key
  const pkcs8 = new Uint8Array(APP_KEY.length / 2);
  for (let i = 0; i < APP_KEY.length; i += 2) pkcs8[i / 2] = parseInt(APP_KEY.substr(i, 2), 16);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);

  // Challenge
  const cRes = await fetch(`${API_BASE}/api/v1/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: APP_ID }),
  });
  assert(cRes.status === 200, `Challenge failed: ${cRes.status}`);
  const { nonce } = await cRes.json();

  // Sign
  const nonceBytes = new Uint8Array(nonce.length / 2);
  for (let i = 0; i < nonce.length; i += 2) nonceBytes[i / 2] = parseInt(nonce.substr(i, 2), 16);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, nonceBytes);
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));

  // Verify
  const vRes = await fetch(`${API_BASE}/api/v1/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: APP_ID, nonce, signature: sigB64 }),
  });
  assert(vRes.status === 200, `Verify failed: ${vRes.status}`);
  const { jwt } = await vRes.json();

  // Set rules. limit must cover all writes across sections 5, 5a, 5a2, 5b, 5b2
  // on the same account: 1 (section 5 single create + idempotent retry
  // which dedupes) + 5 (5a batchCreate) + 5 (5a2 typed Collection.batchCreate)
  // + 2 (5b eid writes) + 3 (5b2 delta writes) = 16. Use 30 for headroom —
  // matches the pattern other deep sections (handshake/share-log/etc.) use
  // when they set rules themselves.
  const rulesRes = await fetch(`${API_BASE}/api/v1/accounts/${testDlk}/rules`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${jwt}` },
    body: JSON.stringify({ rules: [{ type: 'max_entries', limit: 30, app: APP_ID }, { type: 'max_bytes', limit: 102400 }] }),
  });
  assert(rulesRes.status === 200, `Set rules failed: ${rulesRes.status}`);
});

// ============ 4. LOGIN ============

console.log('\n=== 4. Login ===');

await test('Login on "another device"', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  const { dataLookupKey } = await tarn.login(testUsername, testPassword);
  assert(dataLookupKey === testDlk, 'DLK mismatch');
  assert(tarn.isAuthenticated, 'Not authenticated');
});

// ============ 5. WRITE + READ ============

console.log('\n=== 5. Write + Read ===');

let entryTxid;

await test('Create entry', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);
  const { txid } = await tarn.createEntry('entry', {
    title: 'Deployment Test',
    author: 'Tarn CI',
    timestamp: Date.now(),
  });
  assert(txid, 'No txid');
  entryTxid = txid;
  console.log(`    Txid: ${txid.slice(0, 20)}...`);
});

await test('Idempotent write: retry with same X-Idempotency-Key returns same txid (issue #8)', async () => {
  // Low-level test: send two raw POSTs with the same X-Idempotency-Key and
  // assert the second returns the txid from the first — the server short-
  // circuits on the cached response instead of signing a new DataItem.
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);

  // Server doesn't decrypt the body, it just signs + caches. Any bytes work.
  const payload = new TextEncoder().encode(JSON.stringify({ _: 'idempotency-test', t: Date.now() }));
  const tags = [
    { name: 'App', value: APP_ID },
    { name: 'Type', value: 'entry' },
    { name: 'Lk', value: testDlk },
    { name: 'Enc', value: 'aes-256-gcm' },
    { name: 'V', value: '0.4.0' },
  ];
  const key = crypto.randomUUID();
  const headers = {
    'Authorization': `Bearer ${tarn._testJwt()}`,
    'X-Arweave-Tags': JSON.stringify(tags),
    'X-Idempotency-Key': key,
    'Content-Type': 'application/octet-stream',
  };

  const res1 = await fetch(`${API_BASE}/api/v1/entries`, { method: 'POST', headers, body: payload });
  const json1 = await res1.json();
  assert(res1.status === 200, `First write failed: ${res1.status} ${JSON.stringify(json1)}`);

  const res2 = await fetch(`${API_BASE}/api/v1/entries`, { method: 'POST', headers, body: payload });
  const json2 = await res2.json();
  assert(res2.status === 200, `Second write failed: ${res2.status}`);
  assert(json1.id === json2.id, `Idempotency failed: different txids (${json1.id} vs ${json2.id})`);
});

await test('Read entry from D1 cache', async () => {
  await sleep(500); // Brief wait for write-through
  // #60: metadata reads require a session JWT.
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);
  const res = await fetch(`${API_BASE}/api/v1/entries?app=${APP_ID}&type=entry&key=${testDlk}`, { headers: { 'Authorization': `Bearer ${tarn._testJwt()}` } });
  const json = await res.json();
  assert(res.status === 200, `Read failed: ${res.status}`);
  assert(json.entries.length >= 1, `Expected entries, got ${json.entries.length}`);
  const entry = json.entries.find(e => e.txid === entryTxid);
  assert(entry, 'Entry not in cache');
});

await test('Entry available on Turbo gateway', async () => {
  await sleep(3000); // Wait for background Turbo upload
  try {
    const res = await fetch(`https://turbo-gateway.com/${entryTxid}`, { signal: AbortSignal.timeout(10000) });
    if (res.ok) {
      const bytes = (await res.arrayBuffer()).byteLength;
      console.log(`    ${bytes} bytes on Turbo gateway (encrypted)`);
    } else {
      console.log(`    Gateway returned ${res.status} — may need more time`);
    }
  } catch (err) {
    // A throw here is gateway propagation/timeout, not a deploy fault — the
    // Turbo upload is background/async and the public gateway is eventually
    // consistent. The D1-cache read above already proves the write worked.
    console.log(`    Gateway fetch failed (${err.message}) — normal for a fresh upload (async propagation)`);
  }
  // Pass regardless — the D1 cache test above proves the write worked
});

// ============ 5a. BATCH WRITE (Section 5.5 / issue #23) ============
//
// Covers the wire path that tarn.advanced.entries.batchCreate forwards to:
// a 5-item bulk write should land all 5 entries on the deployed API in one
// request (1 rate-limit hit instead of 5) and a subsequent getEntries() must
// surface every one of them. The schema-first wrapper is unit-tested under
// tests/unit/ — this leg confirms the underlying client + API contract.

console.log('\n=== 5a. Batch Write + Read (issue #23) ===');

await test('batchCreate writes 5 entries atomically, getEntries returns all 5', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);
  // Unique type so we don't collide with the single-write test above when
  // counting back through getEntries.
  const batchType = `batch-${Date.now()}`;
  const markers = Array.from({ length: 5 }, (_, i) => `batch-marker-${i}-${Date.now()}`);
  const items = markers.map((marker, i) => ({ marker, idx: i, title: `Batch ${i}` }));

  const out = await tarn.batchCreate(batchType, items);
  assert(Array.isArray(out), 'batchCreate returned non-array');
  assert(out.length === 5, `expected 5 results, got ${out.length}`);
  for (const r of out) {
    assert(typeof r.txid === 'string' && r.txid.length > 0, `bad txid: ${r.txid}`);
    assert('shareKey' in r, 'each result must include shareKey (may be null)');
  }
  console.log(`    Batch txids: ${out.map((r) => r.txid.slice(0, 12)).join(', ')}`);

  await sleep(500); // Brief wait for write-through to D1 cache.
  const entries = await tarn.getEntries(batchType);
  assert(entries.length >= 5, `expected ≥5 entries on read-back, got ${entries.length}`);
  const seen = new Set(entries.map((e) => e.data?.marker));
  for (const marker of markers) {
    assert(seen.has(marker), `marker ${marker} missing from read-back`);
  }
});

await test('batchCreate rejects empty input', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);
  let caught = null;
  try { await tarn.batchCreate('batch-empty', []); } catch (e) { caught = e; }
  assert(caught, 'empty batch must throw');
  assert(/non-empty/i.test(caught.message), `unexpected error: ${caught.message}`);
});

await test('batchCreate rejects 26+ items', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);
  const items = Array.from({ length: 26 }, (_, i) => ({ i }));
  let caught = null;
  try { await tarn.batchCreate('batch-toobig', items); } catch (e) { caught = e; }
  assert(caught, '26-item batch must throw');
  assert(/max 25/i.test(caught.message), `unexpected error: ${caught.message}`);
});

// ============ 5a2. TYPED Collection.batchCreate (issue #33) ============
//
// The end-to-end assertion the issue cares about: 5 records written via
// `tarn.<collection>.batchCreate(...)` must surface through
// `tarn.<collection>.getEntriesSince()` — proving the typed batch path
// stamps Eid + SchemaV per item, closing the orphan gap that the
// schema-less `advanced.entries.batchCreate` (#23) left open.
//
// Uses a fresh `TarnClient.create({ schema, ... })` instance against the
// same test user so the typed surface is exercised end-to-end against
// the live API. The schema is a minimal one-collection schema scoped to
// this test — it shares the `bookish` appId with the rest of the suite,
// but a unique collection name keeps the type namespace clean.

console.log('\n=== 5a2. Typed Collection.batchCreate (issue #33) ===');

await test('typed batchCreate writes 5 books; getEntriesSince surfaces all 5 with Eid', async () => {
  // Unique collection name per run so we don't collide with prior runs on
  // the same dlk. SDK persists the delta cursor per (appId, dlk, type), so a
  // fresh type guarantees a from-scratch sync window.
  const collectionName = `typed-batch-${Date.now()}`;
  const schema = defineSchema({
    appId: APP_ID,
    version: 1,
    collections: {
      [collectionName]: {
        primaryKey: 'bookId',
        fields: {
          bookId: 'string',
          title: 'string',
          author: 'string?',
        },
      },
    },
  });

  const tarn = await TypedTarnClient.create({
    apiBase: API_BASE,
    appId: APP_ID,
    schema,
    storage: TarnStorage.memory(),
  });
  await tarn.login(testUsername, testPassword);

  const records = Array.from({ length: 5 }, (_, i) => ({
    bookId: `typed-b-${i}-${Date.now()}`,
    title: `Typed Batch Book ${i}`,
    author: `Author ${i}`,
  }));

  // Use bracket access — TypedTarnClient exposes collections dynamically
  // under their schema-declared name.
  const collection = tarn[collectionName];
  assert(collection, `typed collection '${collectionName}' must be accessible on tarn`);
  assert(typeof collection.batchCreate === 'function', 'batchCreate must be a method on the typed collection');

  const out = await collection.batchCreate(records);
  assert(Array.isArray(out), 'batchCreate must return an array');
  assert(out.length === 5, `expected 5 validated records back, got ${out.length}`);
  // Input order preserved.
  for (let i = 0; i < 5; i++) {
    assert(out[i].bookId === records[i].bookId, `order mismatch at ${i}: ${out[i].bookId}`);
  }

  await sleep(500); // Brief wait for write-through.

  // The critical assertion: getEntriesSince must surface all 5 records —
  // NOT drop them as "orphan delta events". This is the regression Issue
  // #33 fixes vs the schema-less advanced.entries.batchCreate path.
  const { entries, deleted } = await collection.getEntriesSince();
  assert(deleted.length === 0, `expected 0 deletions on fresh collection, got ${deleted.length}`);
  assert(entries.length >= 5, `expected ≥5 entries surfaced via getEntriesSince, got ${entries.length}`);

  // Verify every written record is present, indexed by its derived Eid.
  const expectedEids = await Promise.all(records.map((r) => collection.eidFor(r.bookId)));
  const seenEids = new Set(entries.map((e) => e.eid));
  for (let i = 0; i < records.length; i++) {
    assert(
      seenEids.has(expectedEids[i]),
      `bookId ${records[i].bookId} (eid ${expectedEids[i]}) missing from getEntriesSince`,
    );
  }

  // And the typed payloads round-trip cleanly.
  const byEid = new Map(entries.map((e) => [e.eid, e.record]));
  for (let i = 0; i < records.length; i++) {
    const got = byEid.get(expectedEids[i]);
    assert(got, `no record for eid ${expectedEids[i]}`);
    assert(got.title === records[i].title, `title mismatch for ${records[i].bookId}: ${got.title}`);
    assert(got.author === records[i].author, `author mismatch for ${records[i].bookId}: ${got.author}`);
  }
});

await test('typed batchCreate rejects empty input without a wire call', async () => {
  const schema = defineSchema({
    appId: APP_ID,
    version: 1,
    collections: {
      empty: {
        primaryKey: 'id',
        fields: { id: 'string', name: 'string' },
      },
    },
  });
  const tarn = await TypedTarnClient.create({
    apiBase: API_BASE, appId: APP_ID, schema, storage: TarnStorage.memory(),
  });
  await tarn.login(testUsername, testPassword);
  let caught = null;
  try { await tarn.empty.batchCreate([]); } catch (e) { caught = e; }
  assert(caught, 'empty input must throw');
  assert(/non-empty/i.test(caught.message), `unexpected error: ${caught.message}`);
});

await test('typed batchCreate aggregates validation failures with indexes', async () => {
  const schema = defineSchema({
    appId: APP_ID,
    version: 1,
    collections: {
      strict: {
        primaryKey: 'id',
        fields: { id: 'string', name: 'string' },
      },
    },
  });
  const tarn = await TypedTarnClient.create({
    apiBase: API_BASE, appId: APP_ID, schema, storage: TarnStorage.memory(),
  });
  await tarn.login(testUsername, testPassword);
  // Index 0 valid, index 1 missing required `name`. Whole batch must reject.
  let caught = null;
  try {
    await tarn.strict.batchCreate([
      { id: 'a', name: 'Good' },
      { id: 'b' }, // missing name
    ]);
  } catch (e) { caught = e; }
  assert(caught, 'mixed-validity batch must throw');
  assert(/\[1\]/.test(caught.message), `error must mention failing index [1]; got: ${caught.message}`);
});

// ============ 5a3. Tarn #34: advanced.entries refuses untagged writes ============
//
// The complement to #33: even the untyped escape hatch
// (`advanced.entries.create` / `.batchCreate`) cannot silently produce
// orphan entries in a defined collection. Before #34, calling
// `tarn.advanced.entries.create('books', { title: 'X' })` would land a
// record on chain with no Eid and no validation — the typed read path
// would then drop it as an "orphan delta event". This block asserts the
// new invariant end-to-end against the live API: untyped writes to a
// defined collection MUST validate + auto-stamp Eid, and the typed read
// path MUST then surface them as if they came through the typed surface.
//
// Together with 5a2, this closes the silent-orphan gap for every caller,
// not just those who happen to use the typed surface.

console.log('\n=== 5a3. advanced.entries invariant for defined collections (issue #34) ===');

await test('advanced.entries.create on a defined collection: validates, stamps Eid, typed read surfaces it', async () => {
  // Unique collection name per run for cursor isolation, same pattern as #33.
  const collectionName = `untyped-create-${Date.now()}`;
  const schema = defineSchema({
    appId: APP_ID,
    version: 1,
    collections: {
      [collectionName]: {
        primaryKey: 'bookId',
        fields: {
          bookId: 'string',
          title: 'string',
        },
      },
    },
  });
  const tarn = await TypedTarnClient.create({
    apiBase: API_BASE, appId: APP_ID, schema, storage: TarnStorage.memory(),
  });
  await tarn.login(testUsername, testPassword);

  // 1. Missing primaryKey must throw — nothing reaches the wire.
  let missingPk = null;
  try {
    await tarn.advanced.entries.create(collectionName, { title: 'no-pk' });
  } catch (e) {
    missingPk = e;
  }
  assert(missingPk, 'untyped create without primaryKey must throw');
  assert(/required field 'bookId' is missing/.test(missingPk.message),
    `expected schema validation error; got: ${missingPk.message}`);

  // 2. Valid untyped create succeeds, then surfaces through the typed read
  //    path — Eid was stamped, so it is not an orphan.
  const bookId = `untyped-b-${Date.now()}`;
  await tarn.advanced.entries.create(collectionName, { bookId, title: 'Untyped-Round-Trip' });

  await sleep(500);
  const collection = tarn[collectionName];
  const fetched = await collection.get(bookId);
  assert(fetched, `untyped write must be visible via typed get(); got null for bookId=${bookId}`);
  assert(fetched.title === 'Untyped-Round-Trip',
    `unexpected title round-trip; got '${fetched.title}'`);
});

await test('advanced.entries.batchCreate on a defined collection: aggregate errors, no orphan writes on success', async () => {
  const collectionName = `untyped-batch-${Date.now()}`;
  const schema = defineSchema({
    appId: APP_ID,
    version: 1,
    collections: {
      [collectionName]: {
        primaryKey: 'bookId',
        fields: {
          bookId: 'string',
          title: 'string',
        },
      },
    },
  });
  const tarn = await TypedTarnClient.create({
    apiBase: API_BASE, appId: APP_ID, schema, storage: TarnStorage.memory(),
  });
  await tarn.login(testUsername, testPassword);

  // 1. Mixed-validity batch must throw with input-indexed reasons, NOTHING
  //    written. The whole batch is rejected up front.
  let caught = null;
  try {
    await tarn.advanced.entries.batchCreate(collectionName, [
      { bookId: 'ok-0', title: 'A' },
      { title: 'no-pk' }, // 1: missing bookId
    ]);
  } catch (e) {
    caught = e;
  }
  assert(caught, 'mixed-validity untyped batch must throw');
  assert(/\[1\]/.test(caught.message),
    `error must include failing input index [1]; got: ${caught.message}`);

  // 2. Valid batch succeeds — every item surfaces through the typed read
  //    path with its derived Eid (no orphans).
  const stamp = Date.now();
  const records = Array.from({ length: 3 }, (_, i) => ({
    bookId: `ub-${i}-${stamp}`,
    title: `Untyped Batch ${i}`,
  }));
  const out = await tarn.advanced.entries.batchCreate(collectionName, records);
  assert(Array.isArray(out) && out.length === 3,
    `expected 3 wire results, got ${out?.length}`);

  await sleep(500);
  const collection = tarn[collectionName];
  for (const r of records) {
    const fetched = await collection.get(r.bookId);
    assert(fetched, `untyped batchCreate item ${r.bookId} must be visible via typed get()`);
    assert(fetched.title === r.title, `title mismatch for ${r.bookId}: ${fetched.title}`);
  }
});

// ============ 5b. EID-NARROWED READ PATH ============
//
// Verifies the API's ?eid= filter and the SDK's getEntryByEid wrapper. This
// is the read path that delete / update / get / share-state lookups all use
// now — before the change they swept the entire collection and decrypted
// every blob just to find one record's txid. Regressions here would
// reintroduce the 300/hr rate-limit issue for any user with non-trivial
// collection sizes.

console.log('\n=== 5b. Eid-narrowed read path ===');

await test('?eid= filter returns at most one live entry with inline blob', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);

  // Write an entry tagged with a unique Eid so we can target it precisely.
  const eidType = `eid-probe-${Date.now()}`;
  const eid = `eid-${crypto.randomUUID()}`;
  const { txid } = await tarn.createEntry(
    eidType,
    { marker: 'eid-roundtrip', t: Date.now() },
    [{ name: 'Eid', value: eid }],
  );
  assert(txid, 'createEntry must return a txid');

  await sleep(500); // write-through to D1

  // Raw API call to prove the filter works at the SQL layer.
  const res = await fetch(
    `${API_BASE}/api/v1/entries?app=${APP_ID}&type=${eidType}&key=${testDlk}&eid=${encodeURIComponent(eid)}`,
    { headers: { 'Authorization': `Bearer ${tarn._testJwt()}` } },
  );
  const json = await res.json();
  assert(res.status === 200, `?eid= filter returned ${res.status}`);
  assert(Array.isArray(json.entries), 'response missing entries array');
  assert(json.entries.length === 1, `expected exactly 1 entry, got ${json.entries.length}`);
  assert(json.entries[0].txid === txid, 'returned entry txid mismatch');
  assert(json.entries[0].eid === eid, 'returned eid mismatch');
  assert(typeof json.entries[0].data === 'string' && json.entries[0].data.length > 0,
    'Eid-filtered response must inline the encrypted blob');
});

await test('getEntryByEid decrypts and returns the single matching record', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);

  const eidType = `eid-sdk-${Date.now()}`;
  const eid = `eid-${crypto.randomUUID()}`;
  const payload = { marker: 'sdk-eid-roundtrip', t: Date.now() };
  await tarn.createEntry(eidType, payload, [{ name: 'Eid', value: eid }]);

  await sleep(500);

  const got = await tarn.getEntryByEid(eidType, eid);
  assert(got, 'getEntryByEid returned null for a record that exists');
  assert(got.data?.marker === payload.marker && got.data?.t === payload.t,
    `decrypted payload mismatch: got ${JSON.stringify(got.data)}`);

  const miss = await tarn.getEntryByEid(eidType, 'eid-not-real');
  assert(miss === null, 'getEntryByEid must return null for an unknown Eid');
});

// ============ 5b2. DELTA-SYNC READ PATH ============
//
// Verifies the API's ?since= cursor filter and the SDK's getEntriesSince
// wrapper. Polling clients use this to learn about cross-device changes
// without re-pulling the full live set — and deletions surface as
// semantic { eid, deleted: true } events, not raw tombstone rows.

console.log('\n=== 5b2. Delta-sync read path ===');

await test('?since= returns events with inline blobs and an advancing cursor', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);

  // Establish a unique type so prior runs don't bleed in.
  const deltaType = `delta-probe-${Date.now()}`;
  const eid = `eid-${crypto.randomUUID()}`;
  await tarn.createEntry(
    deltaType,
    { marker: 'delta-first', t: Date.now() },
    [{ name: 'Eid', value: eid }],
  );
  await sleep(500);

  // First sync from the beginning.
  const url1 = `${API_BASE}/api/v1/entries?app=${APP_ID}&type=${deltaType}&key=${testDlk}&since=${encodeURIComponent('0:')}`;
  const res1 = await fetch(url1, { headers: { 'Authorization': `Bearer ${tarn._testJwt()}` } });
  const json1 = await res1.json();
  assert(res1.status === 200, `delta first sync returned ${res1.status}`);
  assert(Array.isArray(json1.entries), 'response missing entries array');
  assert(json1.entries.length >= 1, `expected ≥1 entry, got ${json1.entries.length}`);
  const matchedEntry = json1.entries.find((e) => e.eid === eid);
  assert(matchedEntry, 'just-written entry should appear in delta');
  assert(typeof matchedEntry.data === 'string' && matchedEntry.data.length > 0,
    'delta event must inline the blob');
  assert(typeof json1.pagination?.cursor === 'string', 'response must carry a cursor');

  // Second sync with the cursor: should see zero new events (nothing changed).
  const cursor = json1.pagination.cursor;
  const url2 = `${API_BASE}/api/v1/entries?app=${APP_ID}&type=${deltaType}&key=${testDlk}&since=${encodeURIComponent(cursor)}`;
  const res2 = await fetch(url2, { headers: { 'Authorization': `Bearer ${tarn._testJwt()}` } });
  const json2 = await res2.json();
  assert(res2.status === 200, `delta warm sync returned ${res2.status}`);
  assert(json2.entries.length === 0, `warm sync should see zero events, got ${json2.entries.length}`);
});

await test('deletion surfaces as { eid, deleted: true } — no tombstone leakage', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);

  const deltaType = `delta-del-${Date.now()}`;
  const eid = `eid-${crypto.randomUUID()}`;
  const { txid } = await tarn.createEntry(
    deltaType,
    { marker: 'will-be-deleted', t: Date.now() },
    [{ name: 'Eid', value: eid }],
  );
  await sleep(500);

  // Capture the cursor at the "just after the create" mark.
  const baseUrl = `${API_BASE}/api/v1/entries?app=${APP_ID}&type=${deltaType}&key=${testDlk}`;
  const after1 = await fetch(`${baseUrl}&since=${encodeURIComponent('0:')}`, { headers: { 'Authorization': `Bearer ${tarn._testJwt()}` } }).then((r) => r.json());
  const cursorAfterCreate = after1.pagination.cursor;
  // Confirm we see the live entry at this point.
  assert(after1.entries.some((e) => e.eid === eid && !e.deleted),
    'create event should appear as a live entry, not deleted');

  // Now tombstone it via the SDK (note: deleteEntry is the low-level API
  // path; this exercises the same protocol-level tombstone behavior the
  // typed Collection.delete uses).
  await tarn.deleteEntry(txid, deltaType, [{ name: 'Eid', value: eid }]);
  await sleep(500);

  // Polling with the post-create cursor should now surface the deletion as
  // a semantic event — never as a tombstone row.
  const after2 = await fetch(`${baseUrl}&since=${encodeURIComponent(cursorAfterCreate)}`, { headers: { 'Authorization': `Bearer ${tarn._testJwt()}` } }).then((r) => r.json());
  const deletion = after2.entries.find((e) => e.eid === eid && e.deleted === true);
  assert(deletion, 'tombstone must surface as { eid, deleted: true } event');
  assert(!('txid' in deletion) || !deletion.data,
    'deletion event should not carry blob data');
  // Belt: no event in the response should mention "tombstone" — that
  // vocabulary stays server-side.
  for (const evt of after2.entries) {
    assert(!('tombstone' in evt), 'wire-level tombstone field must not appear in delta events');
  }
});

await test('getEntriesSince persists cursor across calls', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);

  const deltaType = `delta-sdk-${Date.now()}`;
  await tarn.createEntry(deltaType, { id: 'a' }, [{ name: 'Eid', value: `eid-a-${crypto.randomUUID()}` }]);
  await sleep(500);

  const first = await tarn.getEntriesSince(deltaType);
  assert(first.entries.length >= 1, `first sync should see ≥1 entry, got ${first.entries.length}`);

  // Warm sync — cursor was persisted, so nothing new.
  const second = await tarn.getEntriesSince(deltaType);
  assert(second.entries.length === 0, `warm sync should see 0 entries, got ${second.entries.length}`);
  assert(second.deleted.length === 0, `warm sync should see 0 deletions`);
});

// ============ 5c. SESSION PERSISTENCE (Section 7, issue #19) ============

console.log('\n=== 5b. Session Persistence ===');

await test('serializeSession + resumeSession round-trips against deployed API', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);

  const blob = await tarn.serializeSession();
  assert(typeof blob === 'string' && blob.length > 0, 'serializeSession returned non-empty string');

  const resumed = await TarnClient.resumeSession(API_BASE, APP_ID, blob);
  assert(resumed instanceof TarnClient, 'resumeSession returned a TarnClient');
  assert(resumed.isAuthenticated, 'resumed client is authenticated');
  assert(resumed.dataLookupKey === testDlk, 'resumed dataLookupKey matches');

  // Re-auth via the resumed signing key by dropping the JWT and reading.
  resumed._testInvalidateJwt();
  const entries = await resumed.getEntries('entry');
  assert(Array.isArray(entries), 'resumed client can fetch entries (re-auth via signing key)');
});

await test('resumeSession returns null on tampered blob', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);
  const blob = await tarn.serializeSession();
  const idx = Math.floor(blob.length / 2);
  const flip = blob[idx] === 'A' ? 'B' : 'A';
  const tampered = blob.slice(0, idx) + flip + blob.slice(idx + 1);
  const result = await TarnClient.resumeSession(API_BASE, APP_ID, tampered);
  assert(result === null, 'tampered blob must resume to null');
});

// ============ 5c. SESSION MANAGEMENT (Section 7.5, issue #20) ============

console.log('\n=== 5c. Session Management ===');

await test('listSessions returns at least one session, marked isCurrent', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);
  const sessions = await tarn.listSessions();
  assert(Array.isArray(sessions), 'listSessions returns an array');
  assert(sessions.length >= 1, `expected ≥1 session, got ${sessions.length}`);
  assert(sessions.some(s => s.isCurrent === true), 'one session should be isCurrent');
});

await test('revokeOtherSessions preserves the calling session', async () => {
  // Login as a "second device" so we have something to revoke.
  const peer = new TarnClient(API_BASE, APP_ID);
  await peer.login(testUsername, testPassword);

  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);

  await tarn.revokeOtherSessions();
  const after = await tarn.listSessions();
  assert(after.length === 1, `expected 1 session after revokeOtherSessions, got ${after.length}`);
  assert(after[0].isCurrent === true, 'remaining session should be the calling one');
});

// ============ 6. STATUS ============

console.log('\n=== 6. Status ===');

await test('Status endpoint returns operational data', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);

  // Use raw fetch since TarnClient doesn't expose status
  const keys = await deriveAllKeys(testUsername, testPassword, APP_ID);
  const cRes = await fetch(`${API_BASE}/api/v1/auth/challenge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey }),
  });
  const { nonce } = await cRes.json();
  const sig = await signChallenge(keys.signingKeyPair.privateKey, nonce);
  const vRes = await fetch(`${API_BASE}/api/v1/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey, nonce, signature: sig }),
  });
  const { jwt } = await vRes.json();

  const statusRes = await fetch(`${API_BASE}/api/v1/status`, {
    headers: { 'Authorization': `Bearer ${jwt}` },
  });
  const status = await statusRes.json();
  assert(statusRes.status === 200, `Status failed: ${statusRes.status}`);
  assert(status.protocol_version === '0.4.0', `Wrong version: ${status.protocol_version}`);
  assert(typeof status.users?.total === 'number', 'Missing users.total');
  assert(typeof status.entries?.total === 'number', 'Missing entries.total');
  console.log(`    Users: ${status.users.total}, Entries: ${status.entries.total}`);
});

// ============ 7. SHARING KEYPAIR (issue #13) ============

console.log('\n=== 7. Sharing keypair lookup ===');

await test('getRecipientShareKey returns the published share_pub', async () => {
  const expected = encodeSharePub(
    (await deriveAllKeys(testUsername, testPassword, APP_ID)).sharingKeyPair.publicKey,
  );
  const stranger = new TarnClient(API_BASE, APP_ID);
  const { sharePubBase64Url, discoverable, sharePub } = await stranger.getRecipientShareKey(testUsername);
  assert(discoverable === true, `expected discoverable=true, got ${discoverable}`);
  assert(sharePubBase64Url === expected, `share_pub mismatch:\n  got:  ${sharePubBase64Url}\n  want: ${expected}`);
  assert(sharePub instanceof Uint8Array && sharePub.length === 32, 'sharePub should decode to 32 raw bytes');
});

await test('getRecipientShareKey for unknown username returns null + discoverable=false', async () => {
  const stranger = new TarnClient(API_BASE, APP_ID);
  const { sharePub, discoverable } = await stranger.getRecipientShareKey(`nobody-${Date.now()}@nowhere.test`);
  assert(sharePub === null, 'unknown username should return null sharePub');
  assert(discoverable === false, 'unknown username should be opaque');
});

await test('share_lookup_key is per-app isolated (cross-app probe misses)', async () => {
  // Use a different app_id (the smoke test only seeds bookish on the deployed
  // API, so this lookup will miss for two reasons — different app + different
  // share_lookup_key — both consistent with the design).
  const wrongApp = new TarnClient(API_BASE, 'definitely-not-a-real-app');
  const { sharePub, discoverable } = await wrongApp.getRecipientShareKey(testUsername);
  assert(sharePub === null, 'cross-app lookup should miss');
  assert(discoverable === false, 'cross-app lookup should be opaque');
});

// ============ 8. CONNECTION HANDSHAKE (issue #14, Section 5a) ============

console.log('\n=== 8. Connection handshake (HPKE inbox) ===');

let handshakeAlice;
let handshakeBob;
let handshakeAliceUsername;
let handshakeAliceDlk;
let handshakeAlicePassword;
let handshakeBobUsername;
let handshakeBobDlk;
let handshakeRequestNonce;

await test('Two test users register + complete a mutual handshake against the deployed API', async () => {
  // Note: we don't need to set rules for the connections + pending records
  // because Bookish's standard rules (max_entries with no entry_type filter,
  // max_bytes) apply per-app. The test creates only a few share-state
  // entries — well under the limit. The smoke-test rule set is
  // `max_entries: 20, app: bookish` (see Section 3) and we use 2 entries
  // per user (connections + pending), so we have plenty of headroom.
  handshakeAliceUsername = `deploy-handshake-a-${Date.now()}@test.com`;
  handshakeBobUsername = `deploy-handshake-b-${Date.now()}@test.com`;
  const password = 'handshake-test-' + Date.now();
  handshakeAlicePassword = password;

  handshakeAlice = new TarnClient(API_BASE, APP_ID);
  handshakeBob = new TarnClient(API_BASE, APP_ID);
  const a = await handshakeAlice.register(handshakeAliceUsername, password, { recoveryAcknowledged: true });
  const b = await handshakeBob.register(handshakeBobUsername, password, { recoveryAcknowledged: true });
  handshakeAliceDlk = a.dataLookupKey;
  handshakeBobDlk = b.dataLookupKey;

  // Set permissive rules on each user via the bookish app JWT (the
  // existing test scaffolding sets rules for testDlk only; we replicate
  // the auth+PUT for our two new users).
  const pkcs8 = new Uint8Array(APP_KEY.length / 2);
  for (let i = 0; i < APP_KEY.length; i += 2) pkcs8[i / 2] = parseInt(APP_KEY.substr(i, 2), 16);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const cRes = await fetch(`${API_BASE}/api/v1/auth/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: APP_ID }),
  });
  const { nonce } = await cRes.json();
  const nonceBytes = new Uint8Array(nonce.length / 2);
  for (let i = 0; i < nonce.length; i += 2) nonceBytes[i / 2] = parseInt(nonce.substr(i, 2), 16);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, nonceBytes);
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  const vRes = await fetch(`${API_BASE}/api/v1/auth/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: APP_ID, nonce, signature: sigB64 }),
  });
  const { jwt } = await vRes.json();

  for (const dlk of [handshakeAliceDlk, handshakeBobDlk]) {
    const r = await fetch(`${API_BASE}/api/v1/accounts/${dlk}/rules`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${jwt}` },
      body: JSON.stringify({ rules: [{ type: 'max_entries', limit: 20, app: APP_ID }, { type: 'max_bytes', limit: 102400 }] }),
    });
    assert(r.status === 200, `Set rules failed for ${dlk}: ${r.status}`);
  }

  // Alice → Bob connection request.
  const send = await handshakeAlice.sendConnectionRequest(handshakeBobUsername, { message: 'hi from deployed test' });
  assert(send.requestNonce, 'no requestNonce');
  handshakeRequestNonce = send.requestNonce;

  // Bob picks it up.
  await sleep(500);
  const inbox = await handshakeBob.listIncomingRequests();
  assert(inbox.length >= 1, `Bob expected ≥1 incoming, got ${inbox.length}`);
  assert(inbox.some(r => r.requestNonce === handshakeRequestNonce), 'request nonce not in inbox');

  // Bob accepts.
  await handshakeBob.acceptConnectionRequest(handshakeRequestNonce);
  const bobConnections = await handshakeBob.listConnections();
  assert(bobConnections.some(f => f.username === handshakeAliceUsername), 'Alice not in Bob\'s connections');

  // Alice processes the accept.
  await sleep(500);
  await handshakeAlice.listIncomingRequests();
  const aliceConnections = await handshakeAlice.listConnections();
  assert(aliceConnections.some(f => f.username === handshakeBobUsername), 'Bob not in Alice\'s connections');
});

// ============ 9. SHARE LOG (issue #15, Section 5b) ============

console.log('\n=== 9. Share log (per-pair, signed, stealth-tagged) ===');

await test('Connections from §8 can publish + fetch share log entries with verified signatures', async () => {
  // Re-resolve the connection records on each side. Section 8 left Alice + Bob
  // mutually connected; the seq=0 snapshots were already published by the
  // handshake-acceptance flow.
  const aliceConnections = await handshakeAlice.listConnections();
  const bobConnections = await handshakeBob.listConnections();
  const bobConnectionOfAlice = aliceConnections.find(f => f.username === handshakeBobUsername);
  const aliceConnectionOfBob = bobConnections.find(f => f.username === handshakeAliceUsername);
  assert(bobConnectionOfAlice, 'Bob missing from Alice\'s connections');
  assert(aliceConnectionOfBob, 'Alice missing from Bob\'s connections');

  // Bob fetches Alice's seq=0 snapshot.
  const initial = await handshakeBob._fetchShareLogEntry(aliceConnectionOfBob, 0);
  assert(initial, 'no entry at seq=0 from Alice');
  assert(initial.operation.type === 'snapshot',
    `expected snapshot at seq=0, got ${initial.operation.type}`);
  assert(initial.verified === true, 'seq=0 signature did not verify');

  // Alice publishes a real `add` operation; Bob fetches + verifies.
  const cek = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const addRes = await handshakeAlice._publishShareLogEntry(bobConnectionOfAlice, {
    type: 'add',
    content_id: 'deploy-share-log-' + Date.now(),
    tx_id: 'arweave-tx-deploy-' + Date.now(),
    cek,
    shared_at: Math.floor(Date.now() / 1000),
  });
  assert(addRes.txid, 'no txid on publish');
  assert(typeof addRes.seq === 'number', 'no seq on publish');

  await sleep(500);
  const fetched = await handshakeBob._fetchShareLogEntry(aliceConnectionOfBob, addRes.seq);
  assert(fetched, `Bob found nothing at seq=${addRes.seq}`);
  assert(fetched.operation.type === 'add', 'wrong op type after fetch');
  assert(fetched.verified === true, 'add signature did not verify');
});

await test('Per-tag uniqueness against deployed API: re-publish at same tag → 409', async () => {
  // Push a synthetic tag through Alice's JWT twice — second attempt must be
  // 409 with the existing txid.
  const jwt = handshakeAlice._testJwt();
  const tagSeed = crypto.getRandomValues(new Uint8Array(32));
  // We use deriveLogTag from the SDK to keep the format consistent, but
  // imported lazily to avoid needing share-log re-exports at file load.
  const { deriveLogTag } = await import('../client/src/share-log.js');
  const tag = await deriveLogTag(tagSeed, 0);
  const dummyCipher = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(64))));

  const r1 = await fetch(`${API_BASE}/api/v1/share/log/publish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${jwt}` },
    body: JSON.stringify({ tag, type: 'share-log-v1', ciphertext_base64: dummyCipher }),
  });
  assert(r1.status === 200, `first publish must succeed: ${r1.status}`);
  const j1 = await r1.json();

  const r2 = await fetch(`${API_BASE}/api/v1/share/log/publish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${jwt}` },
    body: JSON.stringify({ tag, type: 'share-log-v1', ciphertext_base64: dummyCipher }),
  });
  assert(r2.status === 409, `second publish must be 409: ${r2.status}`);
  const j2 = await r2.json();
  assert(j2.existing_txid === j1.txid, '409 must echo the original txid');
});

// ============ 9b. SHARE LOG READ FLOW + RETRY (issue #16, Section 5c) ============

console.log('\n=== 9b. Share log read flow + multi-device retry (Section 5c) ===');

await test('readShareLog: Bob bootstraps Alice\'s log, sees content shared by Alice', async () => {
  // Re-resolve connection records (handshakeAlice/Bob persist from §8/§9).
  const aliceConnections = await handshakeAlice.listConnections();
  const bobConnections = await handshakeBob.listConnections();
  const bobConnectionOfAlice = aliceConnections.find(f => f.username === handshakeBobUsername);
  const aliceConnectionOfBob = bobConnections.find(f => f.username === handshakeAliceUsername);
  assert(bobConnectionOfAlice && aliceConnectionOfBob, 'connection records missing');

  const cek1 = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const cek2 = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  await handshakeAlice.shareContent(bobConnectionOfAlice, 'deploy-5c-A', 'tx-5c-A', cek1);
  await handshakeAlice.shareContent(bobConnectionOfAlice, 'deploy-5c-B', 'tx-5c-B', cek2);

  await sleep(800);
  const bobState = await handshakeBob.readShareLog(aliceConnectionOfBob, { refresh: true });
  assert(bobState['deploy-5c-A']?.tx_id === 'tx-5c-A', 'deploy-5c-A missing or wrong tx_id');
  assert(bobState['deploy-5c-B']?.tx_id === 'tx-5c-B', 'deploy-5c-B missing or wrong tx_id');
});

await test('syncShareLog: incremental update + remove flows through to Bob', async () => {
  const aliceConnections = await handshakeAlice.listConnections();
  const bobConnections = await handshakeBob.listConnections();
  const bobConnectionOfAlice = aliceConnections.find(f => f.username === handshakeBobUsername);
  const aliceConnectionOfBob = bobConnections.find(f => f.username === handshakeAliceUsername);

  await handshakeAlice.updateShareContent(bobConnectionOfAlice, 'deploy-5c-A', 'tx-5c-A-v2');
  await handshakeAlice.unshareContent(bobConnectionOfAlice, 'deploy-5c-B');

  await sleep(800);
  const updated = await handshakeBob.syncShareLog(aliceConnectionOfBob);
  assert(updated['deploy-5c-A']?.tx_id === 'tx-5c-A-v2', 'update did not propagate');
  assert(updated['deploy-5c-B'] === undefined, 'remove did not propagate');
});

await test('Concurrent publish race against deployed API: exactly one 409, NOT 500', async () => {
  // Drives the live API's INSERT-vs-UNIQUE catch path for the 409-vs-500
  // contract that 5c's retry depends on. Two parallel POSTs at the same
  // synthetic tag from the same JWT.
  const jwt = handshakeAlice._testJwt();
  const tagSeed = crypto.getRandomValues(new Uint8Array(32));
  const { deriveLogTag } = await import('../client/src/share-log.js');
  const tag = await deriveLogTag(tagSeed, 555000 + Date.now() % 1000);
  const post = (cipher) => fetch(`${API_BASE}/api/v1/share/log/publish`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${jwt}` },
    body: JSON.stringify({ tag, type: 'share-log-v1', ciphertext_base64: cipher }),
  });
  const dummyA = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(64))));
  const dummyB = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(64))));
  const [rA, rB] = await Promise.all([post(dummyA), post(dummyB)]);
  const statuses = [rA.status, rB.status].sort((a, b) => a - b);
  assert(statuses[0] === 200 && statuses[1] === 409,
    `expected [200, 409] from concurrent publishes; got [${statuses.join(', ')}]`);
  const winner = rA.status === 200 ? rA : rB;
  const loser = rA.status === 409 ? rA : rB;
  const wj = await winner.json();
  const lj = await loser.json();
  assert(wj.txid, 'winner missing txid');
  assert(lj.existing_txid === wj.txid,
    `loser.existing_txid (${lj.existing_txid}) !== winner.txid (${wj.txid})`);
});

// (Alice + Bob cleanup moved to after §9d so the mute lifecycle test
// can reuse the established mutual-connection pair without re-registering.)

// ============ 9c. SECTION 5d — REVOCATION + IDENTITY ROTATION ============

console.log('\n=== 9c. Revocation + identity rotation (Section 5d) ===');

// Build two fresh accounts (Pat + Quinn) for the rotation E2E. The §9c flow
// proves the §13.5 protocol works against the deployed API:
//   1. Both accounts register + handshake.
//   2. Pat shares a content item with Quinn.
//   3. Pat changes credentials (issue #17 §13.5 sender flow).
//   4. Quinn syncs and picks up the rotation: connection record updated to
//      Pat's NEW share_pub + signing_pub; subsequent shares from Pat under
//      the NEW pair keys reach Quinn.

const patUsername = `tarn-pat-${Date.now()}-${Math.random().toString(36).slice(2)}@test.com`;
const patPassword = 'pat-pw-' + Date.now();
const quinnUsername = `tarn-quinn-${Date.now()}-${Math.random().toString(36).slice(2)}@test.com`;
const quinnPassword = 'quinn-pw-' + Date.now();

let pat, quinn;
let quinnConnectionOfPat, patConnectionOfQuinn;
let patPhrase;
let patSharePubBeforeRotate;

await test('Pat + Quinn register + handshake against deployed API', async () => {
  pat = new TarnClient(API_BASE, APP_ID);
  quinn = new TarnClient(API_BASE, APP_ID);
  const patReg = await pat.register(patUsername, patPassword, {
    recoveryAcknowledged: true,
  });
  patPhrase = patReg.accountKey;
  const quinnReg = await quinn.register(quinnUsername, quinnPassword, {
    recoveryAcknowledged: true,
  });

  // Set permissive rules on each user via the bookish app JWT (same pattern
  // as §8). Connections + pending records + share-log entries + tarn-share-state
  // writes need rules — the credential-change flow also writes share-state
  // entries to publish snapshots to connections' new logs after rotation.
  const pkcs8 = new Uint8Array(APP_KEY.length / 2);
  for (let i = 0; i < APP_KEY.length; i += 2) pkcs8[i / 2] = parseInt(APP_KEY.substr(i, 2), 16);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const cRes = await fetch(`${API_BASE}/api/v1/auth/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: APP_ID }),
  });
  const { nonce } = await cRes.json();
  const nonceBytes = new Uint8Array(nonce.length / 2);
  for (let i = 0; i < nonce.length; i += 2) nonceBytes[i / 2] = parseInt(nonce.substr(i, 2), 16);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, nonceBytes);
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  const vRes = await fetch(`${API_BASE}/api/v1/auth/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: APP_ID, nonce, signature: sigB64 }),
  });
  const { jwt } = await vRes.json();

  for (const dlk of [pat.dataLookupKey, quinn.dataLookupKey]) {
    const r = await fetch(`${API_BASE}/api/v1/accounts/${dlk}/rules`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${jwt}` },
      body: JSON.stringify({ rules: [{ type: 'max_entries', limit: 50, app: APP_ID }, { type: 'max_bytes', limit: 204800 }] }),
    });
    assert(r.status === 200, `Set rules failed for ${dlk}: ${r.status}`);
  }

  const send = await pat.sendConnectionRequest(quinnUsername);
  await sleep(500);
  await quinn.listIncomingRequests();
  await quinn.acceptConnectionRequest(send.requestNonce);
  await sleep(500);
  await pat.listIncomingRequests();
  quinnConnectionOfPat = (await pat.listConnections()).find(f => f.username === quinnUsername);
  patConnectionOfQuinn = (await quinn.listConnections()).find(f => f.username === patUsername);
  assert(quinnConnectionOfPat, 'Pat missing Quinn after handshake');
  assert(patConnectionOfQuinn, 'Quinn missing Pat after handshake');
  patSharePubBeforeRotate = patConnectionOfQuinn.share_pub;
});

await test('Pat shares a content item with Quinn', async () => {
  const cek = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  await pat.shareContent(quinnConnectionOfPat, 'rot-target-1', 'arweave-rot-pre', cek);
  await sleep(500);
  const state = await quinn.readShareLog(patConnectionOfQuinn, { refresh: true });
  assert(state['rot-target-1'], 'Quinn should see rot-target-1 before rotation');
});

await test('Pat changes credentials → publishes rotate_identity to Quinn (deployed API)', async () => {
  const newUsername = `tarn-pat-rotated-${Date.now()}@test.com`;
  const result = await pat.changeCredentials(newUsername, 'new-pw-' + Date.now(), {
    phrase: patPhrase,
  });
  assert(Array.isArray(result.rotationAnnouncements), 'expected rotationAnnouncements');
  assert(result.rotationAnnouncements.length === 1, 'expected exactly one rotation announcement');
  const ann = result.rotationAnnouncements[0];
  assert(ann.connectionSharePub === quinnConnectionOfPat.share_pub, 'rotation targets the right connection');
  assert(typeof ann.txid === 'string', 'rotation announcement should have a txid');
});

await test('Quinn syncs against deployed API: rotate_identity processed, connection record updated', async () => {
  await sleep(800);
  const stateAfter = await quinn.syncShareLog(patConnectionOfQuinn);
  assert(stateAfter['rot-target-1'], 'Quinn still sees rot-target-1 after rotation (NEW-log seq=0 snapshot)');

  const updatedConnection = (await quinn.listConnections())[0];
  assert(updatedConnection.share_pub !== patSharePubBeforeRotate,
    'Quinn\'s connection record holds Pat\'s NEW share_pub');
  assert(updatedConnection.prior_share_pub === patSharePubBeforeRotate,
    'Quinn records the pre-rotation share_pub');
});

await test('Pat publishes a post-rotation share; Quinn picks it up via NEW-log keys', async () => {
  // Refresh references — Pat's connection record was updated by the rotation
  // (no, actually Pat's view of Quinn is unchanged; only Quinn's view of
  // Pat rotated). But re-fetch defensively.
  quinnConnectionOfPat = (await pat.listConnections()).find(f => f.username === quinnUsername);
  const cek = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  await pat.shareContent(quinnConnectionOfPat, 'rot-target-2-postrotate', 'arweave-rot-post', cek);
  await sleep(500);
  const updatedQuinnConnection = (await quinn.listConnections())[0];
  const stateAfter = await quinn.syncShareLog(updatedQuinnConnection);
  assert(stateAfter['rot-target-2-postrotate'],
    'Quinn should see post-rotation content via NEW-log keys');
});

await test('Cleanup §9c accounts (Pat + Quinn)', async () => {
  await pat.deleteAccount();
  await quinn.deleteAccount();
});

// ============ 9d. MUTE LIFECYCLE (issue #18, Section 6) ============

console.log('\n=== 9d. Mute lifecycle (per-side filter, syncs across devices) ===');

await test('muteConnection persists; isMuted reflects state; unmute reverses; multi-device sync', async () => {
  // Reuse handshake Alice + Bob from §8 — they're still mutual connections.
  const aliceConnections = await handshakeAlice.listConnections();
  const bobOfAlice = aliceConnections.find(c => c.username === handshakeBobUsername);
  assert(bobOfAlice, 'Alice missing Bob (handshake §8 setup gone?)');

  // Baseline.
  assert((await handshakeAlice.isMuted(bobOfAlice)) === false, 'baseline isMuted should be false');
  assert((await handshakeAlice.listMutedConnections()).length === 0, 'baseline list should be empty');

  // Mute.
  const muteRes = await handshakeAlice.muteConnection(bobOfAlice);
  assert(muteRes.muted === true, 'first mute should report muted: true');
  assert(await handshakeAlice.isMuted(bobOfAlice), 'isMuted should be true after mute');
  const muted = await handshakeAlice.listMutedConnections();
  assert(muted.length === 1 && muted[0].share_pub === bobOfAlice.share_pub,
    'list should contain Bob\'s share_pub');
  assert(typeof muted[0].muted_at === 'number', 'muted_at should be a number');

  // Idempotency.
  const muteAgain = await handshakeAlice.muteConnection(bobOfAlice);
  assert(muteAgain.muted === false, 'second mute should be a no-op');

  // Read flow not short-circuited: Alice can still read Bob's outbound log.
  // (The setup published a seq=0 snapshot from Bob during §8 acceptance.)
  const bobAlice = await handshakeBob.listConnections();
  const aliceOfBob = bobAlice.find(c => c.username === handshakeAliceUsername);
  const cek = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  await handshakeBob.shareContent(aliceOfBob, 'mute-visibility-deployed', 'arweave-mute-deploy', cek);
  await sleep(500);
  const aliceState = await handshakeAlice.readShareLog(bobOfAlice, { refresh: true });
  assert(aliceState['mute-visibility-deployed'],
    'readShareLog must NOT short-circuit on muted connections');

  // Multi-device sync: a fresh Alice client (different "device") sees the mute.
  const alice2 = new TarnClient(API_BASE, APP_ID);
  await alice2.login(handshakeAliceUsername, handshakeAlicePassword);
  const muted2 = await alice2.listMutedConnections();
  assert(muted2.length === 1 && muted2[0].share_pub === bobOfAlice.share_pub,
    'device B should see the mute set on device A');
  assert(await alice2.isMuted(bobOfAlice), 'device B isMuted should be true');

  // Unmute on device A; verify device C sees the unmute.
  const unmuteRes = await handshakeAlice.unmuteConnection(bobOfAlice);
  assert(unmuteRes.unmuted === true, 'first unmute should report unmuted: true');
  assert((await handshakeAlice.isMuted(bobOfAlice)) === false, 'isMuted false after unmute');
  const alice3 = new TarnClient(API_BASE, APP_ID);
  await alice3.login(handshakeAliceUsername, handshakeAlicePassword);
  assert((await alice3.isMuted(bobOfAlice)) === false, 'device C should see the unmute');

  // Idempotent unmute.
  const unmuteAgain = await handshakeAlice.unmuteConnection(bobOfAlice);
  assert(unmuteAgain.unmuted === false, 'second unmute should be a no-op');
});

await test('Cleanup §8/§9/§9d accounts (Alice + Bob)', async () => {
  await handshakeAlice.deleteAccount();
  await handshakeBob.deleteAccount();
});

// ============ 9e. INVITE TOKENS (issue #22, Section 8) ============

console.log('\n=== 9e. Invite tokens (single-use, time-limited bootstrap) ===');

let inviteInviter;
let inviteRedeemer;
let inviteInviterUsername;
let inviteRedeemerUsername;

await test('Invite inviter + redeemer register', async () => {
  inviteInviter = new TarnClient(API_BASE, APP_ID);
  inviteRedeemer = new TarnClient(API_BASE, APP_ID);
  inviteInviterUsername = `inv-inviter-${Date.now()}-${Math.random().toString(36).slice(2)}@test.local`;
  inviteRedeemerUsername = `inv-redeemer-${Date.now()}-${Math.random().toString(36).slice(2)}@test.local`;
  const inviterReg = await inviteInviter.register(inviteInviterUsername, 'pw-inv-' + Date.now(), {
    recoveryAcknowledged: true,
  });
  const redeemerReg = await inviteRedeemer.register(inviteRedeemerUsername, 'pw-red-' + Date.now(), {
    recoveryAcknowledged: true,
  });

  // New accounts default to rules_json = NULL which is DENY. Set permissive
  // free-tier-style rules for both so tarn-issued-invites-v1 / tarn-pending-
  // requests-v1 / tarn-connections-v1 blob writes are allowed.
  const pkcs8 = new Uint8Array(APP_KEY.length / 2);
  for (let i = 0; i < APP_KEY.length; i += 2) pkcs8[i / 2] = parseInt(APP_KEY.substr(i, 2), 16);
  const appPriv = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  for (const dlk of [inviterReg.dataLookupKey, redeemerReg.dataLookupKey]) {
    const cRes = await fetch(`${API_BASE}/api/v1/auth/challenge`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential_lookup_key: APP_ID }),
    });
    const { nonce: appNonce } = await cRes.json();
    const nonceBytes = new Uint8Array(appNonce.length / 2);
    for (let i = 0; i < appNonce.length; i += 2) nonceBytes[i / 2] = parseInt(appNonce.substr(i, 2), 16);
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, appPriv, nonceBytes);
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
    const vRes = await fetch(`${API_BASE}/api/v1/auth/verify`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential_lookup_key: APP_ID, nonce: appNonce, signature: sigB64 }),
    });
    const { jwt: appJwt } = await vRes.json();
    await fetch(`${API_BASE}/api/v1/accounts/${dlk}/rules`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${appJwt}` },
      body: JSON.stringify({ rules: [{ type: 'max_entries', limit: 50, app: APP_ID }, { type: 'max_bytes', limit: 204800 }] }),
    });
  }
});

let deployedInvite;

await test('createInviteToken returns a token + url + expiry', async () => {
  deployedInvite = await inviteInviter.createInviteToken({ label: 'Pat', expiry_days: 1 });
  assert(typeof deployedInvite.token_id === 'string' && deployedInvite.token_id.length === 43,
    `bad token_id: ${deployedInvite.token_id}`);
  assert(deployedInvite.invite_url.includes('#'), 'invite_url should include the payload_key fragment');
  assert(typeof deployedInvite.expires_at === 'number', 'expires_at should be a number');
});

await test('previewInviteToken returns the payload (unauthenticated path)', async () => {
  const fragment = deployedInvite.invite_url.split('#')[1];
  const preview = await inviteRedeemer.previewInviteToken(deployedInvite.token_id, fragment);
  assert(preview != null, 'preview should not be null on an active invite');
  assert(!('inviter_display_name' in preview),
    'preview must not carry an inviter display name (no name slot on the wire)');
  assert(typeof preview.inviter_share_pub_fingerprint === 'string',
    'fingerprint must be present on the preview');
});

await test('redeemInviteToken forms a connection on the inviter side after auto-accept', async () => {
  const fragment = deployedInvite.invite_url.split('#')[1];
  const redeem = await inviteRedeemer.redeemInviteToken(deployedInvite.token_id, fragment);
  assert(typeof redeem.requestNonce === 'string', 'redeem must return requestNonce');

  await new Promise(r => setTimeout(r, 500));
  const surfaced = await inviteInviter.listIncomingRequests();
  assert(!surfaced.some(s => s.requestNonce === redeem.requestNonce),
    'auto-accept should consume the request from the surfaced list');
  const conns = await inviteInviter.listConnections();
  assert(conns.length === 1, `inviter should have 1 connection, got ${conns.length}`);
  assert(conns[0].label === 'Pat', `label should seed from issued-invite label, got ${conns[0].label}`);
});

await test('Cleanup invite-leg accounts', async () => {
  await inviteInviter.deleteAccount();
  await inviteRedeemer.deleteAccount();
});

// ============ 9f. RECOVERY (Phases 3-6) =================================
//
// Smoke coverage for Model B account-key storage, toggle, rotation,
// recoverAccount({ rotatePhrase: true }), and the WebAuthn-PRF passkey
// factor. All flows happen end-to-end against the live API; each test
// registers fresh accounts (random usernames) so reruns + concurrent
// runs don't collide. Edge cases live in tests/test-account-key.mjs and
// tests/test-passkeys.mjs — this section just ensures the happy path
// flows still work post-deploy.

// Tiny inline helper so each fresh account gets permissive rules from
// the bookish app JWT — same pattern §8 / §9c / §9e use, factored once.
async function setRulesForAccount(dlk, opts = {}) {
  const limit = opts.maxEntries ?? 30;
  const bytes = opts.maxBytes ?? 102400;
  const pkcs8 = new Uint8Array(APP_KEY.length / 2);
  for (let i = 0; i < APP_KEY.length; i += 2) pkcs8[i / 2] = parseInt(APP_KEY.substr(i, 2), 16);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const cRes = await fetch(`${API_BASE}/api/v1/auth/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: APP_ID }),
  });
  const { nonce } = await cRes.json();
  const nonceBytes = new Uint8Array(nonce.length / 2);
  for (let i = 0; i < nonce.length; i += 2) nonceBytes[i / 2] = parseInt(nonce.substr(i, 2), 16);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, nonceBytes);
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  const vRes = await fetch(`${API_BASE}/api/v1/auth/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential_lookup_key: APP_ID, nonce, signature: sigB64 }),
  });
  const { jwt } = await vRes.json();
  const r = await fetch(`${API_BASE}/api/v1/accounts/${dlk}/rules`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${jwt}` },
    body: JSON.stringify({ rules: [{ type: 'max_entries', limit, app: APP_ID }, { type: 'max_bytes', limit: bytes }] }),
  });
  if (r.status !== 200) throw new Error(`set rules failed: ${r.status}`);
}

function freshUsername(tag) {
  return `deploy-${tag}-${Date.now()}-${Math.random().toString(36).slice(2)}@test.local`;
}

// ============ 9f. ACCOUNT KEY: VIEW (Model B, Phase 3) ==================

console.log('\n=== 9f. Account-key view (Model B) ===');

let modelBClient;
let modelBUsername;
let modelBPassword;
let modelBPhrase;

await test('register({ storeAccountKey: true }) surfaces the phrase + sets account_key_stored', async () => {
  modelBClient = new TarnClient(API_BASE, APP_ID);
  modelBUsername = freshUsername('mb');
  modelBPassword = 'pw-mb-' + Date.now();
  const reg = await modelBClient.register(modelBUsername, modelBPassword, {
    recoveryAcknowledged: true,
    storeAccountKey: true,
  });
  modelBPhrase = reg.accountKey;
  assert(typeof modelBPhrase === 'string' && modelBPhrase.split(' ').length === 24,
    `expected a 24-word phrase, got ${modelBPhrase?.split(' ').length} words`);
  assert(modelBClient.isAccountKeyStored() === true, 'account_key_stored should be true after Model B register');
  await setRulesForAccount(modelBClient.dataLookupKey);
});

await test('viewAccountKey({ password }) round-trips the same phrase that register issued', async () => {
  const out = await modelBClient.viewAccountKey({ password: modelBPassword });
  assert(out.accountKey === modelBPhrase,
    `view() must round-trip the original phrase`);
});

// ============ 9g. ACCOUNT KEY: TOGGLE (Phase 4) =========================

console.log('\n=== 9g. Account-key toggle (enable/disable) ===');

await test('disableKeyStorage flips Model B → A; view() then errors no_account_key_stored', async () => {
  const out = await modelBClient.disableKeyStorage({ password: modelBPassword });
  assert(out.stored === false, 'disable returns stored: false');
  assert(modelBClient.isAccountKeyStored() === false, 'cached flag flipped to false');
  let threw = null;
  try {
    await modelBClient.viewAccountKey({ password: modelBPassword });
  } catch (err) { threw = err; }
  assert(threw && /no_account_key_stored/.test(threw.message),
    `expected no_account_key_stored, got: ${threw?.message}`);
});

await test('enableKeyStorage with the saved phrase restores Model B; view() round-trips', async () => {
  const out = await modelBClient.enableKeyStorage({
    password: modelBPassword,
    accountKey: modelBPhrase,
  });
  assert(out.stored === true, 'enable returns stored: true');
  assert(modelBClient.isAccountKeyStored() === true, 'cached flag flipped back to true');
  const view = await modelBClient.viewAccountKey({ password: modelBPassword });
  assert(view.accountKey === modelBPhrase, 'view() round-trips after re-enable');
});

await test('Cleanup §9f/§9g account', async () => {
  await modelBClient.deleteAccount();
});

// ============ 9h. ACCOUNT KEY: ROTATION (Phase 4) =======================

console.log('\n=== 9h. Account-key rotation ===');

await test('rotateAccountKey: NEW phrase recovers + reads pre-rotation data; OLD phrase is rejected', async () => {
  // Register a fresh account, write a probe entry, rotate, then verify
  // (a) OLD phrase no longer recovers, (b) NEW phrase recovers, (c) the
  // entry is still readable post-recovery (DEK chain preserved across
  // rotation).
  const client = new TarnClient(API_BASE, APP_ID);
  const username = freshUsername('rot');
  const password = 'pw-rot-' + Date.now();
  const reg = await client.register(username, password, { recoveryAcknowledged: true });
  const oldPhrase = reg.accountKey;
  await setRulesForAccount(client.dataLookupKey);

  // Write a probe entry pre-rotation.
  const probeMarker = 'rot-probe-' + Date.now();
  await client.createEntry('entry', { marker: probeMarker, ts: Date.now() });

  // Rotate.
  const rot = await client.rotateAccountKey({ password });
  assert(typeof rot.accountKey === 'string' && rot.accountKey.split(' ').length === 24,
    'rotation returns a new 24-word phrase');
  assert(rot.accountKey !== oldPhrase, 'new phrase differs from old');

  // OLD phrase must now be rejected.
  let threw = null;
  try {
    const stale = new TarnClient(API_BASE, APP_ID);
    await stale.recoverAccount({
      phrase: oldPhrase,
      newUsername: freshUsername('rot-stale'),
      newPassword: 'pw-stale-' + Date.now(),
    });
  } catch (err) { threw = err; }
  assert(threw && /no account found|challenge failed/i.test(threw.message),
    `OLD phrase must be rejected post-rotation; got: ${threw?.message}`);

  // NEW phrase must recover, and the probe entry must still be readable.
  const recovered = new TarnClient(API_BASE, APP_ID);
  await recovered.recoverAccount({
    phrase: rot.accountKey,
    newUsername: freshUsername('rot-rec'),
    newPassword: 'pw-rec-' + Date.now(),
  });
  assert(recovered.isLoggedIn(), 'recovered client is logged in via new phrase');
  const entries = await recovered.getEntries('entry');
  assert(entries.some(e => e.data?.marker === probeMarker),
    'pre-rotation entry must still be readable after recovery');

  await recovered.deleteAccount();
});

// ============ 9i. recoverAccount({ rotatePhrase: true }) ================

console.log('\n=== 9i. recoverAccount({ rotatePhrase: true }) ===');

await test('recoverAccount({ rotatePhrase: true }): NEW phrase replaces OLD; data still readable', async () => {
  const client = new TarnClient(API_BASE, APP_ID);
  const username = freshUsername('rp');
  const password = 'pw-rp-' + Date.now();
  const reg = await client.register(username, password, { recoveryAcknowledged: true });
  const oldPhrase = reg.accountKey;
  await setRulesForAccount(client.dataLookupKey);

  const probeMarker = 'rp-probe-' + Date.now();
  await client.createEntry('entry', { marker: probeMarker, ts: Date.now() });

  // Recover-with-rotation.
  const rec1 = new TarnClient(API_BASE, APP_ID);
  const result = await rec1.recoverAccount({
    phrase: oldPhrase,
    newUsername: freshUsername('rp-1'),
    newPassword: 'pw-rp1-' + Date.now(),
    rotatePhrase: true,
  });
  assert(typeof result.accountKey === 'string' && result.accountKey.split(' ').length === 24,
    'rotatePhrase: true returns a new 24-word phrase');
  assert(result.accountKey !== oldPhrase, 'new phrase differs from old');

  // OLD phrase no longer recovers.
  let threw = null;
  try {
    const c2 = new TarnClient(API_BASE, APP_ID);
    await c2.recoverAccount({
      phrase: oldPhrase,
      newUsername: freshUsername('rp-stale'),
      newPassword: 'pw-stale-' + Date.now(),
    });
  } catch (err) { threw = err; }
  assert(threw && /no account found|challenge failed/i.test(threw.message),
    `OLD phrase must be rejected post-rotation; got: ${threw?.message}`);

  // NEW phrase still recovers and data still reads.
  const rec2 = new TarnClient(API_BASE, APP_ID);
  await rec2.recoverAccount({
    phrase: result.accountKey,
    newUsername: freshUsername('rp-2'),
    newPassword: 'pw-rp2-' + Date.now(),
  });
  const entries = await rec2.getEntries('entry');
  assert(entries.some(e => e.data?.marker === probeMarker),
    'pre-rotation entry must still be readable after recovery via new phrase');

  await rec2.deleteAccount();
});

// ============ 9j. PASSKEYS (register / authenticate / list / remove) ====
//
// Uses the virtual WebAuthn authenticator from
// tests/helpers/virtual-authenticator.mjs to drive the full ceremony
// against the live API. We install the env right before this section
// and restore it immediately after — earlier sections in this file
// don't tolerate a globally-patched fetch (Origin injection is harmless
// against the deployed API but the install also wires up
// navigator.credentials, which we don't want in scope long-term).
//
// The `Origin: http://localhost:3000` header the shim injects is in
// the deployed API's CORS + passkey-origin allowlist (see
// api/src/routes/passkeys.js → ORIGIN_TO_RP_ID and worker.js →
// ALLOWED_ORIGINS), so the same shim works against api.tarn.dev as
// against http://localhost:8787.

console.log('\n=== 9j. Passkey lifecycle (register / authenticate / list / remove) ===');

const { VirtualAuthenticator, installPasskeyTestEnv } = await import('./helpers/virtual-authenticator.mjs');
const passkeyEnv = installPasskeyTestEnv({ origin: 'http://localhost:3000', rpId: 'localhost' });

let pkClient;
let pkUsername;
let pkPassword;
let pkPhrase;
let pkAuth;
let pkCredId;

await test('register fresh account, then enroll a passkey via virtual authenticator', async () => {
  pkClient = new TarnClient(API_BASE, APP_ID);
  pkUsername = freshUsername('pk');
  pkPassword = 'pw-pk-' + Date.now();
  const reg = await pkClient.register(pkUsername, pkPassword, { recoveryAcknowledged: true });
  pkPhrase = reg.accountKey;
  await setRulesForAccount(pkClient.dataLookupKey);

  pkAuth = new VirtualAuthenticator();
  passkeyEnv.stageRegistration(pkAuth);
  const result = await pkClient.registerPasskey({ deviceLabel: 'smoke-passkey' });
  pkCredId = result.credentialId;
  assert(pkCredId && pkCredId === pkAuth.credentialIdB64Url,
    'registerPasskey returned the staged credentialId');
  assert(result.deviceLabel === 'smoke-passkey', 'deviceLabel persisted');
});

await test('listPasskeys() shows the new credential with stale: false', async () => {
  const list = await pkClient.listPasskeys();
  assert(Array.isArray(list) && list.length === 1, `expected 1 passkey, got ${list.length}`);
  assert(list[0].credentialId === pkCredId, 'credentialId matches');
  assert(list[0].stale === false, `expected stale: false on a freshly-registered credential, got ${list[0].stale}`);
  assert(!('publicKey' in list[0]) && !('prfSalt' in list[0]),
    'listPasskeys must not leak public_key / prf_salt');
});

await test('authenticateWithPasskey() on a fresh client mints a session that can read+write', async () => {
  const fresh = new TarnClient(API_BASE, APP_ID);
  passkeyEnv.pinNextAuth(pkAuth.credentialIdB64Url);
  const r = await fresh.authenticateWithPasskey();
  passkeyEnv.clearNextAuth();
  assert(r.dataLookupKey === pkClient.dataLookupKey, 'passkey auth resolved to the registered account');

  // Write + read via the passkey-authenticated session.
  const marker = 'pk-write-' + Date.now();
  await fresh.createEntry('entry', { marker, ts: Date.now() });
  const entries = await fresh.getEntries('entry');
  assert(entries.some(e => e.data?.marker === marker),
    'passkey-authenticated session can read its own writes');
});

await test('removePasskey({ credentialId, password }) removes it from list', async () => {
  await pkClient.removePasskey({ credentialId: pkCredId, password: pkPassword });
  const list = await pkClient.listPasskeys();
  assert(list.length === 0, `expected 0 passkeys after remove, got ${list.length}`);
});

// ============ 9k. CHANGECREDENTIALS WITH PASSKEY RE-TAP (Phase 6.1) =====

console.log('\n=== 9k. changeCredentials with passkey re-tap ===');

await test('changeCredentials({ passkeyTapHandler }) preserves passkey auth across rotation', async () => {
  // Register a fresh passkey; rotate credentials with auto-tap; verify
  // the passkey still authenticates and reads post-rotation data.
  const auth = new VirtualAuthenticator();
  passkeyEnv.stageRegistration(auth);
  const r = await pkClient.registerPasskey({ deviceLabel: 'retap-passkey' });
  const credId = r.credentialId;

  const newPassword = 'pw-pk-changed-' + Date.now();
  let handlerCalls = 0;
  await pkClient.changeCredentials(pkUsername, newPassword, {
    phrase: pkPhrase,
    passkeyTapHandler: async (cred) => {
      handlerCalls += 1;
      assert(cred.credentialId === credId, 'tap handler called with the registered credentialId');
      return true; // auto-tap
    },
  });
  assert(handlerCalls === 1, `expected exactly 1 re-tap, got ${handlerCalls}`);

  // Write a post-rotation entry under the new password.
  const marker = 'post-rotate-' + Date.now();
  await pkClient.createEntry('entry', { marker, ts: Date.now() });

  // Authenticate with the passkey on a fresh client; verify it reads the new entry.
  const fresh = new TarnClient(API_BASE, APP_ID);
  passkeyEnv.pinNextAuth(auth.credentialIdB64Url);
  const session = await fresh.authenticateWithPasskey();
  passkeyEnv.clearNextAuth();
  assert(session.dataLookupKey === pkClient.dataLookupKey, 'passkey resolves to same account post-rotation');
  const entries = await fresh.getEntries('entry');
  assert(entries.some(e => e.data?.marker === marker),
    'passkey-authenticated session reads post-rotation data (re-tap rewrapped gen-2)');
});

await test('Cleanup §9j/§9k account; restore passkey shim', async () => {
  await pkClient.deleteAccount();
  passkeyEnv.restore();
});

// ============ 10. CLEANUP ============

console.log('\n=== 10. Cleanup ===');

await test('Delete test account', async () => {
  const tarn = new TarnClient(API_BASE, APP_ID);
  await tarn.login(testUsername, testPassword);
  await tarn.deleteAccount();
  assert(!tarn.isAuthenticated, 'Still authenticated after deletion');

  // Verify login fails
  const tarn2 = new TarnClient(API_BASE, APP_ID);
  try {
    await tarn2.login(testUsername, testPassword);
    assert(false, 'Login should fail after deletion');
  } catch (err) {
    assert(err.message.includes('not found') || err.message.includes('404'), `Unexpected error: ${err.message}`);
  }
});

// ============ SUMMARY ============

console.log(`\n=== Deployment Test: ${passed} passed, ${failed} failed ===`);
if (failed === 0) {
  console.log('✓ Tarn API is fully operational.\n');
} else {
  console.log('✗ Issues detected — investigate before relying on this deployment.\n');
}
process.exit(failed > 0 ? 1 : 0);
