// Delta-sync cursor integration tests (tarn#38 / audit SDK-3).
//
// Verifies the monotonicity guarantee documented under "Delta-sync cursor"
// in docs/TARN_PROTOCOL.md: the cursor is "<cached_at>:<txid>", cached_at is
// a D1-write-time clock, and incremental syncs return every live entry
// EXACTLY ONCE — even when entries share a cached_at millisecond (batch
// writes) and even when new entries arrive after the cursor has advanced.
//
// Run: node --import tsx tests/test-delta-sync.mjs [apiBaseUrl]
// Requires: cd api && npx wrangler dev --port 8787
//           cd api && npx wrangler d1 migrations apply tarn-api --local

import {
  deriveAllKeys, exportPublicKey, wrapDataKey,
  signChallenge, encrypt, bytesToBase64,
} from '../client/src/crypto.js';
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

async function fetchJSON(path, opts = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: res.status, json, text };
}

// Register + login with the raw API, returning keys + jwt + dlk.
async function rawRegisterAndLogin() {
  const username = randomUsername();
  const password = 'delta-test-pass';
  const keys = await deriveAllKeys(username, password, DEFAULT_APP_ID);
  const pub = await exportPublicKey(keys.signingKeyPair.publicKey);
  const wdk = await wrapDataKey(keys.credentialEncryptionKey.gcmKey, keys.credentialEncryptionKey.kwKey);

  const sharePubBytes = new Uint8Array(32);
  crypto.getRandomValues(sharePubBytes);
  const sharePub = btoa(String.fromCharCode(...sharePubBytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const shareLookupKeyBytes = new Uint8Array(32);
  crypto.getRandomValues(shareLookupKeyBytes);
  const shareLookupKey = Array.from(shareLookupKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');

  const regRes = await fetchJSON('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({
      credential_lookup_key: keys.credentialLookupKey,
      public_key: pub,
      wrapped_data_key: wdk,
      app: DEFAULT_APP_ID,
      share_pub: sharePub,
      share_lookup_key: shareLookupKey,
    }),
  });
  assert(regRes.status === 201, `Register failed: ${regRes.status} ${regRes.text}`);
  const dlk = regRes.json.data_lookup_key;

  const cRes = await fetchJSON('/api/v1/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ credential_lookup_key: keys.credentialLookupKey }),
  });
  assert(cRes.status === 200, `Challenge failed: ${cRes.status}`);
  const sig = await signChallenge(keys.signingKeyPair.privateKey, cRes.json.nonce);
  const vRes = await fetchJSON('/api/v1/auth/verify', {
    method: 'POST',
    body: JSON.stringify({
      credential_lookup_key: keys.credentialLookupKey,
      nonce: cRes.json.nonce,
      signature: sig,
    }),
  });
  assert(vRes.status === 200, `Verify failed: ${vRes.status}`);

  await forceAllowRulesForAccount(dlk);

  return { username, password, keys, dlk, jwt: vRes.json.jwt, encKey: keys.credentialEncryptionKey.gcmKey };
}

function tagsFor(dlk, type, eid, extra = []) {
  return [
    { name: 'App', value: DEFAULT_APP_ID },
    { name: 'Type', value: type },
    { name: 'Lk', value: dlk },
    { name: 'Eid', value: eid },
    { name: 'Enc', value: 'aes-256-gcm' },
    { name: 'V', value: '0.3.0' },
    ...extra,
  ];
}

// Single create — returns txid.
async function createEntry(jwt, dlk, encKey, type, eid, payload) {
  const encrypted = await encrypt(encKey, payload);
  const res = await fetch(`${API_BASE}/api/v1/entries`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${jwt}`,
      'X-Arweave-Tags': JSON.stringify(tagsFor(dlk, type, eid)),
      'Content-Type': 'application/octet-stream',
    },
    body: encrypted,
  });
  const json = await res.json().catch(() => null);
  assert(res.status === 200, `Create failed: ${res.status} ${JSON.stringify(json)}`);
  return json.id;
}

// Batch create — all rows land in the same cached_at millisecond on D1, which
// is exactly the "same/near timestamps" case the cursor's txid tiebreak must
// survive. Returns array of txids.
async function batchCreate(jwt, dlk, encKey, type, items) {
  const entries = [];
  for (const it of items) {
    const encrypted = await encrypt(encKey, it.payload);
    entries.push({ data: bytesToBase64(encrypted), tags: tagsFor(dlk, type, it.eid) });
  }
  const res = await fetch(`${API_BASE}/api/v1/entries/batch`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${jwt}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ entries }),
  });
  const json = await res.json().catch(() => null);
  assert(res.status === 200, `Batch create failed: ${res.status} ${JSON.stringify(json)}`);
  return json.entries.map(e => e.txid);
}

// Drive one page of the delta endpoint. Returns { events, cursor, hasMore }.
async function deltaPage(jwt, dlk, type, cursor) {
  const url = `/api/v1/entries?app=${DEFAULT_APP_ID}&type=${type}&key=${dlk}&since=${encodeURIComponent(cursor)}`;
  const res = await fetchJSON(url, { headers: { 'Authorization': `Bearer ${jwt}` } });
  assert(res.status === 200, `Delta read failed: ${res.status} ${res.text}`);
  return {
    events: res.json.entries || [],
    cursor: res.json.pagination?.cursor,
    hasMore: !!res.json.pagination?.hasMore,
  };
}

// Drain the whole delta stream from `startCursor`, collecting every live event.
// Returns { liveTxids: string[], deletedEids: string[], finalCursor }.
async function drainDelta(jwt, dlk, type, startCursor = '0:') {
  let cursor = startCursor;
  const liveTxids = [];
  const deletedEids = [];
  for (let i = 0; i < 200; i++) {
    const { events, cursor: next, hasMore } = await deltaPage(jwt, dlk, type, cursor);
    for (const evt of events) {
      if (evt.deleted) deletedEids.push(evt.eid);
      else liveTxids.push(evt.txid);
    }
    cursor = next ?? cursor;
    if (!hasMore) break;
  }
  return { liveTxids, deletedEids, finalCursor: cursor };
}

// ============ 1. EXACTLY-ONCE OVER A SINGLE DRAIN ============

console.log('\n=== 1. Incremental sync returns every entry exactly once ===');

await test('Mixed single + batch writes (same-ms cached_at) drain exactly once', async () => {
  const { jwt, dlk, encKey } = await rawRegisterAndLogin();
  const type = 'entry';
  const expected = new Set();

  // A few singletons.
  for (let i = 0; i < 3; i++) {
    expected.add(await createEntry(jwt, dlk, encKey, type, `s${i}`, { idx: i }));
  }
  // A batch of 10 — these share one cached_at millisecond, exercising the
  // (cached_at, txid) tiebreak. >25 total forces multi-page pagination.
  const batchTxids = await batchCreate(jwt, dlk, encKey, type,
    Array.from({ length: 10 }, (_, i) => ({ eid: `b${i}`, payload: { batch: i } })));
  batchTxids.forEach(t => expected.add(t));
  // Another batch to push past the 25-row page cap.
  const batch2 = await batchCreate(jwt, dlk, encKey, type,
    Array.from({ length: 20 }, (_, i) => ({ eid: `c${i}`, payload: { batch2: i } })));
  batch2.forEach(t => expected.add(t));
  await sleep(300);

  const { liveTxids } = await drainDelta(jwt, dlk, type);

  // Exactly once: no duplicates, and every expected txid present.
  const counts = new Map();
  for (const t of liveTxids) counts.set(t, (counts.get(t) || 0) + 1);
  for (const [t, c] of counts) assert(c === 1, `txid ${t} returned ${c} times (expected once)`);
  for (const t of expected) assert(counts.has(t), `expected txid ${t} was skipped`);
  assert(liveTxids.length === expected.size,
    `got ${liveTxids.length} live events, expected ${expected.size}`);
});

// ============ 2. CURSOR ADVANCE THEN NEW WRITE (the audit's scenario) ============

console.log('\n=== 2. Entry written after cursor advance is not skipped ===');

await test('Advance cursor past a window, then write more — catch-up returns the new ones', async () => {
  const { jwt, dlk, encKey } = await rawRegisterAndLogin();
  const type = 'entry';

  // First wave.
  const wave1 = new Set();
  wave1.add(await createEntry(jwt, dlk, encKey, type, 'w1a', { n: 1 }));
  wave1.add(await createEntry(jwt, dlk, encKey, type, 'w1b', { n: 2 }));
  await sleep(200);

  // Drain to fully advance the cursor past wave 1.
  const first = await drainDelta(jwt, dlk, type);
  for (const t of wave1) assert(first.liveTxids.includes(t), `wave-1 txid ${t} missing on first drain`);
  const cursorAfterWave1 = first.finalCursor;

  // A re-poll at the advanced cursor must now return NOTHING.
  const emptyPoll = await drainDelta(jwt, dlk, type, cursorAfterWave1);
  assert(emptyPoll.liveTxids.length === 0,
    `re-poll at advanced cursor returned ${emptyPoll.liveTxids.length} stale events`);

  // Second wave AFTER the cursor advanced — a batch sharing one cached_at ms.
  const wave2 = new Set(await batchCreate(jwt, dlk, encKey, type,
    Array.from({ length: 5 }, (_, i) => ({ eid: `w2_${i}`, payload: { wave: 2, i } }))));
  await sleep(200);

  // Catch-up from the advanced cursor returns exactly wave 2 — never wave 1.
  const second = await drainDelta(jwt, dlk, type, cursorAfterWave1);
  for (const t of wave2) assert(second.liveTxids.includes(t), `wave-2 txid ${t} skipped after cursor advance`);
  for (const t of wave1) assert(!second.liveTxids.includes(t), `wave-1 txid ${t} replayed`);
  assert(second.liveTxids.length === wave2.size,
    `catch-up returned ${second.liveTxids.length} events, expected ${wave2.size}`);
});

// ============ 3. UPDATE + DELETE SEMANTICS THROUGH THE DELTA STREAM ============

console.log('\n=== 3. Update and delete surface as resolved delta events ===');

await test('Update resolves to latest version; delete surfaces as deleted:true', async () => {
  const { jwt, dlk, encKey } = await rawRegisterAndLogin();
  const type = 'entry';

  // Create two entries; advance past them.
  const keepTxid = await createEntry(jwt, dlk, encKey, type, 'keep', { v: 1 });
  const delTxid = await createEntry(jwt, dlk, encKey, type, 'gone', { v: 1 });
  await sleep(200);
  const afterCreate = (await drainDelta(jwt, dlk, type)).finalCursor;

  // Update "keep" (Prev-chain).
  const updEnc = await encrypt(encKey, { v: 2 });
  const updRes = await fetch(`${API_BASE}/api/v1/entries/${keepTxid}`, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${jwt}`,
      'X-Arweave-Tags': JSON.stringify(tagsFor(dlk, type, 'keep', [{ name: 'Prev', value: keepTxid }])),
      'Content-Type': 'application/octet-stream',
    },
    body: updEnc,
  });
  const updJson = await updRes.json();
  assert(updRes.status === 200, `Update failed: ${updRes.status} ${JSON.stringify(updJson)}`);
  const newKeepTxid = updJson.id;

  // Delete "gone" (tombstone).
  const tombEnc = await encrypt(encKey, { tombstone: true });
  const delRes = await fetch(`${API_BASE}/api/v1/entries/${delTxid}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${jwt}`,
      'X-Arweave-Tags': JSON.stringify(tagsFor(dlk, type, 'gone',
        [{ name: 'Op', value: 'tombstone' }, { name: 'Ref', value: delTxid }])),
      'Content-Type': 'application/octet-stream',
    },
    body: tombEnc,
  });
  assert(delRes.status === 200, `Delete failed: ${delRes.status}`);
  await sleep(200);

  // Catch-up from after the creates: see the updated head once, and a delete.
  const delta = await drainDelta(jwt, dlk, type, afterCreate);
  assert(delta.liveTxids.filter(t => t === newKeepTxid).length === 1,
    'updated entry should appear exactly once as its new head');
  assert(!delta.liveTxids.includes(keepTxid), 'superseded prior version should not appear as live');
  assert(delta.deletedEids.includes('gone'), 'deleted Eid should surface as a deletion event');
});

// ============ SUMMARY ============

console.log(`\n=== Delta-sync results: ${passed} passed, ${failed} failed ===\n`);
process.exit(failed > 0 ? 1 : 0);
