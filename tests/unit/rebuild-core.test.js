// Unit tests for tools/lib/rebuild-core.mjs.
//
// These cover the pure parsing/grouping/tombstone logic of the Phase C
// rebuild-from-arweave tool. Synthetic fixtures (no Arweave / no D1) drive
// every code path. The CLI wiring (gateway fetches, GraphQL pagination,
// wrangler invocations) is covered separately by the integration test
// (tests/test-rebuild-from-arweave.mjs).
//
// Run: node --test tests/unit/rebuild-core.test.js
//   or via the umbrella script: npm run test:unit

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  tagValue,
  isTombstoneEdge,
  sortEdgesByTimestamp,
  groupByTag,
  rebuildApps,
  rebuildAccounts,
  dedupeBySharelookupKey,
  rebuildPasskeys,
  rebuildAppConfigRules,
  rebuildShareInbox,
  rebuildShareLog,
} from '../../tools/lib/rebuild-core.mjs';

// ============ FIXTURE BUILDERS ============

function edge(id, tags, blockTimestamp = null) {
  return { node: { id, tags, block: blockTimestamp ? { timestamp: blockTimestamp } : null } };
}

function appRegEdge(txid, appId, ts) {
  return edge(txid, [
    { name: 'App', value: 'tarn' },
    { name: 'Type', value: 'app-reg' },
    { name: 'Lk', value: appId },
    { name: 'V', value: '1' },
  ], ts);
}

function appRegBody({ app_id, public_key, invite_url_template = null, created_at = 1000 }) {
  return JSON.stringify({ v: 1, app_id, public_key, invite_url_template, created_at });
}

function credEdge(txid, lk, opts = {}) {
  const tags = [
    { name: 'App', value: 'tarn' },
    { name: 'Type', value: 'cred' },
    { name: 'Lk', value: lk },
  ];
  if (opts.rlk) tags.push({ name: 'RLk', value: opts.rlk });
  if (opts.tombstoneRef) {
    tags.push({ name: 'Op', value: 'tombstone' });
    tags.push({ name: 'Ref', value: opts.tombstoneRef });
  }
  tags.push({ name: 'V', value: '1' });
  return edge(txid, tags, opts.ts ?? null);
}

function credBody(opts) {
  const blob = {
    data_lookup_key: opts.dlk,
    wrapped_data_key: opts.wrapped ?? 'wrap-bytes',
    public_key: opts.pubkey ?? 'pub-bytes',
    app: opts.app ?? 'bookish',
  };
  if (opts.recovery_lookup_key) blob.recovery_lookup_key = opts.recovery_lookup_key;
  if (opts.recovery_public_key) blob.recovery_public_key = opts.recovery_public_key;
  if (opts.share_pub) {
    blob.share_pub = opts.share_pub;
    blob.share_discoverable = opts.share_discoverable !== false;
  }
  if (opts.share_lookup_key) blob.share_lookup_key = opts.share_lookup_key;
  if (opts.wrapped_account_key) blob.wrapped_account_key = opts.wrapped_account_key;
  return JSON.stringify(blob);
}

function passkeyEdge(txid, lk, credId, opts = {}) {
  const tags = [
    { name: 'App', value: 'tarn' },
    { name: 'Type', value: 'passkey-reg' },
    { name: 'Lk', value: lk },
    { name: 'CredId', value: credId },
  ];
  if (opts.tombstone) tags.push({ name: 'Op', value: 'tombstone' });
  tags.push({ name: 'V', value: '1' });
  return edge(txid, tags, opts.ts ?? null);
}

function passkeyBody({ dlk, credId, pubkey = 'pk', prfSalt = 'salt', deviceLabel = null, createdAt = 100 }) {
  return JSON.stringify({
    v: 1,
    data_lookup_key: dlk,
    credential_id: credId,
    public_key: pubkey,
    prf_salt: prfSalt,
    device_label: deviceLabel,
    created_at: createdAt,
  });
}

function appConfigEdge(txid, appId, dlk, ts) {
  return edge(txid, [
    { name: 'App', value: appId },
    { name: 'Type', value: 'app-config' },
    { name: 'Lk', value: dlk },
    { name: 'V', value: '1' },
  ], ts);
}

function appConfigBody(rules) {
  return JSON.stringify({ rules, set_by: 'app', timestamp: '2026-05-01T00:00:00Z' });
}

function shareEdge(txid, type, tag, appScope, ts) {
  return edge(txid, [
    { name: 'App', value: 'tarn-share' },
    { name: 'Type', value: type },
    { name: 'To', value: tag },
    { name: 'AppScope', value: appScope },
    { name: 'V', value: '0.4.0' },
  ], ts);
}

// ============ TAG HELPERS ============

describe('tagValue / groupByTag / sortEdgesByTimestamp', () => {
  it('tagValue reads tag values from edges and bare nodes', () => {
    const e = edge('a', [{ name: 'App', value: 'tarn' }]);
    assert.equal(tagValue(e, 'App'), 'tarn');
    assert.equal(tagValue(e.node, 'App'), 'tarn');
    assert.equal(tagValue(e, 'Missing'), null);
    assert.equal(tagValue(null, 'App'), null);
  });

  it('isTombstoneEdge detects Op=tombstone tag', () => {
    const live = edge('a', [{ name: 'Op', value: 'live' }]);
    const tomb = edge('b', [{ name: 'Op', value: 'tombstone' }]);
    assert.equal(isTombstoneEdge(live), false);
    assert.equal(isTombstoneEdge(tomb), true);
  });

  it('groupByTag groups by tag value, drops edges without the tag', () => {
    const a = edge('1', [{ name: 'Lk', value: 'k1' }]);
    const b = edge('2', [{ name: 'Lk', value: 'k1' }]);
    const c = edge('3', [{ name: 'Lk', value: 'k2' }]);
    const d = edge('4', []);
    const groups = groupByTag([a, b, c, d], 'Lk');
    assert.equal(groups.size, 2);
    assert.equal(groups.get('k1').length, 2);
    assert.equal(groups.get('k2').length, 1);
  });

  it('sortEdgesByTimestamp returns ASC, undefined timestamps sort to end', () => {
    const e1 = edge('1', [], 100);
    const e2 = edge('2', [], 200);
    const e3 = edge('3', [], null);
    const sorted = sortEdgesByTimestamp([e3, e2, e1]);
    assert.deepEqual(sorted.map((e) => e.node.id), ['1', '2', '3']);
  });

  it('sortEdgesByTimestamp tiebreaks deterministically by id', () => {
    const e1 = edge('b', [], 100);
    const e2 = edge('a', [], 100);
    const sorted = sortEdgesByTimestamp([e1, e2]);
    assert.deepEqual(sorted.map((e) => e.node.id), ['a', 'b']);
  });
});

// ============ APPS ============

describe('rebuildApps', () => {
  it('groups by Lk and picks the latest blob per app', () => {
    const e1 = appRegEdge('tx1', 'bookish', 100);
    const e2 = appRegEdge('tx2', 'bookish', 200); // newer
    const e3 = appRegEdge('tx3', 'other', 150);
    const bodies = new Map([
      ['tx1', appRegBody({ app_id: 'bookish', public_key: 'pk-old', invite_url_template: null, created_at: 1 })],
      ['tx2', appRegBody({ app_id: 'bookish', public_key: 'pk-new', invite_url_template: 'https://x.io/i/{token_id}', created_at: 1 })],
      ['tx3', appRegBody({ app_id: 'other', public_key: 'pk-other', invite_url_template: null, created_at: 1 })],
    ]);
    const { rows, stats } = rebuildApps([e1, e2, e3], bodies);
    assert.equal(rows.length, 2);
    const bookish = rows.find((r) => r.app_id === 'bookish');
    assert.equal(bookish.public_key, 'pk-new');
    assert.equal(bookish.invite_url_template, 'https://x.io/i/{token_id}');
    assert.equal(stats.rebuilt, 2);
    assert.equal(stats.found, 3);
  });

  it('counts body misses without crashing', () => {
    const e = appRegEdge('tx1', 'bookish', 100);
    const { rows, stats } = rebuildApps([e], new Map()); // no body fetched
    assert.equal(rows.length, 0);
    assert.equal(stats.bodyMisses, 1);
    assert.equal(stats.rebuilt, 0);
  });

  it('counts parse errors for malformed bodies', () => {
    const e = appRegEdge('tx1', 'bookish', 100);
    const bodies = new Map([['tx1', '{not json']]);
    const { rows, stats } = rebuildApps([e], bodies);
    assert.equal(rows.length, 0);
    assert.equal(stats.parseErrors, 1);
  });

  it('rejects body whose app_id mismatches the Lk tag', () => {
    const e = appRegEdge('tx1', 'bookish', 100);
    const bodies = new Map([['tx1', appRegBody({ app_id: 'imposter', public_key: 'pk' })]]);
    const { rows, stats } = rebuildApps([e], bodies);
    assert.equal(rows.length, 0);
    assert.equal(stats.parseErrors, 1);
  });
});

// ============ ACCOUNTS ============

describe('rebuildAccounts', () => {
  it('rebuilds a single live account from its credential blob', () => {
    const dlk = 'd'.repeat(64);
    const lk = 'a'.repeat(64);
    const e = credEdge('tx1', lk, { ts: 100 });
    const bodies = new Map([['tx1', credBody({ dlk, app: 'bookish' })]]);
    const { rows, stats } = rebuildAccounts([e], bodies);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].credential_lookup_key, lk);
    assert.equal(rows[0].data_lookup_key, dlk);
    assert.equal(rows[0].app, 'bookish');
    assert.equal(rows[0].rules_json, null);
    assert.equal(rows[0].share_discoverable, 1, 'no share_pub → defaults to discoverable=1');
    assert.equal(stats.rebuilt, 1);
  });

  it('latest credential blob per dlk wins (rotation)', () => {
    const dlk = 'd'.repeat(64);
    const lkOld = 'a'.repeat(64);
    const lkNew = 'b'.repeat(64);
    const eOld = credEdge('tx1', lkOld, { ts: 100 });
    const eNew = credEdge('tx2', lkNew, { ts: 200 });
    const bodies = new Map([
      ['tx1', credBody({ dlk, wrapped: 'old-wrap' })],
      ['tx2', credBody({ dlk, wrapped: 'new-wrap' })],
    ]);
    const { rows } = rebuildAccounts([eOld, eNew], bodies);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].credential_lookup_key, lkNew, 'latest credential_lookup_key wins');
    assert.equal(rows[0].wrapped_data_key, 'new-wrap');
  });

  it('tombstones exclude their referenced credential blob', () => {
    const dlk = 'd'.repeat(64);
    const lk = 'a'.repeat(64);
    const eLive = credEdge('tx-live', lk, { ts: 100 });
    const eTomb = credEdge('tx-tomb', lk, { ts: 200, tombstoneRef: 'tx-live' });
    const bodies = new Map([
      ['tx-live', credBody({ dlk })],
      ['tx-tomb', '{}'],
    ]);
    const { rows, stats } = rebuildAccounts([eLive, eTomb], bodies);
    assert.equal(rows.length, 0, 'tombstoned credential is excluded');
    assert.equal(stats.tombstoned, 1);
  });

  it('reads recovery_lookup_key from RLk tag (post-2026-05) over body field', () => {
    const dlk = 'd'.repeat(64);
    const lk = 'a'.repeat(64);
    const rlkTag = 'r'.repeat(64);
    const rlkBody = 'q'.repeat(64);
    const e = credEdge('tx1', lk, { rlk: rlkTag, ts: 100 });
    const bodies = new Map([['tx1', credBody({ dlk, recovery_lookup_key: rlkBody, recovery_public_key: 'rec-pk' })]]);
    const { rows } = rebuildAccounts([e], bodies);
    assert.equal(rows[0].recovery_lookup_key, rlkTag, 'RLk tag overrides body');
    assert.equal(rows[0].recovery_public_key, 'rec-pk');
  });

  it('falls back to body field when RLk tag is absent (pre-2026-05 blob)', () => {
    const dlk = 'd'.repeat(64);
    const lk = 'a'.repeat(64);
    const rlkBody = 'r'.repeat(64);
    const e = credEdge('tx1', lk, { ts: 100 }); // no rlk tag
    const bodies = new Map([['tx1', credBody({ dlk, recovery_lookup_key: rlkBody, recovery_public_key: 'rec-pk' })]]);
    const { rows } = rebuildAccounts([e], bodies);
    assert.equal(rows[0].recovery_lookup_key, rlkBody);
  });

  it('preserves share fields including share_discoverable=0', () => {
    const dlk = 'd'.repeat(64);
    const lk = 'a'.repeat(64);
    const e = credEdge('tx1', lk, { ts: 100 });
    const bodies = new Map([['tx1', credBody({ dlk, share_pub: 'X'.repeat(43), share_lookup_key: 's'.repeat(64), share_discoverable: false })]]);
    const { rows } = rebuildAccounts([e], bodies);
    assert.equal(rows[0].share_pub, 'X'.repeat(43));
    assert.equal(rows[0].share_lookup_key, 's'.repeat(64));
    assert.equal(rows[0].share_discoverable, 0, 'explicit false → 0');
  });

  it('counts body misses and parse errors without dropping good rows', () => {
    const dlk = 'd'.repeat(64);
    const lk = 'a'.repeat(64);
    const eGood = credEdge('tx1', lk, { ts: 100 });
    const eMissing = credEdge('tx2', 'b'.repeat(64), { ts: 100 });
    const eBad = credEdge('tx3', 'c'.repeat(64), { ts: 100 });
    const bodies = new Map([
      ['tx1', credBody({ dlk })],
      ['tx3', '{not json'],
    ]);
    const { rows, stats } = rebuildAccounts([eGood, eMissing, eBad], bodies);
    assert.equal(rows.length, 1);
    assert.equal(stats.bodyMisses, 1);
    assert.equal(stats.parseErrors, 1);
  });

  it('drops the older of two distinct-dlk / same-share_lookup_key accounts (#41)', () => {
    // Two registrations of the same email (same share_lookup_key) as distinct
    // accounts (distinct data_lookup_key + credential_lookup_key). The partial
    // UNIQUE(share_lookup_key) index would reject the second INSERT; the dedup
    // must keep only the latest by block timestamp.
    const sk = 's'.repeat(64);
    const eOld = credEdge('tx-old', 'a'.repeat(64), { ts: 100 });
    const eNew = credEdge('tx-new', 'b'.repeat(64), { ts: 200 });
    const bodies = new Map([
      ['tx-old', credBody({ dlk: 'd1'.padEnd(64, '0'), share_lookup_key: sk })],
      ['tx-new', credBody({ dlk: 'd2'.padEnd(64, '0'), share_lookup_key: sk })],
    ]);
    const { rows, stats } = rebuildAccounts([eOld, eNew], bodies);
    assert.equal(rows.length, 1, 'only the latest registration survives');
    assert.equal(rows[0].credential_lookup_key, 'b'.repeat(64), 'latest-by-timestamp wins');
    assert.equal(rows[0].data_lookup_key, 'd2'.padEnd(64, '0'));
    assert.equal(stats.shareKeySuperseded, 1);
    assert.equal(stats.rebuilt, 1);
    // No helper field leaks into the emitted row.
    assert.equal('block_timestamp' in rows[0], false, 'block_timestamp stripped from emitted row');
  });

  it('keeps all NULL share_lookup_key accounts (legacy, no uniqueness)', () => {
    const eA = credEdge('txA', 'a'.repeat(64), { ts: 100 });
    const eB = credEdge('txB', 'b'.repeat(64), { ts: 200 });
    const bodies = new Map([
      // No share_lookup_key → null on both.
      ['txA', credBody({ dlk: 'da'.padEnd(64, '0') })],
      ['txB', credBody({ dlk: 'db'.padEnd(64, '0') })],
    ]);
    const { rows, stats } = rebuildAccounts([eA, eB], bodies);
    assert.equal(rows.length, 2, 'NULL share_lookup_key never dedups');
    assert.equal(stats.shareKeySuperseded, 0);
  });
});

// ============ SHARE-LOOKUP-KEY DEDUP (#41) ============

describe('dedupeBySharelookupKey', () => {
  // Minimal candidate factory matching the shape rebuildAccounts emits internally.
  function cand(clk, share_lookup_key, block_timestamp) {
    return { credential_lookup_key: clk, share_lookup_key, block_timestamp };
  }

  function assertNoShareKeyCollision(rows) {
    const seen = new Set();
    for (const r of rows) {
      if (r.share_lookup_key == null || r.share_lookup_key === '') continue;
      assert.equal(seen.has(r.share_lookup_key), false,
        `duplicate non-null share_lookup_key survived: ${r.share_lookup_key}`);
      seen.add(r.share_lookup_key);
    }
  }

  it('distinct dlk + same non-null share_lookup_key → only latest-by-timestamp survives', () => {
    const sk = 's'.repeat(64);
    const out = dedupeBySharelookupKey([
      cand('clk-old', sk, 100),
      cand('clk-new', sk, 200),
    ]);
    assert.equal(out.length, 1);
    assert.equal(out[0].credential_lookup_key, 'clk-new');
    assertNoShareKeyCollision(out);
  });

  it('same share_lookup_key but one NULL → both survive (NULL never dedups)', () => {
    const sk = 's'.repeat(64);
    const out = dedupeBySharelookupKey([
      cand('clk-null', null, 100),
      cand('clk-keyed', sk, 200),
    ]);
    assert.equal(out.length, 2, 'a NULL row never collides with a keyed row');
    assertNoShareKeyCollision(out);
  });

  it('multiple NULL share_lookup_key rows all survive', () => {
    const out = dedupeBySharelookupKey([
      cand('clk-1', null, 100),
      cand('clk-2', null, 200),
      cand('clk-3', '', 300), // empty string treated as no-constraint too
    ]);
    assert.equal(out.length, 3);
  });

  it('distinct share_lookup_keys → both survive', () => {
    const out = dedupeBySharelookupKey([
      cand('clk-1', 'a'.repeat(64), 100),
      cand('clk-2', 'b'.repeat(64), 200),
    ]);
    assert.equal(out.length, 2);
    assertNoShareKeyCollision(out);
  });

  it('tie on block_timestamp → deterministic pick: lexicographically largest credential_lookup_key', () => {
    const sk = 's'.repeat(64);
    const out = dedupeBySharelookupKey([
      cand('clk-aaa', sk, 100),
      cand('clk-zzz', sk, 100), // same ts; larger clk wins
    ]);
    assert.equal(out.length, 1);
    assert.equal(out[0].credential_lookup_key, 'clk-zzz');
    // Order-independent: same winner regardless of input order.
    const out2 = dedupeBySharelookupKey([
      cand('clk-zzz', sk, 100),
      cand('clk-aaa', sk, 100),
    ]);
    assert.equal(out2[0].credential_lookup_key, 'clk-zzz');
  });

  it('null block_timestamp (unconfirmed) is treated as newest', () => {
    const sk = 's'.repeat(64);
    const out = dedupeBySharelookupKey([
      cand('clk-confirmed', sk, 999),
      cand('clk-unconfirmed', sk, null),
    ]);
    assert.equal(out.length, 1);
    assert.equal(out[0].credential_lookup_key, 'clk-unconfirmed',
      'unconfirmed (null ts) sorts newest, matching sortEdgesByTimestamp');
  });

  it('three same-key candidates collapse to the single newest', () => {
    const sk = 's'.repeat(64);
    const out = dedupeBySharelookupKey([
      cand('clk-1', sk, 100),
      cand('clk-2', sk, 300),
      cand('clk-3', sk, 200),
    ]);
    assert.equal(out.length, 1);
    assert.equal(out[0].credential_lookup_key, 'clk-2');
    assertNoShareKeyCollision(out);
  });

  it('no two survivors ever share a non-null share_lookup_key (mixed batch)', () => {
    const sk1 = 's1'.padEnd(64, '0');
    const sk2 = 's2'.padEnd(64, '0');
    const out = dedupeBySharelookupKey([
      cand('clk-a', sk1, 100),
      cand('clk-b', sk1, 200), // dup of sk1
      cand('clk-c', sk2, 150),
      cand('clk-d', null, 175),
      cand('clk-e', sk2, 50),  // dup of sk2
      cand('clk-f', null, 80),
    ]);
    // sk1: clk-b, sk2: clk-c, plus two NULLs (clk-d, clk-f) = 4 survivors.
    assert.equal(out.length, 4);
    assertNoShareKeyCollision(out);
    const clks = out.map((r) => r.credential_lookup_key).sort();
    assert.deepEqual(clks, ['clk-b', 'clk-c', 'clk-d', 'clk-f']);
  });

  it('does not mutate the input array or rows', () => {
    const sk = 's'.repeat(64);
    const input = [cand('clk-old', sk, 100), cand('clk-new', sk, 200)];
    const snapshot = JSON.parse(JSON.stringify(input));
    dedupeBySharelookupKey(input);
    assert.equal(input.length, 2, 'input length unchanged');
    assert.deepEqual(JSON.parse(JSON.stringify(input)), snapshot, 'input rows unchanged');
  });
});

// ============ PASSKEY CREDENTIALS ============

describe('rebuildPasskeys', () => {
  it('rebuilds a registered passkey', () => {
    const dlk = 'd'.repeat(64);
    const credId = 'cred-id-1';
    const e = passkeyEdge('tx1', dlk, credId, { ts: 100 });
    const bodies = new Map([['tx1', passkeyBody({ dlk, credId, deviceLabel: 'iPhone' })]]);
    const { rows, stats } = rebuildPasskeys([e], bodies);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].credential_id, credId);
    assert.equal(rows[0].account_id, dlk);
    assert.equal(rows[0].device_label, 'iPhone');
    assert.equal(rows[0].sign_count, 0, 'sign_count defaults to 0');
    assert.equal(rows[0].last_used_at, null);
    assert.equal(stats.rebuilt, 1);
  });

  it('excludes credentials whose group contains a tombstone', () => {
    const dlk = 'd'.repeat(64);
    const credId = 'cred-id-1';
    const eReg = passkeyEdge('tx1', dlk, credId, { ts: 100 });
    const eTomb = passkeyEdge('tx2', dlk, credId, { ts: 200, tombstone: true });
    const bodies = new Map([
      ['tx1', passkeyBody({ dlk, credId })],
      ['tx2', JSON.stringify({ v: 1, tombstone: true, credential_id: credId })],
    ]);
    const { rows, stats } = rebuildPasskeys([eReg, eTomb], bodies);
    assert.equal(rows.length, 0);
    assert.equal(stats.tombstoned, 1);
  });

  it('latest non-tombstoned blob per CredId wins', () => {
    const dlk = 'd'.repeat(64);
    const credId = 'cred-id-1';
    const eOld = passkeyEdge('tx1', dlk, credId, { ts: 100 });
    const eNew = passkeyEdge('tx2', dlk, credId, { ts: 200 });
    const bodies = new Map([
      ['tx1', passkeyBody({ dlk, credId, deviceLabel: 'old' })],
      ['tx2', passkeyBody({ dlk, credId, deviceLabel: 'new' })],
    ]);
    const { rows } = rebuildPasskeys([eOld, eNew], bodies);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].device_label, 'new');
  });

  it('rejects body whose credential_id mismatches the CredId tag', () => {
    const dlk = 'd'.repeat(64);
    const e = passkeyEdge('tx1', dlk, 'cred-tag', { ts: 100 });
    const bodies = new Map([['tx1', passkeyBody({ dlk, credId: 'cred-mismatch' })]]);
    const { rows, stats } = rebuildPasskeys([e], bodies);
    assert.equal(rows.length, 0);
    assert.equal(stats.parseErrors, 1);
  });
});

// ============ APP-CONFIG → rules_json ============

describe('rebuildAppConfigRules', () => {
  it('returns latest rules per dlk, serialized as JSON', () => {
    const dlk = 'd'.repeat(64);
    const eOld = appConfigEdge('tx1', 'bookish', dlk, 100);
    const eNew = appConfigEdge('tx2', 'bookish', dlk, 200);
    const bodies = new Map([
      ['tx1', appConfigBody([{ allow: 'old' }])],
      ['tx2', appConfigBody([{ allow: 'new' }])],
    ]);
    const { updates, stats } = rebuildAppConfigRules([eOld, eNew], bodies);
    assert.equal(updates.size, 1);
    assert.equal(updates.get(dlk), JSON.stringify([{ allow: 'new' }]));
    assert.equal(stats.applied, 1);
  });

  it('skips bodies that are not arrays', () => {
    const dlk = 'd'.repeat(64);
    const e = appConfigEdge('tx1', 'bookish', dlk, 100);
    const bodies = new Map([['tx1', JSON.stringify({ rules: 'not-an-array' })]]);
    const { updates, stats } = rebuildAppConfigRules([e], bodies);
    assert.equal(updates.size, 0);
    assert.equal(stats.parseErrors, 1);
  });
});

// ============ SHARE-INBOX / SHARE-LOG ============

describe('rebuildShareInbox', () => {
  it('reconstructs every blob as a row keyed by txid', () => {
    const e1 = shareEdge('tx1', 'connection-request-v1', 'tag-a', 'bookish', 100);
    const e2 = shareEdge('tx2', 'connection-accept-v1', 'tag-a', 'bookish', 200);
    const bodies = new Map([
      ['tx1', new Uint8Array([1, 2, 3])],
      ['tx2', new Uint8Array([4, 5, 6])],
    ]);
    const { rows, stats } = rebuildShareInbox([e1, e2], bodies);
    assert.equal(rows.length, 2);
    assert.equal(rows[0].txid, 'tx1');
    assert.equal(rows[0].inbox_tag, 'tag-a');
    assert.equal(rows[0].blob_type, 'connection-request-v1');
    assert.equal(rows[0].app_id, 'bookish');
    assert.equal(rows[0].published_at, 100_000);
    assert.equal(rows[0].ciphertext.length, 3);
    assert.equal(stats.rebuilt, 2);
  });

  it('counts body misses without dropping good rows', () => {
    const e1 = shareEdge('tx1', 'connection-request-v1', 'tag-a', 'bookish', 100);
    const e2 = shareEdge('tx2', 'connection-accept-v1', 'tag-a', 'bookish', 200);
    const bodies = new Map([['tx1', new Uint8Array([1])]]);
    const { rows, stats } = rebuildShareInbox([e1, e2], bodies);
    assert.equal(rows.length, 1);
    assert.equal(stats.bodyMisses, 1);
  });
});

describe('rebuildShareLog', () => {
  it('de-dupes by (app, log_tag, blob_type) keeping the latest by timestamp', () => {
    const e1 = shareEdge('tx1', 'share-log-v1', 'tag-a', 'bookish', 100);
    const e2 = shareEdge('tx2', 'share-log-v1', 'tag-a', 'bookish', 200);
    const bodies = new Map([
      ['tx1', new Uint8Array([1])],
      ['tx2', new Uint8Array([2])],
    ]);
    const { rows } = rebuildShareLog([e1, e2], bodies);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].txid, 'tx2', 'newer wins');
  });

  it('uses the configured sentinel for unknown sender DLK', () => {
    const e = shareEdge('tx1', 'share-log-v1', 'tag-a', 'bookish', 100);
    const bodies = new Map([['tx1', new Uint8Array([1])]]);
    const { rows } = rebuildShareLog([e], bodies, { unknownSenderSentinel: '<unknown>' });
    assert.equal(rows[0].data_lookup_key, '<unknown>');
  });
});
