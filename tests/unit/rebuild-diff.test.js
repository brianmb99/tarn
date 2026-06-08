// Unit tests for tools/lib/rebuild-diff.mjs — the pure D1<->Arweave drift diff
// powering `tools/rebuild-from-arweave.mjs --check` (tarn#49).
//
// Synthetic row arrays (no Arweave / no D1) drive every branch:
//   - clean case (no drift)
//   - only-in-arweave (D1 lost a row the reconstruction still has — the drift
//     that matters for recoverability)
//   - only-in-d1 (a row D1 has that the Arweave walk did not reconstruct)
//   - value-mismatch (a row on both sides whose compared columns differ)
// Plus: acceptable-loss columns are NOT compared, BLOB (ciphertext) columns
// compare by bytes regardless of representation, and the diffRebuild/
// formatDriftReport aggregation + the `clean` flag that gates --check's exit
// code.
//
// The CLI wiring (live-D1 SELECTs via wrangler, GraphQL reconstruction) is
// covered by tests/unit/rebuild-cli-mock.test.js and the destructive
// end-to-end tests/test-rebuild-from-arweave.mjs.
//
// Run: node --test tests/unit/rebuild-diff.test.js
//   or via the umbrella script: npm run test:unit

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  norm,
  normBlob,
  diffTable,
  diffRebuild,
  formatDriftReport,
  TABLE_SPEC,
  TABLE_NAMES,
} from '../../tools/lib/rebuild-diff.mjs';

// ============ FIXTURE BUILDERS (match reducer/D1 row shapes) ============

function app(id, over = {}) {
  return { app_id: id, public_key: `pk-${id}`, invite_url_template: null, ...over };
}

function account(dlk, over = {}) {
  return {
    credential_lookup_key: `clk-${dlk}`,
    public_key: `pub-${dlk}`,
    data_lookup_key: dlk,
    wrapped_data_key: `wrap-${dlk}`,
    app: 'bookish',
    rules_json: null,
    recovery_lookup_key: null,
    recovery_public_key: null,
    share_pub: null,
    share_discoverable: 1,
    share_lookup_key: null,
    wrapped_account_key: null,
    created_at: 1000,
    ...over,
  };
}

function passkey(credId, dlk, over = {}) {
  return {
    account_id: dlk,
    credential_id: credId,
    public_key: `pk-${credId}`,
    prf_salt: `salt-${credId}`,
    device_label: null,
    sign_count: 0,
    last_used_at: null,
    created_at: 100,
    ...over,
  };
}

function inbox(txid, over = {}) {
  return {
    txid,
    app_id: 'bookish',
    inbox_tag: `tag-${txid}`,
    blob_type: 'connection-request-v1',
    ciphertext: new Uint8Array([1, 2, 3]),
    published_at: 5000,
    ...over,
  };
}

function logRow(txid, over = {}) {
  return {
    txid,
    app_id: 'bookish',
    log_tag: `tag-${txid}`,
    blob_type: 'share-log-v1',
    ciphertext: new Uint8Array([9, 8, 7]),
    data_lookup_key: '',
    published_at: 5000,
    ...over,
  };
}

// ============ norm / normBlob ============

describe('norm', () => {
  it('collapses null and undefined to null', () => {
    assert.equal(norm(null), null);
    assert.equal(norm(undefined), null);
  });
  it('coerces numbers and booleans to canonical strings', () => {
    assert.equal(norm(0), '0');
    assert.equal(norm(1), '1');
    assert.equal(norm(false), '0');
    assert.equal(norm(true), '1');
  });
  it('treats numeric 1 and string "1" as equal (SQLite int vs driver string)', () => {
    assert.equal(norm(1), norm('1'));
  });
});

describe('normBlob', () => {
  it('hexes a Uint8Array', () => {
    assert.equal(normBlob(new Uint8Array([0xde, 0xad, 0xbe, 0xef])), 'deadbeef');
  });
  it('parses a SQLite X\'..\' blob literal and bare hex equivalently', () => {
    assert.equal(normBlob("X'DEADBEEF'"), 'deadbeef');
    assert.equal(normBlob('deadbeef'), 'deadbeef');
    assert.equal(normBlob("X'DEADBEEF'"), normBlob(new Uint8Array([0xde, 0xad, 0xbe, 0xef])));
  });
  it('hexes a number[] and a Node Buffer-JSON shape', () => {
    assert.equal(normBlob([1, 2, 3]), '010203');
    assert.equal(normBlob({ type: 'Buffer', data: [1, 2, 3] }), '010203');
  });
  it('hex(ciphertext) from D1 matches the reducer Uint8Array', () => {
    // The CLI reads share blobs as `hex(ciphertext)` (bare hex string); the
    // reducer emits a Uint8Array. They must compare equal.
    const bytes = new Uint8Array([0, 255, 16]);
    assert.equal(normBlob('00FF10'), normBlob(bytes));
  });
});

// ============ TABLE SPEC SANITY ============

describe('TABLE_SPEC', () => {
  it('covers every recoverable table the rebuild reconstructs', () => {
    assert.deepEqual(
      TABLE_NAMES.sort(),
      ['accounts', 'apps', 'passkey_credentials', 'share_inbox', 'share_log'].sort(),
    );
  });
  it('excludes acceptable-loss columns from comparison', () => {
    // created_at is never compared (block-timestamp approximation).
    for (const t of TABLE_NAMES) {
      assert.equal(TABLE_SPEC[t].compareCols.includes('created_at'), false, `${t} compares created_at`);
    }
    // passkey runtime state is not compared.
    assert.equal(TABLE_SPEC.passkey_credentials.compareCols.includes('sign_count'), false);
    assert.equal(TABLE_SPEC.passkey_credentials.compareCols.includes('last_used_at'), false);
    // share_log sender attribution is a documented acceptable loss.
    assert.equal(TABLE_SPEC.share_log.compareCols.includes('data_lookup_key'), false);
    // published_at is a block-timestamp approximation, not compared.
    assert.equal(TABLE_SPEC.share_inbox.compareCols.includes('published_at'), false);
    assert.equal(TABLE_SPEC.share_log.compareCols.includes('published_at'), false);
  });
});

// ============ diffTable — CLEAN ============

describe('diffTable — clean cases', () => {
  it('apps: identical rows → clean, no drift', () => {
    const rows = [app('bookish'), app('photos')];
    const d = diffTable('apps', rows, rows.map((r) => ({ ...r })));
    assert.equal(d.clean, true);
    assert.equal(d.counts.onlyInArweave, 0);
    assert.equal(d.counts.onlyInD1, 0);
    assert.equal(d.counts.mismatched, 0);
  });

  it('accounts: created_at differing does NOT count as drift (acceptable loss)', () => {
    const dlk = 'd'.repeat(64);
    const exp = [account(dlk, { created_at: 1000 })];
    const act = [account(dlk, { created_at: 9999999 })]; // block-ts approximation differs
    const d = diffTable('accounts', exp, act);
    assert.equal(d.clean, true, 'created_at is excluded from comparison');
  });

  it('passkeys: sign_count/last_used_at differing does NOT count as drift', () => {
    const exp = [passkey('cred-1', 'd'.repeat(64), { sign_count: 0, last_used_at: null })];
    const act = [passkey('cred-1', 'd'.repeat(64), { sign_count: 42, last_used_at: 123456 })];
    const d = diffTable('passkey_credentials', exp, act);
    assert.equal(d.clean, true, 'runtime passkey columns are excluded');
  });

  it('accounts: share_discoverable 1 (number) vs "1" (string) is NOT drift', () => {
    const dlk = 'd'.repeat(64);
    const exp = [account(dlk, { share_discoverable: 1 })];
    const act = [account(dlk, { share_discoverable: '1' })]; // driver returned a string
    const d = diffTable('accounts', exp, act);
    assert.equal(d.clean, true);
  });

  it('share_log: data_lookup_key sentinel vs real DLK is NOT drift (acceptable loss)', () => {
    const exp = [logRow('tx1', { data_lookup_key: '' })];          // rebuild sentinel
    const act = [logRow('tx1', { data_lookup_key: 'real-sender' })]; // live DLK
    const d = diffTable('share_log', exp, act);
    assert.equal(d.clean, true, 'sender attribution is unrecoverable, not compared');
  });

  it('share_inbox: ciphertext bytes equal across Uint8Array vs hex → clean', () => {
    const exp = [inbox('tx1', { ciphertext: new Uint8Array([0xab, 0xcd]) })];
    const act = [inbox('tx1', { ciphertext: 'ABCD' })]; // hex(ciphertext) from D1
    const d = diffTable('share_inbox', exp, act);
    assert.equal(d.clean, true);
  });
});

// ============ diffTable — ONLY IN ARWEAVE (the drift that matters) ============

describe('diffTable — only-in-arweave (D1 lost a row)', () => {
  it('accounts: reconstructable row missing from D1 is flagged as drift', () => {
    const dlk = 'd'.repeat(64);
    const exp = [account(dlk)];
    const act = []; // D1 lost it
    const d = diffTable('accounts', exp, act);
    assert.equal(d.clean, false);
    assert.equal(d.counts.onlyInArweave, 1);
    assert.equal(d.onlyInArweave[0].key, dlk);
    assert.equal(d.counts.onlyInD1, 0);
    assert.equal(d.counts.mismatched, 0);
  });

  it('apps: D1 has fewer apps than Arweave → only-in-arweave for the missing one', () => {
    const exp = [app('bookish'), app('photos')];
    const act = [app('bookish')];
    const d = diffTable('apps', exp, act);
    assert.equal(d.clean, false);
    assert.equal(d.counts.onlyInArweave, 1);
    assert.equal(d.onlyInArweave[0].key, 'photos');
  });

  it('passkeys: a passkey present on Arweave but gone from D1 is drift', () => {
    const dlk = 'd'.repeat(64);
    const exp = [passkey('cred-1', dlk), passkey('cred-2', dlk)];
    const act = [passkey('cred-1', dlk)];
    const d = diffTable('passkey_credentials', exp, act);
    assert.equal(d.counts.onlyInArweave, 1);
    assert.equal(d.onlyInArweave[0].key, 'cred-2');
  });
});

// ============ diffTable — ONLY IN D1 ============

describe('diffTable — only-in-d1 (not reconstructable / unindexed)', () => {
  it('apps: D1 has a row Arweave did not reconstruct', () => {
    const exp = [app('bookish')];
    const act = [app('bookish'), app('ghost')];
    const d = diffTable('apps', exp, act);
    assert.equal(d.clean, false);
    assert.equal(d.counts.onlyInD1, 1);
    assert.equal(d.onlyInD1[0].key, 'ghost');
    assert.equal(d.counts.onlyInArweave, 0);
  });

  it('share_inbox: an extra D1 blob (e.g. recently written, not yet indexed)', () => {
    const exp = [inbox('tx1')];
    const act = [inbox('tx1'), inbox('tx2')];
    const d = diffTable('share_inbox', exp, act);
    assert.equal(d.counts.onlyInD1, 1);
    assert.equal(d.onlyInD1[0].key, 'tx2');
  });
});

// ============ diffTable — VALUE MISMATCH ============

describe('diffTable — value mismatch', () => {
  it('apps: public_key differs on a row present in both → mismatch', () => {
    const exp = [app('bookish', { public_key: 'pk-new' })];
    const act = [app('bookish', { public_key: 'pk-old' })];
    const d = diffTable('apps', exp, act);
    assert.equal(d.clean, false);
    assert.equal(d.counts.mismatched, 1);
    assert.equal(d.counts.onlyInArweave, 0);
    assert.equal(d.counts.onlyInD1, 0);
    const m = d.mismatches[0];
    assert.equal(m.key, 'bookish');
    assert.equal(m.fields.length, 1);
    assert.deepEqual(m.fields[0], { col: 'public_key', expected: 'pk-new', actual: 'pk-old' });
  });

  it('accounts: rules_json differs (app-config drift surfaces here)', () => {
    const dlk = 'd'.repeat(64);
    const exp = [account(dlk, { rules_json: JSON.stringify([{ allow: 'new' }]) })];
    const act = [account(dlk, { rules_json: JSON.stringify([{ allow: 'old' }]) })];
    const d = diffTable('accounts', exp, act);
    assert.equal(d.counts.mismatched, 1);
    assert.equal(d.mismatches[0].fields[0].col, 'rules_json');
  });

  it('accounts: multiple columns differing are all reported for the row', () => {
    const dlk = 'd'.repeat(64);
    const exp = [account(dlk, { public_key: 'p1', wrapped_data_key: 'w1' })];
    const act = [account(dlk, { public_key: 'p2', wrapped_data_key: 'w2' })];
    const d = diffTable('accounts', exp, act);
    assert.equal(d.mismatches.length, 1);
    const cols = d.mismatches[0].fields.map((f) => f.col).sort();
    assert.deepEqual(cols, ['public_key', 'wrapped_data_key']);
  });

  it('share_log: ciphertext bytes genuinely differing → mismatch', () => {
    const exp = [logRow('tx1', { ciphertext: new Uint8Array([1, 1, 1]) })];
    const act = [logRow('tx1', { ciphertext: '020202' })];
    const d = diffTable('share_log', exp, act);
    assert.equal(d.counts.mismatched, 1);
    assert.equal(d.mismatches[0].fields[0].col, 'ciphertext');
  });
});

// ============ diffRebuild — AGGREGATION + clean flag (exit-code contract) ============

describe('diffRebuild aggregation', () => {
  it('all-clean across every table → report.clean true (exit 0 contract)', () => {
    const rows = {
      apps: [app('bookish')],
      accounts: [account('d'.repeat(64))],
      passkey_credentials: [passkey('cred-1', 'd'.repeat(64))],
      share_inbox: [inbox('tx1')],
      share_log: [logRow('txL')],
    };
    const actual = JSON.parse(JSON.stringify(rows, (k, v) =>
      (v instanceof Uint8Array ? Array.from(v) : v)));
    const report = diffRebuild(rows, actual);
    assert.equal(report.clean, true, 'no drift → clean (CLI exits 0)');
    assert.deepEqual(report.totals, { onlyInArweave: 0, onlyInD1: 0, mismatched: 0 });
  });

  it('any drift in any table → report.clean false (exit non-zero contract)', () => {
    const expected = {
      apps: [app('bookish')],
      accounts: [account('d'.repeat(64))], // D1 will be missing this
    };
    const actual = {
      apps: [app('bookish')],
      accounts: [], // lost the account
    };
    const report = diffRebuild(expected, actual, { tables: ['apps', 'accounts'] });
    assert.equal(report.clean, false, 'drift anywhere → not clean (CLI exits 1)');
    assert.equal(report.totals.onlyInArweave, 1);
    assert.equal(report.tables.apps.clean, true);
    assert.equal(report.tables.accounts.clean, false);
  });

  it('only diffs the tables passed (skipped tables are not false-positived)', () => {
    const expected = { apps: [app('bookish')] };
    // share_log omitted entirely (would default to []); restrict to apps only.
    const actual = { apps: [app('bookish')], share_log: [logRow('orphan')] };
    const report = diffRebuild(expected, actual, { tables: ['apps'] });
    assert.equal(report.clean, true, 'untracked table is ignored');
    assert.equal('share_log' in report.tables, false);
  });

  it('missing-table-side defaults to empty (apps only-in-arweave)', () => {
    const report = diffRebuild({ apps: [app('bookish')] }, {}, { tables: ['apps'] });
    assert.equal(report.clean, false);
    assert.equal(report.tables.apps.counts.onlyInArweave, 1);
  });

  it('ignoreCols suppresses a column from comparison (app-config --skip case)', () => {
    const dlk = 'd'.repeat(64);
    // Reconstruction left rules_json null (app-config skipped); D1 has real rules.
    const expected = { accounts: [account(dlk, { rules_json: null })] };
    const actual = { accounts: [account(dlk, { rules_json: JSON.stringify([{ x: 1 }]) })] };
    // Without ignoreCols this is a mismatch...
    const drift = diffRebuild(expected, actual, { tables: ['accounts'] });
    assert.equal(drift.tables.accounts.counts.mismatched, 1);
    // ...with ignoreCols.accounts=['rules_json'] it is suppressed (clean).
    const clean = diffRebuild(expected, actual, {
      tables: ['accounts'], ignoreCols: { accounts: ['rules_json'] },
    });
    assert.equal(clean.clean, true, 'rules_json suppressed when app-config was skipped');
  });
});

// ============ formatDriftReport ============

describe('formatDriftReport', () => {
  it('renders a clean verdict with NO DRIFT', () => {
    const report = diffRebuild({ apps: [app('bookish')] }, { apps: [app('bookish')] }, { tables: ['apps'] });
    const text = formatDriftReport(report);
    assert.match(text, /apps: OK/);
    assert.match(text, /RESULT: NO DRIFT/);
  });

  it('renders DRIFT with per-category detail', () => {
    const expected = { accounts: [account('d'.repeat(64))] };
    const actual = { accounts: [] };
    const report = diffRebuild(expected, actual, { tables: ['accounts'] });
    const text = formatDriftReport(report);
    assert.match(text, /accounts: DRIFT/);
    assert.match(text, /only in Arweave \(D1 lost these\)/);
    assert.match(text, /RESULT: DRIFT DETECTED/);
  });
});
