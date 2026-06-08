// rebuild-diff.mjs — pure D1<->Arweave drift diff for the rebuild tool's
// `--check` mode (tarn#49).
//
// `tools/rebuild-from-arweave.mjs --check` reconstructs the EXPECTED D1 state
// from Arweave (via the rebuild-core reducers) and reads the ACTUAL live D1
// state, then hands both to `diffRebuild()` here. This module is the
// side-effect-free core of `--check`: no Arweave, no D1, no I/O. The CLI does
// the GraphQL/gateway/wrangler work and feeds plain row arrays in.
//
// This is the on-demand, ROW-LEVEL counterpart to the hourly count-level drift
// cron (api/src/observability/drift.js, tarn#44). The cron answers "is D1
// missing settled blobs?" cheaply by counting; `--check` answers "does every
// reconstructable row match D1 field-for-field?" by actually rebuilding and
// comparing. Same intent (catch divergence early), different granularity.
//
// The per-table key/compare/ignore spec below is lifted from the proven diff
// in tests/test-rebuild-from-arweave.mjs (its `diff()` over apps / accounts /
// passkey_credentials), generalized to share_inbox + share_log and refactored
// so both the CLI and a node:test unit suite can drive it without Arweave/D1.
//
// "Acceptable losses" (columns Arweave cannot reconstruct exactly) are the same
// set the destructive end-to-end proof documents and excludes:
//   - *.created_at                 — block-timestamp approximation
//   - passkey_credentials.sign_count   — runtime replay counter, rebuilds to 0
//   - passkey_credentials.last_used_at — runtime state, rebuilds to NULL
//   - share_log.data_lookup_key    — sender attribution unrecoverable ('')
//   - share_inbox/share_log.published_at — block-timestamp approximation
// These are NOT compared, so they never produce false drift.

// ============ TABLE SPEC ============

// For each table: the primary key column used to align rows, and the set of
// columns whose VALUES must match. Columns not listed (and not the key) are
// intentionally ignored — they are the documented acceptable losses above, or
// in the case of `ciphertext`, compared specially (it is a BLOB; see norm()).
//
// `blobCols` are compared but require byte-normalization first because a BLOB
// surfaces differently from D1 (hex / array) than from the reducer (Uint8Array).
export const TABLE_SPEC = {
  apps: {
    key: 'app_id',
    compareCols: ['public_key', 'invite_url_template'],
    blobCols: [],
  },
  accounts: {
    key: 'data_lookup_key',
    compareCols: [
      'credential_lookup_key', 'public_key', 'wrapped_data_key', 'app',
      'recovery_lookup_key', 'recovery_public_key', 'share_pub',
      'share_discoverable', 'share_lookup_key', 'wrapped_account_key',
      'rules_json',
    ],
    blobCols: [],
  },
  passkey_credentials: {
    key: 'credential_id',
    compareCols: ['account_id', 'public_key', 'prf_salt', 'device_label'],
    blobCols: [],
  },
  share_inbox: {
    key: 'txid',
    compareCols: ['app_id', 'inbox_tag', 'blob_type', 'ciphertext'],
    blobCols: ['ciphertext'],
  },
  share_log: {
    key: 'txid',
    // data_lookup_key is a documented acceptable loss ('' sentinel on rebuild),
    // so it is NOT in compareCols.
    compareCols: ['app_id', 'log_tag', 'blob_type', 'ciphertext'],
    blobCols: ['ciphertext'],
  },
};

export const TABLE_NAMES = Object.keys(TABLE_SPEC);

// ============ VALUE NORMALIZATION ============

/**
 * Normalize a scalar so an expected value (from a reducer) and an actual value
 * (from `wrangler d1 execute --json`) compare equal when they are semantically
 * the same. D1 returns numbers as numbers and NULLs as null; reducers emit the
 * same JS types, but SQLite integer columns (e.g. share_discoverable 0/1) can
 * surface as either number or string depending on the driver, so we coerce to
 * string. null/undefined both collapse to null.
 */
export function norm(v) {
  if (v == null) return null;
  if (v instanceof Uint8Array) return bytesToHex(v);
  if (typeof v === 'number') return String(v);
  if (typeof v === 'boolean') return v ? '1' : '0';
  return String(v);
}

/**
 * Normalize a BLOB column to a comparable hex string regardless of how it
 * arrives:
 *   - Uint8Array (reducer output, and node:Buffer which extends Uint8Array)
 *   - number[] (some JSON encodings of a blob)
 *   - { type:'Buffer', data:[...] } (Node Buffer JSON shape)
 *   - string of "X'..' " SQLite blob-literal, or a raw hex string, or base64
 * Anything unrecognized falls back to norm().
 */
export function normBlob(v) {
  if (v == null) return null;
  if (v instanceof Uint8Array) return bytesToHex(v);
  if (Array.isArray(v)) return bytesToHex(Uint8Array.from(v));
  if (v && typeof v === 'object' && v.type === 'Buffer' && Array.isArray(v.data)) {
    return bytesToHex(Uint8Array.from(v.data));
  }
  if (typeof v === 'string') {
    // SQLite blob literal X'deadbeef'
    const m = v.match(/^X'([0-9a-fA-F]*)'$/);
    if (m) return m[1].toLowerCase();
    // Bare hex (even length, hex chars only).
    if (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) return v.toLowerCase();
    // Otherwise treat the string's bytes as the content.
    return bytesToHex(new TextEncoder().encode(v));
  }
  return norm(v);
}

function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

// ============ PER-TABLE DIFF ============

function indexByKey(rows, keyCol) {
  const m = new Map();
  for (const r of rows || []) {
    const k = r?.[keyCol];
    if (k == null) continue;
    m.set(String(k), r);
  }
  return m;
}

/**
 * Diff one table. `expected` is the Arweave-reconstructed rows; `actual` is the
 * live D1 rows. Returns structured drift for this table:
 *
 *   {
 *     table,
 *     onlyInArweave: [{ key, row }],   // reconstructable but MISSING from D1
 *     onlyInD1:      [{ key, row }],   // in D1 but not reconstructable from Arweave
 *     mismatches:    [{ key, fields: [{ col, expected, actual }] }],
 *     counts: { expected, actual, onlyInArweave, onlyInD1, mismatched },
 *     clean: boolean,
 *   }
 *
 * Semantics:
 *   - onlyInArweave is the drift that matters most: D1 lost a row that Arweave
 *     can still reconstruct (the recoverability invariant says it should be
 *     there). This is what the issue's acceptance ("D1 lost a row") targets.
 *   - onlyInD1 is reported too — a row D1 has but the Arweave walk did not
 *     reconstruct. Causes: recently-written blobs not yet GraphQL-indexed
 *     (benign lag), an --app scope mismatch, or genuinely orphaned D1 rows.
 *     The CLI documents the lag caveat; --check still flags it as divergence.
 *   - mismatches: a row present on both sides whose compared columns differ.
 */
export function diffTable(table, expected, actual, { ignoreCols = [] } = {}) {
  const spec = TABLE_SPEC[table];
  if (!spec) throw new Error(`diffTable: unknown table ${table}`);
  const { key, blobCols } = spec;
  const ignore = new Set(ignoreCols);
  const compareCols = spec.compareCols.filter((c) => !ignore.has(c));
  const blobSet = new Set(blobCols);

  const exp = indexByKey(expected, key);
  const act = indexByKey(actual, key);

  const onlyInArweave = [];
  const onlyInD1 = [];
  const mismatches = [];

  for (const [k, er] of exp) {
    const ar = act.get(k);
    if (!ar) {
      onlyInArweave.push({ key: k, row: er });
      continue;
    }
    const fields = [];
    for (const col of compareCols) {
      const isBlob = blobSet.has(col);
      const ev = isBlob ? normBlob(er[col]) : norm(er[col]);
      const av = isBlob ? normBlob(ar[col]) : norm(ar[col]);
      if (ev !== av) {
        fields.push({ col, expected: ev, actual: av });
      }
    }
    if (fields.length > 0) mismatches.push({ key: k, fields });
  }

  for (const [k, ar] of act) {
    if (!exp.has(k)) onlyInD1.push({ key: k, row: ar });
  }

  const counts = {
    expected: exp.size,
    actual: act.size,
    onlyInArweave: onlyInArweave.length,
    onlyInD1: onlyInD1.length,
    mismatched: mismatches.length,
  };
  const clean = onlyInArweave.length === 0 && onlyInD1.length === 0 && mismatches.length === 0;
  return { table, onlyInArweave, onlyInD1, mismatches, counts, clean };
}

/**
 * Diff every table. `expected` and `actual` are objects keyed by table name,
 * each mapping to a row array, e.g. { apps:[...], accounts:[...], ... }.
 * Tables omitted from either side default to [] (treated as empty). Tables
 * explicitly skipped by the caller (e.g. via --skip) should simply not be
 * passed; pass `tables` to restrict which tables are diffed.
 *
 * `ignoreCols` ({ [table]: string[] }) drops specific columns from a table's
 * comparison for this run — used by the CLI to suppress accounts.rules_json
 * when the app-config step was --skip'd (no reconstructed baseline for it).
 *
 * Returns:
 *   {
 *     tables: { [name]: <diffTable result> },
 *     clean: boolean,            // true iff every diffed table is clean
 *     totals: { onlyInArweave, onlyInD1, mismatched },
 *   }
 */
export function diffRebuild(expected, actual, { tables = TABLE_NAMES, ignoreCols = {} } = {}) {
  const out = { tables: {}, clean: true, totals: { onlyInArweave: 0, onlyInD1: 0, mismatched: 0 } };
  for (const t of tables) {
    const d = diffTable(t, expected?.[t] ?? [], actual?.[t] ?? [], { ignoreCols: ignoreCols[t] ?? [] });
    out.tables[t] = d;
    out.totals.onlyInArweave += d.counts.onlyInArweave;
    out.totals.onlyInD1 += d.counts.onlyInD1;
    out.totals.mismatched += d.counts.mismatched;
    if (!d.clean) out.clean = false;
  }
  return out;
}

// ============ HUMAN-READABLE REPORT ============

/**
 * Render a structured `diffRebuild` result as a human-readable drift report.
 * Returns a string (the CLI prints it). Pure — no console side effects.
 *
 * @param {ReturnType<typeof diffRebuild>} report
 * @param {{ maxRows?: number }} [opts]  cap rows listed per category
 */
export function formatDriftReport(report, { maxRows = 20 } = {}) {
  const lines = [];
  lines.push('============== DRIFT REPORT (--check) ==============');
  for (const t of Object.keys(report.tables)) {
    const d = report.tables[t];
    const c = d.counts;
    const status = d.clean ? 'OK' : 'DRIFT';
    lines.push(
      `${t}: ${status}  (arweave=${c.expected} d1=${c.actual}; `
      + `only-in-arweave=${c.onlyInArweave} only-in-d1=${c.onlyInD1} mismatched=${c.mismatched})`,
    );
    if (d.clean) continue;
    const show = (label, items, render) => {
      if (items.length === 0) return;
      lines.push(`  ${label} (${items.length}):`);
      for (const it of items.slice(0, maxRows)) lines.push(`    - ${render(it)}`);
      if (items.length > maxRows) lines.push(`    … and ${items.length - maxRows} more`);
    };
    show('only in Arweave (D1 lost these)', d.onlyInArweave, (it) => trunc(it.key));
    show('only in D1 (not reconstructable / unindexed)', d.onlyInD1, (it) => trunc(it.key));
    show('value mismatches', d.mismatches, (it) => {
      const flds = it.fields
        .map((f) => `${f.col}: arweave=${trunc(f.expected)} d1=${trunc(f.actual)}`)
        .join('; ');
      return `${trunc(it.key)} — ${flds}`;
    });
  }
  lines.push('---------------------------------------------------');
  if (report.clean) {
    lines.push('RESULT: NO DRIFT — live D1 matches the Arweave reconstruction.');
  } else {
    lines.push(
      `RESULT: DRIFT DETECTED — only-in-arweave=${report.totals.onlyInArweave}, `
      + `only-in-d1=${report.totals.onlyInD1}, mismatched=${report.totals.mismatched}.`,
    );
  }
  lines.push('===================================================');
  return lines.join('\n');
}

function trunc(v) {
  const s = v == null ? 'NULL' : String(v);
  return s.length > 48 ? s.slice(0, 48) + '…' : s;
}
