#!/usr/bin/env node
/**
 * tools/rebuild-from-arweave.mjs
 *
 * Phase C of the Arweave-recoverability fix
 * (`docs/ARWEAVE_RECOVERABILITY_FIX_PLAN.md`).
 *
 * Walks Arweave via GraphQL and reconstructs every recoverable D1 table
 * for tarn-api. Dry-run by default — pass `--confirm` to actually write.
 * Idempotent: re-running with the same flags re-applies INSERT...ON
 * CONFLICT DO UPDATE so partial state from a previous run is healed.
 *
 * Dependency order (each step depends on the prior step's output):
 *   1. apps                 — App=tarn, Type=app-reg, Lk=<app_id>
 *   2. accounts             — App=tarn, Type=cred,    Lk=<credential_lookup_key>
 *   3. passkey_credentials  — App=tarn, Type=passkey-reg, Lk=<dlk>, CredId=<id>
 *   4. accounts.rules_json  — App=<app_id>, Type=app-config, Lk=<dlk>
 *                              (app_id from step 1)
 *   5. share_inbox          — App=tarn-share, Type=connection-{request,accept}-v1
 *   6. share_log            — App=tarn-share, Type=share-log-v1
 *   7. entries (optional)   — only with --prefetch-content; otherwise lazy
 *                              cold-bootstrap on first read populates the
 *                              cache via api/src/cache.js refreshCache.
 *
 * Usage
 * =====
 *
 *   node tools/rebuild-from-arweave.mjs \
 *     --d1-binding tarn-api \
 *     --arweave-gateway https://arweave.net \
 *     --confirm                       # without --confirm: dry-run
 *
 * Optional flags:
 *   --app=<app_id>              Restrict steps 4-6 to a single app
 *                               (steps 1-3 always rebuild globally; the
 *                               accounts table is keyed by dlk and would
 *                               half-rebuild otherwise).
 *   --gateways="https://a,https://b"   Comma-separated body-fetch fallback
 *                               list. Defaults to Turbo + arweave.net.
 *   --skip=apps,accounts,passkeys,...  Comma-separated step names to skip.
 *   --prefetch-content          Walk every (app, type, dlk) tuple discovered
 *                               in step 2 to pre-populate `entries`. Slow.
 *                               Off by default — refreshCache will lazily
 *                               bootstrap on first read.
 *   --remote                    Run wrangler d1 against --remote D1.
 *                               Default --local.
 *   --max-pages=N               Cap GraphQL pagination per query (safety
 *                               valve). Defaults to 200 (20k blobs per
 *                               query at 100/page).
 *   --quiet                     Suppress per-row chatter.
 *
 * Output
 * ======
 * Per phase: "Phase X: ... start", per page during pagination, end-of-phase
 * count. On exit (success or failure), prints a summary table:
 *
 *   apps:                1 rebuilt (1 found, 0 skipped)
 *   accounts:           12 rebuilt (12 found, 0 tombstoned)
 *   passkey_credentials: 3 rebuilt (4 found, 1 tombstoned)
 *   app-config rules:    8 applied
 *   share_inbox:        42 rebuilt
 *   share_log:         103 rebuilt
 *   total time:         12.4s
 *
 * Failure handling
 * ================
 * Each step is wrapped in try/catch. On failure: print the error, the
 * partial summary, and exit non-zero. Re-running with the same flags is
 * safe (INSERT ... ON CONFLICT DO UPDATE). Steps already completed in a
 * prior run will redundantly UPDATE rows to the same values — harmless.
 *
 * No new dependencies. Uses node:fetch, node:child_process (for wrangler),
 * node:fs (for batched SQL files), and the project's internal
 * tools/lib/rebuild-core.mjs reducers.
 */

import { spawnSync } from 'node:child_process';
import { writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import {
  rebuildApps,
  rebuildAccounts,
  rebuildPasskeys,
  rebuildAppConfigRules,
  rebuildShareInbox,
  rebuildShareLog,
} from './lib/rebuild-core.mjs';

// ============ ARG PARSING ============

const argv = process.argv.slice(2);
const opts = {
  d1Binding: 'tarn-api',
  arweaveGateway: 'https://arweave.net',
  gateways: ['https://turbo-gateway.com', 'https://arweave.net'],
  app: null,
  skip: new Set(),
  prefetchContent: false,
  remote: false,
  confirm: false,
  maxPages: 200,
  quiet: false,
  help: false,
};

for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--help' || a === '-h') opts.help = true;
  else if (a === '--confirm') opts.confirm = true;
  else if (a === '--remote') opts.remote = true;
  else if (a === '--quiet') opts.quiet = true;
  else if (a === '--prefetch-content') opts.prefetchContent = true;
  else if (a === '--d1-binding') opts.d1Binding = argv[++i];
  else if (a.startsWith('--d1-binding=')) opts.d1Binding = a.slice('--d1-binding='.length);
  else if (a === '--arweave-gateway') opts.arweaveGateway = argv[++i];
  else if (a.startsWith('--arweave-gateway=')) opts.arweaveGateway = a.slice('--arweave-gateway='.length);
  else if (a === '--gateways') opts.gateways = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
  else if (a.startsWith('--gateways=')) opts.gateways = a.slice('--gateways='.length).split(',').map((s) => s.trim()).filter(Boolean);
  else if (a === '--app') opts.app = argv[++i];
  else if (a.startsWith('--app=')) opts.app = a.slice('--app='.length);
  else if (a === '--skip') opts.skip = new Set(argv[++i].split(',').map((s) => s.trim()).filter(Boolean));
  else if (a.startsWith('--skip=')) opts.skip = new Set(a.slice('--skip='.length).split(',').map((s) => s.trim()).filter(Boolean));
  else if (a === '--max-pages') opts.maxPages = Number(argv[++i]);
  else if (a.startsWith('--max-pages=')) opts.maxPages = Number(a.slice('--max-pages='.length));
  else { console.error(`Unknown flag: ${a}`); process.exit(1); }
}

if (opts.help) {
  printHelp();
  process.exit(0);
}

function printHelp() {
  // Trimmed help output; full operator docs live in the module header.
  console.log(`
Phase C — rebuild-from-arweave.mjs

Walks Arweave via GraphQL and reconstructs Tarn's D1 cache from on-chain
blobs. Dry-run by default; pass --confirm to actually write.

Usage:
  node tools/rebuild-from-arweave.mjs [options]

Common flags:
  --confirm                Write to D1 (default: dry-run, parse + count only)
  --remote                 Run wrangler against --remote D1 (default: --local)
  --arweave-gateway URL    GraphQL endpoint (default: https://arweave.net)
  --gateways "A,B,C"       Body-fetch fallback list (default: Turbo, arweave.net)
  --app=ID                 Restrict steps 4-6 to a single app
  --skip=apps,accounts,... Comma-separated step names to skip
  --prefetch-content       Pre-walk per-(app,type,dlk) for entries cache. Off by default.
  --max-pages=N            Pagination cap (default: 200)
  --quiet                  Suppress per-blob chatter
  --help                   This message

What it rebuilds:
  apps, accounts, passkey_credentials, accounts.rules_json,
  share_inbox, share_log, [entries with --prefetch-content].

What it does NOT rebuild (acceptable losses per audit):
  cache_meta bootstrap markers, sessions, step_up_tokens,
  webauthn_challenges, pending_txs, idempotency_keys,
  write_rate_limits, account_key_fetch_log, RATE_KV.
`);
}

// ============ LOG HELPERS ============

const t0 = Date.now();
function log(...args) { if (!opts.quiet) console.log(...args); }
function info(...args) { console.log(...args); }
function warn(...args) { console.warn(...args); }
function elapsed() { return ((Date.now() - t0) / 1000).toFixed(1) + 's'; }

// ============ ARWEAVE GRAPHQL ============

const GRAPHQL_TIMEOUT_MS = 15_000;
const PAGE_SIZE = 100;

async function gqlOnce(query, variables) {
  const url = opts.arweaveGateway.replace(/\/+$/, '') + '/graphql';
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, variables }),
    signal: AbortSignal.timeout(GRAPHQL_TIMEOUT_MS),
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    throw new Error(`GraphQL HTTP ${res.status}: ${txt.slice(0, 200)}`);
  }
  const json = await res.json();
  if (json.errors?.length) {
    throw new Error(`GraphQL error: ${json.errors[0].message}`);
  }
  return json.data;
}

/**
 * Page through `transactions(...)` collecting all edges. Stops on hasNextPage=false
 * or after MAX_PAGES (safety valve).
 */
async function gqlPage(tagFilters, label) {
  const q = `query($after:String,$first:Int,$tags:[TagFilter!]){
    transactions(after:$after,first:$first,sort:HEIGHT_ASC,tags:$tags){
      pageInfo{hasNextPage}
      edges{cursor node{id tags{name value}block{timestamp height}}}
    }
  }`;
  const all = [];
  let after = null;
  for (let page = 0; page < opts.maxPages; page++) {
    const data = await gqlOnce(q, { after, first: PAGE_SIZE, tags: tagFilters });
    const txns = data?.transactions;
    const edges = txns?.edges || [];
    all.push(...edges);
    log(`  ${label}: page ${page + 1}, ${edges.length} edges (total ${all.length})`);
    if (edges.length === 0) break;
    if (!txns.pageInfo?.hasNextPage) break;
    after = edges[edges.length - 1].cursor;
  }
  return all;
}

// ============ GATEWAY BODY FETCH (multi-gateway fallback) ============

const GATEWAY_TIMEOUT_MS = 15_000;
const FETCH_CONCURRENCY = 8;

/**
 * Fetch a single blob with multi-gateway fallback. Returns Uint8Array on
 * success, null if every gateway fails. Failure modes: 404, 5xx, network
 * error, timeout, and "TX not found" (some gateways return 200 with a
 * "Pending" body — treated as failure here; we re-try the next gateway).
 */
async function fetchBlob(txid) {
  for (const gw of opts.gateways) {
    try {
      const res = await fetch(gw.replace(/\/+$/, '') + '/' + txid, {
        signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
      });
      if (!res.ok) continue;
      // Some gateways return 200 with a "Pending" placeholder for unconfirmed
      // tx — best-effort sniff.
      const ct = res.headers.get('content-type') || '';
      const buf = new Uint8Array(await res.arrayBuffer());
      if (ct.startsWith('text/') && buf.length < 32) {
        const txt = new TextDecoder().decode(buf);
        if (/pending/i.test(txt)) continue;
      }
      return buf;
    } catch {
      // try next gateway
    }
  }
  return null;
}

/**
 * Fetch bodies for a list of edges, with a small concurrency limit to be
 * polite to the gateway. Returns Map<txid, Uint8Array|null>.
 */
async function fetchBodies(edges, label) {
  const bodies = new Map();
  let i = 0;
  let done = 0;
  async function worker() {
    while (true) {
      const idx = i++;
      if (idx >= edges.length) return;
      const txid = edges[idx]?.node?.id;
      if (!txid) continue;
      const body = await fetchBlob(txid);
      bodies.set(txid, body);
      done += 1;
      if (done % 50 === 0) log(`  ${label}: fetched ${done}/${edges.length} bodies`);
    }
  }
  await Promise.all(Array.from({ length: Math.min(FETCH_CONCURRENCY, edges.length) }, worker));
  return bodies;
}

// ============ D1 ACCESS (via wrangler) ============

const API_CWD = new URL('../api', import.meta.url).pathname.replace(/^\/(\w:)/, '$1');
const TMP_DIR = new URL('../.tmp-rebuild/', import.meta.url).pathname.replace(/^\/(\w:)/, '$1');
try { mkdirSync(TMP_DIR, { recursive: true }); } catch {}

const target = opts.remote ? '--remote' : '--local';

function d1Query(sql) {
  if (!opts.confirm) {
    // Dry-run: still allow read queries so we can compute "would-be" stats.
    // The tool only writes via d1Exec; SELECTs are fine to run.
  }
  const quoted = `"${sql.replace(/"/g, '\\"')}"`;
  const cmd = `npx wrangler d1 execute ${opts.d1Binding} ${target} --json --command ${quoted}`;
  const result = spawnSync(cmd, { cwd: API_CWD, encoding: 'utf8', shell: true });
  if (result.status !== 0) {
    throw new Error(`wrangler d1 SELECT failed (exit ${result.status}): ${result.stderr || result.stdout}`);
  }
  const out = result.stdout;
  const start = out.search(/[[{]/);
  if (start < 0) return { results: [] };
  const parsed = JSON.parse(out.slice(start));
  return Array.isArray(parsed) ? parsed[0] : parsed;
}

function d1ExecFile(sql) {
  if (!opts.confirm) {
    return { skipped: true };
  }
  // Strip explicit transaction control. Recent wrangler (4.x) runs `d1 execute
  // --file` against the local Durable-Object-backed D1, which REJECTS raw
  // `BEGIN`/`COMMIT`/`SAVEPOINT` statements ("use state.storage.transaction()
  // instead"). The batch builders below emit `BEGIN; ... COMMIT;` for advisory
  // atomicity, but every statement is idempotent (`INSERT ... ON CONFLICT DO
  // UPDATE` / `DO NOTHING`), so applying them without an explicit transaction
  // is safe — a partial batch is healed on the next re-run (the tool's
  // documented idempotency guarantee). We drop the wrappers here so the fix is
  // in one place rather than across six builders.
  const cleaned = sql
    .split('\n')
    .filter((line) => !/^\s*(BEGIN|COMMIT)\s*;\s*$/i.test(line))
    .join('\n');
  const tmp = `${TMP_DIR}rebuild-${Date.now()}-${Math.random().toString(36).slice(2)}.sql`;
  writeFileSync(tmp, cleaned);
  const result = spawnSync(
    'npx',
    ['wrangler', 'd1', 'execute', opts.d1Binding, target, '--file', tmp],
    { cwd: API_CWD, encoding: 'utf8', shell: true },
  );
  try { unlinkSync(tmp); } catch {}
  if (result.status !== 0) {
    throw new Error(`wrangler d1 exec failed (exit ${result.status}): ${result.stderr || result.stdout}`);
  }
  return { ok: true };
}

// ============ SQL HELPERS (idempotent) ============

function sqlString(s) {
  if (s == null) return 'NULL';
  return `'${String(s).replace(/'/g, "''")}'`;
}

function sqlNumber(n) {
  if (n == null || !Number.isFinite(n)) return 'NULL';
  return String(n);
}

function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

function sqlBlob(bytes) {
  if (bytes == null) return 'NULL';
  return `X'${bytesToHex(bytes)}'`;
}

// ============ STEP 1 — apps ============

async function rebuildAppsStep(summary) {
  if (opts.skip.has('apps')) { info('Phase apps: SKIPPED'); return null; }
  info(`\nPhase apps: discovering Type=app-reg blobs (${elapsed()})`);
  const tags = [
    { name: 'App', values: ['tarn'] },
    { name: 'Type', values: ['app-reg'] },
  ];
  if (opts.app) tags.push({ name: 'Lk', values: [opts.app] });
  const edges = await gqlPage(tags, 'apps');
  info(`Phase apps: ${edges.length} app-reg edges`);
  const bodies = await fetchBodies(edges, 'apps');
  const { rows, stats } = rebuildApps(edges, bodies);
  summary.apps = { ...stats };
  if (rows.length > 0) {
    let sql = 'BEGIN;\n';
    for (const r of rows) {
      sql += `INSERT INTO apps (app_id, public_key, created_at, invite_url_template) VALUES (${sqlString(r.app_id)}, ${sqlString(r.public_key)}, ${sqlNumber(r.created_at)}, ${sqlString(r.invite_url_template)})
        ON CONFLICT(app_id) DO UPDATE SET
          public_key = excluded.public_key,
          created_at = MIN(apps.created_at, excluded.created_at),
          invite_url_template = excluded.invite_url_template;\n`;
    }
    sql += 'COMMIT;\n';
    d1ExecFile(sql);
  }
  info(`Phase apps: ${rows.length} ${opts.confirm ? 'rebuilt' : '(dry-run, would rebuild)'}`);
  return rows;
}

// ============ STEP 2 — accounts ============

async function rebuildAccountsStep(summary) {
  if (opts.skip.has('accounts')) { info('Phase accounts: SKIPPED'); return null; }
  info(`\nPhase accounts: discovering Type=cred blobs (${elapsed()})`);
  const tags = [
    { name: 'App', values: ['tarn'] },
    { name: 'Type', values: ['cred'] },
  ];
  // No Lk filter — rebuild walks every credential ever published.
  const edges = await gqlPage(tags, 'accounts');
  info(`Phase accounts: ${edges.length} cred edges`);
  const bodies = await fetchBodies(edges, 'accounts');
  const { rows, stats } = rebuildAccounts(edges, bodies);
  summary.accounts = { ...stats };
  if (rows.length > 0) {
    let sql = 'BEGIN;\n';
    for (const r of rows) {
      sql += `INSERT INTO accounts (
        credential_lookup_key, public_key, data_lookup_key, wrapped_data_key, app, rules_json, created_at,
        recovery_lookup_key, recovery_public_key,
        share_pub, share_discoverable, share_lookup_key,
        wrapped_account_key
      ) VALUES (
        ${sqlString(r.credential_lookup_key)}, ${sqlString(r.public_key)}, ${sqlString(r.data_lookup_key)}, ${sqlString(r.wrapped_data_key)}, ${sqlString(r.app)}, ${sqlString(r.rules_json)}, ${sqlNumber(r.created_at)},
        ${sqlString(r.recovery_lookup_key)}, ${sqlString(r.recovery_public_key)},
        ${sqlString(r.share_pub)}, ${sqlNumber(r.share_discoverable)}, ${sqlString(r.share_lookup_key)},
        ${sqlString(r.wrapped_account_key)}
      ) ON CONFLICT(credential_lookup_key) DO UPDATE SET
        public_key = excluded.public_key,
        data_lookup_key = excluded.data_lookup_key,
        wrapped_data_key = excluded.wrapped_data_key,
        app = excluded.app,
        recovery_lookup_key = excluded.recovery_lookup_key,
        recovery_public_key = excluded.recovery_public_key,
        share_pub = excluded.share_pub,
        share_discoverable = excluded.share_discoverable,
        share_lookup_key = excluded.share_lookup_key,
        wrapped_account_key = excluded.wrapped_account_key;\n`;
    }
    sql += 'COMMIT;\n';
    d1ExecFile(sql);
  }
  info(`Phase accounts: ${rows.length} ${opts.confirm ? 'rebuilt' : '(dry-run, would rebuild)'}`);
  return rows;
}

// ============ STEP 3 — passkey_credentials ============

async function rebuildPasskeysStep(summary) {
  if (opts.skip.has('passkeys') || opts.skip.has('passkey_credentials')) {
    info('Phase passkey_credentials: SKIPPED'); return null;
  }
  info(`\nPhase passkey_credentials: discovering Type=passkey-reg blobs (${elapsed()})`);
  const tags = [
    { name: 'App', values: ['tarn'] },
    { name: 'Type', values: ['passkey-reg'] },
  ];
  const edges = await gqlPage(tags, 'passkeys');
  info(`Phase passkey_credentials: ${edges.length} passkey-reg edges`);
  const bodies = await fetchBodies(edges, 'passkeys');
  const { rows, stats } = rebuildPasskeys(edges, bodies);
  summary.passkeys = { ...stats };
  if (rows.length > 0) {
    let sql = 'BEGIN;\n';
    for (const r of rows) {
      sql += `INSERT INTO passkey_credentials (account_id, credential_id, public_key, prf_salt, sign_count, device_label, created_at, last_used_at)
        VALUES (${sqlString(r.account_id)}, ${sqlString(r.credential_id)}, ${sqlString(r.public_key)}, ${sqlString(r.prf_salt)}, ${sqlNumber(r.sign_count)}, ${sqlString(r.device_label)}, ${sqlNumber(r.created_at)}, NULL)
        ON CONFLICT(credential_id) DO UPDATE SET
          account_id = excluded.account_id,
          public_key = excluded.public_key,
          prf_salt = excluded.prf_salt,
          device_label = excluded.device_label,
          created_at = excluded.created_at;\n`;
    }
    sql += 'COMMIT;\n';
    d1ExecFile(sql);
  }
  info(`Phase passkey_credentials: ${rows.length} ${opts.confirm ? 'rebuilt' : '(dry-run, would rebuild)'}`);
  return rows;
}

// ============ STEP 4 — accounts.rules_json ============

async function rebuildAppConfigStep(summary, knownAppIds) {
  if (opts.skip.has('app-config') || opts.skip.has('rules')) {
    info('Phase app-config rules: SKIPPED'); return;
  }
  info(`\nPhase app-config rules: discovering Type=app-config blobs (${elapsed()})`);
  const apps = opts.app ? [opts.app] : (knownAppIds || []);
  if (apps.length === 0) {
    info('Phase app-config rules: no apps in scope; skipping');
    summary.appConfig = { found: 0, applied: 0, bodyMisses: 0, parseErrors: 0 };
    return;
  }
  const allEdges = [];
  for (const app of apps) {
    const tags = [
      { name: 'App', values: [app] },
      { name: 'Type', values: ['app-config'] },
    ];
    const edges = await gqlPage(tags, `app-config[${app}]`);
    allEdges.push(...edges);
  }
  info(`Phase app-config rules: ${allEdges.length} app-config edges across ${apps.length} apps`);
  const bodies = await fetchBodies(allEdges, 'app-config');
  const { updates, stats } = rebuildAppConfigRules(allEdges, bodies);
  summary.appConfig = { ...stats };
  if (updates.size > 0) {
    let sql = 'BEGIN;\n';
    for (const [dlk, rulesJson] of updates) {
      // Only update if a row exists; rebuilds-without-account silently no-op.
      sql += `UPDATE accounts SET rules_json = ${sqlString(rulesJson)} WHERE data_lookup_key = ${sqlString(dlk)};\n`;
    }
    sql += 'COMMIT;\n';
    d1ExecFile(sql);
  }
  info(`Phase app-config rules: ${stats.applied} ${opts.confirm ? 'applied' : '(dry-run, would apply)'}`);
}

// ============ STEP 5 — share_inbox ============

async function rebuildShareInboxStep(summary) {
  if (opts.skip.has('share_inbox') || opts.skip.has('share-inbox')) {
    info('Phase share_inbox: SKIPPED'); return;
  }
  info(`\nPhase share_inbox: discovering App=tarn-share connection blobs (${elapsed()})`);
  const allEdges = [];
  for (const t of ['connection-request-v1', 'connection-accept-v1']) {
    const tags = [
      { name: 'App', values: ['tarn-share'] },
      { name: 'Type', values: [t] },
    ];
    if (opts.app) tags.push({ name: 'AppScope', values: [opts.app] });
    const edges = await gqlPage(tags, `share_inbox[${t}]`);
    allEdges.push(...edges);
  }
  info(`Phase share_inbox: ${allEdges.length} edges`);
  const bodies = await fetchBodies(allEdges, 'share_inbox');
  const { rows, stats } = rebuildShareInbox(allEdges, bodies);
  summary.shareInbox = { ...stats };
  if (rows.length > 0) {
    // Batch — these can be large, so chunk into reasonable SQL files.
    const CHUNK = 50;
    for (let i = 0; i < rows.length; i += CHUNK) {
      let sql = 'BEGIN;\n';
      for (const r of rows.slice(i, i + CHUNK)) {
        sql += `INSERT INTO share_inbox (txid, app_id, inbox_tag, blob_type, ciphertext, published_at)
          VALUES (${sqlString(r.txid)}, ${sqlString(r.app_id)}, ${sqlString(r.inbox_tag)}, ${sqlString(r.blob_type)}, ${sqlBlob(r.ciphertext)}, ${sqlNumber(r.published_at)})
          ON CONFLICT(txid) DO NOTHING;\n`;
      }
      sql += 'COMMIT;\n';
      d1ExecFile(sql);
    }
  }
  info(`Phase share_inbox: ${rows.length} ${opts.confirm ? 'rebuilt' : '(dry-run, would rebuild)'}`);
}

// ============ STEP 6 — share_log ============

async function rebuildShareLogStep(summary) {
  if (opts.skip.has('share_log') || opts.skip.has('share-log')) {
    info('Phase share_log: SKIPPED'); return;
  }
  info(`\nPhase share_log: discovering Type=share-log-v1 blobs (${elapsed()})`);
  const tags = [
    { name: 'App', values: ['tarn-share'] },
    { name: 'Type', values: ['share-log-v1'] },
  ];
  if (opts.app) tags.push({ name: 'AppScope', values: [opts.app] });
  const edges = await gqlPage(tags, 'share_log');
  info(`Phase share_log: ${edges.length} edges`);
  const bodies = await fetchBodies(edges, 'share_log');
  const { rows, stats } = rebuildShareLog(edges, bodies);
  summary.shareLog = { ...stats };
  if (rows.length > 0) {
    const CHUNK = 50;
    for (let i = 0; i < rows.length; i += CHUNK) {
      let sql = 'BEGIN;\n';
      for (const r of rows.slice(i, i + CHUNK)) {
        // share_log has UNIQUE (app_id, log_tag, blob_type) — the rebuild
        // dedups in-memory, but ON CONFLICT keeps idempotency safe across
        // re-runs.
        sql += `INSERT INTO share_log (txid, app_id, log_tag, blob_type, ciphertext, data_lookup_key, published_at)
          VALUES (${sqlString(r.txid)}, ${sqlString(r.app_id)}, ${sqlString(r.log_tag)}, ${sqlString(r.blob_type)}, ${sqlBlob(r.ciphertext)}, ${sqlString(r.data_lookup_key)}, ${sqlNumber(r.published_at)})
          ON CONFLICT(txid) DO NOTHING;\n`;
      }
      sql += 'COMMIT;\n';
      d1ExecFile(sql);
    }
  }
  info(`Phase share_log: ${rows.length} ${opts.confirm ? 'rebuilt' : '(dry-run, would rebuild)'}`);
}

// ============ MAIN ============

async function main() {
  info(`tarn rebuild-from-arweave — ${opts.confirm ? 'CONFIRM (writing)' : 'DRY-RUN'}`);
  info(`  D1 binding: ${opts.d1Binding} ${target}`);
  info(`  Arweave gateway: ${opts.arweaveGateway}`);
  info(`  Body gateways: ${opts.gateways.join(', ')}`);
  if (opts.app) info(`  Scoped to app: ${opts.app}`);
  if (opts.skip.size > 0) info(`  Skipping: ${[...opts.skip].join(', ')}`);
  if (!opts.confirm) info(`  (No D1 writes will occur; pass --confirm to apply.)`);

  const summary = {
    apps: null, accounts: null, passkeys: null, appConfig: null, shareInbox: null, shareLog: null,
  };
  let exitCode = 0;
  try {
    const apps = await rebuildAppsStep(summary);
    await rebuildAccountsStep(summary);
    await rebuildPasskeysStep(summary);
    const knownAppIds = apps?.map((r) => r.app_id) ?? [];
    await rebuildAppConfigStep(summary, knownAppIds);
    await rebuildShareInboxStep(summary);
    await rebuildShareLogStep(summary);
    if (opts.prefetchContent) {
      info('\nPhase entries (prefetch): NOT IMPLEMENTED in v1. Use refreshCache lazily.');
    }
  } catch (err) {
    exitCode = 1;
    warn(`\nFATAL: ${err.message}`);
    if (err.stack) warn(err.stack);
  }

  // Always print summary, even on partial failure.
  info('\n============== SUMMARY ==============');
  if (summary.apps) {
    info(`apps:                ${summary.apps.rebuilt} rebuilt (${summary.apps.found} found, ${summary.apps.bodyMisses + summary.apps.parseErrors} skipped)`);
  } else { info('apps:                SKIPPED'); }
  if (summary.accounts) {
    info(`accounts:           ${summary.accounts.rebuilt} rebuilt (${summary.accounts.found} found, ${summary.accounts.tombstoned} tombstoned, ${summary.accounts.bodyMisses + summary.accounts.parseErrors} skipped)`);
  } else { info('accounts:           SKIPPED'); }
  if (summary.passkeys) {
    info(`passkey_credentials: ${summary.passkeys.rebuilt} rebuilt (${summary.passkeys.found} found, ${summary.passkeys.tombstoned} tombstoned, ${summary.passkeys.bodyMisses + summary.passkeys.parseErrors} skipped)`);
  } else { info('passkey_credentials: SKIPPED'); }
  if (summary.appConfig) {
    info(`app-config rules:    ${summary.appConfig.applied} applied (${summary.appConfig.found} found)`);
  } else { info('app-config rules:    SKIPPED'); }
  if (summary.shareInbox) {
    info(`share_inbox:        ${summary.shareInbox.rebuilt} rebuilt (${summary.shareInbox.found} found, ${summary.shareInbox.bodyMisses} body-miss)`);
  } else { info('share_inbox:        SKIPPED'); }
  if (summary.shareLog) {
    info(`share_log:         ${summary.shareLog.rebuilt} rebuilt (${summary.shareLog.found} found, ${summary.shareLog.bodyMisses} body-miss)`);
  } else { info('share_log:         SKIPPED'); }
  info(`total time:         ${elapsed()}`);
  info(opts.confirm ? '(D1 writes were applied.)' : '(DRY-RUN: no D1 writes applied. Re-run with --confirm to apply.)');

  process.exit(exitCode);
}

main().catch((err) => {
  console.error('Unhandled:', err);
  process.exit(2);
});
