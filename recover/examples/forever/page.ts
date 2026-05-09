/**
 * Reference standalone recovery page — owned-content surface only.
 *
 * Uses {@link import('@tarn/recover').recover} to derive keys, locate
 * the user's account on Arweave, and decrypt every collection declared
 * in the supplied schema. Renders a list per collection with
 * download-as-JSON / CSV / HTML buttons.
 *
 * Scope guard (Phase 7, see `docs/STANDALONE_RECOVERY_PLAN.md` §1
 * revised 2026-05-08): this page must NOT reference
 * `reader.connections()` or `reader.shareLog()`. The forever-page
 * artifact is scoped to the durable owned-content recovery promise;
 * social capability is for live-context apps via the SDK directly.
 *
 * The string literals below are spelled in a way that lets a CI grep
 * detect any accidental future addition of those calls. See
 * `tests/forever-page.test.ts` for the enforcement.
 */

import { recover, type DecryptedEntry, type ReaderSchema } from '../../src/index.js';

// ============ Tiny DOM helpers ============

const $ = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id} not found`);
  return el as T;
};

function setStatus(message: string, kind: 'info' | 'ok' | 'err' | 'warn' = 'info'): void {
  const el = $('status');
  el.textContent = message;
  el.className = 'status' + (kind === 'info' ? '' : ' ' + kind);
}

// ============ Auth-tab toggle ============

const tabKey = $<HTMLButtonElement>('tab-key');
const tabPwd = $<HTMLButtonElement>('tab-pwd');
const panelKey = $('panel-key');
const panelPwd = $('panel-pwd');

let authMode: 'accountKey' | 'password' = 'accountKey';

function selectTab(mode: 'accountKey' | 'password'): void {
  authMode = mode;
  const isKey = mode === 'accountKey';
  tabKey.classList.toggle('active', isKey);
  tabPwd.classList.toggle('active', !isKey);
  tabKey.setAttribute('aria-selected', String(isKey));
  tabPwd.setAttribute('aria-selected', String(!isKey));
  panelKey.classList.toggle('hidden', !isKey);
  panelPwd.classList.toggle('hidden', isKey);
}

tabKey.addEventListener('click', () => selectTab('accountKey'));
tabPwd.addEventListener('click', () => selectTab('password'));

// ============ Input collection + validation ============

function collectInputs(): {
  appId: string;
  schema: ReaderSchema;
  arweaveGateways: string[];
  credentials:
    | { type: 'accountKey'; accountKey: string }
    | { type: 'password'; username: string; password: string };
} {
  const appId = $<HTMLInputElement>('appId').value.trim();
  if (!appId) throw new Error('App ID is required.');

  const schemaText = $<HTMLTextAreaElement>('schema').value.trim();
  if (!schemaText) throw new Error('Schema JSON is required.');
  let schema: unknown;
  try {
    schema = JSON.parse(schemaText);
  } catch (err) {
    throw new Error(`Schema JSON is invalid: ${(err as Error).message}`);
  }
  if (
    !schema ||
    typeof schema !== 'object' ||
    typeof (schema as { appId?: unknown }).appId !== 'string' ||
    typeof (schema as { version?: unknown }).version !== 'number' ||
    !(schema as { collections?: unknown }).collections ||
    typeof (schema as { collections?: unknown }).collections !== 'object'
  ) {
    throw new Error('Schema must be an object with appId, version, and collections.');
  }
  const typedSchema = schema as ReaderSchema;
  if (typedSchema.appId !== appId) {
    throw new Error(
      `Schema appId ('${typedSchema.appId}') does not match the App ID field ('${appId}').`,
    );
  }

  const gateways = $<HTMLTextAreaElement>('gateways')
    .value.split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (gateways.length === 0) throw new Error('At least one Arweave gateway is required.');
  for (const g of gateways) {
    try {
      const u = new URL(g);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        throw new Error('non-http(s) protocol');
      }
    } catch {
      throw new Error(`Gateway "${g}" is not a valid http(s) URL.`);
    }
  }

  if (authMode === 'accountKey') {
    const accountKey = $<HTMLTextAreaElement>('accountKey').value.trim().replace(/\s+/g, ' ');
    if (!accountKey) throw new Error('Account key is required.');
    const wordCount = accountKey.split(' ').length;
    if (wordCount !== 24) {
      throw new Error(`Account key should be 24 words; got ${wordCount}.`);
    }
    return {
      appId,
      schema: typedSchema,
      arweaveGateways: gateways,
      credentials: { type: 'accountKey', accountKey },
    };
  }
  const username = $<HTMLInputElement>('username').value.trim();
  const password = $<HTMLInputElement>('password').value;
  if (!username) throw new Error('Username is required.');
  if (!password) throw new Error('Password is required.');
  return {
    appId,
    schema: typedSchema,
    arweaveGateways: gateways,
    credentials: { type: 'password', username, password },
  };
}

// ============ Progress messages ============

const STAGE_LABELS: Record<string, string> = {
  deriving: 'Deriving keys from your credentials…',
  'locating-account': 'Locating your account on Arweave…',
  'fetching-envelope': 'Fetching your encryption envelope…',
  'walking-log': 'Walking your data history…',
  decrypting: 'Decrypting your data…',
  done: 'Done.',
};

function progressMessage(stage: string, info: Record<string, unknown>): string {
  const base = STAGE_LABELS[stage] ?? stage;
  if (stage === 'walking-log' && typeof info['collection'] === 'string') {
    if (typeof info['live'] === 'number' && typeof info['total'] === 'number') {
      return `Walking ${info['collection']} — ${info['live']} live records (of ${info['total']} blobs).`;
    }
    return `Walking ${info['collection']}…`;
  }
  if (
    stage === 'decrypting' &&
    typeof info['collection'] === 'string' &&
    typeof info['current'] === 'number' &&
    typeof info['total'] === 'number'
  ) {
    return `Decrypting ${info['collection']} ${info['current']}/${info['total']}…`;
  }
  if (stage === 'locating-account' && info['retry']) {
    return `Gateway ${String(info['failedGateway'])} unreachable; trying ${String(info['nextGateway'])}…`;
  }
  return base;
}

// ============ Result rendering + downloads ============

function downloadBlob(filename: string, mime: string, body: BlobPart): void {
  const blob = new Blob([body], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function flattenForCSV(rows: Record<string, unknown>[]): string {
  if (rows.length === 0) return '';
  const headerSet = new Set<string>();
  for (const r of rows) for (const k of Object.keys(r)) headerSet.add(k);
  const headers = [...headerSet];
  const escape = (val: unknown): string => {
    if (val == null) return '';
    let s: string;
    if (typeof val === 'object') s = JSON.stringify(val);
    else s = String(val);
    if (s.includes('"') || s.includes(',') || s.includes('\n') || s.includes('\r')) {
      s = '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  };
  const lines = [headers.map(escape).join(',')];
  for (const r of rows) {
    lines.push(headers.map((h) => escape(r[h])).join(','));
  }
  return lines.join('\n');
}

function renderHTML(appId: string, collection: string, rows: Record<string, unknown>[]): string {
  const escapeHtml = (s: string): string =>
    s
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  const tableRows = rows
    .map((r) => {
      const cells = Object.entries(r)
        .map(
          ([k, v]) =>
            `<tr><th>${escapeHtml(k)}</th><td>${escapeHtml(
              typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v ?? ''),
            )}</td></tr>`,
        )
        .join('');
      return `<table>${cells}</table>`;
    })
    .join('<hr>');
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${escapeHtml(appId)} — ${escapeHtml(collection)}</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 800px; margin: 2em auto; padding: 0 1em; }
h1 { font-size: 1.4em; }
table { border-collapse: collapse; margin: 0.5em 0; width: 100%; }
th, td { border: 1px solid #ccc; padding: 0.4em 0.6em; text-align: left; vertical-align: top; }
th { background: #f4f4f4; width: 30%; white-space: nowrap; }
hr { border: 0; border-top: 1px solid #ddd; margin: 1.2em 0; }
</style></head>
<body>
<h1>${escapeHtml(appId)} / ${escapeHtml(collection)}</h1>
<p><em>${rows.length} record${rows.length === 1 ? '' : 's'}, recovered from Arweave on ${new Date().toISOString()}.</em></p>
${tableRows}
</body></html>`;
}

function renderResults(
  appId: string,
  results: { collection: string; entries: DecryptedEntry[] }[],
): void {
  const root = $('results');
  const body = $('results-body');
  body.innerHTML = '';

  if (results.length === 0) {
    body.textContent = 'No collections in the supplied schema.';
    root.classList.remove('hidden');
    return;
  }

  for (const { collection, entries } of results) {
    const block = document.createElement('div');
    block.className = 'collection-block';

    const heading = document.createElement('h3');
    heading.textContent = `${collection} (${entries.length})`;
    block.appendChild(heading);

    const meta = document.createElement('div');
    meta.className = 'collection-meta';
    if (entries.length === 0) {
      meta.textContent = 'No live records.';
    } else {
      const versioned = entries.filter((e) => e._schemaVersion !== undefined).length;
      meta.textContent = versioned
        ? `${entries.length} records (${versioned} written under an older schema version).`
        : `${entries.length} records.`;
    }
    block.appendChild(meta);

    const actions = document.createElement('div');
    actions.className = 'collection-actions';

    const rows = entries.map((e) => e.data);

    const jsonBtn = document.createElement('button');
    jsonBtn.type = 'button';
    jsonBtn.textContent = 'Download JSON';
    jsonBtn.addEventListener('click', () => {
      downloadBlob(
        `${appId}-${collection}.json`,
        'application/json',
        JSON.stringify(rows, null, 2),
      );
    });
    actions.appendChild(jsonBtn);

    const csvBtn = document.createElement('button');
    csvBtn.type = 'button';
    csvBtn.textContent = 'Download CSV';
    csvBtn.disabled = entries.length === 0;
    csvBtn.addEventListener('click', () => {
      downloadBlob(`${appId}-${collection}.csv`, 'text/csv', flattenForCSV(rows));
    });
    actions.appendChild(csvBtn);

    const htmlBtn = document.createElement('button');
    htmlBtn.type = 'button';
    htmlBtn.textContent = 'Download printable HTML';
    htmlBtn.disabled = entries.length === 0;
    htmlBtn.addEventListener('click', () => {
      downloadBlob(
        `${appId}-${collection}.html`,
        'text/html',
        renderHTML(appId, collection, rows),
      );
    });
    actions.appendChild(htmlBtn);

    block.appendChild(actions);

    if (entries.length > 0) {
      const list = document.createElement('ul');
      list.className = 'entry-list';
      for (const entry of entries.slice(0, 200)) {
        const li = document.createElement('li');
        const summary = summarizeEntry(entry);
        li.textContent = summary;
        li.title = entry.txid;
        list.appendChild(li);
      }
      block.appendChild(list);
      if (entries.length > 200) {
        const more = document.createElement('p');
        more.className = 'hint';
        more.textContent = `(Showing first 200 of ${entries.length}. Use the download buttons to get them all.)`;
        block.appendChild(more);
      }
    }

    body.appendChild(block);
  }

  root.classList.remove('hidden');
}

function summarizeEntry(entry: DecryptedEntry): string {
  const data = entry.data;
  // Prefer common identity-ish fields when present.
  for (const k of ['title', 'name', 'label', 'subject']) {
    const v = data[k];
    if (typeof v === 'string' && v.length > 0) return truncate(v, 80);
  }
  // Else first scalar field.
  for (const v of Object.values(data)) {
    if (typeof v === 'string' && v.length > 0) return truncate(v, 80);
    if (typeof v === 'number') return String(v);
  }
  // Fallback: txid.
  return entry.txid;
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n - 1) + '…';
}

// ============ Recover-button handler ============

const recoverBtn = $<HTMLButtonElement>('recover');

recoverBtn.addEventListener('click', async () => {
  const results = $('results');
  results.classList.add('hidden');

  let inputs: ReturnType<typeof collectInputs>;
  try {
    inputs = collectInputs();
  } catch (err) {
    setStatus((err as Error).message, 'err');
    return;
  }

  recoverBtn.disabled = true;
  setStatus('Starting recovery…');

  try {
    const reader = await recover({
      appId: inputs.appId,
      schema: inputs.schema,
      arweaveGateways: inputs.arweaveGateways,
      credentials: inputs.credentials,
      onProgress: (stage, info) => {
        setStatus(progressMessage(stage, info));
      },
    });

    setStatus(`Account located. ${reader.collections.length} collection(s) in your schema. Decrypting…`);

    const out: { collection: string; entries: DecryptedEntry[] }[] = [];
    for (const name of reader.collections) {
      setStatus(`Decrypting collection: ${name}…`);
      const entries = await reader.allEntries(name);
      out.push({ collection: name, entries });
    }

    const total = out.reduce((sum, c) => sum + c.entries.length, 0);
    setStatus(`Recovered ${total} record(s) across ${out.length} collection(s).`, 'ok');
    renderResults(inputs.appId, out);
  } catch (err) {
    const msg = (err as Error).message ?? String(err);
    let friendly = msg;
    if (/no credential blob/i.test(msg)) {
      friendly =
        'Could not find your account on Arweave with the supplied credentials. ' +
        'Check the App ID, your credentials, and try a different gateway if one is down.';
    } else if (/dek|unwrap|decrypt/i.test(msg)) {
      friendly =
        'Decryption failed. The credentials don\'t match this account, or the data ' +
        'was written under a key the supplied credentials cannot derive. ' +
        `(Underlying: ${msg})`;
    } else if (/gateway/i.test(msg)) {
      friendly =
        'All configured Arweave gateways failed. Add another gateway and try again. ' +
        `(Underlying: ${msg})`;
    }
    setStatus(friendly, 'err');
  } finally {
    recoverBtn.disabled = false;
  }
});
