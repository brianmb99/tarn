/**
 * forever-bootstrap — the one permanent URL an app's users bookmark.
 *
 * Arweave is immutable, so every published recovery page has a different
 * txid and a bookmarked page can never be updated. This page is the fix:
 * a tiny, logic-frozen artifact whose only job is to find the LATEST
 * published forever-page for one app and forward the user to it. Its own
 * txid never needs to change, because nothing here ever needs to change —
 * publishing a new recovery page updates what this page *finds*, not what
 * this page *is*.
 *
 * Trust model (read this before editing anything):
 *
 *   - Discovery is owner-pinned. Arweave tags are a free-for-all — anyone
 *     can publish a blob tagged `App=tarn-recover,Type=forever-page-pointer`.
 *     Every query this page issues filters on `owners: [OWNER_ADDRESS]`,
 *     the operator's normalized wallet address baked in at build time.
 *     "Latest" therefore means "latest SIGNED BY THE OPERATOR KEY", not
 *     "latest anyone published". Removing the owners filter converts this
 *     page into a credential-phishing vector. Do not remove it.
 *   - The destination page is verified before forwarding: the txid a
 *     pointer names must itself exist as an owner-signed
 *     `Type=forever-page` blob with the matching App-Id. A pointer whose
 *     target fails verification is skipped.
 *   - No auto-redirect. The user sees which version they are being
 *     forwarded to (and the pinned URL, which they can bookmark instead)
 *     and clicks through. Silently executing whatever a mutable pointer
 *     names is exactly the behavior this page is careful not to have.
 *   - This page never takes credentials. It has no input fields and must
 *     never grow any — credentials belong on the (verified, immutable)
 *     destination page. Guarded by tests/bootstrap-page.test.ts.
 *   - No SDK, no dependencies, no eval. Plain fetch + GraphQL + DOM, so
 *     the artifact stays small and auditable, and never needs republishing
 *     for an SDK release.
 *
 * If every gateway query fails, the page degrades into a static link to
 * FALLBACK_TXID — the newest known page at the time this bootstrap was
 * built. Raw txid fetch is the weakest possible gateway dependency; any
 * future gateway can serve it.
 *
 * Configuration is injected at build time (scripts/build-bootstrap.mjs)
 * as a JSON <script> block with id "bootstrap-config":
 *
 *   { appId, appName, ownerAddress, gateways, fallbackTxid }
 *
 * The pure helpers below are exported for unit tests; browsers simply
 * never import them (the auto-run at the bottom drives the page).
 */

// ============ Pure helpers ============

const TXID_RE = /^[A-Za-z0-9_-]{43}$/;
const APP_ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

/** Arweave txids and normalized owner addresses share one shape: 43 chars of base64url. */
export function isValidTxid(s) {
  return typeof s === 'string' && TXID_RE.test(s);
}

/**
 * Parse + validate the build-time config block. Throws on anything
 * malformed — a bootstrap with a broken pin must fail loudly, not fall
 * through to an unpinned query.
 */
export function readConfig(doc) {
  const el = doc.getElementById('bootstrap-config');
  if (!el) throw new Error('bootstrap-config block missing');
  const cfg = JSON.parse(el.textContent);
  if (!APP_ID_RE.test(cfg.appId || '')) throw new Error('config: bad appId');
  if (typeof cfg.appName !== 'string' || !cfg.appName.trim()) throw new Error('config: bad appName');
  if (!isValidTxid(cfg.ownerAddress)) throw new Error('config: bad ownerAddress');
  if (!isValidTxid(cfg.fallbackTxid)) throw new Error('config: bad fallbackTxid');
  if (!Array.isArray(cfg.gateways) || cfg.gateways.length === 0
    || !cfg.gateways.every((g) => typeof g === 'string' && /^https:\/\/[^\s/]+$/.test(g))) {
    throw new Error('config: gateways must be a non-empty list of https origins');
  }
  return cfg;
}

/**
 * GraphQL query for the app's pointer chain, newest first. The owners
 * filter is the security boundary — see the file header.
 */
export function buildPointerQuery({ appId, ownerAddress, limit = 20 }) {
  return `{
  transactions(
    owners: [${JSON.stringify(ownerAddress)}]
    tags: [
      { name: "App", values: ["tarn-recover"] }
      { name: "Type", values: ["forever-page-pointer"] }
      { name: "App-Id", values: [${JSON.stringify(appId)}] }
    ]
    first: ${Number(limit)}
    sort: HEIGHT_DESC
  ) { edges { node { id tags { name value } block { height timestamp } } } }
}`;
}

/**
 * GraphQL query verifying that a pointer's target really is an
 * owner-signed forever-page for this app. The pointer is operator-signed
 * so this is defense-in-depth, but it is one cheap query and it means a
 * corrupt or mis-published pointer gets skipped instead of followed.
 */
export function buildPageVerifyQuery({ pageTxid, appId, ownerAddress }) {
  return `{
  transactions(
    ids: [${JSON.stringify(pageTxid)}]
    owners: [${JSON.stringify(ownerAddress)}]
    tags: [
      { name: "App", values: ["tarn-recover"] }
      { name: "Type", values: ["forever-page"] }
      { name: "App-Id", values: [${JSON.stringify(appId)}] }
    ]
    first: 1
  ) { edges { node { id tags { name value } } } }
}`;
}

export function tagValue(tags, name) {
  if (!Array.isArray(tags)) return null;
  const hit = tags.find((t) => t && t.name === name);
  return hit ? String(hit.value) : null;
}

/** Normalize a GraphQL pointer response into plain records. */
export function parsePointerEdges(json) {
  const edges = json && json.data && json.data.transactions && json.data.transactions.edges;
  if (!Array.isArray(edges)) throw new Error('malformed GraphQL response');
  return edges
    .map((e) => e && e.node)
    .filter((n) => n && isValidTxid(n.id))
    .map((n) => ({
      pointerTxid: n.id,
      version: tagValue(n.tags, 'Version') || 'unknown',
      confirmed: !!(n.block && typeof n.block.height === 'number'),
      timestamp: n.block && typeof n.block.timestamp === 'number' ? n.block.timestamp : null,
    }));
}

/**
 * Confirmed pointers first (they are already newest-first from
 * HEIGHT_DESC), then unconfirmed ones. An unmined pointer is legitimately
 * the newest publish, but a confirmed one is the safer default for a
 * recovery flow — the pending one becomes "latest" on the next visit.
 */
export function orderPointers(pointers) {
  return [...pointers.filter((p) => p.confirmed), ...pointers.filter((p) => !p.confirmed)];
}

// ============ Network ============

const FETCH_TIMEOUT_MS = 15_000;

async function graphql(gateway, query, fetchImpl) {
  const res = await fetchImpl(`${gateway}/graphql`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query }),
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const json = await res.json();
  if (json.errors) throw new Error(`GraphQL: ${JSON.stringify(json.errors).slice(0, 200)}`);
  return json;
}

async function fetchBody(gateway, txid, fetchImpl) {
  const res = await fetchImpl(`${gateway}/${txid}`, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.text()).trim();
}

/**
 * Resolve one pointer to a verified destination: fetch the pointer body
 * (the page txid), validate its shape, and verify the target is an
 * owner-signed forever-page for this app. Throws if any step fails.
 */
export async function resolvePointer({ pointer, config, gateway, fetchImpl }) {
  const pageTxid = await fetchBody(gateway, pointer.pointerTxid, fetchImpl);
  if (!isValidTxid(pageTxid)) {
    throw new Error(`pointer ${pointer.pointerTxid} body is not a txid`);
  }
  const verify = await graphql(
    gateway,
    buildPageVerifyQuery({ pageTxid, appId: config.appId, ownerAddress: config.ownerAddress }),
    fetchImpl,
  );
  const edges = verify && verify.data && verify.data.transactions && verify.data.transactions.edges;
  if (!Array.isArray(edges) || edges.length !== 1 || !edges[0].node || edges[0].node.id !== pageTxid) {
    throw new Error(`pointer target ${pageTxid} failed owner/App-Id verification`);
  }
  return {
    pageTxid,
    url: `${gateway}/${pageTxid}`,
    pageVersion: tagValue(edges[0].node.tags, 'Version') || pointer.version,
    sha256: tagValue(edges[0].node.tags, 'Sha256'),
  };
}

/**
 * Full discovery: try each gateway in order; on the first gateway whose
 * pointer query answers, walk its pointers newest-first until one
 * resolves and verifies. Collects per-step errors for display.
 */
export async function discover({ config, fetchImpl }) {
  const errors = [];
  for (const gateway of config.gateways) {
    let pointers;
    try {
      const json = await graphql(
        gateway,
        buildPointerQuery({ appId: config.appId, ownerAddress: config.ownerAddress }),
        fetchImpl,
      );
      pointers = orderPointers(parsePointerEdges(json));
    } catch (err) {
      errors.push(`${gateway}: pointer query failed (${err.message})`);
      continue;
    }
    if (pointers.length === 0) {
      errors.push(`${gateway}: no published recovery pages found for this app`);
      continue;
    }
    // Walk at most a handful — if five consecutive operator-signed
    // pointers fail to resolve, something is wrong enough that the
    // static fallback is the saner path.
    for (const pointer of pointers.slice(0, 5)) {
      try {
        const resolved = await resolvePointer({ pointer, config, gateway, fetchImpl });
        return { resolved, pointer, pointers, gateway, errors };
      } catch (err) {
        errors.push(`${gateway}: ${err.message}`);
      }
    }
  }
  const failure = new Error('discovery failed on every gateway');
  failure.errors = errors;
  throw failure;
}

// ============ Rendering ============

function fmtDate(timestamp) {
  if (!timestamp) return 'pending confirmation';
  return new Date(timestamp * 1000).toLocaleDateString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
  });
}

function setStatus(doc, text) {
  doc.getElementById('status').textContent = text;
}

function show(doc, id) { doc.getElementById(id).classList.remove('hidden'); }
function hide(doc, id) { doc.getElementById(id).classList.add('hidden'); }

function renderLatest(doc, { resolved, pointer }) {
  doc.getElementById('latest-version').textContent = resolved.pageVersion;
  doc.getElementById('latest-date').textContent = fmtDate(pointer.timestamp);
  const link = doc.getElementById('latest-link');
  link.href = resolved.url;
  const pinned = doc.getElementById('latest-url');
  pinned.textContent = resolved.url;
  pinned.href = resolved.url;
  hide(doc, 'status');
  show(doc, 'latest');
}

function renderVersions(doc, { pointers, gateway, config, fetchImpl }) {
  const list = doc.getElementById('versions-list');
  list.textContent = '';
  for (const pointer of pointers) {
    const li = doc.createElement('li');
    const btn = doc.createElement('button');
    btn.type = 'button';
    btn.textContent = `v${pointer.version} — published ${fmtDate(pointer.timestamp)}`;
    const note = doc.createElement('span');
    note.className = 'version-note';
    li.append(btn, note);
    btn.addEventListener('click', async () => {
      note.textContent = ' resolving…';
      try {
        const resolved = await resolvePointer({ pointer, config, gateway, fetchImpl });
        note.textContent = '';
        doc.defaultView.location.href = resolved.url;
      } catch (err) {
        note.textContent = ` could not verify this version (${err.message})`;
      }
    });
    list.appendChild(li);
  }
  show(doc, 'versions');
}

function renderFallback(doc, config, errors) {
  const link = doc.getElementById('fallback-link');
  const url = `${config.gateways[0]}/${config.fallbackTxid}`;
  link.href = url;
  link.textContent = url;
  const errList = doc.getElementById('errors');
  errList.textContent = '';
  for (const e of errors || []) {
    const li = doc.createElement('li');
    li.textContent = e;
    errList.appendChild(li);
  }
  hide(doc, 'status');
  show(doc, 'fallback');
}

// ============ Entry ============

export async function init({ doc = globalThis.document, fetchImpl = globalThis.fetch.bind(globalThis) } = {}) {
  let config;
  try {
    config = readConfig(doc);
  } catch (err) {
    setStatus(doc, `This page is misconfigured (${err.message}). It cannot safely locate a recovery page — contact the app's operator.`);
    return;
  }
  setStatus(doc, 'Looking up the latest recovery page on Arweave…');
  try {
    const found = await discover({ config, fetchImpl });
    renderLatest(doc, found);
    renderVersions(doc, { ...found, config, fetchImpl });
  } catch (err) {
    renderFallback(doc, config, err.errors || [err.message]);
  }
}

// Auto-run in the browser; inert when imported by tests under Node.
if (typeof document !== 'undefined' && document.getElementById('bootstrap-config')) {
  init();
}
