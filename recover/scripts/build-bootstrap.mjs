#!/usr/bin/env node
/**
 * Build an app's forever-bootstrap page.
 *
 * The bootstrap is the one permanent URL an app's users bookmark: a tiny,
 * dependency-free page that finds the latest published forever-page for
 * the app (owner-pinned discovery — see examples/bootstrap/bootstrap.js)
 * and forwards the user to it. Unlike the forever page, the bootstrap is
 * built per app: the app id, app name, operator owner address, gateway
 * list, and static fallback txid are baked in at build time.
 *
 * Usage:
 *   node recover/scripts/build-bootstrap.mjs \
 *     --app-id <id> --app-name <name> \
 *     --owner-address <43-char base64url> \
 *     --fallback-txid <43-char base64url> \
 *     [--gateway <https://...>]... [--out <path>]
 *
 * Flags:
 *   --app-id <id>          App id; must match the App-Id tag the app's
 *                          forever-pages are published with.
 *   --app-name <name>      Human-facing app name (page title + copy).
 *   --owner-address <addr> The operator wallet's normalized Arweave owner
 *                          address — printed by publish-forever.mjs on
 *                          every run with a signing key. This is the
 *                          trust anchor the page pins discovery to.
 *   --fallback-txid <txid> Txid of the newest already-published
 *                          forever-page. Shown as a static link when
 *                          every gateway lookup fails.
 *   --gateway <url>        Gateway base origin (repeatable; ordered).
 *                          Default: https://arweave.net, https://permagate.io.
 *   --out <path>           Output path. Default: recover/dist/bootstrap.html.
 *
 * The build is deterministic: same inputs + same flags → same bytes.
 * No bundler is involved — bootstrap.js is inlined verbatim, so the
 * published artifact is the audited source, character for character.
 *
 * After building, publish with:
 *   node recover/scripts/publish-forever.mjs --bootstrap --app-id <id> --confirm
 * The resulting txid is the app's permanent recovery URL. It should
 * essentially never be republished — that is the whole point.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { createHash } from 'node:crypto';

const TXID_RE = /^[A-Za-z0-9_-]{43}$/;
const APP_ID_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const GATEWAY_RE = /^https:\/\/[^\s/]+$/;
const DEFAULT_GATEWAYS = ['https://arweave.net', 'https://permagate.io'];

export function parseArgs(argv) {
  const flags = {
    appId: null,
    appName: null,
    ownerAddress: null,
    fallbackTxid: null,
    gateways: [],
    out: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--app-id') flags.appId = argv[++i];
    else if (a === '--app-name') flags.appName = argv[++i];
    else if (a === '--owner-address') flags.ownerAddress = argv[++i];
    else if (a === '--fallback-txid') flags.fallbackTxid = argv[++i];
    else if (a === '--gateway') flags.gateways.push(argv[++i]);
    else if (a === '--out') flags.out = argv[++i];
    else if (a === '--help' || a === '-h') flags.help = true;
    else if (a.startsWith('--')) throw new Error(`Unknown flag: ${a}`);
    else throw new Error(`Unexpected positional arg: ${a}`);
  }
  if (flags.gateways.length === 0) flags.gateways = [...DEFAULT_GATEWAYS];
  return flags;
}

/** Validate flags into the config object injected into the page. */
export function buildConfig(flags) {
  if (!flags.appId || !APP_ID_RE.test(flags.appId)) {
    throw new Error('--app-id is required and must be a lowercase slug');
  }
  if (!flags.appName || !flags.appName.trim()) {
    throw new Error('--app-name is required');
  }
  if (!flags.ownerAddress || !TXID_RE.test(flags.ownerAddress)) {
    throw new Error(
      '--owner-address is required: the 43-char base64url owner address printed by publish-forever.mjs',
    );
  }
  if (!flags.fallbackTxid || !TXID_RE.test(flags.fallbackTxid)) {
    throw new Error('--fallback-txid is required and must be a 43-char base64url txid');
  }
  for (const g of flags.gateways) {
    if (!GATEWAY_RE.test(g)) {
      throw new Error(`--gateway must be an https origin with no path (got ${JSON.stringify(g)})`);
    }
  }
  return {
    appId: flags.appId,
    appName: flags.appName.trim(),
    ownerAddress: flags.ownerAddress,
    gateways: flags.gateways.map((g) => g.replace(/\/$/, '')),
    fallbackTxid: flags.fallbackTxid,
  };
}

function escapeHtml(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Substitute the template markers. The config JSON escapes `<` so a
 * hostile-looking app name can never close the JSON <script> block; the
 * app name is HTML-escaped everywhere it lands in markup.
 */
export function renderPage({ template, css, js, config }) {
  for (const marker of ['__INLINE_CSS__', '__INLINE_JS__', '__BOOTSTRAP_CONFIG__', '__APP_NAME__']) {
    if (!template.includes(marker)) throw new Error(`template missing ${marker} marker`);
  }
  const configJson = JSON.stringify(config).replace(/</g, '\\u003c');
  return template
    .replaceAll('__APP_NAME__', () => escapeHtml(config.appName))
    .replace('__INLINE_CSS__', () => css)
    .replace('__BOOTSTRAP_CONFIG__', () => configJson)
    .replace('__INLINE_JS__', () => js);
}

export async function build(argv, { logger = console } = {}) {
  let flags;
  try {
    flags = parseArgs(argv);
  } catch (err) {
    logger.error(err.message);
    return { ok: false, exitCode: 1, error: err.message };
  }
  if (flags.help) {
    printUsage(logger);
    return { ok: true, exitCode: 0, help: true };
  }

  let config;
  try {
    config = buildConfig(flags);
  } catch (err) {
    logger.error(err.message);
    logger.error('Run with --help for usage.');
    return { ok: false, exitCode: 1, error: err.message };
  }

  const here = dirname(fileURLToPath(import.meta.url));
  const root = resolve(here, '..');
  const srcDir = resolve(root, 'examples', 'bootstrap');
  const outPath = resolve(flags.out || resolve(root, 'dist', 'bootstrap.html'));

  const [template, css, js] = await Promise.all([
    readFile(resolve(srcDir, 'bootstrap.html'), 'utf8'),
    readFile(resolve(srcDir, 'bootstrap.css'), 'utf8'),
    readFile(resolve(srcDir, 'bootstrap.js'), 'utf8'),
  ]);

  const html = renderPage({ template, css, js, config });
  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, html, 'utf8');

  const sha256 = createHash('sha256').update(html, 'utf8').digest('hex');
  const sizeKb = (Buffer.byteLength(html, 'utf8') / 1024).toFixed(1);
  logger.log(`[build-bootstrap] wrote ${outPath} (${sizeKb} KB)`);
  logger.log(`[build-bootstrap] sha256 ${sha256}`);
  logger.log(`[build-bootstrap] app-id=${config.appId} owner=${config.ownerAddress}`);
  logger.log(`[build-bootstrap] gateways: ${config.gateways.join(', ')}`);
  logger.log(`[build-bootstrap] fallback: ${config.gateways[0]}/${config.fallbackTxid}`);
  return { ok: true, exitCode: 0, outPath, sha256, config };
}

function printUsage(logger) {
  logger.log(`Usage: node recover/scripts/build-bootstrap.mjs --app-id <id> --app-name <name> \\
  --owner-address <addr> --fallback-txid <txid> [--gateway <url>]... [--out <path>]

Builds the app's forever-bootstrap page (the permanent recovery URL).
  --app-id <id>          App id (matches the App-Id publish tag).
  --app-name <name>      Human-facing app name.
  --owner-address <addr> Operator owner address (printed by publish-forever.mjs).
  --fallback-txid <txid> Newest already-published forever-page txid.
  --gateway <url>        Gateway origin (repeatable; default arweave.net + permagate.io).
  --out <path>           Output (default recover/dist/bootstrap.html).
`);
}

const invokedAs = process.argv[1] ? resolve(process.argv[1]) : null;
const thisFile = fileURLToPath(import.meta.url);
if (invokedAs && invokedAs === thisFile) {
  const result = await build(process.argv.slice(2));
  process.exit(result.exitCode);
}
