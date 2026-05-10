#!/usr/bin/env node
/**
 * Publish the reference standalone recovery page (`dist/forever.html`) to
 * Arweave so the artifact of the permanent owned-content promise is itself
 * permanent. The page survives every other piece of infrastructure dying;
 * publishing it to Arweave is the last step that closes the durability
 * loop.
 *
 * Usage:
 *   node recover/scripts/publish-forever.mjs [options]
 *
 * Options:
 *   --signing-key <hex>   Operator's Arweave-billable signing key
 *                         (secp256k1 hex; same shape as APP_SIGNING_KEY in
 *                         api/.dev.vars). May also be supplied via the
 *                         TARN_OPERATOR_WALLET env var.
 *   --file <path>         Path to the bundled forever.html. Defaults to
 *                         `recover/dist/forever.html`.
 *   --confirm             Actually publish. Without this flag the script
 *                         runs in DRY-RUN mode (default): no signing, no
 *                         network calls, just shows what *would* happen.
 *   --skip-pointer        Skip publishing the `forever-page-pointer` blob
 *                         (the "latest" discovery mechanism). Use this if
 *                         you want to publish a candidate page without
 *                         promoting it to "latest" yet.
 *   --skip-verify         Skip the post-publish gateway-fetch + hash-match
 *                         verification step. Off-label; use only if every
 *                         configured gateway is known to be slow-indexing
 *                         and you don't want to wait.
 *   --gateway <url>       Gateway URL to verify against. Defaults to
 *                         https://arweave.net. Repeat to add fallbacks.
 *
 * Exit codes:
 *   0  — success (or successful dry-run)
 *   1  — usage / pre-publish validation failure
 *   2  — Arweave publish failure (signing or upload)
 *   3  — post-publish verification failure (txid published but gateway
 *        cannot serve a hash-matching copy)
 *
 * "Latest" pointer mechanism:
 *
 *   Arweave is immutable; every publish gets a new txid. Users with a
 *   saved kit that embeds a specific txid keep working forever — that's
 *   the durability point. But a user discovering the recovery page for
 *   the first time needs a way to find the LATEST published forever-page.
 *
 *   We use an Arweave-native pointer: each publish ALSO writes a tiny
 *   `Type=forever-page-pointer` blob whose body is the just-published
 *   forever-page txid. Discovery: query
 *   `App=tarn-recover,Type=forever-page-pointer` and pick the most
 *   recent confirmed entry; its body is the latest forever-page txid.
 *
 *   This keeps the discovery story Tarn-server-independent — the
 *   `@tarn/recover` durability story is "Arweave gateway is enough,"
 *   and the discovery layer should not regress that.
 *
 *   Operators who want to publish a release-candidate page without
 *   promoting it to "latest" pass `--skip-pointer`.
 *
 * Idempotency:
 *
 *   Republishing the same bytes produces a NEW txid each time (Arweave
 *   data items embed timestamps in the signature payload). The script
 *   warns unconditionally before publish that this creates a new
 *   permanent record. The Sha256 tag is the integrity reference: two
 *   publishes with the same Sha256 are byte-identical, even though their
 *   txids differ.
 */

import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { createHash } from 'node:crypto';

import { buildSignedDataItem, uploadSignedDataItem } from '../../api/src/turbo.js';

// ============ Constants ============

// Sanity bounds on the forever-page artifact. The page bundles the
// recover SDK + hash-wasm + @noble/curves; today's size is ~270 KB. The
// bounds here are wide enough to absorb expected growth (new envelope
// versions, new SDK features) while still catching "you forgot to bundle
// something" or "the bundle blew up" failure modes.
const MIN_PAGE_BYTES = 50 * 1024;       // 50 KB — well below current bundle
const MAX_PAGE_BYTES = 5 * 1024 * 1024; // 5 MB — well above forecast growth

const DEFAULT_GATEWAYS = ['https://arweave.net'];

// Post-publish verification timing. Turbo confirms-on-Arweave is usually
// seconds, but indexing on a public gateway can lag. We try a small
// number of times with a backoff; fail loudly if none succeed.
const VERIFY_INITIAL_DELAY_MS = 5_000;
const VERIFY_RETRY_COUNT = 6;
const VERIFY_RETRY_BACKOFF_MS = 10_000;

// ============ Args ============

/**
 * Minimal arg parser. Mirrors the style of tools/generate-app-key.mjs so
 * operators see one flag-parsing convention across the project.
 */
export function parseArgs(argv) {
  const flags = {
    signingKey: null,
    file: null,
    confirm: false,
    skipPointer: false,
    skipVerify: false,
    gateways: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--signing-key') flags.signingKey = argv[++i];
    else if (a === '--file') flags.file = argv[++i];
    else if (a === '--confirm') flags.confirm = true;
    else if (a === '--skip-pointer') flags.skipPointer = true;
    else if (a === '--skip-verify') flags.skipVerify = true;
    else if (a === '--gateway') flags.gateways.push(argv[++i]);
    else if (a === '--help' || a === '-h') {
      flags.help = true;
    } else if (a.startsWith('--')) {
      throw new Error(`Unknown flag: ${a}`);
    } else {
      throw new Error(`Unexpected positional arg: ${a}`);
    }
  }
  if (flags.gateways.length === 0) flags.gateways = [...DEFAULT_GATEWAYS];
  return flags;
}

// ============ Pre-publish verification ============

/**
 * Verify the page artifact exists, has a sane size, and looks like HTML.
 * Returns the buffer + sha256 hex. Throws on failure; the script catches
 * and exits non-zero with the message.
 */
export async function preflightCheck(filePath) {
  if (!existsSync(filePath)) {
    throw new Error(
      `forever-page not found at ${filePath}. Run \`npm run build:forever\` first.`,
    );
  }
  const bytes = await readFile(filePath);
  const size = bytes.byteLength;
  if (size < MIN_PAGE_BYTES) {
    throw new Error(
      `forever-page at ${filePath} is suspiciously small (${size} bytes < ${MIN_PAGE_BYTES} min). ` +
        `Did the build truncate? Try a clean rebuild.`,
    );
  }
  if (size > MAX_PAGE_BYTES) {
    throw new Error(
      `forever-page at ${filePath} is suspiciously large (${size} bytes > ${MAX_PAGE_BYTES} max). ` +
        `Did a dependency balloon? Inspect the bundle before publishing.`,
    );
  }
  const head = bytes.subarray(0, 256).toString('utf8').toLowerCase();
  if (!head.includes('<!doctype html>')) {
    throw new Error(
      `forever-page at ${filePath} does not start with <!DOCTYPE html>. ` +
        `Is this actually the forever-page artifact?`,
    );
  }
  const tail = bytes.subarray(Math.max(0, bytes.byteLength - 256)).toString('utf8').toLowerCase();
  if (!tail.includes('</html>')) {
    throw new Error(
      `forever-page at ${filePath} does not end with </html>. ` +
        `The bundle looks truncated.`,
    );
  }
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  return { bytes, size, sha256 };
}

// ============ Tag construction ============

/**
 * Build the Arweave tag set for a `forever-page` blob.
 *
 * Tag scheme:
 *   App          = 'tarn-recover'   — package namespace
 *   Type         = 'forever-page'   — what this blob is
 *   Version      = '<pkg version>'  — version of @tarn/recover that produced it
 *   Sha256       = '<hex>'          — integrity reference
 *   Content-Type = 'text/html'      — gateway serves it inline
 *
 * Discoverability: `App=tarn-recover,Type=forever-page` enumerates every
 * published reference page across history. `Sha256=<hex>` lookup tells
 * you whether a given byte-blob has ever been published before.
 */
export function buildForeverPageTags({ version, sha256 }) {
  if (!version || typeof version !== 'string') {
    throw new Error('buildForeverPageTags: version must be a non-empty string');
  }
  if (!/^[0-9a-f]{64}$/i.test(sha256)) {
    throw new Error('buildForeverPageTags: sha256 must be a 64-char hex string');
  }
  return [
    { name: 'Content-Type', value: 'text/html' },
    { name: 'App', value: 'tarn-recover' },
    { name: 'Type', value: 'forever-page' },
    { name: 'Version', value: version },
    { name: 'Sha256', value: sha256 },
  ];
}

/**
 * Build the Arweave tag set for the `forever-page-pointer` blob — the
 * "latest" discovery layer described in the file header. The pointer
 * body is the txid of the just-published forever-page.
 */
export function buildPointerTags({ version }) {
  if (!version || typeof version !== 'string') {
    throw new Error('buildPointerTags: version must be a non-empty string');
  }
  return [
    { name: 'Content-Type', value: 'text/plain' },
    { name: 'App', value: 'tarn-recover' },
    { name: 'Type', value: 'forever-page-pointer' },
    { name: 'Version', value: version },
  ];
}

// ============ Publish (real) ============

async function publishToArweave({ bytes, tags, signingKey }) {
  const signed = await buildSignedDataItem(bytes, tags, signingKey);
  const upload = await uploadSignedDataItem(signed.signedDataItem);
  if (!upload.ok) {
    throw new Error(
      `Turbo upload failed (status ${upload.status}): ${upload.body}`,
    );
  }
  return { txid: signed.txid, turboTxid: upload.turboTxid || null };
}

// ============ Post-publish verification ============

async function sleep(ms) {
  return new Promise((res) => setTimeout(res, ms));
}

/**
 * Fetch the published page from a gateway and confirm its hash matches.
 * Tries each gateway in order; on each gateway, retries with a fixed
 * backoff to absorb indexing lag.
 */
export async function verifyPublished({ txid, expectedSha256, gateways, fetchImpl }) {
  const fetcher = fetchImpl || globalThis.fetch;
  if (typeof fetcher !== 'function') {
    throw new Error('verifyPublished: no fetch implementation available');
  }
  await sleep(VERIFY_INITIAL_DELAY_MS);

  const errors = [];
  for (const gateway of gateways) {
    const url = `${gateway.replace(/\/$/, '')}/${txid}`;
    for (let attempt = 0; attempt < VERIFY_RETRY_COUNT; attempt++) {
      try {
        const res = await fetcher(url);
        if (!res.ok) {
          errors.push(`${gateway} attempt ${attempt + 1}: HTTP ${res.status}`);
          await sleep(VERIFY_RETRY_BACKOFF_MS);
          continue;
        }
        const buf = new Uint8Array(await res.arrayBuffer());
        const actualSha = createHash('sha256').update(buf).digest('hex');
        if (actualSha === expectedSha256) {
          return { ok: true, gateway, attempts: attempt + 1 };
        }
        errors.push(
          `${gateway} attempt ${attempt + 1}: hash mismatch (got ${actualSha.slice(0, 16)}…, expected ${expectedSha256.slice(0, 16)}…)`,
        );
        // Hash mismatch isn't a "wait and retry" condition; bail this gateway.
        break;
      } catch (err) {
        errors.push(`${gateway} attempt ${attempt + 1}: ${err.message}`);
        await sleep(VERIFY_RETRY_BACKOFF_MS);
      }
    }
  }
  return { ok: false, errors };
}

// ============ Run ============

/**
 * Programmatic entry — exposed so tests can drive the script without
 * spawning a subprocess. Returns a summary object; on Arweave failures
 * it returns `{ ok: false, exitCode: N }` rather than throwing, so the
 * CLI wrapper at the bottom can mirror the exit code.
 */
export async function run(argv, { logger = console, fetchImpl } = {}) {
  let flags;
  try {
    flags = parseArgs(argv);
  } catch (err) {
    logger.error(err.message);
    logger.error('Run with --help for usage.');
    return { ok: false, exitCode: 1, error: err.message };
  }

  if (flags.help) {
    printUsage(logger);
    return { ok: true, exitCode: 0, dryRun: true, help: true };
  }

  const here = dirname(fileURLToPath(import.meta.url));
  const root = resolve(here, '..');
  const filePath = resolve(flags.file || resolve(root, 'dist', 'forever.html'));

  // Read package version (used as the Version tag).
  const pkgRaw = await readFile(resolve(root, 'package.json'), 'utf8');
  const pkg = JSON.parse(pkgRaw);
  const version = String(pkg.version);

  logger.log('=== @tarn/recover forever-page publisher ===\n');
  logger.log(`Package version: ${version}`);
  logger.log(`Source file:     ${filePath}`);

  let preflight;
  try {
    preflight = await preflightCheck(filePath);
  } catch (err) {
    logger.error(`\n[FATAL] Pre-publish check failed: ${err.message}`);
    return { ok: false, exitCode: 1, error: err.message };
  }
  logger.log(`Size:            ${preflight.size} bytes (${(preflight.size / 1024).toFixed(1)} KB)`);
  logger.log(`SHA-256:         ${preflight.sha256}\n`);

  const tags = buildForeverPageTags({ version, sha256: preflight.sha256 });
  logger.log('Tags:');
  for (const t of tags) logger.log(`  ${t.name} = ${t.value}`);

  // Always warn that publishing creates a new permanent record. Even
  // byte-identical re-publishes get a new txid (data-item signatures
  // include a timestamp); the Sha256 tag is the integrity reference.
  logger.log(
    '\n[NOTE] Publishing creates a NEW permanent record on Arweave. ' +
      'Re-publishing byte-identical content yields a new txid; the Sha256 tag ' +
      'lets future readers spot identical content across publishes.',
  );

  if (!flags.confirm) {
    logger.log('\n--- DRY RUN ---');
    logger.log('No signing, no network calls. Re-run with --confirm to publish for real.');
    if (!flags.skipPointer) {
      logger.log('Would also publish a `forever-page-pointer` blob pointing at the new txid.');
    }
    return {
      ok: true,
      exitCode: 0,
      dryRun: true,
      file: filePath,
      sha256: preflight.sha256,
      size: preflight.size,
      version,
      tags,
    };
  }

  // ============ Real publish from here on ============

  const signingKey = flags.signingKey || process.env.TARN_OPERATOR_WALLET || null;
  if (!signingKey) {
    const msg =
      'Missing operator signing key. Pass --signing-key <hex> or set TARN_OPERATOR_WALLET env var.';
    logger.error(`\n[FATAL] ${msg}`);
    return { ok: false, exitCode: 1, error: msg };
  }

  logger.log('\n=== Publishing forever-page ===');
  let pageResult;
  try {
    pageResult = await publishToArweave({ bytes: preflight.bytes, tags, signingKey });
  } catch (err) {
    logger.error(`\n[FATAL] Publish failed: ${err.message}`);
    return { ok: false, exitCode: 2, error: err.message };
  }
  logger.log(`  txid:  ${pageResult.txid}`);
  if (pageResult.turboTxid && pageResult.turboTxid !== 'skipped-local-dev') {
    logger.log(`  turbo: ${pageResult.turboTxid}`);
  }

  let pointerResult = null;
  if (!flags.skipPointer) {
    logger.log('\n=== Publishing forever-page-pointer ===');
    try {
      pointerResult = await publishToArweave({
        bytes: new TextEncoder().encode(pageResult.txid),
        tags: buildPointerTags({ version }),
        signingKey,
      });
      logger.log(`  txid:  ${pointerResult.txid}`);
      logger.log(`  body:  ${pageResult.txid} (the just-published forever-page)`);
    } catch (err) {
      // Pointer failure is non-fatal — the page itself is published.
      logger.error(`\n[WARN] Pointer publish failed: ${err.message}`);
      logger.error('       The forever-page itself is published; the "latest" pointer is not.');
      logger.error('       Manually re-publish the pointer (a tiny text blob) when convenient.');
    }
  }

  if (!flags.skipVerify) {
    logger.log('\n=== Verifying published page ===');
    logger.log(`Trying ${flags.gateways.length} gateway(s); waiting briefly for indexing…`);
    const verify = await verifyPublished({
      txid: pageResult.txid,
      expectedSha256: preflight.sha256,
      gateways: flags.gateways,
      fetchImpl,
    });
    if (verify.ok) {
      logger.log(`  OK via ${verify.gateway} (attempt ${verify.attempts})`);
    } else {
      logger.error('\n[FATAL] Post-publish verification failed:');
      for (const e of verify.errors) logger.error(`  - ${e}`);
      logger.error(
        '\nThe page was published (txid above) but no gateway confirmed it within the timeout.',
      );
      logger.error('Try again later or pass --skip-verify if you trust the upload.');
      return { ok: false, exitCode: 3, error: 'verification failed', txid: pageResult.txid };
    }
  } else {
    logger.log('\n[INFO] --skip-verify set; trusting Turbo response. No gateway round-trip.');
  }

  logger.log('\n=== Published ===\n');
  logger.log(`forever-page txid: ${pageResult.txid}`);
  logger.log(`Gateway URLs:`);
  logger.log(`  https://arweave.net/${pageResult.txid}`);
  logger.log(`  https://g8way.io/${pageResult.txid}`);
  if (pointerResult) {
    logger.log(`\nforever-page-pointer txid: ${pointerResult.txid}`);
    logger.log(`  https://arweave.net/${pointerResult.txid}`);
  }
  logger.log(
    `\nRecord this txid in operator notes and share with users as the canonical recovery URL.`,
  );

  return {
    ok: true,
    exitCode: 0,
    dryRun: false,
    file: filePath,
    sha256: preflight.sha256,
    size: preflight.size,
    version,
    tags,
    txid: pageResult.txid,
    pointerTxid: pointerResult ? pointerResult.txid : null,
  };
}

function printUsage(logger) {
  logger.log(`Usage: node recover/scripts/publish-forever.mjs [options]

Options:
  --signing-key <hex>   Operator signing key (or TARN_OPERATOR_WALLET env var).
  --file <path>         Path to forever.html (default: recover/dist/forever.html).
  --confirm             Actually publish (default is DRY RUN).
  --skip-pointer        Don't publish the "latest" pointer blob.
  --skip-verify         Don't fetch + hash-check from a gateway after publish.
  --gateway <url>       Gateway for verify (default https://arweave.net; repeatable).
  --help                Show this message.
`);
}

// ============ Entry ============

// Detect "this file was invoked directly" vs "this file was imported".
// Tests import the module, so we must not run the CLI on import.
const invokedAs = process.argv[1] ? resolve(process.argv[1]) : null;
const thisFile = fileURLToPath(import.meta.url);
if (invokedAs && invokedAs === thisFile) {
  const result = await run(process.argv.slice(2));
  process.exit(result.exitCode);
}
