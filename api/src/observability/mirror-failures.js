// mirror-failures.js — durable tracking + self-healing retry for failed
// BACKGROUND ("waitUntil") Arweave mirror uploads (Tarn issue #47).
//
// CONTEXT (why this exists):
//   The /entries data-plane write path is Turbo-FIRST: it fails the request on
//   any Turbo/D1 error, so the caller always learns about a failure. The
//   identity- and share-plane writes (auth credential blobs, account-key
//   republish, app-config / app-reg / app-schema, share-inbox, share-log,
//   passkey-reg, tombstones) are D1-FIRST: they commit to D1, then fire the
//   Turbo upload in `ctx.waitUntil(...)`. Before this module, a Turbo failure
//   there was swallowed with a console.warn — D1 advanced but Arweave never got
//   the mirror, a SILENT divergence that a future D1-rebuild-from-Arweave cannot
//   recover (Arweave never received the bytes). The drift cron's count-compare
//   deliberately does NOT flag this case (it only flags Arweave-ahead-of-D1).
//   This module records every such failure durably and lets the cron re-upload.
//
// SELF-HEALING (store-bytes decision — see migration 0022 header):
//   We persist the already-SIGNED ANS-104 DataItem bytes. The DataItem ID is
//   content-addressed from the signature, so re-uploading the same bytes lands
//   the same txid D1 already cached → the mirror converges with no divergence
//   and no re-signing / no plaintext access. Bytes over MAX_STORED_BYTES are not
//   stored (the row is still recorded for alerting; the cron skips its retry).
//
// ZERO-KNOWLEDGE: the stored bytes are the same signed ciphertext bundle Turbo
// would have taken and that Arweave would have published publicly. This module
// never sees or stores plaintext, account keys, DEKs/CEKs, or kit material.
//
// All writes here are BEST-EFFORT: every function is internally try/caught and
// NEVER throws into the request path (a recorder that throws would defeat the
// purpose — the user-visible op already succeeded in D1).

// Cap on the signed-DataItem bytes we persist for retry. Runtime payloads are
// capped at 100 KB (MAX_UPLOAD_BYTES) / 64 KB (MAX_SCHEMA_BYTES); a signed
// DataItem adds only signature + tag-header overhead. 256 KB is a comfortable
// ceiling that should never be hit by these namespaces — it exists so a wildly
// unexpected payload can't bloat a D1 row. Over the cap → record metadata only.
export const MAX_STORED_BYTES = 256 * 1024;

// Default number of unresolved rows the cron re-attempts per tick. Bounded so a
// large backlog (e.g. after a long Turbo outage) drains over several ticks
// rather than blowing the cron's time budget in one run. Configurable via
// env.MIRROR_RETRY_BATCH.
export const DEFAULT_RETRY_BATCH = 20;

// Retention for RESOLVED failure rows, in days. Open (unresolved) rows are never
// auto-pruned — they are an actionable backlog. Resolved rows are kept briefly
// as an audit trail then reaped. Configurable via env.MIRROR_FAILURE_RETENTION_DAYS.
export const DEFAULT_RESOLVED_RETENTION_DAYS = 7;

const MS_PER_DAY = 24 * 60 * 60 * 1000;

function tagValue(tags, name) {
  if (!Array.isArray(tags)) return null;
  const t = tags.find((x) => x && x.name === name);
  return t ? t.value : null;
}

/**
 * Derive a best-effort `data_lookup_key`-style identifier from the Arweave tags
 * for operator triage. Tries the common identifier tags in priority order. All
 * of these are lookup keys (hashes) or public routing values — never plaintext.
 */
function identifierFromTags(tags) {
  return (
    tagValue(tags, 'Lk') ||
    tagValue(tags, 'To') ||
    tagValue(tags, 'CredId') ||
    null
  );
}

/**
 * Record a failed background mirror upload as a durable row, best-effort.
 *
 * De-dupes on the open (unresolved) intended_txid via migration 0022's partial
 * unique index: a repeat failure for the same content bumps attempt_count and
 * refreshes last_attempt_at / error_message on the existing open row instead of
 * inserting a duplicate. NEVER throws — a failure to record is logged and
 * swallowed so it can't bubble into the already-succeeded request.
 *
 * @param {Object} db - D1 binding (env.DB)
 * @param {Object} args
 * @param {string} args.namespace        - logical namespace (e.g. 'cred', 'share-log')
 * @param {string} [args.intendedTxid]   - content-addressed DataItem ID
 * @param {Array}  [args.tags]           - Arweave tags ([{name,value}])
 * @param {Uint8Array} [args.signedDataItem] - signed bytes for self-healing retry
 * @param {string} [args.errorMessage]   - the Turbo error / thrown message
 * @param {number} [args.now]            - unix ms (injectable for tests)
 * @returns {Promise<{recorded: boolean, storedBytes: boolean, error?: string}>}
 */
export async function recordMirrorFailure(db, {
  namespace,
  intendedTxid = null,
  tags = null,
  signedDataItem = null,
  errorMessage = null,
  now = Date.now(),
} = {}) {
  try {
    if (!db || !namespace) {
      return { recorded: false, storedBytes: false, error: 'missing db or namespace' };
    }

    // Only persist the bytes if they fit the cap; otherwise record metadata only.
    let bytes = null;
    let storedBytes = false;
    if (signedDataItem && signedDataItem.byteLength != null) {
      if (signedDataItem.byteLength <= MAX_STORED_BYTES) {
        bytes = signedDataItem;
        storedBytes = true;
      }
    }

    const dataLookupKey = identifierFromTags(tags);
    const tagsJson = Array.isArray(tags) ? JSON.stringify(tags) : null;
    const errMsg = errorMessage != null ? String(errorMessage).slice(0, 1000) : null;

    // De-dupe path: if there is an OPEN row for this intended_txid, bump it
    // rather than insert. The partial unique index would reject a duplicate
    // INSERT, but doing the UPDATE first keeps attempt_count meaningful and
    // avoids relying on INSERT-OR-IGNORE swallowing the conflict silently.
    if (intendedTxid) {
      const existing = await db
        .prepare('SELECT id FROM arweave_mirror_failures WHERE intended_txid = ?1 AND resolved_at IS NULL')
        .bind(intendedTxid)
        .first();
      if (existing && existing.id != null) {
        await db
          .prepare(
            `UPDATE arweave_mirror_failures
                SET attempt_count = attempt_count + 1,
                    last_attempt_at = ?1,
                    error_message = ?2
              WHERE id = ?3`,
          )
          .bind(now, errMsg, existing.id)
          .run();
        return { recorded: true, storedBytes: false, deduped: true };
      }
    }

    await db
      .prepare(
        `INSERT INTO arweave_mirror_failures
           (created_at, namespace, intended_txid, data_lookup_key, tags_json,
            signed_data_item, error_message, attempt_count, last_attempt_at, resolved_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, NULL)`,
      )
      .bind(now, namespace, intendedTxid, dataLookupKey, tagsJson, bytes, errMsg, now)
      .run();

    return { recorded: true, storedBytes };
  } catch (err) {
    // Best-effort: a recorder failure must never break the request path.
    console.error('[tarn-api][mirror-failures] recordMirrorFailure failed:', err?.message);
    return { recorded: false, storedBytes: false, error: err?.message || String(err) };
  }
}

/**
 * Convenience wrapper for the D1-first waitUntil sites: run the background Turbo
 * upload and, on failure (non-ok result OR a thrown error), record a durable
 * failure row. Keeps the call sites DRY and consistent. Returns the Turbo
 * result (or a synthesized failure result) so callers can still log. NEVER
 * throws.
 *
 * @param {Object} args
 * @param {Function} args.uploadFn   - () => Promise<{ok, status?, body?}> (uploadSignedDataItem bound to the item)
 * @param {Object} args.db           - env.DB
 * @param {string} args.namespace
 * @param {string} args.intendedTxid
 * @param {Array}  args.tags
 * @param {Uint8Array} args.signedDataItem
 * @param {number} [args.now]
 * @returns {Promise<{ok: boolean, status?: number, body?: string}>}
 */
export async function mirrorUploadWithTracking({
  uploadFn,
  db,
  namespace,
  intendedTxid = null,
  tags = null,
  signedDataItem = null,
  now = Date.now(),
}) {
  let result;
  try {
    result = await uploadFn();
  } catch (err) {
    result = { ok: false, status: 0, body: err?.message || String(err) };
  }
  if (!result || !result.ok) {
    await recordMirrorFailure(db, {
      namespace,
      intendedTxid,
      tags,
      signedDataItem,
      errorMessage: result ? `turbo_${result.status ?? 0}: ${result.body ?? ''}` : 'no_result',
      now,
    });
  }
  return result || { ok: false, status: 0, body: 'no_result' };
}

/**
 * Count OPEN (unresolved) mirror failures. Best-effort: returns 0 on any error
 * (a count that itself errors must not crash the cron / /status). Returns -1
 * only if you want to distinguish error from zero — we return { count, error }.
 *
 * @param {Object} db - env.DB
 * @returns {Promise<{count: number, error: string|null}>}
 */
export async function countOpenMirrorFailures(db) {
  try {
    if (!db) return { count: 0, error: 'no_db' };
    const row = await db
      .prepare('SELECT COUNT(*) AS c FROM arweave_mirror_failures WHERE resolved_at IS NULL')
      .first();
    return { count: row?.c ?? 0, error: null };
  } catch (err) {
    return { count: 0, error: err?.message || String(err) };
  }
}

/**
 * Select unresolved failure rows that have stored bytes (so they are
 * RE-UPLOADABLE), oldest-first, bounded to `limit`. Rows without stored bytes
 * (over the size cap) are intentionally excluded — they can't be self-healed and
 * remain open for manual operator reconcile. Best-effort: returns [] on error.
 *
 * @param {Object} db - env.DB
 * @param {number} limit
 * @returns {Promise<Array<{id, intended_txid, namespace, signed_data_item, attempt_count}>>}
 */
export async function selectRetryableMirrorFailures(db, limit = DEFAULT_RETRY_BATCH) {
  try {
    if (!db) return [];
    const res = await db
      .prepare(
        `SELECT id, intended_txid, namespace, signed_data_item, attempt_count
           FROM arweave_mirror_failures
          WHERE resolved_at IS NULL AND signed_data_item IS NOT NULL
          ORDER BY created_at ASC
          LIMIT ?1`,
      )
      .bind(limit)
      .all();
    return res?.results ?? res?.rows ?? [];
  } catch (err) {
    console.error('[tarn-api][mirror-failures] selectRetryableMirrorFailures failed:', err?.message);
    return [];
  }
}

/**
 * Mark a failure row resolved (mirror finally landed on Arweave). Best-effort.
 * @param {Object} db
 * @param {number} id
 * @param {number} [now]
 */
export async function markMirrorResolved(db, id, now = Date.now()) {
  try {
    await db
      .prepare('UPDATE arweave_mirror_failures SET resolved_at = ?1, last_attempt_at = ?1 WHERE id = ?2')
      .bind(now, id)
      .run();
    return true;
  } catch (err) {
    console.error('[tarn-api][mirror-failures] markMirrorResolved failed:', err?.message);
    return false;
  }
}

/**
 * Increment a failure row's attempt_count after a retry that did NOT succeed.
 * Best-effort.
 */
async function bumpAttempt(db, id, now = Date.now(), errorMessage = null) {
  try {
    await db
      .prepare(
        `UPDATE arweave_mirror_failures
            SET attempt_count = attempt_count + 1, last_attempt_at = ?1, error_message = COALESCE(?2, error_message)
          WHERE id = ?3`,
      )
      .bind(now, errorMessage != null ? String(errorMessage).slice(0, 1000) : null, id)
      .run();
  } catch (err) {
    console.error('[tarn-api][mirror-failures] bumpAttempt failed:', err?.message);
  }
}

/**
 * SELF-HEALING RETRY (cron leg). Re-upload up to `batch` unresolved+stored-bytes
 * failures via the supplied uploader. On success, mark the row resolved; on
 * failure, bump its attempt_count. Bounded and resilient — a single bad row
 * never aborts the rest, and the whole leg never throws.
 *
 * The uploader is injected (the same uploadSignedDataItem the runtime uses) so
 * this is unit-testable without a live Turbo. The signed_data_item BLOB comes
 * back from D1 as an ArrayBuffer (Workers) or Buffer/Uint8Array; we normalize
 * to Uint8Array before handing it to the uploader.
 *
 * @param {Object} db - env.DB
 * @param {Object} [opts]
 * @param {Function} [opts.uploadImpl] - (Uint8Array) => Promise<{ok, status?, body?}>
 * @param {number} [opts.batch]
 * @param {number} [opts.now]
 * @returns {Promise<{attempted, resolved, stillFailing, errors: number}>}
 */
export async function retryMirrorFailures(db, opts = {}) {
  const batch = opts.batch ?? DEFAULT_RETRY_BATCH;
  const now = opts.now ?? Date.now();
  const summary = { attempted: 0, resolved: 0, stillFailing: 0, errors: 0 };

  let uploadImpl = opts.uploadImpl;
  if (!uploadImpl) {
    // Lazy import so unit tests that inject uploadImpl never pull in the real
    // network module, and the cron uses the real uploader by default.
    const turbo = await import('../turbo.js');
    uploadImpl = turbo.uploadSignedDataItem;
  }

  let rows;
  try {
    rows = await selectRetryableMirrorFailures(db, batch);
  } catch {
    return summary;
  }

  for (const row of rows) {
    summary.attempted += 1;
    try {
      const raw = row.signed_data_item;
      let bytes;
      if (raw instanceof Uint8Array) bytes = raw;
      else if (raw instanceof ArrayBuffer) bytes = new Uint8Array(raw);
      else if (raw && raw.buffer instanceof ArrayBuffer) bytes = new Uint8Array(raw.buffer, raw.byteOffset || 0, raw.byteLength);
      else if (raw == null) { summary.stillFailing += 1; continue; }
      else bytes = new Uint8Array(raw);

      const result = await uploadImpl(bytes);
      if (result && result.ok) {
        await markMirrorResolved(db, row.id, now);
        summary.resolved += 1;
      } else {
        await bumpAttempt(db, row.id, now, result ? `turbo_${result.status ?? 0}: ${result.body ?? ''}` : 'no_result');
        summary.stillFailing += 1;
      }
    } catch (err) {
      summary.errors += 1;
      await bumpAttempt(db, row.id, now, err?.message || String(err));
      summary.stillFailing += 1;
    }
  }

  return summary;
}

/**
 * Reap RESOLVED failure rows older than the retention cutoff. Open rows are
 * never reaped (they are actionable backlog). Pure SQL; best-effort.
 *
 * @param {Object} db
 * @param {Object} [opts]
 * @param {number} [opts.now]
 * @param {number} [opts.retentionDays]
 * @returns {Promise<{deleted: number, error: string|null}>}
 */
export async function pruneResolvedMirrorFailures(db, opts = {}) {
  const now = opts.now ?? Date.now();
  const retentionDays = opts.retentionDays ?? DEFAULT_RESOLVED_RETENTION_DAYS;
  const cutoff = now - retentionDays * MS_PER_DAY;
  try {
    const res = await db
      .prepare('DELETE FROM arweave_mirror_failures WHERE resolved_at IS NOT NULL AND resolved_at < ?1')
      .bind(cutoff)
      .run();
    const changes = res?.meta?.changes ?? res?.changes ?? 0;
    return { deleted: Number(changes) || 0, error: null };
  } catch (err) {
    return { deleted: 0, error: err?.message || String(err) };
  }
}
