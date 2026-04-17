// Idempotency key support for retry-safe writes (#8).
//
// Writes aren't naturally idempotent: each retry produces a new server-signed
// DataItem with a new txid, polluting Arweave. Clients mitigate this by sending
// a stable X-Idempotency-Key header for each logical write; the server returns
// the original response on any retry within the TTL.

const HEADER = 'X-Idempotency-Key';
const TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const MIN_LEN = 16;
const MAX_LEN = 128;
const VALID_RE = /^[\x20-\x7E]+$/; // printable ASCII

/**
 * Read and validate the idempotency key from the request.
 * @returns {{ key: string|null, error: string|null }}
 *   - If no header: { key: null, error: null } — caller proceeds without idempotency.
 *   - If present and valid: { key, error: null }.
 *   - If present but invalid: { key: null, error: 'message' } — caller returns 400.
 */
export function readIdempotencyKey(request) {
  const raw = request.headers.get(HEADER);
  if (!raw) return { key: null, error: null };
  if (raw.length < MIN_LEN || raw.length > MAX_LEN) {
    return { key: null, error: `${HEADER} must be ${MIN_LEN}–${MAX_LEN} chars` };
  }
  if (!VALID_RE.test(raw)) {
    return { key: null, error: `${HEADER} must be printable ASCII` };
  }
  return { key: raw, error: null };
}

function scopedKey(dataLookupKey, clientKey) {
  return `${dataLookupKey}:${clientKey}`;
}

/**
 * Look up a prior response for this idempotency key. Returns null if not present
 * or expired. Opportunistically purges expired rows on each lookup.
 * @returns {Promise<{status: number, body: object}|null>}
 */
export async function lookupIdempotentResponse(db, dataLookupKey, clientKey) {
  const now = Date.now();
  const cutoff = now - TTL_MS;

  // Lazy cleanup — delete expired rows. Cheap: the index on created_at makes this O(n_expired).
  // Fire-and-forget relative to the main lookup: we don't need to await it before responding.
  // But D1 doesn't support background SQL well in Workers, so just await it — the cost is
  // bounded by the cleanup rate and the total row count tracks TTL × write rate.
  await db.prepare('DELETE FROM idempotency_keys WHERE created_at < ?1').bind(cutoff).run();

  const row = await db.prepare(
    'SELECT response_json, status_code FROM idempotency_keys WHERE scoped_key = ?1'
  ).bind(scopedKey(dataLookupKey, clientKey)).first();

  if (!row) return null;

  try {
    return { status: row.status_code, body: JSON.parse(row.response_json) };
  } catch {
    // Corrupt row — treat as miss. The actual write will overwrite it.
    return null;
  }
}

/**
 * Combined idempotency resolution for a write handler. Call after auth + rate
 * limit but before any Turbo/Arweave work.
 *
 * Returns one of:
 *   - { error: 'message' } — header was present but malformed. Handler should return 400.
 *   - { cached: { status, body } } — a prior response exists and should be returned verbatim.
 *   - { key: null } — no header; proceed without idempotency.
 *   - { key: 'k' } — header valid, no prior response. Proceed; on success, call
 *     storeIdempotentResponse with this key.
 */
export async function resolveIdempotency(request, db, dataLookupKey) {
  const { key, error } = readIdempotencyKey(request);
  if (error) return { error };
  if (!key) return { key: null };
  const cached = await lookupIdempotentResponse(db, dataLookupKey, key);
  if (cached) return { cached };
  return { key };
}

/**
 * Persist a successful response under an idempotency key so future retries
 * return the same answer. Called only on full success (Turbo accepted AND
 * D1 write-through committed).
 */
export async function storeIdempotentResponse(db, dataLookupKey, clientKey, status, body) {
  await db.prepare(
    `INSERT INTO idempotency_keys (scoped_key, response_json, status_code, created_at)
     VALUES (?1, ?2, ?3, ?4)
     ON CONFLICT(scoped_key) DO UPDATE SET
       response_json = excluded.response_json,
       status_code = excluded.status_code,
       created_at = excluded.created_at`
  ).bind(scopedKey(dataLookupKey, clientKey), JSON.stringify(body), status, Date.now()).run();
}
