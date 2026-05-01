/**
 * Deterministic Entry-Id (Eid) derivation for collection records.
 *
 * Eid is the Arweave-tag-level identifier that groups all entries belonging
 * to a single logical record (initial write, updates, tombstone). The Tarn
 * API's resolver dedups by Eid + Prev so reads return one entry per logical
 * record regardless of how many updates have happened.
 *
 * Deriving Eid deterministically from `(appId, collection, primaryKey)` —
 * rather than generating a random Eid on each create — is what makes
 * cross-device identity work. If two devices both call `tarn.books.create({
 * bookId: 'b1', ... })` independently, they produce the same Eid, and the
 * resolver collapses them to one record on read.
 *
 * The hash is namespaced (`tarn-eid|...`) so values cannot be confused with
 * any other use of SHA-256 in the codebase. Truncated to 16 bytes / base64url
 * (≈22 characters) to keep Arweave tag values short while preserving
 * collision resistance well beyond any realistic record count.
 */

const EID_BYTES = 16;
const EID_NAMESPACE = 'tarn-eid';

export async function deriveEid(
  appId: string,
  collection: string,
  primaryKey: string,
): Promise<string> {
  const input = `${EID_NAMESPACE}|${appId}|${collection}|${primaryKey}`;
  const data = new TextEncoder().encode(input);
  const fullHash = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  const truncated = fullHash.slice(0, EID_BYTES);
  return bytesToBase64Url(truncated);
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]!);
  }
  // btoa works in browsers, Cloudflare Workers, and Node 16+. Convert
  // standard base64 to URL-safe form (no padding, no +/).
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
