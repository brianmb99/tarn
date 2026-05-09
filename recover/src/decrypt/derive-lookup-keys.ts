/**
 * Lookup-key derivations.
 *
 * The Tarn API stores credential blobs keyed by EITHER:
 *   - `credential_lookup_key` (Lk) — derived from `(username, password)` via
 *     Argon2id master_key → HKDF-Expand("lookup", appId).
 *   - `recovery_lookup_key` (RLk) — derived from the account-key entropy
 *     alone via HKDF-Expand("recovery-lookup", appId). No salt; no password.
 *
 * Both lookups land at the same credential blob — the only difference is
 * which gateway-side tag the GraphQL query filters on.
 *
 * Borrowed near-verbatim from `client/src/crypto.ts` lines 311-331; the only
 * adaptation is the import surface (sibling files in this package).
 */

import { bytesToHex } from '../crypto/encoding.js';
import { deriveMasterKey, hkdfExpand } from '../crypto/kdf.js';
import { accountKeyToEntropy } from '../crypto/bip39.js';

/** Derive `credential_lookup_key` from `(username, password)` for an app. */
export async function deriveCredentialLookupKey(
  username: string,
  password: string,
  appId: string,
): Promise<string> {
  if (!appId) throw new Error('appId is required');
  const masterKey = await deriveMasterKey(username, password);
  const hash = await hkdfExpand(masterKey, 'lookup', appId);
  return bytesToHex(hash);
}

/** Derive `recovery_lookup_key` from a 24-word account key for an app. */
export async function deriveRecoveryLookupKey(
  accountKey: string,
  appId: string,
): Promise<string> {
  if (!appId) throw new Error('appId is required');
  const entropy = accountKeyToEntropy(accountKey);
  const hash = await hkdfExpand(entropy, 'recovery-lookup', appId);
  return bytesToHex(hash);
}
