/**
 * BIP39 account-key helpers — borrowed verbatim from `client/src/recovery.ts`.
 *
 * Validates and decodes 24-word account keys via `@scure/bip39`. The recover
 * package only needs the read side: `validateAccountKey` and
 * `accountKeyToEntropy`. Generation lives in the writer SDK.
 */

import { mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

/** Result of account-key validation. `normalized` is filled even on failure (best-effort). */
export type PhraseValidation =
  | { valid: true; normalized: string }
  | { valid: false; normalized: string; reason: string };

/**
 * Validate a 24-word account key against BIP39 (word membership + checksum).
 * The user-typed key is normalized — leading/trailing whitespace trimmed,
 * internal whitespace collapsed, lowercased — before validation, mirroring
 * the normalization applied during recovery KEK derivation.
 */
export function validateAccountKey(phrase: string): PhraseValidation {
  if (!phrase || typeof phrase !== 'string') {
    return { valid: false, normalized: '', reason: 'account key must be a non-empty string' };
  }
  const normalized = normalizePhrase(phrase);
  const words = normalized.split(' ');
  if (words.length !== 24) {
    return { valid: false, normalized, reason: `expected 24 words, got ${words.length}` };
  }
  if (!validateMnemonic(normalized, wordlist)) {
    return { valid: false, normalized, reason: 'invalid BIP39 mnemonic (word not in list, or checksum mismatch)' };
  }
  return { valid: true, normalized };
}

/**
 * Recover the raw entropy bytes from an account key. The entropy is the
 * canonical seed for `recovery_lookup_key` and any other phrase-derived
 * sub-keys.
 */
export function accountKeyToEntropy(phrase: string): Uint8Array {
  const v = validateAccountKey(phrase);
  if (!v.valid) throw new Error(`Invalid account key: ${v.reason}`);
  return mnemonicToEntropy(v.normalized, wordlist);
}

function normalizePhrase(phrase: string): string {
  // Match the BIP39 spec normalization used in deriveRecoveryKey: NFKD,
  // lowercase, collapse whitespace to single spaces, trim.
  return phrase.normalize('NFKD').toLowerCase().trim().split(/\s+/).join(' ');
}
