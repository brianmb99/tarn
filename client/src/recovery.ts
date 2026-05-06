// Tarn Client — Account-key primitive (issue #12)
//
// BIP39-style account-key generation, validation, and entropy extraction.
// All operations are client-side — the Tarn API never sees the account key
// or the entropy. Apps that want to render a kit (PDF, JSON, printable
// HTML, etc.) do so themselves; the SDK ships only the primitives.

import { generateMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

// 24-word account key = 256 bits of entropy. Per the design doc this is the
// stronger choice over 12-word; the account key is the user's permanent
// vault key and we want the entropy budget to be comfortable.
const PHRASE_STRENGTH_BITS = 256;

// ============ ACCOUNT KEY GENERATION + VALIDATION ============

/**
 * Generate a fresh 24-word BIP39 mnemonic account key using cryptographically
 * secure randomness. Returns a single space-separated string.
 */
export function generateAccountKey(): string {
  return generateMnemonic(wordlist, PHRASE_STRENGTH_BITS);
}

/** Result of account-key validation. `normalized` is filled even on failure (best-effort). */
export type PhraseValidation =
  | { valid: true; normalized: string }
  | { valid: false; normalized: string; reason: string };

/**
 * Validate an account key against the BIP39 English wordlist (word membership +
 * checksum). The user-typed key is normalized — leading/trailing
 * whitespace trimmed, internal whitespace collapsed, lowercased — before
 * validation, mirroring the normalization applied during recovery KEK
 * derivation.
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
 * Recover the raw entropy bytes from an account key. Useful for tests and for
 * sharing-protocol §14.11 work where the account key will derive an
 * additional sub-key — the entropy is the canonical seed, not the derived
 * recovery KEK.
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
