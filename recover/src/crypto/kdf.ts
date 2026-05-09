/**
 * KDFs — Argon2id (via `hash-wasm`) + HKDF-Expand (via WebCrypto).
 *
 * Borrowed near-verbatim from `client/src/crypto.ts` lines 191-309. The only
 * adaptation is the import surface — primitives now live in this package's
 * sibling files (`./constants.ts`, `./encoding.ts`, `./types.ts`).
 *
 * Argon2id requires WebAssembly (browser-native or node:vm). Tests run under
 * Node 20+ which supports WASM natively; the real browser path is exercised
 * by Phase 7's bundle smoke test.
 */

import { argon2id as argon2idHash } from 'hash-wasm';

import {
  ARGON2ID_ITERATIONS,
  ARGON2ID_MEMORY_KIB,
  ARGON2ID_PARALLELISM,
  DERIVATION_VERSION,
  KEY_LENGTH_BYTES,
  PROTOCOL_ID,
  RECOVERY_SALT_LEN,
} from './constants.js';
import { bs, concatBytes } from './encoding.js';
import type { Argon2idParams, DataKeyHandles } from './types.js';

/**
 * Normalize a username before using it as a salt input. Pure string op,
 * matches `client/src/crypto.ts` `normalizeUsername` byte-for-byte.
 */
export function normalizeUsername(username: string): string {
  if (!username || typeof username !== 'string') throw new Error('Username is required');
  return username.trim().toLowerCase();
}

/**
 * HKDF-Expand with a single 32-byte output block.
 * Equivalent to: `HMAC-SHA256(prk, info || 0x01)`.
 *
 * @param prk - Pseudorandom key (master_key or phrase entropy)
 * @param purpose - Key purpose: "lookup", "encrypt", "sign", "recovery-lookup", etc.
 * @param appId - App identifier
 * @param counter - HKDF counter (for P-256 retry); defaults to 1
 */
export async function hkdfExpand(
  prk: Uint8Array,
  purpose: string,
  appId: string,
  counter: number = 1,
): Promise<Uint8Array> {
  const encoder = new TextEncoder();

  const hmacKey = await crypto.subtle.importKey(
    'raw', bs(prk), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );

  const info = concatBytes(
    encoder.encode(PROTOCOL_ID + purpose + appId + DERIVATION_VERSION),
    new Uint8Array([counter]),
  );

  const result = await crypto.subtle.sign('HMAC', hmacKey, bs(info));
  return new Uint8Array(result);
}

/**
 * Derive `master_key` from username + password via Argon2id.
 *
 * The master_key is app-independent — app isolation happens in sub-key
 * derivation. Salt = SHA-256(normalizedUsername) so an account's salt is
 * deterministic from its identifier.
 */
export async function deriveMasterKey(
  username: string,
  password: string,
): Promise<Uint8Array> {
  if (!username || !password) throw new Error('Username and password are required');

  const normalizedUsername = normalizeUsername(username);
  const encoder = new TextEncoder();

  const salt = new Uint8Array(
    await crypto.subtle.digest('SHA-256', bs(encoder.encode(normalizedUsername))),
  );

  const out = await argon2idHash({
    password: encoder.encode(password),
    salt,
    parallelism: ARGON2ID_PARALLELISM,
    iterations: ARGON2ID_ITERATIONS,
    memorySize: ARGON2ID_MEMORY_KIB,
    hashLength: KEY_LENGTH_BYTES,
    outputType: 'binary',
  });
  return out instanceof Uint8Array ? out : new Uint8Array(out);
}

/**
 * Derive a recovery KEK from a BIP39 mnemonic phrase + per-account salt
 * (issue #12). The mnemonic is normalized via NFKD + lowercase + single-spaced
 * to match BIP39 seed-derivation rules.
 *
 * Returns AES-GCM and AES-KW handles (same 32 bytes, two WebCrypto views) so
 * the caller can both wrap chain entries with AES-KW and use the raw key for
 * any future per-content operations.
 */
export async function deriveRecoveryKey(
  mnemonic: string,
  salt: Uint8Array,
  params?: Partial<Argon2idParams>,
): Promise<DataKeyHandles> {
  if (!mnemonic || typeof mnemonic !== 'string') {
    throw new Error('mnemonic must be a non-empty string');
  }
  if (!(salt instanceof Uint8Array) || salt.length !== RECOVERY_SALT_LEN) {
    throw new Error(`salt must be a Uint8Array of length ${RECOVERY_SALT_LEN}`);
  }
  const memorySize = params?.m_kib ?? ARGON2ID_MEMORY_KIB;
  const iterations = params?.t ?? ARGON2ID_ITERATIONS;
  const parallelism = params?.p ?? ARGON2ID_PARALLELISM;

  const normalized = mnemonic.normalize('NFKD').toLowerCase().trim().split(/\s+/).join(' ');

  const out = await argon2idHash({
    password: new TextEncoder().encode(normalized),
    salt,
    parallelism,
    iterations,
    memorySize,
    hashLength: KEY_LENGTH_BYTES,
    outputType: 'binary',
  });
  const rawBytes = out instanceof Uint8Array ? out : new Uint8Array(out);

  const [gcmKey, kwKey] = await Promise.all([
    crypto.subtle.importKey('raw', bs(rawBytes), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', bs(rawBytes), 'AES-KW', true, ['wrapKey', 'unwrapKey']),
  ]);

  return { gcmKey, kwKey, rawBytes };
}

/**
 * Derive the credential encryption key (DEK-wrapping KEK on the password
 * factor) from `master_key` for a specific app. Returns both an AES-GCM key
 * (for legacy data encryption) and an AES-KW key (for unwrapping chain
 * entries). Same raw bytes, two WebCrypto usages.
 */
export async function deriveCredentialEncryptionKey(
  masterKey: Uint8Array,
  appId: string,
): Promise<DataKeyHandles> {
  if (!appId) throw new Error('appId is required');
  const keyBytes = await hkdfExpand(masterKey, 'encrypt', appId);

  const [gcmKey, kwKey] = await Promise.all([
    crypto.subtle.importKey('raw', bs(keyBytes), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', bs(keyBytes), 'AES-KW', true, ['wrapKey', 'unwrapKey']),
  ]);

  return { gcmKey, kwKey, rawBytes: keyBytes };
}
