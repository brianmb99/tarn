/**
 * AES primitives — borrowed verbatim from `client/src/crypto.ts`.
 *
 * Includes:
 *   - AES-256-GCM decrypt for legacy/raw-DEK blobs.
 *   - AES-KW unwrap for raw chain entries.
 *   - Per-content CEK blob decode (TARN-magic v3).
 *   - `wrapped_account_key` AAD'd unwrap (Phase 3 — Model B).
 *
 * Pure WebCrypto — no environment assumptions beyond the global `crypto`.
 */

import {
  CEK_LEN_BYTES,
  GCM_TAG_LEN_BYTES,
  IV_LEN_BYTES,
  TARN_BLOB_MAGIC,
  TARN_WRAPPED_CEK_LEN,
  WRAPPED_ACCOUNT_KEY_AAD,
} from './constants.js';
import { base64ToBytes, base64UrlToBytes, bs } from './encoding.js';

const MIN_NEW_FORMAT_LEN =
  TARN_BLOB_MAGIC.length + TARN_WRAPPED_CEK_LEN + IV_LEN_BYTES + GCM_TAG_LEN_BYTES;

/**
 * Detect whether a blob has the per-content-CEK magic prefix. Cheap O(1)
 * check; safe on legacy blobs (legacy AES-GCM IVs are random 12-byte values
 * — collision with the 5-byte magic has probability 2^-40).
 */
export function hasTarnBlobMagic(blob: Uint8Array): boolean {
  if (!(blob instanceof Uint8Array) || blob.length < TARN_BLOB_MAGIC.length) {
    return false;
  }
  for (let i = 0; i < TARN_BLOB_MAGIC.length; i++) {
    if (blob[i] !== TARN_BLOB_MAGIC[i]) return false;
  }
  return true;
}

/** Decrypt AES-256-GCM bytes to JSON. Wire: IV(12) || ciphertext+tag. */
export async function decrypt(key: CryptoKey, blob: Uint8Array): Promise<unknown> {
  if (blob.length < 13) throw new Error('Blob too short');
  const iv = blob.slice(0, 12);
  const ciphertext = blob.slice(12);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bs(iv) }, key, bs(ciphertext));
  return JSON.parse(new TextDecoder().decode(decrypted));
}

/**
 * Unwrap data_encryption_key from raw AES-KW ciphertext (no envelope handling).
 * Use {@link import('./envelope.js').unwrapDekChain} for the wire format.
 */
export async function unwrapDataKey(wrappedBase64: string, unwrappingKey: CryptoKey): Promise<CryptoKey> {
  const wrapped = base64ToBytes(wrappedBase64);
  return await crypto.subtle.unwrapKey(
    'raw', bs(wrapped), unwrappingKey, 'AES-KW',
    { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'],
  );
}

/**
 * Decrypt a per-content CEK blob using a DEK from the chain.
 *
 * Layout: magic(5) || wrapped_CEK(40) || iv(12) || ciphertext+tag.
 *
 * The DEK unwraps the per-blob CEK via AES-KW; the CEK then decrypts the
 * payload via AES-GCM.
 */
export async function decryptWithCEK(dek: CryptoKey, blob: Uint8Array): Promise<unknown> {
  if (!hasTarnBlobMagic(blob)) {
    throw new Error('Blob does not have TARN magic prefix');
  }
  if (blob.length < MIN_NEW_FORMAT_LEN) {
    throw new Error(`Blob too short for new format: ${blob.length} < ${MIN_NEW_FORMAT_LEN}`);
  }

  const wrappedCEK = blob.slice(
    TARN_BLOB_MAGIC.length,
    TARN_BLOB_MAGIC.length + TARN_WRAPPED_CEK_LEN,
  );
  const ivStart = TARN_BLOB_MAGIC.length + TARN_WRAPPED_CEK_LEN;
  const iv = blob.slice(ivStart, ivStart + IV_LEN_BYTES);
  const ciphertextAndTag = blob.slice(ivStart + IV_LEN_BYTES);

  const cekGcm = await crypto.subtle.unwrapKey(
    'raw', bs(wrappedCEK), dek, 'AES-KW',
    { name: 'AES-GCM' }, false, ['decrypt'],
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bs(iv) }, cekGcm, bs(ciphertextAndTag),
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}

/**
 * Decrypt a per-content CEK blob using a shareKey directly (skipping the
 * wrapped CEK slot). The recipient path: a friend has fetched the shareKey
 * via the share-log and the blob bytes via the gateway, but does NOT have
 * the writer's DEK to unwrap the in-blob slot.
 *
 * Layout: magic(5) || wrapped_CEK(40) || iv(12) || ciphertext+tag.
 */
export async function decryptBlobWithSharedCEK(
  blob: Uint8Array,
  shareKeyBase64Url: string,
): Promise<unknown> {
  if (!hasTarnBlobMagic(blob)) {
    throw new Error('Blob does not have TARN magic prefix');
  }
  if (blob.length < MIN_NEW_FORMAT_LEN) {
    throw new Error(`Blob too short for new format: ${blob.length} < ${MIN_NEW_FORMAT_LEN}`);
  }

  const cekBytes = base64UrlToBytes(shareKeyBase64Url);
  if (cekBytes.length !== CEK_LEN_BYTES) {
    throw new Error(`shareKey must be ${CEK_LEN_BYTES} raw bytes; got ${cekBytes.length}`);
  }

  const cekGcm = await crypto.subtle.importKey(
    'raw', bs(cekBytes), { name: 'AES-GCM' }, false, ['decrypt'],
  );

  const ivStart = TARN_BLOB_MAGIC.length + TARN_WRAPPED_CEK_LEN;
  const iv = blob.slice(ivStart, ivStart + IV_LEN_BYTES);
  const ciphertextAndTag = blob.slice(ivStart + IV_LEN_BYTES);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bs(iv) }, cekGcm, bs(ciphertextAndTag),
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}

/**
 * Decrypt the `wrapped_account_key` blob under the supplied DEK with the
 * fixed AAD (`tarn-wrapped-account-key-v1`). Returns the recovered
 * 24-word account-key string.
 *
 * Throws on AAD mismatch or any other AES-GCM failure.
 */
export async function unwrapAccountKey(
  dekGcm: CryptoKey,
  wrappedBase64: string,
): Promise<string> {
  if (typeof wrappedBase64 !== 'string' || wrappedBase64.length === 0) {
    throw new Error('unwrapAccountKey: wrappedBase64 must be a non-empty string');
  }
  const blob = base64ToBytes(wrappedBase64);
  if (blob.length < 12 + 16) {
    throw new Error('unwrapAccountKey: wrapped blob too short');
  }
  const iv = blob.slice(0, 12);
  const ciphertext = blob.slice(12);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bs(iv), additionalData: bs(WRAPPED_ACCOUNT_KEY_AAD) },
    dekGcm,
    bs(ciphertext),
  );
  return new TextDecoder().decode(plaintext);
}
