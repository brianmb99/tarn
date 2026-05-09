/**
 * Per-app X25519 sharing keypair derivation — borrowed from
 * `client/src/crypto.ts` (`deriveSharingKeyPair`).
 *
 * The seed is `HKDF-Expand(master_key, "tarn"||"share"||app_id||"1"||0x01)` —
 * same single-block info pattern as the lookup/encrypt/sign sub-keys. Per-app
 * isolation: the same `(username, password)` registered to two different apps
 * produces distinct sharing keypairs.
 *
 * **Recoverability caveat.** This derivation requires `master_key`, which
 * requires `(username, password)`. The recovery package's account-key path
 * does not have access to either, so the sharing keypair is NOT derivable
 * from the account-key alone. Callers using
 * `credentials: { type: 'accountKey', ... }` see an empty connections list /
 * empty share-log; the `password` factor is the path that lights up the
 * sharing surface. This matches an architectural property of the protocol —
 * `share_priv` is rotated whenever credentials change, and the new
 * `share_priv` is only ever derivable from the new `master_key`. (See
 * `client/src/tarn.ts` `recoverAccount` 528-820: the live SDK rotates
 * `share_priv` as part of recovery and accepts that prior `share_priv` is
 * lost.)
 */

import { x25519 } from '@noble/curves/ed25519';

import { hkdfExpand } from './kdf.js';

const X25519_KEY_LEN = 32;

export type SharingKeyPair = {
  /** 32 raw bytes (X25519 private key). */
  privateKey: Uint8Array;
  /** 32 raw bytes (X25519 public key). */
  publicKey: Uint8Array;
};

/**
 * Derive the per-app X25519 sharing keypair from `master_key`.
 *
 * Throws if `appId` is empty or the HKDF output isn't 32 bytes (which would
 * indicate a corrupted dependency, not a runtime input issue).
 */
export async function deriveSharingKeyPair(
  masterKey: Uint8Array,
  appId: string,
): Promise<SharingKeyPair> {
  if (!appId) throw new Error('appId is required');
  if (!(masterKey instanceof Uint8Array) || masterKey.length !== 32) {
    throw new Error('masterKey must be a 32-byte Uint8Array');
  }
  const seed = await hkdfExpand(masterKey, 'share', appId);
  if (seed.length !== X25519_KEY_LEN) {
    throw new Error(`sharing seed length ${seed.length} != ${X25519_KEY_LEN}`);
  }
  const publicKey = x25519.getPublicKey(seed);
  return { privateKey: seed, publicKey };
}
