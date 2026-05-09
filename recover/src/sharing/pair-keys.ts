/**
 * Decoupled per-pair key derivation — extracted from
 * `TarnClient.#getPairKeysFor` (`client/src/tarn.ts` ~4002).
 *
 * The original is a thin wrapper around `deriveSharedSecret` + `derivePairKeys`
 * that pulls `share_priv` / `share_pub` off the TarnClient instance. The
 * recover-client equivalent accepts those bytes as parameters so the
 * orchestrator (which has them in hand from the unwrapped envelope) can keep
 * the per-connection cache locally.
 */

import {
  derivePairKeys,
  deriveSharedSecret,
  type PairKeys,
} from './share-log-primitives.js';
import { base64UrlToBytes } from '../crypto/encoding.js';

/**
 * Derive both directions of per-pair keys for a given connection. Self-inputs
 * are the recovered user's `(share_priv, share_pub)`; the peer input is the
 * connection's `share_pub` as base64url (the wire format used in connection
 * records).
 */
export async function getPairKeysFor(opts: {
  selfSharePriv: Uint8Array;
  selfSharePub: Uint8Array;
  peerSharePubBase64Url: string;
  appId: string;
}): Promise<PairKeys & { sharedSecret: Uint8Array }> {
  if (!(opts.selfSharePriv instanceof Uint8Array) || opts.selfSharePriv.length !== 32) {
    throw new Error('getPairKeysFor: selfSharePriv must be a 32-byte Uint8Array');
  }
  if (!(opts.selfSharePub instanceof Uint8Array) || opts.selfSharePub.length !== 32) {
    throw new Error('getPairKeysFor: selfSharePub must be a 32-byte Uint8Array');
  }
  if (typeof opts.peerSharePubBase64Url !== 'string' || opts.peerSharePubBase64Url.length === 0) {
    throw new Error('getPairKeysFor: peerSharePubBase64Url is required');
  }
  if (typeof opts.appId !== 'string' || opts.appId.length === 0) {
    throw new Error('getPairKeysFor: appId is required');
  }

  const peerSharePub = base64UrlToBytes(opts.peerSharePubBase64Url);
  if (peerSharePub.length !== 32) {
    throw new Error(`getPairKeysFor: peer share_pub must decode to 32 bytes, got ${peerSharePub.length}`);
  }
  const sharedSecret = deriveSharedSecret(opts.selfSharePriv, peerSharePub);
  const keys = await derivePairKeys({
    sharedSecret,
    appId: opts.appId,
    selfSharePub: opts.selfSharePub,
    peerSharePub,
  });
  return { sharedSecret, ...keys };
}
