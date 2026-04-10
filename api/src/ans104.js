// ans104.js — Server-side ANS-104 DataItem construction and signing
// Signs with the app's Ethereum-compatible wallet (secp256k1, signature type 3).
// Ported from Bookish's ans104_signer.js for server-side use.
//
// The app wallet is stored as a Worker secret (APP_SIGNING_KEY).
// Turbo accepts Ethereum-signed DataItems and bills the signing wallet's Turbo balance.

import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

const SIG_TYPE = 3;     // Ethereum
const SIG_LEN = 65;     // r(32) + s(32) + v(1)
const OWNER_LEN = 65;   // uncompressed secp256k1 public key (04 || x || y)
const enc = new TextEncoder();

// ============ HELPERS ============

function hexToBytes(hex) {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function concat(...arrays) {
  let len = 0;
  for (const a of arrays) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

// ============ AVRO TAG SERIALIZATION (ANS-104 spec) ============

// NOTE: Uses 32-bit signed shift for zigzag encoding. Correct for n < 2^30 (~1GB).
// For n >= 2^30 the encoding silently produces wrong results due to JS 32-bit bitwise ops.
// This is safe in Tarn because MAX_UPLOAD_BYTES = 100KB, so n never approaches this limit.
function avroLong(n) {
  let z = (n << 1) ^ (n >> 31);
  const buf = [];
  while ((z & ~0x7f) !== 0) { buf.push((z & 0x7f) | 0x80); z >>>= 7; }
  buf.push(z & 0x7f);
  return new Uint8Array(buf);
}

function serializeTags(tags) {
  if (!tags || tags.length === 0) return new Uint8Array(0);
  const parts = [avroLong(tags.length)];
  for (const { name, value } of tags) {
    const nb = enc.encode(name), vb = enc.encode(value);
    parts.push(avroLong(nb.length), nb, avroLong(vb.length), vb);
  }
  parts.push(new Uint8Array([0]));
  return concat(...parts);
}

// ============ DEEP HASH (SHA-384, per ANS-104 spec) ============

async function sha384(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-384', data));
}

async function deepHash(data) {
  if (data instanceof Uint8Array) {
    const tag = await sha384(concat(enc.encode('blob'), enc.encode(String(data.byteLength))));
    return sha384(concat(tag, await sha384(data)));
  }
  let acc = await sha384(concat(enc.encode('list'), enc.encode(String(data.length))));
  for (const chunk of data) acc = await sha384(concat(acc, await deepHash(chunk)));
  return acc;
}

// ============ EIP-191 HASH ============

function eip191Hash(message) {
  const prefix = enc.encode(`\x19Ethereum Signed Message:\n${message.length}`);
  return keccak_256(concat(prefix, message));
}

// ============ PUBLIC API ============

/**
 * Create a signed ANS-104 DataItem using the app's Ethereum-compatible wallet.
 * Compatible with Turbo's /v1/tx signed data item endpoint.
 *
 * @param {string} privateKeyHex - App wallet private key (hex, with or without 0x)
 * @param {Uint8Array} data - Payload bytes (already encrypted by the client)
 * @param {Array<{name: string, value: string}>} tags - Arweave tags
 * @returns {Promise<Uint8Array>} Raw signed DataItem bytes ready for Turbo upload
 */
export async function createSignedDataItem(privateKeyHex, data, tags) {
  const pk = hexToBytes(privateKeyHex);
  const owner = secp256k1.getPublicKey(pk, false); // uncompressed, 65 bytes
  const tagBytes = serializeTags(tags);
  const payload = data instanceof Uint8Array ? data : new Uint8Array(data);

  // Deep hash per ANS-104 spec
  const signData = await deepHash([
    enc.encode('dataitem'), enc.encode('1'), enc.encode(String(SIG_TYPE)),
    owner,
    new Uint8Array(0),  // target (none)
    new Uint8Array(0),  // anchor (none)
    tagBytes,
    payload,
  ]);

  // EIP-191 sign the deep hash
  const digest = eip191Hash(signData);
  const sig = secp256k1.sign(digest, pk);
  const signature = concat(sig.toCompactRawBytes(), new Uint8Array([sig.recovery + 27]));

  // Binary layout: sigType(2 LE) | sig(65) | owner(65) | target?(1) | anchor?(1) | nTags(8 LE) | tagLen(8 LE) | tags | data
  const numTags = tags ? tags.length : 0;
  const hdrLen = 2 + SIG_LEN + OWNER_LEN + 1 + 1 + 8 + 8;
  const hdr = new ArrayBuffer(hdrLen);
  const v = new DataView(hdr);
  let p = 0;
  v.setUint16(p, SIG_TYPE, true);                                     p += 2;
  new Uint8Array(hdr, p, SIG_LEN).set(signature);                     p += SIG_LEN;
  new Uint8Array(hdr, p, OWNER_LEN).set(owner);                       p += OWNER_LEN;
  v.setUint8(p, 0);                                                   p += 1; // no target
  v.setUint8(p, 0);                                                   p += 1; // no anchor
  v.setUint32(p, numTags, true); v.setUint32(p + 4, 0, true);        p += 8;
  v.setUint32(p, tagBytes.length, true); v.setUint32(p + 4, 0, true);

  return concat(new Uint8Array(hdr), tagBytes, payload);
}

/**
 * Compute the DataItem ID (Arweave transaction ID) from signed DataItem bytes.
 * The ID is the base64url-encoded SHA-256 hash of the signature.
 * @param {Uint8Array} signedDataItem - Full signed DataItem bytes
 * @returns {Promise<string>} Base64url-encoded transaction ID (43 chars)
 */
export async function computeDataItemId(signedDataItem) {
  // DataItem layout: sigType(2) | signature(65) | ...
  // The ID is SHA-256 of the signature bytes
  const signature = signedDataItem.slice(2, 2 + SIG_LEN);
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', signature));
  return base64url(hash);
}

function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Derive the Ethereum address from a private key (for logging/debugging).
 * @param {string} privateKeyHex
 * @returns {string} Checksummed Ethereum address (0x-prefixed)
 */
export function getAddress(privateKeyHex) {
  const pk = hexToBytes(privateKeyHex);
  const pubKey = secp256k1.getPublicKey(pk, false).slice(1); // remove 04 prefix
  const hash = keccak_256(pubKey);
  const addr = Array.from(hash.slice(-20)).map(b => b.toString(16).padStart(2, '0')).join('');
  return '0x' + addr;
}
