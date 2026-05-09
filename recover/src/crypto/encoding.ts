/**
 * Encoding helpers — borrowed verbatim from `client/src/crypto.ts`.
 *
 * Hex / base64 / base64url. All pure, no WebCrypto, no environment
 * assumptions beyond `btoa`/`atob` (present in browsers and modern Node).
 */

export function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlToBytes(b64url: string): Uint8Array {
  const padded = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  return base64ToBytes(padded + '='.repeat(padLen));
}

/**
 * WebCrypto BufferSource helper — TS 5.x narrowed `BufferSource` to require
 * an `ArrayBuffer`-not-`SharedArrayBuffer` backing buffer. Modern lib types
 * say `Uint8Array<ArrayBufferLike>`, which doesn't satisfy that constraint
 * at the type level (runtime is fine — both work). Single helper avoids
 * `as BufferSource` at every call site.
 */
export function bs(b: ArrayBufferView | ArrayBuffer): BufferSource {
  return b as BufferSource;
}
