// PRF extension repair — workaround for @simplewebauthn round-trip bug.
//
// `@simplewebauthn/server@13.x` does not transform buffer values inside
// `extensions` when generating registration / authentication options. The
// Tarn API hands it `extensions.prf.eval.first` (and
// `extensions.prf.evalByCredential[*].first`) as `Uint8Array`. Those
// arrays JSON-serialize to `{"0":n,"1":n,...}` (numeric-keyed object) on
// the wire instead of base64url.
//
// `@simplewebauthn/browser@13.x` also does not transform extension
// buffers on the client side — `startRegistration` / `startAuthentication`
// pass `extensions` through to `navigator.credentials.create()` /
// `.get()` verbatim. The browser then validates that
// `extensions.prf.eval.first` is `ArrayBuffer` / `ArrayBufferView`, sees
// a plain object, and throws.
//
// The fix is purely client-side: walk the extensions payload after
// receiving it and turn numeric-keyed objects back into `Uint8Array`.
// Idempotent — already-correct `Uint8Array` values are passed through.
//
// See https://github.com/brianmb99/tarn/issues/24 for the full root-cause
// analysis. Out of scope: other extensions that might have the same
// problem (largeBlob, credBlob, etc.) — Tarn currently only uses `prf`.

/**
 * Detect a `{"0":n,"1":n,...}` plain object that should be a `Uint8Array`
 * and rebuild the byte array. Throws if the object has no usable numeric
 * keys (defensive: a totally-empty object isn't a valid PRF salt).
 *
 * Exported separately so it can be unit-tested in isolation.
 */
export function numericObjectToBytes(obj: Record<string, number>): Uint8Array {
  const keys = Object.keys(obj)
    .map(Number)
    .filter((k) => Number.isInteger(k) && k >= 0);
  if (keys.length === 0) {
    throw new Error('PRF eval value: not a numeric-keyed byte map');
  }
  const max = Math.max(...keys);
  const out = new Uint8Array(max + 1);
  for (const k of keys) out[k] = obj[String(k)]! & 0xff;
  return out;
}

/**
 * Mutates `extensions` in place to convert any numeric-keyed-object PRF
 * eval values back into `Uint8Array`. Safe to call on:
 *
 *   - `undefined` / `null` extensions (returns input as-is)
 *   - extensions without a `prf` field (returns input as-is)
 *   - extensions with `prf.eval.first` already a `Uint8Array` (no-op)
 *   - extensions with `prf.evalByCredential[credId].first` already a
 *     `Uint8Array` (no-op per credential)
 *
 * Returns the same reference for convenience in fluent call sites.
 *
 * Why mutate rather than clone: the call site passes
 * `pkOptions.extensions` straight into `startRegistration` /
 * `startAuthentication`. Cloning would force callers to reassign the
 * whole field; mutation matches the existing pattern where the lib
 * mutates `options` while filling in defaults.
 */
export function repairPrfExtensionBuffers<T>(extensions: T): T {
  const ext = extensions as any;
  if (!ext || typeof ext !== 'object') return extensions;
  if (!ext.prf || typeof ext.prf !== 'object') return extensions;

  // eval.first
  const evalObj = ext.prf.eval;
  if (evalObj && typeof evalObj === 'object' && evalObj.first != null) {
    if (!ArrayBuffer.isView(evalObj.first)) {
      evalObj.first = numericObjectToBytes(evalObj.first);
    }
  }

  // evalByCredential[credId].first
  const ebc = ext.prf.evalByCredential;
  if (ebc && typeof ebc === 'object') {
    for (const credId of Object.keys(ebc)) {
      const entry = ebc[credId];
      if (entry && typeof entry === 'object' && entry.first != null) {
        if (!ArrayBuffer.isView(entry.first)) {
          entry.first = numericObjectToBytes(entry.first);
        }
      }
    }
  }

  return extensions;
}
