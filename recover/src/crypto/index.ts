/**
 * Public surface of the borrowed crypto primitives.
 *
 * All code in `./` is borrowed near-verbatim from `client/src/crypto.ts` and
 * `client/src/recovery.ts` — pure WebCrypto / `@noble`-free / `hash-wasm`
 * code with zero `TarnClient` coupling. The cross-validation tests in
 * `tests/crypto-cross-validate.test.ts` enforce byte-equality with the
 * client-side originals so the two copies cannot drift.
 *
 * Phase 6 (forward-compat decoder framework) will introduce envelope `v: 2`
 * alongside the v1 unwrap path. The current shape of `parseWrappedDataKey`
 * + `unwrapDataKeyChain` already dispatches on `parsed.v`, so that
 * extension lands cleanly without disturbing v1 consumers.
 */

export * from './constants.js';
export * from './encoding.js';
export * from './types.js';
export * from './kdf.js';
export * from './aes.js';
export * from './envelope.js';
export * from './bip39.js';
