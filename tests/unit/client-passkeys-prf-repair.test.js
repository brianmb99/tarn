// Unit tests for client/src/passkeys/prf.ts — PRF extension buffer repair.
//
// Covers the four acceptance cases from issue #24:
//   - nominal repair of extensions.prf.eval.first numeric-keyed object
//   - repair of extensions.prf.evalByCredential[credId].first per credential
//   - idempotency: an already-correct Uint8Array passes through unchanged
//   - null / undefined / missing prf — no throw, returned as-is
//
// Plus a couple of defensive cases:
//   - numericObjectToBytes on an empty object throws
//   - the helper returns the same reference it was given
//
// Run: node --import tsx --test tests/unit/client-passkeys-prf-repair.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  repairPrfExtensionBuffers,
  numericObjectToBytes,
} from '../../client/src/passkeys/prf.js';

describe('numericObjectToBytes', () => {
  it('reconstructs a Uint8Array from a {"0":n,"1":n,...} object', () => {
    const obj = { 0: 1, 1: 2, 2: 3, 3: 255 };
    const out = numericObjectToBytes(obj);
    assert.ok(out instanceof Uint8Array, 'expected Uint8Array');
    assert.equal(out.length, 4);
    assert.deepEqual(Array.from(out), [1, 2, 3, 255]);
  });

  it('masks values to 8 bits (defensive)', () => {
    // If the wire happens to carry an out-of-range value, mask rather
    // than throw — Uint8Array storage would do this anyway, this just
    // makes the behavior explicit.
    const obj = { 0: 256, 1: 257 };
    const out = numericObjectToBytes(obj);
    assert.deepEqual(Array.from(out), [0, 1]);
  });

  it('throws on an empty object (not a valid PRF salt)', () => {
    assert.throws(() => numericObjectToBytes({}), /numeric-keyed byte map/);
  });

  it('ignores non-numeric keys but uses the numeric ones', () => {
    const obj = { 0: 10, 1: 20, 2: 30, length: 999, foo: 1 };
    const out = numericObjectToBytes(obj);
    assert.deepEqual(Array.from(out), [10, 20, 30]);
  });
});

describe('repairPrfExtensionBuffers', () => {
  it('repairs prf.eval.first when it is a numeric-keyed object', () => {
    const ext = {
      prf: { eval: { first: { 0: 1, 1: 2, 2: 3 } } },
    };
    repairPrfExtensionBuffers(ext);
    assert.ok(
      ext.prf.eval.first instanceof Uint8Array,
      'expected eval.first to be Uint8Array after repair',
    );
    assert.deepEqual(Array.from(ext.prf.eval.first), [1, 2, 3]);
  });

  it('repairs every entry in prf.evalByCredential', () => {
    const ext = {
      prf: {
        evalByCredential: {
          'credA-id': { first: { 0: 5, 1: 6, 2: 7 } },
          'credB-id': { first: { 0: 99, 1: 100 } },
        },
      },
    };
    repairPrfExtensionBuffers(ext);
    assert.ok(ext.prf.evalByCredential['credA-id'].first instanceof Uint8Array);
    assert.deepEqual(
      Array.from(ext.prf.evalByCredential['credA-id'].first),
      [5, 6, 7],
    );
    assert.ok(ext.prf.evalByCredential['credB-id'].first instanceof Uint8Array);
    assert.deepEqual(
      Array.from(ext.prf.evalByCredential['credB-id'].first),
      [99, 100],
    );
  });

  it('is idempotent — a real Uint8Array is passed through unchanged', () => {
    const buf = new Uint8Array([10, 20, 30]);
    const ext = {
      prf: { eval: { first: buf } },
    };
    repairPrfExtensionBuffers(ext);
    assert.strictEqual(
      ext.prf.eval.first,
      buf,
      'expected same Uint8Array reference (no re-allocation)',
    );
    assert.deepEqual(Array.from(ext.prf.eval.first), [10, 20, 30]);
  });

  it('is idempotent across both shapes simultaneously', () => {
    const evalBuf = new Uint8Array([1, 2]);
    const credBuf = new Uint8Array([3, 4]);
    const ext = {
      prf: {
        eval: { first: evalBuf },
        evalByCredential: {
          'cred1': { first: credBuf },
        },
      },
    };
    repairPrfExtensionBuffers(ext);
    assert.strictEqual(ext.prf.eval.first, evalBuf);
    assert.strictEqual(ext.prf.evalByCredential['cred1'].first, credBuf);
  });

  it('does not throw on null / undefined extensions', () => {
    assert.doesNotThrow(() => repairPrfExtensionBuffers(null));
    assert.doesNotThrow(() => repairPrfExtensionBuffers(undefined));
    assert.equal(repairPrfExtensionBuffers(null), null);
    assert.equal(repairPrfExtensionBuffers(undefined), undefined);
  });

  it('does not throw when extensions has no prf field', () => {
    const ext = { credProps: true };
    assert.doesNotThrow(() => repairPrfExtensionBuffers(ext));
    // unchanged
    assert.deepEqual(ext, { credProps: true });
  });

  it('does not throw when prf has no eval / evalByCredential', () => {
    const ext = { prf: {} };
    assert.doesNotThrow(() => repairPrfExtensionBuffers(ext));
    assert.deepEqual(ext, { prf: {} });
  });

  it('does not throw when prf.eval has no first', () => {
    const ext = { prf: { eval: {} } };
    assert.doesNotThrow(() => repairPrfExtensionBuffers(ext));
  });

  it('returns the same reference it was given', () => {
    const ext = { prf: { eval: { first: { 0: 1 } } } };
    const out = repairPrfExtensionBuffers(ext);
    assert.strictEqual(out, ext);
  });

  it('handles a mixed evalByCredential (some bytes, some object) correctly', () => {
    const realBuf = new Uint8Array([1, 2, 3]);
    const ext = {
      prf: {
        evalByCredential: {
          'a': { first: { 0: 10, 1: 11 } }, // needs repair
          'b': { first: realBuf },           // already OK
        },
      },
    };
    repairPrfExtensionBuffers(ext);
    assert.ok(ext.prf.evalByCredential['a'].first instanceof Uint8Array);
    assert.deepEqual(Array.from(ext.prf.evalByCredential['a'].first), [10, 11]);
    assert.strictEqual(ext.prf.evalByCredential['b'].first, realBuf);
  });
});
