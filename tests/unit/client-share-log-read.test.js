// Unit tests for share-log read flow + multi-device retry helpers
// (issue #16, Section 5c).
//
// Covers the pure helpers in client/src/share-log.js. The TarnClient-level
// methods (readShareLog / syncShareLog / shareContent / multi-device retry)
// are exercised in tests/test-share-log.mjs against a running wrangler dev,
// since they depend on the API and on real per-pair handshake state.
//
// Covered here:
//   - discoverHighestSeq:
//       - empty log (probe at anchor misses)
//       - exactly one entry
//       - small log (bisect path)
//       - large log (logarithmic probe-count assertion)
//       - non-zero anchor (incremental sync use case)
//       - safety cap when probe always returns true
//       - bad inputs throw
//   - applyOperationToState (idempotency rules per §8.4):
//       - add → state grows
//       - update → tx_id changes, cek preserved
//       - rotate → cek changes, tx_id preserved
//       - remove → entry dropped
//       - snapshot → state replaced wholesale
//       - rotate_identity → no-op (5d will process)
//       - add for known content_id with same cek → tx_id update, no error
//       - add for known content_id with different cek → adopts new cek + onError
//       - update for unknown content_id → onWarn + no-op
//       - rotate for unknown content_id → onWarn + no-op
//       - remove for unknown content_id → silent no-op
//       - replay safety: applying same op twice → same state
//   - replayOperations: composes apply across an ordered sequence
//
// Run: node --test tests/unit/client-share-log-read.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  discoverHighestSeq,
  applyOperationToState,
  replayOperations,
  OP_ADD, OP_UPDATE, OP_ROTATE, OP_REMOVE, OP_SNAPSHOT, OP_ROTATE_IDENTITY,
} from '../../client/src/share-log.js';

// ============ discoverHighestSeq ============

// Build a probe over a virtual "log" represented as a Set<seq>. Tracks every
// probe call so tests can assert probe-count.
function makeProbe(presentSeqs) {
  const present = new Set(presentSeqs);
  const calls = [];
  const probe = async (seq) => {
    calls.push(seq);
    return present.has(seq);
  };
  return { probe, calls };
}

describe('discoverHighestSeq', () => {
  it('returns -1 for an empty log when anchor=0', async () => {
    const { probe, calls } = makeProbe([]);
    const r = await discoverHighestSeq({ probe, anchor: 0 });
    assert.equal(r.highestSeq, -1);
    assert.equal(r.probeCount, 1, 'should bail out after the first miss');
    assert.deepEqual(calls, [0]);
  });

  it('returns 0 anchor-1 when anchor=1 and seq>=1 is empty', async () => {
    const { probe } = makeProbe([]);
    const r = await discoverHighestSeq({ probe, anchor: 1 });
    assert.equal(r.highestSeq, 0, 'anchor-1 == 0');
  });

  it('handles exactly one entry at seq=0', async () => {
    const { probe, calls } = makeProbe([0]);
    const r = await discoverHighestSeq({ probe, anchor: 0 });
    assert.equal(r.highestSeq, 0);
    assert.deepEqual(calls, [0, 1], 'probe(0)=hit, probe(1)=miss; no bisect');
  });

  it('handles exactly one entry at seq=1 (anchor=0)', async () => {
    const { probe, calls } = makeProbe([0, 1]);
    const r = await discoverHighestSeq({ probe, anchor: 0 });
    assert.equal(r.highestSeq, 1);
    // 0 hits, 1 hits, 3 misses; bisect [2,2] → probe(2). Then lo=1, hi=2,
    // diff=1, exit.
    assert.deepEqual(calls, [0, 1, 3, 2]);
  });

  it('finds highest=9 in a 10-entry log', async () => {
    const { probe, calls } = makeProbe([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const r = await discoverHighestSeq({ probe, anchor: 0 });
    assert.equal(r.highestSeq, 9);
    // Probes: 0✓, 1✓, 3✓, 7✓, 15✗ → bisect [8,14]
    // bisect: probe(11)=miss → hi=11; probe(9)=hit → lo=9; probe(10)=miss → hi=10
    // lo=9, hi=10, diff=1, exit. Total = 5 + 3 = 8.
    assert.equal(r.probeCount, 8);
    assert(calls.length === 8);
  });

  it('is logarithmic on a large log (1000 entries)', async () => {
    const seqs = [];
    for (let i = 0; i < 1000; i++) seqs.push(i);
    const { probe, calls } = makeProbe(seqs);
    const r = await discoverHighestSeq({ probe, anchor: 0 });
    assert.equal(r.highestSeq, 999);
    // 2 * log2(1000) ≈ 20. Loose bound to allow the +/-1 boundary calls.
    assert(r.probeCount <= 25, `probe count ${r.probeCount} should be ≤25 (~2 log2 N)`);
    assert.equal(r.probeCount, calls.length);
  });

  it('is logarithmic on a 10000-entry log', async () => {
    const seqs = [];
    for (let i = 0; i < 10000; i++) seqs.push(i);
    const { probe } = makeProbe(seqs);
    const r = await discoverHighestSeq({ probe, anchor: 0 });
    assert.equal(r.highestSeq, 9999);
    // 2 * log2(10000) ≈ 27.
    assert(r.probeCount <= 32, `probe count ${r.probeCount} should be ≤32`);
  });

  it('returns anchor-1 when anchor itself misses (incremental sync, no new entries)', async () => {
    // lastSeqSeen = 5; sync probes at anchor=6.
    const { probe, calls } = makeProbe([0, 1, 2, 3, 4, 5]);
    const r = await discoverHighestSeq({ probe, anchor: 6 });
    assert.equal(r.highestSeq, 5, 'anchor - 1 = 5');
    assert.deepEqual(calls, [6]);
  });

  it('finds new highest seq from a non-zero anchor (incremental sync)', async () => {
    // lastSeen=5; new entries at 6, 7, 8.
    const seqs = [];
    for (let i = 0; i <= 8; i++) seqs.push(i);
    const { probe } = makeProbe(seqs);
    const r = await discoverHighestSeq({ probe, anchor: 6 });
    assert.equal(r.highestSeq, 8);
  });

  it('returns truncated:true when probe always succeeds (safety cap)', async () => {
    let count = 0;
    const probe = async () => { count++; return true; };
    const r = await discoverHighestSeq({
      probe, anchor: 0, maxExponentialProbes: 10,
    });
    assert.equal(r.probeCount, 10);
    assert.equal(r.truncated, true);
    // lastHit at iteration 10 is 0 + 1 + 2 + 4 + ... + 256 = 511.
    assert.equal(r.highestSeq, 511);
  });

  it('rejects bad inputs', async () => {
    await assert.rejects(
      discoverHighestSeq({ probe: 'nope' }),
      /probe must be a function/,
    );
    await assert.rejects(
      discoverHighestSeq({ probe: async () => true, anchor: -1 }),
      /anchor must be a non-negative integer/,
    );
    await assert.rejects(
      discoverHighestSeq({ probe: async () => true, anchor: 0, maxExponentialProbes: 0 }),
      /maxExponentialProbes must be a positive integer/,
    );
  });
});

// ============ applyOperationToState ============

const CEK_A = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const CEK_B = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA';

describe('applyOperationToState — idempotency rules (§8.4)', () => {
  it('add: state grows', () => {
    const state = {};
    applyOperationToState(state, {
      type: OP_ADD, content_id: 'b1', tx_id: 'tx1', cek: CEK_A, shared_at: 1,
    });
    assert.deepEqual(state, { b1: { tx_id: 'tx1', cek: CEK_A } });
  });

  it('update: tx_id changes, cek preserved', () => {
    const state = { b1: { tx_id: 'tx1', cek: CEK_A } };
    applyOperationToState(state, {
      type: OP_UPDATE, content_id: 'b1', tx_id: 'tx2', updated_at: 2,
    });
    assert.deepEqual(state, { b1: { tx_id: 'tx2', cek: CEK_A } });
  });

  it('rotate: cek changes, tx_id preserved', () => {
    const state = { b1: { tx_id: 'tx1', cek: CEK_A } };
    applyOperationToState(state, {
      type: OP_ROTATE, content_id: 'b1', cek: CEK_B, rotated_at: 3,
    });
    assert.deepEqual(state, { b1: { tx_id: 'tx1', cek: CEK_B } });
  });

  it('remove: entry dropped', () => {
    const state = { b1: { tx_id: 'tx1', cek: CEK_A } };
    applyOperationToState(state, {
      type: OP_REMOVE, content_id: 'b1', removed_at: 4,
    });
    assert.deepEqual(state, {});
  });

  it('snapshot: state replaced wholesale', () => {
    const state = { b1: { tx_id: 'tx1', cek: CEK_A } };
    applyOperationToState(state, {
      type: OP_SNAPSHOT,
      state: {
        b2: { tx_id: 'tx2', cek: CEK_B },
        b3: { tx_id: 'tx3', cek: CEK_A },
      },
      snapshot_at: 5,
      prior_seq: 0,
    });
    assert.deepEqual(state, {
      b2: { tx_id: 'tx2', cek: CEK_B },
      b3: { tx_id: 'tx3', cek: CEK_A },
    });
    assert.equal(state.b1, undefined, 'pre-snapshot keys are wiped');
  });

  it('rotate_identity: no-op (5d will process)', () => {
    const state = { b1: { tx_id: 'tx1', cek: CEK_A } };
    applyOperationToState(state, {
      type: OP_ROTATE_IDENTITY,
      new_share_pub: CEK_A,
      new_signing_pub: 'spki-b64',
      rotated_at: 6,
    });
    assert.deepEqual(state, { b1: { tx_id: 'tx1', cek: CEK_A } });
  });

  it('add for known content_id with same cek: tx_id updates, no error', () => {
    const state = { b1: { tx_id: 'tx1', cek: CEK_A } };
    let errs = 0;
    applyOperationToState(state, {
      type: OP_ADD, content_id: 'b1', tx_id: 'tx2', cek: CEK_A, shared_at: 7,
    }, { onError: () => { errs++; } });
    assert.equal(errs, 0, 'no error when CEKs match');
    assert.deepEqual(state, { b1: { tx_id: 'tx2', cek: CEK_A } });
  });

  it('add for known content_id with different cek: adopts new cek + onError', () => {
    const state = { b1: { tx_id: 'tx1', cek: CEK_A } };
    let errs = [];
    applyOperationToState(state, {
      type: OP_ADD, content_id: 'b1', tx_id: 'tx2', cek: CEK_B, shared_at: 8,
    }, { onError: (m) => errs.push(m) });
    assert.equal(errs.length, 1, 'should fire onError once');
    assert(/different CEK/.test(errs[0]), 'error message mentions CEK divergence');
    assert.deepEqual(state, { b1: { tx_id: 'tx2', cek: CEK_B } }, 'adopts new CEK');
  });

  it('update for unknown content_id: onWarn + no-op', () => {
    const state = {};
    let warns = 0;
    applyOperationToState(state, {
      type: OP_UPDATE, content_id: 'b-unknown', tx_id: 'tx1', updated_at: 9,
    }, { onWarn: () => { warns++; } });
    assert.equal(warns, 1);
    assert.deepEqual(state, {});
  });

  it('rotate for unknown content_id: onWarn + no-op', () => {
    const state = {};
    let warns = 0;
    applyOperationToState(state, {
      type: OP_ROTATE, content_id: 'b-unknown', cek: CEK_A, rotated_at: 10,
    }, { onWarn: () => { warns++; } });
    assert.equal(warns, 1);
    assert.deepEqual(state, {});
  });

  it('remove for unknown content_id: silent no-op', () => {
    const state = {};
    let warns = 0;
    applyOperationToState(state, {
      type: OP_REMOVE, content_id: 'b-unknown', removed_at: 11,
    }, { onWarn: () => { warns++; } });
    assert.equal(warns, 0, 'remove on unknown should be silent');
    assert.deepEqual(state, {});
  });

  it('replay safety: applying the same op twice gives the same state', () => {
    const op1 = { type: OP_ADD, content_id: 'b1', tx_id: 'tx1', cek: CEK_A, shared_at: 1 };
    const op2 = { type: OP_UPDATE, content_id: 'b1', tx_id: 'tx2', updated_at: 2 };

    const stateA = {};
    applyOperationToState(stateA, op1);
    applyOperationToState(stateA, op2);

    const stateB = {};
    applyOperationToState(stateB, op1);
    applyOperationToState(stateB, op1);  // replay add — second is treated as update with same fields
    applyOperationToState(stateB, op2);
    applyOperationToState(stateB, op2);  // replay update — same data, no change

    assert.deepEqual(stateA, stateB);
  });

  it('replay safety: snapshot replay produces the same state', () => {
    const snap = {
      type: OP_SNAPSHOT,
      state: { b1: { tx_id: 'tx1', cek: CEK_A } },
      snapshot_at: 1,
      prior_seq: null,
    };
    const stateA = {};
    applyOperationToState(stateA, snap);

    const stateB = {};
    applyOperationToState(stateB, snap);
    applyOperationToState(stateB, snap);
    applyOperationToState(stateB, snap);
    assert.deepEqual(stateA, stateB);
  });

  it('unknown operation type: onWarn + no-op (forward-compat)', () => {
    const state = { b1: { tx_id: 'tx1', cek: CEK_A } };
    let warns = 0;
    applyOperationToState(state, {
      type: 'futuristic_op', content_id: 'b1',
    }, { onWarn: () => { warns++; } });
    assert.equal(warns, 1);
    assert.deepEqual(state, { b1: { tx_id: 'tx1', cek: CEK_A } });
  });

  it('rejects bad inputs', () => {
    assert.throws(() => applyOperationToState(null, { type: OP_REMOVE, content_id: 'x' }), /state must be an object/);
    assert.throws(() => applyOperationToState({}, null), /operation must be an object/);
  });
});

describe('replayOperations', () => {
  it('applies a sequence of ops in order', () => {
    const ops = [
      { type: OP_ADD, content_id: 'b1', tx_id: 'tx1', cek: CEK_A, shared_at: 1 },
      { type: OP_ADD, content_id: 'b2', tx_id: 'tx2a', cek: CEK_B, shared_at: 2 },
      { type: OP_UPDATE, content_id: 'b2', tx_id: 'tx2b', updated_at: 3 },
      { type: OP_REMOVE, content_id: 'b1', removed_at: 4 },
    ];
    const state = replayOperations(ops);
    assert.deepEqual(state, { b2: { tx_id: 'tx2b', cek: CEK_B } });
  });

  it('starts from initialState', () => {
    const ops = [
      { type: OP_UPDATE, content_id: 'b1', tx_id: 'tx2', updated_at: 1 },
    ];
    const state = replayOperations(ops, { b1: { tx_id: 'tx1', cek: CEK_A } });
    assert.deepEqual(state, { b1: { tx_id: 'tx2', cek: CEK_A } });
  });

  it('snapshot mid-sequence wipes prior state', () => {
    const ops = [
      { type: OP_ADD, content_id: 'b1', tx_id: 'tx1', cek: CEK_A, shared_at: 1 },
      {
        type: OP_SNAPSHOT,
        state: { b9: { tx_id: 'tx9', cek: CEK_B } },
        snapshot_at: 2,
        prior_seq: 0,
      },
      { type: OP_ADD, content_id: 'b3', tx_id: 'tx3', cek: CEK_A, shared_at: 3 },
    ];
    const state = replayOperations(ops);
    assert.deepEqual(state, {
      b9: { tx_id: 'tx9', cek: CEK_B },
      b3: { tx_id: 'tx3', cek: CEK_A },
    });
  });
});
