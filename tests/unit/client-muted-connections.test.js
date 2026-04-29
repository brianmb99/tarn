// Unit tests for the muted-connections record helpers (issue #18, Section 6).
//
// The TarnClient-level mute/unmute lifecycle (mute on device A, hydrate on
// device B) is exercised in tests/test-share-log.mjs against a running
// wrangler dev. These tests cover the pure helpers + record shape.
//
// Run: node --test tests/unit/client-muted-connections.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  MUTED_CONNECTIONS_CONTENT_ID,
  emptyMutedConnectionsRecord,
  addMutedConnection,
  removeMutedConnection,
  isMutedInRecord,
} from '../../client/src/sharing.js';

const SHARE_PUB_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const SHARE_PUB_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const NOW = 1700000000;

describe('muted-connections content_id', () => {
  it('is the documented protocol identifier', () => {
    assert.equal(MUTED_CONNECTIONS_CONTENT_ID, 'tarn-muted-connections-v1');
  });
});

describe('emptyMutedConnectionsRecord', () => {
  it('has app_id, version, and an empty muted array', () => {
    const r = emptyMutedConnectionsRecord('bookish');
    assert.equal(r.app_id, 'bookish');
    assert.equal(r.version, 1);
    assert.deepEqual(r.muted, []);
  });
});

describe('addMutedConnection', () => {
  it('appends a new muted entry', () => {
    let r = emptyMutedConnectionsRecord('bookish');
    r = addMutedConnection(r, SHARE_PUB_A, NOW);
    assert.equal(r.muted.length, 1);
    assert.deepEqual(r.muted[0], { share_pub: SHARE_PUB_A, muted_at: NOW });
  });

  it('is idempotent on share_pub (does not overwrite muted_at)', () => {
    let r = emptyMutedConnectionsRecord('bookish');
    r = addMutedConnection(r, SHARE_PUB_A, NOW);
    const second = addMutedConnection(r, SHARE_PUB_A, NOW + 100);
    assert.equal(second.muted.length, 1);
    assert.equal(second.muted[0].muted_at, NOW, 'original muted_at preserved');
  });

  it('appends a second distinct connection', () => {
    let r = emptyMutedConnectionsRecord('bookish');
    r = addMutedConnection(r, SHARE_PUB_A, NOW);
    r = addMutedConnection(r, SHARE_PUB_B, NOW + 1);
    assert.equal(r.muted.length, 2);
  });

  it('rejects non-string share_pub', () => {
    const r = emptyMutedConnectionsRecord('bookish');
    assert.throws(() => addMutedConnection(r, 123, NOW), /connectionSharePubBase64Url/);
    assert.throws(() => addMutedConnection(r, null, NOW), /connectionSharePubBase64Url/);
    assert.throws(() => addMutedConnection(r, '', NOW), /connectionSharePubBase64Url/);
  });

  it('rejects non-integer muted_at', () => {
    const r = emptyMutedConnectionsRecord('bookish');
    assert.throws(() => addMutedConnection(r, SHARE_PUB_A, 'now'), /mutedAt/);
    assert.throws(() => addMutedConnection(r, SHARE_PUB_A, 1.5), /mutedAt/);
  });

  it('rejects a malformed record', () => {
    assert.throws(() => addMutedConnection({ wrong: 'shape' }, SHARE_PUB_A, NOW), /muted-connections record/);
    assert.throws(() => addMutedConnection(null, SHARE_PUB_A, NOW), /muted-connections record/);
  });
});

describe('removeMutedConnection', () => {
  it('removes a muted entry', () => {
    let r = emptyMutedConnectionsRecord('bookish');
    r = addMutedConnection(r, SHARE_PUB_A, NOW);
    r = addMutedConnection(r, SHARE_PUB_B, NOW + 1);
    r = removeMutedConnection(r, SHARE_PUB_A);
    assert.equal(r.muted.length, 1);
    assert.equal(r.muted[0].share_pub, SHARE_PUB_B);
  });

  it('is idempotent on absent share_pub', () => {
    let r = emptyMutedConnectionsRecord('bookish');
    r = addMutedConnection(r, SHARE_PUB_A, NOW);
    const after = removeMutedConnection(r, SHARE_PUB_B);
    assert.equal(after.muted.length, 1);
  });

  it('rejects malformed args', () => {
    const r = emptyMutedConnectionsRecord('bookish');
    assert.throws(() => removeMutedConnection(r, ''), /connectionSharePubBase64Url/);
    assert.throws(() => removeMutedConnection(null, SHARE_PUB_A), /muted-connections record/);
  });
});

describe('isMutedInRecord', () => {
  it('returns true for a muted share_pub', () => {
    let r = emptyMutedConnectionsRecord('bookish');
    r = addMutedConnection(r, SHARE_PUB_A, NOW);
    assert.equal(isMutedInRecord(r, SHARE_PUB_A), true);
  });

  it('returns false for an absent share_pub', () => {
    const r = emptyMutedConnectionsRecord('bookish');
    assert.equal(isMutedInRecord(r, SHARE_PUB_A), false);
  });

  it('returns false after unmute', () => {
    let r = emptyMutedConnectionsRecord('bookish');
    r = addMutedConnection(r, SHARE_PUB_A, NOW);
    r = removeMutedConnection(r, SHARE_PUB_A);
    assert.equal(isMutedInRecord(r, SHARE_PUB_A), false);
  });

  it('rejects a malformed record', () => {
    assert.throws(() => isMutedInRecord({}, SHARE_PUB_A), /muted-connections record/);
  });
});
