// Unit tests for strict option-bag validation (client/src/opts.ts) and its
// wiring into the SDK's connections/invites surface.
//
// Silently-ignored options are how the `display_name`-vs-`label` integration
// bug shipped: the call succeeded while the option did nothing. These tests
// pin the contract that unknown keys throw, and throw BEFORE auth checks so
// the mistake surfaces in any environment, authenticated or not.
//
// Run: node --import tsx --test tests/unit/opts-validation.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { assertKnownOpts } from '../../client/src/opts.js';
import { TarnClient } from '../../client/src/tarn.js';

describe('assertKnownOpts', () => {
  it('accepts known keys, empty bags, and nullish bags', () => {
    assertKnownOpts('fn', { label: 'x', expiry_days: 7 }, ['label', 'expiry_days']);
    assertKnownOpts('fn', {}, ['label']);
    assertKnownOpts('fn', null, ['label']);
    assertKnownOpts('fn', undefined, ['label']);
  });

  it('rejects unknown keys, naming the key and the supported set', () => {
    assert.throws(
      () => assertKnownOpts('createInviteToken', { display_name: 'Maya' }, ['label', 'expiry_days']),
      /createInviteToken\(\): unknown option "display_name" — supported options: label, expiry_days/,
    );
  });

  it('rejects unknown keys even when their value is undefined', () => {
    assert.throws(
      () => assertKnownOpts('fn', { display_name: undefined }, ['label']),
      /unknown option "display_name"/,
    );
  });

  it('rejects non-object bags', () => {
    assert.throws(() => assertKnownOpts('fn', 'label', ['label']), /opts must be an object/);
    assert.throws(() => assertKnownOpts('fn', ['label'], ['label']), /opts must be an object/);
  });
});

describe('SDK methods reject unknown options before auth checks', () => {
  // Unauthenticated client: if opts validation ran AFTER #requireAuth, these
  // calls would throw "not authenticated" instead of the unknown-option
  // error, and the misuse would stay invisible until production auth.
  const client = new TarnClient('http://stub', 'test-app');

  it('createInviteToken rejects the original display_name mistake', async () => {
    await assert.rejects(
      client.createInviteToken({ display_name: 'Maya', expiry_days: 7 }),
      /createInviteToken\(\): unknown option "display_name"/,
    );
  });

  it('createInviteToken names recipient_metadata as the supported alternative', async () => {
    await assert.rejects(
      client.createInviteToken({ display_name: 'Maya' }),
      /supported options: label, expiry_days, recipient_metadata/,
    );
  });

  it('connection-surface methods reject unknown options', async () => {
    await assert.rejects(
      client.sendConnectionRequest('peer@example.com', { greeting: 'hi' }),
      /sendConnectionRequest\(\): unknown option "greeting"/,
    );
    await assert.rejects(
      client.acceptConnectionRequest('nonce', { display_name: 'x' }),
      /acceptConnectionRequest\(\): unknown option "display_name"/,
    );
    await assert.rejects(
      client.listIncomingRequests({ window: 5 }),
      /listIncomingRequests\(\): unknown option "window"/,
    );
    await assert.rejects(
      client.removeConnection({ share_pub: 'x' }, { notifyPeer: true }),
      /removeConnection\(\): unknown option "notifyPeer"/,
    );
    await assert.rejects(
      client.revokeContentFromConnections('content-1', { connection: [] }),
      /revokeContentFromConnections\(\): unknown option "connection"/,
    );
    await assert.rejects(
      client.readShareLog({ share_pub: 'x', signing_pub: 'y' }, { fresh: true }),
      /readShareLog\(\): unknown option "fresh"/,
    );
  });
});
