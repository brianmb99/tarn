// Unit tests for buildCredentialTags — covers the dual-tag (Lk + RLk)
// scheme that unblocks gateway-direct credential discovery for the
// standalone-recovery package (`@tarn/recover`).
//
// The recovery client only has the user's account key — it can derive
// recovery_lookup_key (HMAC, no salt) but not credential_lookup_key
// (which depends on the password). Tagging the credential blob with both
// makes the blob discoverable by either lookup key.
//
// Run: node --test tests/unit/auth-credential-tags.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildCredentialTags } from '../../api/src/routes/auth.js';
import { PROTOCOL_VERSION } from '../../api/src/constants.js';

const CLK = 'a'.repeat(64);
const RLK = 'b'.repeat(64);

function tagValue(tags, name) {
  const t = tags.find(t => t.name === name);
  return t ? t.value : null;
}

describe('buildCredentialTags', () => {
  it('emits App, Type, Lk, V when no recovery lookup key is supplied', () => {
    const tags = buildCredentialTags(CLK);
    assert.equal(tagValue(tags, 'App'), 'tarn');
    assert.equal(tagValue(tags, 'Type'), 'cred');
    assert.equal(tagValue(tags, 'Lk'), CLK);
    assert.equal(tagValue(tags, 'V'), PROTOCOL_VERSION);
    assert.equal(tagValue(tags, 'RLk'), null, 'RLk must be omitted when recoveryLookupKey is absent');
  });

  it('emits RLk when a recovery lookup key is supplied', () => {
    const tags = buildCredentialTags(CLK, RLK);
    assert.equal(tagValue(tags, 'Lk'), CLK);
    assert.equal(tagValue(tags, 'RLk'), RLK, 'RLk must equal the supplied recovery_lookup_key');
    // Sanity: the V tag still trails (consumers don't depend on order, but
    // existing tests/snapshots relied on the original layout).
    assert.equal(tagValue(tags, 'V'), PROTOCOL_VERSION);
  });

  it('treats null/undefined recovery lookup key as absent', () => {
    for (const empty of [null, undefined]) {
      const tags = buildCredentialTags(CLK, empty);
      assert.equal(tagValue(tags, 'RLk'), null);
    }
  });

  it('treats empty-string recovery lookup key as absent (defensive)', () => {
    // The route handlers normalize NULL/empty before calling this helper,
    // but buildCredentialTags should not emit a useless RLk='' tag if a
    // future caller forgets.
    const tags = buildCredentialTags(CLK, '');
    assert.equal(tagValue(tags, 'RLk'), null);
  });

  it('Lk and RLk are independent (different lookup-key spaces)', () => {
    const tags = buildCredentialTags(CLK, RLK);
    assert.notEqual(tagValue(tags, 'Lk'), tagValue(tags, 'RLk'));
  });

  it('returns a fresh array (caller may push without mutating internal state)', () => {
    const a = buildCredentialTags(CLK, RLK);
    const b = buildCredentialTags(CLK, RLK);
    assert.notEqual(a, b);
    a.push({ name: 'Extra', value: 'x' });
    assert.equal(b.find(t => t.name === 'Extra'), undefined);
  });
});
