// Unit tests for the Phase-B passkey-reg Arweave wire format helpers
// (api/src/routes/passkey-reg.js).
//
// Phase B of the Arweave-recoverability fix plan
// (docs/ARWEAVE_RECOVERABILITY_FIX_PLAN.md) mirrors `passkey_credentials`
// rows to Arweave so a D1 wipe doesn't permanently strand a user's
// passkey-only auth path. This test pins the wire shape: tag set, body
// JSON layout, tombstone discriminator, and the explicit "what's NOT
// persisted" stance (sign_count, last_used_at).
//
// Run: node --test tests/unit/passkey-reg-wire-format.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildPasskeyRegTags,
  buildPasskeyRegBlob,
  buildPasskeyRegTombstoneBlob,
} from '../../api/src/routes/passkey-reg.js';
import { PROTOCOL_VERSION } from '../../api/src/constants.js';

const DLK = 'a'.repeat(64);
const CRED_ID = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'; // base64url-ish
const PUB_KEY = 'cGFzc2tleS1wdWJsaWMta2V5LWJ5dGVz';
const PRF_SALT = 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ';

function tagValue(tags, name) {
  const t = tags.find(t => t.name === name);
  return t ? t.value : null;
}

describe('buildPasskeyRegTags', () => {
  it('emits App=tarn, Type=passkey-reg, Lk=<dlk>, CredId=<id>, V on registration', () => {
    const tags = buildPasskeyRegTags(DLK, CRED_ID);
    assert.equal(tagValue(tags, 'App'), 'tarn');
    assert.equal(tagValue(tags, 'Type'), 'passkey-reg');
    assert.equal(tagValue(tags, 'Lk'), DLK);
    assert.equal(tagValue(tags, 'CredId'), CRED_ID);
    assert.equal(tagValue(tags, 'V'), PROTOCOL_VERSION);
    assert.equal(tagValue(tags, 'Op'), null, 'Op tag must be absent on a live blob');
  });

  it('adds Op=tombstone when opts.tombstone is true', () => {
    const tags = buildPasskeyRegTags(DLK, CRED_ID, { tombstone: true });
    assert.equal(tagValue(tags, 'Op'), 'tombstone');
    // CredId and Lk still present on the tombstone — that's the whole
    // point of the CredId-by-tag tombstone scheme: a CredId-keyed query
    // discovers the tombstone alongside any live blobs.
    assert.equal(tagValue(tags, 'CredId'), CRED_ID);
    assert.equal(tagValue(tags, 'Lk'), DLK);
  });

  it('throws on missing dataLookupKey', () => {
    assert.throws(() => buildPasskeyRegTags('', CRED_ID), TypeError);
    assert.throws(() => buildPasskeyRegTags(null, CRED_ID), TypeError);
  });

  it('throws on missing credentialId', () => {
    assert.throws(() => buildPasskeyRegTags(DLK, ''), TypeError);
    assert.throws(() => buildPasskeyRegTags(DLK, null), TypeError);
  });

  it('returns a fresh array (caller may push without mutating internal state)', () => {
    const a = buildPasskeyRegTags(DLK, CRED_ID);
    const b = buildPasskeyRegTags(DLK, CRED_ID);
    assert.notEqual(a, b);
    a.push({ name: 'Extra', value: 'x' });
    assert.equal(b.find(t => t.name === 'Extra'), undefined);
  });
});

describe('buildPasskeyRegBlob', () => {
  it('emits the documented v1 shape with all required fields', () => {
    const json = buildPasskeyRegBlob({
      dataLookupKey: DLK,
      credentialId: CRED_ID,
      publicKey: PUB_KEY,
      prfSalt: PRF_SALT,
      deviceLabel: 'iPhone 16',
      createdAt: 1_700_000_000_000,
    });
    const parsed = JSON.parse(json);
    assert.equal(parsed.v, 1);
    assert.equal(parsed.data_lookup_key, DLK);
    assert.equal(parsed.credential_id, CRED_ID);
    assert.equal(parsed.public_key, PUB_KEY);
    assert.equal(parsed.prf_salt, PRF_SALT);
    assert.equal(parsed.device_label, 'iPhone 16');
    assert.equal(parsed.created_at, 1_700_000_000_000);
  });

  it('persists null device_label when omitted', () => {
    const parsed = JSON.parse(buildPasskeyRegBlob({
      dataLookupKey: DLK,
      credentialId: CRED_ID,
      publicKey: PUB_KEY,
      prfSalt: PRF_SALT,
    }));
    assert.equal(parsed.device_label, null);
    assert.equal(typeof parsed.created_at, 'number', 'created_at defaults to Date.now()');
  });

  it('does NOT persist sign_count or last_used_at (acceptable losses on rebuild)', () => {
    // The whole "what's NOT persisted" contract from the plan is pinned here:
    // sign_count is runtime state (defaults to 0 on rebuild — first
    // post-rebuild auth produces a benign update); last_used_at is UX scaffold.
    const parsed = JSON.parse(buildPasskeyRegBlob({
      dataLookupKey: DLK,
      credentialId: CRED_ID,
      publicKey: PUB_KEY,
      prfSalt: PRF_SALT,
      deviceLabel: 'X',
      // Even if a future caller passes these, they should not appear in
      // the body — pin the field set explicitly.
      // @ts-ignore intentional extra fields
      sign_count: 7,
      // @ts-ignore intentional extra fields
      last_used_at: 1_700_000_000_000,
    }));
    assert.equal('sign_count' in parsed, false);
    assert.equal('last_used_at' in parsed, false);
  });

  it('throws on missing required fields', () => {
    const base = {
      dataLookupKey: DLK,
      credentialId: CRED_ID,
      publicKey: PUB_KEY,
      prfSalt: PRF_SALT,
    };
    for (const key of ['dataLookupKey', 'credentialId', 'publicKey', 'prfSalt']) {
      const broken = { ...base, [key]: '' };
      assert.throws(() => buildPasskeyRegBlob(broken), TypeError, `expected throw on missing ${key}`);
    }
  });

  it('coerces non-string device_label to string', () => {
    const parsed = JSON.parse(buildPasskeyRegBlob({
      dataLookupKey: DLK,
      credentialId: CRED_ID,
      publicKey: PUB_KEY,
      prfSalt: PRF_SALT,
      deviceLabel: 12345,
    }));
    assert.equal(parsed.device_label, '12345');
  });
});

describe('buildPasskeyRegTombstoneBlob', () => {
  it('emits a minimal v1 tombstone body that names the credential', () => {
    const parsed = JSON.parse(buildPasskeyRegTombstoneBlob(CRED_ID));
    assert.equal(parsed.v, 1);
    assert.equal(parsed.tombstone, true);
    assert.equal(parsed.credential_id, CRED_ID);
    // Body is intentionally minimal — no public_key, no prf_salt, no
    // dlk leak. The discriminating info is in the tags.
    assert.equal('public_key' in parsed, false);
    assert.equal('prf_salt' in parsed, false);
    assert.equal('data_lookup_key' in parsed, false);
  });

  it('throws on missing credentialId', () => {
    assert.throws(() => buildPasskeyRegTombstoneBlob(''), TypeError);
    assert.throws(() => buildPasskeyRegTombstoneBlob(null), TypeError);
  });
});
