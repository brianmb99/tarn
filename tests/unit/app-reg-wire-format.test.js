// Unit tests for the Type=app-reg wire format (api/src/app-reg.js).
//
// These cover the helper that constructs the tag set + JSON body for the
// Arweave blob that mirrors the `apps` D1 table. The blob's discoverability
// (App=tarn,Type=app-reg,Lk=<app_id>) is what the Phase C rebuild tool will
// rely on, so the tag scheme is load-bearing.
//
// Run: node --test tests/unit/app-reg-wire-format.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAppRegTags,
  buildAppRegBody,
  APP_REG_BLOB_VERSION,
} from '../../api/src/app-reg.js';
import { PROTOCOL_VERSION } from '../../api/src/constants.js';

const APP_ID = 'bookish';
const PUB = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEexamplebase64spki=';
const TPL = 'https://example.com/invite#token={token_id}';

function tagValue(tags, name) {
  const t = tags.find(t => t.name === name);
  return t ? t.value : null;
}

describe('buildAppRegTags', () => {
  it('emits App, Type, Lk, V in the canonical order', () => {
    const tags = buildAppRegTags(APP_ID);
    assert.equal(tagValue(tags, 'App'), 'tarn');
    assert.equal(tagValue(tags, 'Type'), 'app-reg');
    assert.equal(tagValue(tags, 'Lk'), APP_ID);
    assert.equal(tagValue(tags, 'V'), PROTOCOL_VERSION);
    assert.equal(tags.length, 4);
  });

  it('tag order is stable: App, Type, Lk, V', () => {
    // Stable order is not load-bearing for Arweave (tags are an unordered set
    // by GraphQL semantics) but it makes ANS-104 byte-identical reproduction
    // possible across replays of the same registration, so we lock it.
    const tags = buildAppRegTags(APP_ID);
    assert.deepEqual(tags.map(t => t.name), ['App', 'Type', 'Lk', 'V']);
  });

  it('throws on missing/empty app_id', () => {
    assert.throws(() => buildAppRegTags(''), /non-empty string/);
    assert.throws(() => buildAppRegTags(null), /non-empty string/);
    assert.throws(() => buildAppRegTags(undefined), /non-empty string/);
    assert.throws(() => buildAppRegTags(123), /non-empty string/);
  });

  it('returns a fresh array (caller may push without mutating internal state)', () => {
    const a = buildAppRegTags(APP_ID);
    const b = buildAppRegTags(APP_ID);
    assert.notEqual(a, b);
    a.push({ name: 'Extra', value: 'x' });
    assert.equal(b.find(t => t.name === 'Extra'), undefined);
  });
});

describe('buildAppRegBody', () => {
  it('returns a JSON string with all canonical fields when invite_url_template is provided', () => {
    const text = buildAppRegBody({
      app_id: APP_ID,
      public_key: PUB,
      invite_url_template: TPL,
      created_at: 1700000000000,
    });
    const obj = JSON.parse(text);
    assert.equal(obj.v, APP_REG_BLOB_VERSION);
    assert.equal(obj.v, 1);
    assert.equal(obj.app_id, APP_ID);
    assert.equal(obj.public_key, PUB);
    assert.equal(obj.invite_url_template, TPL);
    assert.equal(obj.created_at, 1700000000000);
  });

  it('serializes invite_url_template as null when omitted', () => {
    const obj = JSON.parse(buildAppRegBody({
      app_id: APP_ID,
      public_key: PUB,
      created_at: 1,
    }));
    assert.equal(obj.invite_url_template, null);
  });

  it('serializes invite_url_template as null when explicitly null', () => {
    const obj = JSON.parse(buildAppRegBody({
      app_id: APP_ID,
      public_key: PUB,
      invite_url_template: null,
      created_at: 1,
    }));
    assert.equal(obj.invite_url_template, null);
  });

  it('defaults created_at to Date.now() when omitted', () => {
    const before = Date.now();
    const obj = JSON.parse(buildAppRegBody({ app_id: APP_ID, public_key: PUB }));
    const after = Date.now();
    assert.ok(obj.created_at >= before && obj.created_at <= after,
      `created_at ${obj.created_at} should be in [${before}, ${after}]`);
  });

  it('throws on missing/empty app_id', () => {
    assert.throws(() => buildAppRegBody({ public_key: PUB }), /app_id must be a non-empty string/);
    assert.throws(() => buildAppRegBody({ app_id: '', public_key: PUB }), /app_id must be a non-empty string/);
  });

  it('throws on missing/empty public_key', () => {
    assert.throws(() => buildAppRegBody({ app_id: APP_ID }), /public_key must be a non-empty string/);
    assert.throws(() => buildAppRegBody({ app_id: APP_ID, public_key: '' }), /public_key must be a non-empty string/);
  });

  it('throws when invite_url_template is the wrong type', () => {
    assert.throws(
      () => buildAppRegBody({ app_id: APP_ID, public_key: PUB, invite_url_template: 42 }),
      /invite_url_template must be a string or null/,
    );
    assert.throws(
      () => buildAppRegBody({ app_id: APP_ID, public_key: PUB, invite_url_template: {} }),
      /invite_url_template must be a string or null/,
    );
  });

  it('round-trips: tags + body together fully describe an app row', () => {
    // The Phase C rebuild tool will read tags + body and reconstruct an
    // `apps` row. Verify the cross-product is internally consistent: the
    // `Lk` tag must equal the body's `app_id`.
    const tags = buildAppRegTags(APP_ID);
    const body = JSON.parse(buildAppRegBody({
      app_id: APP_ID, public_key: PUB, invite_url_template: TPL, created_at: 5,
    }));
    assert.equal(tagValue(tags, 'Lk'), body.app_id);
  });
});
