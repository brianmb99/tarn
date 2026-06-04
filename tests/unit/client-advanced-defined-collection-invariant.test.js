// Unit tests for tarn #34: the SDK invariant that the untyped escape hatch
// (`advanced.entries.create` / `.batchCreate`) cannot silently produce
// orphan entries in a defined collection.
//
// Background: before #34, the typed `tarn.<collection>.create()` path
// validated payloads and stamped each entry with an Eid tag (so the typed
// read path could find it), but `advanced.entries.create('books', ...)` did
// not — even though `books` was a defined collection. The result was silent
// data loss: writes accepted by the API, then dropped by every subsequent
// typed read. We hit 266 of these in production on a real account.
//
// These tests exercise `AdvancedEntries` directly with a synthetic
// AdvancedSchemaInfo populated for a `books` collection — no TarnClient
// bootstrap, no live API. Mirrors the existing
// `client-advanced-batch-create.test.js` pattern but covers the
// schemaInfo path the old tests skipped.
//
// Run via the repo-level runner: npm run test:unit

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { AdvancedEntries } from '../../client/src/client/namespaces/advanced.js';
import { deriveEid } from '../../client/src/collections/eid.js';
import { defineSchema } from '../../client/src/schema/index.js';

// ============ Fixtures ============

// Same shape used in the typed tests so the invariant holds end-to-end.
const schema = defineSchema({
  appId: 'bookish',
  version: 4,
  collections: {
    books: {
      primaryKey: 'bookId',
      fields: {
        bookId: 'string',
        title: 'string',
        author: 'string?',
        rating: 'number?',
        isPrivate: { type: 'boolean', default: false },
      },
      shareable: true,
    },
  },
});

function makeSchemaInfo() {
  const collectionsByType = new Map();
  for (const [name, def] of Object.entries(schema.collections)) {
    collectionsByType.set(name, def);
  }
  return {
    collectionsByType,
    schemaVersion: schema.version,
    appId: schema.appId,
  };
}

function makeFakeClient() {
  const calls = { create: [], batchCreate: [], update: [], delete: [] };
  let txidCounter = 0;
  let shareKeyCounter = 0;
  const client = {
    calls,
    async createEntry(type, payload, extraTags) {
      calls.create.push({ type, payload: { ...payload }, extraTags: extraTags.slice() });
      return { txid: `tx-${++txidCounter}`, shareKey: `sk-${++shareKeyCounter}` };
    },
    async batchCreate(type, items, extraTagsPerItem) {
      calls.batchCreate.push({
        type,
        items: items.slice(),
        extraTagsPerItem: extraTagsPerItem.map((t) => t.slice()),
      });
      return items.map(() => ({
        txid: `tx-${++txidCounter}`,
        shareKey: `sk-${++shareKeyCounter}`,
      }));
    },
    async updateEntry(priorTxid, type, payload, extraTags) {
      calls.update.push({ priorTxid, type, payload: { ...payload }, extraTags: extraTags.slice() });
      return { txid: `tx-${++txidCounter}`, shareKey: `sk-${++shareKeyCounter}` };
    },
    async deleteEntry() { return { txid: 'unused' }; },
    async getEntries() { return []; },
    async getEntryByEid() { return null; },
    async getEntriesSince() { return { entries: [], deleted: [] }; },
    async getShareKey() { return null; },
    async fetchBlob() { return null; },
    async decryptSharedBlob() { return {}; },
    async listConnections() { return []; },
    async isMuted() { return false; },
    async shareContent() { return {}; },
    async unshareContent() { return {}; },
    async readShareLog() { return {}; },
    isLoggedIn() { return true; },
  };
  return client;
}

// ============ advanced.entries.create — defined collection ============

describe('AdvancedEntries.create (defined collection — Tarn #34)', () => {
  it('throws TarnSchemaError when payload is missing the required primaryKey', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    // 'bookId' is required by the schema; title alone is not enough.
    await assert.rejects(
      () => advanced.create('books', { title: 'lost' }),
      /required field 'bookId' is missing/,
    );
    assert.equal(fake.calls.create.length, 0, 'no wire call on validation failure');
  });

  it('throws TarnSchemaError when an unknown field is present (typo protection)', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    await assert.rejects(
      () => advanced.create('books', { bookId: 'b1', title: 'A', titel: 'typo' }),
      /unknown field 'titel'/,
    );
    assert.equal(fake.calls.create.length, 0);
  });

  it('throws TarnSchemaError on field type mismatch', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    await assert.rejects(
      // title declared as string — number violates it.
      () => advanced.create('books', { bookId: 'b1', title: 42 }),
      /field 'title': expected string/,
    );
    assert.equal(fake.calls.create.length, 0);
  });

  it('auto-stamps Eid + SchemaV when payload is valid', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    await advanced.create('books', { bookId: 'b1', title: 'A' });

    assert.equal(fake.calls.create.length, 1);
    const call = fake.calls.create[0];
    const eid = call.extraTags.find((t) => t.name === 'Eid');
    const schemaV = call.extraTags.find((t) => t.name === 'SchemaV');
    assert.ok(eid, 'Eid must be auto-stamped on a defined-collection write');
    assert.ok(schemaV, 'SchemaV must be auto-stamped on a defined-collection write');
    assert.equal(schemaV.value, '4');

    const expectedEid = await deriveEid('bookish', 'books', 'b1');
    assert.equal(eid.value, expectedEid, 'Eid must be derived from (appId, type, primaryKey)');
  });

  it('applies schema defaults (auto-fills isPrivate)', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    // isPrivate has default: false — omit it.
    await advanced.create('books', { bookId: 'b1', title: 'A' });
    const call = fake.calls.create[0];
    assert.equal(call.payload.isPrivate, false, 'schema default must be applied to the written payload');
  });

  it('respects a caller-supplied Eid that matches the derived value (no double-stamp)', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    const derived = await deriveEid('bookish', 'books', 'b1');
    await advanced.create(
      'books',
      { bookId: 'b1', title: 'A' },
      [{ name: 'Eid', value: derived }, { name: 'X-Custom', value: 'preserved' }],
    );

    const call = fake.calls.create[0];
    const eidTags = call.extraTags.filter((t) => t.name === 'Eid');
    assert.equal(eidTags.length, 1, 'caller-supplied Eid must not be double-stamped');
    assert.equal(eidTags[0].value, derived);
    // Other caller tags survive untouched.
    assert.ok(call.extraTags.find((t) => t.name === 'X-Custom' && t.value === 'preserved'));
  });

  it('respects a caller-supplied SchemaV (does not double-stamp)', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    await advanced.create(
      'books',
      { bookId: 'b1', title: 'A' },
      [{ name: 'SchemaV', value: '99' }],
    );
    const call = fake.calls.create[0];
    const schemaVs = call.extraTags.filter((t) => t.name === 'SchemaV');
    assert.equal(schemaVs.length, 1, 'caller-supplied SchemaV must not be double-stamped');
    assert.equal(schemaVs[0].value, '99');
  });

  it('throws TarnSchemaError when caller-supplied Eid does not match derived value', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    await assert.rejects(
      () => advanced.create(
        'books',
        { bookId: 'b1', title: 'A' },
        [{ name: 'Eid', value: 'mismatched-eid' }],
      ),
      /caller-supplied Eid 'mismatched-eid' does not match/,
    );
    assert.equal(fake.calls.create.length, 0, 'no wire call on Eid mismatch');
  });
});

// ============ advanced.entries.create — UNdefined type (escape hatch preserved) ============

describe('AdvancedEntries.create (undefined type — escape hatch preserved)', () => {
  it('passes payload through verbatim with no validation', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    // 'app-cache' is NOT in the schema. The SDK must not validate the
    // payload — apps can write anything they want under unknown types.
    await advanced.create('app-cache', { anything: 'goes', missing: undefined });
    assert.equal(fake.calls.create.length, 1);
    const call = fake.calls.create[0];
    assert.equal(call.type, 'app-cache');
    assert.equal(call.payload.anything, 'goes');
  });

  it('does not auto-stamp Eid or SchemaV for undefined types', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    await advanced.create('app-cache', { foo: 'bar' });
    const call = fake.calls.create[0];
    assert.equal(call.extraTags.find((t) => t.name === 'Eid'), undefined);
    assert.equal(call.extraTags.find((t) => t.name === 'SchemaV'), undefined);
  });

  it('forwards caller-supplied extraTags verbatim', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    const extraTags = [{ name: 'Anything', value: 'X' }, { name: 'Eid', value: 'caller-Eid-untouched' }];
    await advanced.create('app-cache', { foo: 'bar' }, extraTags);
    const call = fake.calls.create[0];
    // No validation for undefined types means the caller's Eid is passed
    // through as-is — including non-canonical values. The escape hatch
    // remains an escape hatch.
    assert.deepEqual(call.extraTags, extraTags);
  });

  it('behaves as a pure pass-through when no schemaInfo is supplied (legacy path)', async () => {
    // Some test paths instantiate AdvancedEntries with no schemaInfo at all
    // (no TarnClient context). The full pass-through behavior must still
    // be intact for that mode.
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake);
    await advanced.create('books', { whatever: 1 }, [{ name: 'Custom', value: 'Y' }]);
    const call = fake.calls.create[0];
    assert.equal(call.type, 'books');
    assert.deepEqual(call.extraTags, [{ name: 'Custom', value: 'Y' }]);
  });
});

// ============ advanced.entries.batchCreate — defined collection ============

describe('AdvancedEntries.batchCreate (defined collection — Tarn #34)', () => {
  it('stamps Eid + SchemaV on every item, derived from each primaryKey', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    const items = [
      { bookId: 'b1', title: 'Alpha' },
      { bookId: 'b2', title: 'Beta' },
    ];
    await advanced.batchCreate('books', items);

    assert.equal(fake.calls.batchCreate.length, 1);
    const call = fake.calls.batchCreate[0];
    assert.equal(call.extraTagsPerItem.length, 2);

    const eid1 = await deriveEid('bookish', 'books', 'b1');
    const eid2 = await deriveEid('bookish', 'books', 'b2');
    assert.equal(call.extraTagsPerItem[0].find((t) => t.name === 'Eid').value, eid1);
    assert.equal(call.extraTagsPerItem[1].find((t) => t.name === 'Eid').value, eid2);
    for (const tags of call.extraTagsPerItem) {
      assert.equal(tags.find((t) => t.name === 'SchemaV').value, '4');
    }
  });

  it('aggregates validation failures across the batch — no wire call', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    // Mix valid + invalid: indexes 1 and 3 fail.
    const items = [
      { bookId: 'b1', title: 'ok-0' },
      { title: 'no-pk' },                       // 1: missing bookId
      { bookId: 'b2', title: 'ok-2' },
      { bookId: 'b3' },                         // 3: missing title
    ];
    let thrown = null;
    try {
      await advanced.batchCreate('books', items);
    } catch (err) {
      thrown = err;
    }
    assert.ok(thrown, 'must throw');
    assert.match(thrown.message, /2\/4/, 'error must include failure count');
    assert.match(thrown.message, /\[1\]/, 'error must include failing index 1');
    assert.match(thrown.message, /\[3\]/, 'error must include failing index 3');
    // Both root causes are mentioned so the caller can fix everything at once,
    // not one round-trip per failure.
    assert.match(thrown.message, /required field 'bookId'/);
    assert.match(thrown.message, /required field 'title'/);
    assert.equal(fake.calls.batchCreate.length, 0, 'no wire call when any item fails');
  });

  it('respects caller-supplied per-item Eid that matches derived, no double-stamp', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    const items = [{ bookId: 'b1', title: 'A' }, { bookId: 'b2', title: 'B' }];
    const eid1 = await deriveEid('bookish', 'books', 'b1');
    const eid2 = await deriveEid('bookish', 'books', 'b2');
    const perItemExtraTags = [
      [{ name: 'Eid', value: eid1 }],
      [{ name: 'Eid', value: eid2 }],
    ];
    await advanced.batchCreate('books', items, [], perItemExtraTags);

    const call = fake.calls.batchCreate[0];
    for (const tags of call.extraTagsPerItem) {
      const eids = tags.filter((t) => t.name === 'Eid');
      assert.equal(eids.length, 1, 'caller per-item Eid must not be double-stamped');
    }
  });

  it('throws TarnSchemaError when a per-item caller Eid mismatches the derived value', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    const items = [{ bookId: 'b1', title: 'A' }];
    const perItemExtraTags = [[{ name: 'Eid', value: 'wrong' }]];
    await assert.rejects(
      () => advanced.batchCreate('books', items, [], perItemExtraTags),
      /caller-supplied Eid 'wrong' does not match/,
    );
    assert.equal(fake.calls.batchCreate.length, 0);
  });
});

// ============ advanced.entries.batchCreate — UNdefined type (escape hatch) ============

describe('AdvancedEntries.batchCreate (undefined type — escape hatch preserved)', () => {
  it('passes items through verbatim with no validation', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    const items = [{ anything: 1 }, { anything: 2 }];
    await advanced.batchCreate('app-cache', items);
    assert.equal(fake.calls.batchCreate.length, 1);
    assert.deepEqual(fake.calls.batchCreate[0].items, items);
  });

  it('does not auto-stamp Eid or SchemaV for undefined types', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    await advanced.batchCreate('app-cache', [{ foo: 1 }]);
    const tags = fake.calls.batchCreate[0].extraTagsPerItem[0];
    assert.equal(tags.find((t) => t.name === 'Eid'), undefined);
    assert.equal(tags.find((t) => t.name === 'SchemaV'), undefined);
  });

  it('preserves batch-level extraTags and per-item extras for undefined types', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    const batchTags = [{ name: 'Migration', value: 'v1' }];
    const perItem = [
      [{ name: 'Prev', value: 'orphan-tx-A' }],
      [{ name: 'Prev', value: 'orphan-tx-B' }],
    ];
    await advanced.batchCreate(
      'app-cache',
      [{ a: 1 }, { a: 2 }],
      batchTags,
      perItem,
    );
    const tags0 = fake.calls.batchCreate[0].extraTagsPerItem[0];
    const tags1 = fake.calls.batchCreate[0].extraTagsPerItem[1];
    assert.ok(tags0.find((t) => t.name === 'Migration' && t.value === 'v1'));
    assert.ok(tags0.find((t) => t.name === 'Prev' && t.value === 'orphan-tx-A'));
    assert.ok(tags1.find((t) => t.name === 'Prev' && t.value === 'orphan-tx-B'));
  });
});

// ============ advanced.entries.update — defined collection ============

describe('AdvancedEntries.update (defined collection — Tarn #34)', () => {
  it('validates payload and auto-stamps Eid + SchemaV', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    await advanced.update('prior-tx', 'books', { bookId: 'b1', title: 'New' });

    assert.equal(fake.calls.update.length, 1);
    const call = fake.calls.update[0];
    assert.equal(call.priorTxid, 'prior-tx');
    const eid = call.extraTags.find((t) => t.name === 'Eid');
    const expectedEid = await deriveEid('bookish', 'books', 'b1');
    assert.equal(eid.value, expectedEid, 'update Eid must match the canonical derivation');
    assert.ok(call.extraTags.find((t) => t.name === 'SchemaV'));
  });

  it('throws TarnSchemaError on validation failure (missing required field)', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    await assert.rejects(
      () => advanced.update('prior-tx', 'books', { bookId: 'b1' }),
      /required field 'title' is missing/,
    );
    assert.equal(fake.calls.update.length, 0);
  });

  it('passes through for undefined types without validation', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake, makeSchemaInfo());
    await advanced.update('prior-tx', 'app-cache', { whatever: 'X' });
    assert.equal(fake.calls.update.length, 1);
    assert.deepEqual(fake.calls.update[0].extraTags, []);
  });
});
