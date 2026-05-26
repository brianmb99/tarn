// Unit tests for `advanced.entries.batchCreate` (tarn #23).
//
// Covers the schema-first wrapper at AdvancedEntries.batchCreate:
//   - surface presence on the namespace class
//   - throws on empty input
//   - throws on items.length > 25
//   - forwards (type, items, extraTags) to the underlying client's batchCreate
//   - returns the underlying client's array verbatim, preserving input order
//
// Exercises the wrapper in isolation against a hand-rolled fake that records
// call arguments — no schema bootstrap, no live API, no Crypto subtle. The
// full IUnderlyingClient stub path (with TarnClient.create assembly) is
// covered separately in client/tests/client.test.ts.
//
// Run via the repo-level runner: npm run test:unit

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { AdvancedEntries } from '../../client/src/client/namespaces/advanced.js';

function makeFakeClient() {
  const calls = [];
  let txidCounter = 0;
  let shareKeyCounter = 0;
  const client = {
    calls,
    async batchCreate(type, items, extraTags) {
      calls.push({ type, items: items.slice(), extraTags: extraTags === undefined ? undefined : extraTags.slice() });
      return items.map(() => ({
        txid: `tx-${++txidCounter}`,
        shareKey: `sk-${++shareKeyCounter}`,
      }));
    },
    // The rest of IAdvancedClient is unused by batchCreate but required for
    // the type cast at the AdvancedEntries constructor. We provide no-op
    // stubs so static checks pass; the methods are never called from these
    // tests.
    async createEntry() { return { txid: 'unused', shareKey: null }; },
    async updateEntry() { return { txid: 'unused', shareKey: null }; },
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

describe('AdvancedEntries.batchCreate', () => {
  it('exposes batchCreate as a function on the namespace', () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake);
    assert.equal(typeof advanced.batchCreate, 'function');
  });

  it('throws on empty input without calling the underlying client', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake);
    await assert.rejects(
      () => advanced.batchCreate('books', []),
      /non-empty/i,
    );
    assert.equal(fake.calls.length, 0);
  });

  it('throws on 26 items without calling the underlying client', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake);
    const items = Array.from({ length: 26 }, (_, i) => ({ i }));
    await assert.rejects(
      () => advanced.batchCreate('books', items),
      /max 25/i,
    );
    assert.equal(fake.calls.length, 0);
  });

  it('accepts the boundary case of exactly 25 items', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake);
    const items = Array.from({ length: 25 }, (_, i) => ({ i }));
    const out = await advanced.batchCreate('books', items);
    assert.equal(out.length, 25);
    assert.equal(fake.calls.length, 1);
    assert.equal(fake.calls[0].items.length, 25);
  });

  it('forwards (type, items, extraTags) verbatim to the underlying client', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake);
    const items = [{ a: 1 }, { a: 2 }];
    const extraTags = [{ name: 'Migration', value: 'v1' }];
    await advanced.batchCreate('books', items, extraTags);
    assert.equal(fake.calls.length, 1);
    assert.equal(fake.calls[0].type, 'books');
    assert.deepEqual(fake.calls[0].items, items);
    assert.deepEqual(fake.calls[0].extraTags, extraTags);
  });

  it('defaults extraTags to [] when omitted', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake);
    await advanced.batchCreate('books', [{ a: 1 }]);
    assert.equal(fake.calls.length, 1);
    assert.deepEqual(fake.calls[0].extraTags, []);
  });

  it('returns the underlying result preserving input order', async () => {
    const fake = makeFakeClient();
    const advanced = new AdvancedEntries(fake);
    const items = [{ marker: 'first' }, { marker: 'second' }, { marker: 'third' }];
    const out = await advanced.batchCreate('books', items);
    assert.equal(out.length, 3);
    // Fake assigns txid/shareKey in the order it iterates items, so the
    // first input maps to tx-1/sk-1 and so on. The wrapper must not reorder.
    assert.deepEqual(
      out.map((r) => r.txid),
      ['tx-1', 'tx-2', 'tx-3'],
    );
    assert.deepEqual(
      out.map((r) => r.shareKey),
      ['sk-1', 'sk-2', 'sk-3'],
    );
  });
});
