/**
 * Collection<T> unit tests. Exercises:
 *   - create: schema validation, Eid + SchemaV tag emission, payload passthrough
 *   - update: read-modify-write, Prev chain via priorTxid, partial merge, primaryKey lock
 *   - delete: tombstone with Eid tag, "not found" error path
 *   - get / list: round-trip from underlying client, primaryKey filtering
 *   - Eid determinism: same (app, collection, pk) → same Eid; different inputs → different
 *
 * Uses an in-memory MockTarnClient that records calls so we can assert on
 * exact arguments. The mock implements ITarnClient — Collection has no
 * dependency on the JS TarnClient under test.
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { defineSchema } from '../src/schema/index.js';
import type { CollectionDef } from '../src/schema/index.js';
import {
  Collection,
  createCollection,
  deriveEid,
  TarnCollectionError,
} from '../src/collections/index.js';
import type { DecryptedEntry, ITarnClient, Tag } from '../src/collections/index.js';

// ============ Mock underlying client ============

type CreateCall = { type: string; plaintext: Record<string, unknown>; extraTags: Tag[] };
type UpdateCall = { priorTxid: string; type: string; plaintext: Record<string, unknown>; extraTags: Tag[] };
type DeleteCall = { targetTxid: string; type: string; extraTags: Tag[] };

class MockTarnClient implements ITarnClient {
  entries: DecryptedEntry[] = [];
  createCalls: CreateCall[] = [];
  updateCalls: UpdateCall[] = [];
  deleteCalls: DeleteCall[] = [];
  getEntriesCalls: string[] = [];
  #txidCounter = 0;

  isLoggedIn(): boolean {
    return true;
  }

  async createEntry(
    type: string,
    plaintext: Record<string, unknown>,
    extraTags: Tag[] = [],
  ): Promise<{ txid: string }> {
    this.createCalls.push({ type, plaintext, extraTags });
    const txid = this.#nextTxid();
    this.entries.push({
      txid,
      data: { ...plaintext },
      tags: [{ name: 'Type', value: type }, ...extraTags],
    });
    return { txid };
  }

  async updateEntry(
    priorTxid: string,
    type: string,
    plaintext: Record<string, unknown>,
    extraTags: Tag[] = [],
  ): Promise<{ txid: string }> {
    this.updateCalls.push({ priorTxid, type, plaintext, extraTags });
    // Replace the prior entry to mimic the API's Prev-chain resolution.
    this.entries = this.entries.filter((e) => e.txid !== priorTxid);
    const txid = this.#nextTxid();
    this.entries.push({
      txid,
      data: { ...plaintext },
      tags: [{ name: 'Type', value: type }, ...extraTags],
    });
    return { txid };
  }

  async deleteEntry(
    targetTxid: string,
    type: string,
    extraTags: Tag[] = [],
  ): Promise<{ txid: string }> {
    this.deleteCalls.push({ targetTxid, type, extraTags });
    // Remove the target to mimic tombstone resolution.
    this.entries = this.entries.filter((e) => e.txid !== targetTxid);
    return { txid: this.#nextTxid() };
  }

  async getEntries(type: string): Promise<DecryptedEntry[]> {
    this.getEntriesCalls.push(type);
    return this.entries.filter((e) => e.tags.some((t) => t.name === 'Type' && t.value === type));
  }

  #nextTxid(): string {
    this.#txidCounter++;
    return `mock-tx-${this.#txidCounter}`;
  }
}

// ============ Test fixtures ============

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

type BookRecord = {
  bookId: string;
  title: string;
  author?: string;
  rating?: number;
  isPrivate: boolean;
};

function makeBooks(client: MockTarnClient): Collection<BookRecord> {
  return createCollection<BookRecord>({
    client,
    appId: schema.appId,
    name: 'books',
    def: schema.collections.books as CollectionDef,
    schemaVersion: schema.version,
  });
}

// ============ Eid determinism ============

describe('deriveEid', () => {
  it('produces the same Eid for the same (app, collection, primaryKey)', async () => {
    const a = await deriveEid('bookish', 'books', 'b1');
    const b = await deriveEid('bookish', 'books', 'b1');
    assert.equal(a, b);
  });

  it('produces different Eids for different primaryKeys', async () => {
    const a = await deriveEid('bookish', 'books', 'b1');
    const b = await deriveEid('bookish', 'books', 'b2');
    assert.notEqual(a, b);
  });

  it('produces different Eids for different collections', async () => {
    const a = await deriveEid('bookish', 'books', 'b1');
    const b = await deriveEid('bookish', 'notes', 'b1');
    assert.notEqual(a, b);
  });

  it('produces different Eids for different apps', async () => {
    const a = await deriveEid('bookish', 'books', 'b1');
    const b = await deriveEid('otherapp', 'books', 'b1');
    assert.notEqual(a, b);
  });

  it('returns base64url-shaped output (no padding, no +/)', async () => {
    const eid = await deriveEid('bookish', 'books', 'b1');
    assert.ok(/^[A-Za-z0-9_-]+$/.test(eid), `Eid should be base64url; got '${eid}'`);
    assert.ok(!eid.includes('='));
    assert.ok(!eid.includes('+'));
    assert.ok(!eid.includes('/'));
  });
});

// ============ Collection.create ============

describe('Collection.create', () => {
  let mock: MockTarnClient;
  let books: Collection<BookRecord>;

  beforeEach(() => {
    mock = new MockTarnClient();
    books = makeBooks(mock);
  });

  it('writes a validated record with Eid + SchemaV tags', async () => {
    await books.create({ bookId: 'b1', title: 'Foo', isPrivate: false });

    assert.equal(mock.createCalls.length, 1);
    const call = mock.createCalls[0]!;
    assert.equal(call.type, 'books');
    assert.equal(call.plaintext['bookId'], 'b1');
    assert.equal(call.plaintext['title'], 'Foo');
    assert.equal(call.plaintext['isPrivate'], false);

    const tagNames = call.extraTags.map((t) => t.name);
    assert.ok(tagNames.includes('Eid'), 'Eid tag should be present');
    assert.ok(tagNames.includes('SchemaV'), 'SchemaV tag should be present');

    const eidTag = call.extraTags.find((t) => t.name === 'Eid')!;
    const expectedEid = await deriveEid('bookish', 'books', 'b1');
    assert.equal(eidTag.value, expectedEid);

    const schemaVTag = call.extraTags.find((t) => t.name === 'SchemaV')!;
    assert.equal(schemaVTag.value, '4');
  });

  it('applies schema defaults', async () => {
    // isPrivate has default: false. Omit it from the create call.
    await books.create({ bookId: 'b2', title: 'Bar' } as BookRecord);
    const call = mock.createCalls[0]!;
    assert.equal(call.plaintext['isPrivate'], false);
  });

  it('rejects unknown fields (typo protection)', async () => {
    await assert.rejects(
      () => books.create({ bookId: 'b1', title: 'Foo', titel: 'typo', isPrivate: false } as unknown as BookRecord),
      /unknown field 'titel'/,
    );
  });

  it('rejects missing required field', async () => {
    await assert.rejects(
      () => books.create({ bookId: 'b1', isPrivate: false } as BookRecord),
      /required field 'title'/,
    );
  });

  it('rejects empty primaryKey', async () => {
    await assert.rejects(
      () => books.create({ bookId: '', title: 'Foo', isPrivate: false }),
      // Schema validation produces a string-type-ok record, then primaryKey
      // extraction rejects the empty value.
      /primaryKey 'bookId' must be a non-empty string/,
    );
  });

  it('two creates with the same primaryKey produce the same Eid', async () => {
    await books.create({ bookId: 'b1', title: 'First', isPrivate: false });
    // Second create with same pk would normally be an app-level mistake; we
    // verify only that the Eid is stable, not that the SDK prevents it
    // (preventing duplicates is an app or API rules concern).
    await books.create({ bookId: 'b1', title: 'Second', isPrivate: false });
    const eidA = mock.createCalls[0]!.extraTags.find((t) => t.name === 'Eid')!.value;
    const eidB = mock.createCalls[1]!.extraTags.find((t) => t.name === 'Eid')!.value;
    assert.equal(eidA, eidB);
  });
});

// ============ Collection.update ============

describe('Collection.update', () => {
  let mock: MockTarnClient;
  let books: Collection<BookRecord>;

  beforeEach(async () => {
    mock = new MockTarnClient();
    books = makeBooks(mock);
    await books.create({ bookId: 'b1', title: 'Foo', author: 'AuthorA', isPrivate: false });
  });

  it('partial-update merges patch into prior record', async () => {
    await books.update('b1', { rating: 5 });

    assert.equal(mock.updateCalls.length, 1);
    const call = mock.updateCalls[0]!;
    assert.equal(call.priorTxid, 'mock-tx-1', 'Prev should chain to the original txid');
    assert.equal(call.type, 'books');
    // All prior fields preserved + patch applied.
    assert.equal(call.plaintext['bookId'], 'b1');
    assert.equal(call.plaintext['title'], 'Foo');
    assert.equal(call.plaintext['author'], 'AuthorA');
    assert.equal(call.plaintext['rating'], 5);
    assert.equal(call.plaintext['isPrivate'], false);
  });

  it('attaches the same Eid as the original create', async () => {
    await books.update('b1', { rating: 5 });
    const createEid = mock.createCalls[0]!.extraTags.find((t) => t.name === 'Eid')!.value;
    const updateEid = mock.updateCalls[0]!.extraTags.find((t) => t.name === 'Eid')!.value;
    assert.equal(createEid, updateEid);
  });

  it('rejects updating the primaryKey', async () => {
    await assert.rejects(
      () => books.update('b1', { bookId: 'b2' } as Partial<BookRecord>),
      /cannot update primaryKey 'bookId'/,
    );
  });

  it('rejects unknown fields in patch', async () => {
    await assert.rejects(
      () => books.update('b1', { titel: 'typo' } as unknown as Partial<BookRecord>),
      /unknown field 'titel'/,
    );
  });

  it('throws TarnCollectionError when the record does not exist', async () => {
    await assert.rejects(
      () => books.update('does-not-exist', { rating: 5 }),
      TarnCollectionError,
    );
  });

  it('two sequential updates chain via Prev', async () => {
    await books.update('b1', { rating: 5 });   // mock-tx-1 -> mock-tx-2
    await books.update('b1', { rating: 4 });   // mock-tx-2 -> mock-tx-3
    assert.equal(mock.updateCalls[0]!.priorTxid, 'mock-tx-1');
    assert.equal(mock.updateCalls[1]!.priorTxid, 'mock-tx-2');
  });
});

// ============ Collection.delete ============

describe('Collection.delete', () => {
  let mock: MockTarnClient;
  let books: Collection<BookRecord>;

  beforeEach(async () => {
    mock = new MockTarnClient();
    books = makeBooks(mock);
    await books.create({ bookId: 'b1', title: 'Foo', isPrivate: false });
  });

  it('tombstones the live record with the matching Eid', async () => {
    await books.delete('b1');

    assert.equal(mock.deleteCalls.length, 1);
    const call = mock.deleteCalls[0]!;
    assert.equal(call.targetTxid, 'mock-tx-1');
    assert.equal(call.type, 'books');

    const eidTag = call.extraTags.find((t) => t.name === 'Eid');
    assert.ok(eidTag, 'Eid tag should be present on tombstone');
    const expectedEid = await deriveEid('bookish', 'books', 'b1');
    assert.equal(eidTag.value, expectedEid);
  });

  it('throws TarnCollectionError when the record does not exist', async () => {
    await assert.rejects(
      () => books.delete('does-not-exist'),
      TarnCollectionError,
    );
  });
});

// ============ Collection.get / list ============

describe('Collection.get / list', () => {
  let mock: MockTarnClient;
  let books: Collection<BookRecord>;

  beforeEach(() => {
    mock = new MockTarnClient();
    books = makeBooks(mock);
  });

  it('list returns [] when collection is empty', async () => {
    const all = await books.list();
    assert.deepEqual(all, []);
  });

  it('get returns null when primaryKey is absent', async () => {
    const r = await books.get('nope');
    assert.equal(r, null);
  });

  it('list returns all live records', async () => {
    await books.create({ bookId: 'b1', title: 'A', isPrivate: false });
    await books.create({ bookId: 'b2', title: 'B', isPrivate: false });
    const all = await books.list();
    assert.equal(all.length, 2);
    assert.deepEqual(all.map((b) => b.bookId).sort(), ['b1', 'b2']);
  });

  it('get returns the matching record', async () => {
    await books.create({ bookId: 'b1', title: 'A', isPrivate: false });
    await books.create({ bookId: 'b2', title: 'B', isPrivate: false });
    const r = await books.get('b2');
    assert.ok(r);
    assert.equal(r.title, 'B');
  });

  it('list reflects updates (prior version not returned)', async () => {
    await books.create({ bookId: 'b1', title: 'Original', isPrivate: false });
    await books.update('b1', { title: 'Revised' });
    const all = await books.list();
    assert.equal(all.length, 1);
    assert.equal(all[0]!.title, 'Revised');
  });

  it('list reflects deletes (record gone)', async () => {
    await books.create({ bookId: 'b1', title: 'A', isPrivate: false });
    await books.create({ bookId: 'b2', title: 'B', isPrivate: false });
    await books.delete('b1');
    const all = await books.list();
    assert.equal(all.length, 1);
    assert.equal(all[0]!.bookId, 'b2');
  });
});
