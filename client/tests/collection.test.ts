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
import type { DecryptedEntry, ITarnClient, ShareConnection, Tag } from '../src/collections/index.js';

// ============ Mock underlying client ============

type CreateCall = { type: string; plaintext: Record<string, unknown>; extraTags: Tag[] };
type UpdateCall = { priorTxid: string; type: string; plaintext: Record<string, unknown>; extraTags: Tag[] };
type DeleteCall = { targetTxid: string; type: string; extraTags: Tag[] };
type ShareCall = { connection: ShareConnection; contentId: string; txid: string; shareKey: string };
type UnshareCall = { connection: ShareConnection; contentId: string };

class MockTarnClient implements ITarnClient {
  entries: DecryptedEntry[] = [];
  shareKeysByTxid = new Map<string, string>();
  createCalls: CreateCall[] = [];
  updateCalls: UpdateCall[] = [];
  deleteCalls: DeleteCall[] = [];
  getEntriesCalls: string[] = [];
  shareCalls: ShareCall[] = [];
  unshareCalls: UnshareCall[] = [];
  shareLogStateByConnection = new Map<string, Record<string, { tx_id: string; cek: string }>>();
  connections: ShareConnection[] = [];
  mutedSharePubs = new Set<string>();
  blobsByTxid = new Map<string, Uint8Array>();
  decryptedBySharedBlob = new Map<string, Record<string, unknown>>();
  #txidCounter = 0;
  #shareKeyCounter = 0;

  isLoggedIn(): boolean {
    return true;
  }

  async createEntry(
    type: string,
    plaintext: Record<string, unknown>,
    extraTags: Tag[] = [],
  ): Promise<{ txid: string; shareKey: string | null }> {
    this.createCalls.push({ type, plaintext, extraTags });
    const txid = this.#nextTxid();
    const shareKey = this.#nextShareKey();
    this.entries.push({
      txid,
      data: { ...plaintext },
      tags: [{ name: 'Type', value: type }, ...extraTags],
    });
    this.shareKeysByTxid.set(txid, shareKey);
    return { txid, shareKey };
  }

  // Tracked for assertions: Collection<T>.batchCreate exercises this path.
  // Captures (type, items, extraTagsPerItem) so tests can verify the per-item
  // Eid + SchemaV stamping.
  batchCreateCalls: Array<{
    type: string;
    items: Array<Record<string, unknown>>;
    extraTagsPerItem: Tag[][];
  }> = [];
  async batchCreate(
    type: string,
    items: Array<Record<string, unknown>>,
    extraTagsPerItem: Tag[][] = [],
  ): Promise<Array<{ txid: string; shareKey: string | null }>> {
    this.batchCreateCalls.push({ type, items, extraTagsPerItem });
    const out: Array<{ txid: string; shareKey: string | null }> = [];
    for (let i = 0; i < items.length; i++) {
      const item = items[i]!;
      const perItem = extraTagsPerItem[i] ?? [];
      const txid = this.#nextTxid();
      const shareKey = this.#nextShareKey();
      this.entries.push({
        txid,
        data: { ...item },
        tags: [{ name: 'Type', value: type }, ...perItem],
      });
      this.shareKeysByTxid.set(txid, shareKey);
      out.push({ txid, shareKey });
    }
    return out;
  }

  async updateEntry(
    priorTxid: string,
    type: string,
    plaintext: Record<string, unknown>,
    extraTags: Tag[] = [],
  ): Promise<{ txid: string; shareKey: string | null }> {
    this.updateCalls.push({ priorTxid, type, plaintext, extraTags });
    this.entries = this.entries.filter((e) => e.txid !== priorTxid);
    const txid = this.#nextTxid();
    const shareKey = this.#nextShareKey();
    this.entries.push({
      txid,
      data: { ...plaintext },
      tags: [{ name: 'Type', value: type }, ...extraTags],
    });
    this.shareKeysByTxid.set(txid, shareKey);
    return { txid, shareKey };
  }

  async deleteEntry(
    targetTxid: string,
    type: string,
    extraTags: Tag[] = [],
  ): Promise<{ txid: string }> {
    this.deleteCalls.push({ targetTxid, type, extraTags });
    this.entries = this.entries.filter((e) => e.txid !== targetTxid);
    return { txid: this.#nextTxid() };
  }

  async getEntries(type: string): Promise<DecryptedEntry[]> {
    this.getEntriesCalls.push(type);
    return this.entries.filter((e) => e.tags.some((t) => t.name === 'Type' && t.value === type));
  }

  // Narrowed Eid lookup. Tracked separately so tests can assert call shape and
  // confirm callers stopped using getEntries for single-record lookups.
  getEntryByEidCalls: Array<{ type: string; eid: string }> = [];
  async getEntryByEid(type: string, eid: string): Promise<DecryptedEntry | null> {
    this.getEntryByEidCalls.push({ type, eid });
    const match = this.entries.find((e) =>
      e.tags.some((t) => t.name === 'Type' && t.value === type) &&
      e.tags.some((t) => t.name === 'Eid' && t.value === eid),
    );
    return match ?? null;
  }

  // Delta-sync stub. Tests inject scenarios by setting `getEntriesSinceResponse`
  // before calling Collection.getEntriesSince(); the mock returns whatever is
  // pre-staged. Calls are tracked for shape assertions.
  getEntriesSinceCalls: string[] = [];
  getEntriesSinceResponse: {
    entries: Array<{ eid: string | null; txid: string; data: Record<string, unknown>; tags: Tag[] }>;
    deleted: string[];
  } = { entries: [], deleted: [] };
  async getEntriesSince(type: string): Promise<{
    entries: Array<{ eid: string | null; txid: string; data: Record<string, unknown>; tags: Tag[] }>;
    deleted: string[];
  }> {
    this.getEntriesSinceCalls.push(type);
    return this.getEntriesSinceResponse;
  }

  // ---- Blob / shareKey helpers ----

  async getShareKey(txid: string): Promise<string | null> {
    return this.shareKeysByTxid.get(txid) ?? null;
  }

  async fetchBlob(txid: string): Promise<Uint8Array | null> {
    return this.blobsByTxid.get(txid) ?? null;
  }

  async decryptSharedBlob(blob: Uint8Array, _shareKey: string): Promise<Record<string, unknown>> {
    // Mock decrypt: look up by blob bytes (using length+first byte as key
    // to avoid Uint8Array identity issues).
    const key = `${blob.length}:${blob[0] ?? 0}`;
    const found = this.decryptedBySharedBlob.get(key);
    if (!found) throw new Error('mock decryptSharedBlob: blob not registered');
    return found;
  }

  // ---- Sharing primitives ----

  async listConnections(): Promise<ShareConnection[]> {
    return this.connections;
  }

  async isMuted(connection: ShareConnection): Promise<boolean> {
    return this.mutedSharePubs.has(connection.share_pub);
  }

  async shareContent(
    connection: ShareConnection,
    contentId: string,
    txid: string,
    shareKey: string,
  ): Promise<unknown> {
    this.shareCalls.push({ connection, contentId, txid, shareKey });
    let state = this.shareLogStateByConnection.get(connection.share_pub);
    if (!state) {
      state = {};
      this.shareLogStateByConnection.set(connection.share_pub, state);
    }
    state[contentId] = { tx_id: txid, cek: shareKey };
    return { ok: true };
  }

  async unshareContent(connection: ShareConnection, contentId: string): Promise<unknown> {
    this.unshareCalls.push({ connection, contentId });
    const state = this.shareLogStateByConnection.get(connection.share_pub);
    if (state) delete state[contentId];
    return { ok: true };
  }

  async readShareLog(
    connection: ShareConnection,
  ): Promise<Record<string, { tx_id: string; cek: string }>> {
    return this.shareLogStateByConnection.get(connection.share_pub) ?? {};
  }

  // ---- Helpers for tests ----

  #blobCounter = 0;

  /** Register a (blob, plaintext) pair so decryptSharedBlob can resolve it. */
  registerSharedBlob(txid: string, plaintext: Record<string, unknown>): Uint8Array {
    this.#blobCounter++;
    // First byte uniquely identifies this blob in the mock-decrypt map.
    const bytes = new Uint8Array([this.#blobCounter, 1, 2, 3, 4]);
    this.blobsByTxid.set(txid, bytes);
    const key = `${bytes.length}:${bytes[0] ?? 0}`;
    this.decryptedBySharedBlob.set(key, plaintext);
    return bytes;
  }

  #nextTxid(): string {
    this.#txidCounter++;
    return `mock-tx-${this.#txidCounter}`;
  }

  #nextShareKey(): string {
    this.#shareKeyCounter++;
    return `mock-sk-${this.#shareKeyCounter}`;
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

  // ---- { unset } option (issue #26) ----

  it('unset clears an optional field — key absent on returned record and on get()', async () => {
    // Seed an optional field via update so we know it was actually present.
    await books.update('b1', { rating: 5 });
    assert.equal((await books.get('b1'))!.rating, 5);

    const returned = await books.update('b1', {}, { unset: ['rating'] });

    // 1. Returned record: the key must be truly absent, not undefined / null.
    assert.ok(!Object.prototype.hasOwnProperty.call(returned, 'rating'),
      `expected 'rating' to be absent from returned record; got ${JSON.stringify(returned)}`);

    // 2. Last persisted entry: the key must be truly absent on the wire.
    const lastUpdate = mock.updateCalls.at(-1)!;
    assert.ok(!Object.prototype.hasOwnProperty.call(lastUpdate.plaintext, 'rating'),
      `expected 'rating' to be absent from persisted plaintext; got ${JSON.stringify(lastUpdate.plaintext)}`);

    // 3. Round-trip via get(): the key must remain absent on read-back.
    const readBack = await books.get('b1');
    assert.ok(readBack);
    assert.ok(!Object.prototype.hasOwnProperty.call(readBack, 'rating'),
      `expected 'rating' to be absent on get(); got ${JSON.stringify(readBack)}`);
  });

  it('unset of a field that was never present is a no-op (no error)', async () => {
    // 'rating' was never set on b1 in the beforeEach seed.
    const returned = await books.update('b1', {}, { unset: ['rating'] });
    assert.ok(!Object.prototype.hasOwnProperty.call(returned, 'rating'));
    // All other fields are still there.
    assert.equal(returned.bookId, 'b1');
    assert.equal(returned.title, 'Foo');
    assert.equal(returned.author, 'AuthorA');
    assert.equal(returned.isPrivate, false);
  });

  it('unset of a required field throws the existing required-field validation error', async () => {
    await assert.rejects(
      () => books.update('b1', {}, { unset: ['title'] }),
      /required field 'title'/,
    );
  });

  it('when the same field is in both patch and unset, unset wins (delete-after-merge)', async () => {
    // 'rating' is optional, so we can exercise the precedence cleanly.
    const returned = await books.update('b1', { rating: 5 }, { unset: ['rating'] });
    assert.ok(!Object.prototype.hasOwnProperty.call(returned, 'rating'),
      `expected unset to win over patch; got ${JSON.stringify(returned)}`);

    // And the persisted entry agrees.
    const lastUpdate = mock.updateCalls.at(-1)!;
    assert.ok(!Object.prototype.hasOwnProperty.call(lastUpdate.plaintext, 'rating'));
  });

  it('empty unset: [] behaves identically to omitting the option', async () => {
    await books.update('b1', { rating: 5 });
    const before = mock.updateCalls.length;

    const returned = await books.update('b1', { author: 'AuthorB' }, { unset: [] });

    // rating is still there, author updated, exactly one new entry chain step.
    assert.equal(returned.rating, 5);
    assert.equal(returned.author, 'AuthorB');
    assert.equal(mock.updateCalls.length, before + 1);
  });

  it('unset with multiple fields clears all of them in a single write', async () => {
    // Set author and rating both first; then clear both in one update.
    await books.update('b1', { rating: 5 });
    const before = mock.updateCalls.length;

    const returned = await books.update('b1', {}, { unset: ['author', 'rating'] });

    // Exactly one new chain entry — not two.
    assert.equal(mock.updateCalls.length, before + 1);

    // Both fields gone on the returned record.
    assert.ok(!Object.prototype.hasOwnProperty.call(returned, 'author'));
    assert.ok(!Object.prototype.hasOwnProperty.call(returned, 'rating'));

    // And on the persisted entry.
    const lastUpdate = mock.updateCalls.at(-1)!;
    assert.ok(!Object.prototype.hasOwnProperty.call(lastUpdate.plaintext, 'author'));
    assert.ok(!Object.prototype.hasOwnProperty.call(lastUpdate.plaintext, 'rating'));
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

  it('is idempotent: missing record returns silently with no delete call', async () => {
    // delete() used to throw TarnCollectionError on a missing primaryKey.
    // After the Eid-lookup refactor it became idempotent — REST DELETE
    // semantics, and the previous behavior turned retry loops into death
    // loops when a record was already gone.
    await books.delete('does-not-exist'); // must not throw
    assert.equal(mock.deleteCalls.length, 0, 'no delete call should be issued for a missing record');
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

// ============ Collection.batchCreate ============

describe('Collection.batchCreate', () => {
  let mock: MockTarnClient;
  let books: Collection<BookRecord>;

  beforeEach(() => {
    mock = new MockTarnClient();
    books = makeBooks(mock);
  });

  it('throws on empty input without calling the underlying client', async () => {
    await assert.rejects(() => books.batchCreate([]), TarnCollectionError);
    assert.equal(mock.batchCreateCalls.length, 0);
  });

  it('throws on > 25 items', async () => {
    const items = Array.from({ length: 26 }, (_, i) => ({
      bookId: `b${i}`,
      title: `T${i}`,
      isPrivate: false,
    }));
    await assert.rejects(() => books.batchCreate(items), TarnCollectionError);
    assert.equal(mock.batchCreateCalls.length, 0);
  });

  it('stamps Eid + SchemaV per item, derived from each primaryKey', async () => {
    const items: BookRecord[] = [
      { bookId: 'b1', title: 'Alpha', isPrivate: false },
      { bookId: 'b2', title: 'Beta', isPrivate: true },
    ];
    await books.batchCreate(items);

    assert.equal(mock.batchCreateCalls.length, 1);
    const call = mock.batchCreateCalls[0]!;
    assert.equal(call.type, 'books');
    assert.equal(call.extraTagsPerItem.length, 2);

    // Eids derived from each primaryKey — must match Collection.eidFor.
    const expectedEid1 = await books.eidFor('b1');
    const expectedEid2 = await books.eidFor('b2');
    assert.equal(call.extraTagsPerItem[0]!.find((t) => t.name === 'Eid')!.value, expectedEid1);
    assert.equal(call.extraTagsPerItem[1]!.find((t) => t.name === 'Eid')!.value, expectedEid2);

    // SchemaV stamped on every item.
    for (const tags of call.extraTagsPerItem) {
      assert.ok(tags.find((t) => t.name === 'SchemaV')?.value, 'SchemaV must be stamped');
    }
  });

  it('validates each record before sending to the underlying client', async () => {
    // Missing required `bookId` should fail validation.
    await assert.rejects(
      () => books.batchCreate([{ title: 'no-id', isPrivate: false } as unknown as BookRecord]),
      TarnCollectionError,
    );
    assert.equal(mock.batchCreateCalls.length, 0, 'no wire call on validation failure');
  });

  it('aggregates all validation failures with input indexes — no wire call', async () => {
    // Mix of valid + invalid records. Index 1 and 3 fail; the error must
    // mention both, and no wire call happens.
    const items: Array<Partial<BookRecord>> = [
      { bookId: 'ok-1', title: 'Good', isPrivate: false },           // 0: ok
      { bookId: 'bad-2', isPrivate: false },                          // 1: missing title
      { bookId: 'ok-3', title: 'Good', isPrivate: false },           // 2: ok
      { title: 'no-id', isPrivate: false },                           // 3: missing bookId
    ];
    let thrown: unknown = null;
    try {
      await books.batchCreate(items as BookRecord[]);
    } catch (err) {
      thrown = err;
    }
    assert.ok(thrown instanceof TarnCollectionError, 'must throw TarnCollectionError');
    const msg = (thrown as TarnCollectionError).message;
    // Summary names the failing indexes (1 and 3) and the count (2/4).
    assert.match(msg, /2\/4/, `error must report failure count; got: ${msg}`);
    assert.match(msg, /\[1\]/, `error must mention failing index 1; got: ${msg}`);
    assert.match(msg, /\[3\]/, `error must mention failing index 3; got: ${msg}`);
    assert.equal(mock.batchCreateCalls.length, 0, 'no wire call even when some records validate');
  });

  it('returns the validated records in input order', async () => {
    const items: BookRecord[] = [
      { bookId: 'b1', title: 'A', isPrivate: false },
      { bookId: 'b2', title: 'B', isPrivate: false },
      { bookId: 'b3', title: 'C', isPrivate: false },
    ];
    const out = await books.batchCreate(items);
    assert.equal(out.length, 3);
    assert.deepEqual(out.map((r) => r.bookId), ['b1', 'b2', 'b3']);
  });
});

// ============ Collection.getEntriesSince + eidFor ============

describe('Collection.getEntriesSince', () => {
  let mock: MockTarnClient;
  let books: Collection<BookRecord>;

  beforeEach(() => {
    mock = new MockTarnClient();
    books = makeBooks(mock);
  });

  it('forwards to the underlying client with this collection name', async () => {
    await books.getEntriesSince();
    assert.deepEqual(mock.getEntriesSinceCalls, ['books']);
  });

  it('returns typed { record, eid } pairs alongside deleted Eids', async () => {
    mock.getEntriesSinceResponse = {
      entries: [
        {
          eid: 'eid-b1',
          txid: 'tx-1',
          data: { bookId: 'b1', title: 'Alpha', isPrivate: false },
          tags: [],
        },
        {
          eid: 'eid-b2',
          txid: 'tx-2',
          data: { bookId: 'b2', title: 'Beta', isPrivate: true },
          tags: [],
        },
      ],
      deleted: ['eid-gone'],
    };

    const { entries, deleted } = await books.getEntriesSince();
    assert.equal(entries.length, 2);
    assert.equal(entries[0]!.record.title, 'Alpha');
    assert.equal(entries[0]!.eid, 'eid-b1');
    assert.equal(entries[1]!.record.title, 'Beta');
    assert.deepEqual(deleted, ['eid-gone']);
  });

  it('drops orphan events (no Eid) — typed Collection always writes with Eid', async () => {
    mock.getEntriesSinceResponse = {
      entries: [
        { eid: null, txid: 'tx-orphan', data: { bookId: 'lost' }, tags: [] },
        { eid: 'eid-real', txid: 'tx-1', data: { bookId: 'b1', title: 'kept', isPrivate: false }, tags: [] },
      ],
      deleted: [],
    };

    const { entries } = await books.getEntriesSince();
    assert.equal(entries.length, 1, 'orphan event should be dropped');
    assert.equal(entries[0]!.eid, 'eid-real');
  });
});

describe('Collection.eidFor', () => {
  it('returns the same Eid that create() attaches to the entry', async () => {
    const mock = new MockTarnClient();
    const books = makeBooks(mock);

    await books.create({ bookId: 'b1', title: 'X', isPrivate: false });
    const eidFromCreate = mock.createCalls[0]!.extraTags.find((t) => t.name === 'Eid')!.value;

    const eidFromHelper = await books.eidFor('b1');
    assert.equal(eidFromHelper, eidFromCreate,
      'Collection.eidFor must match the Eid the protocol layer stamps on writes');
  });
});

// ============ Sharing — share / shareWithAll / unshare / listShared ============

const conn1: ShareConnection = { share_pub: 'sp-conn1', signing_pub: 'sg-conn1' };
const conn2: ShareConnection = { share_pub: 'sp-conn2', signing_pub: 'sg-conn2' };
const conn3: ShareConnection = { share_pub: 'sp-conn3', signing_pub: 'sg-conn3' };

describe('Collection.share', () => {
  let mock: MockTarnClient;
  let books: Collection<BookRecord>;

  beforeEach(async () => {
    mock = new MockTarnClient();
    mock.connections = [conn1, conn2];
    books = makeBooks(mock);
    await books.create({ bookId: 'b1', title: 'Foo', isPrivate: false });
  });

  it('publishes (contentId, txid, shareKey) to one connection', async () => {
    await books.share(conn1, 'b1');
    assert.equal(mock.shareCalls.length, 1);
    const call = mock.shareCalls[0]!;
    assert.equal(call.connection, conn1);
    assert.equal(call.contentId, 'books:b1');
    assert.equal(call.txid, 'mock-tx-1');
    assert.equal(call.shareKey, 'mock-sk-1');
  });

  it('throws when the record does not exist', async () => {
    await assert.rejects(() => books.share(conn1, 'does-not-exist'), TarnCollectionError);
  });

  it('throws when the collection is not shareable', async () => {
    const settingsCol = createCollection<{ key: string; value: unknown }>({
      client: mock,
      appId: 'bookish',
      name: 'settings',
      def: {
        primaryKey: 'key',
        fields: { key: 'string', value: 'json' },
        shareable: false,
      },
      schemaVersion: 4,
    });
    await assert.rejects(() => settingsCol.share(conn1, 'theme'), /requires the collection to declare shareable: true/);
  });

  it('after update, share emits the new (txid, shareKey) — supersedes prior', async () => {
    await books.share(conn1, 'b1');                            // emits mock-tx-1 / mock-sk-1
    await books.update('b1', { rating: 5 });                   // mock-tx-2 / mock-sk-2
    await books.share(conn1, 'b1');                            // should emit mock-tx-2 / mock-sk-2

    assert.equal(mock.shareCalls.length, 2);
    assert.equal(mock.shareCalls[0]!.txid, 'mock-tx-1');
    assert.equal(mock.shareCalls[0]!.shareKey, 'mock-sk-1');
    assert.equal(mock.shareCalls[1]!.txid, 'mock-tx-2');
    assert.equal(mock.shareCalls[1]!.shareKey, 'mock-sk-2');
  });
});

describe('Collection.shareWithAll', () => {
  let mock: MockTarnClient;
  let books: Collection<BookRecord>;

  beforeEach(async () => {
    mock = new MockTarnClient();
    mock.connections = [conn1, conn2, conn3];
    books = makeBooks(mock);
    await books.create({ bookId: 'b1', title: 'Foo', isPrivate: false });
  });

  it('publishes to every connection', async () => {
    const result = await books.shareWithAll('b1');
    assert.equal(result.ok, 3);
    assert.equal(result.failed.length, 0);
    assert.equal(mock.shareCalls.length, 3);
    const sharePubs = mock.shareCalls.map((c) => c.connection.share_pub).sort();
    assert.deepEqual(sharePubs, ['sp-conn1', 'sp-conn2', 'sp-conn3']);
  });

  it('skips muted connections', async () => {
    mock.mutedSharePubs.add(conn2.share_pub);
    const result = await books.shareWithAll('b1');
    assert.equal(result.ok, 2);
    const sharePubs = mock.shareCalls.map((c) => c.connection.share_pub).sort();
    assert.deepEqual(sharePubs, ['sp-conn1', 'sp-conn3']);
  });

  it('records per-connection failures without aborting the loop', async () => {
    const orig = mock.shareContent.bind(mock);
    let failOnce = true;
    mock.shareContent = async (conn, cid, txid, sk) => {
      if (failOnce && conn.share_pub === conn2.share_pub) {
        failOnce = false;
        throw new Error('simulated transient');
      }
      return orig(conn, cid, txid, sk);
    };
    const result = await books.shareWithAll('b1');
    assert.equal(result.ok, 2);
    assert.equal(result.failed.length, 1);
    assert.equal(result.failed[0]!.connection.share_pub, 'sp-conn2');
    assert.match(result.failed[0]!.error, /simulated transient/);
  });
});

describe('Collection.unshare', () => {
  let mock: MockTarnClient;
  let books: Collection<BookRecord>;

  beforeEach(async () => {
    mock = new MockTarnClient();
    mock.connections = [conn1];
    books = makeBooks(mock);
    await books.create({ bookId: 'b1', title: 'Foo', isPrivate: false });
    await books.share(conn1, 'b1');
  });

  it('publishes a remove op for the contentId', async () => {
    await books.unshare(conn1, 'b1');
    assert.equal(mock.unshareCalls.length, 1);
    assert.equal(mock.unshareCalls[0]!.contentId, 'books:b1');
  });
});

describe('Collection.listShared', () => {
  let mock: MockTarnClient;
  let books: Collection<BookRecord>;

  beforeEach(() => {
    mock = new MockTarnClient();
    books = makeBooks(mock);
  });

  it('returns [] when the connection has no share-log state', async () => {
    const result = await books.listShared(conn1);
    assert.deepEqual(result, []);
  });

  it('fetches and decrypts every shared record', async () => {
    // Set up two shared books on conn1's share-log.
    mock.shareLogStateByConnection.set(conn1.share_pub, {
      'books:b1': { tx_id: 'tx-friend-1', cek: 'sk-friend-1' },
      'books:b2': { tx_id: 'tx-friend-2', cek: 'sk-friend-2' },
    });
    mock.registerSharedBlob('tx-friend-1', { bookId: 'b1', title: 'Friend Book 1', isPrivate: false });
    mock.registerSharedBlob('tx-friend-2', { bookId: 'b2', title: 'Friend Book 2', isPrivate: false });

    const result = await books.listShared(conn1);
    assert.equal(result.length, 2);
    const titles = result.map((r) => r.title).sort();
    assert.deepEqual(titles, ['Friend Book 1', 'Friend Book 2']);
  });

  it('filters by collection (ignores share-log entries for other collections)', async () => {
    mock.shareLogStateByConnection.set(conn1.share_pub, {
      'books:b1': { tx_id: 'tx-friend-1', cek: 'sk-friend-1' },
      'notes:n1': { tx_id: 'tx-friend-9', cek: 'sk-friend-9' }, // different collection
    });
    mock.registerSharedBlob('tx-friend-1', { bookId: 'b1', title: 'Book', isPrivate: false });
    mock.registerSharedBlob('tx-friend-9', { noteId: 'n1', body: 'Note' });

    const result = await books.listShared(conn1);
    assert.equal(result.length, 1);
    assert.equal(result[0]!.bookId, 'b1');
  });

  it('skips entries whose blob is unavailable', async () => {
    mock.shareLogStateByConnection.set(conn1.share_pub, {
      'books:b1': { tx_id: 'tx-friend-1', cek: 'sk-friend-1' },
      'books:b2': { tx_id: 'tx-missing', cek: 'sk-friend-2' },
    });
    mock.registerSharedBlob('tx-friend-1', { bookId: 'b1', title: 'Book 1', isPrivate: false });
    // tx-missing has no blob registered.

    const result = await books.listShared(conn1);
    assert.equal(result.length, 1);
    assert.equal(result[0]!.bookId, 'b1');
  });

  it('skips entries whose decrypt fails', async () => {
    mock.shareLogStateByConnection.set(conn1.share_pub, {
      'books:b1': { tx_id: 'tx-friend-1', cek: 'sk-friend-1' },
    });
    // Don't register the blob with the mock decrypter — fetchBlob returns
    // bytes but decryptSharedBlob will throw because the (length, first-byte)
    // key isn't registered.
    mock.blobsByTxid.set('tx-friend-1', new Uint8Array([99, 99, 99]));

    const result = await books.listShared(conn1);
    assert.equal(result.length, 0);
  });
});
