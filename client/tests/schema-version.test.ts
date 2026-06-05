/**
 * Read-side SchemaV version dispatch (Tarn #37 / audit finding SDK-1).
 *
 * Before this change the SDK stamped a `SchemaV` tag on every write and read
 * it nowhere — the first schema bump had no defined cross-version read
 * behavior. These tests pin the conservative policy (see
 * `collections/schema-version.ts` and `docs/SDK_ARCHITECTURE.md`):
 *
 *   - entryV === clientV          → normal read.
 *   - entryV  <  clientV          → backward-compatible: pass through (or run
 *                                   declared `migrations` forward).
 *   - entryV  >  clientV          → future entry: list()/getEntriesSince()
 *                                   skip-with-warning; get()/update() throw
 *                                   TarnSchemaVersionError.
 *   - missing SchemaV tag         → treated as oldest; never crashes.
 *
 * The pure dispatcher is exercised directly, then through Collection<T>'s
 * read paths via a small ITarnClient mock that lets us set arbitrary tags
 * (including a SchemaV the local Collection didn't write).
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { defineSchema } from '../src/schema/index.js';
import type { CollectionDef } from '../src/schema/index.js';
import {
  Collection,
  createCollection,
  deriveEid,
  TarnSchemaVersionError,
  readSchemaVTag,
  dispatchSchemaVersion,
  OLDEST_SCHEMA_VERSION,
} from '../src/collections/index.js';
import type { DecryptedEntry, ITarnClient, ShareConnection, Tag } from '../src/collections/index.js';

// ============ Minimal ITarnClient mock ============
//
// Unlike collection.test.ts's MockTarnClient (which synthesizes tags on
// write), this mock lets a test PLANT an entry with arbitrary tags — the
// whole point is to simulate an entry written by a different-version client.

class VersionMockClient implements ITarnClient {
  entries: DecryptedEntry[] = [];

  isLoggedIn(): boolean {
    return true;
  }

  /** Plant an entry with explicit tags (Type + Eid + whatever SchemaV). */
  plant(args: { type: string; eid: string | null; data: Record<string, unknown>; schemaV?: number | null; txid?: string }): void {
    const tags: Tag[] = [{ name: 'Type', value: args.type }];
    if (args.eid) tags.push({ name: 'Eid', value: args.eid });
    if (args.schemaV != null) tags.push({ name: 'SchemaV', value: String(args.schemaV) });
    this.entries.push({ txid: args.txid ?? `tx-${this.entries.length + 1}`, data: args.data, tags });
  }

  async createEntry(): Promise<{ txid: string; shareKey: string | null }> {
    throw new Error('not used');
  }
  async batchCreate(): Promise<Array<{ txid: string; shareKey: string | null }>> {
    throw new Error('not used');
  }
  async updateEntry(
    _priorTxid: string,
    type: string,
    plaintext: Record<string, unknown>,
    extraTags: Tag[] = [],
  ): Promise<{ txid: string; shareKey: string | null }> {
    const txid = `tx-upd-${this.entries.length + 1}`;
    this.entries.push({ txid, data: { ...plaintext }, tags: [{ name: 'Type', value: type }, ...extraTags] });
    return { txid, shareKey: null };
  }
  async deleteEntry(): Promise<{ txid: string }> {
    return { txid: 'tx-del' };
  }

  async getEntries(type: string): Promise<DecryptedEntry[]> {
    return this.entries.filter((e) => e.tags.some((t) => t.name === 'Type' && t.value === type));
  }

  async getEntryByEid(type: string, eid: string): Promise<DecryptedEntry | null> {
    return (
      this.entries.find(
        (e) =>
          e.tags.some((t) => t.name === 'Type' && t.value === type) &&
          e.tags.some((t) => t.name === 'Eid' && t.value === eid),
      ) ?? null
    );
  }

  getEntriesSinceResponse: {
    entries: Array<{ eid: string | null; txid: string; data: Record<string, unknown>; tags: Tag[] }>;
    deleted: string[];
  } = { entries: [], deleted: [] };
  async getEntriesSince(): Promise<{
    entries: Array<{ eid: string | null; txid: string; data: Record<string, unknown>; tags: Tag[] }>;
    deleted: string[];
  }> {
    return this.getEntriesSinceResponse;
  }

  async getShareKey(): Promise<string | null> {
    return null;
  }
  async fetchBlob(): Promise<Uint8Array | null> {
    return null;
  }
  async decryptSharedBlob(): Promise<Record<string, unknown>> {
    throw new Error('not used');
  }
  async listConnections(): Promise<ShareConnection[]> {
    return [];
  }
  async isMuted(): Promise<boolean> {
    return false;
  }
  async shareContent(): Promise<unknown> {
    return {};
  }
  async unshareContent(): Promise<unknown> {
    return {};
  }
  async readShareLog(): Promise<Record<string, { tx_id: string; cek: string }>> {
    return {};
  }
}

// Client schema version = 2. Entries can be planted at v1 (older), v2 (same),
// v3 (future), or with no SchemaV tag (legacy).
const CLIENT_VERSION = 2;
const schema = defineSchema({
  appId: 'bookish',
  version: CLIENT_VERSION,
  collections: {
    books: {
      primaryKey: 'bookId',
      fields: {
        bookId: 'string',
        title: 'string',
        rating: 'number?',
      },
    },
  },
});

function makeBooks(
  client: ITarnClient,
  migrations?: Record<number, (old: Record<string, unknown>) => Record<string, unknown>>,
): Collection<{ bookId: string; title: string; rating?: number }> {
  return createCollection({
    client,
    appId: schema.appId,
    name: 'books',
    def: schema.collections.books as CollectionDef,
    schemaVersion: schema.version,
    migrations,
  });
}

// ============ Pure dispatcher ============

describe('readSchemaVTag', () => {
  it('reads a valid integer SchemaV tag', () => {
    assert.equal(readSchemaVTag([{ name: 'SchemaV', value: '3' }]), 3);
  });
  it('returns null when absent', () => {
    assert.equal(readSchemaVTag([{ name: 'Type', value: 'books' }]), null);
  });
  it('returns null when malformed (non-numeric or < 1)', () => {
    assert.equal(readSchemaVTag([{ name: 'SchemaV', value: 'x' }]), null);
    assert.equal(readSchemaVTag([{ name: 'SchemaV', value: '0' }]), null);
  });
  it('returns null for non-array input', () => {
    assert.equal(readSchemaVTag(undefined), null);
  });
});

describe('dispatchSchemaVersion (pure)', () => {
  const rec = { bookId: 'b1', title: 'T' };

  it('same version → returns the record unchanged', () => {
    const out = dispatchSchemaVersion({
      record: rec,
      tags: [{ name: 'SchemaV', value: '2' }],
      clientVersion: 2,
    });
    assert.equal(out, rec);
  });

  it('older version, no migrations → pass-through (backward-compat)', () => {
    const out = dispatchSchemaVersion({
      record: rec,
      tags: [{ name: 'SchemaV', value: '1' }],
      clientVersion: 2,
    });
    assert.deepEqual(out, rec);
  });

  it('older version with a declared migrator → migrates forward', () => {
    const out = dispatchSchemaVersion({
      record: { bookId: 'b1', title: 'T' },
      tags: [{ name: 'SchemaV', value: '1' }],
      clientVersion: 2,
      migrations: { 1: (old) => ({ ...old, rating: 0 }) },
    });
    assert.deepEqual(out, { bookId: 'b1', title: 'T', rating: 0 });
  });

  it('chains multiple migrators across versions in ascending order', () => {
    const out = dispatchSchemaVersion({
      record: { v: 'start' },
      tags: [{ name: 'SchemaV', value: '1' }],
      clientVersion: 3,
      migrations: {
        1: (old) => ({ ...old, step1: true }),
        2: (old) => ({ ...old, step2: true }),
      },
    });
    assert.deepEqual(out, { v: 'start', step1: true, step2: true });
  });

  it('future version → throws TarnSchemaVersionError carrying both versions', () => {
    assert.throws(
      () =>
        dispatchSchemaVersion({
          record: rec,
          tags: [{ name: 'SchemaV', value: '5' }],
          clientVersion: 2,
          txid: 'tx-future',
        }),
      (err: unknown) => {
        assert.ok(err instanceof TarnSchemaVersionError);
        assert.equal(err.entryVersion, 5);
        assert.equal(err.clientVersion, 2);
        assert.equal(err.txid, 'tx-future');
        return true;
      },
    );
  });

  it('missing SchemaV tag → treated as oldest version (no crash)', () => {
    const out = dispatchSchemaVersion({
      record: rec,
      tags: [{ name: 'Type', value: 'books' }],
      clientVersion: 2,
    });
    // Oldest < client → backward-compat pass-through.
    assert.deepEqual(out, rec);
    assert.equal(OLDEST_SCHEMA_VERSION, 1);
  });
});

// ============ Collection.list ============

describe('Collection.list — SchemaV dispatch', () => {
  let mock: VersionMockClient;
  let books: Collection<{ bookId: string; title: string; rating?: number }>;

  beforeEach(() => {
    mock = new VersionMockClient();
    books = makeBooks(mock);
  });

  it('reads same-version entries normally', async () => {
    mock.plant({ type: 'books', eid: 'e1', data: { bookId: 'b1', title: 'Same' }, schemaV: 2 });
    const all = await books.list();
    assert.equal(all.length, 1);
    assert.equal(all[0]!.title, 'Same');
  });

  it('reads older-version entries (backward-compat)', async () => {
    mock.plant({ type: 'books', eid: 'e1', data: { bookId: 'b1', title: 'Old' }, schemaV: 1 });
    const all = await books.list();
    assert.equal(all.length, 1);
    assert.equal(all[0]!.title, 'Old');
  });

  it('reads entries with NO SchemaV tag without crashing', async () => {
    mock.plant({ type: 'books', eid: 'e1', data: { bookId: 'b1', title: 'Legacy' }, schemaV: null });
    const all = await books.list();
    assert.equal(all.length, 1);
    assert.equal(all[0]!.title, 'Legacy');
  });

  it('SKIPS future-version entries (one newer record cannot break the list)', async () => {
    mock.plant({ type: 'books', eid: 'e1', data: { bookId: 'b1', title: 'Now' }, schemaV: 2 });
    mock.plant({ type: 'books', eid: 'e2', data: { bookId: 'b2', title: 'Future', secret: 1 }, schemaV: 99 });
    const all = await books.list();
    assert.equal(all.length, 1, 'future-version entry should be skipped');
    assert.equal(all[0]!.title, 'Now');
  });

  it('applies a declared migrator to older entries on list', async () => {
    const booksWithMig = makeBooks(mock, { 1: (old) => ({ ...old, rating: 3 }) });
    mock.plant({ type: 'books', eid: 'e1', data: { bookId: 'b1', title: 'Old' }, schemaV: 1 });
    const all = await booksWithMig.list();
    assert.equal(all.length, 1);
    assert.equal(all[0]!.rating, 3);
  });
});

// ============ Collection.getEntriesSince ============

describe('Collection.getEntriesSince — SchemaV dispatch', () => {
  let mock: VersionMockClient;
  let books: Collection<{ bookId: string; title: string; rating?: number }>;

  beforeEach(() => {
    mock = new VersionMockClient();
    books = makeBooks(mock);
  });

  it('passes same/older entries through and SKIPS a future-version entry', async () => {
    mock.getEntriesSinceResponse = {
      entries: [
        { eid: 'e1', txid: 'tx-1', data: { bookId: 'b1', title: 'Same' }, tags: [{ name: 'SchemaV', value: '2' }] },
        { eid: 'e2', txid: 'tx-2', data: { bookId: 'b2', title: 'Old' }, tags: [{ name: 'SchemaV', value: '1' }] },
        { eid: 'e3', txid: 'tx-3', data: { bookId: 'b3', title: 'Future' }, tags: [{ name: 'SchemaV', value: '7' }] },
        { eid: 'e4', txid: 'tx-4', data: { bookId: 'b4', title: 'Legacy' }, tags: [] }, // no SchemaV
      ],
      deleted: ['e-gone'],
    };
    const { entries, deleted } = await books.getEntriesSince();
    const titles = entries.map((e) => e.record.title).sort();
    assert.deepEqual(titles, ['Legacy', 'Old', 'Same'], 'future-version (e3) must be skipped');
    assert.deepEqual(deleted, ['e-gone']);
  });

  it('migrates older delta entries forward when a migrator is declared', async () => {
    const booksWithMig = makeBooks(mock, { 1: (old) => ({ ...old, rating: 9 }) });
    mock.getEntriesSinceResponse = {
      entries: [
        { eid: 'e1', txid: 'tx-1', data: { bookId: 'b1', title: 'Old' }, tags: [{ name: 'SchemaV', value: '1' }] },
      ],
      deleted: [],
    };
    const { entries } = await booksWithMig.getEntriesSince();
    assert.equal(entries.length, 1);
    assert.equal(entries[0]!.record.rating, 9);
  });
});

// ============ Collection.get / update (single-record → throw) ============

describe('Collection.get — SchemaV dispatch', () => {
  let mock: VersionMockClient;
  let books: Collection<{ bookId: string; title: string; rating?: number }>;

  beforeEach(() => {
    mock = new VersionMockClient();
    books = makeBooks(mock);
  });

  it('returns a same-version record', async () => {
    const eid = await deriveEid('bookish', 'books', 'b1');
    mock.plant({ type: 'books', eid, data: { bookId: 'b1', title: 'Same' }, schemaV: 2 });
    const r = await books.get('b1');
    assert.ok(r);
    assert.equal(r.title, 'Same');
  });

  it('returns an older-version record (backward-compat)', async () => {
    const eid = await deriveEid('bookish', 'books', 'b1');
    mock.plant({ type: 'books', eid, data: { bookId: 'b1', title: 'Old' }, schemaV: 1 });
    const r = await books.get('b1');
    assert.ok(r);
    assert.equal(r.title, 'Old');
  });

  it('returns a record with no SchemaV tag (legacy, no crash)', async () => {
    const eid = await deriveEid('bookish', 'books', 'b1');
    mock.plant({ type: 'books', eid, data: { bookId: 'b1', title: 'Legacy' }, schemaV: null });
    const r = await books.get('b1');
    assert.ok(r);
    assert.equal(r.title, 'Legacy');
  });

  it('THROWS TarnSchemaVersionError on a future-version record (single-record read)', async () => {
    const eid = await deriveEid('bookish', 'books', 'b1');
    mock.plant({ type: 'books', eid, data: { bookId: 'b1', title: 'Future' }, schemaV: 42, txid: 'tx-fut' });
    await assert.rejects(
      () => books.get('b1'),
      (err: unknown) => {
        assert.ok(err instanceof TarnSchemaVersionError);
        assert.equal(err.entryVersion, 42);
        assert.equal(err.clientVersion, 2);
        return true;
      },
    );
  });

  it('update() refuses to read-modify-write a future-version record', async () => {
    const eid = await deriveEid('bookish', 'books', 'b1');
    mock.plant({ type: 'books', eid, data: { bookId: 'b1', title: 'Future' }, schemaV: 42 });
    await assert.rejects(() => books.update('b1', { title: 'Patched' }), TarnSchemaVersionError);
  });
});
