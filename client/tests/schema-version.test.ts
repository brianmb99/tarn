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

import { defineSchema, resolveCollectionMigrations, isScopedMigrations } from '../src/schema/index.js';
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
  async syncShareLog(): Promise<Record<string, { tx_id: string; cek: string }>> {
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

// ============ Tarn #55: migration shape resolution + scoping ============

/** Capture console.warn calls for the duration of `fn`, then restore. */
async function captureWarns(fn: () => void | Promise<void>): Promise<string[]> {
  const warns: string[] = [];
  const orig = console.warn;
  console.warn = (...args: unknown[]) => {
    warns.push(args.map((a) => (typeof a === 'string' ? a : String(a))).join(' '));
  };
  try {
    await fn();
  } finally {
    console.warn = orig;
  }
  return warns;
}

describe('migration shape resolution (Tarn #55)', () => {
  type R = Record<string, unknown>;

  it('isScopedMigrations: numeric keys → flat; collection-name keys → scoped', () => {
    assert.equal(isScopedMigrations({ 1: (r: R) => r }), false);
    assert.equal(isScopedMigrations({ books: { 1: (r: R) => r } }), true);
    // Empty → treated as flat (no migrators either way).
    assert.equal(isScopedMigrations({}), false);
  });

  it('flat shape resolves to the same map for every collection (legacy)', () => {
    const flat = { 1: (r: R) => ({ ...r, touched: true }) };
    const forBooks = resolveCollectionMigrations(flat, 'books');
    const forNotes = resolveCollectionMigrations(flat, 'notes');
    assert.equal(forBooks, flat);
    assert.equal(forNotes, flat);
  });

  it('scoped shape resolves ONLY the named collection (the fix)', () => {
    const booksMig = { 1: (r: R) => ({ ...r, fromBooks: true }) };
    const scoped = { books: booksMig };
    assert.equal(resolveCollectionMigrations(scoped, 'books'), booksMig);
    // notes has no scoped entry → undefined → the migrator never runs on notes.
    assert.equal(resolveCollectionMigrations(scoped, 'notes'), undefined);
  });

  it('undefined migrations → undefined for any collection', () => {
    assert.equal(resolveCollectionMigrations(undefined, 'books'), undefined);
  });

  it('end-to-end: a scoped books-only migrator does NOT touch notes records', async () => {
    // Two collections, client at v2. Plant a v1 record in each. Only books has
    // a declared v1 migrator. notes' v1 record must pass through untouched.
    const booksMock = new VersionMockClient();
    const notesMock = new VersionMockClient();

    const booksMig = resolveCollectionMigrations(
      { books: { 1: (r: R) => ({ ...r, migrated: true }) } },
      'books',
    );
    const notesMig = resolveCollectionMigrations(
      { books: { 1: (r: R) => ({ ...r, migrated: true }) } },
      'notes',
    );

    const books = createCollection<{ bookId: string; title: string; migrated?: boolean }>({
      client: booksMock,
      appId: 'bookish',
      name: 'books',
      def: { primaryKey: 'bookId', fields: { bookId: 'string', title: 'string' } },
      schemaVersion: 2,
      migrations: booksMig,
    });
    const notes = createCollection<{ noteId: string; body: string; migrated?: boolean }>({
      client: notesMock,
      appId: 'bookish',
      name: 'notes',
      def: { primaryKey: 'noteId', fields: { noteId: 'string', body: 'string' } },
      schemaVersion: 2,
      migrations: notesMig,
    });

    booksMock.plant({ type: 'books', eid: 'be1', data: { bookId: 'b1', title: 'B' }, schemaV: 1 });
    notesMock.plant({ type: 'notes', eid: 'ne1', data: { noteId: 'n1', body: 'N' }, schemaV: 1 });

    const bookList = await books.list();
    const noteList = await notes.list();

    assert.equal(bookList[0]!.migrated, true, 'books migrator should run on books');
    assert.equal(
      Object.prototype.hasOwnProperty.call(noteList[0]!, 'migrated'),
      false,
      'books migrator must NOT have touched notes (Tarn #55)',
    );
  });
});

// ============ Tarn #58c: migration chain gap warning ============

describe('migration chain gap warning (Tarn #58c)', () => {
  type R = Record<string, unknown>;

  it('warns when a declared-migrations chain has a gap on the walked range', async () => {
    // Client v3, entry v1. Migrators declared for 1 and... nothing for 2.
    // Because migrations IS declared, the missing step 2 should warn.
    const warns = await captureWarns(() => {
      dispatchSchemaVersion({
        record: { bookId: 'b1', title: 'T' },
        tags: [{ name: 'SchemaV', value: '1' }],
        clientVersion: 3,
        migrations: { 1: (r: R) => r }, // step 2 missing → gap
        txid: 'tx-gap',
      });
    });
    assert.equal(warns.length, 1, 'exactly one gap warning expected');
    assert.match(warns[0]!, /migration chain gap/);
    assert.match(warns[0]!, /version\(s\) 2/);
  });

  it('does NOT warn when NO migrations are declared (all-additive contract)', async () => {
    const warns = await captureWarns(() => {
      dispatchSchemaVersion({
        record: { bookId: 'b1', title: 'T' },
        tags: [{ name: 'SchemaV', value: '1' }],
        clientVersion: 3,
        // no migrations at all → additive contract, stays silent.
      });
    });
    assert.equal(warns.length, 0);
  });

  it('does NOT warn when the chain is complete', async () => {
    const warns = await captureWarns(() => {
      dispatchSchemaVersion({
        record: { bookId: 'b1', title: 'T' },
        tags: [{ name: 'SchemaV', value: '1' }],
        clientVersion: 3,
        migrations: { 1: (r: R) => r, 2: (r: R) => r }, // complete
      });
    });
    assert.equal(warns.length, 0);
  });
});

// ============ Tarn #57: missing-required-field read warning ============

describe('missing-required-field read warning (Tarn #57)', () => {
  const defWithRequired: CollectionDef = {
    primaryKey: 'bookId',
    fields: {
      bookId: 'string',
      title: 'string',
      // v2 added this REQUIRED field with no default and no migrator — the
      // landmine. A v1 record lacks it.
      isbn: 'string',
    },
  };

  it('warns when an older record is missing a required field after dispatch', async () => {
    const warns = await captureWarns(() => {
      dispatchSchemaVersion({
        record: { bookId: 'b1', title: 'Old' }, // no isbn
        tags: [{ name: 'SchemaV', value: '1' }],
        clientVersion: 2,
        def: defWithRequired,
        txid: 'tx-missing',
      });
    });
    assert.equal(warns.length, 1);
    assert.match(warns[0]!, /missing required field\(s\) \[isbn\]/);
    assert.match(warns[0]!, /returned unchanged/);
  });

  it('returns the record UNCHANGED (non-breaking: warn, never throw/drop)', async () => {
    const rec = { bookId: 'b1', title: 'Old' };
    let out: Record<string, unknown> = {};
    // Wrap in captureWarns purely to keep the expected warning out of test
    // output — the assertion here is about the RETURN value, not the warn.
    await captureWarns(() => {
      out = dispatchSchemaVersion({
        record: rec,
        tags: [{ name: 'SchemaV', value: '1' }],
        clientVersion: 2,
        def: defWithRequired,
      });
    });
    assert.deepEqual(out, rec, 'record must pass through; no fields added or removed');
  });

  it('does NOT warn when a migrator fills the required field', async () => {
    const warns = await captureWarns(() => {
      const out = dispatchSchemaVersion({
        record: { bookId: 'b1', title: 'Old' },
        tags: [{ name: 'SchemaV', value: '1' }],
        clientVersion: 2,
        def: defWithRequired,
        migrations: { 1: (r) => ({ ...r, isbn: '000' }) },
      });
      assert.equal((out as Record<string, unknown>)['isbn'], '000');
    });
    assert.equal(warns.length, 0, 'a migrator that fills the field must suppress the warning');
  });

  it('does NOT warn when the required field has a default', async () => {
    const defWithDefault: CollectionDef = {
      primaryKey: 'bookId',
      fields: {
        bookId: 'string',
        title: 'string',
        // required, but with a default — the validator fills it on create.
        flag: { type: 'boolean', default: false },
      },
    };
    const warns = await captureWarns(() => {
      dispatchSchemaVersion({
        record: { bookId: 'b1', title: 'Old' },
        tags: [{ name: 'SchemaV', value: '1' }],
        clientVersion: 2,
        def: defWithDefault,
      });
    });
    assert.equal(warns.length, 0);
  });

  it('does NOT warn for same-version reads (hot path untouched)', async () => {
    const warns = await captureWarns(() => {
      dispatchSchemaVersion({
        record: { bookId: 'b1', title: 'T' }, // missing isbn but same version
        tags: [{ name: 'SchemaV', value: '2' }],
        clientVersion: 2,
        def: defWithRequired,
      });
    });
    assert.equal(warns.length, 0, 'same-version reads return early, no required-field scan');
  });
});
