/**
 * Schema module unit tests. Exercises:
 *   - defineSchema validation: shape, reserved names, required structure
 *   - Field DSL: shorthand, long-form, defaults, enums
 *   - validateRecordForCreate: required fields, unknown fields, defaults, type coercion
 *   - validateRecordForUpdate: partial, primaryKey lock, unknown rejection
 *
 * Run via: cd client && npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  defineSchema,
  TarnSchemaError,
  validateRecordForCreate,
  validateRecordForUpdate,
  RESERVED_TYPE_NAMES,
} from '../src/schema/index.js';
import type { CollectionDef } from '../src/schema/index.js';

// ============ defineSchema — shape validation ============

describe('defineSchema', () => {
  it('accepts a minimal valid schema', () => {
    const s = defineSchema({
      appId: 'bookish',
      version: 1,
      collections: {
        books: {
          primaryKey: 'id',
          fields: { id: 'string', title: 'string' },
        },
      },
    });
    assert.equal(s.appId, 'bookish');
    assert.equal(s.version, 1);
    assert.equal(s.collections.books.primaryKey, 'id');
  });

  it('rejects non-object input', () => {
    assert.throws(() => defineSchema(null as unknown as never), TarnSchemaError);
    assert.throws(() => defineSchema('hi' as unknown as never), TarnSchemaError);
  });

  it('rejects empty appId', () => {
    assert.throws(
      () => defineSchema({
        appId: '',
        version: 1,
        collections: { c: { primaryKey: 'id', fields: { id: 'string' } } },
      }),
      /appId/,
    );
  });

  it('rejects non-positive-integer version', () => {
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 0,
        collections: { c: { primaryKey: 'id', fields: { id: 'string' } } },
      }),
      /version/,
    );
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: -1,
        collections: { c: { primaryKey: 'id', fields: { id: 'string' } } },
      }),
      /version/,
    );
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 1.5,
        collections: { c: { primaryKey: 'id', fields: { id: 'string' } } },
      }),
      /version/,
    );
  });

  it('rejects empty collections', () => {
    assert.throws(
      () => defineSchema({ appId: 'x', version: 1, collections: {} }),
      /at least one collection/,
    );
  });

  it('rejects reserved collection names', () => {
    for (const reserved of RESERVED_TYPE_NAMES) {
      assert.throws(
        () => defineSchema({
          appId: 'x',
          version: 1,
          collections: {
            [reserved]: { primaryKey: 'id', fields: { id: 'string' } },
          },
        }),
        /reserved/,
        `expected '${reserved}' to be rejected`,
      );
    }
  });

  it('rejects invalid collection name format', () => {
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 1,
        collections: { Books: { primaryKey: 'id', fields: { id: 'string' } } },
      }),
      /must match/,
    );
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 1,
        collections: { '1books': { primaryKey: 'id', fields: { id: 'string' } } },
      }),
      /must match/,
    );
  });

  it('rejects collection where primaryKey is not a declared field', () => {
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 1,
        collections: { books: { primaryKey: 'missing', fields: { id: 'string' } } },
      }),
      /primaryKey 'missing' is not declared/,
    );
  });

  it('rejects collection where primaryKey field is optional', () => {
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 1,
        collections: { books: { primaryKey: 'id', fields: { id: 'string?' } } },
      }),
      /must be required/,
    );
  });

  it('rejects empty fields', () => {
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 1,
        collections: { books: { primaryKey: 'id', fields: {} } },
      }),
      /at least one field/,
    );
  });

  it('rejects invalid field type names', () => {
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 1,
        collections: {
          books: {
            primaryKey: 'id',
            fields: { id: 'string', bad: 'wat' as unknown as 'string' },
          },
        },
      }),
      /invalid type/,
    );
  });

  it('accepts shorthand and long-form fields side by side', () => {
    const s = defineSchema({
      appId: 'x',
      version: 1,
      collections: {
        books: {
          primaryKey: 'id',
          fields: {
            id: 'string',
            title: 'string',
            author: 'string?',
            rating: 'number?',
            isPrivate: { type: 'boolean', default: false },
            status: { type: 'string', enum: ['unread', 'reading', 'read'] as const },
          },
        },
      },
    });
    assert.equal(s.collections.books.fields.author, 'string?');
  });

  it('rejects field with empty enum array', () => {
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 1,
        collections: {
          books: {
            primaryKey: 'id',
            fields: {
              id: 'string',
              status: { type: 'string', enum: [] as readonly string[] },
            },
          },
        },
      }),
      /non-empty array/,
    );
  });

  it('accepts migrations for prior versions only', () => {
    type R = Record<string, unknown>;
    const s = defineSchema({
      appId: 'x',
      version: 3,
      collections: { books: { primaryKey: 'id', fields: { id: 'string' } } },
      migrations: {
        1: (r: R) => ({ ...r, migratedFromV1: true }),
        2: (r: R) => ({ ...r, migratedFromV2: true }),
      },
    });
    assert.ok(s.migrations);
  });

  it('rejects migration for current or future version', () => {
    type R = Record<string, unknown>;
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 2,
        collections: { books: { primaryKey: 'id', fields: { id: 'string' } } },
        migrations: { 2: (r: R) => r },
      }),
      /not less than current/,
    );
  });

  // ---- Tarn #58b: defaults validated at defineSchema time ----

  it('rejects a default of the wrong type (Tarn #58b)', () => {
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 1,
        collections: {
          books: {
            primaryKey: 'id',
            fields: {
              id: 'string',
              // boolean field with a string default — must fail at definition.
              isPrivate: { type: 'boolean', default: 'nope' as unknown as boolean },
            },
          },
        },
      }),
      /invalid default/,
    );
  });

  it('rejects a default outside the field enum (Tarn #58b)', () => {
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 1,
        collections: {
          books: {
            primaryKey: 'id',
            fields: {
              id: 'string',
              status: { type: 'string', enum: ['unread', 'read'] as const, default: 'shelved' },
            },
          },
        },
      }),
      /invalid default/,
    );
  });

  it('rejects an invalid date default (Tarn #58b)', () => {
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 1,
        collections: {
          books: {
            primaryKey: 'id',
            fields: {
              id: 'string',
              addedAt: { type: 'date', required: false, default: 'not a date' },
            },
          },
        },
      }),
      /invalid default/,
    );
  });

  it('accepts a valid default (Tarn #58b — no false positive)', () => {
    const s = defineSchema({
      appId: 'x',
      version: 1,
      collections: {
        books: {
          primaryKey: 'id',
          fields: {
            id: 'string',
            isPrivate: { type: 'boolean', default: false },
            status: { type: 'string', enum: ['unread', 'read'] as const, default: 'unread' },
            count: { type: 'integer', required: false, default: 0 },
          },
        },
      },
    });
    assert.ok(s);
  });

  // ---- Tarn #55: collection-scoped migrations validation ----

  it('accepts collection-scoped migrations (Tarn #55)', () => {
    type R = Record<string, unknown>;
    const s = defineSchema({
      appId: 'x',
      version: 2,
      collections: {
        books: { primaryKey: 'id', fields: { id: 'string' } },
        notes: { primaryKey: 'nid', fields: { nid: 'string' } },
      },
      migrations: {
        books: { 1: (r: R) => ({ ...r, fromBooksV1: true }) },
        notes: { 1: (r: R) => ({ ...r, fromNotesV1: true }) },
      },
    });
    assert.ok(s.migrations);
  });

  it('rejects scoped migrations naming an unknown collection (Tarn #55)', () => {
    type R = Record<string, unknown>;
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 2,
        collections: { books: { primaryKey: 'id', fields: { id: 'string' } } },
        migrations: { widgets: { 1: (r: R) => r } },
      }),
      /unknown collection 'widgets'/,
    );
  });

  it('rejects scoped migration for current/future version (Tarn #55)', () => {
    type R = Record<string, unknown>;
    assert.throws(
      () => defineSchema({
        appId: 'x',
        version: 2,
        collections: { books: { primaryKey: 'id', fields: { id: 'string' } } },
        migrations: { books: { 2: (r: R) => r } },
      }),
      /not less than current/,
    );
  });
});

// ============ validateRecordForCreate ============

const booksCollection: CollectionDef = {
  primaryKey: 'id',
  fields: {
    id: 'string',
    title: 'string',
    author: 'string?',
    rating: 'number?',
    isPrivate: { type: 'boolean', default: false },
    status: { type: 'string', enum: ['unread', 'reading', 'read'] as const },
    pages: 'integer?',
    addedAt: 'date?',
    notes: 'json?',
  },
};

describe('validateRecordForCreate', () => {
  it('accepts a valid record', () => {
    const out = validateRecordForCreate('books', booksCollection, {
      id: 'b1',
      title: 'Foo',
      author: 'Bar',
      status: 'reading',
    });
    assert.equal(out['id'], 'b1');
    assert.equal(out['author'], 'Bar');
    assert.equal(out['status'], 'reading');
    // Default applied for isPrivate.
    assert.equal(out['isPrivate'], false);
    // Optional unset fields are not present in the output.
    assert.equal('rating' in out, false);
  });

  it('throws when required field is missing', () => {
    assert.throws(
      () => validateRecordForCreate('books', booksCollection, { id: 'b1', status: 'unread' }),
      /required field 'title'/,
    );
  });

  it('throws on unknown field (typo protection)', () => {
    assert.throws(
      () => validateRecordForCreate('books', booksCollection, {
        id: 'b1', title: 'Foo', status: 'unread', titel: 'typo',
      }),
      /unknown field 'titel'/,
    );
  });

  it('throws on type mismatch', () => {
    assert.throws(
      () => validateRecordForCreate('books', booksCollection, {
        id: 'b1', title: 123, status: 'unread',
      }),
      /expected string, got number/,
    );
  });

  it('rejects non-finite numbers', () => {
    assert.throws(
      () => validateRecordForCreate('books', booksCollection, {
        id: 'b1', title: 'Foo', status: 'unread', rating: Infinity,
      }),
      /expected finite number/,
    );
    assert.throws(
      () => validateRecordForCreate('books', booksCollection, {
        id: 'b1', title: 'Foo', status: 'unread', rating: NaN,
      }),
      /expected finite number/,
    );
  });

  it('rejects non-integer for integer field', () => {
    assert.throws(
      () => validateRecordForCreate('books', booksCollection, {
        id: 'b1', title: 'Foo', status: 'unread', pages: 100.5,
      }),
      /expected integer/,
    );
  });

  it('rejects enum violation', () => {
    assert.throws(
      () => validateRecordForCreate('books', booksCollection, {
        id: 'b1', title: 'Foo', status: 'shelved',
      }),
      /not in enum/,
    );
  });

  it('coerces ISO date string to Date', () => {
    const out = validateRecordForCreate('books', booksCollection, {
      id: 'b1', title: 'Foo', status: 'unread', addedAt: '2026-05-01T12:00:00Z',
    });
    assert.ok(out['addedAt'] instanceof Date);
    assert.equal((out['addedAt'] as Date).getUTCFullYear(), 2026);
  });

  it('rejects invalid date string', () => {
    assert.throws(
      () => validateRecordForCreate('books', booksCollection, {
        id: 'b1', title: 'Foo', status: 'unread', addedAt: 'not a date',
      }),
      /expected ISO date string/,
    );
  });

  it('accepts json field with arbitrary structure', () => {
    const out = validateRecordForCreate('books', booksCollection, {
      id: 'b1', title: 'Foo', status: 'unread',
      notes: { custom: { nested: [1, 2, 3] }, count: 5 },
    });
    assert.deepEqual(out['notes'], { custom: { nested: [1, 2, 3] }, count: 5 });
  });

  it('rejects non-JSON-serializable json field (BigInt)', () => {
    assert.throws(
      () => validateRecordForCreate('books', booksCollection, {
        id: 'b1', title: 'Foo', status: 'unread',
        notes: { big: 1n },
      }),
      /not JSON-serializable/,
    );
  });

  it('rejects non-object payloads', () => {
    assert.throws(
      () => validateRecordForCreate('books', booksCollection, null),
      /non-array object/,
    );
    assert.throws(
      () => validateRecordForCreate('books', booksCollection, [] as unknown),
      /non-array object/,
    );
    assert.throws(
      () => validateRecordForCreate('books', booksCollection, 'hi'),
      /non-array object/,
    );
  });

  it('accepts Date instance directly', () => {
    const d = new Date('2026-05-01');
    const out = validateRecordForCreate('books', booksCollection, {
      id: 'b1', title: 'Foo', status: 'unread', addedAt: d,
    });
    assert.equal(out['addedAt'], d);
  });
});

// ============ validateRecordForUpdate ============

describe('validateRecordForUpdate', () => {
  it('accepts a valid partial patch', () => {
    const out = validateRecordForUpdate('books', booksCollection, { rating: 5 });
    assert.deepEqual(out, { rating: 5 });
  });

  it('rejects updates to primaryKey', () => {
    assert.throws(
      () => validateRecordForUpdate('books', booksCollection, { id: 'b2' }),
      /cannot update primaryKey 'id'/,
    );
  });

  it('rejects unknown fields', () => {
    assert.throws(
      () => validateRecordForUpdate('books', booksCollection, { titel: 'typo' }),
      /unknown field 'titel'/,
    );
  });

  it('skips undefined values silently', () => {
    const out = validateRecordForUpdate('books', booksCollection, { rating: undefined });
    assert.deepEqual(out, {});
  });

  it('validates types on patch fields', () => {
    assert.throws(
      () => validateRecordForUpdate('books', booksCollection, { rating: 'high' }),
      /expected finite number/,
    );
  });

  it('validates enum on patch fields', () => {
    assert.throws(
      () => validateRecordForUpdate('books', booksCollection, { status: 'shelved' }),
      /not in enum/,
    );
  });

  it('rejects non-object patches', () => {
    assert.throws(
      () => validateRecordForUpdate('books', booksCollection, null),
      /non-array object/,
    );
  });
});
