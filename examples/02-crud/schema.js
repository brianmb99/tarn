import { defineSchema } from 'tarn-client';

/**
 * Two collections:
 *   - books    — full record with optional fields and an enum field
 *   - settings — generic key/value store (json type accepts anything)
 */
export const schema = defineSchema({
  appId: 'bookish',
  version: 1,
  collections: {
    books: {
      primaryKey: 'bookId',
      fields: {
        bookId: 'string',
        title:  'string',
        author: 'string?',
        rating: { type: 'integer', required: false },
        status: { type: 'string', enum: ['unread', 'reading', 'done'] },
      },
      shareable: true,
    },
    settings: {
      primaryKey: 'key',
      fields: {
        key:   'string',
        value: 'json',
      },
    },
  },
});
