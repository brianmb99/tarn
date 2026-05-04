import { defineSchema } from 'tarn-client';

/**
 * Two collections:
 *   - notes    — full record with optional fields and an enum field
 *   - settings — generic key/value store (json type accepts anything)
 */
export const schema = defineSchema({
  appId: 'bookish',
  version: 1,
  collections: {
    notes: {
      primaryKey: 'noteId',
      fields: {
        noteId:   'string',
        title:    'string',
        body:     'string?',
        priority: { type: 'integer', required: false },
        status:   { type: 'string', enum: ['draft', 'active', 'archived'] },
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
