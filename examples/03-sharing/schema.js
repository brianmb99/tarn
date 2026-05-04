import { defineSchema } from 'tarn-client';

export const schema = defineSchema({
  appId: 'bookish',
  version: 1,
  collections: {
    notes: {
      primaryKey: 'noteId',
      fields: {
        noteId: 'string',
        title:  'string',
        body:   'string?',
      },
      shareable: true,
    },
  },
});
