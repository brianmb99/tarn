import { defineSchema } from 'tarn-client';

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
      },
      shareable: true,
    },
  },
});
