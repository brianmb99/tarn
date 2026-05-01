/**
 * In-memory storage adapter. Always discards the session on process restart;
 * useful for SSR contexts, tests, and short-lived workers where persistence
 * is unwanted.
 */

import type { TarnStorageAdapter } from './adapter.js';

export function memoryStorage(): TarnStorageAdapter {
  let stored: string | null = null;
  return {
    async read() {
      return stored;
    },
    async write(blob: string) {
      stored = blob;
    },
    async clear() {
      stored = null;
    },
  };
}
