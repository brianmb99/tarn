/**
 * Browser localStorage adapter. Synchronous under the hood, async at the
 * adapter boundary so it composes cleanly with the other adapters.
 *
 * Throws synchronously at construction time if `localStorage` is not
 * available — which is what we want: the app picked this adapter and
 * we can't silently degrade.
 */

import type { TarnStorageAdapter } from './adapter.js';

const DEFAULT_KEY = 'tarn:session:v1';

export function localStorageAdapter(opts: { key?: string } = {}): TarnStorageAdapter {
  if (typeof globalThis.localStorage === 'undefined') {
    throw new Error(
      'TarnStorage.localStorage() requires a browser localStorage; use .memory() or .custom() in non-browser environments',
    );
  }
  const key = opts.key ?? DEFAULT_KEY;
  return {
    async read() {
      return globalThis.localStorage.getItem(key);
    },
    async write(blob: string) {
      globalThis.localStorage.setItem(key, blob);
    },
    async clear() {
      globalThis.localStorage.removeItem(key);
    },
  };
}
