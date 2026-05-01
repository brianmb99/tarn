/**
 * Public surface of the storage module.
 *
 * Apps:
 *   import { TarnStorage } from '@tarn/sdk';
 *   const tarn = await TarnClient.create({
 *     ...,
 *     storage: TarnStorage.localStorage(),
 *   });
 *
 * IndexedDB-backed adapter (deferred): apps with > a few KB of session
 * material or worker-context constraints will want it. localStorage is
 * the right default for typical browser apps; memory + custom cover the
 * other common cases.
 */

import { localStorageAdapter } from './local-storage.js';
import { memoryStorage } from './memory.js';
import { customStorage } from './custom.js';

export type { TarnStorageAdapter } from './adapter.js';

export const TarnStorage = {
  localStorage: localStorageAdapter,
  memory: memoryStorage,
  custom: customStorage,
} as const;
