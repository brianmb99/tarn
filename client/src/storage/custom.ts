/**
 * Custom adapter — accepts read/write/clear functions from the app.
 *
 * Lets apps wire any backend (electron's keytar, mobile secure storage,
 * an authenticated server endpoint, etc.) without requiring the SDK to
 * ship adapters for everything. The contract is identical to the built-ins;
 * the SDK doesn't care where the bytes live.
 */

import type { TarnStorageAdapter } from './adapter.js';

export function customStorage(impl: TarnStorageAdapter): TarnStorageAdapter {
  if (typeof impl?.read !== 'function') throw new Error('TarnStorage.custom(): read must be a function');
  if (typeof impl?.write !== 'function') throw new Error('TarnStorage.custom(): write must be a function');
  if (typeof impl?.clear !== 'function') throw new Error('TarnStorage.custom(): clear must be a function');
  return impl;
}
