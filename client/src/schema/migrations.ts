/**
 * Schema migration shape handling (Tarn #55).
 *
 * Schema-level `migrations` come in two shapes (see `types.ts` →
 * `SchemaMigrations`):
 *
 *   - **flat / legacy**: `{ [version]: Migration }` — applies to EVERY
 *     collection (the original, unscoped behavior).
 *   - **collection-scoped**: `{ [collectionName]: { [version]: Migration } }`
 *     — each migrator runs only against its own collection's records.
 *
 * This module owns the structural disambiguation between the two and the
 * resolution of "what flat per-version map does collection X actually get?".
 * Both `defineSchema()` validation and the TarnClient collection builder route
 * through here so the rules can't drift.
 */

import type { CollectionMigrations, Migration, SchemaMigrations } from './types.js';

/**
 * Decide whether a `migrations` object is the flat (legacy, collection-agnostic)
 * shape or the collection-scoped shape, purely from its top-level keys:
 *
 *   - every top-level key parses as a positive integer  → flat
 *   - otherwise (any non-numeric / collection-name key) → scoped
 *
 * An empty object is treated as flat (it carries no migrators either way, so
 * the distinction is moot — and "flat empty" keeps the legacy path inert).
 */
export function isScopedMigrations(migrations: SchemaMigrations): boolean {
  const keys = Object.keys(migrations);
  if (keys.length === 0) return false;
  // Scoped the moment any top-level key is not a positive-integer string.
  for (const k of keys) {
    if (!isPositiveIntKey(k)) return true;
  }
  return false;
}

/**
 * Resolve the per-version migrator map that a single named collection should
 * receive, given the schema-level migrations (either shape) — or `undefined`
 * if none apply.
 *
 *   - flat shape  → the whole map applies to every collection (legacy).
 *   - scoped shape → only `migrations[collectionName]` applies; collections
 *     with no entry get `undefined` (so a v1→v2 migrator declared for `books`
 *     never runs against `notes` records — the core of Tarn #55).
 */
export function resolveCollectionMigrations(
  migrations: SchemaMigrations | undefined,
  collectionName: string,
): CollectionMigrations | undefined {
  if (migrations === undefined) return undefined;
  if (isScopedMigrations(migrations)) {
    const scoped = migrations as Record<string, CollectionMigrations>;
    return scoped[collectionName];
  }
  // Flat / legacy: the same map applies to every collection.
  return migrations as CollectionMigrations;
}

/** True when a string key is a base-10 positive integer (`'1'`, `'2'`, …). */
export function isPositiveIntKey(key: string): boolean {
  const n = Number(key);
  return Number.isInteger(n) && n >= 1 && String(n) === key;
}

// Re-exported for callers that want the migrator type without reaching into types.ts.
export type { Migration };
