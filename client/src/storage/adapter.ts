/**
 * Session storage adapter interface.
 *
 * The SDK ships several built-in adapters (`TarnStorage.localStorage()`,
 * `.indexedDB()`, `.memory()`, `.custom()`) but the host app picks. Different
 * runtimes have legitimately different needs — browser apps want
 * localStorage, mobile webviews want secure storage, server-side rendered
 * apps want an in-memory adapter — and the SDK refusing to opinionate on
 * this is the right call.
 *
 * The persisted blob is opaque to the adapter — it's an encrypted
 * serialization of the user's session, produced by `serializeSession()`
 * and consumed by `resumeSession()` on the underlying client. Adapters
 * just store and retrieve bytes (string-encoded for transport).
 */
export interface TarnStorageAdapter {
  /** Read the persisted session blob, or null if none. */
  read(): Promise<string | null>;

  /**
   * Write (or overwrite) the persisted session blob. Storage failures should
   * propagate to callers — the SDK assumes the write succeeded if no throw.
   */
  write(blob: string): Promise<void>;

  /** Delete any persisted session blob. Idempotent: no error if nothing is there. */
  clear(): Promise<void>;
}
