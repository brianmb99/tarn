// Delta-sync cursor persistence — IndexedDB-backed, scoped by (appId, dlk, type).
//
// The delta endpoint (GET /api/v1/entries?...&since=<cursor>) returns a
// new cursor in every response. The SDK persists that cursor across page
// reloads / app restarts so a subsequent sync picks up exactly where the
// last one stopped — no full-history replay, no duplicate processing.
//
// The cursor is server-issued and opaque to the SDK; we store the string
// verbatim. Tiny payload (~80 bytes) per scope. Same IDB-with-graceful-
// fallback pattern as blob-cache.ts and session-persistence.ts.

const DB_NAME = 'tarn-sync-cursors';
const STORE_NAME = 'cursors';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(new Error('IndexedDB not available'));
      return;
    }
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB open failed'));
  });
}

function dbGet(db: IDBDatabase, key: string): Promise<string | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(key);
    req.onsuccess = () => resolve(req.result as string | undefined);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB get failed'));
  });
}

function dbPut(db: IDBDatabase, key: string, value: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const req = tx.objectStore(STORE_NAME).put(value, key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error ?? new Error('IndexedDB put failed'));
  });
}

function cursorKey(appId: string, dlk: string, type: string): string {
  return `${appId}:${dlk}:${type}`;
}

/**
 * Read the last-stored cursor for this scope. Returns null on miss or any
 * IndexedDB failure — a missing cursor means "start from the beginning",
 * which is correct first-sync behavior.
 */
export async function getCursor(
  appId: string,
  dlk: string,
  type: string,
): Promise<string | null> {
  if (typeof indexedDB === 'undefined') return null;
  try {
    const db = await openDb();
    try {
      const value = await dbGet(db, cursorKey(appId, dlk, type));
      return typeof value === 'string' ? value : null;
    } finally {
      db.close();
    }
  } catch {
    return null;
  }
}

/**
 * Persist the cursor for this scope. Failures swallowed — a broken cursor
 * store means the next sync starts from scratch, which is correct (just
 * slower). The network round trip already produced the events the caller
 * needs.
 */
export async function setCursor(
  appId: string,
  dlk: string,
  type: string,
  cursor: string,
): Promise<void> {
  if (typeof indexedDB === 'undefined') return;
  try {
    const db = await openDb();
    try {
      await dbPut(db, cursorKey(appId, dlk, type), cursor);
    } finally {
      db.close();
    }
  } catch {
    // Swallow — see header doc.
  }
}
