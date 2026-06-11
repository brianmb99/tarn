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

function dbGetAllKeys(db: IDBDatabase): Promise<IDBValidKey[]> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).getAllKeys();
    req.onsuccess = () => resolve(req.result ?? []);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB getAllKeys failed'));
  });
}

// Issue all deletes synchronously on ONE readwrite transaction (awaiting
// between requests risks auto-commit closing the transaction in real
// IndexedDB), resolve when the last succeeds.
function dbDeleteKeys(db: IDBDatabase, keys: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    if (keys.length === 0) {
      resolve();
      return;
    }
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    let remaining = keys.length;
    for (const key of keys) {
      const req = store.delete(key);
      req.onsuccess = () => {
        remaining -= 1;
        if (remaining === 0) resolve();
      };
      req.onerror = () => reject(req.error ?? new Error('IndexedDB delete failed'));
    }
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

/**
 * Delete every cursor stored for this (appId, dlk) scope — all types
 * (issue #71). Invoked from clearSession() so logout forgets the account's
 * delta position: a cursor that outlives the app's own cache makes the next
 * delta sync silently skip history ("missing data" after re-login).
 *
 * Per-key deletion (prefix filter over getAllKeys) rather than
 * deleteDatabase: whole-DB deletion blocks while another tab holds a
 * connection, and would needlessly drop other accounts' cursors, which are
 * harmless and save those accounts a full resync.
 *
 * Entirely best-effort: any failure is swallowed — a wipe failure must
 * never break logout.
 */
export async function clearCursorsForScope(appId: string, dlk: string): Promise<void> {
  if (typeof indexedDB === 'undefined') return;
  try {
    const db = await openDb();
    try {
      const prefix = `${appId}:${dlk}:`;
      const keys = await dbGetAllKeys(db);
      const mine = keys.filter(
        (k): k is string => typeof k === 'string' && k.startsWith(prefix),
      );
      await dbDeleteKeys(db, mine);
    } finally {
      db.close();
    }
  } catch {
    // Swallow — see doc above.
  }
}
