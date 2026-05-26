// Ciphertext blob cache — IndexedDB-backed, scoped by (appId, dlk).
//
// Arweave txids are content hashes, so blobs are immutable forever. Once the
// SDK has fetched the encrypted bytes for a given txid, it never needs to
// fetch them again. Before this cache existed, every list() call refetched
// all N blobs every time — turning a 200-record library into a 201-hit
// burst against the 300/hr IP rate-limit bucket. With the cache, warm reads
// resolve from IndexedDB and only genuinely-new entries trigger a network
// fetch.
//
// We store CIPHERTEXT, not plaintext. Decryption happens on every read
// (AES-GCM is hardware-accelerated, sub-millisecond per blob — the cost
// is irrelevant at typical record counts). The point is to avoid the
// *network*, not the crypto. Storing plaintext in IndexedDB would change
// the at-rest threat model: an attacker who exfiltrated IndexedDB would
// get plaintext directly, without needing the password to run the DEK
// chain. Ciphertext caching preserves the property that the password is
// the only thing that unlocks user data.
//
// Mirrors session-persistence.ts conventions: gracefully no-op when
// IndexedDB is absent (Node tests without the shim, restricted runtimes),
// single objectStore, key-by-string.
//
// Not yet implemented (deferred until measurement says it matters):
//   - Size-bounded LRU eviction. Cache grows monotonically until the
//     browser's storage quota kicks in. For Bookish-scale libraries
//     (hundreds of records) this is months out.
//   - Prune-on-tombstone. Deleted records' ciphertext stays cached
//     (harmless — undecryptable without an entry pointing at it, just
//     wasted bytes).
// When either bites, add an LRU lookup table alongside the store.

const DB_NAME = 'tarn-blob-cache';
const STORE_NAME = 'blobs';

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

function dbGet(db: IDBDatabase, key: string): Promise<Uint8Array | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(key);
    req.onsuccess = () => resolve(req.result as Uint8Array | undefined);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB get failed'));
  });
}

function dbPut(db: IDBDatabase, key: string, value: Uint8Array): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const req = tx.objectStore(STORE_NAME).put(value, key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error ?? new Error('IndexedDB put failed'));
  });
}

// Compose the cache key. Scoping by (appId, dlk) gives us multi-app and
// multi-account isolation on the same origin. After a credential change the
// dlk rotates, so blobs cached under the prior dlk become orphans — fine,
// they're ciphertext and undecryptable without the matching DEK chain.
function cacheKey(appId: string, dlk: string, txid: string): string {
  return `${appId}:${dlk}:${txid}`;
}

/**
 * Look up cached ciphertext for a txid under this (appId, dlk) scope.
 * Returns null on miss OR on any IndexedDB failure — the caller falls back
 * to the network, so a broken cache must not break reads.
 */
export async function getCachedBlob(
  appId: string,
  dlk: string,
  txid: string,
): Promise<Uint8Array | null> {
  if (typeof indexedDB === 'undefined') return null;
  try {
    const db = await openDb();
    try {
      const value = await dbGet(db, cacheKey(appId, dlk, txid));
      return value instanceof Uint8Array ? value : null;
    } finally {
      db.close();
    }
  } catch {
    return null;
  }
}

/**
 * Store ciphertext for a txid under this (appId, dlk) scope. Failures are
 * swallowed — a quota error or storage-disabled environment shouldn't
 * surface to callers, since the network read already produced the bytes
 * the caller needs.
 */
export async function setCachedBlob(
  appId: string,
  dlk: string,
  txid: string,
  bytes: Uint8Array,
): Promise<void> {
  if (typeof indexedDB === 'undefined') return;
  try {
    const db = await openDb();
    try {
      await dbPut(db, cacheKey(appId, dlk, txid), bytes);
    } finally {
      db.close();
    }
  } catch {
    // Swallow — see header doc.
  }
}
