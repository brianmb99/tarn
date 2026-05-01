// Session persistence — at-rest encryption + IndexedDB-backed wrapping key
// (Section 7, issue #19).
//
// Split into two layers so the pure-crypto half is Node-testable without an
// IndexedDB shim:
//   - encryptSessionBlob / decryptSessionBlob: WebCrypto-only, no I/O.
//   - getOrCreateWrappingKey / clearWrappingKey: IndexedDB-only, browser-only.
//
// On-disk envelope (after base64url encoding by the caller in tarn.js):
//   IV (12 bytes) || AES-256-GCM ciphertext+tag

const DB_NAME = 'tarn-session';
const STORE_NAME = 'keys';
const KEY_RECORD_ID = 'wrapping-key-v1';
const IV_LEN = 12;

/**
 * Encrypt a plaintext byte buffer under an AES-256-GCM key. Generates a fresh
 * 12-byte IV. Returns IV || ciphertext+tag concatenated.
 *
 * @param plaintextBytes
 * @param key — AES-256-GCM, usages must include 'encrypt'
 */
export async function encryptSessionBlob(
  plaintextBytes: Uint8Array,
  key: CryptoKey,
): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  // Cast at the WebCrypto boundary: TS 5.x narrows BufferSource to require
  // an ArrayBuffer (not SharedArrayBuffer) backing, but Uint8Array's buffer
  // is the lib-level union. Runtime accepts either; the cast just smooths
  // the type layer.
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    plaintextBytes as BufferSource,
  );
  const ctBytes = new Uint8Array(ct);
  const out = new Uint8Array(IV_LEN + ctBytes.length);
  out.set(iv, 0);
  out.set(ctBytes, IV_LEN);
  return out;
}

/**
 * Decrypt a blob in IV || ciphertext+tag form. Throws on auth-tag failure,
 * length-too-short, or any underlying WebCrypto error. The caller in tarn.js
 * wraps this in try/catch so the public `resumeSession()` surface returns
 * `null` for any decrypt failure.
 */
export async function decryptSessionBlob(
  blobBytes: Uint8Array,
  key: CryptoKey,
): Promise<Uint8Array> {
  if (!(blobBytes instanceof Uint8Array) || blobBytes.length <= IV_LEN) {
    throw new Error('session blob too short');
  }
  const iv = blobBytes.subarray(0, IV_LEN);
  const ct = blobBytes.subarray(IV_LEN);
  // TS 5.x narrowed BufferSource to require ArrayBuffer-not-SharedArrayBuffer
  // backing storage; subarray() returns Uint8Array<ArrayBufferLike>. The
  // runtime is fine — WebCrypto accepts either backing — but we need to
  // smooth this at the type layer. Casting via `as BufferSource` is the
  // narrow approach.
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, ct as BufferSource);
  return new Uint8Array(pt);
}

// ============ IndexedDB layer (browser-only) ============

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

function dbGet<T = unknown>(db: IDBDatabase, storeName: string, id: string): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).get(id);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB get failed'));
  });
}

function dbPut(db: IDBDatabase, storeName: string, value: unknown, id: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const req = tx.objectStore(storeName).put(value, id);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error ?? new Error('IndexedDB put failed'));
  });
}

function dbDelete(db: IDBDatabase, storeName: string, id: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const req = tx.objectStore(storeName).delete(id);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error ?? new Error('IndexedDB delete failed'));
  });
}

/**
 * Open `tarn-session.keys`, return the existing wrapping key if present, or
 * generate a fresh AES-256-GCM key with `extractable: false` and store it.
 * The non-extractable flag is the load-bearing piece of the threat model
 * (Section 7) — even an XSS that reads IndexedDB cannot exfiltrate raw bytes
 * for offline replay; it can only invoke the key in-page.
 */
export async function getOrCreateWrappingKey(): Promise<CryptoKey> {
  const db = await openDb();
  try {
    const existing = await dbGet<unknown>(db, STORE_NAME, KEY_RECORD_ID);
    if (existing instanceof CryptoKey) return existing;
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false, // extractable: false — Section 7 threat model
      ['encrypt', 'decrypt'],
    );
    await dbPut(db, STORE_NAME, key, KEY_RECORD_ID);
    return key;
  } finally {
    db.close();
  }
}

/**
 * Delete the wrapping-key record. Renders all previously-emitted session
 * blobs unreadable on this origin.
 */
export async function clearWrappingKey(): Promise<void> {
  const db = await openDb();
  try {
    await dbDelete(db, STORE_NAME, KEY_RECORD_ID);
  } finally {
    db.close();
  }
}
