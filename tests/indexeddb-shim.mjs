// Minimal in-memory IndexedDB shim for the Section 7 session-persistence path.
// Node has no IndexedDB; the production runtime is the browser. We polyfill
// just the surface client/src/session-persistence.js touches: open +
// objectStore + readonly/readwrite get/put/delete on a single store. This is
// a test-time shim, not a runtime dep — the production code path is browser.
//
// Loaded as a side-effect import (no exports). Idempotent: if a real or prior
// IndexedDB is already on globalThis, leaves it alone.

if (typeof globalThis.indexedDB === 'undefined') {
  const stores = new Map(); // dbName -> Map<storeName, Map<id, value>>
  function makeReq(resultFn) {
    const req = { onsuccess: null, onerror: null, result: undefined, error: null };
    queueMicrotask(() => {
      try { req.result = resultFn(); req.onsuccess?.({ target: req }); }
      catch (err) { req.error = err; req.onerror?.({ target: req }); }
    });
    return req;
  }
  globalThis.indexedDB = {
    open(dbName /*, version*/) {
      const req = { onupgradeneeded: null, onsuccess: null, onerror: null, result: null };
      const isFirst = !stores.has(dbName);
      queueMicrotask(() => {
        if (!stores.has(dbName)) stores.set(dbName, new Map());
        const dbStores = stores.get(dbName);
        const db = {
          objectStoreNames: { contains: (name) => dbStores.has(name) },
          createObjectStore(name) { if (!dbStores.has(name)) dbStores.set(name, new Map()); return {}; },
          transaction(name /*, mode*/) {
            return {
              objectStore: () => {
                const store = dbStores.get(name);
                return {
                  get: (id) => makeReq(() => store.get(id)),
                  put: (value, id) => makeReq(() => { store.set(id, value); return undefined; }),
                  delete: (id) => makeReq(() => { store.delete(id); return undefined; }),
                };
              },
            };
          },
          close() {},
        };
        req.result = db;
        // why: real IndexedDB fires onupgradeneeded only on version bumps, so
        // we mirror that — first open per dbName gets the upgrade callback.
        if (isFirst && req.onupgradeneeded) req.onupgradeneeded({ target: req });
        req.onsuccess?.({ target: req });
      });
      return req;
    },
  };
}
