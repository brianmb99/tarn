// Unit tests for handleRegister's share_lookup_key validation (issue #30).
//
// Issue #30 closed a per-app email-uniqueness gap that allowed two distinct
// accounts to coexist for the same (email, app) when one of them was a
// pre-#13 row with NULL share_lookup_key. The fix is to require both
// share_pub and share_lookup_key at the API boundary on every new
// registration so that every row in `accounts` going forward has a
// non-NULL share_lookup_key, which the partial unique index in migration
// 0009 then enforces.
//
// These tests pin the API-boundary behavior with a focused mock of D1 +
// RATE_KV. They are intentionally narrower than the integration tests in
// tests/test-auth.mjs / tests/test-share.mjs — those exercise the full
// challenge/verify roundtrip against wrangler dev. Here we only care
// about the validation gate, so we don't need a real Worker runtime.
//
// Run: node --test tests/unit/auth-register-share-lookup-key.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { handleRegister } from '../../api/src/routes/auth.js';

// ============ Fixture builders ============

function randomHex64() {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomSharePub() {
  // 43-char base64url encoding of 32 raw bytes (no padding).
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// A real P-256 SPKI public key (base64). Generated once at module load so
// the API's importPublicKey() check passes — but we don't keep the private
// key because none of these tests reach the signing layer.
let validPubBase64;
async function getValidPubBase64() {
  if (validPubBase64) return validPubBase64;
  const { publicKey } = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const spki = await globalThis.crypto.subtle.exportKey('spki', publicKey);
  validPubBase64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  return validPubBase64;
}

// Build a minimal Cloudflare Request object compatible with handleRegister's
// expectations: headers.get('CF-Connecting-IP') for rate limiting, json()
// to parse the body.
function makeRequest(body) {
  return {
    headers: {
      get(name) {
        if (name === 'CF-Connecting-IP') return '127.0.0.1';
        return null;
      },
    },
    async json() { return body; },
  };
}

// D1 mock that knows just enough SQL to satisfy handleRegister:
//   SELECT 1 FROM apps WHERE app_id = ?1  → returns row when app is registered
//   SELECT * FROM accounts WHERE credential_lookup_key = ?1  → null (no existing account)
//   SELECT 1 FROM accounts WHERE recovery_lookup_key/share_lookup_key/data_lookup_key = ?1  → null
//   INSERT INTO accounts ...  → records the bind values for assertions
//
// `existingShareLookupKeys` lets us simulate a collision for the 409 case.
function makeDB({ existingShareLookupKeys = new Set() } = {}) {
  const inserts = [];
  return {
    inserts,
    prepare(sql) {
      const params = [];
      return {
        bind(...args) {
          params.push(...args);
          return this;
        },
        async first() {
          if (sql.includes('FROM apps WHERE app_id')) {
            return { ok: 1 };
          }
          if (sql.includes('FROM accounts WHERE credential_lookup_key')) {
            return null;
          }
          if (sql.includes('FROM accounts WHERE recovery_lookup_key')) {
            return null;
          }
          if (sql.includes('FROM accounts WHERE share_lookup_key')) {
            const slk = params[0];
            return existingShareLookupKeys.has(slk) ? { ok: 1 } : null;
          }
          if (sql.includes('FROM accounts WHERE data_lookup_key')) {
            return null;
          }
          throw new Error(`mock D1: unsupported SQL for first(): ${sql}`);
        },
        async run() {
          if (sql.startsWith('INSERT INTO accounts')) {
            inserts.push(params);
            return { success: true };
          }
          throw new Error(`mock D1: unsupported SQL for run(): ${sql}`);
        },
      };
    },
  };
}

function makeEnv(overrides = {}) {
  return {
    DB: overrides.DB || makeDB(),
    RATE_KV: null, // fails open per rate-limit.js — sufficient for these tests
    ...overrides,
  };
}

function makeCtx() {
  // handleRegister only uses ctx.waitUntil for the (skipped, since
  // APP_SIGNING_KEY is unset) Arweave republish. Provide a no-op.
  return { waitUntil: () => {} };
}

// Valid base payload missing only the share_* fields the test will vary.
async function basePayload() {
  return {
    credential_lookup_key: randomHex64(),
    public_key: await getValidPubBase64(),
    wrapped_data_key: 'AAAA',
    app: 'unit-test-app',
  };
}

async function readJSON(res) {
  return JSON.parse(await res.text());
}

// ============ Tests ============

describe('handleRegister — share_lookup_key required (issue #30)', () => {
  it('rejects a payload with no share_lookup_key (400)', async () => {
    const env = makeEnv();
    const body = {
      ...(await basePayload()),
      // Deliberately no share_pub / share_lookup_key — the pre-#30
      // "old client" wire shape. Must now 400.
    };
    const res = await handleRegister(makeRequest(body), env, makeCtx(), {});
    assert.equal(res.status, 400, 'missing share_lookup_key must 400');
    const json = await readJSON(res);
    assert.match(json.error, /share_lookup_key is required/);
  });

  it('rejects a payload with explicit null share_lookup_key (400)', async () => {
    const env = makeEnv();
    const body = {
      ...(await basePayload()),
      share_pub: randomSharePub(),
      share_lookup_key: null,
    };
    const res = await handleRegister(makeRequest(body), env, makeCtx(), {});
    assert.equal(res.status, 400, 'null share_lookup_key must 400');
    const json = await readJSON(res);
    assert.match(json.error, /share_lookup_key is required/);
  });

  it('rejects a payload with empty-string share_lookup_key (400)', async () => {
    const env = makeEnv();
    const body = {
      ...(await basePayload()),
      share_pub: randomSharePub(),
      share_lookup_key: '',
    };
    const res = await handleRegister(makeRequest(body), env, makeCtx(), {});
    assert.equal(res.status, 400, 'empty share_lookup_key must 400');
    const json = await readJSON(res);
    assert.match(json.error, /share_lookup_key is required/);
  });

  it('rejects a payload with share_lookup_key but no share_pub (400)', async () => {
    const env = makeEnv();
    const body = {
      ...(await basePayload()),
      share_lookup_key: randomHex64(),
      // no share_pub
    };
    const res = await handleRegister(makeRequest(body), env, makeCtx(), {});
    assert.equal(res.status, 400, 'missing share_pub must 400');
    const json = await readJSON(res);
    assert.match(json.error, /share_pub is required/);
  });

  it('rejects a payload with malformed share_lookup_key shape (400)', async () => {
    const env = makeEnv();
    const body = {
      ...(await basePayload()),
      share_pub: randomSharePub(),
      share_lookup_key: 'not-hex-64', // wrong shape — only 10 chars, not hex64
    };
    const res = await handleRegister(makeRequest(body), env, makeCtx(), {});
    assert.equal(res.status, 400, 'malformed share_lookup_key must 400');
    const json = await readJSON(res);
    assert.match(json.error, /Invalid share_lookup_key/);
  });

  it('accepts a payload with valid share_pub + share_lookup_key (201)', async () => {
    const db = makeDB();
    const env = makeEnv({ DB: db });
    const body = {
      ...(await basePayload()),
      share_pub: randomSharePub(),
      share_lookup_key: randomHex64(),
    };
    const res = await handleRegister(makeRequest(body), env, makeCtx(), {});
    assert.equal(res.status, 201, `valid payload must succeed, got ${res.status} ${await res.text()}`);
    assert.equal(db.inserts.length, 1, 'should have inserted exactly one accounts row');
    // share_lookup_key is the 11th parameter in the INSERT (index 10):
    //   credential_lookup_key, public_key, data_lookup_key, wrapped_data_key,
    //   app, created_at, recovery_lookup_key, recovery_public_key, share_pub,
    //   share_discoverable, share_lookup_key, wrapped_account_key
    const insertedShareLookupKey = db.inserts[0][10];
    assert.equal(insertedShareLookupKey, body.share_lookup_key,
      'inserted share_lookup_key must match payload — guarantees NOT NULL going forward');
    assert.notEqual(insertedShareLookupKey, null,
      'no new row may have NULL share_lookup_key (issue #30 invariant)');
  });

  it('returns 409 when share_lookup_key collides with an existing account', async () => {
    // The pre-existing same-share_lookup_key check is the per-app email-
    // uniqueness gate. Pin it explicitly so a future refactor that removes
    // the up-front SELECT (e.g., relying solely on the partial unique index)
    // still maintains the 409 contract clients depend on.
    const collidingKey = randomHex64();
    const db = makeDB({ existingShareLookupKeys: new Set([collidingKey]) });
    const env = makeEnv({ DB: db });
    const body = {
      ...(await basePayload()),
      share_pub: randomSharePub(),
      share_lookup_key: collidingKey,
    };
    const res = await handleRegister(makeRequest(body), env, makeCtx(), {});
    assert.equal(res.status, 409, `colliding share_lookup_key must 409, got ${res.status}`);
    const json = await readJSON(res);
    assert.match(json.error, /share_lookup_key already in use/);
    assert.equal(db.inserts.length, 0, 'no row should have been inserted on conflict');
  });
});
