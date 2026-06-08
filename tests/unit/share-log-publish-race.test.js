// Driven multi-device share-log write race at the SERVER level (tarn#62b).
//
// Context: the existing tests/test-share-log.mjs §8 only SIMULATES a 409, and
// the client-side conflict-storm behaviour (backoff, seq-advance, no reuse) is
// covered by tests/unit/client-share-log-conflict.test.js — but that test
// always-409s the publish; the server never actually inserts, so the REAL
// server-side unique-index conflict semantics in routes/share-log.js
// (handleShareLogPublish) are not driven.
//
// handleShareLogPublish relies on the D1 UNIQUE index on
// (app_id, log_tag, blob_type) (sharing §9.1): it pre-checks for an existing
// row, then INSERTs and lets the index reject any concurrent collision
// atomically — returning 409 with the winner's txid so the loser can retry at
// a fresh seq.
//
// This test DRIVES two concurrent publishers through the REAL handler against
// an in-memory share_log D1 shim that enforces the unique index (the INSERT
// check-and-set is atomic within a microtask, mirroring SQLite's constraint
// enforcement at write time). It asserts:
//   (a) exactly ONE publisher wins (200) and the other gets 409 — even when
//       BOTH pass the non-atomic pre-check first (the pre-check race);
//   (b) the 409 carries the winner's existing_txid so the loser can retry;
//   (c) the single persisted row is the winner's (no double-insert, no seq reuse
//       at the same tag).
//
// Run: node --import tsx --test tests/unit/share-log-publish-race.test.js
//   or via the umbrella: npm run test:unit

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { handleShareLogPublish } from '../../api/src/routes/share-log.js';
import { signJWT, _resetHMACKey } from '../../api/src/auth.js';

const JWT_SECRET = btoa('share-log-race-test-secret-key-0123456789abc');
// A deterministic 32-byte secp256k1 private key (hex). createSignedDataItem in
// ans104.js signs with this; any valid hex key works — the txid is derived from
// the real signature so each distinct ciphertext yields a distinct txid.
const APP_SIGNING_KEY = '11'.repeat(32);
const APP = 'bookish';
const DLK = 'e'.repeat(64);
const TYPE = 'share-log-v1';
// 43-char base64url tag (HMAC-SHA-256 output shape the handler validates).
const TAG = 'A'.repeat(43);

// Build a valid AES-GCM-shaped ciphertext (>= 28 bytes) as base64.
function ciphertextB64(fillByte) {
  const bytes = new Uint8Array(64).fill(fillByte);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// In-memory share_log D1 shim that enforces the UNIQUE(app_id, log_tag,
// blob_type) index. The INSERT's check-and-throw is synchronous (no await
// before the constraint test), so two interleaved handler calls cannot both
// insert — exactly the atomicity the real unique index provides.
function makeD1() {
  const rows = new Map(); // key "app|tag|type" -> { txid }
  let insertAttempts = 0;
  const db = {
    _rows: rows,
    _stats: () => ({ insertAttempts, rowCount: rows.size }),
    prepare(sql) {
      let args = [];
      return {
        bind(...a) { args = a; return this; },
        async first() {
          if (/SELECT txid FROM share_log WHERE app_id = \?1 AND log_tag = \?2 AND blob_type = \?3/.test(sql)) {
            const key = `${args[0]}|${args[1]}|${args[2]}`;
            return rows.has(key) ? { txid: rows.get(key).txid } : null;
          }
          return null;
        },
        async run() {
          if (/INSERT INTO share_log/.test(sql)) {
            insertAttempts += 1;
            // args: txid, app_id, log_tag, blob_type, ciphertext, dlk, published_at
            const [txid, appId, logTag, blobType] = args;
            const key = `${appId}|${logTag}|${blobType}`;
            // Atomic constraint check (synchronous — no await before this).
            if (rows.has(key)) {
              const err = new Error('D1_ERROR: UNIQUE constraint failed: share_log.app_id, share_log.log_tag, share_log.blob_type');
              throw err;
            }
            rows.set(key, { txid });
            return { success: true };
          }
          return { success: true };
        },
      };
    },
  };
  return db;
}

function makeRequest(jwt, body) {
  return {
    url: 'https://api.tarn.dev/api/v1/share/log/publish',
    headers: {
      get(name) {
        if (name === 'Authorization') return `Bearer ${jwt}`;
        if (name === 'CF-Connecting-IP') return '127.0.0.1';
        return null;
      },
    },
    async json() { return body; },
  };
}

// Swallow waitUntil work (background Turbo mirror) — best-effort, must not
// affect main-path assertions. TARN_SKIP_TURBO short-circuits the upload.
const ctx = { waitUntil(p) { Promise.resolve(p).catch(() => {}); } };
const cors = {};

function makeEnv(db) {
  return { DB: db, JWT_SECRET, APP_SIGNING_KEY, TARN_SKIP_TURBO: '1' };
}

async function userJwt() {
  // role=user + app claim (handler requires auth.app); no sid → skips the
  // session-active check.
  return await signJWT({ sub: DLK, role: 'user', app: APP }, JWT_SECRET);
}

describe('tarn#62b — server-side share-log multi-device write race', () => {
  beforeEach(() => {
    _resetHMACKey();
    globalThis.__TARN_SKIP_TURBO__ = true; // belt-and-suspenders for uploadSignedDataItem
  });

  it('sanity: a single publish succeeds (real handler, real signing, 200 + txid)', async () => {
    const db = makeD1();
    const env = makeEnv(db);
    const jwt = await userJwt();
    const res = await handleShareLogPublish(
      makeRequest(jwt, { tag: TAG, type: TYPE, ciphertext_base64: ciphertextB64(1) }), env, ctx, cors,
    );
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.txid, 'winner returns a txid');
    assert.equal(db._stats().rowCount, 1);
  });

  it('two concurrent publishers at the same tag: exactly one 200, one 409 with the winner txid', async () => {
    const db = makeD1();
    const env = makeEnv(db);
    const jwtA = await userJwt();
    const jwtB = await userJwt();

    // Distinct ciphertexts → distinct signatures → distinct txids, so we can
    // tell which publisher won and confirm the 409 names the actual winner.
    const [resA, resB] = await Promise.all([
      handleShareLogPublish(makeRequest(jwtA, { tag: TAG, type: TYPE, ciphertext_base64: ciphertextB64(0xA1) }), env, ctx, cors),
      handleShareLogPublish(makeRequest(jwtB, { tag: TAG, type: TYPE, ciphertext_base64: ciphertextB64(0xB2) }), env, ctx, cors),
    ]);

    const statuses = [resA.status, resB.status].sort();
    assert.deepEqual(statuses, [200, 409], `expected exactly one 200 and one 409, got ${statuses}`);

    const winnerRes = resA.status === 200 ? resA : resB;
    const loserRes = resA.status === 200 ? resB : resA;
    const winnerBody = await winnerRes.json();
    const loserBody = await loserRes.json();

    // Exactly one row persisted; it is the winner's.
    assert.equal(db._stats().rowCount, 1, 'only one row survives the unique index');
    const persisted = [...db._rows.values()][0].txid;
    assert.equal(persisted, winnerBody.txid, 'persisted row is the winner');

    // The 409 hands the loser the winner's txid so it can short-circuit / retry.
    assert.equal(loserBody.error, 'tag already published');
    assert.equal(loserBody.existing_txid, winnerBody.txid,
      'loser 409 must carry the winner txid so retry/own-publish detection works');

    // Both publishers attempted the INSERT (the pre-check did NOT serialize
    // them); the unique index is what actually resolved the race.
    assert.ok(db._stats().insertAttempts >= 2,
      `both publishers should reach INSERT (pre-check is non-atomic); attempts=${db._stats().insertAttempts}`);
  });

  it('a second publish at an ALREADY-TAKEN tag 409s via the pre-check (no wasted INSERT)', async () => {
    const db = makeD1();
    const env = makeEnv(db);
    const jwt = await userJwt();

    const first = await handleShareLogPublish(
      makeRequest(jwt, { tag: TAG, type: TYPE, ciphertext_base64: ciphertextB64(7) }), env, ctx, cors,
    );
    assert.equal(first.status, 200);
    const firstBody = await first.json();
    const attemptsAfterFirst = db._stats().insertAttempts;

    // Sequential second publish at the same tag: the pre-check sees the row and
    // 409s WITHOUT attempting an INSERT.
    const second = await handleShareLogPublish(
      makeRequest(jwt, { tag: TAG, type: TYPE, ciphertext_base64: ciphertextB64(8) }), env, ctx, cors,
    );
    assert.equal(second.status, 409);
    const secondBody = await second.json();
    assert.equal(secondBody.existing_txid, firstBody.txid);
    assert.equal(db._stats().insertAttempts, attemptsAfterFirst,
      'pre-check short-circuits — no second INSERT attempt');
    assert.equal(db._stats().rowCount, 1);
  });
});
