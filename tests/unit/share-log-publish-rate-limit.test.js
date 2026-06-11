// Per-account share-log publish rate limit (tarn#66).
//
// Every accepted publish is an Arweave upload spending the app wallet, so
// handleShareLogPublish gets the same D1 atomic-counter treatment as data
// writes (write.js) and inbox publishes (share-inbox.js). These tests drive
// the REAL handler against a D1 shim that honours the
// `INSERT INTO write_rate_limits ... ON CONFLICT ... RETURNING count` SQL and
// assert:
//   (a) a publish over the hourly budget is rejected 429 (Retry-After: 3600);
//   (b) a 409 tag-already-published replay does NOT consume budget — the
//       counter sits AFTER the uniqueness pre-check on purpose, because
//       reconcile loops legitimately re-publish existing tags (SDK backs off
//       on the 409) and those replays spend no wallet money.
//
// Run: node --import tsx --test tests/unit/share-log-publish-rate-limit.test.js
//   or via the umbrella: npm run test:unit

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { handleShareLogPublish } from '../../api/src/routes/share-log.js';
import { signJWT, _resetHMACKey } from '../../api/src/auth.js';

const JWT_SECRET = btoa('share-log-rate-limit-test-secret-0123456789');
const APP_SIGNING_KEY = '22'.repeat(32);
const APP = 'bookish';
const DLK = 'd'.repeat(64);
const TYPE = 'share-log-v1';
const MAX_PER_HOUR = 2000; // mirrors MAX_LOG_PUBLISHES_PER_HOUR in the route

function tagFor(n) {
  // 43-char base64url tag, varied per call.
  return (String(n).padStart(4, '0') + 'B'.repeat(43)).slice(0, 43);
}

function ciphertextB64(fillByte) {
  const bytes = new Uint8Array(64).fill(fillByte);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// D1 shim: share_log unique-index semantics + a REAL counter for the
// write_rate_limits upsert the handler issues.
function makeD1({ seedCounts = {} } = {}) {
  const rows = new Map();          // share_log: "app|tag|type" -> { txid }
  const counters = new Map(Object.entries(seedCounts)); // write_rate_limits: key -> count
  const db = {
    _rows: rows,
    _counters: counters,
    prepare(sql) {
      let args = [];
      return {
        bind(...a) { args = a; return this; },
        async first() {
          if (/SELECT txid FROM share_log/.test(sql)) {
            const key = `${args[0]}|${args[1]}|${args[2]}`;
            return rows.has(key) ? { txid: rows.get(key).txid } : null;
          }
          if (/INSERT INTO write_rate_limits/.test(sql)) {
            const key = args[0];
            const next = (counters.get(key) ?? 0) + 1;
            counters.set(key, next);
            return { count: next };
          }
          return null;
        },
        async run() {
          if (/INSERT INTO share_log/.test(sql)) {
            const [txid, appId, logTag, blobType] = args;
            const key = `${appId}|${logTag}|${blobType}`;
            if (rows.has(key)) throw new Error('UNIQUE constraint failed');
            rows.set(key, { txid });
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

const ctx = { waitUntil(p) { Promise.resolve(p).catch(() => {}); } };
const cors = {};

function makeEnv(db) {
  return { DB: db, JWT_SECRET, APP_SIGNING_KEY, TARN_SKIP_TURBO: '1' };
}

function rateKeyNow() {
  const hour = new Date().toISOString().slice(0, 13);
  return `share-log-publish:${DLK}:${hour}`;
}

async function userJwt() {
  return await signJWT({ sub: DLK, role: 'user', app: APP }, JWT_SECRET);
}

describe('tarn#66 — share-log publish per-account rate limit', () => {
  beforeEach(() => {
    _resetHMACKey();
    globalThis.__TARN_SKIP_TURBO__ = true;
  });

  it('allows the publish that reaches the budget, 429s the one past it', async () => {
    // Seed the counter one below the cap: the next publish lands exactly AT
    // the cap (allowed), the one after exceeds it (429).
    const db = makeD1({ seedCounts: { [rateKeyNow()]: MAX_PER_HOUR - 1 } });
    const env = makeEnv(db);
    const jwt = await userJwt();

    const atCap = await handleShareLogPublish(
      makeRequest(jwt, { tag: tagFor(1), type: TYPE, ciphertext_base64: ciphertextB64(1) }), env, ctx, cors,
    );
    assert.equal(atCap.status, 200, 'publish #MAX is still inside the budget');

    const overCap = await handleShareLogPublish(
      makeRequest(jwt, { tag: tagFor(2), type: TYPE, ciphertext_base64: ciphertextB64(2) }), env, ctx, cors,
    );
    assert.equal(overCap.status, 429);
    assert.equal(overCap.headers.get('Retry-After'), '3600');
    assert.equal(db._rows.size, 1, 'the rejected publish wrote nothing');
  });

  it('a 409 tag-already-published replay does NOT consume budget', async () => {
    const db = makeD1();
    const env = makeEnv(db);
    const jwt = await userJwt();

    const first = await handleShareLogPublish(
      makeRequest(jwt, { tag: tagFor(3), type: TYPE, ciphertext_base64: ciphertextB64(3) }), env, ctx, cors,
    );
    assert.equal(first.status, 200);
    const afterFirst = db._counters.get(rateKeyNow());
    assert.equal(afterFirst, 1, 'accepted publish consumed one unit');

    const replay = await handleShareLogPublish(
      makeRequest(jwt, { tag: tagFor(3), type: TYPE, ciphertext_base64: ciphertextB64(4) }), env, ctx, cors,
    );
    assert.equal(replay.status, 409);
    assert.equal(db._counters.get(rateKeyNow()), afterFirst,
      '409 replays spend no wallet money and must not consume budget');
  });
});
