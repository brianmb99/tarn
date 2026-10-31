// /auth/verify session continuity, including the opt-in reject.
//
// require_previous_sid === true with a previous_sid whose row is gone
// (revoked, another account, or idle-pruned) is 401 session_not_found:
// no new row, no JWT. The flag without previous_sid is ignored. Omitting
// the flag keeps the old mint-or-reuse behaviour.
//
// Run: node --import tsx --test tests/unit/auth-verify-previous-sid.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { handleVerify } from '../../api/src/routes/auth.js';
import { SESSION_IDLE_SECONDS } from '../../api/src/sessions.js';

const DLK = 'ab'.repeat(32);
const CLK = 'cd'.repeat(32);
const APP = 'bookish';
const JWT_SECRET = Buffer.from('unit-test-jwt-secret-32bytes!!').toString('base64');

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

let keypair;
async function getKeypair() {
  if (keypair) return keypair;
  const kp = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  keypair = { privateKey: kp.privateKey, publicKey: bytesToBase64(spki) };
  return keypair;
}

async function signNonce(nonce) {
  const { privateKey } = await getKeypair();
  const sig = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    hexToBytes(nonce),
  ));
  return bytesToBase64(sig);
}

function decodeJwtPayload(jwt) {
  const body = jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
  const padded = body + '='.repeat((4 - (body.length % 4)) % 4);
  return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
}

// D1 surface handleVerify + createOrReuseSession + consumeNonce touch.
function makeEnv({ sessions }) {
  const rows = new Map(sessions.map((r) => [r.sid, { ...r }]));
  return {
    JWT_SECRET,
    DB: {
      _rows: rows,
      prepare(sql) {
        const params = [];
        return {
          bind(...args) {
            params.push(...args);
            return this;
          },
          async first() {
            if (sql.startsWith('DELETE FROM auth_nonces')) {
              return {
                credential_lookup_key: CLK,
                created_at: Date.now(),
                expires_at: Date.now() + 60_000,
              };
            }
            if (sql.includes('FROM accounts WHERE credential_lookup_key')) {
              const { publicKey } = await getKeypair();
              return {
                data_lookup_key: DLK,
                public_key: publicKey,
                app: APP,
                wrapped_account_key: 'wrap',
              };
            }
            if (sql.startsWith('SELECT sid FROM sessions WHERE sid = ?1 AND data_lookup_key = ?2')) {
              const [sid, dlk] = params;
              const row = rows.get(sid);
              return row && row.data_lookup_key === dlk ? { sid: row.sid } : null;
            }
            throw new Error(`mock D1 first() unsupported SQL: ${sql}`);
          },
          async run() {
            if (sql.startsWith('DELETE FROM sessions')) {
              const [dlk, cutoff] = params;
              for (const [sid, row] of [...rows]) {
                if (row.data_lookup_key === dlk && row.last_seen_at < cutoff) rows.delete(sid);
              }
              return { success: true };
            }
            if (sql.startsWith('UPDATE sessions SET last_seen_at')) {
              const [lastSeen, sid] = params;
              const row = rows.get(sid);
              if (row) row.last_seen_at = lastSeen;
              return { success: true };
            }
            if (sql.startsWith('INSERT INTO sessions')) {
              const [sid, dlk, app, created_at, last_seen_at, device_label, via_recovery] = params;
              rows.set(sid, {
                sid, data_lookup_key: dlk, app, created_at, last_seen_at, device_label, via_recovery,
              });
              return { success: true };
            }
            throw new Error(`mock D1 run() unsupported SQL: ${sql}`);
          },
        };
      },
    },
  };
}

async function verify(body, sessions = []) {
  const env = makeEnv({ sessions });
  const res = await handleVerify({ async json() { return body; } }, env, {});
  const json = await res.json();
  return { status: res.status, json, rows: env.DB._rows };
}

function liveRow(sid, lastSeen = 10) {
  return {
    sid,
    data_lookup_key: DLK,
    app: APP,
    created_at: 10,
    last_seen_at: lastSeen,
    device_label: null,
    via_recovery: 0,
  };
}

describe('POST /auth/verify require_previous_sid', () => {
  it('401s with no row and no jwt when the required previous sid is gone', async () => {
    const nonce = 'ab'.repeat(32);
    const { status, json, rows } = await verify({
      credential_lookup_key: CLK,
      nonce,
      signature: await signNonce(nonce),
      previous_sid: 'sid-revoked',
      require_previous_sid: true,
    });
    assert.equal(status, 401);
    assert.deepEqual(json, { error: 'session_not_found' });
    assert.equal(Object.hasOwn(json, 'jwt'), false);
    assert.equal(rows.size, 0, 'reject path must not insert a session row');
  });

  it('treats a 90-day-idle previous sid as missing after prune', async () => {
    const nonce = 'cd'.repeat(32);
    const now = Math.floor(Date.now() / 1000);
    const { status, json, rows } = await verify({
      credential_lookup_key: CLK,
      nonce,
      signature: await signNonce(nonce),
      previous_sid: 'sid-idle',
      require_previous_sid: true,
    }, [
      liveRow('sid-idle', now - SESSION_IDLE_SECONDS - 1),
    ]);
    assert.equal(status, 401);
    assert.equal(json.error, 'session_not_found');
    assert.equal(Object.hasOwn(json, 'jwt'), false);
    assert.equal(rows.has('sid-idle'), false, 'idle row was pruned');
    assert.equal(rows.size, 0, 'no replacement row');
  });

  it('401s when the previous sid belongs to a different account', async () => {
    const nonce = 'ef'.repeat(32);
    const other = {
      sid: 'sid-other',
      data_lookup_key: 'ff'.repeat(32),
      app: APP,
      created_at: 10,
      last_seen_at: Math.floor(Date.now() / 1000),
      device_label: null,
      via_recovery: 0,
    };
    const { status, json, rows } = await verify({
      credential_lookup_key: CLK,
      nonce,
      signature: await signNonce(nonce),
      previous_sid: 'sid-other',
      require_previous_sid: true,
    }, [other]);
    assert.equal(status, 401);
    assert.equal(json.error, 'session_not_found');
    assert.equal(Object.hasOwn(json, 'jwt'), false);
    assert.equal(rows.size, 1);
    assert.equal(rows.has('sid-other'), true, 'the other account row is untouched');
  });

  it('ignores require_previous_sid when previous_sid is absent and mints', async () => {
    const nonce = '11'.repeat(32);
    const { status, json, rows } = await verify({
      credential_lookup_key: CLK,
      nonce,
      signature: await signNonce(nonce),
      require_previous_sid: true,
    });
    assert.equal(status, 200);
    assert.equal(Object.hasOwn(json, 'previous_sid_status'), false);
    assert.equal(json.expiresIn, 900);
    const claims = decodeJwtPayload(json.jwt);
    assert.equal(typeof claims.sid, 'string');
    assert.equal(rows.has(claims.sid), true);
    assert.equal(rows.size, 1);
  });

  it('ignores the flag when previous_sid is an empty string', async () => {
    const nonce = '22'.repeat(32);
    const { status, json, rows } = await verify({
      credential_lookup_key: CLK,
      nonce,
      signature: await signNonce(nonce),
      previous_sid: '',
      require_previous_sid: true,
    });
    assert.equal(status, 200);
    assert.equal(rows.has(decodeJwtPayload(json.jwt).sid), true);
  });

  it('mints a new sid when previous_sid is gone and the flag is absent', async () => {
    const nonce = '33'.repeat(32);
    const { status, json, rows } = await verify({
      credential_lookup_key: CLK,
      nonce,
      signature: await signNonce(nonce),
      previous_sid: 'sid-revoked',
    });
    assert.equal(status, 200);
    assert.equal(Object.hasOwn(json, 'previous_sid_status'), false);
    const sid = decodeJwtPayload(json.jwt).sid;
    assert.notEqual(sid, 'sid-revoked');
    assert.equal(rows.has(sid), true);
    assert.equal(rows.size, 1);
  });

  it('reuses a live previous sid when the flag is set', async () => {
    const nonce = '44'.repeat(32);
    const seen = Math.floor(Date.now() / 1000) - 120;
    const { status, json, rows } = await verify({
      credential_lookup_key: CLK,
      nonce,
      signature: await signNonce(nonce),
      previous_sid: 'sid-live',
      require_previous_sid: true,
    }, [
      liveRow('sid-live', seen),
    ]);
    assert.equal(status, 200);
    assert.equal(Object.hasOwn(json, 'previous_sid_status'), false);
    assert.equal(decodeJwtPayload(json.jwt).sid, 'sid-live');
    assert.equal(rows.size, 1, 'no second row');
    assert.ok(rows.get('sid-live').last_seen_at > seen, 'last_seen_at bumped');
  });

  it('reuses a live previous sid when the flag is absent', async () => {
    const nonce = '55'.repeat(32);
    const seen = Math.floor(Date.now() / 1000) - 120;
    const { status, json, rows } = await verify({
      credential_lookup_key: CLK,
      nonce,
      signature: await signNonce(nonce),
      previous_sid: 'sid-live',
    }, [
      liveRow('sid-live', seen),
    ]);
    assert.equal(status, 200);
    assert.equal(decodeJwtPayload(json.jwt).sid, 'sid-live');
    assert.equal(rows.size, 1);
    assert.ok(rows.get('sid-live').last_seen_at > seen);
  });
});
