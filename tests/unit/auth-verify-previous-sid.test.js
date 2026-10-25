// /auth/verify reports whether a supplied previous_sid was reused.
//
// The status code stays 200 in every case so clients that predate the field
// keep working. The field itself is how a current client learns that its
// server-side session row is gone (revoked or idle-pruned) without the
// server refusing to mint a replacement sid.
//
// Run: node --import tsx --test tests/unit/auth-verify-previous-sid.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { handleVerify } from '../../api/src/routes/auth.js';

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
            if (sql.startsWith('DELETE FROM sessions')) return { success: true };
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

describe('POST /auth/verify previous_sid_status', () => {
  it('omits the field when no previous_sid was sent, and still returns 200', async () => {
    const nonce = 'ab'.repeat(32);
    const { status, json, rows } = await verify({
      credential_lookup_key: CLK,
      nonce,
      signature: await signNonce(nonce),
    });
    assert.equal(status, 200);
    assert.equal(Object.hasOwn(json, 'previous_sid_status'), false);
    assert.equal(json.expiresIn, 900);
    assert.equal(json.account_key_stored, true);
    const claims = decodeJwtPayload(json.jwt);
    assert.equal(typeof claims.sid, 'string');
    assert.equal(rows.has(claims.sid), true, 'a new session row was minted');
  });

  it("returns previous_sid_status 'reused' and keeps the same sid when the row is live", async () => {
    const nonce = 'cd'.repeat(32);
    const { status, json, rows } = await verify({
      credential_lookup_key: CLK,
      nonce,
      signature: await signNonce(nonce),
      previous_sid: 'sid-live',
    }, [
      { sid: 'sid-live', data_lookup_key: DLK, app: APP, created_at: 10, last_seen_at: 10, device_label: null, via_recovery: 0 },
    ]);
    assert.equal(status, 200);
    assert.equal(json.previous_sid_status, 'reused');
    assert.equal(decodeJwtPayload(json.jwt).sid, 'sid-live');
    assert.equal(rows.size, 1, 'no second row');
    assert.ok(rows.get('sid-live').last_seen_at > 10, 'last_seen_at bumped');
  });

  it("returns previous_sid_status 'not_found' and mints a new sid when the row is gone", async () => {
    const nonce = 'ef'.repeat(32);
    const { status, json, rows } = await verify({
      credential_lookup_key: CLK,
      nonce,
      signature: await signNonce(nonce),
      previous_sid: 'sid-revoked',
    });
    assert.equal(status, 200, 'old clients must still get a JWT');
    assert.equal(json.previous_sid_status, 'not_found');
    const sid = decodeJwtPayload(json.jwt).sid;
    assert.notEqual(sid, 'sid-revoked');
    assert.equal(rows.has(sid), true);
    assert.equal(rows.has('sid-revoked'), false);
  });

  it("returns 'not_found' when previous_sid belongs to a different account", async () => {
    const nonce = '11'.repeat(32);
    const { status, json } = await verify({
      credential_lookup_key: CLK,
      nonce,
      signature: await signNonce(nonce),
      previous_sid: 'sid-other',
    }, [
      { sid: 'sid-other', data_lookup_key: 'ff'.repeat(32), app: APP, created_at: 10, last_seen_at: 10, device_label: null, via_recovery: 0 },
    ]);
    assert.equal(status, 200);
    assert.equal(json.previous_sid_status, 'not_found');
    assert.notEqual(decodeJwtPayload(json.jwt).sid, 'sid-other');
  });
});
