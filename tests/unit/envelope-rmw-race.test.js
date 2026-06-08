// Driven concurrency test for the ENVELOPE read-modify-write hazard (tarn#62a).
//
// FINDING (verified against the source, 2026-06-07):
//   Every server-side write of accounts.wrapped_data_key is a BLIND overwrite
//   of a client-computed envelope, with NO optimistic-concurrency / compare-
//   and-swap guard:
//     - routes/passkeys.js handlePasskeyRegister      → UPDATE accounts SET wrapped_data_key = ?2 (in a batch)
//     - routes/passkeys.js handleDeletePasskey        → UPDATE accounts SET wrapped_data_key = ?2 (in a batch)
//     - routes/passkeys.js handlePasskeyRefreshCredential → UPDATE accounts SET wrapped_data_key = ?2
//     - routes/account.js  handleRotateAccountKey     → UPDATE accounts SET wrapped_data_key = ?2, ...
//   In all four the new envelope arrives fully-formed in the request body; the
//   server validates only its SHAPE (validateEnvelopeShape) and writes it. The
//   read half of the read-modify-write happens CLIENT-SIDE (the SDK fetches the
//   envelope, unwraps, mutates, re-wraps, and posts the whole thing back). There
//   is no `WHERE wrapped_data_key = <expected>` and no version/gen check, so
//   when two devices concurrently mutate the SAME base envelope, last-write-wins
//   and the earlier device's change is SILENTLY LOST.
//
// This test DRIVES the real handler (handlePasskeyRefreshCredential — the
// simplest envelope writer: a plain UPDATE, no webauthn verification) end-to-end
// through the real requireAuth path (real signed JWTs) against an in-memory
// `accounts` D1 shim, and demonstrates the lost update concretely.
//
// Per the issue instructions: a new test that exposes a REAL bug is a valuable
// finding, NOT something to hide or weaken. So:
//   * The "documents the lost update" test ASSERTS the buggy behaviour (it
//     passes today, and is the executable evidence of the hazard).
//   * The "no lost update" test — the behaviour we WANT once a CAS/gen guard is
//     added — is marked `{ todo: true }` so the suite stays green while flagging
//     the gap. When the server grows a compare-and-swap (e.g. an `expected_gen`
//     or `If-Match`-style guard), drop the todo and it should pass.
//
// Run: node --import tsx --test tests/unit/envelope-rmw-race.test.js
//   or via the umbrella: npm run test:unit

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { handlePasskeyRefreshCredential } from '../../api/src/routes/passkeys.js';
import { signJWT, _resetHMACKey } from '../../api/src/auth.js';

// Base64-encoded HMAC secret (getHMACKey does atob()).
const JWT_SECRET = btoa('envelope-rmw-race-test-secret-key-0123456789');
const DLK = 'd'.repeat(64);
const CRED_A = 'cred-A';
const CRED_B = 'cred-B';

// Build a wire-format envelope with a single (latest) gen whose wrappings are
// password + one passkey_prf per credential. `wrappedByCred` maps credential_id
// → the `wrapped` value for that credential's passkey_prf wrapping.
function makeEnvelope(wrappedByCred) {
  const wrappings = [{ factor: 'password', wrapped: 'pw-wrap' }];
  for (const [credId, wrapped] of Object.entries(wrappedByCred)) {
    wrappings.push({ factor: 'passkey_prf', credential_id: credId, wrapped });
  }
  return JSON.stringify({ v: 1, dek_chain: [{ wrappings }] });
}

// Read a credential's current passkey_prf `wrapped` value out of an envelope's
// latest gen (null if absent).
function readWrapped(envelopeStr, credId) {
  const parsed = JSON.parse(envelopeStr);
  const latest = parsed.dek_chain[parsed.dek_chain.length - 1];
  const w = (latest.wrappings || []).find(
    (x) => x.factor === 'passkey_prf' && x.credential_id === credId,
  );
  return w ? w.wrapped : null;
}

// In-memory `accounts` + `passkey_credentials` D1 shim covering exactly the
// statements handlePasskeyRefreshCredential issues:
//   - SELECT id FROM passkey_credentials WHERE credential_id=?1 AND account_id=?2
//   - UPDATE accounts SET wrapped_data_key=?2 WHERE data_lookup_key=?1 RETURNING ...
//   - (best-effort audit) INSERT INTO account_key_fetch_log ...
function makeD1(initialEnvelope) {
  const account = {
    credential_lookup_key: 'clk', public_key: 'pub', wrapped_data_key: initialEnvelope,
    app: 'bookish', recovery_lookup_key: null, recovery_public_key: null,
    share_pub: null, share_discoverable: 1, share_lookup_key: null,
    wrapped_account_key: null, data_lookup_key: DLK,
  };
  const creds = new Set([CRED_A, CRED_B]);
  const db = {
    _account: account,
    prepare(sql) {
      let args = [];
      return {
        bind(...a) { args = a; return this; },
        async first() {
          if (/FROM passkey_credentials WHERE credential_id = \?1 AND account_id = \?2/.test(sql)) {
            const [credId, accId] = args;
            return (creds.has(credId) && accId === DLK) ? { id: credId } : null;
          }
          if (/UPDATE accounts\s+SET wrapped_data_key = \?2/.test(sql)) {
            const [dlk, envelope] = args;
            if (dlk !== DLK) return null;
            account.wrapped_data_key = envelope; // BLIND overwrite — the bug under test.
            return { ...account };
          }
          return null;
        },
        async run() {
          // account_key_fetch_log audit insert — no-op.
          return { success: true };
        },
      };
    },
  };
  return db;
}

function makeRequest(jwt, body) {
  return {
    headers: {
      get(name) {
        if (name === 'Authorization') return `Bearer ${jwt}`;
        if (name === 'Origin') return 'https://getbookish.app';
        return null;
      },
    },
    async json() { return body; },
  };
}

// Defer waitUntil work but swallow it (audit / Arweave republish are best-effort
// and must not interfere with the main-path assertions).
const ctx = { waitUntil(p) { Promise.resolve(p).catch(() => {}); } };
const cors = {};

async function jwtForCred(credId) {
  // via_passkey + matching passkey_cred_id, no sid → skips the session-active
  // check (pre-7.5 grandfather path in requireAuth).
  return await signJWT(
    { sub: DLK, role: 'user', app: 'bookish', via_passkey: true, passkey_cred_id: credId },
    JWT_SECRET,
  );
}

describe('tarn#62a — envelope read-modify-write race (concurrent passkey refresh)', () => {
  beforeEach(() => { _resetHMACKey(); });

  it('sanity: a single refresh persists the new wrapping (real handler + real auth)', async () => {
    const db = makeD1(makeEnvelope({ [CRED_A]: 'stale', [CRED_B]: 'stale' }));
    const env = { DB: db, JWT_SECRET };
    const jwtA = await jwtForCred(CRED_A);

    // Client A reads the base envelope, refreshes ONLY its own wrapping.
    const base = db._account.wrapped_data_key;
    const newEnv = makeEnvelope({ [CRED_A]: 'fresh-A', [CRED_B]: readWrapped(base, CRED_B) });
    const res = await handlePasskeyRefreshCredential(
      makeRequest(jwtA, { credential_id: CRED_A, new_envelope: newEnv }), env, ctx, cors,
    );
    assert.equal(res.status, 200);
    assert.equal(readWrapped(db._account.wrapped_data_key, CRED_A), 'fresh-A');
    assert.equal(readWrapped(db._account.wrapped_data_key, CRED_B), 'stale');
  });

  it('REAL BUG (documented): two concurrent refreshes on the same base envelope LOSE one update', async () => {
    const db = makeD1(makeEnvelope({ [CRED_A]: 'stale', [CRED_B]: 'stale' }));
    const env = { DB: db, JWT_SECRET };
    const jwtA = await jwtForCred(CRED_A);
    const jwtB = await jwtForCred(CRED_B);

    // Both devices read the SAME base envelope BEFORE either writes (the
    // read-modify-write window). This is exactly the multi-device sequence the
    // SDK produces: fetch envelope → mutate locally → POST.
    const base = db._account.wrapped_data_key;
    const baseB_forA = readWrapped(base, CRED_B); // A sees B's CURRENT wrapping
    const baseA_forB = readWrapped(base, CRED_A); // B sees A's CURRENT wrapping

    // A wants {A: fresh-A, B: <unchanged from base>}
    const envFromA = makeEnvelope({ [CRED_A]: 'fresh-A', [CRED_B]: baseB_forA });
    // B wants {A: <unchanged from base>, B: fresh-B}
    const envFromB = makeEnvelope({ [CRED_A]: baseA_forB, [CRED_B]: 'fresh-B' });

    // Drive them concurrently. D1 serializes the two UPDATEs; both started from
    // the same base, so whichever lands LAST overwrites the other's change.
    const [resA, resB] = await Promise.all([
      handlePasskeyRefreshCredential(makeRequest(jwtA, { credential_id: CRED_A, new_envelope: envFromA }), env, ctx, cors),
      handlePasskeyRefreshCredential(makeRequest(jwtB, { credential_id: CRED_B, new_envelope: envFromB }), env, ctx, cors),
    ]);
    assert.equal(resA.status, 200);
    assert.equal(resB.status, 200, 'no CAS guard exists, so the second write is ACCEPTED (not 409) — this is the bug');

    const finalA = readWrapped(db._account.wrapped_data_key, CRED_A);
    const finalB = readWrapped(db._account.wrapped_data_key, CRED_B);

    // The correct end state would be BOTH fresh (A=fresh-A AND B=fresh-B). The
    // actual end state has exactly ONE fresh and one reverted-to-stale — a lost
    // update. We assert that at least one update was lost (last-write-wins), so
    // the test is deterministic regardless of which Promise settled last.
    const bothFresh = finalA === 'fresh-A' && finalB === 'fresh-B';
    assert.equal(bothFresh, false,
      'EXPECTED FAILURE-OF-SAFETY: a CAS guard would land both updates; today one is lost');

    const oneLost =
      (finalA === 'fresh-A' && finalB === 'stale') ||
      (finalA === 'stale' && finalB === 'fresh-B');
    assert.ok(oneLost,
      `lost-update signature not observed; finalA=${finalA} finalB=${finalB}`);
  });

  // The behaviour we WANT after the server grows a compare-and-swap / gen guard
  // on wrapped_data_key. Marked todo so the suite stays green while flagging the
  // gap; flip to a real assertion when the guard lands (then this should pass
  // and the "REAL BUG" test above should be inverted/removed).
  it('no lost update when both refreshes commit (requires server-side CAS — NOT yet implemented)', { todo: 'tarn#62a: add optimistic-concurrency guard on accounts.wrapped_data_key' }, async () => {
    const db = makeD1(makeEnvelope({ [CRED_A]: 'stale', [CRED_B]: 'stale' }));
    const env = { DB: db, JWT_SECRET };
    const jwtA = await jwtForCred(CRED_A);
    const jwtB = await jwtForCred(CRED_B);
    const base = db._account.wrapped_data_key;
    const envFromA = makeEnvelope({ [CRED_A]: 'fresh-A', [CRED_B]: readWrapped(base, CRED_B) });
    const envFromB = makeEnvelope({ [CRED_A]: readWrapped(base, CRED_A), [CRED_B]: 'fresh-B' });
    await Promise.all([
      handlePasskeyRefreshCredential(makeRequest(jwtA, { credential_id: CRED_A, new_envelope: envFromA }), env, ctx, cors),
      handlePasskeyRefreshCredential(makeRequest(jwtB, { credential_id: CRED_B, new_envelope: envFromB }), env, ctx, cors),
    ]);
    // With a CAS guard the loser would 409 and retry against the winner's
    // envelope, so BOTH wrappings end up fresh.
    assert.equal(readWrapped(db._account.wrapped_data_key, CRED_A), 'fresh-A');
    assert.equal(readWrapped(db._account.wrapped_data_key, CRED_B), 'fresh-B');
  });
});
