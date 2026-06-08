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
// statements handlePasskeyRefreshCredential issues (tarn#63 version):
//   - SELECT id FROM passkey_credentials WHERE credential_id=?1 AND account_id=?2
//   - SELECT envelope_generation FROM accounts WHERE data_lookup_key=?1  (pre-read)
//   - UPDATE accounts SET wrapped_data_key=?2, envelope_generation = envelope_generation + 1
//       WHERE data_lookup_key=?1 AND envelope_generation=?3 RETURNING ...  (CAS)
//   - (best-effort audit) INSERT INTO account_key_fetch_log ...
//
// The CAS UPDATE faithfully models D1: it only mutates (and only RETURNs a row)
// when the supplied expected generation matches the stored one; otherwise it
// affects 0 rows and `.first()` resolves to null — which the handler turns into
// a 409. This is what makes the lost-update impossible.
function makeD1(initialEnvelope) {
  const account = {
    credential_lookup_key: 'clk', public_key: 'pub', wrapped_data_key: initialEnvelope,
    app: 'bookish', recovery_lookup_key: null, recovery_public_key: null,
    share_pub: null, share_discoverable: 1, share_lookup_key: null,
    wrapped_account_key: null, data_lookup_key: DLK,
    envelope_generation: 0,
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
          if (/SELECT envelope_generation FROM accounts WHERE data_lookup_key = \?1/.test(sql)) {
            const [dlk] = args;
            return dlk === DLK ? { envelope_generation: account.envelope_generation } : null;
          }
          if (/UPDATE accounts\s+SET wrapped_data_key = \?2,\s*envelope_generation = envelope_generation \+ 1/.test(sql)) {
            const [dlk, envelope, expectedGen] = args;
            // Compare-and-swap: only commit when dlk matches AND the expected
            // generation equals the stored one. 0-row match → null (→ 409).
            if (dlk !== DLK || expectedGen !== account.envelope_generation) return null;
            account.wrapped_data_key = envelope;
            account.envelope_generation += 1;
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

    // Client A reads the base envelope + its generation (0), refreshes ONLY
    // its own wrapping, and submits with expected_generation matching.
    const base = db._account.wrapped_data_key;
    const gen0 = db._account.envelope_generation;
    const newEnv = makeEnvelope({ [CRED_A]: 'fresh-A', [CRED_B]: readWrapped(base, CRED_B) });
    const res = await handlePasskeyRefreshCredential(
      makeRequest(jwtA, { credential_id: CRED_A, new_envelope: newEnv, expected_generation: gen0 }), env, ctx, cors,
    );
    assert.equal(res.status, 200);
    assert.equal(readWrapped(db._account.wrapped_data_key, CRED_A), 'fresh-A');
    assert.equal(readWrapped(db._account.wrapped_data_key, CRED_B), 'stale');
    // The CAS bumped the generation and the response surfaces the new value.
    assert.equal(db._account.envelope_generation, gen0 + 1);
    const body = await res.json();
    assert.equal(body.envelope_generation, gen0 + 1);
  });

  it('CAS catches the race: two concurrent refreshes on the same base/gen → one 200, one 409 (no silent loss)', async () => {
    const db = makeD1(makeEnvelope({ [CRED_A]: 'stale', [CRED_B]: 'stale' }));
    const env = { DB: db, JWT_SECRET };
    const jwtA = await jwtForCred(CRED_A);
    const jwtB = await jwtForCred(CRED_B);

    // Both devices read the SAME base envelope + the SAME generation (0) BEFORE
    // either writes — the read-modify-write window. This is exactly the
    // multi-device sequence the SDK produces: fetch envelope+gen → mutate
    // locally → POST with expected_generation.
    const base = db._account.wrapped_data_key;
    const sharedGen = db._account.envelope_generation; // both read gen 0
    const baseB_forA = readWrapped(base, CRED_B);
    const baseA_forB = readWrapped(base, CRED_A);

    const envFromA = makeEnvelope({ [CRED_A]: 'fresh-A', [CRED_B]: baseB_forA });
    const envFromB = makeEnvelope({ [CRED_A]: baseA_forB, [CRED_B]: 'fresh-B' });

    // Drive them concurrently, BOTH claiming expected_generation = 0. D1
    // serializes the two CAS UPDATEs: the first matches gen 0 and bumps to 1;
    // the second now mismatches (stored gen is 1, expected is 0) → 0 rows → 409.
    const [resA, resB] = await Promise.all([
      handlePasskeyRefreshCredential(makeRequest(jwtA, { credential_id: CRED_A, new_envelope: envFromA, expected_generation: sharedGen }), env, ctx, cors),
      handlePasskeyRefreshCredential(makeRequest(jwtB, { credential_id: CRED_B, new_envelope: envFromB, expected_generation: sharedGen }), env, ctx, cors),
    ]);

    // Exactly one 200 and one 409 — the conflict is CAUGHT, not silently lost.
    const statuses = [resA.status, resB.status].sort();
    assert.deepEqual(statuses, [200, 409],
      `expected one 200 + one 409; got ${resA.status} and ${resB.status}`);

    // The loser's 409 body carries the conflict code + the current generation
    // so the SDK knows to re-fetch and retry.
    const loser = resA.status === 409 ? resA : resB;
    const loserBody = await loser.json();
    assert.equal(loserBody.code, 'ENVELOPE_GENERATION_CONFLICT');
    assert.equal(typeof loserBody.current_generation, 'number');

    // Crucially: the winner's update is intact and NOTHING was overwritten by
    // the loser. The generation advanced exactly once.
    assert.equal(db._account.envelope_generation, sharedGen + 1);
    const finalA = readWrapped(db._account.wrapped_data_key, CRED_A);
    const finalB = readWrapped(db._account.wrapped_data_key, CRED_B);
    // Exactly one of the two is fresh (the winner's); the other stayed at its
    // base value — but NO accepted write was clobbered (the loser was rejected,
    // not silently dropped). This is the safe outcome.
    const exactlyOneFresh =
      (finalA === 'fresh-A' && finalB !== 'fresh-B') ||
      (finalB === 'fresh-B' && finalA !== 'fresh-A');
    assert.ok(exactlyOneFresh, `winner's write must survive; finalA=${finalA} finalB=${finalB}`);
  });

  // The behaviour we WANT — and now HAVE — once the server enforces the
  // generation CAS: the loser of the race gets a 409, RE-FETCHES the winner's
  // envelope + new generation, RE-APPLIES its own mutation onto that fresh
  // base, and RETRIES with the new expected_generation. Then BOTH wrappings
  // land. Here we drive the retry by hand (the SDK does this internally via
  // #casWrite); the point is to prove the SERVER admits a correctly-retried
  // second write and nothing is lost.
  it('no lost update: loser re-fetches + re-applies onto the winner and both refreshes land', async () => {
    const db = makeD1(makeEnvelope({ [CRED_A]: 'stale', [CRED_B]: 'stale' }));
    const env = { DB: db, JWT_SECRET };
    const jwtA = await jwtForCred(CRED_A);
    const jwtB = await jwtForCred(CRED_B);

    const base = db._account.wrapped_data_key;
    const sharedGen = db._account.envelope_generation;

    // A and B both build from gen 0 and submit concurrently with expected gen 0.
    const envFromA = makeEnvelope({ [CRED_A]: 'fresh-A', [CRED_B]: readWrapped(base, CRED_B) });
    const envFromB = makeEnvelope({ [CRED_A]: readWrapped(base, CRED_A), [CRED_B]: 'fresh-B' });
    const [resA, resB] = await Promise.all([
      handlePasskeyRefreshCredential(makeRequest(jwtA, { credential_id: CRED_A, new_envelope: envFromA, expected_generation: sharedGen }), env, ctx, cors),
      handlePasskeyRefreshCredential(makeRequest(jwtB, { credential_id: CRED_B, new_envelope: envFromB, expected_generation: sharedGen }), env, ctx, cors),
    ]);

    // One won, one got 409. Identify the loser and what fresh value it owns.
    const aWon = resA.status === 200;
    const loserJwt = aWon ? jwtB : jwtA;
    const loserCred = aWon ? CRED_B : CRED_A;
    const loserFresh = aWon ? 'fresh-B' : 'fresh-A';
    const loserRes = aWon ? resB : resA;
    assert.equal((aWon ? resA : resB).status, 200);
    assert.equal(loserRes.status, 409);

    // SDK-style retry: re-fetch the winner's live envelope + current gen,
    // re-apply the loser's own change onto it, resubmit with the fresh gen.
    const freshBase = db._account.wrapped_data_key;
    const freshGen = db._account.envelope_generation; // = 1
    const retryEnv = makeEnvelope({
      [CRED_A]: loserCred === CRED_A ? loserFresh : readWrapped(freshBase, CRED_A),
      [CRED_B]: loserCred === CRED_B ? loserFresh : readWrapped(freshBase, CRED_B),
    });
    const retryRes = await handlePasskeyRefreshCredential(
      makeRequest(loserJwt, { credential_id: loserCred, new_envelope: retryEnv, expected_generation: freshGen }),
      env, ctx, cors,
    );
    assert.equal(retryRes.status, 200, 'the correctly-retried second write must be admitted');

    // Both wrappings are now fresh — no lost update.
    assert.equal(readWrapped(db._account.wrapped_data_key, CRED_A), 'fresh-A');
    assert.equal(readWrapped(db._account.wrapped_data_key, CRED_B), 'fresh-B');
    // Generation advanced exactly twice (one per accepted write).
    assert.equal(db._account.envelope_generation, sharedGen + 2);
  });
});
