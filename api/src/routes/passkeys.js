// Passkey route handlers — Phase 6 of the recovery roadmap.
//
// Implements the WebAuthn-PRF passkey factor as a third independent
// encryption factor alongside `password` and `recovery_phrase`. A
// registered passkey can both unwrap the DEK chain (via PRF-derived key)
// and authenticate a session (via the standard WebAuthn signature).
//
//   POST /api/v1/auth/passkey/register-options          (JWT, user)
//   POST /api/v1/auth/passkey/register                  (JWT, user)
//   POST /api/v1/auth/passkey/authentication-options    (public)
//   POST /api/v1/auth/passkey/authenticate              (public)
//   GET  /api/v1/account/passkeys                       (JWT, user)
//   DELETE /api/v1/account/passkeys/:credential_id      (JWT + step-up)
//
// Library choice: @simplewebauthn/server v13 handles the CBOR/COSE parsing
// and signature verification. Avoiding it would mean reimplementing the
// COSE Key parser, the attestation-object CBOR layout, and replay-counter
// semantics — error-prone for a security-critical primitive. The library
// is mainstream (>4 years old, widely used in CF Workers deployments) and
// satisfies the supply-chain rule (latest >7 days old at time of work).
//
// Origin / RP-ID: Tarn serves multiple front-ends (getbookish.app,
// dev.getbookish.app, localhost). The relying-party-id is derived from
// the request's `Origin` header — we intersect it against the
// `ALLOWED_ORIGINS` allowlist, then strip the scheme to get the eTLD+1
// shape WebAuthn requires. Local-dev origins map to `localhost`. This
// pattern mirrors the CORS handler so the surface stays consistent.

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

import { jsonResponse, errorResponse } from '../worker.js';
import { requireAuth } from '../middleware/auth.js';
import { signJWT, PASSKEY_JWT_TTL_SECONDS } from '../auth.js';
import { checkAndIncrementRateLimit } from '../rate-limit.js';
import { consumeStepUpToken, STEP_UP_SCOPE_ACCOUNT_KEY_FETCH, buildCredentialTags } from './auth.js';
import { buildSignedDataItem, uploadSignedDataItem } from '../turbo.js';
import { upsertWriteThrough, markLookupBootstrapped } from '../cache.js';
import { persistPasskeyRegBlob, persistPasskeyRegTombstone } from './passkey-reg.js';
import { mirrorUploadWithTracking } from '../observability/mirror-failures.js';
import {
  pruneStaleSessions,
  createOrReuseSession,
  validateDeviceLabel,
} from '../sessions.js';

// ============ HELPERS ============

const WEBAUTHN_CHALLENGE_TTL_SECONDS = 60;
const RP_NAME = 'Tarn';

// ============ APP-WIDE CONSTANT PRF SALT (tarn#59) ============
//
// A single, fixed 32-byte PRF salt used for EVERY Tarn passkey, at both
// register time and authentication time. This closes the per-credential
// enumeration in the public authentication-options endpoint: with a constant
// salt the server returns ONE value via `options.extensions.prf.eval.first`
// and NO per-credential `evalByCredential` map, so the discoverable
// (usernameless) flow no longer has to read & echo the entire
// passkey_credentials table on an unauthenticated call.
//
// WHY THIS IS CRYPTOGRAPHICALLY SAFE (verify against WebAuthn PRF mechanics):
//   The WebAuthn PRF extension is HMAC keyed by a per-CREDENTIAL secret that
//   the authenticator generates at registration time and never exports. The
//   RP-supplied salt is only the HMAC *message*. So PRF(constant_salt) is
//   still UNIQUE per credential — two different passkeys fed the SAME salt
//   produce DIFFERENT 32-byte outputs (different authenticator secret), hence
//   different `passkey_KEK`s, hence per-credential-unique AES-KW wrappings.
//   The salt was never a secret anyway — it was previously returned in the
//   clear on a public endpoint. A constant salt removes a server-side lookup
//   without weakening the derivation.
//
// WHY PER-ACCOUNT SALT CANNOT WORK FOR THE DISCOVERABLE FLOW:
//   At authentication-options time the server does NOT know which account is
//   signing in (the whole point of usernameless / resident-credential login).
//   Returning a per-account salt would require first resolving the account —
//   i.e. re-introducing exactly the enumeration we are removing. The PRF salt
//   must therefore be a value the server can return WITHOUT knowing the
//   account: a single app-wide constant is the only shape that satisfies that.
//
// The value is derived deterministically from a fixed domain string so it is
// self-documenting and reproducible, and lives SERVER-SIDE only — both
// register-options and authentication-options return the SAME constant, so the
// SDK never hardcodes it: it simply uses whatever salt the server provides at
// register (to wrap) and at auth (to unwrap). See PASSKEY_PRF_SALT_DOMAIN.
const PASSKEY_PRF_SALT_DOMAIN = 'tarn-passkey-prf-constant-salt-v1';

// SHA-256 of the domain string → a fixed 32-byte salt. Computed once at module
// load. Synchronous derivation is impossible in the Workers runtime (only
// crypto.subtle is available, which is async), so we lazily memoize the digest
// the first time a handler needs it.
let _constantPrfSalt = null;
async function getConstantPrfSalt() {
  if (_constantPrfSalt) return _constantPrfSalt;
  const data = new TextEncoder().encode(PASSKEY_PRF_SALT_DOMAIN);
  const digest = await crypto.subtle.digest('SHA-256', data);
  _constantPrfSalt = new Uint8Array(digest); // 32 bytes
  return _constantPrfSalt;
}

// Abuse cap for the public, unauthenticated passkey authentication-options
// endpoint (tarn#59). Keyed per-IP, mirroring the other public endpoints
// (register / lookup / share-lookup / inbox-fetch). Each options call mints a
// WebAuthn challenge row + (in the discoverable flow) reads the credential
// table, so an unbounded public endpoint is both a scraping surface and a
// write-amplification vector. 60/hr is generous for a real sign-in ceremony
// (a user retrying a few times still fits comfortably) while shutting down
// bulk enumeration. Fails open on KV outage, same as every other limiter.
const MAX_PASSKEY_AUTH_OPTIONS_PER_HOUR = 60;

async function checkPasskeyAuthOptionsRateLimit(env, request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const data = new TextEncoder().encode(ip + '-tarn-passkey-authopts-salt');
  const hash = await crypto.subtle.digest('SHA-256', data);
  const ipHash = Array.from(new Uint8Array(hash)).slice(0, 8)
    .map(b => b.toString(16).padStart(2, '0')).join('');
  const hour = new Date().toISOString().slice(0, 13); // YYYY-MM-DDTHH
  const key = `passkey-authopts:${ipHash}:${hour}`;
  const { allowed, count } = await checkAndIncrementRateLimit(
    env.RATE_KV, key, MAX_PASSKEY_AUTH_OPTIONS_PER_HOUR,
  );
  return { allowed, remaining: Math.max(0, MAX_PASSKEY_AUTH_OPTIONS_PER_HOUR - count) };
}

/**
 * Allowlist of (origin → rp_id) pairs. Tarn-issued passkeys must have an
 * RP-ID matching one of these, or registration / authentication is
 * refused. Mirrors the CORS allowlist in worker.js — keep them in sync.
 */
const ORIGIN_TO_RP_ID = {
  'https://getbookish.app': 'getbookish.app',
  'https://dev.getbookish.app': 'dev.getbookish.app',
  'https://tarn.dev': 'tarn.dev',
  'http://localhost:3000': 'localhost',
  'http://127.0.0.1:3000': 'localhost',
};

function rpFromRequest(request) {
  const origin = request.headers.get('Origin');
  if (!origin || !(origin in ORIGIN_TO_RP_ID)) return null;
  return { origin, rpId: ORIGIN_TO_RP_ID[origin] };
}

function generateChallengeBytes() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Phase 6.2 — given a parsed envelope object and a credential_id, return
 * true if the credential has NO `passkey_prf` wrapping at the LATEST gen.
 * Returns false when a wrapping is present, when the envelope is
 * unparseable (best-effort: surface as "not stale" so the SDK still gets
 * a session and discovers the real error itself), or when no dek_chain
 * is present.
 *
 * Used both by /auth/passkey/authenticate (per-credential, on the
 * credential the user just signed in with) and by /account/passkeys
 * (per-credential, across the full registered list).
 */
function isCredentialStale(envelopeObj, credentialId) {
  try {
    if (!envelopeObj || !Array.isArray(envelopeObj.dek_chain) || envelopeObj.dek_chain.length === 0) {
      return false;
    }
    const latest = envelopeObj.dek_chain[envelopeObj.dek_chain.length - 1];
    const wraps = Array.isArray(latest?.wrappings) ? latest.wrappings : [];
    const hit = wraps.some(
      w => w?.factor === 'passkey_prf' && w?.credential_id === credentialId,
    );
    return !hit;
  } catch {
    return false;
  }
}

function bytesToBase64Url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(b64url) {
  const padded = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  const bin = atob(padded + '='.repeat(padLen));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/**
 * Audit-log a passkey lifecycle event into account_key_fetch_log (the
 * shared "account-security audit" table from migration 0017).
 *
 * Best-effort — a D1 hiccup must not fail the user-visible operation.
 */
function writePasskeyAudit(ctx, env, request, dataLookupKey, op) {
  ctx.waitUntil((async () => {
    try {
      const ip = request.headers.get('CF-Connecting-IP') || null;
      let ipHash = null;
      if (ip) {
        const data = new TextEncoder().encode(ip + '-tarn-account-key-audit-salt');
        const hash = await crypto.subtle.digest('SHA-256', data);
        ipHash = Array.from(new Uint8Array(hash))
          .slice(0, 8)
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      }
      const userAgent = (request.headers.get('User-Agent') || '').slice(0, 256) || null;
      await env.DB.prepare(
        'INSERT INTO account_key_fetch_log (data_lookup_key, fetched_at, ip_hash, user_agent, op) VALUES (?1, ?2, ?3, ?4, ?5)'
      ).bind(dataLookupKey, Date.now(), ipHash, userAgent, op).run();
    } catch (err) {
      console.warn(`[tarn-api] passkey audit insert failed (op=${op}):`, err.message);
    }
  })());
}

/**
 * Republish the credential mapping blob to Arweave with the supplied
 * envelope. Mirrors persistCredentialBlobFromRow in account.js but reads
 * a freshly-supplied envelope (we just updated wrapped_data_key) rather
 * than the row's value. Best-effort (waitUntil).
 */
function persistCredentialBlobFromRowWithEnvelope(ctx, env, row) {
  const blob = {
    data_lookup_key: row.data_lookup_key,
    wrapped_data_key: row.wrapped_data_key,
    public_key: row.public_key,
    app: row.app,
  };
  if (row.recovery_lookup_key) blob.recovery_lookup_key = row.recovery_lookup_key;
  if (row.recovery_public_key) blob.recovery_public_key = row.recovery_public_key;
  if (row.share_pub) blob.share_pub = row.share_pub;
  if (row.share_pub) blob.share_discoverable = row.share_discoverable === 1;
  if (row.share_lookup_key) blob.share_lookup_key = row.share_lookup_key;
  if (row.wrapped_account_key) blob.wrapped_account_key = row.wrapped_account_key;

  // Dual-tag with Lk + RLk — see buildCredentialTags in auth.js for rationale.
  const tags = buildCredentialTags(row.credential_lookup_key, row.recovery_lookup_key);

  ctx.waitUntil((async () => {
    try {
      const signingKey = env.APP_SIGNING_KEY;
      if (!signingKey) {
        console.warn('[tarn-api] APP_SIGNING_KEY not set — skipping Arweave republish');
        return;
      }
      const blobBytes = new TextEncoder().encode(JSON.stringify(blob));
      const { signedDataItem, txid } = await buildSignedDataItem(blobBytes, tags, signingKey);
      await upsertWriteThrough(env.DB, txid, tags);
      await markLookupBootstrapped(env.DB, row.credential_lookup_key, 'tarn', 'cred');
      console.log(`[tarn-api] Passkey republish cached: ${txid}`);
      const turbo = await mirrorUploadWithTracking({
        uploadFn: () => uploadSignedDataItem(signedDataItem),
        db: env.DB,
        namespace: 'cred-passkey-republish',
        intendedTxid: txid,
        tags,
        signedDataItem,
      });
      if (turbo.ok) {
        console.log(`[tarn-api] Passkey republish uploaded to Turbo: ${txid}`);
      } else {
        console.warn(`[tarn-api] Passkey republish Turbo upload failed: ${turbo.status} ${turbo.body}`);
      }
    } catch (err) {
      console.error('[tarn-api] Passkey republish error:', err.message);
    }
  })());
}

/**
 * Validate that a wire-format `wrapped_data_key` envelope contains
 * exactly one `passkey_prf` wrapping per registered credential at every
 * gen, plus the existing `password` wrapping. Returns null on success or
 * an error string. Conservative: we don't deeply validate the existing
 * factors here (the SDK already builds them well-formed), only that the
 * passkey wrappings the caller is registering / removing make sense.
 */
function validateEnvelopeShape(envelopeStr) {
  if (typeof envelopeStr !== 'string' || envelopeStr.length === 0) {
    return 'envelope must be a non-empty string';
  }
  if (envelopeStr.length > 16384) {
    return 'envelope is implausibly long';
  }
  let parsed;
  try {
    parsed = JSON.parse(envelopeStr);
  } catch {
    return 'envelope is not valid JSON';
  }
  if (!parsed || typeof parsed !== 'object') return 'envelope must be an object';
  if (parsed.v !== 1) return `envelope: unexpected version ${parsed.v}`;
  if (!Array.isArray(parsed.dek_chain) || parsed.dek_chain.length === 0) {
    return 'envelope: dek_chain must be a non-empty array';
  }
  for (const entry of parsed.dek_chain) {
    if (!entry || !Array.isArray(entry.wrappings)) {
      return 'envelope: dek_chain entry malformed';
    }
    const seen = new Set();
    for (const w of entry.wrappings) {
      if (!w || typeof w.factor !== 'string' || typeof w.wrapped !== 'string') {
        return 'envelope: wrapping malformed';
      }
      // factor + credential_id must be unique within the entry; password and
      // recovery_phrase carry no credential_id, passkey_prf carries one.
      const dedupKey = w.factor === 'passkey_prf'
        ? `${w.factor}:${w.credential_id}`
        : w.factor;
      if (seen.has(dedupKey)) return `envelope: duplicate wrapping ${dedupKey}`;
      seen.add(dedupKey);
      if (w.factor === 'passkey_prf') {
        if (typeof w.credential_id !== 'string' || w.credential_id.length === 0) {
          return 'envelope: passkey_prf wrapping missing credential_id';
        }
      }
    }
  }
  return null;
}

/**
 * tarn#63 — validate a client-supplied `expected_generation` field for the
 * envelope compare-and-swap. Returns either:
 *   { ok: true, expected: <int|null> }   — null means "client did not send one"
 *   { ok: false, error: <string> }       — present but malformed (caller → 400)
 *
 * Lenient on ABSENCE (null/undefined): a legacy client / bundle that predates
 * the CAS protocol omits the field, and we must not 400 it out of existence
 * during the migrate→deploy→ship-SDK window. Such a write falls back to a
 * read-current-then-write (preserving today's last-write-wins for legacy
 * callers only). STRICT on PRESENCE: a sent value must be a non-negative
 * integer or it's a client bug we want to surface.
 */
function parseExpectedGeneration(value) {
  if (value === undefined || value === null) return { ok: true, expected: null };
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    return { ok: false, error: 'expected_generation must be a non-negative integer' };
  }
  return { ok: true, expected: value };
}

// ============ POST /api/v1/auth/passkey/register-options ============

export async function handlePasskeyRegisterOptions(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') {
    return errorResponse('Only user accounts can register passkeys', 403, cors);
  }

  const rp = rpFromRequest(request);
  if (!rp) {
    return errorResponse('Origin not allowed for passkey operations', 400, cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  // device_label is bounded to the same length policy as session labels.
  const labelErr = validateDeviceLabel(body?.device_label);
  if (labelErr) return errorResponse(labelErr, 400, cors);

  // Existing credentials for this account — feed to excludeCredentials so
  // the authenticator refuses to re-enroll the same key twice.
  const existing = await env.DB.prepare(
    'SELECT credential_id FROM passkey_credentials WHERE account_id = ?1'
  ).bind(auth.data_lookup_key).all();
  const excludeCredentials = (existing.results || []).map(r => ({
    id: r.credential_id,
    transports: undefined,
  }));

  // tarn#59 — use the APP-WIDE CONSTANT PRF salt (not a per-credential
  // random one). The PRF output is still unique per credential because the
  // authenticator keys it on a per-credential secret; the salt is only the
  // HMAC message. Registering under the constant means the credential's
  // wrapping is derived from PRF(constant), which is exactly what the
  // discoverable auth-options flow will hand back at sign-in — so the same
  // wrapping key is reproduced without the server ever enumerating salts.
  const prfSalt = await getConstantPrfSalt();
  const prfSaltB64Url = bytesToBase64Url(prfSalt);

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: rp.rpId,
    userID: new TextEncoder().encode(auth.data_lookup_key),
    userName: auth.data_lookup_key, // opaque — Tarn doesn't surface usernames here
    timeout: 60_000,
    attestationType: 'none', // PRF flow — we trust the device, no attestation chain needed
    excludeCredentials,
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
    extensions: {
      // The simplewebauthn types treat `prf` as opt-in. Cast through a
      // looser shape so the build doesn't choke on the not-yet-merged
      // typing for the PRF extension.
      prf: { eval: { first: prfSalt } },
    },
  });

  // Persist the challenge so the verify step can rebind it. Bind to the
  // logged-in account.
  const issuedAt = Date.now();
  const expiresAt = issuedAt + WEBAUTHN_CHALLENGE_TTL_SECONDS * 1000;
  await env.DB.prepare(
    'INSERT INTO webauthn_challenges (challenge, data_lookup_key, purpose, issued_at, expires_at, consumed_at) VALUES (?1, ?2, ?3, ?4, ?5, NULL)'
  ).bind(
    options.challenge,
    auth.data_lookup_key,
    'register',
    issuedAt,
    expiresAt,
  ).run();

  return jsonResponse({
    options,
    prf_salt: prfSaltB64Url,
  }, 200, cors);
}

// ============ POST /api/v1/auth/passkey/register ============

export async function handlePasskeyRegister(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') {
    return errorResponse('Only user accounts can register passkeys', 403, cors);
  }

  const rp = rpFromRequest(request);
  if (!rp) {
    return errorResponse('Origin not allowed for passkey operations', 400, cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { credential, prf_salt, new_envelope, device_label, expected_generation } = body || {};
  if (!credential || typeof credential !== 'object') {
    return errorResponse('credential is required', 400, cors);
  }
  if (typeof prf_salt !== 'string' || prf_salt.length === 0) {
    return errorResponse('prf_salt is required', 400, cors);
  }
  const envErr = validateEnvelopeShape(new_envelope);
  if (envErr) return errorResponse(`new_envelope: ${envErr}`, 400, cors);
  const labelErr = validateDeviceLabel(device_label);
  if (labelErr) return errorResponse(labelErr, 400, cors);
  const gen = parseExpectedGeneration(expected_generation);
  if (!gen.ok) return errorResponse(gen.error, 400, cors);

  // Pull the original challenge by digest of the supplied clientDataJSON →
  // simplewebauthn does the canonical binding for us, but we still need to
  // hand it the expected challenge. Look up by the challenge value the
  // SDK echoes back from the server-issued options.
  let clientDataChallenge;
  try {
    const cd = JSON.parse(
      new TextDecoder().decode(base64UrlToBytes(credential.response.clientDataJSON))
    );
    clientDataChallenge = cd.challenge;
  } catch {
    return errorResponse('credential.response.clientDataJSON is malformed', 400, cors);
  }

  const challengeRow = await env.DB.prepare(
    `UPDATE webauthn_challenges
        SET consumed_at = ?2
      WHERE challenge = ?1
        AND consumed_at IS NULL
        AND expires_at >= ?2
        AND purpose = 'register'
        AND data_lookup_key = ?3
      RETURNING challenge`
  ).bind(clientDataChallenge, Date.now(), auth.data_lookup_key).first();
  if (!challengeRow) {
    return errorResponse('Invalid or expired registration challenge', 401, cors);
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: clientDataChallenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.rpId,
      requireUserVerification: false,
    });
  } catch (err) {
    return errorResponse(`Registration verification failed: ${err.message || 'unknown'}`, 400, cors);
  }
  if (!verification.verified || !verification.registrationInfo) {
    return errorResponse('Registration verification rejected', 400, cors);
  }

  const reg = verification.registrationInfo;
  // simplewebauthn v13 returns `credential.id` (base64url string),
  // `credential.publicKey` (Uint8Array, COSE-encoded), `credential.counter`.
  const credentialId = reg.credential.id;
  const publicKeyB64 = bytesToBase64Url(reg.credential.publicKey);
  const signCount = reg.credential.counter;

  // tarn#63 — db.batch CANNOT be used for the CAS here. A conditional UPDATE
  // that matches 0 rows does NOT throw, so it would NOT abort a D1 batch — the
  // sibling credential INSERT would still commit, defeating the guard. So we
  // run the envelope CAS as a STANDALONE statement FIRST and only INSERT the
  // credential row if the CAS actually landed.
  //
  // Read the current generation first to disambiguate 404 (no account) from
  // 409 (stale expected) and to supply the expected value for legacy callers.
  const cur = await env.DB.prepare(
    'SELECT envelope_generation FROM accounts WHERE data_lookup_key = ?1'
  ).bind(auth.data_lookup_key).first();
  if (!cur) {
    return errorResponse('Account not found', 404, cors);
  }
  const expectedGen = gen.expected === null ? cur.envelope_generation : gen.expected;

  // Step 1: conditional envelope CAS (standalone). On a CAS miss we 409 and
  // never touch passkey_credentials, so there is NO orphan credential row.
  const updated = await env.DB.prepare(
    `UPDATE accounts
        SET wrapped_data_key = ?2,
            envelope_generation = envelope_generation + 1
      WHERE data_lookup_key = ?1
        AND envelope_generation = ?3
      RETURNING credential_lookup_key, public_key, wrapped_data_key, app,
                recovery_lookup_key, recovery_public_key,
                share_pub, share_discoverable, share_lookup_key,
                wrapped_account_key, data_lookup_key, envelope_generation`
  ).bind(auth.data_lookup_key, new_envelope, expectedGen).first();
  if (!updated) {
    return jsonResponse(
      {
        error: 'envelope generation conflict — re-fetch and retry',
        code: 'ENVELOPE_GENERATION_CONFLICT',
        current_generation: cur.envelope_generation,
      },
      409,
      cors,
    );
  }

  // Step 2: insert the credential row. The CAS already committed.
  //
  // tarn#59 — the `prf_salt` column is now VESTIGIAL. With the app-wide
  // constant salt (getConstantPrfSalt), every new row stores that same
  // constant (register-options handed it to the SDK, which echoes it back
  // here), and the authentication-options path no longer reads the column at
  // all — it returns the constant directly. We keep storing it (rather than
  // dropping the column) so the row shape and the Arweave `Type=passkey-reg`
  // mirror stay unchanged (no migration, no rebuild-tool churn); the value is
  // simply ignored on read. The column may be dropped in a future migration.
  //
  // Residual window (CAS committed, INSERT fails): the envelope now carries a
  // passkey_prf wrapping for `credentialId` with no passkey_credentials row.
  // This is HARMLESS and self-correcting: the orphan wrapping is dead weight
  // (no credential row can ever use it), the DEK chain stays fully intact
  // (password + recovery + the orphan wrapping), and NO auth factor is lost.
  // A retry of register re-runs cleanly (the failed INSERT never committed, so
  // the UNIQUE guard is not tripped on the same credential_id). We chose this
  // ordering over INSERT-first because the alternative residual — a registered
  // credential with no envelope wrapping — surfaces as a visible "stale"
  // passkey the user must manually repair, whereas an orphan wrapping is
  // invisible and inert.
  try {
    await env.DB.prepare(
      'INSERT INTO passkey_credentials (account_id, credential_id, public_key, prf_salt, sign_count, device_label, created_at, last_used_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)'
    ).bind(
      auth.data_lookup_key,
      credentialId,
      publicKeyB64,
      prf_salt,
      signCount,
      device_label || null,
      Date.now(),
    ).run();
  } catch (err) {
    if (/UNIQUE/i.test(err.message || '')) {
      // The credential_id is already registered (a concurrent register won the
      // INSERT, or a retry after a successful prior INSERT). The CAS we just
      // committed re-wrote the envelope to (re)include this credential's
      // wrapping, which is idempotently correct — the credential row already
      // exists and now has a matching wrapping. Surface 409 so the caller
      // knows the credential was not freshly created by THIS request.
      return errorResponse('Credential already registered', 409, cors);
    }
    throw err;
  }

  writePasskeyAudit(ctx, env, request, auth.data_lookup_key, 'passkey_register');
  persistCredentialBlobFromRowWithEnvelope(ctx, env, updated);

  // Phase B (Arweave-recoverability) — mirror the new credential row to
  // Arweave as a `Type=passkey-reg` blob. D1-first ordering (the row was
  // inserted above); the upload runs in ctx.waitUntil. See
  // `routes/passkey-reg.js` header for the full wire format and the
  // ordering / tombstone-scheme rationale.
  const createdAt = Date.now();
  persistPasskeyRegBlob(ctx, env, {
    dataLookupKey: auth.data_lookup_key,
    credentialId,
    publicKey: publicKeyB64,
    prfSalt: prf_salt,
    deviceLabel: device_label || null,
    createdAt,
  });

  return jsonResponse({
    credential_id: credentialId,
    device_label: device_label || null,
    created_at: createdAt,
    // tarn#63 — the post-write generation, so the SDK can advance its local
    // CAS token for a follow-up envelope mutation in the same session.
    envelope_generation: updated.envelope_generation,
  }, 201, cors);
}

// ============ POST /api/v1/auth/passkey/authentication-options ============

export async function handlePasskeyAuthOptions(request, env, ctx, cors) {
  const rp = rpFromRequest(request);
  if (!rp) {
    return errorResponse('Origin not allowed for passkey operations', 400, cors);
  }

  // tarn#59 — this endpoint is public, so it is rate-limited to blunt bulk
  // probing and challenge-row write amplification. Per-IP, hourly, fails open.
  const { allowed } = await checkPasskeyAuthOptionsRateLimit(env, request);
  if (!allowed) {
    return errorResponse('Rate limit exceeded', 429, { ...cors, 'Retry-After': '3600' });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    body = {};
  }
  const credentialIdHint = typeof body?.credential_id === 'string' ? body.credential_id : null;

  // tarn#59 — ENUMERATION CLOSED. The PRF salt is now an app-wide CONSTANT
  // (see getConstantPrfSalt), so neither flow needs to read the
  // passkey_credentials table to build the PRF eval. We return the single
  // constant via `options.extensions.prf.eval.first` and NO per-credential
  // `evalByCredential` map.
  //
  // Two flows, two postures for `allowCredentials`:
  //
  //   credential_id supplied (account-identified re-tap, e.g. the SDK's
  //   re-wrap ceremony): steer the authenticator to exactly that one
  //   credential. We trust the caller-supplied ID directly — no DB read is
  //   needed because the salt is constant and a wrong/unknown ID simply means
  //   the authenticator finds nothing to assert with (it is re-verified at the
  //   /authenticate step regardless). Scoped — no other credential is touched.
  //
  //   no credential_id (usernameless / discoverable sign-in, what Bookish
  //   does): STANDARD discoverable flow — `allowCredentials` is left empty so
  //   the authenticator self-presents its resident credentials. NO table read,
  //   NO per-credential salt map, NO top-level dump → the enumeration that
  //   tarn#59 set out to remove is gone.
  const prfSalt = await getConstantPrfSalt();

  const challenge = generateChallengeBytes();

  const options = await generateAuthenticationOptions({
    rpID: rp.rpId,
    timeout: 60_000,
    // Discoverable flow → empty allow-list (authenticator self-presents its
    // resident credentials). Account-identified re-tap → steer to the one
    // credential the caller named (trusted directly; re-verified at
    // /authenticate). No credential-table SELECT in either path.
    allowCredentials: credentialIdHint
      ? [{ id: credentialIdHint }]
      : [],
    userVerification: 'preferred',
    challenge,
    extensions: {
      // tarn#59 — single constant PRF salt for the whole RP. Every Tarn
      // passkey was wrapped (at register) under PRF(constant), so the same
      // salt unwraps whichever resident credential the user selects. No
      // per-credential `evalByCredential` map → no enumeration.
      prf: {
        eval: { first: prfSalt },
      },
    },
  });

  // Persist the challenge with no account binding (we don't yet know who
  // is signing in until the credential is presented).
  const issuedAt = Date.now();
  const expiresAt = issuedAt + WEBAUTHN_CHALLENGE_TTL_SECONDS * 1000;
  await env.DB.prepare(
    'INSERT INTO webauthn_challenges (challenge, data_lookup_key, purpose, issued_at, expires_at, consumed_at) VALUES (?1, NULL, ?2, ?3, ?4, NULL)'
  ).bind(options.challenge, 'authenticate', issuedAt, expiresAt).run();

  // tarn#59 — the single constant salt rides in
  // `options.extensions.prf.eval.first`. No top-level dump, no per-credential
  // map.
  return jsonResponse({
    options,
    rp_id: rp.rpId,
  }, 200, cors);
}

// ============ POST /api/v1/auth/passkey/authenticate ============

export async function handlePasskeyAuthenticate(request, env, ctx, cors) {
  const rp = rpFromRequest(request);
  if (!rp) {
    return errorResponse('Origin not allowed for passkey operations', 400, cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { credential, previous_sid, device_label } = body || {};
  if (!credential || typeof credential !== 'object' || typeof credential.id !== 'string') {
    return errorResponse('credential is required', 400, cors);
  }
  const labelErr = validateDeviceLabel(device_label);
  if (labelErr) return errorResponse(labelErr, 400, cors);

  // Fetch the credential row.
  const credRow = await env.DB.prepare(
    'SELECT id, account_id, credential_id, public_key, sign_count FROM passkey_credentials WHERE credential_id = ?1'
  ).bind(credential.id).first();
  if (!credRow) {
    return errorResponse('Unknown credential', 401, cors);
  }

  // Find the bound account (need app + data_lookup_key).
  const account = await env.DB.prepare(
    'SELECT data_lookup_key, app, wrapped_data_key, wrapped_account_key, envelope_generation FROM accounts WHERE data_lookup_key = ?1'
  ).bind(credRow.account_id).first();
  if (!account) {
    return errorResponse('Account not found', 401, cors);
  }

  // Pull and consume the challenge.
  let clientDataChallenge;
  try {
    const cd = JSON.parse(
      new TextDecoder().decode(base64UrlToBytes(credential.response.clientDataJSON))
    );
    clientDataChallenge = cd.challenge;
  } catch {
    return errorResponse('credential.response.clientDataJSON is malformed', 400, cors);
  }
  const challengeRow = await env.DB.prepare(
    `UPDATE webauthn_challenges
        SET consumed_at = ?2
      WHERE challenge = ?1
        AND consumed_at IS NULL
        AND expires_at >= ?2
        AND purpose = 'authenticate'
      RETURNING challenge`
  ).bind(clientDataChallenge, Date.now()).first();
  if (!challengeRow) {
    return errorResponse('Invalid or expired authentication challenge', 401, cors);
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: clientDataChallenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.rpId,
      credential: {
        id: credRow.credential_id,
        publicKey: base64UrlToBytes(credRow.public_key),
        counter: credRow.sign_count,
      },
      requireUserVerification: false,
    });
  } catch (err) {
    return errorResponse(`Authentication verification failed: ${err.message || 'unknown'}`, 401, cors);
  }
  if (!verification.verified) {
    return errorResponse('Authentication verification rejected', 401, cors);
  }

  // Update sign_count + last_used_at. Some authenticators (especially
  // synced cross-device passkeys like iCloud Keychain) keep counter = 0
  // forever; we accept that and just record whatever the assertion claims.
  await env.DB.prepare(
    'UPDATE passkey_credentials SET sign_count = ?2, last_used_at = ?3 WHERE id = ?1'
  ).bind(credRow.id, verification.authenticationInfo.newCounter, Date.now()).run();

  // Phase 6.1 — stale-credential detection. A credential is "stale" when
  // its passkey_credentials row exists but no `passkey_prf` wrapping for
  // this credential_id is present at the LATEST gen of the envelope.
  // This typically happens when changeCredentials ran on another device
  // without re-tapping this passkey. Auth still succeeds (the JWT is
  // minted, older gens unwrap normally) but the client needs to repair
  // the wrap before it can decrypt anything written under the new gen.
  // The wire signal lets the SDK transparently surface a refresh path.
  let staleCredential = false;
  try {
    const env_ = JSON.parse(account.wrapped_data_key);
    staleCredential = isCredentialStale(env_, credRow.credential_id);
  } catch {
    // Envelope parse failure — treat as not stale; the SDK will hit a
    // different error code-path on its own unwrap attempt.
  }

  // Mint a session JWT — same shape as /auth/verify for user logins.
  // Include the credential_id used for this auth so the refresh-credential
  // endpoint can verify the caller is updating their own credential and
  // not arbitrarily overwriting someone else's wrapping.
  const jwtPayload = {
    sub: account.data_lookup_key,
    role: 'user',
    app: account.app,
    via_passkey: true,
    passkey_cred_id: credRow.credential_id,
  };
  const nowSeconds = Math.floor(Date.now() / 1000);
  await pruneStaleSessions(env, account.data_lookup_key, nowSeconds);
  const sid = await createOrReuseSession(env, {
    dlk: account.data_lookup_key,
    app: account.app,
    deviceLabel: device_label || null,
    viaRecovery: false,
    previousSid: previous_sid,
    nowSeconds,
  });
  jwtPayload.sid = sid;

  // Issue #28: Passkey-authenticated JWTs live for the full 7-day session-blob
  // lifetime. The SDK's `#ensureFreshJwt` has no refresh path for passkey-only
  // sessions (no `#signingKeyPair` to re-sign a challenge nonce), so a short
  // TTL would silently break the session well before the blob expires.
  const jwt = await signJWT(jwtPayload, env.JWT_SECRET, PASSKEY_JWT_TTL_SECONDS);
  writePasskeyAudit(ctx, env, request, account.data_lookup_key, 'passkey_authenticate');

  return jsonResponse({
    jwt,
    expiresIn: PASSKEY_JWT_TTL_SECONDS,
    data_lookup_key: account.data_lookup_key,
    wrapped_data_key: account.wrapped_data_key,
    // tarn#63 — the envelope's optimistic-concurrency token, so the
    // stale-credential refresh flow can send it as expected_generation.
    envelope_generation: account.envelope_generation,
    account_key_stored: account.wrapped_account_key != null,
    credential_id: credRow.credential_id,
    stale_credential: staleCredential,
  }, 200, cors);
}

// ============ GET /api/v1/account/passkeys ============

export async function handleListPasskeys(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') {
    return errorResponse('Only user accounts can list passkeys', 403, cors);
  }

  const rows = await env.DB.prepare(
    `SELECT credential_id, device_label, created_at, last_used_at
       FROM passkey_credentials
      WHERE account_id = ?1
      ORDER BY created_at ASC`
  ).bind(auth.data_lookup_key).all();

  // Phase 6.2 — surface per-credential stale state. Pull the live
  // envelope once, parse once, then mark each credential row as stale or
  // fresh by checking whether its (passkey_prf, credential_id) wrapping
  // exists at the latest gen. Apps surface this as a "Refresh
  // recommended" indicator so users can repair credentials proactively
  // (instead of discovering staleness only after bouncing off it at
  // login).
  const accountRow = await env.DB.prepare(
    'SELECT wrapped_data_key FROM accounts WHERE data_lookup_key = ?1'
  ).bind(auth.data_lookup_key).first();
  let envelopeObj = null;
  if (accountRow?.wrapped_data_key) {
    try {
      envelopeObj = JSON.parse(accountRow.wrapped_data_key);
    } catch {
      // Treat all credentials as not stale on parse failure — the SDK
      // will hit a more useful error path on its own unwrap attempt.
      envelopeObj = null;
    }
  }

  const passkeys = (rows.results || []).map(r => ({
    credential_id: r.credential_id,
    device_label: r.device_label,
    created_at: r.created_at,
    last_used_at: r.last_used_at,
    stale: envelopeObj ? isCredentialStale(envelopeObj, r.credential_id) : false,
  }));
  return jsonResponse({ passkeys }, 200, cors);
}

// ============ POST /api/v1/auth/passkey/refresh-credential ============
//
// Phase 6.1 — repair a stale passkey credential. "Stale" means the
// credential's row exists in passkey_credentials but the latest gen of
// the account's envelope has no `passkey_prf` wrapping for it (typically
// because changeCredentials ran on another device without a re-tap of
// this passkey). The client has just authenticated with the passkey,
// also obtained the password from the user, unwrapped the latest gen
// via the password, and re-wrapped it under the passkey PRF KEK; this
// endpoint stores the rebuilt envelope.
//
// Auth posture:
//   - JWT required, role=user.
//   - JWT MUST carry `via_passkey: true` AND `passkey_cred_id` matching
//     the credential being refreshed. This proves the caller actually
//     authenticated with the passkey they're now repairing — they cannot
//     use a password-side JWT to overwrite someone else's wrapping.
//   - The credential MUST belong to the authenticated account.
//   - Envelope shape is validated; other than the new wrapping the
//     server can't verify the contents (zero-knowledge), but it can
//     ensure the shape is well-formed.
//
// No step-up token is required: the passkey assertion that produced the
// JWT IS the proof of possession (it's the moral equivalent of the
// step-up password re-entry the DELETE path uses). The narrow scope
// (single credential, restricted to the same passkey that just signed
// in) means the blast radius of any compromise is identical to the
// session that just established.
export async function handlePasskeyRefreshCredential(request, env, ctx, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') {
    return errorResponse('Only user accounts can refresh passkey credentials', 403, cors);
  }
  if (!auth.via_passkey || !auth.passkey_cred_id) {
    return errorResponse(
      'refresh-credential requires a passkey-authenticated session',
      403,
      cors,
    );
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }
  const { credential_id, new_envelope, expected_generation } = body || {};
  if (typeof credential_id !== 'string' || credential_id.length === 0) {
    return errorResponse('credential_id is required', 400, cors);
  }
  if (credential_id !== auth.passkey_cred_id) {
    return errorResponse(
      'credential_id must match the passkey that established this session',
      403,
      cors,
    );
  }
  const envErr = validateEnvelopeShape(new_envelope);
  if (envErr) return errorResponse(`new_envelope: ${envErr}`, 400, cors);
  const gen = parseExpectedGeneration(expected_generation);
  if (!gen.ok) return errorResponse(gen.error, 400, cors);

  // Confirm the credential belongs to this account (defense in depth —
  // the JWT already proved it, but we re-check at the DB).
  const credRow = await env.DB.prepare(
    'SELECT id FROM passkey_credentials WHERE credential_id = ?1 AND account_id = ?2'
  ).bind(credential_id, auth.data_lookup_key).first();
  if (!credRow) {
    return errorResponse('Passkey not found', 404, cors);
  }

  // Sanity check: the new envelope MUST have a passkey_prf wrapping for
  // this credential at the latest gen. Otherwise we'd accept a write
  // that re-establishes the exact stale state we're trying to fix.
  try {
    const parsed = JSON.parse(new_envelope);
    const latest = parsed.dek_chain[parsed.dek_chain.length - 1];
    const hit = (latest?.wrappings || []).some(
      w => w?.factor === 'passkey_prf' && w?.credential_id === credential_id,
    );
    if (!hit) {
      return errorResponse(
        'new_envelope: latest gen must include a passkey_prf wrapping for this credential',
        400,
        cors,
      );
    }
  } catch {
    return errorResponse('new_envelope: parse failed during stale-state check', 400, cors);
  }

  // tarn#63 — read the current generation first so we can (a) disambiguate
  // "account not found" (404) from a CAS conflict (409), and (b) supply the
  // expected value for legacy callers that don't send one. A standalone
  // UPDATE here (no batch), so CAS-miss handling is straightforward: the
  // conditional WHERE matches 0 rows → .first() is null → we 409.
  const cur = await env.DB.prepare(
    'SELECT envelope_generation FROM accounts WHERE data_lookup_key = ?1'
  ).bind(auth.data_lookup_key).first();
  if (!cur) {
    return errorResponse('Account not found', 404, cors);
  }
  // Legacy client (no expected_generation): fall back to the current value so
  // the CAS always matches — preserves pre-tarn#63 last-write-wins for old
  // bundles only. New SDK always sends an explicit expected_generation.
  const expectedGen = gen.expected === null ? cur.envelope_generation : gen.expected;

  const updated = await env.DB.prepare(
    `UPDATE accounts
        SET wrapped_data_key = ?2,
            envelope_generation = envelope_generation + 1
      WHERE data_lookup_key = ?1
        AND envelope_generation = ?3
      RETURNING credential_lookup_key, public_key, wrapped_data_key, app,
                recovery_lookup_key, recovery_public_key,
                share_pub, share_discoverable, share_lookup_key,
                wrapped_account_key, data_lookup_key, envelope_generation`
  ).bind(auth.data_lookup_key, new_envelope, expectedGen).first();
  if (!updated) {
    // The row exists (we just read it) but the CAS matched 0 rows → another
    // device advanced the generation between this caller's fetch and write.
    // Tell the SDK to re-fetch and re-apply onto the fresh base.
    return jsonResponse(
      {
        error: 'envelope generation conflict — re-fetch and retry',
        code: 'ENVELOPE_GENERATION_CONFLICT',
        current_generation: cur.envelope_generation,
      },
      409,
      cors,
    );
  }

  writePasskeyAudit(ctx, env, request, auth.data_lookup_key, 'passkey_refresh_credential');
  persistCredentialBlobFromRowWithEnvelope(ctx, env, updated);

  return jsonResponse({
    refreshed: true,
    credential_id,
    envelope_generation: updated.envelope_generation,
  }, 200, cors);
}

// ============ DELETE /api/v1/account/passkeys/:credential_id ============

export async function handleDeletePasskey(request, env, ctx, credentialId, cors) {
  const auth = await requireAuth(request, env, ctx);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') {
    return errorResponse('Only user accounts can remove passkeys', 403, cors);
  }

  // Step-up gated: removing a passkey is a security-affecting operation,
  // same posture as the account-key toggle endpoints. Reuse the existing
  // ACCOUNT_KEY_FETCH scope rather than minting a new one — the check is
  // identical (proves the user just re-entered their password) and the
  // narrow scope set keeps the cognitive load low. We may split the scope
  // in a future phase if step-up posture diverges per operation.
  const stepUpToken = request.headers.get('X-Step-Up-Token');
  if (!stepUpToken) {
    return errorResponse('Step-up token required', 401, cors);
  }
  const consumed = await consumeStepUpToken(env, stepUpToken, STEP_UP_SCOPE_ACCOUNT_KEY_FETCH);
  if (!consumed) {
    return errorResponse('Invalid or expired step-up token', 401, cors);
  }
  if (consumed.data_lookup_key !== auth.data_lookup_key) {
    return errorResponse('Step-up token does not match session', 401, cors);
  }

  if (!credentialId || typeof credentialId !== 'string') {
    return errorResponse('credential_id required', 400, cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }
  const { new_envelope, expected_generation } = body || {};
  const envErr = validateEnvelopeShape(new_envelope);
  if (envErr) return errorResponse(`new_envelope: ${envErr}`, 400, cors);
  const gen = parseExpectedGeneration(expected_generation);
  if (!gen.ok) return errorResponse(gen.error, 400, cors);

  // Confirm the credential belongs to this account.
  const credRow = await env.DB.prepare(
    'SELECT id FROM passkey_credentials WHERE credential_id = ?1 AND account_id = ?2'
  ).bind(credentialId, auth.data_lookup_key).first();
  if (!credRow) {
    return errorResponse('Passkey not found', 404, cors);
  }

  // NOTE: Future-proofing — when password-removal becomes a thing, we
  // need to refuse deletion of the last remaining auth factor. Today
  // password is always present (every account registers with one), so
  // a passkey cannot be the only path in. Documented here so we don't
  // forget when the password-optional flow lands.

  // tarn#63 — same db.batch atomicity trap as register: a conditional UPDATE
  // that matches 0 rows does NOT throw, so it would NOT abort a batch — the
  // sibling DELETE would still commit. Run the envelope CAS STANDALONE FIRST;
  // only DELETE the credential row if the CAS landed.
  const cur = await env.DB.prepare(
    'SELECT envelope_generation FROM accounts WHERE data_lookup_key = ?1'
  ).bind(auth.data_lookup_key).first();
  if (!cur) {
    return errorResponse('Account not found', 404, cors);
  }
  const expectedGen = gen.expected === null ? cur.envelope_generation : gen.expected;

  // Step 1: conditional envelope CAS (standalone). On a CAS miss we 409 and
  // never DELETE the credential row.
  const updated = await env.DB.prepare(
    `UPDATE accounts
        SET wrapped_data_key = ?2,
            envelope_generation = envelope_generation + 1
      WHERE data_lookup_key = ?1
        AND envelope_generation = ?3
      RETURNING credential_lookup_key, public_key, wrapped_data_key, app,
                recovery_lookup_key, recovery_public_key,
                share_pub, share_discoverable, share_lookup_key,
                wrapped_account_key, data_lookup_key, envelope_generation`
  ).bind(auth.data_lookup_key, new_envelope, expectedGen).first();
  if (!updated) {
    return jsonResponse(
      {
        error: 'envelope generation conflict — re-fetch and retry',
        code: 'ENVELOPE_GENERATION_CONFLICT',
        current_generation: cur.envelope_generation,
      },
      409,
      cors,
    );
  }

  // Step 2: delete the credential row. The CAS already committed.
  //
  // Residual window (CAS committed, DELETE fails): the envelope no longer
  // carries this credential's passkey_prf wrapping, but its
  // passkey_credentials row survives. This is the SAFE-failing direction for a
  // REMOVE: the passkey can no longer unwrap the latest gen (its wrapping is
  // gone), so it is effectively defanged even though the row lingers. It
  // surfaces as the existing "stale credential" state and a retry of
  // removePasskey is idempotent (DELETE by id is a no-op the second time; the
  // already-built envelope simply omits the wrapping again).
  await env.DB.prepare('DELETE FROM passkey_credentials WHERE id = ?1').bind(credRow.id).run();

  writePasskeyAudit(ctx, env, request, auth.data_lookup_key, 'passkey_remove');
  persistCredentialBlobFromRowWithEnvelope(ctx, env, updated);

  // Phase B (Arweave-recoverability) — publish a tombstone for the
  // passkey-reg blob so a Phase-C rebuild excludes this credential. We
  // tombstone by `CredId`-tag rather than `tombstone_ref=<txid>` to
  // avoid threading the original txid through the schema; see the
  // `routes/passkey-reg.js` header for rationale.
  persistPasskeyRegTombstone(ctx, env, auth.data_lookup_key, credentialId);

  return jsonResponse({
    removed: true,
    credential_id: credentialId,
    envelope_generation: updated.envelope_generation,
  }, 200, cors);
}
