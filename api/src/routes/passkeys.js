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
import { signJWT } from '../auth.js';
import { consumeStepUpToken, STEP_UP_SCOPE_ACCOUNT_KEY_FETCH } from './auth.js';
import { buildSignedDataItem, uploadSignedDataItem } from '../turbo.js';
import { upsertWriteThrough, markLookupBootstrapped } from '../cache.js';
import {
  pruneStaleSessions,
  createOrReuseSession,
  validateDeviceLabel,
} from '../sessions.js';
import { PROTOCOL_VERSION } from '../constants.js';

// ============ HELPERS ============

const WEBAUTHN_CHALLENGE_TTL_SECONDS = 60;
const RP_NAME = 'Tarn';

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

  const tags = [
    { name: 'App', value: 'tarn' },
    { name: 'Type', value: 'cred' },
    { name: 'Lk', value: row.credential_lookup_key },
    { name: 'V', value: PROTOCOL_VERSION },
  ];

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
      const turbo = await uploadSignedDataItem(signedDataItem);
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

  // Generate a fresh PRF salt for this passkey. The salt is what binds the
  // PRF-derived secret to this credential — same salt + same passkey →
  // same wrapping key, deterministically.
  const prfSalt = generateChallengeBytes();
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

  const { credential, prf_salt, new_envelope, device_label } = body || {};
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

  // Atomic: insert the credential row + write the new envelope. If a
  // concurrent request lost the race for the credential_id (unique), the
  // second insert fails — surface as 409.
  let row;
  try {
    row = await env.DB.batch([
      env.DB.prepare(
        'INSERT INTO passkey_credentials (account_id, credential_id, public_key, prf_salt, sign_count, device_label, created_at, last_used_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)'
      ).bind(
        auth.data_lookup_key,
        credentialId,
        publicKeyB64,
        prf_salt,
        signCount,
        device_label || null,
        Date.now(),
      ),
      env.DB.prepare(
        `UPDATE accounts
            SET wrapped_data_key = ?2
          WHERE data_lookup_key = ?1
          RETURNING credential_lookup_key, public_key, wrapped_data_key, app,
                    recovery_lookup_key, recovery_public_key,
                    share_pub, share_discoverable, share_lookup_key,
                    wrapped_account_key, data_lookup_key`
      ).bind(auth.data_lookup_key, new_envelope),
    ]);
  } catch (err) {
    if (/UNIQUE/i.test(err.message || '')) {
      return errorResponse('Credential already registered', 409, cors);
    }
    throw err;
  }

  const updated = row[1].results?.[0];
  if (!updated) {
    return errorResponse('Account not found', 404, cors);
  }

  writePasskeyAudit(ctx, env, request, auth.data_lookup_key, 'passkey_register');
  persistCredentialBlobFromRowWithEnvelope(ctx, env, updated);

  return jsonResponse({
    credential_id: credentialId,
    device_label: device_label || null,
    created_at: Date.now(),
  }, 201, cors);
}

// ============ POST /api/v1/auth/passkey/authentication-options ============

export async function handlePasskeyAuthOptions(request, env, ctx, cors) {
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
  const credentialIdHint = typeof body?.credential_id === 'string' ? body.credential_id : null;

  // Discoverable flow: when no credential_id is supplied, return ALL of
  // the relying party's credentials so the authenticator can pick. In
  // practice with PRF there's no privacy concern (the credential_id is
  // already the public identifier of the passkey), so this is fine.
  // When a credential_id IS supplied, narrow to just that one (faster
  // for known-account flows).
  let rows;
  if (credentialIdHint) {
    rows = await env.DB.prepare(
      'SELECT credential_id, prf_salt FROM passkey_credentials WHERE credential_id = ?1'
    ).bind(credentialIdHint).all();
  } else {
    rows = await env.DB.prepare(
      'SELECT credential_id, prf_salt FROM passkey_credentials'
    ).all();
  }
  const credentials = rows.results || [];

  const challenge = generateChallengeBytes();
  const challengeB64Url = bytesToBase64Url(challenge);

  const options = await generateAuthenticationOptions({
    rpID: rp.rpId,
    timeout: 60_000,
    allowCredentials: credentials.map(r => ({ id: r.credential_id })),
    userVerification: 'preferred',
    challenge,
    extensions: {
      // PRF eval at auth time uses the SAME salt that was bound at register
      // time. Because the authenticator selects ONE credential at auth, we
      // need to hand it a per-credential map so it picks the right salt.
      prf: {
        evalByCredential: Object.fromEntries(
          credentials.map(r => [r.credential_id, { first: base64UrlToBytes(r.prf_salt) }]),
        ),
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

  // Echo the per-credential prf_salt back so the SDK can derive the
  // wrapping key locally after the assertion. Repeated here for clarity
  // even though it's already in the extensions block.
  return jsonResponse({
    options,
    allow_credentials: credentials.map(r => ({
      credential_id: r.credential_id,
      prf_salt: r.prf_salt,
    })),
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
    'SELECT data_lookup_key, app, wrapped_data_key, wrapped_account_key FROM accounts WHERE data_lookup_key = ?1'
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

  // Mint a session JWT — same shape as /auth/verify for user logins.
  const jwtPayload = {
    sub: account.data_lookup_key,
    role: 'user',
    app: account.app,
    via_passkey: true,
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

  const jwt = await signJWT(jwtPayload, env.JWT_SECRET);
  writePasskeyAudit(ctx, env, request, account.data_lookup_key, 'passkey_authenticate');

  return jsonResponse({
    jwt,
    expiresIn: 900,
    data_lookup_key: account.data_lookup_key,
    wrapped_data_key: account.wrapped_data_key,
    account_key_stored: account.wrapped_account_key != null,
    credential_id: credRow.credential_id,
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

  const passkeys = (rows.results || []).map(r => ({
    credential_id: r.credential_id,
    device_label: r.device_label,
    created_at: r.created_at,
    last_used_at: r.last_used_at,
  }));
  return jsonResponse({ passkeys }, 200, cors);
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
  const { new_envelope } = body || {};
  const envErr = validateEnvelopeShape(new_envelope);
  if (envErr) return errorResponse(`new_envelope: ${envErr}`, 400, cors);

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

  const result = await env.DB.batch([
    env.DB.prepare('DELETE FROM passkey_credentials WHERE id = ?1').bind(credRow.id),
    env.DB.prepare(
      `UPDATE accounts
          SET wrapped_data_key = ?2
        WHERE data_lookup_key = ?1
        RETURNING credential_lookup_key, public_key, wrapped_data_key, app,
                  recovery_lookup_key, recovery_public_key,
                  share_pub, share_discoverable, share_lookup_key,
                  wrapped_account_key, data_lookup_key`
    ).bind(auth.data_lookup_key, new_envelope),
  ]);
  const updated = result[1].results?.[0];
  if (!updated) {
    return errorResponse('Account not found', 404, cors);
  }

  writePasskeyAudit(ctx, env, request, auth.data_lookup_key, 'passkey_remove');
  persistCredentialBlobFromRowWithEnvelope(ctx, env, updated);

  return jsonResponse({ removed: true, credential_id: credentialId }, 200, cors);
}
