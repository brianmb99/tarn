// Auth route handlers: register, challenge, verify, credential change, account deletion
// Implements Tarn Protocol ECDSA P-256 challenge-response auth.

import { jsonResponse, errorResponse } from '../worker.js';
import { generateChallenge, storeNonce, consumeNonce, signJWT } from '../auth.js';
import { importPublicKey, verifySignature, isValidHex64 } from '../crypto.js';
import { requireAuth } from '../middleware/auth.js';
import { buildSignedDataItem, uploadSignedDataItem } from '../turbo.js';
import { upsertWriteThrough, markLookupBootstrapped } from '../cache.js';

import { PROTOCOL_VERSION } from '../constants.js';

// ============ HELPERS ============

function generateDataLookupKey() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function buildCredentialBlob(dataLookupKey, wrappedDataKey, publicKey, app, recoveryLookupKey, recoveryPublicKey) {
  // Optional recovery fields (issue #12) are written when present so that a
  // pure-Arweave rebuild can repopulate the new D1 columns. Pre-v4 (recovery-
  // less) blobs omit them; the rebuild path treats absent fields as NULL.
  const blob = { data_lookup_key: dataLookupKey, wrapped_data_key: wrappedDataKey, public_key: publicKey, app };
  if (recoveryLookupKey) blob.recovery_lookup_key = recoveryLookupKey;
  if (recoveryPublicKey) blob.recovery_public_key = recoveryPublicKey;
  return JSON.stringify(blob);
}

function buildCredentialTags(credentialLookupKey) {
  return [
    { name: 'App', value: 'tarn' },
    { name: 'Type', value: 'cred' },
    { name: 'Lk', value: credentialLookupKey },
    { name: 'V', value: PROTOCOL_VERSION },
  ];
}

/**
 * Persist a credential mapping blob to Arweave (non-blocking).
 * Returns immediately — upload runs in ctx.waitUntil.
 */
function persistCredentialBlob(ctx, env, credentialLookupKey, dataLookupKey, wrappedDataKey, publicKey, app, recoveryLookupKey, recoveryPublicKey) {
  const blobBody = buildCredentialBlob(dataLookupKey, wrappedDataKey, publicKey, app, recoveryLookupKey, recoveryPublicKey);
  const tags = buildCredentialTags(credentialLookupKey);

  ctx.waitUntil((async () => {
    try {
      const signingKey = env.APP_SIGNING_KEY;
      if (!signingKey) {
        console.warn('[tarn-api] APP_SIGNING_KEY not set — skipping Arweave upload');
        return;
      }
      const blobBytes = new TextEncoder().encode(blobBody);
      const { signedDataItem, txid } = await buildSignedDataItem(blobBytes, tags, signingKey);
      await upsertWriteThrough(env.DB, txid, tags);
      // Mark the credential lookup tuple as bootstrapped so post-register
      // lookups don't fall back to a redundant Arweave GraphQL query.
      // Tags on credential entries use App='tarn', Type='cred' (see buildCredentialTags).
      await markLookupBootstrapped(env.DB, credentialLookupKey, 'tarn', 'cred');
      console.log(`[tarn-api] Credential blob cached: ${txid}`);
      const turbo = await uploadSignedDataItem(signedDataItem);
      if (turbo.ok) {
        console.log(`[tarn-api] Credential blob uploaded to Turbo: ${txid}`);
      } else {
        console.warn(`[tarn-api] Credential blob Turbo upload failed: ${turbo.status} ${turbo.body}`);
      }
    } catch (err) {
      console.error('[tarn-api] Credential blob upload error:', err.message);
    }
  })());
}

// ============ POST /api/v1/auth/register ============

const MAX_REGISTRATIONS_PER_HOUR = 100;

async function checkRegistrationRateLimit(env, request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const data = new TextEncoder().encode(ip + '-tarn-register-salt');
  const hash = await crypto.subtle.digest('SHA-256', data);
  const ipHash = Array.from(new Uint8Array(hash)).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
  const hour = new Date().toISOString().slice(0, 13);
  const key = `register:${ipHash}:${hour}`;
  const count = parseInt(await env.RATE_KV.get(key) || '0');
  if (count >= MAX_REGISTRATIONS_PER_HOUR) {
    return { allowed: false };
  }
  await env.RATE_KV.put(key, String(count + 1), { expirationTtl: 3600 });
  return { allowed: true };
}

export async function handleRegister(request, env, ctx, cors) {
  // IP rate limit
  const { allowed } = await checkRegistrationRateLimit(env, request);
  if (!allowed) {
    return errorResponse('Registration rate limit exceeded', 429, cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { credential_lookup_key, public_key, wrapped_data_key, app, recovery_lookup_key, recovery_public_key } = body;

  // Validate app — must be a registered app
  if (!app || typeof app !== 'string') {
    return errorResponse('app is required', 400, cors);
  }
  const registeredApp = await env.DB.prepare(
    'SELECT 1 FROM apps WHERE app_id = ?1'
  ).bind(app).first();
  if (!registeredApp) {
    return errorResponse('Unregistered app: ' + app, 400, cors);
  }

  // Validate credential_lookup_key
  if (!isValidHex64(credential_lookup_key)) {
    return errorResponse('Invalid credential_lookup_key: must be 64-char lowercase hex', 400, cors);
  }

  // Validate public_key by attempting import
  try {
    await importPublicKey(public_key);
  } catch {
    return errorResponse('Invalid public_key: must be base64-encoded SPKI P-256 public key', 400, cors);
  }

  // Validate wrapped_data_key
  if (!wrapped_data_key || typeof wrapped_data_key !== 'string' || wrapped_data_key.length === 0) {
    return errorResponse('wrapped_data_key is required', 400, cors);
  }

  // Optional recovery factor (issue #12). Both must be present together (or
  // both absent — pre-v4 accounts). recovery_lookup_key is hex64 like the
  // credential lookup key; recovery_public_key is a base64 SPKI P-256.
  if ((recovery_lookup_key == null) !== (recovery_public_key == null)) {
    return errorResponse('recovery_lookup_key and recovery_public_key must be provided together', 400, cors);
  }
  if (recovery_lookup_key != null) {
    if (!isValidHex64(recovery_lookup_key)) {
      return errorResponse('Invalid recovery_lookup_key: must be 64-char lowercase hex', 400, cors);
    }
    if (recovery_lookup_key === credential_lookup_key) {
      return errorResponse('recovery_lookup_key must differ from credential_lookup_key', 400, cors);
    }
    try {
      await importPublicKey(recovery_public_key);
    } catch {
      return errorResponse('Invalid recovery_public_key: must be base64-encoded SPKI P-256 public key', 400, cors);
    }
  }

  // Idempotency: if an account already exists for this credential_lookup_key,
  // check whether this is a retry of a previous successful register (same payload)
  // or a real conflict (different credentials claiming the same lookup key).
  //
  // A retry sending identical bytes is expected when the client got a 503-after-commit:
  // the D1 INSERT succeeded but the response was lost (wall-time exceeded, edge drop,
  // etc). Without idempotency, the user is permanently stuck — the account exists
  // but every retry returns 409. See issue #6.
  const existing = await env.DB.prepare(
    'SELECT data_lookup_key, public_key, wrapped_data_key, app, recovery_lookup_key, recovery_public_key FROM accounts WHERE credential_lookup_key = ?1'
  ).bind(credential_lookup_key).first();
  if (existing) {
    const sameCreds =
      existing.public_key === public_key &&
      existing.wrapped_data_key === wrapped_data_key &&
      existing.app === app &&
      (existing.recovery_lookup_key ?? null) === (recovery_lookup_key ?? null) &&
      (existing.recovery_public_key ?? null) === (recovery_public_key ?? null);
    if (sameCreds) {
      // Same payload — treat as idempotent success. The client can proceed as if
      // the original register succeeded (which it did, at the D1 layer).
      // Return 201 (not 200) to match the status code of a fresh register. The
      // deployed client strictly checks `status === 201`; a 200 would look like
      // failure to it. Payload is identical.
      return jsonResponse({ data_lookup_key: existing.data_lookup_key }, 201, cors);
    }
    return errorResponse('credential_lookup_key already in use with different credentials', 409, cors);
  }

  // Reject up-front if the supplied recovery_lookup_key is already taken by a
  // DIFFERENT account. This avoids the more expensive UNIQUE-failure path
  // below for the common case of an honest collision detection.
  if (recovery_lookup_key) {
    const recoveryConflict = await env.DB.prepare(
      'SELECT 1 FROM accounts WHERE recovery_lookup_key = ?1'
    ).bind(recovery_lookup_key).first();
    if (recoveryConflict) {
      return errorResponse('recovery_lookup_key already in use', 409, cors);
    }
  }

  // Generate unique data_lookup_key
  let data_lookup_key;
  for (let attempt = 0; attempt < 5; attempt++) {
    const candidate = generateDataLookupKey();
    const dlkExists = await env.DB.prepare(
      'SELECT 1 FROM accounts WHERE data_lookup_key = ?1'
    ).bind(candidate).first();
    if (!dlkExists) {
      data_lookup_key = candidate;
      break;
    }
  }
  if (!data_lookup_key) {
    return errorResponse('Failed to generate unique data_lookup_key', 500, cors);
  }

  // Insert account (rules_json NULL = DENY until app sets rules).
  // If a concurrent retry raced us between the uniqueness check and the INSERT,
  // the UNIQUE constraint will fire. Catch it and re-run the idempotency check
  // so concurrent retries also converge to the same success response.
  try {
    await env.DB.prepare(
      'INSERT INTO accounts (credential_lookup_key, public_key, data_lookup_key, wrapped_data_key, app, rules_json, created_at, recovery_lookup_key, recovery_public_key) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8)'
    ).bind(credential_lookup_key, public_key, data_lookup_key, wrapped_data_key, app, Date.now(), recovery_lookup_key ?? null, recovery_public_key ?? null).run();
  } catch (err) {
    // UNIQUE constraint on credential_lookup_key OR recovery_lookup_key —
    // concurrent retry won the race (or recovery key collision).
    if (/UNIQUE/i.test(err.message || '')) {
      const raced = await env.DB.prepare(
        'SELECT data_lookup_key, public_key, wrapped_data_key, app, recovery_lookup_key, recovery_public_key FROM accounts WHERE credential_lookup_key = ?1'
      ).bind(credential_lookup_key).first();
      if (raced &&
          raced.public_key === public_key &&
          raced.wrapped_data_key === wrapped_data_key &&
          raced.app === app &&
          (raced.recovery_lookup_key ?? null) === (recovery_lookup_key ?? null) &&
          (raced.recovery_public_key ?? null) === (recovery_public_key ?? null)) {
        return jsonResponse({ data_lookup_key: raced.data_lookup_key }, 201, cors);
      }
      // Distinguish the two unique-constraint paths so the client gets a
      // useful error message.
      if (recovery_lookup_key) {
        const recoveryRow = await env.DB.prepare(
          'SELECT 1 FROM accounts WHERE recovery_lookup_key = ?1'
        ).bind(recovery_lookup_key).first();
        if (recoveryRow) {
          return errorResponse('recovery_lookup_key already in use', 409, cors);
        }
      }
      return errorResponse('credential_lookup_key already in use with different credentials', 409, cors);
    }
    throw err;
  }

  // Persist credential mapping to Arweave (non-blocking)
  persistCredentialBlob(ctx, env, credential_lookup_key, data_lookup_key, wrapped_data_key, public_key, app, recovery_lookup_key, recovery_public_key);

  return jsonResponse({ data_lookup_key }, 201, cors);
}

// ============ POST /api/v1/auth/challenge ============

export async function handleChallenge(request, env, cors) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { credential_lookup_key, recovery_lookup_key } = body;

  // Recovery-flow challenge (issue #12): the body carries recovery_lookup_key
  // instead of credential_lookup_key. Find the account by its recovery column,
  // return the same shape (nonce + data_lookup_key + wrapped_data_key) so the
  // client can derive the recovery KEK from the envelope salt and unwrap the
  // DEK chain. The nonce is scoped to recovery_lookup_key so verify uses the
  // recovery_public_key for signature verification.
  if (recovery_lookup_key && !credential_lookup_key) {
    if (typeof recovery_lookup_key !== 'string' || !/^[a-f0-9]{64}$/.test(recovery_lookup_key)) {
      return errorResponse('Invalid recovery_lookup_key', 400, cors);
    }
    const recoveryAccount = await env.DB.prepare(
      'SELECT data_lookup_key, wrapped_data_key FROM accounts WHERE recovery_lookup_key = ?1'
    ).bind(recovery_lookup_key).first();
    if (!recoveryAccount) {
      return errorResponse('Unknown recovery_lookup_key', 404, cors);
    }
    const nonce = generateChallenge();
    await storeNonce(env, nonce, recovery_lookup_key);
    return jsonResponse({
      nonce,
      data_lookup_key: recoveryAccount.data_lookup_key,
      wrapped_data_key: recoveryAccount.wrapped_data_key,
    }, 200, cors);
  }

  if (!credential_lookup_key || typeof credential_lookup_key !== 'string') {
    return errorResponse('credential_lookup_key is required', 400, cors);
  }

  // Look up in accounts table first
  const account = await env.DB.prepare(
    'SELECT data_lookup_key, wrapped_data_key FROM accounts WHERE credential_lookup_key = ?1'
  ).bind(credential_lookup_key).first();

  if (account) {
    const nonce = generateChallenge();
    await storeNonce(env, nonce, credential_lookup_key);
    return jsonResponse({
      nonce,
      data_lookup_key: account.data_lookup_key,
      wrapped_data_key: account.wrapped_data_key,
    }, 200, cors);
  }

  // Fall back to apps table
  const app = await env.DB.prepare(
    'SELECT app_id FROM apps WHERE app_id = ?1'
  ).bind(credential_lookup_key).first();

  if (app) {
    const nonce = generateChallenge();
    await storeNonce(env, nonce, credential_lookup_key);
    return jsonResponse({ nonce }, 200, cors);
  }

  return errorResponse('Unknown credential_lookup_key', 404, cors);
}

// ============ POST /api/v1/auth/verify ============

export async function handleVerify(request, env, cors) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { credential_lookup_key, recovery_lookup_key, nonce, signature } = body;
  const lookupKey = credential_lookup_key || recovery_lookup_key;
  if (!lookupKey || !nonce || !signature) {
    return errorResponse('lookup_key, nonce, and signature are required', 400, cors);
  }

  // Consume nonce (single-use)
  const nonceData = await consumeNonce(env, nonce);
  if (!nonceData) {
    return errorResponse('Invalid or expired nonce', 401, cors);
  }

  // Verify nonce was issued for this lookup key (the challenge handler stores
  // the same lookup key the client sent — credential or recovery).
  if (nonceData.credentialLookupKey !== lookupKey) {
    return errorResponse('Nonce credential mismatch', 401, cors);
  }

  // Look up public key. Recovery-flow auth uses recovery_public_key and emits
  // a JWT carrying via_recovery: true so downstream credential-change knows to
  // skip the password-side authorization checks.
  let publicKeyBase64;
  let jwtPayload;

  if (recovery_lookup_key) {
    const recoveryAccount = await env.DB.prepare(
      'SELECT data_lookup_key, recovery_public_key, app FROM accounts WHERE recovery_lookup_key = ?1'
    ).bind(recovery_lookup_key).first();
    if (recoveryAccount && recoveryAccount.recovery_public_key) {
      publicKeyBase64 = recoveryAccount.recovery_public_key;
      jwtPayload = {
        sub: recoveryAccount.data_lookup_key,
        role: 'user',
        app: recoveryAccount.app,
        via_recovery: true,
      };
    }
  } else {
    const account = await env.DB.prepare(
      'SELECT data_lookup_key, public_key, app FROM accounts WHERE credential_lookup_key = ?1'
    ).bind(credential_lookup_key).first();

    if (account) {
      publicKeyBase64 = account.public_key;
      jwtPayload = { sub: account.data_lookup_key, role: 'user', app: account.app };
    } else {
      const app = await env.DB.prepare(
        'SELECT app_id, public_key FROM apps WHERE app_id = ?1'
      ).bind(credential_lookup_key).first();

      if (app) {
        publicKeyBase64 = app.public_key;
        jwtPayload = { sub: app.app_id, role: 'app' };
      }
    }
  }

  if (!publicKeyBase64) {
    return errorResponse('Account not found', 401, cors);
  }

  // Import public key and verify signature
  let publicKey;
  try {
    publicKey = await importPublicKey(publicKeyBase64);
  } catch {
    return errorResponse('Stored public key is invalid', 500, cors);
  }

  const valid = await verifySignature(publicKey, nonce, signature);
  if (!valid) {
    return errorResponse('Invalid signature', 401, cors);
  }

  // Issue JWT
  const jwt = await signJWT(jwtPayload, env.JWT_SECRET);
  return jsonResponse({ jwt, expiresIn: 900 }, 200, cors);
}

// ============ PUT /api/v1/auth — Credential Change ============

export async function handleCredentialChange(request, env, ctx, cors) {
  const auth = await requireAuth(request, env);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') return errorResponse('Only user accounts can change credentials', 403, cors);

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const {
    new_credential_lookup_key,
    new_public_key,
    new_wrapped_data_key,
    new_recovery_lookup_key,
    new_recovery_public_key,
  } = body;

  // Validate new credential_lookup_key
  if (!isValidHex64(new_credential_lookup_key)) {
    return errorResponse('Invalid new_credential_lookup_key: must be 64-char lowercase hex', 400, cors);
  }

  // Validate new public_key
  try {
    await importPublicKey(new_public_key);
  } catch {
    return errorResponse('Invalid new_public_key: must be base64-encoded SPKI P-256 public key', 400, cors);
  }

  // Validate new wrapped_data_key
  if (!new_wrapped_data_key || typeof new_wrapped_data_key !== 'string' || new_wrapped_data_key.length === 0) {
    return errorResponse('new_wrapped_data_key is required', 400, cors);
  }

  // Optional new recovery factor (issue #12). If supplied, must be both fields
  // together; recovery_lookup_key must be unique across the table (excluding
  // the row we're about to update).
  if ((new_recovery_lookup_key == null) !== (new_recovery_public_key == null)) {
    return errorResponse('new_recovery_lookup_key and new_recovery_public_key must be provided together', 400, cors);
  }
  if (new_recovery_lookup_key != null) {
    if (!isValidHex64(new_recovery_lookup_key)) {
      return errorResponse('Invalid new_recovery_lookup_key: must be 64-char lowercase hex', 400, cors);
    }
    if (new_recovery_lookup_key === new_credential_lookup_key) {
      return errorResponse('new_recovery_lookup_key must differ from new_credential_lookup_key', 400, cors);
    }
    try {
      await importPublicKey(new_recovery_public_key);
    } catch {
      return errorResponse('Invalid new_recovery_public_key: must be base64-encoded SPKI P-256 public key', 400, cors);
    }
  }

  // Check new_credential_lookup_key not already in use
  const conflict = await env.DB.prepare(
    'SELECT 1 FROM accounts WHERE credential_lookup_key = ?1'
  ).bind(new_credential_lookup_key).first();
  if (conflict) {
    return errorResponse('new_credential_lookup_key already in use', 409, cors);
  }

  // Read current account (need rules_json, app, and existing recovery fields
  // to preserve them when the caller doesn't supply replacements).
  const current = await env.DB.prepare(
    'SELECT credential_lookup_key, rules_json, app, recovery_lookup_key, recovery_public_key FROM accounts WHERE data_lookup_key = ?1'
  ).bind(auth.data_lookup_key).first();
  if (!current) {
    return errorResponse('Account not found', 404, cors);
  }

  // Recovery factor: caller-supplied values win; otherwise preserve existing.
  const finalRecoveryLookupKey = new_recovery_lookup_key ?? current.recovery_lookup_key ?? null;
  const finalRecoveryPublicKey = new_recovery_public_key ?? current.recovery_public_key ?? null;

  // If the caller supplied a new recovery_lookup_key that differs from the
  // existing one, check uniqueness.
  if (
    new_recovery_lookup_key != null &&
    new_recovery_lookup_key !== current.recovery_lookup_key
  ) {
    const recoveryConflict = await env.DB.prepare(
      'SELECT 1 FROM accounts WHERE recovery_lookup_key = ?1'
    ).bind(new_recovery_lookup_key).first();
    if (recoveryConflict) {
      return errorResponse('new_recovery_lookup_key already in use', 409, cors);
    }
  }

  // PK change: delete old row + insert new (SQLite doesn't support UPDATE of PK).
  // NOTE: There is a small race window here. A concurrent handleChallenge using the old
  // credential_lookup_key could receive a nonce, but by the time handleVerify runs, the
  // row is gone and the user gets a 401. This is acceptable — the user simply re-logs in
  // with the new credentials. The probability is very low (requires two devices changing
  // credentials and logging in within the same D1 batch window).
  await env.DB.batch([
    env.DB.prepare('DELETE FROM accounts WHERE credential_lookup_key = ?1').bind(current.credential_lookup_key),
    env.DB.prepare(
      'INSERT INTO accounts (credential_lookup_key, public_key, data_lookup_key, wrapped_data_key, app, rules_json, created_at, recovery_lookup_key, recovery_public_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)'
    ).bind(
      new_credential_lookup_key,
      new_public_key,
      auth.data_lookup_key,
      new_wrapped_data_key,
      current.app,
      current.rules_json,
      Date.now(),
      finalRecoveryLookupKey,
      finalRecoveryPublicKey,
    ),
  ]);

  // Persist new credential mapping to Arweave (non-blocking)
  persistCredentialBlob(
    ctx, env,
    new_credential_lookup_key, auth.data_lookup_key, new_wrapped_data_key, new_public_key, current.app,
    finalRecoveryLookupKey, finalRecoveryPublicKey,
  );

  return jsonResponse({ ok: true }, 200, cors);
}

// ============ DELETE /api/v1/auth — Account Deletion ============

export async function handleDeleteAccount(request, env, ctx, cors) {
  const auth = await requireAuth(request, env);
  if (!auth) return errorResponse('Unauthorized', 401, cors);
  if (auth.role !== 'user') return errorResponse('Only user accounts can be deleted', 403, cors);

  // Find current account
  const account = await env.DB.prepare(
    'SELECT credential_lookup_key FROM accounts WHERE data_lookup_key = ?1'
  ).bind(auth.data_lookup_key).first();
  if (!account) {
    return errorResponse('Account not found', 404, cors);
  }

  // Find the credential mapping txid to tombstone
  const credEntry = await env.DB.prepare(
    "SELECT txid FROM entries WHERE lookup_key = ?1 AND type = 'cred' AND is_tombstone = 0 ORDER BY cached_at DESC LIMIT 1"
  ).bind(account.credential_lookup_key).first();

  // Delete account from D1
  await env.DB.prepare('DELETE FROM accounts WHERE data_lookup_key = ?1').bind(auth.data_lookup_key).run();

  // Write tombstone to Arweave (non-blocking)
  if (credEntry?.txid) {
    const tombstoneTags = [
      { name: 'App', value: 'tarn' },
      { name: 'Type', value: 'cred' },
      { name: 'Op', value: 'tombstone' },
      { name: 'Ref', value: credEntry.txid },
      { name: 'Lk', value: account.credential_lookup_key },
      { name: 'V', value: PROTOCOL_VERSION },
    ];

    ctx.waitUntil((async () => {
      try {
        const signingKey = env.APP_SIGNING_KEY;
        if (!signingKey) {
          console.warn('[tarn-api] APP_SIGNING_KEY not set — skipping tombstone upload');
          return;
        }
        const tombstoneBody = new TextEncoder().encode(JSON.stringify({ tombstone: true }));
        const { signedDataItem, txid } = await buildSignedDataItem(tombstoneBody, tombstoneTags, signingKey);
        await upsertWriteThrough(env.DB, txid, tombstoneTags);
        console.log(`[tarn-api] Account tombstone cached: ${txid}`);
        const turbo = await uploadSignedDataItem(signedDataItem);
        if (turbo.ok) {
          console.log(`[tarn-api] Account tombstone uploaded to Turbo: ${txid}`);
        }
      } catch (err) {
        console.error('[tarn-api] Account tombstone upload error:', err.message);
      }
    })());
  }

  return jsonResponse({ ok: true, deleted: true }, 200, cors);
}
