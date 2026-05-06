// Tarn API — Encrypted data platform cache and write layer
// Identity: ECDSA P-256 challenge-response auth. Data: AES-256-GCM encrypted blobs on Arweave.

import { handleHealth } from './routes/info.js';
import { handleEntries, handleEntryById } from './routes/entries.js';
import { handleLookup } from './routes/lookup.js';
import { handleShareLookup } from './routes/share.js';
import { handleShareInboxPublish, handleShareInboxFetch } from './routes/share-inbox.js';
import { handleShareLogPublish, handleShareLogFetch } from './routes/share-log.js';
import {
  handleRegister,
  handleChallenge,
  handleVerify,
  handleCredentialChange,
  handleDeleteAccount,
  handleStepUp,
} from './routes/auth.js';
import {
  handleGetAccountKey,
  handlePutAccountKey,
  handleDeleteAccountKey,
  handleRotateAccountKey,
} from './routes/account.js';
import {
  handlePasskeyRegisterOptions,
  handlePasskeyRegister,
  handlePasskeyAuthOptions,
  handlePasskeyAuthenticate,
  handleListPasskeys,
  handleDeletePasskey,
} from './routes/passkeys.js';
import { handleCreateEntry, handleBatchCreate, handleEditEntry, handleDeleteEntry } from './routes/write.js';
import { handleSyncStatus, handleSyncAck } from './routes/sync.js';
import { handleSetRules, handleSetInviteTemplate, handleSetSchema } from './routes/apps.js';
import { handleStatus } from './routes/status.js';
import { handleListSessions, handleRevokeSession, handleRevokeAllSessions } from './routes/sessions.js';
import {
  handleCreateInvite,
  handleGetInvite,
  handleRedeemInvite,
  handleRevokeInvite,
  handleGetAppInviteTemplate,
} from './routes/invites.js';
import { setSkipTurboFromEnv } from './turbo.js';

// ============ CORS ============

const ALLOWED_ORIGINS = [
  'https://getbookish.app',
  'https://dev.getbookish.app',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'https://tarn.dev',
];

function getCorsHeaders(request) {
  const origin = request.headers.get('Origin');
  if (!origin || !ALLOWED_ORIGINS.includes(origin)) return {};
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Arweave-Tags, X-Idempotency-Key, X-Step-Up-Token',
  };
}

// ============ RESPONSE HELPERS ============

export function jsonResponse(data, status = 200, cors = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors },
  });
}

export function errorResponse(message, status, cors = {}) {
  return jsonResponse({ error: message }, status, cors);
}

// ============ ROUTER ============

export default {
  async fetch(request, env, ctx) {
    const cors = getCorsHeaders(request);

    // Wire the local-dev TARN_SKIP_TURBO flag (see turbo.js) into the
    // Worker-scoped global. Cheap idempotent assignment per request.
    // Pass `request` so the function can refuse the flag on production hosts
    // (defense-in-depth against accidental `wrangler secret put` in prod).
    setSkipTurboFromEnv(env, request);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      // Auth — registration and login
      if (path === '/api/v1/auth/register' && method === 'POST') {
        return await handleRegister(request, env, ctx, cors);
      }
      if (path === '/api/v1/auth/challenge' && method === 'POST') {
        return await handleChallenge(request, env, cors);
      }
      if (path === '/api/v1/auth/verify' && method === 'POST') {
        return await handleVerify(request, env, cors);
      }
      if (path === '/api/v1/auth/step-up' && method === 'POST') {
        return await handleStepUp(request, env, cors);
      }

      // Account-key Model B retrieval (Phase 3, RECOVERY_PLAN.md). Requires
      // both a session JWT (Authorization: Bearer …) and a single-use
      // step-up token (X-Step-Up-Token header).
      if (path === '/api/v1/account/account-key' && method === 'GET') {
        return await handleGetAccountKey(request, env, ctx, cors);
      }
      // Phase 4: toggle Model A ↔ Model B. Same auth posture as fetch
      // (JWT + X-Step-Up-Token) for both PUT and DELETE.
      if (path === '/api/v1/account/account-key' && method === 'PUT') {
        return await handlePutAccountKey(request, env, ctx, cors);
      }
      if (path === '/api/v1/account/account-key' && method === 'DELETE') {
        return await handleDeleteAccountKey(request, env, ctx, cors);
      }
      // Phase 4: rotate the account key. JWT only — the friction is on
      // the client side (user must have generated and confirmed a new
      // phrase before this is reachable).
      if (path === '/api/v1/account/rotate-account-key' && method === 'POST') {
        return await handleRotateAccountKey(request, env, ctx, cors);
      }

      // Phase 6: WebAuthn passkey factor (RECOVERY_PLAN.md §6).
      // Registration is JWT-authed (logged-in users add a passkey to
      // their account); authentication is public (the assertion proves
      // possession without a prior session).
      if (path === '/api/v1/auth/passkey/register-options' && method === 'POST') {
        return await handlePasskeyRegisterOptions(request, env, ctx, cors);
      }
      if (path === '/api/v1/auth/passkey/register' && method === 'POST') {
        return await handlePasskeyRegister(request, env, ctx, cors);
      }
      if (path === '/api/v1/auth/passkey/authentication-options' && method === 'POST') {
        return await handlePasskeyAuthOptions(request, env, ctx, cors);
      }
      if (path === '/api/v1/auth/passkey/authenticate' && method === 'POST') {
        return await handlePasskeyAuthenticate(request, env, ctx, cors);
      }
      if (path === '/api/v1/account/passkeys' && method === 'GET') {
        return await handleListPasskeys(request, env, ctx, cors);
      }
      if (path.startsWith('/api/v1/account/passkeys/') && method === 'DELETE') {
        const credentialId = decodeURIComponent(path.slice('/api/v1/account/passkeys/'.length));
        if (credentialId && !credentialId.includes('/')) {
          return await handleDeletePasskey(request, env, ctx, credentialId, cors);
        }
      }

      // Auth — credential management (authenticated)
      if (path === '/api/v1/auth' && method === 'PUT') {
        return await handleCredentialChange(request, env, ctx, cors);
      }
      if (path === '/api/v1/auth' && method === 'DELETE') {
        return await handleDeleteAccount(request, env, ctx, cors);
      }

      // Info (public)
      if (path === '/api/v1/health' && method === 'GET') {
        return await handleHealth(env, cors);
      }

      // Entries — reads (public, IP rate-limited)
      if (path === '/api/v1/entries' && method === 'GET') {
        return await handleEntries(url, env, ctx, cors, request);
      }
      if (path.startsWith('/api/v1/entries/') && method === 'GET') {
        const txid = path.slice('/api/v1/entries/'.length);
        if (txid && !txid.includes('/')) {
          return await handleEntryById(txid, url, env, ctx, cors, request);
        }
      }

      // Entries — writes (authenticated)
      if (path === '/api/v1/entries' && method === 'POST') {
        return await handleCreateEntry(request, env, ctx, cors);
      }
      if (path === '/api/v1/entries/batch' && method === 'POST') {
        return await handleBatchCreate(request, env, ctx, cors);
      }
      if (path.startsWith('/api/v1/entries/') && method === 'PUT') {
        const txid = path.slice('/api/v1/entries/'.length);
        if (txid && !txid.includes('/')) {
          return await handleEditEntry(txid, request, env, ctx, cors);
        }
      }
      if (path.startsWith('/api/v1/entries/') && method === 'DELETE') {
        const txid = path.slice('/api/v1/entries/'.length);
        if (txid && !txid.includes('/')) {
          return await handleDeleteEntry(txid, request, env, ctx, cors);
        }
      }

      // Sync
      if (path === '/api/v1/sync/status' && method === 'GET') {
        return await handleSyncStatus(url, env, cors, request);
      }
      if (path === '/api/v1/sync/ack' && method === 'POST') {
        return await handleSyncAck(request, env, ctx, cors);
      }

      // Lookup (credentials, account metadata)
      if (path === '/api/v1/lookup' && method === 'GET') {
        return await handleLookup(url, request, env, ctx, cors);
      }

      // Share keypair lookup (issue #13) — returns share_pub by username-only key
      if (path === '/api/v1/share/lookup' && method === 'GET') {
        return await handleShareLookup(url, request, env, cors);
      }

      // Connection-handshake inbox (issue #14, Section 5a; renamed in Section 6
      // / issue #18) — HPKE-sealed connection_request + connection_accept blobs,
      // addressed by inbox tag.
      if (path === '/api/v1/share/inbox/publish' && method === 'POST') {
        return await handleShareInboxPublish(request, env, ctx, cors);
      }
      if (path === '/api/v1/share/inbox/fetch' && method === 'GET') {
        return await handleShareInboxFetch(url, request, env, cors);
      }

      // Per-pair share log (issue #15, Section 5b) — stealth-addressed
      // encrypted entries with per-tag uniqueness on publish.
      if (path === '/api/v1/share/log/publish' && method === 'POST') {
        return await handleShareLogPublish(request, env, ctx, cors);
      }
      if (path === '/api/v1/share/log/fetch' && method === 'GET') {
        return await handleShareLogFetch(url, request, env, cors);
      }

      // Sessions (Section 7.5, issue #20) — user-role only.
      // Bare `/api/v1/sessions` MUST be matched before the `/sessions/`
      // parameterized DELETE so DELETE /api/v1/sessions doesn't get captured
      // as a sid revoke with empty sid.
      if (path === '/api/v1/sessions' && method === 'GET') {
        return await handleListSessions(request, env, ctx, cors);
      }
      if (path === '/api/v1/sessions' && method === 'DELETE') {
        return await handleRevokeAllSessions(request, env, ctx, cors);
      }
      if (path.startsWith('/api/v1/sessions/') && method === 'DELETE') {
        const sid = path.slice('/api/v1/sessions/'.length);
        return await handleRevokeSession(request, env, ctx, sid, cors);
      }

      // Status (authenticated — app or user)
      if (path === '/api/v1/status' && method === 'GET') {
        return await handleStatus(request, env, ctx, cors);
      }

      // Invite tokens (Section 8, issue #22). Match the bare /invite POST
      // before any parameterized /invite/:token_id so a malformed POST
      // doesn't get captured as a redeem.
      if (path === '/api/v1/invite' && method === 'POST') {
        return await handleCreateInvite(request, env, ctx, cors);
      }
      if (path.startsWith('/api/v1/invite/redeem/') && method === 'POST') {
        const tokenId = path.slice('/api/v1/invite/redeem/'.length);
        return await handleRedeemInvite(request, env, ctx, tokenId, cors);
      }
      if (path.startsWith('/api/v1/invite/') && method === 'GET') {
        const tokenId = path.slice('/api/v1/invite/'.length);
        if (tokenId && !tokenId.includes('/')) {
          return await handleGetInvite(request, env, tokenId, cors);
        }
      }
      if (path.startsWith('/api/v1/invite/') && method === 'DELETE') {
        const tokenId = path.slice('/api/v1/invite/'.length);
        if (tokenId && !tokenId.includes('/')) {
          return await handleRevokeInvite(request, env, ctx, tokenId, cors);
        }
      }

      // App invite template (unauthenticated read; app-role write).
      const inviteTemplateMatch = path.match(/^\/api\/v1\/apps\/([^/]+)\/invite-template$/);
      if (inviteTemplateMatch && method === 'GET') {
        return await handleGetAppInviteTemplate(request, env, inviteTemplateMatch[1], cors);
      }
      if (inviteTemplateMatch && method === 'PUT') {
        return await handleSetInviteTemplate(inviteTemplateMatch[1], request, env, ctx, cors);
      }

      // App management — rules (authenticated, app role)
      const rulesMatch = path.match(/^\/api\/v1\/accounts\/([a-f0-9]{64})\/rules$/);
      if (rulesMatch && method === 'PUT') {
        return await handleSetRules(rulesMatch[1], request, env, ctx, cors);
      }

      // App schema publication (authenticated, app role) — SDK redesign step 5
      const schemaMatch = path.match(/^\/api\/v1\/apps\/([^/]+)\/schema$/);
      if (schemaMatch && method === 'PUT') {
        return await handleSetSchema(schemaMatch[1], request, env, ctx, cors);
      }

      return errorResponse('Not found', 404, cors);
    } catch (err) {
      console.error('[tarn-api] Unhandled error:', err.message, err.stack);
      return errorResponse('Internal server error', 500, cors);
    }
  },
};
