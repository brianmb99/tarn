// Tarn API — Encrypted data platform cache and write layer
// Identity: ECDSA P-256 challenge-response auth. Data: AES-256-GCM encrypted blobs on Arweave.

import { handleHealth } from './routes/info.js';
import { handleEntries, handleEntryById } from './routes/entries.js';
import { handleLookup } from './routes/lookup.js';
import { handleRegister, handleChallenge, handleVerify, handleCredentialChange, handleDeleteAccount } from './routes/auth.js';
import { handleCreateEntry, handleEditEntry, handleDeleteEntry } from './routes/write.js';
import { handleSyncStatus, handleSyncAck } from './routes/sync.js';

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
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Arweave-Tags',
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
        return await handleEntries(url, env, ctx, cors);
      }
      if (path.startsWith('/api/v1/entries/') && method === 'GET') {
        const txid = path.slice('/api/v1/entries/'.length);
        if (txid && !txid.includes('/')) {
          return await handleEntryById(txid, url, env, ctx, cors);
        }
      }

      // Entries — writes (authenticated)
      if (path === '/api/v1/entries' && method === 'POST') {
        return await handleCreateEntry(request, env, ctx, cors);
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
        return await handleSyncStatus(url, env, cors);
      }
      if (path === '/api/v1/sync/ack' && method === 'POST') {
        return await handleSyncAck(request, env, cors);
      }

      // Lookup (credentials, account metadata)
      if (path === '/api/v1/lookup' && method === 'GET') {
        return await handleLookup(url, request, env, ctx, cors);
      }

      // App management — rules (authenticated, app role)
      const rulesMatch = path.match(/^\/api\/v1\/accounts\/([a-f0-9]{64})\/rules$/);
      if (rulesMatch && method === 'PUT') {
        // Deferred to Phase 4: import handleSetRules from './routes/apps.js'
        return errorResponse('Not implemented', 501, cors);
      }

      return errorResponse('Not found', 404, cors);
    } catch (err) {
      console.error('[tarn-api] Unhandled error:', err.message, err.stack);
      return errorResponse('Internal server error', 500, cors);
    }
  },
};
