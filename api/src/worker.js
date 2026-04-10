// Tarn API — Encrypted data platform cache and write layer
// Phase 1: Reads public, IP rate-limited. Phase 2: Authenticated writes.

import { handleHealth, handleFees } from './routes/info.js';
import { handleEntries, handleEntryById } from './routes/entries.js';
import { handleLookup } from './routes/lookup.js';
import { handleChallenge, handleVerify } from './routes/auth.js';
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
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Payment, X-Arweave-Tags, X-Signed-DataItem',
    'Access-Control-Expose-Headers': 'X-Payment-Required',
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
      // Auth (public)
      if (path === '/api/v1/auth/challenge' && method === 'POST') {
        return await handleChallenge(request, env, cors);
      }
      if (path === '/api/v1/auth/verify' && method === 'POST') {
        return await handleVerify(request, env, cors);
      }

      // Info (public, GET only)
      if (path === '/api/v1/health' && method === 'GET') {
        return await handleHealth(env, cors);
      }
      if (path === '/api/v1/fees' && method === 'GET') {
        return handleFees(cors);
      }

      // Entries — reads
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

      // Lookup (credentials, account metadata, GET only)
      if (path === '/api/v1/lookup' && method === 'GET') {
        return await handleLookup(url, request, env, ctx, cors);
      }

      return errorResponse('Not found', 404, cors);
    } catch (err) {
      console.error('[tarn-api] Unhandled error:', err.message, err.stack);
      return errorResponse('Internal server error', 500, cors);
    }
  },
};
