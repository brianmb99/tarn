// Health check endpoint

import { jsonResponse } from '../worker.js';
import { PROTOCOL_VERSION } from '../constants.js';

const ARWEAVE_GRAPHQL = 'https://arweave.net/graphql';

export async function handleHealth(env, cors) {
  const checks = {};

  // D1 check
  try {
    const result = await env.DB.prepare('SELECT COUNT(*) as count FROM entries').first();
    checks.d1 = { reachable: true, entryCount: result?.count ?? 0 };
  } catch (err) {
    checks.d1 = { reachable: false, error: err.message };
  }

  // Arweave GraphQL check
  try {
    const res = await fetch(ARWEAVE_GRAPHQL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: '{ transactions(first: 1) { edges { node { id } } } }' }),
      signal: AbortSignal.timeout(5000),
    });
    checks.arweave = { reachable: res.ok, statusCode: res.status };
  } catch (err) {
    checks.arweave = { reachable: false, error: err.message };
  }

  const healthy = checks.d1?.reachable && checks.arweave?.reachable;

  return jsonResponse(
    { healthy, version: PROTOCOL_VERSION, checks },
    healthy ? 200 : 503,
    cors,
  );
}
