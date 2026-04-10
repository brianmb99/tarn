// Auth middleware: extract and verify JWT from Authorization header

import { verifyJWT } from '../auth.js';

/**
 * Verify JWT from Authorization header. Returns { address } on success.
 * Returns null if no token or invalid token — caller decides the error response.
 */
export async function requireAuth(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;

  const token = authHeader.slice(7);
  if (!token) return null;

  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload || !payload.sub) return null;

  return { address: payload.sub };
}
