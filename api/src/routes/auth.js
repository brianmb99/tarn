// Auth endpoints: challenge/verify flow for wallet-signature JWT auth

import { jsonResponse, errorResponse } from '../worker.js';
import { generateChallenge, storeNonce, consumeNonce, verifySignature, signJWT } from '../auth.js';

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

export async function handleChallenge(request, env, cors) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const address = body.address;
  if (!address || !ADDRESS_RE.test(address)) {
    return errorResponse('Invalid address: expected 0x-prefixed 40-char hex', 400, cors);
  }

  const { nonce, message } = generateChallenge(address);
  await storeNonce(env, nonce, address);

  return jsonResponse({ message, nonce, expiresIn: 300 }, 200, cors);
}

export async function handleVerify(request, env, cors) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400, cors);
  }

  const { address, signature, nonce } = body;
  if (!address || !ADDRESS_RE.test(address)) {
    return errorResponse('Invalid address', 400, cors);
  }
  if (!signature || !nonce) {
    return errorResponse('Missing signature or nonce', 400, cors);
  }

  // Consume nonce (single-use)
  const nonceData = await consumeNonce(env, nonce);
  if (!nonceData) {
    return errorResponse('Invalid or expired nonce', 401, cors);
  }

  // Verify nonce was issued for this address
  if (nonceData.address !== address.toLowerCase()) {
    return errorResponse('Nonce address mismatch', 401, cors);
  }

  // Reconstruct the challenge message and verify signature
  const message = [
    'Sign this message to authenticate with Tarn API.',
    '',
    `Address: ${address}`,
    `Nonce: ${nonce}`,
    `Timestamp: ${new Date(nonceData.createdAt).toISOString()}`,
  ].join('\n');

  if (!verifySignature(message, signature, address)) {
    return errorResponse('Invalid signature', 401, cors);
  }

  // Issue JWT
  const token = await signJWT({ sub: address.toLowerCase() }, env.JWT_SECRET);

  return jsonResponse({ token, expiresIn: 900 }, 200, cors);
}
