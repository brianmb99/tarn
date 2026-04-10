// Auth primitives: JWT, challenge/nonce, signature verification
// Uses WebCrypto HMAC-SHA256 for JWT (zero deps) and ethers for EIP-191 signature recovery.

import { ethers } from 'ethers';

const JWT_TTL_SECONDS = 900; // 15 minutes
const NONCE_TTL_SECONDS = 300; // 5 minutes

// ============ CHALLENGE / NONCE ============

export function generateChallenge(address) {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const nonce = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const message = [
    'Sign this message to authenticate with Tarn API.',
    '',
    `Address: ${address}`,
    `Nonce: ${nonce}`,
    `Timestamp: ${new Date().toISOString()}`,
  ].join('\n');
  return { nonce, message };
}

export async function storeNonce(env, nonce, address) {
  await env.AUTH_KV.put(
    `nonce:${nonce}`,
    JSON.stringify({ address: address.toLowerCase(), createdAt: Date.now() }),
    { expirationTtl: NONCE_TTL_SECONDS }
  );
}

export async function consumeNonce(env, nonce) {
  const key = `nonce:${nonce}`;
  const raw = await env.AUTH_KV.get(key);
  if (!raw) return null;
  // Single-use: delete immediately
  await env.AUTH_KV.delete(key);
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// ============ SIGNATURE VERIFICATION ============

export function verifySignature(message, signature, expectedAddress) {
  try {
    const recovered = ethers.verifyMessage(message, signature);
    return recovered.toLowerCase() === expectedAddress.toLowerCase();
  } catch {
    return false;
  }
}

// ============ JWT (WebCrypto HMAC-SHA256) ============

let _hmacKey = null;

async function getHMACKey(secret) {
  if (_hmacKey) return _hmacKey;
  const keyData = Uint8Array.from(atob(secret), c => c.charCodeAt(0));
  _hmacKey = await crypto.subtle.importKey(
    'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );
  return _hmacKey;
}

function base64url(data) {
  if (typeof data === 'string') {
    return btoa(data).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  }
  // ArrayBuffer
  return btoa(String.fromCharCode(...new Uint8Array(data)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64urlDecode(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - str.length % 4) % 4);
  return atob(padded);
}

export async function signJWT(payload, secret) {
  const key = await getHMACKey(secret);
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const now = Math.floor(Date.now() / 1000);
  const body = base64url(JSON.stringify({
    ...payload,
    iat: now,
    exp: now + JWT_TTL_SECONDS,
  }));
  const sigInput = new TextEncoder().encode(`${header}.${body}`);
  const sig = await crypto.subtle.sign('HMAC', key, sigInput);
  return `${header}.${body}.${base64url(sig)}`;
}

export async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const key = await getHMACKey(secret);
  const sigInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const signature = Uint8Array.from(base64urlDecode(parts[2]), c => c.charCodeAt(0));

  const valid = await crypto.subtle.verify('HMAC', key, signature, sigInput);
  if (!valid) return null;

  try {
    const payload = JSON.parse(base64urlDecode(parts[1]));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}
