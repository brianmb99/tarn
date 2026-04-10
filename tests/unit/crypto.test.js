// Unit tests for api/src/crypto.js — ECDSA P-256 primitives
// Run: node --test tests/unit/crypto.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { importPublicKey, exportPublicKey, verifySignature, generateNonce, isValidHex64 } from '../../api/src/crypto.js';

// Helper: generate a P-256 key pair for testing
async function generateTestKeyPair() {
  return await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
}

// Helper: sign data with a private key (what the client would do)
async function signData(privateKey, dataHex) {
  const data = hexToBytes(dataHex);
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    data
  );
  return bytesToBase64(new Uint8Array(sig));
}

// Helper: export public key to base64 SPKI
async function exportPubKey(publicKey) {
  const der = await crypto.subtle.exportKey('spki', publicKey);
  return bytesToBase64(new Uint8Array(der));
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

// ============ importPublicKey / exportPublicKey ============

describe('importPublicKey', () => {
  it('should import a valid P-256 SPKI public key', async () => {
    const { publicKey } = await generateTestKeyPair();
    const base64 = await exportPubKey(publicKey);
    const imported = await importPublicKey(base64);
    assert.ok(imported instanceof CryptoKey);
    assert.equal(imported.algorithm.name, 'ECDSA');
    assert.equal(imported.algorithm.namedCurve, 'P-256');
    assert.deepEqual(imported.usages, ['verify']);
  });

  it('should round-trip export then import', async () => {
    const { publicKey } = await generateTestKeyPair();
    const base64 = await exportPubKey(publicKey);
    const imported = await importPublicKey(base64);
    const reExported = await exportPublicKey(imported);
    assert.equal(reExported, base64);
  });

  it('should reject null input', async () => {
    await assert.rejects(() => importPublicKey(null), /Public key is required/);
  });

  it('should reject empty string', async () => {
    await assert.rejects(() => importPublicKey(''), /Public key is required/);
  });

  it('should reject non-string input', async () => {
    await assert.rejects(() => importPublicKey(123), /Public key is required/);
  });

  it('should reject garbage base64', async () => {
    await assert.rejects(() => importPublicKey('not-valid-base64!!!'));
  });

  it('should reject valid base64 of wrong key type', async () => {
    // Generate an HMAC key and try to import it as P-256
    const hmacKey = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' },
      true,
      ['sign']
    );
    const raw = await crypto.subtle.exportKey('raw', hmacKey);
    const base64 = bytesToBase64(new Uint8Array(raw));
    await assert.rejects(() => importPublicKey(base64));
  });
});

// ============ verifySignature ============

describe('verifySignature', () => {
  it('should verify a valid signature', async () => {
    const { publicKey, privateKey } = await generateTestKeyPair();
    const imported = await importPublicKey(await exportPubKey(publicKey));
    const nonce = generateNonce();
    const sig = await signData(privateKey, nonce);
    const result = await verifySignature(imported, nonce, sig);
    assert.equal(result, true);
  });

  it('should reject a signature of different data', async () => {
    const { publicKey, privateKey } = await generateTestKeyPair();
    const imported = await importPublicKey(await exportPubKey(publicKey));
    const nonce1 = generateNonce();
    const nonce2 = generateNonce();
    const sig = await signData(privateKey, nonce1);
    const result = await verifySignature(imported, nonce2, sig);
    assert.equal(result, false);
  });

  it('should reject a signature from a different key', async () => {
    const kp1 = await generateTestKeyPair();
    const kp2 = await generateTestKeyPair();
    const imported1 = await importPublicKey(await exportPubKey(kp1.publicKey));
    const nonce = generateNonce();
    const sig = await signData(kp2.privateKey, nonce);
    const result = await verifySignature(imported1, nonce, sig);
    assert.equal(result, false);
  });

  it('should reject a truncated signature (32 bytes instead of 64)', async () => {
    const { publicKey, privateKey } = await generateTestKeyPair();
    const imported = await importPublicKey(await exportPubKey(publicKey));
    const nonce = generateNonce();
    const fullSig = await signData(privateKey, nonce);
    // Truncate: take first 32 bytes worth of base64
    const truncated = bytesToBase64(new Uint8Array(32)); // all zeros, wrong length
    const result = await verifySignature(imported, nonce, truncated);
    assert.equal(result, false);
  });

  it('should reject 64 zero bytes as signature', async () => {
    const { publicKey } = await generateTestKeyPair();
    const imported = await importPublicKey(await exportPubKey(publicKey));
    const nonce = generateNonce();
    const zeroSig = bytesToBase64(new Uint8Array(64));
    const result = await verifySignature(imported, nonce, zeroSig);
    assert.equal(result, false);
  });

  it('should reject garbage signature base64', async () => {
    const { publicKey } = await generateTestKeyPair();
    const imported = await importPublicKey(await exportPubKey(publicKey));
    const nonce = generateNonce();
    const result = await verifySignature(imported, nonce, 'not-valid!!!');
    assert.equal(result, false);
  });

  it('should return false on empty signature', async () => {
    const { publicKey } = await generateTestKeyPair();
    const imported = await importPublicKey(await exportPubKey(publicKey));
    const nonce = generateNonce();
    const result = await verifySignature(imported, nonce, '');
    assert.equal(result, false);
  });
});

// ============ generateNonce ============

describe('generateNonce', () => {
  it('should return a 64-character hex string', () => {
    const nonce = generateNonce();
    assert.equal(nonce.length, 64);
    assert.match(nonce, /^[a-f0-9]{64}$/);
  });

  it('should generate unique nonces', () => {
    const nonces = new Set();
    for (let i = 0; i < 100; i++) {
      nonces.add(generateNonce());
    }
    assert.equal(nonces.size, 100, 'Expected 100 unique nonces');
  });
});

// ============ isValidHex64 ============

describe('isValidHex64', () => {
  it('should accept a valid 64-char hex string', () => {
    assert.equal(isValidHex64('a'.repeat(64)), true);
    assert.equal(isValidHex64('0123456789abcdef'.repeat(4)), true);
  });

  it('should reject uppercase hex', () => {
    assert.equal(isValidHex64('A'.repeat(64)), false);
  });

  it('should reject too-short strings', () => {
    assert.equal(isValidHex64('a'.repeat(63)), false);
  });

  it('should reject too-long strings', () => {
    assert.equal(isValidHex64('a'.repeat(65)), false);
  });

  it('should reject non-hex characters', () => {
    assert.equal(isValidHex64('g'.repeat(64)), false);
  });

  it('should reject null', () => {
    assert.equal(isValidHex64(null), false);
  });

  it('should reject numbers', () => {
    assert.equal(isValidHex64(123), false);
  });

  it('should reject empty string', () => {
    assert.equal(isValidHex64(''), false);
  });
});
