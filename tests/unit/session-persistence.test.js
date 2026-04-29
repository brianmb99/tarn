// Unit tests for the pure-crypto layer of client/src/session-persistence.js.
// Run: node --test tests/unit/session-persistence.test.js
//
// The IndexedDB layer (getOrCreateWrappingKey / clearWrappingKey) is browser-
// only and exercised via the integration test in tests/test-client.mjs. The
// production wrapping key is non-extractable; here we generate an extractable
// stand-in because the encrypt/decrypt logic is identical regardless.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  encryptSessionBlob,
  decryptSessionBlob,
} from '../../client/src/session-persistence.js';

async function generateTestKey() {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
}

const enc = new TextEncoder();
const dec = new TextDecoder();

describe('encryptSessionBlob / decryptSessionBlob', () => {
  it('roundtrips a small payload', async () => {
    const key = await generateTestKey();
    const pt = enc.encode('hello world');
    const blob = await encryptSessionBlob(pt, key);
    assert.ok(blob instanceof Uint8Array);
    assert.ok(blob.length >= pt.length + 12 + 16, 'blob must include 12-byte IV + 16-byte tag');
    const decrypted = await decryptSessionBlob(blob, key);
    assert.equal(dec.decode(decrypted), 'hello world');
  });

  it('roundtrips an empty payload', async () => {
    const key = await generateTestKey();
    const pt = new Uint8Array(0);
    const blob = await encryptSessionBlob(pt, key);
    const decrypted = await decryptSessionBlob(blob, key);
    assert.equal(decrypted.length, 0);
  });

  it('roundtrips a 1 KiB payload', async () => {
    const key = await generateTestKey();
    const pt = crypto.getRandomValues(new Uint8Array(1024));
    const blob = await encryptSessionBlob(pt, key);
    const decrypted = await decryptSessionBlob(blob, key);
    assert.deepEqual(decrypted, pt);
  });

  it('roundtrips a 64 KiB payload', async () => {
    const key = await generateTestKey();
    const pt = crypto.getRandomValues(new Uint8Array(64 * 1024));
    const blob = await encryptSessionBlob(pt, key);
    const decrypted = await decryptSessionBlob(blob, key);
    assert.deepEqual(decrypted, pt);
  });

  it('produces different ciphertexts on each call (fresh IV)', async () => {
    const key = await generateTestKey();
    const pt = enc.encode('same plaintext');
    const a = await encryptSessionBlob(pt, key);
    const b = await encryptSessionBlob(pt, key);
    assert.notDeepEqual(a, b, 'two encryptions of the same plaintext must differ');
    // The first 12 bytes are the IV; they should differ.
    assert.notDeepEqual(a.subarray(0, 12), b.subarray(0, 12));
  });

  it('rejects a tampered ciphertext byte', async () => {
    const key = await generateTestKey();
    const pt = enc.encode('tamper test payload');
    const blob = await encryptSessionBlob(pt, key);
    // Flip a bit in the ciphertext region (after the 12-byte IV).
    const tampered = new Uint8Array(blob);
    tampered[15] ^= 0x01;
    await assert.rejects(() => decryptSessionBlob(tampered, key));
  });

  it('rejects a tampered IV byte', async () => {
    const key = await generateTestKey();
    const pt = enc.encode('tamper iv test');
    const blob = await encryptSessionBlob(pt, key);
    const tampered = new Uint8Array(blob);
    tampered[0] ^= 0x01;
    await assert.rejects(() => decryptSessionBlob(tampered, key));
  });

  it('rejects a tampered auth-tag byte', async () => {
    const key = await generateTestKey();
    const pt = enc.encode('tamper tag test');
    const blob = await encryptSessionBlob(pt, key);
    const tampered = new Uint8Array(blob);
    tampered[tampered.length - 1] ^= 0x01;
    await assert.rejects(() => decryptSessionBlob(tampered, key));
  });

  it('rejects decrypt with a different key', async () => {
    const key1 = await generateTestKey();
    const key2 = await generateTestKey();
    const pt = enc.encode('wrong key test');
    const blob = await encryptSessionBlob(pt, key1);
    await assert.rejects(() => decryptSessionBlob(blob, key2));
  });

  it('rejects a blob that is too short', async () => {
    const key = await generateTestKey();
    const tooShort = new Uint8Array(5);
    await assert.rejects(() => decryptSessionBlob(tooShort, key));
  });

  it('rejects a blob with only IV and no ciphertext', async () => {
    const key = await generateTestKey();
    const ivOnly = new Uint8Array(12);
    await assert.rejects(() => decryptSessionBlob(ivOnly, key));
  });

  it('produces output with the correct IV/ciphertext layout', async () => {
    const key = await generateTestKey();
    const pt = enc.encode('layout check');
    const blob = await encryptSessionBlob(pt, key);
    // The decryptor in this module uses bytes 0..12 as IV. Verify by manually
    // splitting and decrypting through the WebCrypto API directly.
    const iv = blob.subarray(0, 12);
    const ct = blob.subarray(12);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    assert.equal(dec.decode(new Uint8Array(decrypted)), 'layout check');
  });
});
