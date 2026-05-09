/**
 * Cross-validation tests for the Phase 5 sharing primitives.
 *
 * Same posture as `crypto-cross-validate.test.ts`: for every primitive the
 * recover package borrowed from `client/src/share-log.ts` and
 * `client/src/sharing.ts`, run BOTH copies on identical inputs and assert
 * byte-equality. If the two copies drift, this test fails.
 *
 * Covered primitives:
 *   - deriveSharedSecret (X25519 ECDH)
 *   - derivePairKeys (HKDF-Expand outputs + role assignment)
 *   - deriveLogTag (stealth-tag derivation)
 *   - encryptShareLogEntry / decryptShareLogEntry (AES-GCM seal/open)
 *   - signOperation / verifyOperationSignature (ECDSA P-256)
 *   - canonicalJSONStringify (deterministic JSON canonicalization)
 *   - applyOperationToState / replayOperations (state machine)
 *   - hpkeSeal / hpkeOpen (RFC 9180 X25519/HKDF-SHA256/AES-256-GCM)
 *   - deriveInboxTag (HMAC-SHA256 over recipient share_pub digest + window)
 *   - validateConnectionRequestPayload / validateConnectionAcceptPayload
 *   - deriveSharingKeyPair (X25519 keypair from master_key + appId)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Recover-side primitives.
import * as recoverSharing from '../src/sharing/index.js';
import { deriveSharingKeyPair as recoverDeriveSharingKeyPair } from '../src/crypto/share-key.js';
import { deriveMasterKey as recoverDeriveMasterKey } from '../src/crypto/kdf.js';

// Client-side originals.
import * as clientShareLog from '../../client/src/share-log.js';
import * as clientSharing from '../../client/src/sharing.js';
import * as clientCrypto from '../../client/src/crypto.js';

const TEST_APP = 'cross-validate-share';

// Two pinned X25519 keypairs (raw 32 bytes each) so the lex-sort of share_pubs
// is deterministic and we can predict the role assignment.
function bytes(...a: number[]): Uint8Array { return new Uint8Array(a); }
const ALICE_SHARE_PRIV = bytes(
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
);
const BOB_SHARE_PRIV = bytes(
  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
  0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
  0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
);

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// Derive matching X25519 public keys from each side's library so the tests
// match what each implementation expects. The recover package uses
// `@noble/curves/ed25519` (x25519); the client package uses the same import.
import { x25519 as nobleX25519 } from '@noble/curves/ed25519';
const ALICE_SHARE_PUB = nobleX25519.getPublicKey(ALICE_SHARE_PRIV);
const BOB_SHARE_PUB = nobleX25519.getPublicKey(BOB_SHARE_PRIV);

// ============ deriveSharedSecret (X25519 ECDH) ============

describe('cross-validate: deriveSharedSecret', () => {
  it('produces identical shared secret bytes', () => {
    const recoverOut = recoverSharing.deriveSharedSecret(ALICE_SHARE_PRIV, BOB_SHARE_PUB);
    const clientOut = clientShareLog.deriveSharedSecret(ALICE_SHARE_PRIV, BOB_SHARE_PUB);
    assert.equal(recoverOut.length, 32);
    assert.ok(bytesEqual(recoverOut, clientOut));
  });

  it('symmetric: A→B equals B→A', () => {
    const ab = recoverSharing.deriveSharedSecret(ALICE_SHARE_PRIV, BOB_SHARE_PUB);
    const ba = recoverSharing.deriveSharedSecret(BOB_SHARE_PRIV, ALICE_SHARE_PUB);
    assert.ok(bytesEqual(ab, ba), 'X25519 ECDH should be symmetric');
  });
});

// ============ derivePairKeys ============

describe('cross-validate: derivePairKeys', () => {
  it('produces identical key bytes + tag seeds + role', async () => {
    const sharedSecret = recoverSharing.deriveSharedSecret(ALICE_SHARE_PRIV, BOB_SHARE_PUB);

    const recoverOut = await recoverSharing.derivePairKeys({
      sharedSecret,
      appId: TEST_APP,
      selfSharePub: ALICE_SHARE_PUB,
      peerSharePub: BOB_SHARE_PUB,
    });
    const clientOut = await clientShareLog.derivePairKeys({
      sharedSecret,
      appId: TEST_APP,
      selfSharePub: ALICE_SHARE_PUB,
      peerSharePub: BOB_SHARE_PUB,
    });

    assert.equal(recoverOut.role, clientOut.role);
    assert.ok(bytesEqual(recoverOut.outboundKeyBytes, clientOut.outboundKeyBytes));
    assert.ok(bytesEqual(recoverOut.inboundKeyBytes, clientOut.inboundKeyBytes));
    assert.ok(bytesEqual(recoverOut.outboundTagSeed, clientOut.outboundTagSeed));
    assert.ok(bytesEqual(recoverOut.inboundTagSeed, clientOut.inboundTagSeed));
  });

  it('A.outbound = B.inbound (the round-trip invariant)', async () => {
    const sharedSecret = recoverSharing.deriveSharedSecret(ALICE_SHARE_PRIV, BOB_SHARE_PUB);
    const aliceKeys = await recoverSharing.derivePairKeys({
      sharedSecret,
      appId: TEST_APP,
      selfSharePub: ALICE_SHARE_PUB,
      peerSharePub: BOB_SHARE_PUB,
    });
    const bobKeys = await recoverSharing.derivePairKeys({
      sharedSecret,
      appId: TEST_APP,
      selfSharePub: BOB_SHARE_PUB,
      peerSharePub: ALICE_SHARE_PUB,
    });
    assert.ok(bytesEqual(aliceKeys.outboundKeyBytes, bobKeys.inboundKeyBytes));
    assert.ok(bytesEqual(bobKeys.outboundKeyBytes, aliceKeys.inboundKeyBytes));
    assert.ok(bytesEqual(aliceKeys.outboundTagSeed, bobKeys.inboundTagSeed));
    assert.ok(bytesEqual(bobKeys.outboundTagSeed, aliceKeys.inboundTagSeed));
  });
});

// ============ deriveLogTag ============

describe('cross-validate: deriveLogTag', () => {
  it('produces identical tag string for the same (seed, seq)', async () => {
    const seed = bytes(...new Array(32).fill(0).map((_, i) => i + 1));
    for (const seq of [0, 1, 7, 100, 99999]) {
      const recoverTag = await recoverSharing.deriveLogTag(seed, seq);
      const clientTag = await clientShareLog.deriveLogTag(seed, seq);
      assert.equal(recoverTag, clientTag, `seq=${seq} mismatch`);
      assert.equal(recoverTag.length, 43, '43-char base64url');
    }
  });
});

// ============ encryptShareLogEntry / decryptShareLogEntry ============

describe('cross-validate: encrypt/decryptShareLogEntry', () => {
  it('round-trips: client-encrypted entry decrypts under recover', async () => {
    const sharedSecret = recoverSharing.deriveSharedSecret(ALICE_SHARE_PRIV, BOB_SHARE_PUB);
    const aliceKeys = await recoverSharing.derivePairKeys({
      sharedSecret,
      appId: TEST_APP,
      selfSharePub: ALICE_SHARE_PUB,
      peerSharePub: BOB_SHARE_PUB,
    });

    const op = {
      type: 'add' as const,
      seq: 7,
      content_id: 'content-A',
      tx_id: 'tx-12345',
      cek: recoverSharing.canonicalJSONStringify({}).repeat(0) || 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      shared_at: 1700000000,
      signature: 'AAAAAAAAAAAAAAAA',
    };

    const blobFromClient = await clientShareLog.encryptShareLogEntry(op as any, aliceKeys.outboundKey);

    // Recover-side decrypt using same key (symmetric: alice encrypts under
    // her outbound; recover uses alice's outbound key as inbound for symmetry
    // here — but since AES-GCM is symmetric we can use the SAME key).
    const decoded = await recoverSharing.decryptShareLogEntry(blobFromClient, aliceKeys.outboundKey);
    assert.deepEqual(decoded, op);
  });

  it('round-trips: recover-encrypted entry decrypts under client', async () => {
    const sharedSecret = recoverSharing.deriveSharedSecret(ALICE_SHARE_PRIV, BOB_SHARE_PUB);
    const aliceKeys = await recoverSharing.derivePairKeys({
      sharedSecret,
      appId: TEST_APP,
      selfSharePub: ALICE_SHARE_PUB,
      peerSharePub: BOB_SHARE_PUB,
    });

    const op = {
      type: 'remove' as const,
      seq: 12,
      content_id: 'content-X',
      removed_at: 1700001000,
      signature: 'BBBBBBBBBBBBBBBB',
    };

    const blobFromRecover = await recoverSharing.encryptShareLogEntry(op as any, aliceKeys.outboundKey);
    const decoded = await clientShareLog.decryptShareLogEntry(blobFromRecover, aliceKeys.outboundKey);
    assert.deepEqual(decoded, op);
  });
});

// ============ canonicalJSONStringify ============

describe('cross-validate: canonicalJSONStringify', () => {
  it('produces identical canonical JSON for nested objects', () => {
    const obj = { z: 1, a: { y: 2, b: [3, 4, { p: 'x' }] } };
    assert.equal(
      recoverSharing.canonicalJSONStringify(obj),
      clientShareLog.canonicalJSONStringify(obj),
    );
  });

  it('drops undefined per RFC 8785', () => {
    const obj = { a: 1, b: undefined as unknown as number, c: 3 };
    const out = recoverSharing.canonicalJSONStringify(obj);
    assert.equal(out, '{"a":1,"c":3}');
  });
});

// ============ signOperation + verifyOperationSignature ============

describe('cross-validate: sign + verify ECDSA P-256', () => {
  it('client-signed operation verifies under recover', async () => {
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
    const spkiBase64 = btoa(String.fromCharCode(...spki));

    const op = { type: 'add' as const, seq: 1, content_id: 'c', tx_id: 't', cek: 'AAAA'.repeat(11), shared_at: 100 };
    const signed = await clientShareLog.signOperation(op as any, kp.privateKey);

    const ok = await recoverSharing.verifyOperationSignature(signed, spkiBase64);
    assert.equal(ok, true);
  });

  it('verify rejects tampered signature', async () => {
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
    const spkiBase64 = btoa(String.fromCharCode(...spki));

    const op = { type: 'remove' as const, seq: 5, content_id: 'cx', removed_at: 200 };
    const signed = await recoverSharing.signOperation(op as any, kp.privateKey);
    const tampered = { ...signed, content_id: 'mutated' };
    const ok = await recoverSharing.verifyOperationSignature(tampered, spkiBase64);
    assert.equal(ok, false);
  });
});

// ============ applyOperationToState / replayOperations ============

describe('cross-validate: state machine (sharing §8.4)', () => {
  it('replay produces identical state map under both implementations', () => {
    const ops = [
      { type: 'add', seq: 0, content_id: 'A', tx_id: 'tA', cek: 'cAAA', shared_at: 100 },
      { type: 'add', seq: 1, content_id: 'B', tx_id: 'tB', cek: 'cBBB', shared_at: 110 },
      { type: 'update', seq: 2, content_id: 'A', tx_id: 'tA2', updated_at: 120 },
      { type: 'rotate', seq: 3, content_id: 'B', cek: 'cCCC', rotated_at: 130 },
      { type: 'remove', seq: 4, content_id: 'A', removed_at: 140 },
    ];

    const recoverState = recoverSharing.replayOperations(ops, {}, { onWarn: () => {} });
    const clientState = clientShareLog.replayOperations(ops, {}, { onWarn: () => {} });
    assert.deepEqual(recoverState, clientState);
    assert.deepEqual(recoverState, { B: { tx_id: 'tB', cek: 'cCCC' } });
  });

  it('snapshot wipes prior state per §8.4', () => {
    const ops = [
      { type: 'add', seq: 0, content_id: 'A', tx_id: 'tA', cek: 'cAAA', shared_at: 100 },
      { type: 'snapshot', seq: 1, state: { B: { tx_id: 'tB', cek: 'cBBB' } }, snapshot_at: 200, prior_seq: 0 },
    ];
    const state = recoverSharing.replayOperations(ops);
    assert.deepEqual(state, { B: { tx_id: 'tB', cek: 'cBBB' } });
  });
});

// ============ HPKE seal/open + inbox tag ============

describe('cross-validate: HPKE primitives', () => {
  it('deriveInboxTag matches client byte-for-byte across windows', async () => {
    for (const window of [0, 100, 19834, 99999]) {
      const recoverTag = await recoverSharing.deriveInboxTag(BOB_SHARE_PUB, TEST_APP, window);
      const clientTag = await clientSharing.deriveInboxTag(BOB_SHARE_PUB, TEST_APP, window);
      assert.equal(recoverTag, clientTag, `window=${window} mismatch`);
    }
  });

  it('hpkeSeal (client) → hpkeOpen (recover) round-trips', async () => {
    const plaintext = new TextEncoder().encode(JSON.stringify({ hello: 'world' }));
    const blob = await clientSharing.hpkeSeal({
      recipientSharePub: BOB_SHARE_PUB,
      info: 'tarn-connection-request-v1',
      plaintext,
    });
    const decoded = await recoverSharing.hpkeOpen({
      sharePriv: BOB_SHARE_PRIV,
      info: 'tarn-connection-request-v1',
      blob,
    });
    assert.deepEqual(Array.from(decoded), Array.from(plaintext));
  });

  it('hpkeOpen rejects info-string mismatch', async () => {
    const blob = await recoverSharing.hpkeSeal({
      recipientSharePub: BOB_SHARE_PUB,
      info: recoverSharing.INFO_CONNECTION_REQUEST,
      plaintext: new TextEncoder().encode('{}'),
    });
    await assert.rejects(
      () => recoverSharing.hpkeOpen({
        sharePriv: BOB_SHARE_PRIV,
        info: recoverSharing.INFO_CONNECTION_ACCEPT, // wrong info
        blob,
      }),
    );
  });
});

// ============ Connection payload validators ============

describe('cross-validate: connection payload validators', () => {
  it('validateConnectionRequestPayload matches client outcome on a well-formed payload', () => {
    const payload = {
      type: 'connection_request',
      sender_email: 'alice@example.com',
      sender_share_pub: recoverSharing['canonicalJSONStringify'](null) || 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      sender_signing_pub: 'AAAAAAAAAA',
      sender_app_id: TEST_APP,
      nonce: 'AAAAAAAAAAAAAAAAAAAAAA',
      timestamp: Math.floor(Date.now() / 1000),
    };
    // Replace the share_pub with a real 32-byte base64url string.
    payload.sender_share_pub = clientCrypto.bytesToBase64Url(BOB_SHARE_PUB);
    payload.nonce = clientCrypto.bytesToBase64Url(new Uint8Array(16));

    const recoverOut = recoverSharing.validateConnectionRequestPayload(payload, TEST_APP);
    const clientOut = clientSharing.validateConnectionRequestPayload(payload, TEST_APP);
    assert.equal(recoverOut.valid, clientOut.valid);
    assert.equal(recoverOut.valid, true);
  });

  it('validateConnectionAcceptPayload matches client on wrong-app', () => {
    const payload = {
      type: 'connection_accept',
      sender_email: 'bob@example.com',
      sender_share_pub: clientCrypto.bytesToBase64Url(BOB_SHARE_PUB),
      sender_signing_pub: 'AAAAAAAAAA',
      sender_app_id: 'wrong-app',
      in_reply_to: 'AAAAAAAAAAAAAAAAAAAAAA',
      timestamp: Math.floor(Date.now() / 1000),
    };
    const recoverOut = recoverSharing.validateConnectionAcceptPayload(payload, TEST_APP);
    const clientOut = clientSharing.validateConnectionAcceptPayload(payload, TEST_APP);
    assert.equal(recoverOut.valid, false);
    assert.equal(clientOut.valid, false);
  });
});

// ============ deriveSharingKeyPair ============

describe('cross-validate: deriveSharingKeyPair', () => {
  it('matches client output byte-for-byte from the same master_key + appId', async () => {
    // Use a small fake master_key (32 bytes) to skip the slow Argon2id step.
    const fakeMasterKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) fakeMasterKey[i] = i + 50;

    const recoverOut = await recoverDeriveSharingKeyPair(fakeMasterKey, TEST_APP);
    const clientOut = await clientCrypto.deriveSharingKeyPair(fakeMasterKey, TEST_APP);
    assert.ok(bytesEqual(recoverOut.privateKey, clientOut.privateKey));
    assert.ok(bytesEqual(recoverOut.publicKey, clientOut.publicKey));
    assert.equal(recoverOut.privateKey.length, 32);
    assert.equal(recoverOut.publicKey.length, 32);
  });

  it('end-to-end with deriveMasterKey + deriveSharingKeyPair matches client deriveAllKeys', async () => {
    const username = 'sharing-derive@example.com';
    const password = 'sharing-derive-pw';
    const masterKey = await recoverDeriveMasterKey(username, password);
    const recoverShareKp = await recoverDeriveSharingKeyPair(masterKey, TEST_APP);
    const clientAll = await clientCrypto.deriveAllKeys(username, password, TEST_APP);
    assert.ok(bytesEqual(recoverShareKp.privateKey, clientAll.sharingKeyPair.privateKey));
    assert.ok(bytesEqual(recoverShareKp.publicKey, clientAll.sharingKeyPair.publicKey));
  });
});
