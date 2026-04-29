// Unit tests for revocation + identity rotation primitives (issue #17,
// Section 5d).
//
// Covers the pure helpers + share-log type extension. The TarnClient-level
// flows (changeCredentials → rotation announce → recipient pickup,
// recoverAccount rotation, removeConnection, revokeContentForConnections fanout) are
// exercised end-to-end in tests/test-share-log.mjs against a running
// wrangler dev.
//
// Covered here:
//   - rotate_identity operation construction (buildOperationUnsigned + 4 fields)
//   - rotate_identity sign + verify under OLD signing key, fails under NEW
//   - rotate_identity validation: rejects malformed payload
//   - rotateConnectionIdentity: replaces share_pub/signing_pub/credential_lookup_key,
//     records prior_share_pub + rotated_at; idempotent on missing connection
//   - removeConnection: idempotent on absent share_pub
//
// Run: node --test tests/unit/client-rotate-identity.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildOperationUnsigned,
  signOperation,
  verifyOperationSignature,
  encryptShareLogEntry,
  decryptShareLogEntry,
  derivePairKeys,
  deriveSharedSecret,
  OP_ROTATE_IDENTITY,
  KNOWN_OP_TYPES,
} from '../../client/src/share-log.js';
import {
  bytesToBase64Url,
  deriveSharingKeyPair,
} from '../../client/src/crypto.js';
import {
  removeConnection,
  rotateConnectionIdentity,
  emptyConnectionsRecord,
  upsertConnection,
} from '../../client/src/sharing.js';

const TEST_APP = 'bookish';

// Reuse the deterministic-keypair pattern from client-share-log.test.js so
// the keys are stable across runs.
function fixedMasterKey(seed = 0) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = (seed * 7 + i * 17 + 1) & 0xff;
  return out;
}
async function makeSharingKeypair(seed) {
  const mk = fixedMasterKey(seed);
  const { privateKey, publicKey } = await deriveSharingKeyPair(mk, `seed-${seed}`);
  return { priv: privateKey, pub: publicKey };
}

async function freshSigningKeyPair() {
  const kp = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'],
  );
  // Export the public key as SPKI base64 (the connection record format).
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  const spkiBase64 = btoa(String.fromCharCode(...spki));
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, spkiBase64 };
}

// ============ buildOperationUnsigned: rotate_identity ============

describe('buildOperationUnsigned: rotate_identity (Section 5d)', () => {
  it('is recognized as a known op type', () => {
    assert.ok(KNOWN_OP_TYPES.has(OP_ROTATE_IDENTITY));
  });

  it('accepts the four required fields and shapes them', () => {
    const op = buildOperationUnsigned({
      type: OP_ROTATE_IDENTITY, seq: 5,
      new_share_pub: bytesToBase64Url(new Uint8Array(32).fill(0x42)),
      new_signing_pub: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...',
      new_credential_lookup_key: 'a'.repeat(64),
      rotated_at: 1714400000,
    });
    assert.equal(op.type, 'rotate_identity');
    assert.equal(op.seq, 5);
    assert.equal(op.new_credential_lookup_key, 'a'.repeat(64));
    assert.equal(op.rotated_at, 1714400000);
  });

  it('rejects when new_share_pub is missing or wrong length', () => {
    assert.throws(() => buildOperationUnsigned({
      type: OP_ROTATE_IDENTITY, seq: 0,
      new_signing_pub: 'x',
      new_credential_lookup_key: 'k',
      rotated_at: 1,
    }));
    assert.throws(() => buildOperationUnsigned({
      type: OP_ROTATE_IDENTITY, seq: 0,
      new_share_pub: bytesToBase64Url(new Uint8Array(16)), // wrong length
      new_signing_pub: 'x',
      new_credential_lookup_key: 'k',
      rotated_at: 1,
    }));
  });

  it('rejects when new_credential_lookup_key is missing', () => {
    assert.throws(() => buildOperationUnsigned({
      type: OP_ROTATE_IDENTITY, seq: 0,
      new_share_pub: bytesToBase64Url(new Uint8Array(32)),
      new_signing_pub: 'x',
      rotated_at: 1,
    }));
  });

  it('drops extraneous caller-provided keys', () => {
    const op = buildOperationUnsigned({
      type: OP_ROTATE_IDENTITY, seq: 0,
      new_share_pub: bytesToBase64Url(new Uint8Array(32).fill(1)),
      new_signing_pub: 'sigpub',
      new_credential_lookup_key: 'lkey',
      rotated_at: 1,
      malicious_extra: 'should-be-dropped',
    });
    assert.equal(op.malicious_extra, undefined);
  });
});

// ============ Sign + verify under OLD key (sender side, sharing §13.5) ============

describe('rotate_identity: sign with OLD signing_priv, verify with OLD signing_pub', () => {
  it('round-trips: sign with OLD, verify with OLD → true', async () => {
    const oldSigning = await freshSigningKeyPair();

    const op = buildOperationUnsigned({
      type: OP_ROTATE_IDENTITY, seq: 12,
      new_share_pub: bytesToBase64Url(new Uint8Array(32).fill(0x55)),
      new_signing_pub: 'NEW_SIGNING_PUB_BASE64',
      new_credential_lookup_key: 'b'.repeat(64),
      rotated_at: 1714400001,
    });
    const signed = await signOperation(op, oldSigning.privateKey);
    assert.ok(signed.signature, 'signature should be present');

    const verified = await verifyOperationSignature(signed, oldSigning.spkiBase64);
    assert.equal(verified, true, 'OLD signing_pub should verify');
  });

  it('verify with WRONG (NEW) signing_pub → false (recipient rejects forgery)', async () => {
    const oldSigning = await freshSigningKeyPair();
    const newSigning = await freshSigningKeyPair();

    const op = buildOperationUnsigned({
      type: OP_ROTATE_IDENTITY, seq: 1,
      new_share_pub: bytesToBase64Url(new Uint8Array(32).fill(0x99)),
      new_signing_pub: newSigning.spkiBase64,
      new_credential_lookup_key: 'c'.repeat(64),
      rotated_at: 1714400002,
    });
    const signed = await signOperation(op, oldSigning.privateKey);

    // Verify against the NEW pubkey — this is the key inside the
    // announcement, NOT the cached signing_pub. Should fail.
    const verifiedWithNew = await verifyOperationSignature(signed, newSigning.spkiBase64);
    assert.equal(verifiedWithNew, false, 'NEW signing_pub must NOT verify the OLD-key signature');
  });

  it('seq-binding: tampering with seq breaks verification', async () => {
    const oldSigning = await freshSigningKeyPair();
    const op = buildOperationUnsigned({
      type: OP_ROTATE_IDENTITY, seq: 7,
      new_share_pub: bytesToBase64Url(new Uint8Array(32).fill(0x21)),
      new_signing_pub: 'pub',
      new_credential_lookup_key: 'k'.repeat(64),
      rotated_at: 1714400003,
    });
    const signed = await signOperation(op, oldSigning.privateKey);
    const tampered = { ...signed, seq: 8 };
    const verified = await verifyOperationSignature(tampered, oldSigning.spkiBase64);
    assert.equal(verified, false, 'seq tampering must break signature verification');
  });

  it('encrypt under OLD K_AB and decrypt: round-trip', async () => {
    // Full round-trip: build → sign with OLD signing_priv → encrypt under
    // OLD K_AB (derived from OLD share_priv + recipient's share_pub) → decrypt.
    const aliceOld = await makeSharingKeypair(101);
    const bob = await makeSharingKeypair(102);
    const oldSigning = await freshSigningKeyPair();

    const sharedSecret = deriveSharedSecret(aliceOld.priv, bob.pub);
    const alicePair = await derivePairKeys({
      sharedSecret,
      appId: TEST_APP,
      selfSharePub: aliceOld.pub,
      peerSharePub: bob.pub,
    });
    const bobSharedSecret = deriveSharedSecret(bob.priv, aliceOld.pub);
    const bobPair = await derivePairKeys({
      sharedSecret: bobSharedSecret,
      appId: TEST_APP,
      selfSharePub: bob.pub,
      peerSharePub: aliceOld.pub,
    });

    const op = buildOperationUnsigned({
      type: OP_ROTATE_IDENTITY, seq: 3,
      new_share_pub: bytesToBase64Url(new Uint8Array(32).fill(0xAA)),
      new_signing_pub: 'NEW_SIG_PUB',
      new_credential_lookup_key: 'd'.repeat(64),
      rotated_at: 1714400004,
    });
    const signed = await signOperation(op, oldSigning.privateKey);
    const blob = await encryptShareLogEntry(signed, alicePair.outboundKey);

    // Bob decrypts with his INBOUND key (= Alice's OUTBOUND key bytes).
    const decrypted = await decryptShareLogEntry(blob, bobPair.inboundKey);
    assert.equal(decrypted.type, 'rotate_identity');
    assert.equal(decrypted.seq, 3);
    assert.equal(decrypted.new_credential_lookup_key, 'd'.repeat(64));
    const verified = await verifyOperationSignature(decrypted, oldSigning.spkiBase64);
    assert.equal(verified, true);
  });
});

// ============ rotateConnectionIdentity (recipient-side connection record update) ============

describe('rotateConnectionIdentity (sharing §13.5 step 4)', () => {
  it('replaces share_pub, signing_pub, credential_lookup_key; records prior + rotated_at', () => {
    const connection = {
      email: 'alice@example.com',
      share_pub: 'OLD_SHARE_PUB',
      signing_pub: 'OLD_SIG_PUB',
      credential_lookup_key: 'OLD_LK',
      established_at: 1714000000,
    };
    let record = emptyConnectionsRecord('bookish');
    record = upsertConnection(record, connection);

    const updated = rotateConnectionIdentity(record, 'OLD_SHARE_PUB', {
      newSharePubBase64Url: 'NEW_SHARE_PUB',
      newSigningPubBase64: 'NEW_SIG_PUB',
      newCredentialLookupKey: 'NEW_LK',
      rotatedAt: 1714400000,
    });
    assert.equal(updated.connections.length, 1);
    const f = updated.connections[0];
    assert.equal(f.share_pub, 'NEW_SHARE_PUB');
    assert.equal(f.signing_pub, 'NEW_SIG_PUB');
    assert.equal(f.credential_lookup_key, 'NEW_LK');
    assert.equal(f.rotated_at, 1714400000);
    assert.equal(f.prior_share_pub, 'OLD_SHARE_PUB', 'should record prior share_pub for audit');
    // Other fields preserved.
    assert.equal(f.email, 'alice@example.com');
    assert.equal(f.established_at, 1714000000);
  });

  it('returns the record unchanged if the connection share_pub is not present (idempotent on replay)', () => {
    const record = upsertConnection(emptyConnectionsRecord('bookish'), {
      email: 'a',
      share_pub: 'EXISTS',
      signing_pub: 'sp',
    });
    const updated = rotateConnectionIdentity(record, 'NOT_PRESENT', {
      newSharePubBase64Url: 'NEW',
      newSigningPubBase64: 'NEW_SP',
      newCredentialLookupKey: 'NLK',
      rotatedAt: 1,
    });
    assert.equal(updated, record, 'idempotent — same reference returned');
  });

  it('throws on malformed update payload', () => {
    const record = upsertConnection(emptyConnectionsRecord('bookish'), {
      email: 'a', share_pub: 'X', signing_pub: 'Y',
    });
    assert.throws(() => rotateConnectionIdentity(record, 'X', null));
    assert.throws(() => rotateConnectionIdentity(record, 'X', {
      // missing fields
      newSharePubBase64Url: 'A',
    }));
    assert.throws(() => rotateConnectionIdentity(record, 'X', {
      newSharePubBase64Url: 'A',
      newSigningPubBase64: 'B',
      newCredentialLookupKey: 'C',
      rotatedAt: 'not-a-number',
    }));
  });
});

// ============ removeConnection (sharing §10.1 removeConnection) ============

describe('removeConnection (sharing §10.1)', () => {
  it('drops the connection by share_pub', () => {
    let record = emptyConnectionsRecord('bookish');
    record = upsertConnection(record, { email: 'a', share_pub: 'A', signing_pub: 's' });
    record = upsertConnection(record, { email: 'b', share_pub: 'B', signing_pub: 's' });
    const after = removeConnection(record, 'A');
    assert.equal(after.connections.length, 1);
    assert.equal(after.connections[0].share_pub, 'B');
  });

  it('idempotent on absent share_pub: returns equivalent record', () => {
    const record = upsertConnection(emptyConnectionsRecord('bookish'), {
      email: 'a', share_pub: 'A', signing_pub: 's',
    });
    const after = removeConnection(record, 'NOT_PRESENT');
    assert.equal(after.connections.length, 1);
  });

  it('throws on missing share_pub argument', () => {
    const record = emptyConnectionsRecord('bookish');
    assert.throws(() => removeConnection(record, ''));
    assert.throws(() => removeConnection(record, null));
  });
});
