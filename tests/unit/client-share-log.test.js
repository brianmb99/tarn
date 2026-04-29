// Unit tests for share log primitives (issue #15, Section 5b).
//
// Covers:
//   - deriveSharedSecret: ECDH symmetry between Alice and Bob
//   - derivePairKeys: direction-aware K_AB and T_AB_seed (outbound ≠ inbound)
//   - deriveLogTag: 43-char base64url, deterministic, distinct per-seq
//   - canonicalJSONStringify: deterministic key ordering, RFC 8785-ish shape
//   - signOperation + verifyOperationSignature round-trip
//   - All five operation types parse + sign + verify cleanly
//   - rotate_identity is recognized as a sixth type (no parse error)
//   - encryptShareLogEntry + decryptShareLogEntry round-trip
//   - Tampering: bit flip in ciphertext fails decrypt; bit flip in operation
//     fails signature verification
//   - shouldEmitSnapshot threshold logic
//
// Run: node --test tests/unit/client-share-log.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  deriveSharedSecret,
  derivePairKeys,
  deriveLogTag,
  canonicalJSONStringify,
  canonicalJSONBytes,
  computeSigInput,
  signOperation,
  verifyOperationSignature,
  encryptShareLogEntry,
  decryptShareLogEntry,
  buildOperationUnsigned,
  shouldEmitSnapshot,
  KNOWN_OP_TYPES,
  OP_ADD,
  OP_UPDATE,
  OP_ROTATE,
  OP_REMOVE,
  OP_SNAPSHOT,
  OP_ROTATE_IDENTITY,
  DEFAULT_COMPACTION_INTERVAL,
} from '../../client/src/share-log.js';
import {
  bytesToBase64Url,
  base64UrlToBytes,
  deriveSharingKeyPair,
} from '../../client/src/crypto.js';

const TEST_APP = 'bookish';
const OTHER_APP = 'cellar';

// Build a deterministic X25519 keypair via the SDK's own derivation. Going
// through deriveSharingKeyPair avoids importing @noble/curves at the tests/
// level (it's installed under client/node_modules — see the same workaround
// in client-sharing-handshake.test.js).
function fixedMasterKey(seed = 0) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = (seed * 7 + i * 17 + 1) & 0xff;
  return out;
}
async function makeKeypair(seed) {
  const mk = fixedMasterKey(seed);
  const { privateKey, publicKey } = await deriveSharingKeyPair(mk, `seed-${seed}`);
  return { priv: privateKey, pub: publicKey };
}
const KP = {};
for (const i of [1, 2, 3]) {
  KP[i] = await makeKeypair(i);
}
function keypairFromSeed(seed) {
  if (!KP[seed]) throw new Error(`No precomputed keypair for seed ${seed}`);
  return KP[seed];
}

async function freshSigningKey() {
  return await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'],
  );
}

async function exportSpkiBase64(pubKey) {
  const der = new Uint8Array(await crypto.subtle.exportKey('spki', pubKey));
  let bin = '';
  for (let i = 0; i < der.length; i++) bin += String.fromCharCode(der[i]);
  return btoa(bin);
}

const ALICE = keypairFromSeed(1);
const BOB = keypairFromSeed(2);

// ============ deriveSharedSecret ============

describe('deriveSharedSecret', () => {
  it('is symmetric: Alice and Bob compute the same S_AB', () => {
    const s1 = deriveSharedSecret(ALICE.priv, BOB.pub);
    const s2 = deriveSharedSecret(BOB.priv, ALICE.pub);
    assert.deepEqual(Array.from(s1), Array.from(s2));
    assert.equal(s1.length, 32);
  });

  it('produces different S for different counterparties', () => {
    const eve = keypairFromSeed(3);
    const sAB = deriveSharedSecret(ALICE.priv, BOB.pub);
    const sAE = deriveSharedSecret(ALICE.priv, eve.pub);
    assert.notDeepEqual(Array.from(sAB), Array.from(sAE));
  });

  it('rejects malformed inputs', () => {
    assert.throws(() => deriveSharedSecret(new Uint8Array(31), BOB.pub));
    assert.throws(() => deriveSharedSecret(ALICE.priv, new Uint8Array(33)));
    assert.throws(() => deriveSharedSecret('not a u8', BOB.pub));
  });
});

// ============ derivePairKeys ============

describe('derivePairKeys', () => {
  it('returns four direction-aware keys + four matching seeds', async () => {
    const sharedSecret = deriveSharedSecret(ALICE.priv, BOB.pub);
    const keys = await derivePairKeys({
      sharedSecret, appId: TEST_APP,
      selfSharePub: ALICE.pub, peerSharePub: BOB.pub,
    });
    assert.ok(keys.outboundKey);
    assert.ok(keys.inboundKey);
    assert.equal(keys.outboundTagSeed.length, 32);
    assert.equal(keys.inboundTagSeed.length, 32);
    assert.equal(keys.outboundKeyBytes.length, 32);
    assert.equal(keys.inboundKeyBytes.length, 32);
    assert.ok(keys.role === 'forward' || keys.role === 'reverse');
  });

  it('outbound and inbound key bytes differ (direction asymmetry)', async () => {
    const sharedSecret = deriveSharedSecret(ALICE.priv, BOB.pub);
    const keys = await derivePairKeys({
      sharedSecret, appId: TEST_APP,
      selfSharePub: ALICE.pub, peerSharePub: BOB.pub,
    });
    assert.notDeepEqual(
      Array.from(keys.outboundKeyBytes),
      Array.from(keys.inboundKeyBytes),
    );
    assert.notDeepEqual(
      Array.from(keys.outboundTagSeed),
      Array.from(keys.inboundTagSeed),
    );
  });

  it('Alice outbound matches Bob inbound (and vice versa)', async () => {
    const sAB = deriveSharedSecret(ALICE.priv, BOB.pub);
    const sBA = deriveSharedSecret(BOB.priv, ALICE.pub);
    const aliceSide = await derivePairKeys({
      sharedSecret: sAB, appId: TEST_APP,
      selfSharePub: ALICE.pub, peerSharePub: BOB.pub,
    });
    const bobSide = await derivePairKeys({
      sharedSecret: sBA, appId: TEST_APP,
      selfSharePub: BOB.pub, peerSharePub: ALICE.pub,
    });
    // Alice's outbound (Alice→Bob) must equal Bob's inbound (Bob reads Alice).
    assert.deepEqual(
      Array.from(aliceSide.outboundKeyBytes),
      Array.from(bobSide.inboundKeyBytes),
    );
    assert.deepEqual(
      Array.from(aliceSide.outboundTagSeed),
      Array.from(bobSide.inboundTagSeed),
    );
    // Symmetric: Bob's outbound (Bob→Alice) must equal Alice's inbound.
    assert.deepEqual(
      Array.from(bobSide.outboundKeyBytes),
      Array.from(aliceSide.inboundKeyBytes),
    );
    assert.deepEqual(
      Array.from(bobSide.outboundTagSeed),
      Array.from(aliceSide.inboundTagSeed),
    );
    // Roles are opposite — exactly one side is "forward".
    assert.notEqual(aliceSide.role, bobSide.role);
  });

  it('per-app isolation: same shared secret + different app_id → distinct keys', async () => {
    const sharedSecret = deriveSharedSecret(ALICE.priv, BOB.pub);
    const a = await derivePairKeys({
      sharedSecret, appId: TEST_APP,
      selfSharePub: ALICE.pub, peerSharePub: BOB.pub,
    });
    const b = await derivePairKeys({
      sharedSecret, appId: OTHER_APP,
      selfSharePub: ALICE.pub, peerSharePub: BOB.pub,
    });
    assert.notDeepEqual(
      Array.from(a.outboundKeyBytes), Array.from(b.outboundKeyBytes),
    );
    assert.notDeepEqual(
      Array.from(a.outboundTagSeed), Array.from(b.outboundTagSeed),
    );
  });

  it('rejects pairing with self', async () => {
    const sharedSecret = new Uint8Array(32).fill(1); // dummy, not used past arg check
    await assert.rejects(() => derivePairKeys({
      sharedSecret, appId: TEST_APP,
      selfSharePub: ALICE.pub, peerSharePub: ALICE.pub,
    }));
  });
});

// ============ deriveLogTag ============

describe('deriveLogTag', () => {
  it('returns 43-char base64url for 32-byte HMAC output', async () => {
    const seed = new Uint8Array(32).fill(0x42);
    const tag = await deriveLogTag(seed, 0);
    assert.equal(tag.length, 43);
    assert.match(tag, /^[A-Za-z0-9_-]{43}$/);
  });

  it('is deterministic for (seed, seq)', async () => {
    const seed = new Uint8Array(32).fill(0x55);
    const a = await deriveLogTag(seed, 7);
    const b = await deriveLogTag(seed, 7);
    assert.equal(a, b);
  });

  it('different seq produces different tags', async () => {
    const seed = new Uint8Array(32).fill(0x55);
    const t0 = await deriveLogTag(seed, 0);
    const t1 = await deriveLogTag(seed, 1);
    const t100 = await deriveLogTag(seed, 100);
    assert.notEqual(t0, t1);
    assert.notEqual(t0, t100);
    assert.notEqual(t1, t100);
  });

  it('different seeds produce different tags at the same seq', async () => {
    const seedA = new Uint8Array(32).fill(0x11);
    const seedB = new Uint8Array(32).fill(0x22);
    const t1 = await deriveLogTag(seedA, 5);
    const t2 = await deriveLogTag(seedB, 5);
    assert.notEqual(t1, t2);
  });

  it('rejects malformed inputs', async () => {
    await assert.rejects(() => deriveLogTag(new Uint8Array(31), 0));
    await assert.rejects(() => deriveLogTag(new Uint8Array(32), -1));
    await assert.rejects(() => deriveLogTag(new Uint8Array(32), 1.5));
  });
});

// ============ canonicalJSONStringify ============

describe('canonicalJSONStringify', () => {
  it('sorts object keys lexicographically', () => {
    assert.equal(
      canonicalJSONStringify({ b: 1, a: 2 }),
      '{"a":2,"b":1}',
    );
  });

  it('produces identical output regardless of construction order', () => {
    const o1 = { a: 1, b: 2, c: 3 };
    const o2 = {};
    o2.c = 3; o2.b = 2; o2.a = 1;
    assert.equal(canonicalJSONStringify(o1), canonicalJSONStringify(o2));
  });

  it('recurses into nested objects + arrays', () => {
    assert.equal(
      canonicalJSONStringify({ outer: { z: 1, a: 2 }, list: [{ b: 1, a: 2 }] }),
      '{"list":[{"a":2,"b":1}],"outer":{"a":2,"z":1}}',
    );
  });

  it('handles primitives + null', () => {
    assert.equal(canonicalJSONStringify(null), 'null');
    assert.equal(canonicalJSONStringify(true), 'true');
    assert.equal(canonicalJSONStringify(false), 'false');
    assert.equal(canonicalJSONStringify(42), '42');
    assert.equal(canonicalJSONStringify('hi'), '"hi"');
  });

  it('drops undefined entries from objects', () => {
    assert.equal(
      canonicalJSONStringify({ a: 1, b: undefined, c: 3 }),
      '{"a":1,"c":3}',
    );
  });

  it('rejects NaN, Infinity, functions', () => {
    assert.throws(() => canonicalJSONStringify(NaN));
    assert.throws(() => canonicalJSONStringify(Infinity));
    assert.throws(() => canonicalJSONStringify(() => 1));
  });

  it('canonicalJSONBytes returns matching UTF-8 bytes', () => {
    const value = { a: 'x', b: 1 };
    const expected = '{"a":"x","b":1}';
    const bytes = canonicalJSONBytes(value);
    const decoded = new TextDecoder().decode(bytes);
    assert.equal(decoded, expected);
  });

  it('determinism across runs (same inputs → same bytes)', () => {
    const value = { z: { a: 1, b: 2 }, m: [1, 2, { x: 1, y: 2 }], a: 'hello' };
    const a = canonicalJSONStringify(value);
    const b = canonicalJSONStringify(value);
    const c = canonicalJSONStringify(JSON.parse(JSON.stringify(value)));
    assert.equal(a, b);
    assert.equal(a, c);
  });
});

// ============ signOperation + verifyOperationSignature ============

describe('signOperation + verifyOperationSignature', () => {
  it('round-trips for an `add` operation', async () => {
    const { privateKey, publicKey } = await freshSigningKey();
    const pubB64 = await exportSpkiBase64(publicKey);
    const op = buildOperationUnsigned({
      type: OP_ADD,
      seq: 0,
      content_id: 'book-42',
      tx_id: 'arweave-tx-abc',
      cek: bytesToBase64Url(new Uint8Array(32).fill(7)),
      shared_at: 1714230000,
    });
    const signed = await signOperation(op, privateKey);
    assert.ok(signed.signature);
    assert.equal(typeof signed.signature, 'string');
    const ok = await verifyOperationSignature(signed, pubB64);
    assert.equal(ok, true);
  });

  it('fails verification when signature is tampered', async () => {
    const { privateKey, publicKey } = await freshSigningKey();
    const pubB64 = await exportSpkiBase64(publicKey);
    const op = buildOperationUnsigned({
      type: OP_REMOVE, seq: 5, content_id: 'book-9', removed_at: 1714230000,
    });
    const signed = await signOperation(op, privateKey);
    // Flip a bit in the signature.
    const sigBytes = base64UrlToBytes(signed.signature);
    sigBytes[5] ^= 0x01;
    const tampered = { ...signed, signature: bytesToBase64Url(sigBytes) };
    assert.equal(await verifyOperationSignature(tampered, pubB64), false);
  });

  it('fails verification when seq is changed (seq is in sig_input)', async () => {
    const { privateKey, publicKey } = await freshSigningKey();
    const pubB64 = await exportSpkiBase64(publicKey);
    const op = buildOperationUnsigned({
      type: OP_REMOVE, seq: 5, content_id: 'book-9', removed_at: 1714230000,
    });
    const signed = await signOperation(op, privateKey);
    const tampered = { ...signed, seq: 6 };
    assert.equal(await verifyOperationSignature(tampered, pubB64), false);
  });

  it('fails verification when an operation field is changed', async () => {
    const { privateKey, publicKey } = await freshSigningKey();
    const pubB64 = await exportSpkiBase64(publicKey);
    const op = buildOperationUnsigned({
      type: OP_REMOVE, seq: 5, content_id: 'book-9', removed_at: 1714230000,
    });
    const signed = await signOperation(op, privateKey);
    const tampered = { ...signed, content_id: 'book-evil' };
    assert.equal(await verifyOperationSignature(tampered, pubB64), false);
  });

  it('fails verification under a different signing key', async () => {
    const alice = await freshSigningKey();
    const bob = await freshSigningKey();
    const bobPubB64 = await exportSpkiBase64(bob.publicKey);
    const op = buildOperationUnsigned({
      type: OP_REMOVE, seq: 5, content_id: 'book-9', removed_at: 1714230000,
    });
    const signed = await signOperation(op, alice.privateKey);
    assert.equal(await verifyOperationSignature(signed, bobPubB64), false);
  });

  it('canonical bytes are stable across construction order', async () => {
    const a = buildOperationUnsigned({
      type: OP_ADD, seq: 0,
      content_id: 'x', tx_id: 'tx1',
      cek: bytesToBase64Url(new Uint8Array(32)),
      shared_at: 1714230000,
    });
    // Construct the same operation with shuffled extras in the input — the
    // builder normalizes to the canonical key set.
    const b = buildOperationUnsigned({
      shared_at: 1714230000,
      cek: bytesToBase64Url(new Uint8Array(32)),
      tx_id: 'tx1',
      content_id: 'x',
      seq: 0,
      type: OP_ADD,
    });
    const aBytes = await computeSigInput(a);
    const bBytes = await computeSigInput(b);
    assert.deepEqual(Array.from(aBytes), Array.from(bBytes));
  });
});

// ============ Operation types ============

describe('buildOperationUnsigned: all five normal types + rotate_identity', () => {
  const baseSeq = 3;

  it('add', () => {
    const op = buildOperationUnsigned({
      type: OP_ADD, seq: baseSeq,
      content_id: 'c', tx_id: 't',
      cek: bytesToBase64Url(new Uint8Array(32).fill(1)),
      shared_at: 1714000000,
    });
    assert.equal(op.type, 'add');
    assert.equal(op.seq, baseSeq);
  });

  it('update', () => {
    const op = buildOperationUnsigned({
      type: OP_UPDATE, seq: baseSeq,
      content_id: 'c', tx_id: 't2', updated_at: 1714000001,
    });
    assert.equal(op.type, 'update');
    assert.equal(op.tx_id, 't2');
  });

  it('rotate', () => {
    const op = buildOperationUnsigned({
      type: OP_ROTATE, seq: baseSeq,
      content_id: 'c',
      cek: bytesToBase64Url(new Uint8Array(32).fill(9)),
      rotated_at: 1714000002,
    });
    assert.equal(op.type, 'rotate');
  });

  it('remove', () => {
    const op = buildOperationUnsigned({
      type: OP_REMOVE, seq: baseSeq, content_id: 'c', removed_at: 1714000003,
    });
    assert.equal(op.type, 'remove');
    assert.equal(op.content_id, 'c');
  });

  it('snapshot (with state)', () => {
    const op = buildOperationUnsigned({
      type: OP_SNAPSHOT, seq: baseSeq,
      state: {
        a: { tx_id: 'tx-a', cek: bytesToBase64Url(new Uint8Array(32).fill(1)) },
        b: { tx_id: 'tx-b', cek: bytesToBase64Url(new Uint8Array(32).fill(2)) },
      },
      snapshot_at: 1714000004,
      prior_seq: baseSeq - 1,
    });
    assert.equal(op.type, 'snapshot');
    assert.equal(op.prior_seq, baseSeq - 1);
    assert.deepEqual(Object.keys(op.state).sort(), ['a', 'b']);
  });

  it('snapshot at seq=0 with prior_seq=null (initial-state snapshot, §6.6)', () => {
    const op = buildOperationUnsigned({
      type: OP_SNAPSHOT, seq: 0,
      state: {},
      snapshot_at: 1714000004,
      prior_seq: null,
    });
    assert.equal(op.seq, 0);
    assert.equal(op.prior_seq, null);
  });

  it('rotate_identity is recognized (parses without error) — emitted by 5d', () => {
    assert.ok(KNOWN_OP_TYPES.has(OP_ROTATE_IDENTITY));
    const op = buildOperationUnsigned({
      type: OP_ROTATE_IDENTITY, seq: baseSeq,
      new_share_pub: bytesToBase64Url(new Uint8Array(32).fill(0xab)),
      new_signing_pub: 'MFkw...somefakeSPKI...==',
      new_credential_lookup_key: 'a'.repeat(64),
      rotated_at: 1714000005,
    });
    assert.equal(op.type, 'rotate_identity');
    assert.equal(op.new_credential_lookup_key, 'a'.repeat(64));
  });

  it('rejects unknown operation types', () => {
    assert.throws(() => buildOperationUnsigned({ type: 'mystery', seq: 0 }));
  });

  it('rejects bad seq', () => {
    assert.throws(() => buildOperationUnsigned({
      type: OP_REMOVE, seq: -1, content_id: 'x', removed_at: 1,
    }));
    assert.throws(() => buildOperationUnsigned({
      type: OP_REMOVE, seq: 1.5, content_id: 'x', removed_at: 1,
    }));
  });

  it('rejects malformed cek (wrong length)', () => {
    assert.throws(() => buildOperationUnsigned({
      type: OP_ADD, seq: 0,
      content_id: 'c', tx_id: 't',
      cek: bytesToBase64Url(new Uint8Array(16)),
      shared_at: 1,
    }));
  });
});

// ============ encryptShareLogEntry / decryptShareLogEntry ============

describe('encrypt/decryptShareLogEntry round-trip', () => {
  it('round-trips an `add` entry under per-pair K_AB', async () => {
    const sharedSecret = deriveSharedSecret(ALICE.priv, BOB.pub);
    const aliceKeys = await derivePairKeys({
      sharedSecret, appId: TEST_APP,
      selfSharePub: ALICE.pub, peerSharePub: BOB.pub,
    });
    const sharedSecretBob = deriveSharedSecret(BOB.priv, ALICE.pub);
    const bobKeys = await derivePairKeys({
      sharedSecret: sharedSecretBob, appId: TEST_APP,
      selfSharePub: BOB.pub, peerSharePub: ALICE.pub,
    });

    const { privateKey, publicKey } = await freshSigningKey();
    const pubB64 = await exportSpkiBase64(publicKey);

    const op = buildOperationUnsigned({
      type: OP_ADD, seq: 0,
      content_id: 'book-42', tx_id: 'tx-abc',
      cek: bytesToBase64Url(new Uint8Array(32).fill(7)),
      shared_at: 1714230000,
    });
    const signed = await signOperation(op, privateKey);

    // Alice encrypts with her outbound key.
    const blob = await encryptShareLogEntry(signed, aliceKeys.outboundKey);
    // Bob decrypts with his inbound key (= Alice's outbound, sharing §4.5).
    const decoded = await decryptShareLogEntry(blob, bobKeys.inboundKey);
    assert.equal(decoded.content_id, 'book-42');
    assert.equal(decoded.seq, 0);
    const ok = await verifyOperationSignature(decoded, pubB64);
    assert.equal(ok, true);
  });

  it('Bob CANNOT decrypt with the wrong-direction key', async () => {
    const sAB = deriveSharedSecret(ALICE.priv, BOB.pub);
    const aliceKeys = await derivePairKeys({
      sharedSecret: sAB, appId: TEST_APP,
      selfSharePub: ALICE.pub, peerSharePub: BOB.pub,
    });
    const sBA = deriveSharedSecret(BOB.priv, ALICE.pub);
    const bobKeys = await derivePairKeys({
      sharedSecret: sBA, appId: TEST_APP,
      selfSharePub: BOB.pub, peerSharePub: ALICE.pub,
    });
    const { privateKey } = await freshSigningKey();

    const op = buildOperationUnsigned({
      type: OP_REMOVE, seq: 0, content_id: 'c', removed_at: 1,
    });
    const signed = await signOperation(op, privateKey);
    const blob = await encryptShareLogEntry(signed, aliceKeys.outboundKey);

    // Wrong direction: Bob's outbound (which equals Alice's inbound) — not
    // the stream Alice wrote.
    await assert.rejects(() => decryptShareLogEntry(blob, bobKeys.outboundKey));
  });

  it('a single bit flip in ciphertext fails decryption', async () => {
    const sAB = deriveSharedSecret(ALICE.priv, BOB.pub);
    const aliceKeys = await derivePairKeys({
      sharedSecret: sAB, appId: TEST_APP,
      selfSharePub: ALICE.pub, peerSharePub: BOB.pub,
    });
    const sBA = deriveSharedSecret(BOB.priv, ALICE.pub);
    const bobKeys = await derivePairKeys({
      sharedSecret: sBA, appId: TEST_APP,
      selfSharePub: BOB.pub, peerSharePub: ALICE.pub,
    });
    const { privateKey } = await freshSigningKey();

    const op = buildOperationUnsigned({
      type: OP_REMOVE, seq: 0, content_id: 'c', removed_at: 1,
    });
    const signed = await signOperation(op, privateKey);
    const blob = await encryptShareLogEntry(signed, aliceKeys.outboundKey);
    blob[blob.length - 1] ^= 0x01; // flip last bit (in the GCM tag)

    await assert.rejects(() => decryptShareLogEntry(blob, bobKeys.inboundKey));
  });

  it('all five operation types round-trip end-to-end', async () => {
    const sAB = deriveSharedSecret(ALICE.priv, BOB.pub);
    const aliceKeys = await derivePairKeys({
      sharedSecret: sAB, appId: TEST_APP,
      selfSharePub: ALICE.pub, peerSharePub: BOB.pub,
    });
    const sBA = deriveSharedSecret(BOB.priv, ALICE.pub);
    const bobKeys = await derivePairKeys({
      sharedSecret: sBA, appId: TEST_APP,
      selfSharePub: BOB.pub, peerSharePub: ALICE.pub,
    });
    const { privateKey, publicKey } = await freshSigningKey();
    const pubB64 = await exportSpkiBase64(publicKey);

    const ops = [
      {
        type: OP_ADD, seq: 0, content_id: 'a', tx_id: 'tx-a',
        cek: bytesToBase64Url(new Uint8Array(32).fill(1)), shared_at: 1,
      },
      { type: OP_UPDATE, seq: 1, content_id: 'a', tx_id: 'tx-a-v2', updated_at: 2 },
      {
        type: OP_ROTATE, seq: 2, content_id: 'a',
        cek: bytesToBase64Url(new Uint8Array(32).fill(9)), rotated_at: 3,
      },
      { type: OP_REMOVE, seq: 3, content_id: 'a', removed_at: 4 },
      {
        type: OP_SNAPSHOT, seq: 4,
        state: {
          a: { tx_id: 'tx-a-v2', cek: bytesToBase64Url(new Uint8Array(32).fill(9)) },
        },
        snapshot_at: 5, prior_seq: 3,
      },
    ];
    for (const fields of ops) {
      const op = buildOperationUnsigned(fields);
      const signed = await signOperation(op, privateKey);
      const blob = await encryptShareLogEntry(signed, aliceKeys.outboundKey);
      const decoded = await decryptShareLogEntry(blob, bobKeys.inboundKey);
      assert.equal(decoded.type, fields.type);
      assert.equal(decoded.seq, fields.seq);
      const ok = await verifyOperationSignature(decoded, pubB64);
      assert.equal(ok, true, `signature verify failed for ${fields.type}`);
    }
  });
});

// ============ shouldEmitSnapshot (compaction §8.6) ============

describe('shouldEmitSnapshot', () => {
  it('returns false when below the default interval', () => {
    assert.equal(shouldEmitSnapshot({ nonSnapshotsSinceLastSnapshot: 99 }), false);
  });
  it('returns true at the default interval', () => {
    assert.equal(
      shouldEmitSnapshot({ nonSnapshotsSinceLastSnapshot: DEFAULT_COMPACTION_INTERVAL }),
      true,
    );
  });
  it('respects a custom interval', () => {
    assert.equal(
      shouldEmitSnapshot({ nonSnapshotsSinceLastSnapshot: 5, compactionInterval: 10 }),
      false,
    );
    assert.equal(
      shouldEmitSnapshot({ nonSnapshotsSinceLastSnapshot: 10, compactionInterval: 10 }),
      true,
    );
  });
  it('rejects bad interval', () => {
    assert.throws(() => shouldEmitSnapshot({
      nonSnapshotsSinceLastSnapshot: 1, compactionInterval: 0,
    }));
  });
});
