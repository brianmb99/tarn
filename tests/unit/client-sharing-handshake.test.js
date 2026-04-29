// Unit tests for the friend handshake crypto primitives (issue #14, Section 5a).
//
// Covers:
//   - HPKE round-trip (seal + open) with raw 32-byte X25519 key bytes
//   - HPKE info-string binding (request blob can't be opened as accept)
//   - Inbox tag derivation: shape, determinism, per-recipient/per-app/per-window
//     differentiation
//   - Friend request + accept payload construction and validation, including
//     timestamp window enforcement (sharing §13.8) and per-app isolation
//   - Replay-nonce cache: first hit succeeds, repeat is flagged, expired
//     entries evicted
//   - Forged-accept detection: cross-reference against outbound pending list
//     (sharing §13.9)
//   - Friends + pending records: empty initialization, idempotent upsert,
//     remove path
//
// Run: node --test tests/unit/client-sharing-handshake.test.js

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { deriveSharingKeyPair } from '../../client/src/crypto.js';
import {
  hpkeSeal,
  hpkeOpen,
  INFO_FRIEND_REQUEST,
  INFO_FRIEND_ACCEPT,
  deriveInboxTag,
  inboxWindowFor,
  currentInboxWindow,
  recentInboxWindows,
  buildFriendRequestPayload,
  validateFriendRequestPayload,
  buildFriendAcceptPayload,
  validateFriendAcceptPayload,
  makeReplayNonceCache,
  checkAndRecordNonce,
  REPLAY_PAST_WINDOW_SEC,
  REPLAY_FUTURE_WINDOW_SEC,
  findOutboundForAccept,
  emptyFriendsRecord,
  emptyPendingRequestsRecord,
  upsertFriend,
  addOutboundPending,
  addInboundPending,
  removeOutboundPending,
  removeInboundPending,
  FRIENDS_CONTENT_ID,
  PENDING_REQUESTS_CONTENT_ID,
} from '../../client/src/sharing.js';
import {
  bytesToBase64Url,
  base64UrlToBytes,
} from '../../client/src/crypto.js';

function fixedMasterKey(seed = 0) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = (seed * 7 + i * 17 + 1) & 0xff;
  return out;
}

// Build an X25519 keypair via the SDK's own derivation. We don't import
// @noble/curves directly because it's a transitive dependency of the client
// package, not the tests folder — Node's resolution rules surface that as a
// hard error at the top of the test file otherwise. Going through
// deriveSharingKeyPair gives us the same X25519 primitive (the underlying
// implementation lives in @noble/curves/ed25519) without the resolution
// hassle and matches the production code path.
async function makeKeypair(seed) {
  const mk = fixedMasterKey(seed);
  const { privateKey, publicKey } = await deriveSharingKeyPair(mk, `seed-${seed}`);
  return { priv: privateKey, pub: publicKey };
}

// Precompute the keypairs we use across describe blocks. `describe` callbacks
// are synchronous, so we generate everything we need at module-load time and
// reference these constants from the tests.
const KP = {};
for (const i of [1, 2, 3, 4, 5, 10, 11, 12, 13, 14, 15, 16, 20, 21, 30]) {
  KP[i] = await makeKeypair(i);
}
function keypairFromSeed(seed) {
  if (!KP[seed]) throw new Error(`No precomputed keypair for seed ${seed}`);
  return KP[seed];
}

// ============ HPKE round-trip ============

describe('hpkeSeal / hpkeOpen', () => {
  it('round-trips a small payload between two synthetic key pairs', async () => {
    const recipient = keypairFromSeed(1);
    const plaintext = new TextEncoder().encode('hello bob');
    const blob = await hpkeSeal({
      recipientSharePub: recipient.pub,
      info: INFO_FRIEND_REQUEST,
      plaintext,
    });
    assert.ok(blob instanceof Uint8Array);
    // 32 (enc) + 16 (AEAD tag) + plaintext bytes = at least 57 for 9-byte plaintext
    assert.ok(blob.length >= 32 + 16 + plaintext.length, `blob too short: ${blob.length}`);

    const pt = await hpkeOpen({
      sharePriv: recipient.priv,
      info: INFO_FRIEND_REQUEST,
      blob,
    });
    assert.equal(new TextDecoder().decode(pt), 'hello bob');
  });

  it('opening with the wrong private key fails (AEAD authenticity)', async () => {
    const correct = keypairFromSeed(2);
    const wrong = keypairFromSeed(3);
    const blob = await hpkeSeal({
      recipientSharePub: correct.pub,
      info: INFO_FRIEND_REQUEST,
      plaintext: new TextEncoder().encode('secret'),
    });
    await assert.rejects(() => hpkeOpen({
      sharePriv: wrong.priv,
      info: INFO_FRIEND_REQUEST,
      blob,
    }));
  });

  it('opening with the wrong info string fails (info binding)', async () => {
    // Sealing under "tarn-connection-request-v1" must NOT open as
    // "tarn-connection-accept-v1" — defense against an attacker re-tagging a
    // captured request blob and re-publishing as an accept.
    const recipient = keypairFromSeed(4);
    const blob = await hpkeSeal({
      recipientSharePub: recipient.pub,
      info: INFO_FRIEND_REQUEST,
      plaintext: new TextEncoder().encode('hi'),
    });
    await assert.rejects(() => hpkeOpen({
      sharePriv: recipient.priv,
      info: INFO_FRIEND_ACCEPT,
      blob,
    }));
  });

  it('rejects malformed blob (too short, missing AEAD tag)', async () => {
    const recipient = keypairFromSeed(5);
    await assert.rejects(() => hpkeOpen({
      sharePriv: recipient.priv,
      info: INFO_FRIEND_REQUEST,
      blob: new Uint8Array(20),
    }), /too short/);
  });
});

// ============ Inbox tag derivation ============

describe('deriveInboxTag', () => {
  const APP = 'bookish';

  it('produces a 43-char base64url string (32 bytes HMAC-SHA-256)', async () => {
    const { pub } = keypairFromSeed(10);
    const tag = await deriveInboxTag(pub, APP, 12345);
    assert.equal(typeof tag, 'string');
    assert.equal(tag.length, 43);
    assert.match(tag, /^[A-Za-z0-9_-]+$/);
  });

  it('is deterministic for the same (recipient, app, window)', async () => {
    const { pub } = keypairFromSeed(11);
    const a = await deriveInboxTag(pub, APP, 100);
    const b = await deriveInboxTag(pub, APP, 100);
    assert.equal(a, b);
  });

  it('differs across recipients (same app + window)', async () => {
    const a = await deriveInboxTag(keypairFromSeed(12).pub, APP, 100);
    const b = await deriveInboxTag(keypairFromSeed(13).pub, APP, 100);
    assert.notEqual(a, b);
  });

  it('differs across apps (same recipient + window) — per-app isolation', async () => {
    // The acceptance criterion: a Bookish friend request cannot bootstrap a
    // Cellar handshake. Different app_id in the HMAC info → different tag,
    // so a Bookish-app sender would write to the wrong inbox if it tried to
    // contact the same recipient via the Cellar inbox (and vice versa).
    const { pub } = keypairFromSeed(14);
    const a = await deriveInboxTag(pub, 'bookish', 100);
    const b = await deriveInboxTag(pub, 'cellar', 100);
    assert.notEqual(a, b);
  });

  it('differs across windows (same recipient + app) — rolling tag', async () => {
    const { pub } = keypairFromSeed(15);
    const a = await deriveInboxTag(pub, APP, 100);
    const b = await deriveInboxTag(pub, APP, 101);
    assert.notEqual(a, b);
  });

  it('rejects non-32-byte recipient public keys', async () => {
    await assert.rejects(() => deriveInboxTag(new Uint8Array(31), APP, 1), /32-byte/);
    await assert.rejects(() => deriveInboxTag(new Uint8Array(33), APP, 1), /32-byte/);
  });

  it('rejects negative or non-integer window', async () => {
    const { pub } = keypairFromSeed(16);
    await assert.rejects(() => deriveInboxTag(pub, APP, -1), /non-negative integer/);
    await assert.rejects(() => deriveInboxTag(pub, APP, 1.5), /non-negative integer/);
  });
});

describe('inbox windows', () => {
  it('inboxWindowFor() floors unix seconds by 86400', () => {
    assert.equal(inboxWindowFor(0), 0);
    assert.equal(inboxWindowFor(86400), 1);
    assert.equal(inboxWindowFor(86399), 0);
    assert.equal(inboxWindowFor(86400 * 30 + 1), 30);
  });

  it('currentInboxWindow() == floor(Date.now()/1000/86400)', () => {
    const now = 1745812800000; // 2025-04-28 00:00:00 UTC
    const expected = Math.floor(now / 1000 / 86400);
    assert.equal(currentInboxWindow(now), expected);
  });

  it('recentInboxWindows() returns N descending windows ending at current', () => {
    const now = 86400 * 1000 * 100; // window 100
    const out = recentInboxWindows(3, now);
    assert.deepEqual(out, [100, 99, 98]);
  });
});

// ============ Friend request payload ============

describe('buildFriendRequestPayload', () => {
  const senderPub = keypairFromSeed(20).pub;

  it('builds a well-formed payload with random nonce', () => {
    const p = buildFriendRequestPayload({
      senderEmail: 'alice@test.com',
      senderSharePub: senderPub,
      senderSigningPubBase64: 'fake-spki-base64',
      senderAppId: 'bookish',
      message: 'hi bob',
    });
    assert.equal(p.type, 'connection_request');
    assert.equal(p.sender_email, 'alice@test.com');
    assert.equal(p.sender_app_id, 'bookish');
    assert.equal(base64UrlToBytes(p.sender_share_pub).length, 32);
    assert.equal(base64UrlToBytes(p.nonce).length, 16);
    assert.equal(typeof p.timestamp, 'number');
    assert.equal(p.message, 'hi bob');
  });

  it('omits message when not supplied', () => {
    const p = buildFriendRequestPayload({
      senderEmail: 'a@b.c',
      senderSharePub: senderPub,
      senderSigningPubBase64: 'x',
      senderAppId: 'app',
    });
    assert.equal(p.message, undefined);
  });

  it('rejects oversized message', () => {
    assert.throws(() => buildFriendRequestPayload({
      senderEmail: 'a@b.c',
      senderSharePub: senderPub,
      senderSigningPubBase64: 'x',
      senderAppId: 'app',
      message: 'x'.repeat(281),
    }), /message exceeds/);
  });

  it('rejects 31-byte share_pub', () => {
    assert.throws(() => buildFriendRequestPayload({
      senderEmail: 'a@b.c',
      senderSharePub: new Uint8Array(31),
      senderSigningPubBase64: 'x',
      senderAppId: 'app',
    }), /32-byte/);
  });
});

describe('validateFriendRequestPayload', () => {
  const senderPub = keypairFromSeed(21).pub;
  const APP = 'bookish';

  function make(overrides = {}) {
    return {
      type: 'connection_request',
      sender_email: 'alice@test.com',
      sender_share_pub: bytesToBase64Url(senderPub),
      sender_signing_pub: 'spki-base64',
      sender_app_id: APP,
      nonce: bytesToBase64Url(new Uint8Array(16).fill(1)),
      timestamp: Math.floor(Date.now() / 1000),
      ...overrides,
    };
  }

  it('accepts a well-formed payload and returns normalized fields', () => {
    const v = validateFriendRequestPayload(make(), APP);
    assert.equal(v.valid, true);
    assert.equal(v.normalized.senderEmail, 'alice@test.com');
    assert.equal(v.normalized.senderAppId, APP);
    assert.ok(v.normalized.senderSharePub instanceof Uint8Array);
    assert.equal(v.normalized.senderSharePub.length, 32);
    assert.ok(v.normalized.nonce instanceof Uint8Array);
    assert.equal(v.normalized.nonce.length, 16);
    assert.equal(v.normalized.message, null);
  });

  it('rejects mismatched app_id (per-app isolation)', () => {
    const v = validateFriendRequestPayload(make({ sender_app_id: 'cellar' }), APP);
    assert.equal(v.valid, false);
    assert.match(v.reason, /sender_app_id/);
  });

  it('rejects timestamp older than 7 days (replay window)', () => {
    const tooOld = Math.floor(Date.now() / 1000) - REPLAY_PAST_WINDOW_SEC - 60;
    const v = validateFriendRequestPayload(make({ timestamp: tooOld }), APP);
    assert.equal(v.valid, false);
    assert.match(v.reason, /too old/);
  });

  it('rejects timestamp far in the future', () => {
    const future = Math.floor(Date.now() / 1000) + REPLAY_FUTURE_WINDOW_SEC + 60;
    const v = validateFriendRequestPayload(make({ timestamp: future }), APP);
    assert.equal(v.valid, false);
    assert.match(v.reason, /future/);
  });

  it('rejects wrong type field', () => {
    const v = validateFriendRequestPayload(make({ type: 'something_else' }), APP);
    assert.equal(v.valid, false);
    assert.match(v.reason, /wrong type/);
  });

  it('rejects 15-byte nonce', () => {
    const v = validateFriendRequestPayload(make({ nonce: bytesToBase64Url(new Uint8Array(15)) }), APP);
    assert.equal(v.valid, false);
    assert.match(v.reason, /nonce must be 16/);
  });

  it('rejects 31-byte share_pub', () => {
    const v = validateFriendRequestPayload(make({ sender_share_pub: bytesToBase64Url(new Uint8Array(31)) }), APP);
    assert.equal(v.valid, false);
    assert.match(v.reason, /sender_share_pub/);
  });

  it('rejects non-object input', () => {
    assert.equal(validateFriendRequestPayload(null, APP).valid, false);
    assert.equal(validateFriendRequestPayload('foo', APP).valid, false);
    assert.equal(validateFriendRequestPayload(123, APP).valid, false);
  });
});

// ============ Friend accept payload ============

describe('buildFriendAcceptPayload + validateFriendAcceptPayload', () => {
  const senderPub = keypairFromSeed(30).pub;
  const APP = 'bookish';

  it('round-trips through validate', () => {
    const inReplyTo = bytesToBase64Url(new Uint8Array(16).fill(2));
    const p = buildFriendAcceptPayload({
      senderEmail: 'bob@test.com',
      senderSharePub: senderPub,
      senderSigningPubBase64: 'spki',
      senderAppId: APP,
      inReplyToNonceBase64Url: inReplyTo,
    });
    assert.equal(p.type, 'connection_accept');
    assert.equal(p.in_reply_to, inReplyTo);

    const v = validateFriendAcceptPayload(p, APP);
    assert.equal(v.valid, true);
    assert.equal(v.normalized.inReplyToNonceBase64Url, inReplyTo);
  });

  it('rejects mismatched app_id', () => {
    const inReplyTo = bytesToBase64Url(new Uint8Array(16).fill(3));
    const p = buildFriendAcceptPayload({
      senderEmail: 'bob@test.com',
      senderSharePub: senderPub,
      senderSigningPubBase64: 'spki',
      senderAppId: 'cellar',
      inReplyToNonceBase64Url: inReplyTo,
    });
    const v = validateFriendAcceptPayload(p, APP);
    assert.equal(v.valid, false);
    assert.match(v.reason, /sender_app_id/);
  });
});

// ============ Replay-nonce cache (sharing §13.8) ============

describe('replay-nonce cache', () => {
  it('first occurrence is not a replay; repeat is flagged', () => {
    const c = makeReplayNonceCache();
    assert.deepEqual(checkAndRecordNonce(c, 'abc'), { replay: false });
    assert.deepEqual(checkAndRecordNonce(c, 'abc'), { replay: true });
    assert.deepEqual(checkAndRecordNonce(c, 'abc'), { replay: true });
  });

  it('different nonces are independent', () => {
    const c = makeReplayNonceCache();
    assert.deepEqual(checkAndRecordNonce(c, 'a'), { replay: false });
    assert.deepEqual(checkAndRecordNonce(c, 'b'), { replay: false });
    assert.deepEqual(checkAndRecordNonce(c, 'a'), { replay: true });
    assert.deepEqual(checkAndRecordNonce(c, 'c'), { replay: false });
  });

  it('expired entries are evicted on next access', () => {
    const c = makeReplayNonceCache();
    // Record at "now = 0"
    assert.deepEqual(checkAndRecordNonce(c, 'old', 0), { replay: false });
    // Far in the future, the old nonce should be evicted
    const farFuture = 86400 * 30; // 30 days later, well past TTL (7+1=8 days)
    assert.deepEqual(checkAndRecordNonce(c, 'old', farFuture), { replay: false });
  });

  it('rejects wrong cache shape', () => {
    assert.throws(() => checkAndRecordNonce(null, 'x'), /cache must be/);
    assert.throws(() => checkAndRecordNonce({}, 'x'), /cache must be/);
  });
});

// ============ Forged-accept detection (sharing §13.9) ============

describe('findOutboundForAccept', () => {
  it('matches on snake_case request_nonce (wire-format record shape)', () => {
    // The persisted pending record uses snake_case keys per sharing §7.2.
    const outbound = [
      { recipient_email: 'a@x.y', request_nonce: 'AAAA', sent_at: 1 },
      { recipient_email: 'b@x.y', request_nonce: 'BBBB', sent_at: 2 },
    ];
    assert.deepEqual(findOutboundForAccept('BBBB', outbound), outbound[1]);
  });

  it('also matches on camelCase requestNonce (UI/SDK view)', () => {
    const outbound = [
      { recipientEmail: 'a@x.y', requestNonce: 'AAAA' },
      { recipientEmail: 'b@x.y', requestNonce: 'BBBB' },
    ];
    assert.deepEqual(findOutboundForAccept('BBBB', outbound), outbound[1]);
  });

  it('returns null when no matching outbound exists (forged accept)', () => {
    const outbound = [{ request_nonce: 'AAAA' }];
    assert.equal(findOutboundForAccept('BBBB', outbound), null);
  });

  it('returns null on empty pending list', () => {
    assert.equal(findOutboundForAccept('AAAA', []), null);
  });

  it('returns null on non-string inReplyTo', () => {
    assert.equal(findOutboundForAccept(null, [{ request_nonce: 'AAAA' }]), null);
  });
});

// ============ Friends + pending records ============

describe('friends record', () => {
  it('emptyFriendsRecord() shape', () => {
    const r = emptyFriendsRecord('bookish');
    assert.equal(r.app_id, 'bookish');
    assert.equal(r.version, 1);
    assert.deepEqual(r.friends, []);
  });

  it('upsertFriend() adds a new friend', () => {
    const r = emptyFriendsRecord('bookish');
    const out = upsertFriend(r, { email: 'a@x.y', share_pub: 'pub-A', signing_pub: 's', established_at: 1, initial_request_nonce: 'n' });
    assert.equal(out.friends.length, 1);
    assert.equal(out.friends[0].email, 'a@x.y');
    // Original record is unchanged (immutability).
    assert.equal(r.friends.length, 0);
  });

  it('upsertFriend() replaces by share_pub (idempotent)', () => {
    let r = emptyFriendsRecord('bookish');
    r = upsertFriend(r, { email: 'a@x.y', share_pub: 'pub-A', signing_pub: 's1', established_at: 1, initial_request_nonce: 'n' });
    r = upsertFriend(r, { email: 'a@x.y', share_pub: 'pub-A', signing_pub: 's2', established_at: 2, initial_request_nonce: 'n' });
    assert.equal(r.friends.length, 1);
    assert.equal(r.friends[0].signing_pub, 's2');
  });

  it('upsertFriend() differentiates distinct share_pub values', () => {
    let r = emptyFriendsRecord('bookish');
    r = upsertFriend(r, { email: 'a@x.y', share_pub: 'pub-A', signing_pub: 's', established_at: 1, initial_request_nonce: 'n' });
    r = upsertFriend(r, { email: 'b@x.y', share_pub: 'pub-B', signing_pub: 's', established_at: 1, initial_request_nonce: 'n' });
    assert.equal(r.friends.length, 2);
  });

  it('rejects malformed input', () => {
    assert.throws(() => upsertFriend(null, {}));
    assert.throws(() => upsertFriend(emptyFriendsRecord('bookish'), {}));
  });
});

describe('pending requests record', () => {
  it('emptyPendingRequestsRecord() shape', () => {
    const r = emptyPendingRequestsRecord('bookish');
    assert.equal(r.app_id, 'bookish');
    assert.deepEqual(r.outbound, []);
    assert.deepEqual(r.inbound, []);
  });

  it('addOutboundPending + removeOutboundPending', () => {
    let r = emptyPendingRequestsRecord('bookish');
    r = addOutboundPending(r, { request_nonce: 'AAAA', recipient_email: 'a@x.y' });
    r = addOutboundPending(r, { request_nonce: 'BBBB', recipient_email: 'b@x.y' });
    assert.equal(r.outbound.length, 2);
    // Idempotent on duplicate nonce.
    r = addOutboundPending(r, { request_nonce: 'AAAA', recipient_email: 'a@x.y' });
    assert.equal(r.outbound.length, 2);
    r = removeOutboundPending(r, 'AAAA');
    assert.equal(r.outbound.length, 1);
    assert.equal(r.outbound[0].request_nonce, 'BBBB');
  });

  it('addInboundPending + removeInboundPending', () => {
    let r = emptyPendingRequestsRecord('bookish');
    r = addInboundPending(r, { request_nonce: 'X', sender_email: 'a@x.y' });
    r = addInboundPending(r, { request_nonce: 'Y', sender_email: 'b@x.y' });
    assert.equal(r.inbound.length, 2);
    r = addInboundPending(r, { request_nonce: 'X', sender_email: 'a@x.y' });
    assert.equal(r.inbound.length, 2);
    r = removeInboundPending(r, 'X');
    assert.equal(r.inbound.length, 1);
  });

  it('content_id constants are stable', () => {
    assert.equal(FRIENDS_CONTENT_ID, 'tarn-connections-v1');
    assert.equal(PENDING_REQUESTS_CONTENT_ID, 'tarn-pending-requests-v1');
  });
});
