// Virtual WebAuthn authenticator for integration tests.
//
// Drives the full passkey flow against the live API by impersonating a
// platform authenticator: holds an EC P-256 keypair per credential, builds
// CBOR-encoded attestation objects + authenticator data, and produces
// ECDSA signatures that pass @simplewebauthn/server's verification.
//
// PRF model
// ---------
// Real authenticators implement PRF as HMAC-SHA-256 keyed by a secret the
// authenticator generates at registration time, evaluated against a salt
// the RP supplies. We mirror that exactly: each credential gets a random
// 32-byte `prfSecret`, and `prfEvaluate(salt) = HMAC-SHA-256(prfSecret, salt)`.
// This is deterministic per (credential, salt) — same as the real flow.
//
// Wire surface
// ------------
// `register({rpId, origin, challenge, prfSalt})` returns the SAME shape the
// SDK gets back from `@simplewebauthn/browser`'s `startRegistration()`:
// base64url id/rawId, base64url-encoded attestationObject + clientDataJSON,
// type 'public-key', and `clientExtensionResults.prf.results.first` as an
// ArrayBuffer.
//
// `authenticate({rpId, origin, challenge, prfSalt})` returns the
// `startAuthentication()` shape: signature is DER-encoded ECDSA-with-SHA256
// (which @simplewebauthn/server unwraps to raw r||s before verification).
//
// Sign-count semantics: per WebAuthn spec, each assertion increments the
// counter. Some real authenticators (synced passkeys) keep it at 0 — we
// increment by 1 each call to mirror a hardware authenticator. Tests that
// want regression behavior can rewind via `setSignCount()`.

import * as nodeCrypto from 'node:crypto';
// `@simplewebauthn/server` is installed under api/node_modules (not at the
// repo root), so we resolve it via a relative path. This keeps the test
// dep-free at the workspace level — we reuse the API's CBOR encoder
// rather than vendoring tiny-cbor ourselves.
import { isoCBOR } from '../../api/node_modules/@simplewebauthn/server/esm/helpers/index.js';

// --------------- Helpers ---------------

function bytesToBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(b64url) {
  const padded = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  return new Uint8Array(Buffer.from(padded + '='.repeat(padLen), 'base64'));
}

function bytesToBuffer(bytes) {
  // ArrayBuffer copy — the @simplewebauthn/browser code passes
  // BufferSources to navigator.credentials, and our shim hands the same
  // shapes back. Node's Uint8Array doesn't always carry an
  // ArrayBuffer-only `.buffer` (it can share with a larger pool), so make
  // a fresh ArrayBuffer slice.
  const ab = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(ab).set(bytes);
  return ab;
}

function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.byteLength;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.byteLength; }
  return out;
}

function sha256(bytes) {
  return new Uint8Array(nodeCrypto.createHash('sha256').update(bytes).digest());
}

function hmacSha256(key, msg) {
  return new Uint8Array(
    nodeCrypto.createHmac('sha256', Buffer.from(key)).update(Buffer.from(msg)).digest()
  );
}

// --------------- COSE EC2 public-key encoder ---------------

const COSE_KTY = 1;
const COSE_ALG = 3;
const COSE_CRV = -1;
const COSE_X = -2;
const COSE_Y = -3;
const COSE_KTY_EC2 = 2;
const COSE_ALG_ES256 = -7;
const COSE_CRV_P256 = 1;

/**
 * Take a Node ECDSA (P-256) public key (KeyObject) and produce the COSE
 * EC2 CBOR-encoded form @simplewebauthn/server expects in the credential
 * public-key slot of authenticatorData.
 */
function encodeCoseEC2PublicKey(publicKey) {
  // Export as JWK to extract x/y in raw 32-byte form.
  const jwk = publicKey.export({ format: 'jwk' });
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error(`encodeCoseEC2PublicKey: expected EC P-256, got ${jwk.kty}/${jwk.crv}`);
  }
  const x = base64UrlToBytes(jwk.x);
  const y = base64UrlToBytes(jwk.y);
  if (x.length !== 32 || y.length !== 32) {
    throw new Error(`encodeCoseEC2PublicKey: x/y must be 32 bytes, got ${x.length}/${y.length}`);
  }
  // tiny-cbor takes a Map for the CBOR Map type.
  const m = new Map();
  m.set(COSE_KTY, COSE_KTY_EC2);
  m.set(COSE_ALG, COSE_ALG_ES256);
  m.set(COSE_CRV, COSE_CRV_P256);
  m.set(COSE_X, x);
  m.set(COSE_Y, y);
  return new Uint8Array(isoCBOR.encode(m));
}

// --------------- authenticatorData ---------------

// AAGUID for our virtual authenticator. WebAuthn spec says zero AAGUID is
// allowed for "unknown" authenticators; using all-zero keeps the wire
// shape small and predictable.
const VIRTUAL_AAGUID = new Uint8Array(16);

const FLAG_UP = 1 << 0;       // user presence
const FLAG_UV = 1 << 2;       // user verified
const FLAG_AT = 1 << 6;       // attested credential data present
const FLAG_BE = 1 << 3;       // backup eligible — set so backup-flag parser doesn't trip
const FLAG_BS = 1 << 4;       // backup state
const FLAG_ED = 1 << 7;       // extension data present (we don't use)

function buildAuthenticatorData({
  rpId,
  flags,
  signCount,
  credentialId,           // Uint8Array (raw, not base64)
  credentialPublicKey,    // Uint8Array (COSE-encoded) — only present at register time
}) {
  const rpIdHash = sha256(new TextEncoder().encode(rpId));
  const flagsByte = new Uint8Array([flags]);
  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, signCount, false);

  if (credentialPublicKey) {
    // Attested credential data: AAGUID(16) + credIdLen(2 BE) + credId + COSE pubkey
    const credIdLenBytes = new Uint8Array(2);
    new DataView(credIdLenBytes.buffer).setUint16(0, credentialId.length, false);
    return concatBytes(
      rpIdHash, flagsByte, counterBytes,
      VIRTUAL_AAGUID, credIdLenBytes, credentialId, credentialPublicKey,
    );
  }
  // Auth-time: just rpIdHash + flags + counter (no `at` flag, no
  // attested credential data section).
  return concatBytes(rpIdHash, flagsByte, counterBytes);
}

// --------------- VirtualAuthenticator ---------------

export class VirtualAuthenticator {
  constructor() {
    // Each instance models ONE registered credential. Multi-credential
    // testing instantiates multiple authenticators.
    this.credentialId = nodeCrypto.randomBytes(32);   // raw bytes
    this.credentialIdB64Url = bytesToBase64Url(this.credentialId);
    const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.prfSecret = nodeCrypto.randomBytes(32);
    this.signCount = 0;
  }

  /**
   * Inject a passkey-shaped credential into a `navigator.credentials.create`
   * call. The SDK calls `startRegistration()` which calls
   * `navigator.credentials.create()`; this method returns the
   * PublicKeyCredential-shaped object that helper expects.
   *
   * Caller supplies the rpId/origin/challenge/prfSalt the SDK pulled out
   * of the server's options payload.
   */
  buildRegistrationResponse({ rpId, origin, challenge, prfSalt }) {
    // clientDataJSON (UTF-8 encoded JSON).
    const clientData = {
      type: 'webauthn.create',
      challenge,                    // already base64url
      origin,
      crossOrigin: false,
    };
    const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));

    const cosePub = encodeCoseEC2PublicKey(this.publicKey);
    // Don't increment signCount on registration — counter starts at 0.
    const authData = buildAuthenticatorData({
      rpId,
      flags: FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BE | FLAG_BS,
      signCount: 0,
      credentialId: this.credentialId,
      credentialPublicKey: cosePub,
    });

    // attestation object: { fmt: 'none', attStmt: {}, authData }
    const attestationMap = new Map();
    attestationMap.set('fmt', 'none');
    attestationMap.set('attStmt', new Map());
    attestationMap.set('authData', authData);
    const attestationObject = new Uint8Array(isoCBOR.encode(attestationMap));

    const prfOutput = hmacSha256(this.prfSecret, base64UrlToBytes(prfSalt));

    return this.#wrapAsPublicKeyCredential({
      // startRegistration reads `id` (string), `rawId` (BufferSource),
      // `type`, `response.attestationObject` + `response.clientDataJSON`
      // (BufferSources), `response.getTransports()` (optional),
      // `getClientExtensionResults()`.
      id: this.credentialIdB64Url,
      rawId: bytesToBuffer(this.credentialId),
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        attestationObject: bytesToBuffer(attestationObject),
        clientDataJSON: bytesToBuffer(clientDataJSON),
        getTransports: () => ['internal'],
        // The L3 helpers below are optional (try/catch'd in the SDK
        // wrapper) — return undefined to skip the optional codepaths.
      },
      clientExtensionResults: {
        prf: { results: { first: bytesToBuffer(prfOutput) } },
      },
    });
  }

  /**
   * Inject a passkey-shaped assertion into `navigator.credentials.get()`.
   */
  buildAuthenticationResponse({ rpId, origin, challenge, prfSalt, signCountOverride, signOverride, tamperSignature = false }) {
    const clientData = {
      type: 'webauthn.get',
      challenge,
      origin,
      crossOrigin: false,
    };
    const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));

    const counter = signCountOverride !== undefined ? signCountOverride : ++this.signCount;
    const authData = buildAuthenticatorData({
      rpId,
      flags: FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS,
      signCount: counter,
    });

    // ECDSA signature over authData || sha256(clientDataJSON), DER-encoded.
    let signature;
    if (signOverride) {
      signature = signOverride;
    } else {
      const clientDataHash = sha256(clientDataJSON);
      const data = concatBytes(authData, clientDataHash);
      signature = new Uint8Array(
        nodeCrypto.sign('sha256', Buffer.from(data), this.privateKey),
      );
    }
    if (tamperSignature && signature.length > 8) {
      // Flip the last byte to make verification fail without changing
      // shape. Done after the signature is generated.
      signature = new Uint8Array(signature);
      signature[signature.length - 1] ^= 0xff;
    }

    const prfOutput = hmacSha256(this.prfSecret, base64UrlToBytes(prfSalt));

    return this.#wrapAsPublicKeyCredential({
      id: this.credentialIdB64Url,
      rawId: bytesToBuffer(this.credentialId),
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        authenticatorData: bytesToBuffer(authData),
        clientDataJSON: bytesToBuffer(clientDataJSON),
        signature: bytesToBuffer(signature),
        userHandle: null,
      },
      clientExtensionResults: {
        prf: { results: { first: bytesToBuffer(prfOutput) } },
      },
    });
  }

  /**
   * Wrap a plain object so it duck-types as a PublicKeyCredential —
   * `getClientExtensionResults()` is a method, but we hold the data on a
   * plain field so it survives JSON-style cloning.
   */
  #wrapAsPublicKeyCredential(obj) {
    const ext = obj.clientExtensionResults;
    return {
      ...obj,
      clientExtensionResults: ext, // keep as field too
      getClientExtensionResults: () => ext,
    };
  }

  setSignCount(n) { this.signCount = n; }
}

// --------------- Test environment shim ---------------

/**
 * Install a minimal `navigator.credentials` + `PublicKeyCredential` shim
 * that routes WebAuthn ceremonies through the supplied registry of
 * authenticators (keyed by base64url credential_id).
 *
 * Also patches `globalThis.fetch` to inject an `Origin` header on every
 * outbound request — Node's fetch doesn't set one, but the API's CORS +
 * passkey origin allowlist requires it. We only inject if no Origin is
 * already on the request.
 *
 * Returns the registry so tests can register/lookup authenticators.
 */
export function installPasskeyTestEnv({ origin = 'http://localhost:3000', rpId = 'localhost' } = {}) {
  const registry = new Map(); // credentialIdB64Url -> VirtualAuthenticator
  const state = {
    origin,
    rpId,
    // For a registration ceremony we don't yet know the credentialId —
    // the test stages the next "to-register" authenticator here.
    pendingRegistration: null,
    // For an auth ceremony, the test can pin which credential will
    // respond (default: first match in the allowCredentials list).
    nextAuthCredentialId: null,
    // Optional pre-call interceptors so a test can mutate the response
    // (e.g. tamper signature) without subclassing.
    onBeforeAuth: null,
    // Track all challenges seen — lets a test confirm replay protection.
    seenChallenges: [],
  };

  // Stash originals for restore.
  const originals = {
    navigator: globalThis.navigator,
    PublicKeyCredential: globalThis.PublicKeyCredential,
    fetch: globalThis.fetch,
  };

  // PublicKeyCredential must be a function (constructor) for
  // browserSupportsWebAuthn() to return true.
  function PublicKeyCredentialShim() {}
  PublicKeyCredentialShim.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
  PublicKeyCredentialShim.getClientCapabilities = async () => ({ prf: true });
  globalThis.PublicKeyCredential = PublicKeyCredentialShim;

  const credentials = {
    async create(opts) {
      const publicKey = opts?.publicKey;
      if (!publicKey) throw new Error('virtual authenticator: missing publicKey on create()');
      const challenge = bytesToBase64Url(new Uint8Array(publicKey.challenge));
      state.seenChallenges.push(challenge);
      const auth = state.pendingRegistration;
      if (!auth) {
        throw new Error(
          'virtual authenticator: no pendingRegistration staged — ' +
          'tests must call stageRegistration(authenticator) before triggering registerPasskey()',
        );
      }
      // PRF salt was supplied by the SDK via extensions — eval it.
      const prfSalt = publicKey.extensions?.prf?.eval?.first;
      if (!prfSalt) throw new Error('virtual authenticator: PRF salt missing from create() options');
      const prfSaltB64 = bytesToBase64Url(new Uint8Array(prfSalt));
      const cred = auth.buildRegistrationResponse({
        rpId: publicKey.rp?.id || state.rpId,
        origin: state.origin,
        challenge,
        prfSalt: prfSaltB64,
      });
      registry.set(auth.credentialIdB64Url, auth);
      state.pendingRegistration = null;
      return cred;
    },

    async get(opts) {
      const publicKey = opts?.publicKey;
      if (!publicKey) throw new Error('virtual authenticator: missing publicKey on get()');
      const challenge = bytesToBase64Url(new Uint8Array(publicKey.challenge));
      state.seenChallenges.push(challenge);

      let pickedB64;
      if (state.nextAuthCredentialId) {
        pickedB64 = state.nextAuthCredentialId;
      } else {
        const allowed = publicKey.allowCredentials || [];
        for (const a of allowed) {
          const id = bytesToBase64Url(new Uint8Array(a.id));
          if (registry.has(id)) { pickedB64 = id; break; }
        }
        // tarn#59 — discoverable flow: the server leaves allowCredentials
        // empty (the standard usernameless shape), so a real platform
        // authenticator self-selects from its resident credentials. Simulate
        // that by picking any registered credential the RP knows about. (With
        // the constant-salt scheme there is no per-credential map to consult;
        // a real authenticator just shows the user their resident keys.)
        if (!pickedB64 && allowed.length === 0) {
          for (const id of registry.keys()) { pickedB64 = id; break; }
        }
      }
      if (!pickedB64) throw new Error('virtual authenticator: no allowed credential found in registry');

      const auth = registry.get(pickedB64);
      if (!auth) throw new Error(`virtual authenticator: unknown credentialId ${pickedB64}`);

      // tarn#59 — the PRF salt is now the single app-wide CONSTANT carried in
      // extensions.prf.eval.first. Prefer it; fall back to the deprecated
      // per-credential evalByCredential[credId].first for backward compat with
      // any pre-tarn#59 wire shape.
      const prf = publicKey.extensions?.prf || {};
      let saltSrc = prf.eval?.first;
      if (!saltSrc) saltSrc = prf.evalByCredential?.[pickedB64]?.first;
      if (!saltSrc) throw new Error(`virtual authenticator: no PRF salt for ${pickedB64}`);
      const prfSaltB64 = bytesToBase64Url(new Uint8Array(saltSrc));

      let extras = {};
      if (state.onBeforeAuth) extras = state.onBeforeAuth(auth) || {};

      return auth.buildAuthenticationResponse({
        rpId: publicKey.rpId || state.rpId,
        origin: state.origin,
        challenge,
        prfSalt: prfSaltB64,
        ...extras,
      });
    },
  };

  globalThis.navigator = { credentials };

  // Patch fetch to inject Origin header.
  const realFetch = originals.fetch;
  globalThis.fetch = async (url, opts = {}) => {
    const headers = new Headers(opts.headers || {});
    if (!headers.has('Origin') && !headers.has('origin')) {
      headers.set('Origin', state.origin);
    }
    return realFetch(url, { ...opts, headers });
  };

  return {
    registry,
    state,
    /** Stage `auth` as the next authenticator to respond to a registration ceremony. */
    stageRegistration(auth) { state.pendingRegistration = auth; },
    /** Pin which credentialId will respond to the next auth ceremony. */
    pinNextAuth(b64) { state.nextAuthCredentialId = b64; },
    clearNextAuth() { state.nextAuthCredentialId = null; },
    /** Attach a per-call mutator (e.g. to tamper signature) for the next get() call. */
    onceBeforeAuth(fn) {
      const prev = state.onBeforeAuth;
      state.onBeforeAuth = (auth) => {
        state.onBeforeAuth = prev;
        return fn(auth);
      };
    },
    restore() {
      globalThis.navigator = originals.navigator;
      globalThis.PublicKeyCredential = originals.PublicKeyCredential;
      globalThis.fetch = originals.fetch;
    },
  };
}
