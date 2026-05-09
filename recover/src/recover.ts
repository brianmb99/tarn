/**
 * `recover()` — public entry point for the standalone-recovery package.
 *
 * Given a user's credentials (either `(username, password)` or an account
 * key) and an ordered list of Arweave gateways, returns a {@link Reader}
 * bound to that account. The reader exposes the user's owned collection
 * data via async iterators; everything happens client-side, with no Tarn
 * API in the loop.
 *
 * Usage:
 *
 *   import { recover } from '@tarn/recover';
 *
 *   const reader = await recover({
 *     appId: 'bookish',
 *     schema: bookishSchema,
 *     arweaveGateways: ['https://arweave.net', 'https://g8way.io'],
 *     credentials: { type: 'password', username, password },
 *     // OR: credentials: { type: 'accountKey', accountKey },
 *     onProgress: (stage, info) => console.log(stage, info),
 *   });
 *
 *   for await (const book of reader.entries('books')) {
 *     render(book);
 *   }
 *
 * Phase 4 covers the `entries(...)` / `allEntries(...)` surface for owned
 * collections. Sharing / connections / share-log iteration is Phase 5;
 * the reader throws if those surfaces are accessed.
 */

import {
  makeMultiGatewayClient,
  type MultiGatewayClient,
} from './gateway/multi-gateway.js';
import { findCredentialBlob } from './gateway/queries.js';
import {
  derivePasswordKEK,
  deriveRecoveryKEK,
} from './decrypt/derive-keys.js';
import {
  deriveCredentialLookupKey,
  deriveRecoveryLookupKey,
} from './decrypt/derive-lookup-keys.js';
import {
  parseEnvelope,
  unwrapDekChain,
} from './decrypt/unwrap-envelope.js';
import {
  FACTOR_PASSWORD,
  FACTOR_RECOVERY_PHRASE,
} from './crypto/constants.js';
import { deriveMasterKey } from './crypto/kdf.js';
import { deriveSharingKeyPair } from './crypto/share-key.js';
import { Reader, type ReaderAccount, type ReaderSchema } from './reader/reader.js';
import type { OnProgress } from './progress.js';

/**
 * Credentials block. Exactly one shape is accepted per call. `password`
 * mode requires both `username` and `password`; `accountKey` mode is
 * username-less (the BIP39 account key alone is sufficient — see
 * `docs/STANDALONE_RECOVERY_PLAN.md` §"Resolved scope decisions" item 3).
 */
export type RecoverCredentials =
  | { type: 'password'; username: string; password: string }
  | { type: 'accountKey'; accountKey: string };

export interface RecoverOptions {
  /** App identifier. Must match the `appId` the writer used at register time. */
  appId: string;
  /**
   * The app's schema (output of `defineSchema()` or any compatible shape:
   * `{ appId, version, collections }`). Used for collection enumeration
   * and the `_schemaVersion` marker on returned entries.
   */
  schema: ReaderSchema;
  /**
   * Ordered list of Arweave gateway base URLs (e.g.
   * `['https://arweave.net', 'https://g8way.io']`). Tried in order; on
   * any retryable failure the next gateway is consulted.
   */
  arweaveGateways: string[];
  /** Credentials block; see {@link RecoverCredentials}. */
  credentials: RecoverCredentials;
  /** Diagnostic progress callback. Errors thrown from it are swallowed. */
  onProgress?: OnProgress;
}

/**
 * Run the full recovery flow and return a {@link Reader} bound to the
 * recovered account.
 *
 * Throws on:
 *   - Missing / malformed inputs.
 *   - No credential blob found at any configured gateway.
 *   - Envelope parse failure (corrupt or unknown wire version).
 *   - Factor mismatch (e.g., password wrapping absent for the requested
 *     account, or account key didn't unwrap the chain).
 */
export async function recover(opts: RecoverOptions): Promise<Reader> {
  validateOptions(opts);

  const onProgress = opts.onProgress;
  const emit = (stage: Parameters<NonNullable<OnProgress>>[0], info: Record<string, unknown> = {}): void => {
    if (!onProgress) return;
    try {
      onProgress(stage, info);
    } catch {
      // Progress callbacks are diagnostic — never let one block recovery.
    }
  };

  // === 1. Multi-gateway client ===
  const client: MultiGatewayClient = makeMultiGatewayClient(opts.arweaveGateways, {
    ...(onProgress
      ? {
          onProgress: (info) => emit('locating-account', {
            retry: true,
            failedGateway: info.failedGateway,
            nextGateway: info.nextGateway,
            kind: info.error.kind,
          }),
        }
      : {}),
  });

  // === 2. Derive lookup key from credentials ===
  emit('deriving', { factor: opts.credentials.type });

  let lookupArg: { recoveryLookupKey?: string; credentialLookupKey?: string };
  if (opts.credentials.type === 'password') {
    const lk = await deriveCredentialLookupKey(
      opts.credentials.username,
      opts.credentials.password,
      opts.appId,
    );
    lookupArg = { credentialLookupKey: lk };
  } else {
    const rlk = await deriveRecoveryLookupKey(opts.credentials.accountKey, opts.appId);
    lookupArg = { recoveryLookupKey: rlk };
  }

  // === 3. Locate the credential blob on Arweave ===
  emit('locating-account', { factor: opts.credentials.type });
  const credBlob = await findCredentialBlob(client, lookupArg);
  if (!credBlob) {
    throw new Error(
      `recover: no credential blob found on any configured gateway for ${
        opts.credentials.type === 'password' ? 'username + password' : 'account key'
      }`,
    );
  }

  // === 4. Pull dataLookupKey + envelope out of the credential body ===
  emit('fetching-envelope', { txid: credBlob.txid });
  const body = credBlob.body as Record<string, unknown> | null;
  if (!body || typeof body !== 'object') {
    throw new Error(`recover: credential blob ${credBlob.txid} body is not an object`);
  }
  const dataLookupKey = body['data_lookup_key'];
  const wrappedDataKey = body['wrapped_data_key'];
  // `public_key` (base64 SPKI P-256) is the user's signing pub. Used by the
  // sharing reader to verify outgoing share-log entries (which the user
  // themselves signed). Optional in older credential blobs — when absent,
  // the SharingReader surfaces outgoing entries with `verified: false`.
  const publicKey = body['public_key'];
  if (typeof dataLookupKey !== 'string' || dataLookupKey.length === 0) {
    throw new Error(`recover: credential blob ${credBlob.txid} missing data_lookup_key`);
  }
  if (typeof wrappedDataKey !== 'string' || wrappedDataKey.length === 0) {
    throw new Error(`recover: credential blob ${credBlob.txid} missing wrapped_data_key`);
  }
  const ownSigningPubBase64 = typeof publicKey === 'string' && publicKey.length > 0
    ? publicKey
    : undefined;

  // === 5. Derive the factor's KEK + unwrap the DEK chain ===
  const parsed = parseEnvelope(wrappedDataKey);

  let kek: CryptoKey;
  let factor: typeof FACTOR_PASSWORD | typeof FACTOR_RECOVERY_PHRASE;
  // Phase 5: when the password factor is in play we also derive the
  // X25519 share keypair so the Reader can light up `connections()` and
  // `shareLog()`. The account-key path leaves this undefined — see
  // `crypto/share-key.ts` for the architectural reason.
  let shareKeyPair: { privateKey: Uint8Array; publicKey: Uint8Array } | undefined;
  if (opts.credentials.type === 'password') {
    // Compute master_key once; both the password KEK and the share keypair
    // need it, and it's the slow Argon2id step.
    const masterKey = await deriveMasterKey(
      opts.credentials.username,
      opts.credentials.password,
    );
    const [passwordKek, sharing] = await Promise.all([
      derivePasswordKEK({
        username: opts.credentials.username,
        password: opts.credentials.password,
        appId: opts.appId,
      }),
      deriveSharingKeyPair(masterKey, opts.appId),
    ]);
    kek = passwordKek;
    shareKeyPair = sharing;
    factor = FACTOR_PASSWORD;
  } else {
    kek = await deriveRecoveryKEK({
      accountKey: opts.credentials.accountKey,
      recoverySalt: parsed.recovery.salt,
      kdfParams: parsed.recovery.kdfParams,
    });
    factor = FACTOR_RECOVERY_PHRASE;
  }

  const dekChain = await unwrapDekChain({
    envelope: wrappedDataKey,
    kek,
    factor,
  });

  // === 6. Build the Reader ===
  const account: ReaderAccount = {
    appId: opts.appId,
    envelopeVersion: dekChain.envelopeVersion,
    totalGens: dekChain.dekByGen.size,
    ...(opts.credentials.type === 'password' ? { username: opts.credentials.username } : {}),
  };

  const reader = new Reader({
    appId: opts.appId,
    schema: opts.schema,
    client,
    dataLookupKey,
    dekChain,
    account,
    ...(onProgress ? { onProgress } : {}),
    ...(shareKeyPair ? { shareKeyPair } : {}),
    ...(ownSigningPubBase64 ? { ownSigningPubBase64 } : {}),
  });

  emit('done', { totalGens: dekChain.dekByGen.size, currentGen: dekChain.currentGen });
  return reader;
}

// ============ Validation ============

function validateOptions(opts: RecoverOptions): void {
  if (!opts || typeof opts !== 'object') {
    throw new Error('recover: options object is required');
  }
  if (typeof opts.appId !== 'string' || opts.appId.length === 0) {
    throw new Error('recover: appId must be a non-empty string');
  }
  if (!opts.schema || typeof opts.schema !== 'object') {
    throw new Error('recover: schema must be a non-null object');
  }
  if (typeof opts.schema.appId !== 'string' || opts.schema.appId.length === 0) {
    throw new Error('recover: schema.appId must be a non-empty string');
  }
  if (opts.schema.appId !== opts.appId) {
    throw new Error(
      `recover: schema.appId ('${opts.schema.appId}') does not match options.appId ('${opts.appId}')`,
    );
  }
  if (!Number.isInteger(opts.schema.version) || opts.schema.version < 1) {
    throw new Error('recover: schema.version must be a positive integer');
  }
  if (!opts.schema.collections || typeof opts.schema.collections !== 'object') {
    throw new Error('recover: schema.collections must be a non-null object');
  }
  if (!Array.isArray(opts.arweaveGateways) || opts.arweaveGateways.length === 0) {
    throw new Error('recover: arweaveGateways must be a non-empty array of URLs');
  }
  for (const gw of opts.arweaveGateways) {
    if (typeof gw !== 'string' || gw.length === 0) {
      throw new Error('recover: every arweaveGateways entry must be a non-empty string');
    }
  }
  if (!opts.credentials || typeof opts.credentials !== 'object') {
    throw new Error('recover: credentials block is required');
  }
  if (opts.credentials.type === 'password') {
    if (typeof opts.credentials.username !== 'string' || opts.credentials.username.length === 0) {
      throw new Error('recover: credentials.username must be a non-empty string');
    }
    if (typeof opts.credentials.password !== 'string' || opts.credentials.password.length === 0) {
      throw new Error('recover: credentials.password must be a non-empty string');
    }
  } else if (opts.credentials.type === 'accountKey') {
    if (typeof opts.credentials.accountKey !== 'string' || opts.credentials.accountKey.length === 0) {
      throw new Error('recover: credentials.accountKey must be a non-empty string');
    }
  } else {
    throw new Error(
      // @ts-expect-error narrowing exhaustively — runtime guard for callers from JS.
      `recover: credentials.type must be 'password' or 'accountKey' (got '${opts.credentials.type}')`,
    );
  }
}
