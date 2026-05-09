/**
 * Public surface of the sharing primitives — Phase 5.
 *
 * Pure code borrowed from `client/src/share-log.ts` and
 * `client/src/sharing.ts`, plus a thin `getPairKeysFor` extraction that
 * wraps the pure derivations in a recover-client-friendly signature.
 *
 * The cross-validation tests in `tests/sharing-cross-validate.test.ts` enforce
 * byte-equality with the client-side originals so the two copies cannot
 * drift.
 */

export {
  // Per-pair key derivation
  deriveSharedSecret,
  derivePairKeys,
  // Stealth tag derivation
  deriveLogTag,
  // Entry seal/open
  encryptShareLogEntry,
  decryptShareLogEntry,
  // Signature verification (and signing — fixtures use it)
  computeSigInput,
  signOperation,
  verifyOperationSignature,
  // Highest-seq discovery
  discoverHighestSeq,
  // State machine
  applyOperationToState,
  replayOperations,
  // Canonical JSON (load-bearing for signature verification)
  canonicalJSONStringify,
  canonicalJSONBytes,
  // Operation type constants
  OP_ADD,
  OP_UPDATE,
  OP_ROTATE,
  OP_REMOVE,
  OP_SNAPSHOT,
  OP_ROTATE_IDENTITY,
  KNOWN_OP_TYPES,
  SHARE_LOG_TYPE,
  MAX_LOG_BLOB_PLAINTEXT_BYTES,
  // Types
  type OpType,
  type DerivePairKeysOpts,
  type PairKeys,
  type DiscoverHighestSeqOpts,
  type DiscoverHighestSeqResult,
  type OpAddFields,
  type OpUpdateFields,
  type OpRotateFields,
  type OpRemoveFields,
  type OpSnapshotFields,
  type OpRotateIdentityFields,
  type SnapshotState,
  type OperationUnsigned,
  type OperationSigned,
  type ShareLogState,
  type StateHooks,
} from './share-log-primitives.js';

export {
  // HPKE
  hpkeSeal,
  hpkeOpen,
  // Inbox tag derivation
  inboxWindowFor,
  currentInboxWindow,
  recentInboxWindows,
  deriveInboxTag,
  // Connection request/accept payloads + validators
  validateConnectionRequestPayload,
  validateConnectionAcceptPayload,
  // Connection record helpers
  emptyConnectionsRecord,
  isConnectionsRecord,
  // Constants
  INFO_CONNECTION_REQUEST,
  INFO_CONNECTION_ACCEPT,
  CONNECTIONS_CONTENT_ID,
  PENDING_REQUESTS_CONTENT_ID,
  MUTED_CONNECTIONS_CONTENT_ID,
  ISSUED_INVITES_CONTENT_ID,
  REPLAY_PAST_WINDOW_SEC,
  REPLAY_FUTURE_WINDOW_SEC,
  REPLAY_NONCE_TTL_SEC,
  DEFAULT_POLL_WINDOWS,
  MAX_HANDSHAKE_BLOB_BYTES,
  MAX_REQUEST_MESSAGE_LEN,
  // Types
  type ConnectionRequestPayload,
  type NormalizedConnectionRequest,
  type ConnectionAcceptPayload,
  type NormalizedConnectionAccept,
  type ValidationResult,
  type ConnectionEntry,
  type ConnectionsRecord,
} from './hpke-primitives.js';

export { getPairKeysFor } from './pair-keys.js';
