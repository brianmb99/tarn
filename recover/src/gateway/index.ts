/**
 * Public surface of the gateway-direct read primitives.
 *
 * Phase 2 deliverable. Later phases (the `recover()` orchestrator, the
 * schema-aware reader, the share-log replayer) consume these.
 */

export {
  ArweaveClient,
  GatewayError,
  tagMap,
  type ArweaveClientOptions,
  type ArweaveEdge,
  type ArweaveNode,
  type ArweaveTag,
  type ArweaveQueryResult,
  type GatewayErrorKind,
  type TransactionsQueryVariables,
} from './arweave-client.js';

export {
  MultiGatewayClient,
  AllGatewaysFailedError,
  makeMultiGatewayClient,
  type MultiGatewayClientOptions,
  type OnProgress,
  type RetryProgress,
} from './multi-gateway.js';

export {
  findCredentialBlob,
  findAppBlob,
  findContentBlobs,
  findShareLogBlobs,
  findShareInboxBlobs,
  findPasskeyCredentials,
  type BlobRecord,
  type JsonBlobRecord,
  type FindCredentialBlobArgs,
  type FindAppBlobArgs,
  type FindContentBlobsArgs,
  type FindShareLogBlobsArgs,
  type FindShareInboxBlobsArgs,
  type FindPasskeyCredentialsArgs,
} from './queries.js';
