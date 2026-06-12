/**
 * Multi-gateway Arweave client.
 *
 * Wraps an ordered list of {@link ArweaveClient}s with the failure-handling
 * rules from `docs/STANDALONE_RECOVERY_PLAN.md` Phase 2:
 *
 *   - Try gateways in order.
 *   - On any of: connection error, timeout, HTTP 5xx, HTTP 429, or
 *     "TX not found" for a confirmed TX → try the next gateway.
 *   - Only fail the operation when ALL gateways are exhausted, in which
 *     case throw {@link AllGatewaysFailedError} carrying every per-gateway
 *     error so callers can show "tried N gateways, here's why each one
 *     failed."
 *   - Surface each retry via an optional `onProgress` callback.
 *
 * Gateways are not round-robin'd; the first one in the list is preferred.
 * The plan calls this out explicitly: a slow-but-eventually-correct
 * gateway is preferable to splitting load randomly across a list whose
 * relative health we don't know.
 */

import {
  ArweaveClient,
  GatewayError,
  type GatewayErrorKind,
  type ArweaveQueryResult,
  type TransactionsQueryVariables,
} from './arweave-client.js';

/**
 * Categories of failure that trigger a fallover to the next gateway.
 * `bad_response` and `http_4xx` (other than 429) are NOT retryable —
 * they'd repeat at the next gateway and likely indicate either a client
 * bug or genuine "this transaction does not exist anywhere" condition.
 *
 * `graphql_error` is borderline; treat as retryable since gateways have
 * been seen to return GraphQL errors during indexer hiccups.
 */
const RETRYABLE_KINDS = new Set<GatewayErrorKind>([
  'timeout',
  'network',
  'http_5xx',
  'http_429',
  'tx_not_found',
  'graphql_error',
]);

/**
 * Per-attempt context passed to {@link MultiGatewayClient.OnProgress}.
 */
export interface RetryProgress {
  /** The operation that failed and is being retried. */
  operation: 'queryTransactions' | 'fetchBlob';
  /** Index (0-based) of the gateway that just failed. */
  failedIndex: number;
  /** URL of the gateway that just failed. */
  failedGateway: string;
  /** The structured error from the failed gateway. */
  error: GatewayError;
  /** Index (0-based) of the gateway about to be tried next. */
  nextIndex: number;
  /** URL of the gateway about to be tried next. */
  nextGateway: string;
  /** Total number of gateways configured. */
  totalGateways: number;
}

export type OnProgress = (info: RetryProgress) => void;

export interface MultiGatewayClientOptions {
  /** Configured gateway list, tried in order. Must be non-empty. */
  clients: ArweaveClient[];
  /** Optional callback invoked on each retry. */
  onProgress?: OnProgress;
}

/**
 * Thrown when every configured gateway has failed for a single operation.
 * Carries the per-gateway errors so callers can render "tried N gateways"
 * UI without inspecting the underlying errors directly.
 */
export class AllGatewaysFailedError extends Error {
  readonly errors: GatewayError[];
  readonly operation: string;

  constructor(operation: string, errors: GatewayError[]) {
    const summary = errors
      .map((e) => `${e.gateway}: ${e.kind}${e.status !== undefined ? `(${e.status})` : ''}`)
      .join('; ');
    super(`All ${errors.length} gateways failed for ${operation}: ${summary}`);
    this.name = 'AllGatewaysFailedError';
    this.errors = errors;
    this.operation = operation;
  }
}

/**
 * Multi-gateway client. Same surface as {@link ArweaveClient}'s public
 * methods, but with built-in fallover.
 */
export class MultiGatewayClient {
  readonly #clients: ArweaveClient[];
  readonly #onProgress: OnProgress | undefined;

  constructor(options: MultiGatewayClientOptions) {
    if (!options.clients || options.clients.length === 0) {
      throw new Error('MultiGatewayClient requires at least one ArweaveClient');
    }
    this.#clients = [...options.clients];
    this.#onProgress = options.onProgress;
  }

  /** The configured gateway URLs, in priority order. */
  get gateways(): readonly string[] {
    return this.#clients.map((c) => c.gateway);
  }

  /**
   * Run a `transactions` GraphQL query against the first gateway that
   * succeeds. See {@link ArweaveClient.queryTransactions}.
   */
  async queryTransactions(variables: TransactionsQueryVariables): Promise<ArweaveQueryResult> {
    return this.#runWithFallover('queryTransactions', (client) => client.queryTransactions(variables));
  }

  /**
   * Fetch a transaction body from the first gateway that succeeds.
   * See {@link ArweaveClient.fetchBlob}.
   */
  async fetchBlob(txid: string): Promise<Uint8Array> {
    return this.#runWithFallover('fetchBlob', (client) => client.fetchBlob(txid));
  }

  async #runWithFallover<T>(
    operation: 'queryTransactions' | 'fetchBlob',
    op: (client: ArweaveClient) => Promise<T>,
  ): Promise<T> {
    const errors: GatewayError[] = [];
    for (let i = 0; i < this.#clients.length; i++) {
      const client = this.#clients[i]!;
      try {
        return await op(client);
      } catch (err) {
        // Re-throw non-GatewayError unexpected exceptions immediately.
        // Those signal a programmer error in this package, not a gateway
        // issue, and silently retrying would mask the bug.
        if (!(err instanceof GatewayError)) {
          throw err;
        }
        errors.push(err);
        if (!RETRYABLE_KINDS.has(err.kind)) {
          // Non-retryable: stop here, report what we have.
          throw new AllGatewaysFailedError(operation, errors);
        }
        const nextIndex = i + 1;
        if (nextIndex < this.#clients.length && this.#onProgress) {
          this.#onProgress({
            operation,
            failedIndex: i,
            failedGateway: client.gateway,
            error: err,
            nextIndex,
            nextGateway: this.#clients[nextIndex]!.gateway,
            totalGateways: this.#clients.length,
          });
        }
        // Loop to next gateway.
      }
    }
    throw new AllGatewaysFailedError(operation, errors);
  }
}

/**
 * Convenience: build a {@link MultiGatewayClient} from an array of base
 * URLs (e.g. `['https://arweave.net', 'https://permagate.io']`).
 */
export function makeMultiGatewayClient(
  gateways: string[],
  options: { timeoutMs?: number; fetch?: typeof fetch; onProgress?: OnProgress } = {},
): MultiGatewayClient {
  if (!gateways || gateways.length === 0) {
    throw new Error('makeMultiGatewayClient requires at least one gateway URL');
  }
  const clients = gateways.map(
    (gateway) =>
      new ArweaveClient({
        gateway,
        ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
        ...(options.fetch !== undefined ? { fetch: options.fetch } : {}),
      }),
  );
  return new MultiGatewayClient({
    clients,
    ...(options.onProgress !== undefined ? { onProgress: options.onProgress } : {}),
  });
}
