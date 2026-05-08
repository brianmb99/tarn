/**
 * Single-gateway Arweave client.
 *
 * Wraps GraphQL queries (`POST <gateway>/graphql`) and binary blob fetches
 * (`GET <gateway>/<txid>`) against ONE Arweave gateway. Per-call timeout is
 * configurable; default is 30 s.
 *
 * This client deliberately treats every failure mode as a structured error
 * (a `GatewayError`) instead of a thrown `Error`. The multi-gateway wrapper
 * needs the failure category (timeout vs. 429 vs. 5xx vs. "tx not found"
 * vs. network) to decide whether to fall over to the next gateway. Throwing
 * generic `Error`s would force string-matching at the wrapper layer; we'd
 * rather pay the conversion cost up-front here.
 *
 * For the contract this client satisfies, see
 * `docs/STANDALONE_RECOVERY_PLAN.md` Phase 2.
 */

/**
 * Categorised reasons a single-gateway call failed. The multi-gateway
 * wrapper falls over on every category here EXCEPT `bad_response` (a
 * malformed but non-error reply, which would just repeat at the next
 * gateway and likely indicates a client-side bug).
 */
export type GatewayErrorKind =
  | 'timeout'
  | 'network'
  | 'http_5xx'
  | 'http_429'
  | 'http_4xx'        // 4xx other than 429 — surfaced but not auto-retried
  | 'tx_not_found'    // 404 on a blob fetch (gateway behind on indexing)
  | 'graphql_error'   // GraphQL returned an `errors` array
  | 'bad_response';   // unparseable JSON / unexpected shape

export class GatewayError extends Error {
  readonly kind: GatewayErrorKind;
  readonly status?: number;
  readonly gateway: string;
  /** Original cause (e.g. AbortError, TypeError from fetch). */
  override readonly cause?: unknown;

  constructor(
    kind: GatewayErrorKind,
    gateway: string,
    message: string,
    opts: { status?: number; cause?: unknown } = {},
  ) {
    super(message);
    this.name = 'GatewayError';
    this.kind = kind;
    this.gateway = gateway;
    if (opts.status !== undefined) this.status = opts.status;
    if (opts.cause !== undefined) this.cause = opts.cause;
  }
}

/**
 * Options for {@link ArweaveClient}. The `gateway` is the base URL; do not
 * include a trailing slash. `timeoutMs` defaults to 30000.
 */
export interface ArweaveClientOptions {
  gateway: string;
  /** Per-call timeout in milliseconds. Default: 30000. */
  timeoutMs?: number;
  /** Override `fetch` (e.g. for testing). Defaults to global `fetch`. */
  fetch?: typeof fetch;
}

/**
 * One edge in an Arweave GraphQL `transactions` response.
 */
export interface ArweaveEdge {
  cursor?: string;
  node: ArweaveNode;
}

export interface ArweaveTag {
  name: string;
  value: string;
}

export interface ArweaveNode {
  id: string;
  tags: ArweaveTag[];
  block?: { timestamp?: number; height?: number } | null;
}

/**
 * Result of a GraphQL `transactions` query.
 */
export interface ArweaveQueryResult {
  edges: ArweaveEdge[];
  hasNextPage: boolean;
  endCursor: string | null;
}

/**
 * GraphQL variables for the standard `transactions(...)` query shape used
 * by the Tarn ecosystem. We expose them as a typed surface so callers
 * don't need to hand-build GraphQL strings.
 */
export interface TransactionsQueryVariables {
  tags: { name: string; values: string[] }[];
  /** `HEIGHT_DESC` (default — newest first) or `HEIGHT_ASC`. */
  sort?: 'HEIGHT_DESC' | 'HEIGHT_ASC';
  /** Default: 100. Arweave gateways cap at 100. */
  first?: number;
  /** GraphQL `after` cursor for pagination. */
  after?: string | null;
}

const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * The standard `transactions` query body. Mirrors the shape used by
 * `api/src/arweave.js` (`searchEntriesByLookupKey` / `searchEntriesByAddr`)
 * so the on-the-wire request is identical between the live API and the
 * recover package.
 */
const TRANSACTIONS_QUERY = `
  query($after: String, $first: Int, $tags: [TagFilter!], $sort: SortOrder) {
    transactions(after: $after, first: $first, tags: $tags, sort: $sort) {
      pageInfo { hasNextPage }
      edges {
        cursor
        node {
          id
          tags { name value }
          block { timestamp height }
        }
      }
    }
  }
`;

/**
 * Single-gateway Arweave reader. Stateless apart from configuration —
 * safe to call concurrently.
 */
export class ArweaveClient {
  readonly gateway: string;
  readonly timeoutMs: number;
  readonly #fetch: typeof fetch;

  constructor(options: ArweaveClientOptions) {
    this.gateway = options.gateway.replace(/\/+$/, '');
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    // Capture `globalThis.fetch` lazily so the constructor doesn't blow up
    // in environments where the override is supplied.
    this.#fetch = options.fetch ?? ((...args) => globalThis.fetch(...args));
  }

  /**
   * Run a `transactions` GraphQL query against this gateway.
   *
   * Translates HTTP / network failures to {@link GatewayError}. Returns a
   * decoded `ArweaveQueryResult` on success.
   */
  async queryTransactions(
    variables: TransactionsQueryVariables,
  ): Promise<ArweaveQueryResult> {
    const url = `${this.gateway}/graphql`;
    const body = JSON.stringify({
      query: TRANSACTIONS_QUERY,
      variables: {
        after: variables.after ?? null,
        first: variables.first ?? 100,
        tags: variables.tags,
        sort: variables.sort ?? 'HEIGHT_DESC',
      },
    });

    let res: Response;
    try {
      res = await this.#withTimeout((signal) =>
        this.#fetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body,
          signal,
        }),
      );
    } catch (err) {
      throw this.#fetchError(err);
    }

    if (res.status === 429) {
      throw new GatewayError('http_429', this.gateway, `GraphQL 429 from ${this.gateway}`, { status: 429 });
    }
    if (res.status >= 500) {
      throw new GatewayError('http_5xx', this.gateway, `GraphQL ${res.status} from ${this.gateway}`, { status: res.status });
    }
    if (res.status >= 400) {
      throw new GatewayError('http_4xx', this.gateway, `GraphQL ${res.status} from ${this.gateway}`, { status: res.status });
    }

    let json: unknown;
    try {
      json = await res.json();
    } catch (err) {
      throw new GatewayError('bad_response', this.gateway, `GraphQL response not JSON: ${(err as Error).message}`, { cause: err });
    }

    const obj = json as {
      data?: {
        transactions?: {
          pageInfo?: { hasNextPage?: boolean };
          edges?: ArweaveEdge[];
        };
      };
      errors?: { message?: string }[];
    };

    if (obj.errors && obj.errors.length > 0) {
      const msg = obj.errors[0]?.message ?? 'unknown GraphQL error';
      throw new GatewayError('graphql_error', this.gateway, `GraphQL error: ${msg}`);
    }

    const txns = obj.data?.transactions;
    const edges: ArweaveEdge[] = Array.isArray(txns?.edges) ? (txns!.edges as ArweaveEdge[]) : [];
    const hasNextPage = Boolean(txns?.pageInfo?.hasNextPage);
    const endCursor = edges.length > 0 ? (edges[edges.length - 1]?.cursor ?? null) : null;

    return { edges, hasNextPage, endCursor };
  }

  /**
   * Fetch a transaction body (the encrypted blob) from this gateway.
   *
   * Returns the raw bytes. Translates HTTP / network failures to
   * {@link GatewayError}; in particular, an HTTP 404 becomes a
   * `tx_not_found` error which the multi-gateway wrapper treats as
   * "try the next one" (the gateway may simply be behind on indexing).
   */
  async fetchBlob(txid: string): Promise<Uint8Array> {
    const url = `${this.gateway}/${encodeURIComponent(txid)}`;

    let res: Response;
    try {
      res = await this.#withTimeout((signal) => this.#fetch(url, { signal }));
    } catch (err) {
      throw this.#fetchError(err);
    }

    if (res.status === 404) {
      throw new GatewayError('tx_not_found', this.gateway, `TX ${txid} not found at ${this.gateway}`, { status: 404 });
    }
    if (res.status === 429) {
      throw new GatewayError('http_429', this.gateway, `Blob 429 from ${this.gateway}`, { status: 429 });
    }
    if (res.status >= 500) {
      throw new GatewayError('http_5xx', this.gateway, `Blob ${res.status} from ${this.gateway}`, { status: res.status });
    }
    if (res.status >= 400) {
      throw new GatewayError('http_4xx', this.gateway, `Blob ${res.status} from ${this.gateway}`, { status: res.status });
    }

    let buf: ArrayBuffer;
    try {
      buf = await res.arrayBuffer();
    } catch (err) {
      throw new GatewayError('bad_response', this.gateway, `Blob body unreadable: ${(err as Error).message}`, { cause: err });
    }

    return new Uint8Array(buf);
  }

  /** Run `fn(signal)` with this client's timeout enforced via AbortController. */
  async #withTimeout<T>(fn: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      return await fn(ctrl.signal);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Map a thrown fetch/abort error to a {@link GatewayError}. Anything
   * resembling an abort becomes `timeout`; everything else becomes
   * `network`.
   */
  #fetchError(err: unknown): GatewayError {
    const e = err as { name?: string; message?: string };
    const name = e?.name ?? '';
    const message = e?.message ?? String(err);
    if (name === 'AbortError' || /aborted|timeout/i.test(message)) {
      return new GatewayError('timeout', this.gateway, `timeout against ${this.gateway}`, { cause: err });
    }
    return new GatewayError('network', this.gateway, `network error against ${this.gateway}: ${message}`, { cause: err });
  }
}

/**
 * Convert an ArweaveTag[] (the wire shape) into an object keyed by tag name.
 *
 * Arweave permits duplicate tag names; this helper keeps the LAST value for
 * each name (matching how the live API treats them). For tag schemes where
 * a name can legitimately appear multiple times (none in Tarn's current
 * use), callers should walk the raw array.
 */
export function tagMap(tags: ArweaveTag[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const t of tags) out[t.name] = t.value;
  return out;
}
