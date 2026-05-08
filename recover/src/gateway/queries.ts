/**
 * Tag-filtered Arweave queries used by the standalone-recovery flow.
 *
 * These mirror the tag schemes documented in `docs/TARN_PROTOCOL.md`
 * (Arweave Tag Scheme section) and used by the live API in
 * `api/src/arweave.js`. The recover package consumes them via gateway-direct
 * GraphQL — there's no Tarn server involved.
 *
 * Each query returns rich enough data for later phases: parsed body JSON
 * (when applicable), tag map, txid, and block height. We deliberately do
 * NOT strip any fields here; later phases (the schema-aware reader, the
 * share-log replayer) decide what they need.
 *
 * "Most-recent" semantics: GraphQL is queried with `sort: HEIGHT_DESC`
 * and the latest blob (by block height) wins. For `findCredentialBlob`
 * and `findAppBlob` we return ONLY the latest. For `findContentBlobs`
 * we return ALL matching blobs sorted ascending by block height — Phase 4
 * needs the full Prev-chain to apply tombstones / Eid dedup.
 */

import type { MultiGatewayClient } from './multi-gateway.js';
import { tagMap, type ArweaveEdge, type ArweaveNode, type ArweaveTag } from './arweave-client.js';

/**
 * A single Arweave blob with its tags, body bytes, and where it landed
 * on-chain. The body is fetched lazily — `loadBody()` triggers the HTTP
 * GET against the gateway. We split it this way so callers that only need
 * tag inspection (e.g., enumerating passkey credentials by `CredId`) don't
 * pay for blob fetches they won't use.
 */
export interface BlobRecord {
  /** Arweave transaction id. */
  txid: string;
  /** Tags as authored, in original order. */
  tags: ArweaveTag[];
  /** Tags collapsed to a name→value map (last write wins on duplicates). */
  tagMap: Record<string, string>;
  /** Block timestamp (unix-seconds) if the TX is confirmed; null otherwise. */
  blockTimestamp: number | null;
  /** Block height if the TX is confirmed; null otherwise. */
  blockHeight: number | null;
  /** Lazily fetch the body bytes. Cached after first call. */
  loadBody(): Promise<Uint8Array>;
}

/**
 * Same as {@link BlobRecord} but with the body already decoded as JSON.
 * Returned by query helpers that always need the body (e.g.
 * {@link findCredentialBlob}, {@link findAppBlob}).
 */
export interface JsonBlobRecord extends BlobRecord {
  /** The body parsed as JSON. */
  body: unknown;
}

function makeBlobRecord(client: MultiGatewayClient, edge: ArweaveEdge): BlobRecord {
  const node = edge.node;
  let cached: Uint8Array | undefined;
  return {
    txid: node.id,
    tags: node.tags,
    tagMap: tagMap(node.tags),
    blockTimestamp: node.block?.timestamp ?? null,
    blockHeight: node.block?.height ?? null,
    async loadBody(): Promise<Uint8Array> {
      if (cached === undefined) {
        cached = await client.fetchBlob(node.id);
      }
      return cached;
    },
  };
}

async function asJsonBlob(client: MultiGatewayClient, edge: ArweaveEdge): Promise<JsonBlobRecord> {
  const base = makeBlobRecord(client, edge);
  const bytes = await base.loadBody();
  const text = new TextDecoder('utf-8').decode(bytes);
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch (err) {
    throw new Error(`blob ${base.txid} body is not JSON: ${(err as Error).message}`);
  }
  return Object.assign(base, { body });
}

// ============ Credential blob ============

export interface FindCredentialBlobArgs {
  /**
   * `recovery_lookup_key` — derived from the account-key alone (HMAC, no
   * salt). The credential blob carries this as a secondary `RLk` tag,
   * added 2026-05 to support standalone recovery from the account-key
   * alone. Older credential blobs lacked this tag and become RLk-
   * discoverable on their next republish.
   */
  recoveryLookupKey?: string;
  /**
   * `credential_lookup_key` — the original lookup key (Argon2id-derived
   * from `(username, password)`). The credential blob's primary `Lk` tag.
   */
  credentialLookupKey?: string;
}

/**
 * Find an account's credential blob on Arweave. Caller supplies EITHER
 * `recoveryLookupKey` (the account-key path) OR `credentialLookupKey` (the
 * password path). Returns the most-recent matching blob, with body parsed
 * as JSON.
 *
 * Returns `null` if no matching blob exists at any gateway. Throws if all
 * gateways fail (see {@link MultiGatewayClient}).
 */
export async function findCredentialBlob(
  client: MultiGatewayClient,
  args: FindCredentialBlobArgs,
): Promise<JsonBlobRecord | null> {
  if (!args.recoveryLookupKey && !args.credentialLookupKey) {
    throw new Error('findCredentialBlob: must supply recoveryLookupKey or credentialLookupKey');
  }
  const tags: { name: string; values: string[] }[] = [
    { name: 'App', values: ['tarn'] },
    { name: 'Type', values: ['cred'] },
  ];
  if (args.recoveryLookupKey) {
    tags.push({ name: 'RLk', values: [args.recoveryLookupKey] });
  }
  if (args.credentialLookupKey) {
    tags.push({ name: 'Lk', values: [args.credentialLookupKey] });
  }

  // HEIGHT_DESC + first: 1 — we want the most recent credential blob, which
  // reflects the live state of the account.
  const result = await client.queryTransactions({ tags, sort: 'HEIGHT_DESC', first: 1 });
  const edge = result.edges[0];
  if (!edge) return null;
  return asJsonBlob(client, edge);
}

// ============ App registration blob ============

export interface FindAppBlobArgs {
  appId: string;
}

/**
 * Find an app's `Type=app-reg` blob on Arweave. Used by later phases that
 * need the app's public key (e.g. to verify share-log signatures). Returns
 * the most-recent matching blob, with body parsed as JSON.
 *
 * Tag scheme: `App=tarn, Type=app-reg, Lk=<app_id>`. Latest wins.
 */
export async function findAppBlob(
  client: MultiGatewayClient,
  args: FindAppBlobArgs,
): Promise<JsonBlobRecord | null> {
  const tags = [
    { name: 'App', values: ['tarn'] },
    { name: 'Type', values: ['app-reg'] },
    { name: 'Lk', values: [args.appId] },
  ];
  const result = await client.queryTransactions({ tags, sort: 'HEIGHT_DESC', first: 1 });
  const edge = result.edges[0];
  if (!edge) return null;
  return asJsonBlob(client, edge);
}

// ============ Content blobs (per-collection user data) ============

export interface FindContentBlobsArgs {
  /** App id (e.g. `'bookish'`). */
  app: string;
  /** Collection name as used in `defineSchema` (e.g. `'books'`). */
  type: string;
  /**
   * The user's data lookup key (the account-bound, server-generated 64-hex
   * string). Tags content blobs as `Lk`.
   */
  dataLookupKey: string;
}

/**
 * Find all content blobs for a (data_lookup_key, app, type) triple. Returns
 * the full set sorted ascending by block height (deterministic, oldest
 * first). The schema-aware reader walks this in order to apply Prev-chain
 * resolution and tombstone semantics.
 *
 * No body decoding is performed here — content bodies are encrypted blobs,
 * not JSON, so callers fetch + decrypt them via {@link BlobRecord.loadBody}.
 *
 * Pagination is handled internally with a hard cap on page count to bound
 * worst-case latency.
 */
export async function findContentBlobs(
  client: MultiGatewayClient,
  args: FindContentBlobsArgs,
): Promise<BlobRecord[]> {
  const tags = [
    { name: 'App', values: [args.app] },
    { name: 'Type', values: [args.type] },
    { name: 'Lk', values: [args.dataLookupKey] },
  ];
  const edges = await paginateAll(client, tags);
  return sortByHeightAscending(edges).map((e) => makeBlobRecord(client, e));
}

// ============ Share-log blobs ============

export interface FindShareLogBlobsArgs {
  /** Stealth log tag (deriveLogTag output). Single value; one per pair+seq. */
  logTag: string;
  /** App id ("AppScope" in the share-log tag scheme). */
  appScope: string;
}

/**
 * Find share-log blobs by stealth tag. Tag scheme (per `docs/TARN_PROTOCOL.md`
 * sharing §8.1, mirrored by `api/src/routes/share-log.js`):
 *
 *   `App=tarn-share, Type=share-log-v1, To=<log_tag>, AppScope=<app_id>`
 *
 * Returns all matching blobs sorted ascending by block height. In the
 * common case there's exactly one blob per tag (the protocol disallows
 * republishing at the same tag); ordering matters only for edge cases
 * where a gateway has split history.
 */
export async function findShareLogBlobs(
  client: MultiGatewayClient,
  args: FindShareLogBlobsArgs,
): Promise<BlobRecord[]> {
  const tags = [
    { name: 'App', values: ['tarn-share'] },
    { name: 'Type', values: ['share-log-v1'] },
    { name: 'To', values: [args.logTag] },
    { name: 'AppScope', values: [args.appScope] },
  ];
  const edges = await paginateAll(client, tags);
  return sortByHeightAscending(edges).map((e) => makeBlobRecord(client, e));
}

// ============ Share-inbox blobs ============

export interface FindShareInboxBlobsArgs {
  /** Stealth inbox tag (deriveInboxTag output). */
  inboxTag: string;
}

/**
 * Find share-inbox blobs by stealth tag. Tag scheme (per
 * `api/src/routes/share-inbox.js` §147):
 *
 *   `App=tarn-share, Type=connection-request-v1|connection-accept-v1, To=<inbox_tag>`
 *
 * Both `connection-request-v1` and `connection-accept-v1` blobs share
 * the same `To` tag scheme (the inbox is bidirectional from the inbox
 * owner's perspective), so we ask GraphQL for both Types in one query.
 */
export async function findShareInboxBlobs(
  client: MultiGatewayClient,
  args: FindShareInboxBlobsArgs,
): Promise<BlobRecord[]> {
  const tags = [
    { name: 'App', values: ['tarn-share'] },
    { name: 'Type', values: ['connection-request-v1', 'connection-accept-v1'] },
    { name: 'To', values: [args.inboxTag] },
  ];
  const edges = await paginateAll(client, tags);
  return sortByHeightAscending(edges).map((e) => makeBlobRecord(client, e));
}

// ============ Passkey credentials ============

export interface FindPasskeyCredentialsArgs {
  /** The account's data lookup key — passkey-reg blobs are tagged with `Lk=<dlk>`. */
  dataLookupKey: string;
}

/**
 * Find the live passkey credentials for an account. Tag scheme (per
 * `docs/TARN_PROTOCOL.md` §"Arweave mirror — `Type=passkey-reg` blobs"):
 *
 *   `App=tarn, Type=passkey-reg, Lk=<dlk>` (registrations)
 *   `App=tarn, Type=passkey-reg, Lk=<dlk>, CredId=<id>, Op=tombstone` (removals)
 *
 * Tombstone semantics are by `CredId` (NOT by `Ref=<txid>`). A credential
 * is excluded if any blob with its `CredId` carries `Op=tombstone`. We
 * apply the tombstone here because the rule is documented as part of the
 * passkey-reg tag scheme itself, not part of higher-level
 * collection/Eid resolution. Phase 4 handles tombstones for
 * collection content separately.
 *
 * Returns the live (non-tombstoned) credentials with their bodies loaded
 * and parsed as JSON. The latest registration per `CredId` wins.
 */
export async function findPasskeyCredentials(
  client: MultiGatewayClient,
  args: FindPasskeyCredentialsArgs,
): Promise<JsonBlobRecord[]> {
  const tags = [
    { name: 'App', values: ['tarn'] },
    { name: 'Type', values: ['passkey-reg'] },
    { name: 'Lk', values: [args.dataLookupKey] },
  ];
  const edges = await paginateAll(client, tags);

  // Group by CredId and detect tombstones.
  const byCredId = new Map<string, ArweaveEdge[]>();
  for (const edge of edges) {
    const credId = tagValue(edge.node, 'CredId');
    if (!credId) continue;
    const list = byCredId.get(credId) ?? [];
    list.push(edge);
    byCredId.set(credId, list);
  }

  const liveLatestPerCredId: ArweaveEdge[] = [];
  for (const [, list] of byCredId) {
    const tombstoned = list.some((e) => tagValue(e.node, 'Op') === 'tombstone');
    if (tombstoned) continue;
    // Latest registration wins (HEIGHT_ASC sort, take last).
    const sorted = sortByHeightAscending(list);
    const latest = sorted[sorted.length - 1];
    if (latest) liveLatestPerCredId.push(latest);
  }

  return Promise.all(liveLatestPerCredId.map((e) => asJsonBlob(client, e)));
}

// ============ Helpers ============

const MAX_PAGES = 50;
const PAGE_SIZE = 100;

/**
 * Walk all pages of a `transactions` query, with a hard ceiling to bound
 * latency. Returns every edge across all pages.
 */
async function paginateAll(
  client: MultiGatewayClient,
  tags: { name: string; values: string[] }[],
): Promise<ArweaveEdge[]> {
  const all: ArweaveEdge[] = [];
  let cursor: string | null = null;
  for (let page = 0; page < MAX_PAGES; page++) {
    // Use HEIGHT_DESC for stable cursor semantics across pages; we re-sort
    // ascending at the call site.
    const result = await client.queryTransactions({
      tags,
      sort: 'HEIGHT_DESC',
      first: PAGE_SIZE,
      after: cursor,
    });
    if (result.edges.length === 0) break;
    all.push(...result.edges);
    if (!result.hasNextPage || !result.endCursor) break;
    cursor = result.endCursor;
  }
  return all;
}

function tagValue(node: ArweaveNode, name: string): string | null {
  for (const t of node.tags) {
    if (t.name === name) return t.value;
  }
  return null;
}

/**
 * Sort by block height ascending; null heights (unconfirmed) sort last.
 * Stable: equal heights preserve input order.
 */
function sortByHeightAscending(edges: ArweaveEdge[]): ArweaveEdge[] {
  // Decorate-sort-undecorate to keep the sort stable on equal heights.
  return edges
    .map((edge, idx) => ({ edge, idx, height: edge.node.block?.height ?? Number.POSITIVE_INFINITY }))
    .sort((a, b) => (a.height - b.height) || (a.idx - b.idx))
    .map((x) => x.edge);
}
