// Arweave GraphQL query layer — new tag scheme only (App, Type, Addr, Lk)
// Ported from public/js/core/arweave_query.js but queries new tags.

const ARWEAVE_GRAPHQL = 'https://arweave.net/graphql';

/**
 * Resilient Arweave GraphQL query. Never throws for HTTP/parse errors.
 */
async function queryGraphQL(query, variables) {
  try {
    const res = await fetch(ARWEAVE_GRAPHQL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(variables ? { query, variables } : { query }),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return { data: null, error: `http_${res.status}` };
    const json = await res.json();
    if (json.errors?.length) return { data: null, error: json.errors[0].message };
    return { data: json.data, error: null };
  } catch (err) {
    return { data: null, error: err.message };
  }
}

/**
 * Search entries by wallet address (App + Type + Addr tags).
 * Used for book entries and any wallet-addressed entry types.
 */
export async function searchEntriesByAddr(addr, { app, type, cursor = null, limit = 100 } = {}) {
  const tags = [
    { name: 'App', values: [app] },
    { name: 'Type', values: [type] },
    { name: 'Addr', values: [addr.toLowerCase()] },
  ];

  const q = `query($after:String,$first:Int,$tags:[TagFilter!]){
    transactions(after:$after,first:$first,sort:HEIGHT_DESC,tags:$tags){
      pageInfo{hasNextPage}
      edges{cursor node{id tags{name value}block{timestamp height}}}
    }
  }`;

  const { data, error } = await queryGraphQL(q, { after: cursor, first: limit, tags });
  if (error) return { edges: [], hasNextPage: false, error };

  const txns = data?.transactions;
  return {
    edges: txns?.edges || [],
    hasNextPage: !!txns?.pageInfo?.hasNextPage,
    error: null,
  };
}

/**
 * Search entries by lookup key (App + Type + Lk tags).
 * Used for credential mappings, account metadata, and data-entry cold
 * bootstrap. Single page; use fetchAllPagesByLookupKey for a full scan.
 */
export async function searchEntriesByLookupKey(lookupKey, { app, type, cursor = null, limit = 100 } = {}) {
  const tags = [
    { name: 'App', values: [app] },
    { name: 'Type', values: [type] },
    { name: 'Lk', values: [lookupKey] },
  ];

  const q = `query($after:String,$first:Int,$tags:[TagFilter!]){
    transactions(after:$after,first:$first,sort:HEIGHT_DESC,tags:$tags){
      pageInfo{hasNextPage}
      edges{cursor node{id tags{name value}block{timestamp height}}}
    }
  }`;

  const { data, error } = await queryGraphQL(q, { after: cursor, first: limit, tags });
  if (error) return { edges: [], hasNextPage: false, error };

  const txns = data?.transactions;
  return {
    edges: txns?.edges || [],
    hasNextPage: !!txns?.pageInfo?.hasNextPage,
    error: null,
  };
}

/**
 * Fetch all pages of entries for a lookup key (tarn#64).
 *
 * Cold bootstrap must ingest the COMPLETE live set before the cache layer
 * latches its "D1 is authoritative" marker — a single 10-entry page silently
 * truncated rebuilds of any collection with more live entries.
 *
 * MAX_PAGES bounds Worker resource use; `truncated: true` tells the caller
 * the scan stopped with pages remaining (the caller must NOT latch its
 * bootstrap marker in that case, so the next read resumes the ingest).
 *
 * @returns {Promise<{edges: Array, error: string|null, truncated: boolean}>}
 */
export async function fetchAllPagesByLookupKey(lookupKey, { app, type } = {}) {
  const allEdges = [];
  let cursor = null;
  let pages = 0;
  const MAX_PAGES = 20;

  while (pages < MAX_PAGES) {
    const { edges, hasNextPage, error } = await searchEntriesByLookupKey(lookupKey, { app, type, cursor, limit: 100 });

    if (error) {
      console.warn('[tarn-api] Arweave lookup-key query error on page', pages, ':', error);
      return { edges: allEdges, error, truncated: false };
    }

    allEdges.push(...edges);

    if (!hasNextPage || edges.length === 0) {
      return { edges: allEdges, error: null, truncated: false };
    }
    cursor = edges[edges.length - 1].cursor;
    pages++;
  }

  console.warn('[tarn-api] Lookup-key scan hit MAX_PAGES with pages remaining — bootstrap marker must not latch', { app, type });
  return { edges: allEdges, error: null, truncated: true };
}

/**
 * Fetch all pages of entries for a wallet, stopping early when we hit known txids.
 * @param {string} addr - wallet address
 * @param {Object} opts - app, type
 * @param {Set<string>|null} knownTxids - txids already in D1 (for incremental refresh)
 * @returns {Promise<{edges: Array, error: string|null}>}
 */
export async function fetchAllPages(addr, { app, type }, knownTxids = null) {
  const allEdges = [];
  let cursor = null;
  let pages = 0;
  const MAX_PAGES = 20;

  while (pages < MAX_PAGES) {
    const { edges, hasNextPage, error } = await searchEntriesByAddr(addr, { app, type, cursor, limit: 100 });

    if (error) {
      console.warn('[tarn-api] Arweave query error on page', pages, ':', error);
      return { edges: allEdges, error };
    }

    if (edges.length === 0) break;

    // Short-circuit: if all edges on this page are already known, stop paginating
    let allKnown = knownTxids && edges.length > 0;
    for (const edge of edges) {
      allEdges.push(edge);
      if (knownTxids && !knownTxids.has(edge.node.id)) {
        allKnown = false;
      }
    }

    if (allKnown) {
      console.log('[tarn-api] Short-circuit: all', edges.length, 'entries on page', pages, 'already cached');
      break;
    }

    if (!hasNextPage) break;
    cursor = edges[edges.length - 1].cursor;
    pages++;
  }

  return { edges: allEdges, error: null };
}
