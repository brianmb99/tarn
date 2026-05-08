// rebuild-core.mjs — pure logic for `tools/rebuild-from-arweave.mjs`.
//
// Phase C of the Arweave-recoverability fix
// (`docs/ARWEAVE_RECOVERABILITY_FIX_PLAN.md`).
//
// This module is the side-effect-free core of the rebuild tool. Everything
// here is exported pure functions over arrays of "edge"-shaped objects (the
// same {node:{id,tags,block,...}} shape Arweave's GraphQL API returns), plus
// optional fetched body bytes. The CLI in tools/rebuild-from-arweave.mjs
// drives I/O — GraphQL queries, gateway fetches, D1 writes — and hands the
// data to these functions.
//
// The split is deliberate: every tombstone-aware grouping and every
// blob-body parser is unit-testable here without hitting Arweave or D1.
// The CLI orchestration is integration-testable separately (and
// property-testable end-to-end via the rebuild-property script).

// ============ TAG HELPERS ============

export function tagValue(edgeOrNode, name) {
  const tags = edgeOrNode?.node?.tags || edgeOrNode?.tags || [];
  return tags.find((t) => t.name === name)?.value ?? null;
}

export function isTombstoneEdge(edge) {
  return tagValue(edge, 'Op') === 'tombstone';
}

/**
 * Sort edges by Arweave block.timestamp ASC, then by id (deterministic
 * tiebreak). Edges without a block (unconfirmed) sort to the end so
 * confirmed history wins ordering ties. "Latest" then is the last element
 * of the sorted array.
 */
export function sortEdgesByTimestamp(edges) {
  return [...edges].sort((a, b) => {
    const ta = a?.node?.block?.timestamp ?? Number.POSITIVE_INFINITY;
    const tb = b?.node?.block?.timestamp ?? Number.POSITIVE_INFINITY;
    if (ta !== tb) return ta - tb;
    const ia = a?.node?.id ?? '';
    const ib = b?.node?.id ?? '';
    return ia.localeCompare(ib);
  });
}

/**
 * Group edges by the value of a given tag, dropping any edge that lacks the
 * tag. Returns Map<tagValue, edges[]>.
 */
export function groupByTag(edges, tagName) {
  const groups = new Map();
  for (const edge of edges) {
    const v = tagValue(edge, tagName);
    if (v == null) continue;
    if (!groups.has(v)) groups.set(v, []);
    groups.get(v).push(edge);
  }
  return groups;
}

// ============ APPS ============

/**
 * Reduce a list of `App=tarn, Type=app-reg` edges + their fetched bodies
 * into rebuilt rows for the `apps` D1 table.
 *
 * Input shape: edges from the GraphQL query, plus `bodies` — a Map<txid,
 * Uint8Array|string|null> with the JSON body bytes for each edge (or null
 * if the body could not be fetched). Edges with no fetchable body are
 * counted as `bodyMisses` and skipped (the rebuild can't reconstruct an
 * apps row without the public_key from the body).
 *
 * No tombstones in v1 — the wire format documents app-deregistration as
 * future work. Latest blob per `app_id` wins.
 *
 * @returns {{rows: Array<{app_id, public_key, invite_url_template, created_at}>,
 *            stats: {found: number, rebuilt: number, bodyMisses: number, parseErrors: number}}}
 */
export function rebuildApps(edges, bodies) {
  const stats = { found: edges.length, rebuilt: 0, bodyMisses: 0, parseErrors: 0 };
  const groups = groupByTag(edges, 'Lk');
  const rows = [];

  for (const [appId, groupEdges] of groups) {
    const sorted = sortEdgesByTimestamp(groupEdges);
    const latest = sorted[sorted.length - 1];
    const txid = latest?.node?.id;
    const body = bodies.get(txid);
    if (body == null) {
      stats.bodyMisses += 1;
      continue;
    }
    let parsed;
    try {
      parsed = JSON.parse(typeof body === 'string' ? body : new TextDecoder().decode(body));
    } catch {
      stats.parseErrors += 1;
      continue;
    }
    if (!parsed || typeof parsed.app_id !== 'string' || typeof parsed.public_key !== 'string') {
      stats.parseErrors += 1;
      continue;
    }
    if (parsed.app_id !== appId) {
      // Mismatched body / tag — skip (caller may want to log).
      stats.parseErrors += 1;
      continue;
    }
    rows.push({
      app_id: parsed.app_id,
      public_key: parsed.public_key,
      invite_url_template: parsed.invite_url_template ?? null,
      created_at: Number.isFinite(parsed.created_at)
        ? parsed.created_at
        : (latest.node.block?.timestamp ? latest.node.block.timestamp * 1000 : Date.now()),
    });
    stats.rebuilt += 1;
  }

  return { rows, stats };
}

// ============ ACCOUNTS ============

/**
 * Reduce credential blob edges (`App=tarn, Type=cred`) + bodies into
 * `accounts` rows. Tombstones (`Op=tombstone, Ref=<txid>`) exclude their
 * referenced credential, and per `data_lookup_key` the latest non-tombstoned
 * blob wins (credential rotation creates multiple blobs sharing the same
 * dlk; latest defines the live `credential_lookup_key` and wrappings).
 *
 * Each input edge represents a credential blob. The body parses as the
 * structure built by `buildCredentialBlob` in api/src/routes/auth.js:
 *   { data_lookup_key, wrapped_data_key, public_key, app,
 *     [recovery_lookup_key], [recovery_public_key],
 *     [share_pub], [share_discoverable], [share_lookup_key],
 *     [wrapped_account_key] }
 *
 * The credential_lookup_key comes from the `Lk` tag (not the body).
 * recovery_lookup_key comes from the `RLk` tag when present (post 2026-05),
 * falling back to the body field for older blobs.
 */
export function rebuildAccounts(edges, bodies) {
  const stats = {
    found: edges.length,
    rebuilt: 0,
    tombstoned: 0,
    bodyMisses: 0,
    parseErrors: 0,
  };

  // 1. Build the tombstone-ref set. A live blob whose txid is referenced by
  //    any tombstone is considered deleted.
  const tombRefs = new Set();
  const liveEdges = [];
  for (const edge of edges) {
    if (isTombstoneEdge(edge)) {
      const ref = tagValue(edge, 'Ref');
      if (ref) tombRefs.add(ref);
    } else {
      liveEdges.push(edge);
    }
  }

  // 2. Drop tombstoned edges and group remaining by data_lookup_key (read
  //    from body since the tag carries credential_lookup_key, not dlk).
  //    For accounts that have rotated credentials, multiple blobs share the
  //    same dlk; latest non-tombstoned wins.
  const byDlk = new Map();
  for (const edge of liveEdges) {
    if (tombRefs.has(edge?.node?.id)) {
      stats.tombstoned += 1;
      continue;
    }
    const txid = edge?.node?.id;
    const body = bodies.get(txid);
    if (body == null) {
      stats.bodyMisses += 1;
      continue;
    }
    let parsed;
    try {
      parsed = JSON.parse(typeof body === 'string' ? body : new TextDecoder().decode(body));
    } catch {
      stats.parseErrors += 1;
      continue;
    }
    if (!parsed || typeof parsed.data_lookup_key !== 'string'
        || typeof parsed.wrapped_data_key !== 'string'
        || typeof parsed.public_key !== 'string'
        || typeof parsed.app !== 'string') {
      stats.parseErrors += 1;
      continue;
    }
    const dlk = parsed.data_lookup_key;
    if (!byDlk.has(dlk)) byDlk.set(dlk, []);
    byDlk.get(dlk).push({ edge, parsed });
  }

  const rows = [];
  for (const [dlk, entries] of byDlk) {
    entries.sort((a, b) => {
      const ta = a.edge?.node?.block?.timestamp ?? Number.POSITIVE_INFINITY;
      const tb = b.edge?.node?.block?.timestamp ?? Number.POSITIVE_INFINITY;
      if (ta !== tb) return ta - tb;
      return (a.edge?.node?.id ?? '').localeCompare(b.edge?.node?.id ?? '');
    });
    const winner = entries[entries.length - 1];
    const credLookupKey = tagValue(winner.edge, 'Lk');
    if (!credLookupKey) {
      stats.parseErrors += 1;
      continue;
    }
    // RLk tag is the canonical home for recovery_lookup_key (added 2026-05);
    // fall back to body field for pre-RLk blobs.
    const recoveryLookupKey = tagValue(winner.edge, 'RLk') ?? winner.parsed.recovery_lookup_key ?? null;
    const ts = winner.edge?.node?.block?.timestamp;
    const createdAt = ts ? ts * 1000 : Date.now();

    rows.push({
      credential_lookup_key: credLookupKey,
      public_key: winner.parsed.public_key,
      data_lookup_key: dlk,
      wrapped_data_key: winner.parsed.wrapped_data_key,
      app: winner.parsed.app,
      // rules_json is rebuilt separately from app-config blobs (Phase C step 4).
      rules_json: null,
      created_at: createdAt,
      recovery_lookup_key: recoveryLookupKey,
      recovery_public_key: winner.parsed.recovery_public_key ?? null,
      share_pub: winner.parsed.share_pub ?? null,
      share_discoverable: winner.parsed.share_pub != null
        ? (winner.parsed.share_discoverable === false ? 0 : 1)
        : 1, // SQL DEFAULT 1 — accounts without a share keypair default to discoverable.
      share_lookup_key: winner.parsed.share_lookup_key ?? null,
      wrapped_account_key: winner.parsed.wrapped_account_key ?? null,
    });
    stats.rebuilt += 1;
  }

  return { rows, stats };
}

// ============ PASSKEY CREDENTIALS ============

/**
 * Reduce `App=tarn, Type=passkey-reg` edges into `passkey_credentials` rows.
 *
 * Tombstoning is by-CredId (see passkey-reg.js): if any blob in a
 * `CredId`-keyed group carries `Op=tombstone`, the entire group is excluded.
 * Among the surviving (non-tombstoned) groups, latest blob per CredId wins.
 *
 * `account_id` in D1 is the credential's owning account's data_lookup_key
 * (string), recoverable from the blob body's `data_lookup_key` field.
 *
 * `sign_count` defaults to 0; `last_used_at` defaults to NULL — both are
 * runtime state explicitly out of scope for Arweave persistence.
 */
export function rebuildPasskeys(edges, bodies) {
  const stats = {
    found: edges.length,
    rebuilt: 0,
    tombstoned: 0,
    bodyMisses: 0,
    parseErrors: 0,
  };

  const groups = groupByTag(edges, 'CredId');

  const rows = [];
  for (const [credId, groupEdges] of groups) {
    const tombstoned = groupEdges.some(isTombstoneEdge);
    if (tombstoned) {
      stats.tombstoned += 1;
      continue;
    }
    const sorted = sortEdgesByTimestamp(groupEdges);
    const winner = sorted[sorted.length - 1];
    const txid = winner?.node?.id;
    const body = bodies.get(txid);
    if (body == null) {
      stats.bodyMisses += 1;
      continue;
    }
    let parsed;
    try {
      parsed = JSON.parse(typeof body === 'string' ? body : new TextDecoder().decode(body));
    } catch {
      stats.parseErrors += 1;
      continue;
    }
    if (!parsed
        || typeof parsed.data_lookup_key !== 'string'
        || typeof parsed.public_key !== 'string'
        || typeof parsed.prf_salt !== 'string'
        || typeof parsed.credential_id !== 'string') {
      stats.parseErrors += 1;
      continue;
    }
    if (parsed.credential_id !== credId) {
      stats.parseErrors += 1;
      continue;
    }
    rows.push({
      account_id: parsed.data_lookup_key,
      credential_id: credId,
      public_key: parsed.public_key,
      prf_salt: parsed.prf_salt,
      sign_count: 0,
      device_label: parsed.device_label ?? null,
      created_at: Number.isFinite(parsed.created_at)
        ? parsed.created_at
        : (winner.node.block?.timestamp ? winner.node.block.timestamp * 1000 : Date.now()),
      last_used_at: null,
    });
    stats.rebuilt += 1;
  }

  return { rows, stats };
}

// ============ APP-CONFIG → accounts.rules_json ============

/**
 * Reduce `App=tarn, Type=app-config` edges + bodies into a Map<dlk, rules_json>
 * suitable for `UPDATE accounts SET rules_json = ? WHERE data_lookup_key = ?`.
 *
 * The blob body shape (per `routes/apps.js`) is `{ rules, set_by, timestamp }`.
 * We persist `JSON.stringify(rules)` into `accounts.rules_json` exactly as
 * the live writer does.
 *
 * Note that `App` tag on the actual blob is the per-app `app_id`, NOT
 * `tarn` — the runtime writer (`apps.js:78`) sets `App=<app_id>`. The
 * rebuild scan therefore enumerates `Type=app-config` across every app
 * the user has registered. The CLI passes the union of edges across all
 * known apps (or `--app=<id>` filter when scoped).
 */
export function rebuildAppConfigRules(edges, bodies) {
  const stats = {
    found: edges.length,
    applied: 0,
    bodyMisses: 0,
    parseErrors: 0,
  };
  const groups = groupByTag(edges, 'Lk');
  const updates = new Map();

  for (const [dlk, groupEdges] of groups) {
    const sorted = sortEdgesByTimestamp(groupEdges);
    const winner = sorted[sorted.length - 1];
    const txid = winner?.node?.id;
    const body = bodies.get(txid);
    if (body == null) {
      stats.bodyMisses += 1;
      continue;
    }
    let parsed;
    try {
      parsed = JSON.parse(typeof body === 'string' ? body : new TextDecoder().decode(body));
    } catch {
      stats.parseErrors += 1;
      continue;
    }
    if (!parsed || !Array.isArray(parsed.rules)) {
      stats.parseErrors += 1;
      continue;
    }
    updates.set(dlk, JSON.stringify(parsed.rules));
    stats.applied += 1;
  }

  return { updates, stats };
}

// ============ SHARE-INBOX / SHARE-LOG ============

/**
 * Build share_inbox rows from `App=tarn-share, Type=connection-{request,accept}-v1`
 * edges and fetched ciphertext bodies. Multiple writers per `(tag, type)`
 * are expected — every blob becomes its own row keyed by txid.
 */
export function rebuildShareInbox(edges, bodies) {
  const stats = {
    found: edges.length,
    rebuilt: 0,
    bodyMisses: 0,
    parseErrors: 0,
  };
  const rows = [];
  for (const edge of edges) {
    const txid = edge?.node?.id;
    const inboxTag = tagValue(edge, 'To');
    const blobType = tagValue(edge, 'Type');
    const appScope = tagValue(edge, 'AppScope');
    if (!txid || !inboxTag || !blobType || !appScope) {
      stats.parseErrors += 1;
      continue;
    }
    const body = bodies.get(txid);
    if (body == null) {
      stats.bodyMisses += 1;
      continue;
    }
    const ciphertext = body instanceof Uint8Array
      ? body
      : new TextEncoder().encode(typeof body === 'string' ? body : '');
    const ts = edge?.node?.block?.timestamp;
    rows.push({
      txid,
      app_id: appScope,
      inbox_tag: inboxTag,
      blob_type: blobType,
      ciphertext,
      published_at: ts ? ts * 1000 : Date.now(),
    });
    stats.rebuilt += 1;
  }
  return { rows, stats };
}

/**
 * Build share_log rows. Same shape as inbox, but with the additional
 * `data_lookup_key` column — which is NOT in any Arweave tag (per the
 * audit, this is operator metadata, sender-attribution is unrecoverable).
 * We fill it with NULL on rebuild and let the operator scope it back later
 * if needed; the column is NOT NULL in the schema, so we have to set
 * something — we use the empty string '' as the deliberate sentinel for
 * "unknown sender on rebuild" and document it in the protocol doc.
 */
export function rebuildShareLog(edges, bodies, { unknownSenderSentinel = '' } = {}) {
  const stats = {
    found: edges.length,
    rebuilt: 0,
    bodyMisses: 0,
    parseErrors: 0,
  };
  const rows = [];
  // De-dupe by (app, log_tag, blob_type) — share_log has a UNIQUE index on
  // this triplet (the §9.1 collision check). On Arweave a single tag can
  // legitimately have only one accepted blob (writer enforces the uniqueness),
  // but to be safe across replays we keep the latest by timestamp.
  const seen = new Map();
  for (const edge of edges) {
    const txid = edge?.node?.id;
    const logTag = tagValue(edge, 'To');
    const blobType = tagValue(edge, 'Type');
    const appScope = tagValue(edge, 'AppScope');
    if (!txid || !logTag || !blobType || !appScope) {
      stats.parseErrors += 1;
      continue;
    }
    const key = `${appScope}|${logTag}|${blobType}`;
    const existing = seen.get(key);
    const ts = edge?.node?.block?.timestamp ?? Number.POSITIVE_INFINITY;
    const existingTs = existing?.edge?.node?.block?.timestamp ?? Number.POSITIVE_INFINITY;
    if (!existing || ts > existingTs) {
      seen.set(key, { edge, ts });
    }
  }
  for (const { edge } of seen.values()) {
    const txid = edge?.node?.id;
    const body = bodies.get(txid);
    if (body == null) {
      stats.bodyMisses += 1;
      continue;
    }
    const ciphertext = body instanceof Uint8Array
      ? body
      : new TextEncoder().encode(typeof body === 'string' ? body : '');
    const ts = edge?.node?.block?.timestamp;
    rows.push({
      txid,
      app_id: tagValue(edge, 'AppScope'),
      log_tag: tagValue(edge, 'To'),
      blob_type: tagValue(edge, 'Type'),
      ciphertext,
      data_lookup_key: unknownSenderSentinel,
      published_at: ts ? ts * 1000 : Date.now(),
    });
    stats.rebuilt += 1;
  }
  return { rows, stats };
}
