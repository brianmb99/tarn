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
    shareKeySuperseded: 0,
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
      // block_timestamp is the winning credential blob's Arweave confirmation
      // time (seconds, or null if unconfirmed). It is NOT a D1 column — it is
      // carried so the share_lookup_key dedup below can pick the most-recent
      // registration per email, matching live #30 semantics. Stripped before
      // the row is emitted to SQL.
      block_timestamp: ts ?? null,
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
  }

  // Second dedup pass: the `accounts` table has a partial UNIQUE index on
  // non-NULL `share_lookup_key` (idx_accounts_share_lookup_key, per #30).
  // Real Arweave history can contain multiple credential blobs with DISTINCT
  // data_lookup_key but the SAME share_lookup_key (the same email re-registered
  // as different accounts over dev history — legit pre-#30 / test cruft). The
  // per-dlk resolution above does not catch that collision, so without this
  // pass two surviving rows would violate the UNIQUE(share_lookup_key) index
  // and abort the whole `wrangler d1 execute --file` batch (#41). We keep only
  // the most-recent registration per non-NULL share_lookup_key, matching live
  // semantics. NULL share_lookup_key rows (legacy) have no uniqueness
  // constraint and are all kept.
  const deduped = dedupeBySharelookupKey(rows);
  stats.shareKeySuperseded = rows.length - deduped.length;
  // Strip the dedup-only helper field; it is not a D1 column.
  const emitted = deduped.map(({ block_timestamp, ...row }) => row);
  stats.rebuilt = emitted.length;

  return { rows: emitted, stats };
}

/**
 * Collapse account-candidate rows so that no two surviving rows share a
 * non-NULL `share_lookup_key`. This mirrors the live #30 uniqueness invariant:
 * a given email's `share_lookup_key` is held by its most-recent registration.
 *
 * Winner rule (same notion of "newest" as the per-dlk credential supersede):
 *   - Highest `block_timestamp` wins (Arweave block confirmation time, seconds).
 *   - A null/undefined `block_timestamp` (unconfirmed at scan time) is treated
 *     as newest — it sorts after any confirmed timestamp, so it wins. This
 *     matches `sortEdgesByTimestamp`, which sorts missing timestamps to the end
 *     ("latest").
 *   - Tie on `block_timestamp`: deterministic pick by the lexicographically
 *     LARGEST `credential_lookup_key` (the stable per-row identifier), mirroring
 *     the id-based tiebreak in the per-dlk sort where the last element wins.
 *
 * Rows with a NULL/empty `share_lookup_key` are never deduped — they carry no
 * uniqueness constraint and are all returned. Input order of surviving rows is
 * otherwise preserved.
 *
 * Pure: does not mutate the input array or its row objects.
 *
 * @param {Array<{credential_lookup_key: string, share_lookup_key: ?string, block_timestamp: ?number}>} accounts
 * @returns {Array} the deduped subset (a new array; same row object references)
 */
export function dedupeBySharelookupKey(accounts) {
  // Index of the current winner per non-null share_lookup_key.
  const winnerByShareKey = new Map();
  // Marks losing positions so we can preserve order for everything else.
  const dropped = new Set();

  function newer(a, b) {
    // Returns true if candidate `a` should beat current winner `b`.
    const ta = a.block_timestamp == null ? Number.POSITIVE_INFINITY : a.block_timestamp;
    const tb = b.block_timestamp == null ? Number.POSITIVE_INFINITY : b.block_timestamp;
    if (ta !== tb) return ta > tb;
    // Tie-break: lexicographically larger credential_lookup_key wins.
    const ia = a.credential_lookup_key ?? '';
    const ib = b.credential_lookup_key ?? '';
    return ia.localeCompare(ib) > 0;
  }

  for (let i = 0; i < accounts.length; i++) {
    const row = accounts[i];
    const sk = row.share_lookup_key;
    if (sk == null || sk === '') continue; // NULL/empty: no uniqueness constraint.
    const current = winnerByShareKey.get(sk);
    if (!current) {
      winnerByShareKey.set(sk, { row, index: i });
      continue;
    }
    if (newer(row, current.row)) {
      dropped.add(current.index);
      winnerByShareKey.set(sk, { row, index: i });
    } else {
      dropped.add(i);
    }
  }

  const out = [];
  for (let i = 0; i < accounts.length; i++) {
    if (!dropped.has(i)) out.push(accounts[i]);
  }
  return out;
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
