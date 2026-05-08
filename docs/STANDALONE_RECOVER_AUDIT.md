# Phase 1 audit — `@tarn/recover` reusable surface

> **Status:** Phase 1 of the [Standalone recovery package plan](./STANDALONE_RECOVERY_PLAN.md). Pure analysis. Input for Phases 2-9.
>
> **Method:** Read every file under `client/src/`, traced the live read path through `client/src/tarn.ts` and `api/src/routes/`, cross-checked the protocol doc against current envelope handling.

## TL;DR

Roughly **60–65% of what `@tarn/recover` needs already exists as pure WebCrypto/`@noble`/`@hpke` code in the SDK** — `crypto.ts`, `recovery.ts`, `share-log.ts`, `sharing.ts`, the schema modules, and `collections/eid.ts` can be reused near-verbatim. The net-new work is concentrated in three buckets: (1) a gateway-direct Arweave reader (GraphQL + blob HTTP fetches with multi-gateway fallback), (2) replacing the API-call-based `getEntries` / share-log fetch / inbox fetch with their gateway-direct equivalents, and (3) a small number of read-side helpers that today live as private methods on `TarnClient` (`#decryptBlob`, `#findShareStateEntry`, the readShareLog walk) but are pure logic and just need extracting.

**`username` is NOT cryptographically required** — see Section D.

---

## A. Module-by-module classification

### Pure (reusable verbatim)

| Module | Lines | Why it's pure |
|---|---|---|
| `client/src/crypto.ts` | 1–1323 | Zero network, zero `TarnClient` state. Pure WebCrypto + `@noble/curves` + `hash-wasm`. Includes Argon2id KDF (`deriveMasterKey` 234-257, `deriveRecoveryKey` 274-309), HKDF-Expand (202-223), all key derivations (312-488), AES-GCM (`encrypt` 519, `decrypt` 533), AES-KW (795-810), envelope parsing (`parseWrappedDataKey` 876-1009), DEK-chain unwrap (`unwrapDataKeyChain` 1032-1075), per-content-CEK blob decode (`decryptWithCEK` 723-748, `decryptBlobWithSharedCEK` 759-787), magic-prefix detection (`hasTarnBlobMagic` 658-666), wrapped-account-key decrypt (`unwrapAccountKey` 594-613), and the encoding helpers (1252-1323). **Reuse 100%.** |
| `client/src/recovery.ts` | 1–69 | BIP39 wrapper around `@scure/bip39`. `validateAccountKey` (38-51) and `accountKeyToEntropy` (59-63) are exactly what the recover flow needs. **Reuse 100%.** |
| `client/src/share-log.ts` | 1–812 | Pure crypto + state-machine module. Per-pair key derivations (`deriveSharedSecret` 141, `derivePairKeys` 176-212), tag derivation (`deriveLogTag` 230-242), canonical JSON (246-281), operation parsing/validation (283-488), AES-GCM seal/open of share-log entries (`encryptShareLogEntry` 577, `decryptShareLogEntry` 598-618), ECDSA sig verification (`verifyOperationSignature` 521-561), `discoverHighestSeq` (655-710), and `applyOperationToState` / `replayOperations` (725-812). **Reuse 100%.** The `discoverHighestSeq` already takes a `probe` callback so it works against any backend — feed it a gateway-direct probe. |
| `client/src/sharing.ts` | 1–862 | Pure HPKE seal/open + payload validators + connection-record helpers. `inboxWindowFor`/`recentInboxWindows` (98-117), `deriveInboxTag` (139-170), `hpkeOpen` (236-259), `validateConnectionRequestPayload` (347-423), `validateConnectionAcceptPayload` (474-530), `findOutboundForAccept` (573-584), record-shape helpers (621-810), `MUTED_CONNECTIONS_CONTENT_ID` etc. The recover client only needs the read/decode side (`hpkeOpen`, validators, content-id constants) — but the whole module is import-clean. **Reuse 100%.** |
| `client/src/sharing/types.ts` | 1–199 | Type definitions. **Reuse 100%.** |
| `client/src/schema/*.ts` | (all 5 files, 594 LOC) | `defineSchema`, `validateRecordForCreate/Update`, types. No I/O. The recover client only needs `validate*` for shape-checking decoded entries; reuse the modules wholesale. **Reuse 100%.** |
| `client/src/collections/eid.ts` | 1–44 | Pure SHA-256 helper for deterministic Eid derivation. `@tarn/recover` doesn't write so doesn't strictly need it, but reusing keeps "what is an Eid" code-defined in one place. **Reuse 100%.** |
| `client/src/collections/types.ts` | 1–148 | Type definitions for `DecryptedEntry`, `Tag`, `ShareConnection`. **Reuse 100%.** |

### Coupled (depends on TarnClient state, but the logic is portable)

| Module / function | Where | What's coupled | Decoupling cost |
|---|---|---|---|
| `Collection<T>` | `client/src/collections/collection.ts` 39-298 | Constructor takes an `ITarnClient`; calls `client.createEntry/updateEntry/deleteEntry/getEntries/...`. The READ slice (`list`, `get`, `listShared` 109-231) only needs `getEntries`, `readShareLog`, `fetchBlob`, `decryptSharedBlob`. | Trivial: write a read-only `Collection` (or just inline the body of `list()` lines 109-126: it's just `getEntries(name) → map e.data`) over the new gateway-direct backend. |
| `TarnClient.#decryptBlob` | `client/src/tarn.ts` 5986-5996 | Reads `this.#dekByGen` + `this.#currentGen`. | Pure logic — extract as `decryptOwnedBlob(dekByGen, blobBytes, tags)`. ~10 lines. |
| `TarnClient.#findShareStateEntry` | `tarn.ts` 5489-5496 | Iterates `getEntries('tarn-share-state')` and matches on `Eid` tag. | Pure logic — extract as `findShareStateEntry(entries, contentId)`. |
| `TarnClient.readShareLog` | `tarn.ts` 4380-4487 | Calls `#requireAuth`, `#getPairKeysFor`, `#probeInboundTagExists` (which calls `#getShareLogBlobByTag` against the API), `_fetchShareLogEntry`, `#processRotateIdentityEntry`. | The orchestration logic (snapshot-walk, replay) is reusable; the I/O dependencies (`#getShareLogBlobByTag` API call, `#probeInboundTagExists`) need swapping for gateway-direct. The `#getPairKeysFor` derives `derivePairKeys()` over X25519 ECDH and is pure once you supply `share_priv` + peer `share_pub`. |
| `TarnClient.#getPairKeysFor` | `tarn.ts` 4002-4023 | Reads `this.#sharingKeyPair.privateKey`. | Pure — accept `(sharePriv, peerSharePub, appId)` and return `derivePairKeys()` output. The pair-key cache is a perf-only concern; recover client can skip caching or use a plain `Map`. |
| `_fetchShareLogEntry` | (search the read path through `tarn.ts`; called from `readShareLog` 4421) | Wraps `#getShareLogBlobByTag` (line 5275) which calls Tarn's `/api/v1/share/log/fetch`. | Replace inner fetch with a gateway-direct GraphQL probe by `To` tag (the share-log Arweave tag scheme is documented at `api/src/routes/share-log.js` 113-119: `App=tarn-share, Type=share-log-v1, To=<log_tag>, AppScope=<app_id>`). |
| `TarnClient.#loadConnectionsRecord` | `tarn.ts` 5403-5409 | Reads `getEntries('tarn-share-state')` and finds the entry tagged `Eid=tarn-connections-v1`. | Pure given gateway-direct `getEntries`. |

### API-dependent (needs net-new gateway-direct equivalent)

| Behavior | Current path | Net-new gateway-direct path |
|---|---|---|
| List user's content blobs | `TarnClient.getEntries(type)` `tarn.ts` 2772-2825 → `GET /api/v1/entries?app=...&type=...&key=<dlk>` (returns metadata) → per-blob `#fetchBlob` 6106-6129 → `GET /api/v1/entries/{txid}` → base64 → bytes. Worker resolves Prev/Eid/tombstone server-side (`refreshCache` + `getResolvedEntries` in `api/src/routes/entries.js` 37-83). | GraphQL by `App + Type + Lk` tags (mirror of `api/src/arweave.js` 59-79 `searchEntriesByLookupKey`), HTTP `GET <gateway>/<txid>` for the raw blob, **and** client-side resolution of Prev chains + Eid dedup + tombstone application (logic that today is in `api/src/cache.js`/resolver — needs porting). |
| Fetch single blob | `#fetchBlob` 6106-6129 → `/api/v1/entries/{txid}` | `GET <gateway>/<txid>` with multi-gateway fallback. |
| Fetch share-log blob by tag | `#getShareLogBlobByTag` `tarn.ts` 5275-5289 → `GET /api/v1/share/log/fetch?app=...&tag=...&type=share-log-v1` | GraphQL by `App=tarn-share + Type=share-log-v1 + To=<log_tag> + AppScope=<app_id>`, then HTTP fetch the txid. |
| Fetch inbox blobs by tag | `#fetchInboxBlobs` `tarn.ts` 5293-5308 → `/api/v1/share/inbox/fetch` | GraphQL by `App=tarn-share + Type=connection-request-v1\|connection-accept-v1 + To=<inbox_tag>`, then HTTP fetch each. |
| Locate the account record | `recoverAccount` `tarn.ts` 528-820 → `POST /api/v1/auth/challenge { recovery_lookup_key }` returns `{ wrapped_data_key, data_lookup_key, nonce }`. Tarn-mediated. | GraphQL by `App=tarn + Type=cred + Lk=<recovery_lookup_key>` — but **the credential blob currently uses `Lk = credential_lookup_key`, not `recovery_lookup_key`** (see `api/src/routes/auth.js` 55-57 and 812-816, plus protocol §"Arweave Tag Scheme" line 512). For a gateway-direct lookup keyed by `recovery_lookup_key`, the credential blob must publish a *secondary* tag (`RLk` or `RecoveryLk`) carrying the recovery lookup key, OR the recovery client must take a different lookup path. **This is a real gap for the contract** — the account record is currently NOT discoverable on Arweave from the account-key-only inputs. See "Open issue" below. |

---

## B. Live read-path traces

### B.1. `tarn.collections.books.list()` — read all owned content

1. **Typed surface** — `Collection.list()` (`collections/collection.ts` 109-126) calls `client.getEntries(name)` and maps `e.data` to typed records.
2. **`TarnClient.getEntries(type)`** (`tarn.ts` 2772-2825):
   - **Auth** — `await this.#requireAuth()` (line 2773; see 6002-6029) — verifies JWT, refreshes via challenge-response if expired. **API-dependent.**
   - **List metadata** — paginated `GET /api/v1/entries?app=...&type=...&key=<data_lookup_key>` (lines 2779-2795). Server returns `{txid, tags, confirmed, ...}` per entry; **server already resolves Prev chains + Eid dedup + tombstones** (`api/src/routes/entries.js` 60 → `getResolvedEntries`). **API-dependent.**
   - **Per-blob fetch** — for each entry, `#fetchBlob(txid)` (lines 2807-2810; 6106-6129) → `GET /api/v1/entries/{txid}` → `base64ToBytes(json.data)`. Server lazy-loads from a public Arweave gateway internally if D1 is cold. **API-dependent.**
   - **Decrypt** — `#decryptBlob(blobBytes, tags)` (line 2811; 5986-5996): `readGenTag(tags) ?? 1` → `dek = #dekByGen.get(gen)` → `decryptWithCEK(dek.kwKey, blobBytes)`. **Pure** (uses `crypto.ts` `decryptWithCEK`).
3. Returns `[{txid, data, tags}]`.

**Net-new for `@tarn/recover`:** steps 2a–c. Step 2d (decrypt) is reusable.

### B.2. `tarn.connections.list()` — read connection records

1. **Typed surface** — `ConnectionsNamespace.list()` (`namespaces/connections.ts` 107-110) calls `client.listConnections()` and re-shapes via `#toConnection`.
2. **`TarnClient.listConnections()`** (`tarn.ts` 3499; verified earlier in the grep) calls `#loadConnectionsRecord()` (5403-5409).
3. **`#loadConnectionsRecord()`** → `#findShareStateEntry(CONNECTIONS_CONTENT_ID)` (5489-5496):
   - Calls `getEntries('tarn-share-state')` — same path as B.1, just different `type` value.
   - Filters entries by `Eid === 'tarn-connections-v1'`.
4. Returns the decrypted JSON from the matching entry's `data` field — i.e., `{app_id, version, connections: [...]}`.

**Net-new for `@tarn/recover`:** same as B.1. The record-decoding side is pure (`#findShareStateEntry` is 7 lines of in-memory filter).

### B.3. `tarn.shareLog.read(connection)` — read per-pair share log

(Currently exposed via `TarnClient.readShareLog` 4380-4487; the SDK re-exports this via collection `listShared` and a few namespaces — there's no top-level `tarn.shareLog` namespace.)

1. **Auth** — `#requireAuth()`. API-dependent.
2. **Derive per-pair keys** — `#getPairKeysFor(connection.share_pub)` (4002-4023) does X25519 ECDH (`deriveSharedSecret` from `share-log.ts` 141) + HKDF (`derivePairKeys` 176-212). **Pure given `share_priv` and peer `share_pub`.**
3. **Highest-seq discovery** — `discoverHighestSeq` (`share-log.ts` 655-710) with `probe = (seq) => #probeInboundTagExists(pair, seq)`:
   - `deriveLogTag(pair.inboundTagSeed, seq)` — pure (`share-log.ts` 230).
   - `#getShareLogBlobByTag(tag)` (5275-5289) — **API call** to `/api/v1/share/log/fetch`.
4. **Walk back to last snapshot** — for each `seq`, `_fetchShareLogEntry(connection, seq)` → fetch + verify ECDSA signature (`verifyOperationSignature` `share-log.ts` 521) + decrypt (`decryptShareLogEntry` 598). Verify is pure; decrypt is pure; fetch is API-dependent.
5. **Apply snapshot, walk forward** — `applyOperationToState` (`share-log.ts` 725-796) on each entry. **Pure.**
6. **Handle `OP_ROTATE_IDENTITY`** — `#processRotateIdentityEntry` mutates the connection record, recurses on `readShareLog` against the rotated connection. The mutation logic (`rotateConnectionIdentity` `sharing.ts` 681-714) is pure; the persistence/recursion is what couples it to `TarnClient`.

**Net-new for `@tarn/recover`:**
- Replacement `probe` and `_fetchShareLogEntry` that hit Arweave gateways via `App=tarn-share + Type=share-log-v1 + To=<log_tag> + AppScope=<app_id>` GraphQL.
- Decoupled `getPairKeys(sharePriv, peerSharePub, appId)` helper (already pure under the hood, just needs an extraction).
- Skip `#processRotateIdentityEntry`'s side effect (no need to persist anything during recovery) but still respect "rotate_identity is terminal on the OLD log; switch to NEW log" semantics for read fidelity.

---

## C. Net-new component list

Synthesized from A and B.

| # | Component | Where it goes | Notes |
|---|---|---|---|
| 1 | **Multi-gateway Arweave client** — `class GatewayClient { graphql(query, variables); fetchBlob(txid); }` with ordered fallback per `STANDALONE_RECOVERY_PLAN.md` Phase 2 failure rules (5xx, 429, network, "TX not found" → next gateway; surface retry via `onProgress`; only fail when all exhausted). | `src/gateway/client.ts` | All net-new. Cite `arweave.js` 1-79 in the API codebase as the wire-format reference. |
| 2 | **GraphQL query helpers** — `findCredentialByLookupKey(lookupKey)`, `findEntries(app, type, lk, after?)`, `findShareLogBlob(appId, logTag)`, `findInboxBlobs(appId, type, inboxTag)`. | `src/gateway/queries.ts` | Mirror the API's `searchEntriesByLookupKey` (`api/src/arweave.js` 59-79) and `searchEntriesByAddr` (30-53) tag schemes. |
| 3 | **Account-record discovery from account key alone** — see "Open issue" below. Either (a) tag the credential blob with both `Lk=credential_lookup_key` and (new) `RLk=recovery_lookup_key`, or (b) accept that the recovery client needs `username` + `password` to find the credential blob (defeats the point). | New tag in `api/src/routes/auth.js` writes; gateway query in `src/gateway/queries.ts`. | **This is a protocol-level addition** required for the standalone-recovery contract to hold. Phase 1 cannot resolve it alone — flag for Phase 2. |
| 4 | **Browser-deliverable Argon2id** — already used via `hash-wasm` in `crypto.ts` 11. Verify it loads in a single-page recovery context (no bundler magic). | (No new file — bundle config concern) | The package.json + bundling setup in Phase 2. |
| 5 | **Decoupled DEK-chain unwrap entry point** — wraps `parseWrappedDataKey` + `deriveRecoveryKey` + `unwrapDataKeyChain` into a single "given account key + envelope, return DEKs". Currently inlined into `recoverAccount` `tarn.ts` 567-577. | `src/recovery/unwrap.ts` | ~30 lines of orchestration; underlying primitives are reusable from `crypto.ts`. |
| 6 | **Tombstone + Prev-chain + Eid resolver** — port the server-side resolver logic (currently in `api/src/cache.js`/`getResolvedEntries`) to the client. Given an array of decoded entries with their Eid + Prev tags, emit only the live tip per Eid, dropping tombstoned ones. | `src/reader/resolve.ts` | The pure logic is small (LWW per Eid by block timestamp / position). API-side reference: `api/src/routes/entries.js` 60 `getResolvedEntries`. |
| 7 | **Schema-aware reader** — given resolved entries, schema, app id, yield typed plaintext via async iterator. Wraps the resolver + `decryptOwnedBlob`. Tags each entry with `_schemaVersion` from the `SchemaV` Arweave tag (per `STANDALONE_RECOVERY_PLAN.md` API shape). | `src/reader/entries.ts` | Tombstone count exposed as `reader.tombstoneCount`. |
| 8 | **Share-log entry lookup by stealth tag** — gateway-direct GraphQL by `To=<log_tag>` (sharing-protocol §4.4). | `src/gateway/queries.ts` | Tag scheme: `App=tarn-share, Type=share-log-v1, To=<log_tag>, AppScope=<app_id>` (see `api/src/routes/share-log.js` 116-119). |
| 9 | **Per-pair share-log key derivation, decoupled** — accept `(ownSharePriv: Uint8Array, peerSharePub: Uint8Array, appId: string)`, return `derivePairKeys()` output. Trivial extraction of `tarn.ts` 4002-4023. | `src/sharing/pair.ts` | `derivePairKeys` itself (`share-log.ts` 176-212) is already exported and pure. |
| 10 | **Tombstone application logic** for connection records — mostly handled by reusing the connection-record JSON shape from `sharing.ts` (`ConnectionsRecord`, etc.); each share-state entry is a full snapshot, no tombstone semantics needed beyond resolving the live tip. **No new code.** | — | — |
| 11 | **Account record decoder** — given the credential blob bytes (which are *unencrypted* per protocol §"Credential Mapping on Arweave" lines 553-575), JSON.parse and return `{data_lookup_key, wrapped_data_key, public_key, recovery_lookup_key, recovery_public_key, wrapped_account_key?}`. | `src/recovery/account-record.ts` | ~10 lines. |
| 12 | **`recover()` orchestrator** — the public API per `STANDALONE_RECOVERY_PLAN.md` "Proposed API shape". Stitches gateway client + account-record lookup + DEK unwrap + reader + share-log walk + connections decoder, wires `onProgress` callbacks. | `src/index.ts` | The bulk of Phase 2 wiring. |
| 13 | **Username-only fallback path** (if needed per "Open issue") — derive `credential_lookup_key` from `(username, password)` and use it for the gateway lookup. Kept for completeness if account-key-alone discovery isn't added. | `src/recovery/lookup.ts` | Hopefully unneeded. |

### Open issue: account-record discoverability from account-key alone

The credential blob on Arweave is currently tagged only with `Lk = credential_lookup_key` (verified at `api/src/routes/auth.js` 55-57 and 812-816, and protocol doc line 512: *"For credential blobs: `Lk` = `credential_lookup_key`."*). The credential blob's *body* contains `recovery_lookup_key` (protocol §"Credential Mapping on Arweave" line 563), but you can't query GraphQL by body content.

**Implication:** an Arweave-direct reader given only `(account_key, app_id)` cannot find the credential blob without already knowing `credential_lookup_key`, which requires `master_key`, which requires `(username, password)`.

**Resolutions to surface in Phase 2:**
- **(a)** Add a secondary tag `RLk = recovery_lookup_key` to credential-blob writes (small change to `api/src/routes/auth.js` 49-67, 803-820, and `account.js` 102-118). Backfills naturally on next credential publish; older records remain Tarn-API-discoverable but not gateway-direct-discoverable. Acceptable trade-off given recovery records are republished on every credential operation. Recommended.
- **(b)** Add `username` to the inputs of `recover()` and use it to derive `credential_lookup_key` directly. Requires the password too (since `master_key = Argon2id(password, sha256(username))`); standalone recovery loses its "account key alone" promise.
- **(c)** Compute a `recovery_credential_lookup_key = HMAC(phrase_entropy, "tarn" || "recovery-cred-lookup" || app_id)` and tag the credential blob with that. Same as (a) with a different naming.

(a) is the cheapest and preserves the contract. **Recommend Phase 2 add the `RLk` tag.** This was not in the original plan estimate.

---

## D. Is `username` cryptographically required?

**No.** The recovery path is mathematically driven by account-key entropy alone, **subject to the discoverability gap in Section C.**

Walk through the actual derivations:

1. **Account-record lookup tag.** Per protocol §"Recovery Factor" (lines 152-167) and `crypto.ts` 312-331:
   ```
   recovery_lookup_key = HMAC-SHA256(phrase_entropy, "tarn" || "recovery-lookup" || app_id || "1" || 0x01)
   ```
   No username, no salt. **Reachable from account-key + app_id alone.** Code: `deriveRecoveryLookupKey` in `crypto.ts` 324-331.

2. **Recovery KEK derivation.** Per protocol line 161 and `crypto.ts` 274-309:
   ```
   recovery_KEK = Argon2id(account_key, recovery_salt, m=64MiB, t=3, p=1)
   ```
   `recovery_salt` is per-account random, **stored in the envelope** (`crypto.ts` `parseWrappedDataKey` 967-986, returned in `parsed.recovery.salt`). The envelope is part of the credential blob. So once you have the credential blob, you have the salt, and you can derive the KEK from `account_key` alone. **No username dependency.**

3. **Recovery signing keypair** (for authenticating to *Tarn's API* for credential rotation). Per `crypto.ts` `deriveRecoverySigningKeyPair` 342-361 — also derived from `phrase_entropy + app_id` only. **Not relevant for `@tarn/recover`** since the standalone reader does not authenticate to Tarn's API at all; it reads Arweave directly. Listing it for completeness.

4. **`master_key` and password-derived keys.** `master_key = Argon2id(password, sha256(normalizedUsername))` — only relevant for the *write* path and for the live SDK's password login. **Not in the recovery read path.** Confirmed by tracing `recoverAccount` `tarn.ts` 528-820: the only `username` reference is in the *re-registration* phase (line 599 `deriveAllKeys(newUsername, newPassword, ...)`), which establishes new credentials AFTER recovery succeeds. The recovery itself (lines 541-577) never touches a username.

5. **DEK-chain unwrap.** `unwrapDataKeyChain(envelope, recoveryKEK.kwKey, FACTOR_RECOVERY_PHRASE)` (`crypto.ts` 1032-1075, called from `tarn.ts` 573-577). All inputs: envelope (already fetched) + recovery KEK (derived from account-key + envelope salt). **No username.**

6. **Per-content blob decrypt.** `decryptWithCEK(dek.kwKey, blob)` (`crypto.ts` 723-748) — DEK selected by `Gen` tag from the chain. **No username.**

**Conclusion:** if the account record is reachable on Arweave by `recovery_lookup_key`, the entire decrypt chain proceeds from account-key only. Per Section C, the *current* tag scheme does not yet expose that lookup path — the credential blob is tagged by `credential_lookup_key`, not `recovery_lookup_key`. **The tag-scheme addition (Section C, resolution (a)) is what makes the account-key-alone promise actually reachable on a live Arweave gateway today.**

This matches the `STANDALONE_RECOVERY_PLAN.md` decision §3: "verify against current envelope shape before fixing the API. If username is genuinely optional crypto-wise, document it as such (and still ask for it in the UX as a weak identity verification)." → **Document as optional crypto-wise, ask for it in UX as confirmation only, fix the tag scheme so the contract holds end-to-end.**

---

## E. Proposed `@tarn/recover` directory structure

Concrete enough that Phase 2 can scaffold from this. "Borrowed" means copy-as-is or re-export from `tarn-client`; "Net-new" means write fresh.

```
@tarn/recover/
├── src/
│   ├── index.ts                          # NET-NEW. Public API: recover(), Reader class.
│   │
│   ├── crypto/
│   │   ├── index.ts                      # BORROWED — re-exports from tarn-client/crypto
│   │   │                                 #   (parseWrappedDataKey, unwrapDataKeyChain,
│   │   │                                 #    decryptWithCEK, decryptBlobWithSharedCEK,
│   │   │                                 #    deriveRecoveryKey, deriveRecoveryLookupKey,
│   │   │                                 #    accountKeyToEntropy, hasTarnBlobMagic,
│   │   │                                 #    base64* helpers).
│   │   └── argon2.ts                     # NET-NEW (thin) — verifies hash-wasm loads in browser.
│   │
│   ├── recovery/
│   │   ├── account-key.ts                # BORROWED — re-exports validateAccountKey, accountKeyToEntropy
│   │   │                                 #   from tarn-client/recovery (recovery.ts).
│   │   ├── account-record.ts             # NET-NEW — JSON-decode credential blob, return typed shape.
│   │   ├── unwrap.ts                     # NET-NEW (thin) — given accountKey + envelope, return DEK chain.
│   │   │                                 #   Wraps parseWrappedDataKey + deriveRecoveryKey +
│   │   │                                 #   unwrapDataKeyChain (~30 LOC).
│   │   └── lookup.ts                     # NET-NEW — derives recovery_lookup_key from accountKey+appId.
│   │
│   ├── gateway/
│   │   ├── client.ts                     # NET-NEW — multi-gateway fallback orchestration.
│   │   │                                 #   Failure rules: 5xx, 429, network, "TX not found" → next gateway.
│   │   ├── queries.ts                    # NET-NEW — GraphQL by tags.
│   │   │                                 #   findCredentialByRecoveryLookupKey(),
│   │   │                                 #   findEntriesByLookupKey(app, type, lk, cursor),
│   │   │                                 #   findShareLogBlob(appId, logTag),
│   │   │                                 #   findInboxBlobs(appId, type, inboxTag).
│   │   └── blob.ts                       # NET-NEW — HTTP GET <gateway>/<txid>, with fallback.
│   │
│   ├── reader/
│   │   ├── resolve.ts                    # NET-NEW — Prev-chain + Eid + tombstone resolution.
│   │   │                                 #   Port from api/src/cache.js getResolvedEntries logic.
│   │   ├── entries.ts                    # NET-NEW — async iterator for collection entries.
│   │   │                                 #   Uses crypto/decryptWithCEK + reader/resolve.
│   │   └── decode-entry.ts               # NET-NEW (thin) — extract decryptOwnedBlob() from
│   │                                     #   tarn.ts #decryptBlob (5986-5996), ~10 LOC.
│   │
│   ├── sharing/
│   │   ├── pair.ts                       # NET-NEW (thin) — getPairKeys(sharePriv, peerSharePub, appId).
│   │   │                                 #   Wraps deriveSharedSecret + derivePairKeys (~10 LOC).
│   │   ├── connections.ts                # NET-NEW (thin) — read connections record.
│   │   │                                 #   findShareStateEntry(entries, CONNECTIONS_CONTENT_ID)
│   │   │                                 #   from sharing.ts re-export.
│   │   ├── share-log.ts                  # NET-NEW — readShareLog port without the
│   │   │                                 #   #requireAuth/#processRotateIdentityEntry coupling.
│   │   │                                 #   Reuses share-log.ts: discoverHighestSeq,
│   │   │                                 #   verifyOperationSignature, decryptShareLogEntry,
│   │   │                                 #   applyOperationToState.
│   │   └── primitives.ts                 # BORROWED — re-exports from tarn-client/share-log
│   │                                     #   (everything: derivePairKeys, deriveLogTag,
│   │                                     #    discoverHighestSeq, verifyOperationSignature,
│   │                                     #    decryptShareLogEntry, applyOperationToState, OP_*).
│   │
│   ├── schema/
│   │   └── index.ts                      # BORROWED — re-exports defineSchema, validateRecord*.
│   │                                     #   (Apps pass their schema in; we use it to validate-on-read.)
│   │
│   └── types.ts                          # NET-NEW — public Reader, RecoverOpts, RecoverProgress types.
│
├── test/
│   ├── fixtures/                         # NET-NEW (Phase 6). Synthetic Arweave-ish data.
│   ├── unit/                             # NET-NEW. Mostly per-helper tests.
│   └── integration/                      # NET-NEW. End-to-end against a fake gateway.
│
├── README.md                             # NET-NEW. Forward-compat contract lives here.
├── package.json                          # NET-NEW. ESM-only.
└── tsconfig.json                         # NET-NEW.
```

**Reuse summary:**
- `crypto.ts` — full re-export (everything used).
- `recovery.ts` — full re-export.
- `share-log.ts` — full re-export (only the read+verify side actually consumed).
- `sharing.ts` — full re-export (only `hpkeOpen`, validators, `CONNECTIONS_CONTENT_ID` etc. consumed; rest harmless).
- `schema/*.ts` — full re-export.
- `collections/eid.ts` + `collections/types.ts` — re-export if useful.

**Bundling note:** `@tarn/recover` should depend on `tarn-client` rather than vendoring the modules, so any decoder fix in `tarn-client` automatically flows. The forward-compat contract requires the inverse — that `tarn-client`'s ongoing changes never break existing fixtures — which is enforced by Phase 6's CI matrix.

---

## F. Phase 2-9 estimate revisions

Original (per `STANDALONE_RECOVERY_PLAN.md`):

| Phase | Original | Revised | Why |
|---|---|---|---|
| **2** Gateway-direct read | 4-5 days | **5-6 days** | The `RLk` tag-scheme addition (Section C) is a small Tarn-side patch but needs coordinating: write side in `api/src/routes/auth.js` + `account.js`, schema doc update, smoke test, then the gateway-side query. Plus the multi-gateway fallback orchestration with the 4-failure-mode coverage isn't trivial. |
| **3** KDF + envelope unwrapping | 3-4 days | **2 days** | Most of this exists already (Argon2id via `hash-wasm`, AES-KW via WebCrypto, `parseWrappedDataKey` and `unwrapDataKeyChain` in `crypto.ts`). The work is browser-context verification + a small `unwrap.ts` orchestrator + unit tests against fixtures. Original estimate was pessimistic. |
| **4** Schema-aware reader | 3-4 days | **3-4 days** | Unchanged. Iterator + tombstone + Prev-chain resolver + per-entry decode is roughly the size estimated. The `getResolvedEntries` port from `api/src/cache.js` is the thickest single piece. |
| **5** Connection + share-log | 4-5 days | **5-7 days** | Slightly grown. `readShareLog` is the most coupled piece in `tarn.ts` (depends on `#getPairKeysFor`, `#probeInboundTagExists`, `#getShareLogBlobByTag`, `_fetchShareLogEntry`, `#processRotateIdentityEntry`, plus the rotate-identity NEW-log re-bootstrap branch on lines 4471-4476). Decoupling cleanly without regressing the live SDK takes care. Plus invites/redeemed-invites surface (`tarn.ts` 3949+) if v1 wants to surface "redeemed invite history" in the connection record reader — verify whether Bookish needs that. |
| **6** Forward-compat infra | 3-4 days | **4-5 days** | This is the load-bearing piece of the contract. Building the fixture vault with credentials + entries + share-logs + connection records across at least two envelope versions (current v1 only — but needs the harness to support a hypothetical v2) means structuring the decoder dispatch defensively from the start. CI matrix needs gateway mocks. Not trivial. |
| **7** Reference HTML | 1-2 days | **1-2 days** | Unchanged. Single-file HTML with bundled JS. The hard part was already done in Phase 5 (the runtime). |
| **8** Documentation | 2-3 days | **2-3 days** | Unchanged. README is the constitutional document. |
| **9** Publish to Arweave | 1 day | **1 day** | Unchanged. Use the bundled SDK or Turbo CLI. |

**Plus:** ~1 day for the `RLk` tag addition at the protocol layer, including the migration smoke test against existing accounts (those won't have the tag until they next rotate credentials — document the gap and let it bake out organically, OR add a one-shot republish script). Counts as part of Phase 2 above but flagging.

**Grand total range:** 23-30 days vs. original 21-29. Modestly grown, primarily on the share-log/connections side.

---

## Anything broken or inconsistent in the existing code?

**Nothing broken.** Two minor observations:

1. **The credential-blob tag scheme gap (Section C "Open issue").** Not a bug in the live SDK — the live SDK reaches the credential blob via the Tarn API, which knows the mapping. But it makes the "account-key alone reaches Arweave" promise harder to honor than it needs to be. Easy fix.

2. **`Connection.username` vs `sender_email` legacy naming.** The wire shape uses `sender_email` in connection-request/accept payloads (`sharing.ts` 286-320, `validateConnectionRequestPayload` 359), but the typed Connection surface uses `username`. The mapping is done in `connectionsNamespace.#toConnection` (`namespaces/connections.ts` 238-251) and `validate*` functions. Consistent in practice, but the `sender_email` field name on the wire predates the email→username rename. Not a recover-client problem (the recover client just decodes the wire shape and re-projects). Worth noting in case the rename surfaces somewhere subtle.

Otherwise the code is in good shape for Phase 2 to start.
