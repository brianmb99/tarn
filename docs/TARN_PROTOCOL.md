# Tarn Protocol — Working Draft

**Status:** Active design discussion (Issue #69)
**Last updated:** 2026-04-10

Tarn is an app-agnostic platform for storing encrypted, user-owned data permanently on Arweave. This document defines the complete protocol: identity, authentication, encryption, and data operations.

---

## Key Hierarchy

All sub-keys are derived using **HKDF-Expand** (RFC 5869) with structured info strings. No ad-hoc SHA-256 concatenation. The info string follows a fixed structure:

```
info = protocol || purpose || app_id || version || 0x01
```

Where:
- `protocol` = `"tarn"` (fixed)
- `purpose` = one of: `"lookup"`, `"encrypt"`, `"sign"`
- `app_id` = registered app identifier (e.g., `"bookish"`)
- `version` = `"1"` (derivation version — allows future KDF changes)
- `0x01` = HKDF counter byte per RFC 5869

HKDF-Expand with a single 32-byte output block reduces to one HMAC call:

```
sub_key = HMAC-SHA256(master_key, info)
```

### Full derivation chain

```
email + password (user input, never leaves client)
  -> master_key                  KDF(password, SHA-256(normalizedEmail))
                                   v2: Argon2id (m=64MiB, t=3, p=1)  — current default
                                   v1: PBKDF2-SHA256, 600K iterations — legacy

master_key + app_id:
  -> credential_lookup_key       HMAC-SHA256(master_key, "tarn" || "lookup"  || app_id || "1" || 0x01)
  -> credential_encryption_key   HMAC-SHA256(master_key, "tarn" || "encrypt" || app_id || "1" || 0x01)
  -> signing_key_seed            HMAC-SHA256(master_key, "tarn" || "sign"    || app_id || "1" || 0x01)
     -> signing_key_pair         ECDSA P-256 from signing_key_seed (see P-256 derivation)
       -> public_key             sent to API, stored in D1 and on Arweave
       -> private_key            never leaves client
```

### Master-key KDF versioning

The KDF version is encoded in the `wrapped_data_key` field of the credential mapping blob (see [Wrapped Data Key](#wrapped-data-key) below for wire format). New accounts always use Argon2id (v2). Existing PBKDF2 (v1) accounts continue to log in via a legacy path; migration to Argon2id is intentionally out of scope and will be addressed separately.

Login dispatch — because `credential_lookup_key` depends on `master_key` which depends on the KDF, the client cannot know which KDF an account uses before looking it up. The client tries the current default KDF (Argon2id) first; on a 404 it falls back to PBKDF2 with a freshly-derived `credential_lookup_key`. New accounts pay only the Argon2id cost; legacy accounts pay both KDFs once per login (~2s worst case on a representative slow device).

Argon2id parameters were chosen against a ~2s slow-device login budget: 64 MiB memory + 3 iterations + 1-way parallelism (single-threaded; aligns with browser realities). The memory-hard property neutralizes GPU/ASIC parallelism that defeats PBKDF2 — the primary reason for the change.

**Per-app isolation:** Every derived key includes `app_id`. The same email+password produces completely independent identities per app. Different credential_lookup_key, different encryption_key, different signing key. A Bookish user and a Cellar user with the same email+password cannot see each other's data, share sessions, or even detect each other's existence.

### P-256 private key derivation

The `signing_key_seed` (32 bytes from HMAC) is used as the P-256 private scalar. P-256 requires the private key to be in [1, n-1] where n is the curve order.

```
seed = HMAC-SHA256(master_key, "tarn" || "sign" || app_id || "1" || 0x01)
if seed == 0 or seed >= n:
  seed = HMAC-SHA256(master_key, "tarn" || "sign" || app_id || "1" || 0x02)
  (repeat with incrementing counter — probability of needing this: ~2^-128)
```

Import as PKCS#8 DER → export public key as SPKI → send SPKI to API.

### Wrapped Data Key

The `data_encryption_key` (DEK) is wrapped using **AES-KW** (RFC 3394, Key Wrap):

```
wrapped_bytes = AES-KW-Wrap(data_encryption_key, credential_encryption_key)
                            ^^^^ payload            ^^^^ wrapping key
```

AES-KW is deterministic (no IV), purpose-built for key wrapping, and available in WebCrypto via `crypto.subtle.wrapKey('raw', key, wrappingKey, 'AES-KW')`.

At registration the DEK is generated as 32 fresh random bytes (issue #11) — no more self-wrapping. The DEK is then wrapped under the `credential_encryption_key` and packaged into a v3 envelope (see below).

After a credential change, the wrap is regenerated under the new `credential_encryption_key`. Argon2id accounts also get a fresh DEK appended to the chain at the next-highest generation (forward-secret rotation) — see [Forward-secret DEK rotation](#forward-secret-dek-rotation) below.

#### Wire format (`wrapped_data_key` field)

The API stores `wrapped_data_key` as opaque text. The string carries a version indicator so the client knows the structure and a KDF indicator so the client can verify which master-key KDF the account was registered under.

**v4 (current default — Argon2id accounts after issue #12):** JSON envelope with a multi-factor DEK chain. Each chain entry is wrapped under one or more factors; any factor's KEK independently unwraps the DEK. New v4 accounts always carry both `password` and `recovery_phrase` factors.

```json
{
  "v": 4,
  "kdf": "argon2id",
  "kdf_params": { "m_kib": 65536, "t": 3, "p": 1 },
  "recovery": {
    "kdf": "argon2id",
    "kdf_params": { "m_kib": 65536, "t": 3, "p": 1 },
    "salt": "<base64 16-byte per-account random salt>"
  },
  "dek_chain": [
    { "gen": 1, "wrappings": [
      { "factor": "password",        "wrapped": "<base64 AES-KW ciphertext (40 bytes)>" },
      { "factor": "recovery_phrase", "wrapped": "<base64 AES-KW ciphertext (40 bytes)>" }
    ]},
    { "gen": 2, "wrappings": [
      { "factor": "password",        "wrapped": "<base64 AES-KW ciphertext (40 bytes)>" }
    ]}
  ]
}
```

- `recovery` block is the recovery factor's derivation metadata (Argon2id params + per-account salt). Absent → no recovery factor enrolled (treat as v3-equivalent for read).
- Each `dek_chain` entry's `wrappings` array carries the same DEK wrapped under each factor's KEK. AES-KW is deterministic, so the same (DEK, KEK) pair always produces the same ciphertext bytes — preserving register-retry idempotency.
- When `changeCredentials` runs without the recovery phrase: old gens preserve their existing recovery wrappings verbatim (re-wrapping under the same KEK is byte-identical anyway), and the new gen N+1 has only a `password` wrapping. The gap is closed by `recoverAccount` or `regenerateRecoveryKit`, which re-wrap every gen under the recovery factor.

**v3 (legacy single-factor chain — issue #11 accounts pre-issue-#12):** JSON envelope with a single-factor DEK chain.

```json
{
  "v": 3,
  "kdf": "argon2id",
  "kdf_params": { "m_kib": 65536, "t": 3, "p": 1 },
  "dek_chain": [
    { "gen": 1, "wrapped": "<base64 AES-KW ciphertext (40 bytes)>" },
    { "gen": 2, "wrapped": "<base64 AES-KW ciphertext (40 bytes)>" }
  ]
}
```

The chain is appended only — every credential change adds an entry at gen N+1. The current generation (used for new writes) is the entry with the highest `gen`. Old gens stay in the chain so older content blobs remain decryptable. v3 envelopes are read as a single-factor (`password`) v4 chain with no recovery metadata.

**v2 (legacy Argon2id accounts):** JSON envelope with a single wrapped DEK.

```json
{
  "v": 2,
  "kdf": "argon2id",
  "kdf_params": { "m_kib": 65536, "t": 3, "p": 1 },
  "wrapped": "<base64 AES-KW ciphertext (40 bytes)>"
}
```

v2 accounts upgrade to v3 on next credential change: the existing DEK is preserved as gen 1 (re-wrapped under the new KEK) and a fresh random DEK is minted as gen 2.

**v1 (legacy PBKDF2 accounts):** the bare base64 AES-KW ciphertext, no envelope. PBKDF2 accounts stay on the legacy single-key path on credential change — issue #11's forward-secret rotation is scoped to Argon2id accounts; v1 → v3 migration is a separate concern.

Detection rule: if `wrapped_data_key[0] === '{'`, parse as JSON and dispatch on `v`; otherwise treat as v1 bare base64. The base64 alphabet `[A-Za-z0-9+/=]` never starts with `{`, so the prefix check is unambiguous.

All envelope shapes are byte-stable for the same `(email, password, app)` inputs (AES-KW is deterministic; JSON.stringify is insertion-ordered; chain entries are written in generation order). This preserves the register-retry idempotency check (server compares the stored `wrapped_data_key` to the incoming one byte-for-byte; a retry of an interrupted register sends the same bytes).

#### Forward-secret DEK rotation

On every credential change for an Argon2id account, the client mints a fresh random DEK at gen N+1 and appends it to the chain. Subsequent writes use the new gen; old gens remain in the chain so prior data is still readable. An attacker who later compromises the OLD `credential_encryption_key` cannot decrypt content written after the rotation (the new gen DEK is not derivable from old credentials).

This is the only forward-secrecy property Tarn provides today. Old credential blobs on Arweave remain unwrappable by anyone who held the old credentials, but the DEK they yield is bound to data written before the rotation.

### Recovery factor (issue #12)

v4 accounts publish a `recovery_lookup_key` and `recovery_public_key` alongside the password-derived `credential_lookup_key` / `public_key`. Both are derived from the user's BIP39 recovery phrase (24-word, 256-bit entropy) and let the user authenticate to the API for credential rotation when they have lost their password.

Derivation:

```
phrase_entropy           = BIP39 entropy bytes (32 for 24-word phrase)
recovery_lookup_key      = HMAC-SHA256(phrase_entropy, "tarn" || "recovery-lookup" || app_id || "1" || 0x01)
recovery_signing_seed    = HMAC-SHA256(phrase_entropy, "tarn" || "recovery-sign"   || app_id || "1" || 0x01)
recovery_signing_key     = ECDSA P-256 from recovery_signing_seed (same retry rule as the password-derived signing seed)
recovery_KEK             = Argon2id(phrase, recovery_salt, m=64MiB, t=3, p=1)
                           (recovery_salt is per-account random, lives in the v4 envelope's `recovery.salt`)
```

`recovery_lookup_key` and `recovery_signing_key` derive from the raw phrase entropy directly (no salt), so they are stable across credential changes — the phrase remains the same secret regardless of how many times the password rotates. The `recovery_KEK` derives via Argon2id with the per-account salt, providing the slow-brute-force defense at unwrap time.

The recovery phrase is **mandatory at signup** (the SDK enforces this with a synchronous `recoveryAcknowledged: true` flag on `register()`) and is also optionally emailed to the user via the [Recovery email forwarder](#recovery-email-forwarder-issue-12).

### Data lookup key

Generated by the API at registration. Random, unique, opaque 64-char hex string. Not derived from any client secret. Returned to the client at registration.

---

## Security Model

### Threat model

Tarn assumes credentials are never compromised. Credential changes are a convenience feature (e.g., new email address), not a security remediation tool. All encrypted data is publicly visible on Arweave — security depends entirely on password entropy + PBKDF2 cost.

### Forward secrecy on credential change (Argon2id accounts)

Issue #11 added forward-secret DEK rotation for Argon2id accounts. On every credential change a fresh random DEK is appended to the chain at gen N+1; future writes go to gen N+1. An attacker who later compromises old credentials can:

1. Derive the old `credential_lookup_key`
2. Find the old credential mapping blob on Arweave
3. Unwrap the OLD `wrapped_data_key` with the old `credential_encryption_key`
4. Recover DEKs at gens 1..N (the chain entries that existed at the time of the old credential blob)

What they CANNOT do: decrypt content written under gen N+1 (or later). Those CEKs are wrapped under the new DEK, which is not derivable from old credentials. The old credential blob does not contain the new DEK — it predates it.

What's still inherent to immutable storage: the old credential blob itself stays on Arweave forever, so an attacker who compromised the old credentials at any point retains permanent access to data written before the rotation. Tarn cannot revoke past leaks.

### Legacy PBKDF2 accounts have no forward secrecy

PBKDF2 (KDF v1) accounts are out of scope for issue #11's rotation. Their DEK is rewrapped under new credentials on every change but never replaced — old credentials still unwrap the same DEK and decrypt all data, past and future.

### Password requirements

Since Arweave data is publicly available (encrypted), the security boundary is password entropy + PBKDF2 iteration cost. The API enforces minimum password complexity at registration. 600K PBKDF2 iterations meets OWASP 2023 recommendations.

### Per-app isolation

Different apps derive completely independent key sets from the same email+password. A compromise of one app's credential_lookup_key reveals nothing about the user's identity in another app. Even Arweave observers cannot link a user's Bookish account to their Cellar account.

### What the API knows vs. doesn't know

| API sees                              | API never sees                   |
|--------------------------------------|----------------------------------|
| public_key (for signature verification) | private_key (signing)          |
| credential_lookup_key                | master_key                       |
| data_lookup_key (it generated it)    | email, password                  |
| wrapped_data_key (opaque, AES-KW)    | data_encryption_key              |
| encrypted data blobs (opaque)        | credential_encryption_key        |
| app_id (which app the user registered for) | plaintext of any data blob |

No secrets stored by the API. Zero-knowledge preserved for all key material that protects user data.

---

## App Identity

Apps are first-class Tarn entities. An app must be registered before users can create accounts for it.

### App registration

Privileged operation (initially manual, eventually a developer portal):

```
App generates ECDSA P-256 key pair
Tarn operator registers: { app_id, public_key }
Stored in D1 and on Arweave: Type: 'app-reg', Lk: app_id
```

### App authentication

Same challenge-response protocol as users:

```
POST /api/v1/auth/challenge  { credential_lookup_key: <app_id> }
POST /api/v1/auth/verify     { credential_lookup_key: <app_id>, nonce, signature }
-> JWT with { sub: <app_id>, role: 'app' }
```

### App wallets for Arweave storage

Each app has its own Arweave/Turbo wallet (Ethereum-compatible) for signing DataItems. The wallet private key is stored as a Worker secret (`APP_SIGNING_KEY`). Turbo provides free uploads under 100KB; larger uploads consume the wallet's Turbo balance.

### App scoping on user accounts

User accounts are per-app. Registration requires a valid `app` parameter referencing a registered app. The JWT includes `app: <app_id>`. Write endpoints validate that the `App` tag matches `jwt.app`. A user cannot write entries for an app they're not registered with.

---

## Arweave Tag Scheme

All blobs on Arweave carry these tags:

| Tag  | Meaning                    | Example                            |
|------|---------------------------|-------------------------------------|
| App  | App identifier             | `bookish`, `winelist`              |
| Type | Blob type                  | `cred`, `entry`, `acct`            |
| Lk   | Lookup key (64-char hex)   | `a3f8...`                          |
| Enc  | Encryption method          | `aes-256-gcm` or `tarn-cek-1`      |
| V    | Protocol version           | `0.4.0`                            |

For credential blobs: `Lk` = `credential_lookup_key`.
For data blobs: `Lk` = `data_lookup_key`.

Additional tags for versioning and key rotation (data blobs only):

| Tag  | Meaning                                                       |
|------|---------------------------------------------------------------|
| Prev | Txid of prior version (edits)                                 |
| Op   | Operation flag (`tombstone`)                                  |
| Ref  | Txid referenced by tombstone                                  |
| Gen  | DEK generation that wrapped the per-content CEK (issue #11)   |

The `Gen` tag is present on new-format (`Enc: tarn-cek-1`) blobs; it carries the integer generation number (e.g. `1`, `2`) that selects which DEK from the user's chain unwraps the blob's CEK. Legacy `aes-256-gcm` blobs carry no `Gen` tag and decrypt with the gen-1 DEK directly.

---

## Blob Format

Two formats coexist; the SDK detects which by inspecting the first 5 bytes.

### New format — per-content CEK (issue #11, default for v3 accounts)

```
[magic: 5 bytes][wrapped_CEK: 40 bytes][IV: 12 bytes][ciphertext + GCM tag: N+16 bytes]
```

- `magic = 0x54 0x41 0x52 0x4e 0x02` — ASCII `"TARN"` followed by version byte `0x02`. The trailing byte is the format version; future revisions reuse the `0x54 0x41 0x52 0x4e` prefix and increment.
- `CEK` is generated fresh per blob (`crypto.getRandomValues(32)`). `wrapped_CEK = AES-KW(CEK, DEK[currentGen])` — 40 bytes (32-byte CEK + 8-byte AES-KW overhead).
- `IV` is 12 random bytes per encryption.
- Ciphertext is AES-256-GCM with the per-blob CEK over UTF-8-JSON plaintext.

Per-blob fixed overhead: 73 bytes (5 + 40 + 12 + 16).

The generation indicator does not live in the blob bytes — it travels alongside as the Arweave `Gen` tag (e.g. `Gen: 1`, `Gen: 2`). This keeps the byte layout stable so a recipient who only has the CEK (sharing protocol, future Section 5 work) can skip bytes 5..44 and decrypt bytes 45..end without parsing tags.

**Reading.** The owner reads bytes 5..44 (`wrapped_CEK`), unwraps it with `DEK[gen]` (gen from the `Gen` tag, default 1 if absent), and decrypts bytes 45..end with that CEK. A recipient with a CEK from a share log skips the wrapped portion and decrypts directly.

The `Enc` tag for new-format blobs is `tarn-cek-1`.

### Legacy format

```
[IV: 12 bytes] [ciphertext + GCM tag: N bytes]
```

Direct AES-256-GCM with the user's DEK. No magic prefix. `Enc: aes-256-gcm`. Pre-issue-#11 blobs and writes by accounts that haven't yet upgraded to v3 envelopes.

**Detection.** SDK reads the first 5 bytes. Match against `0x54 0x41 0x52 0x4e 0x02` → new format; otherwise legacy. Legacy blobs continue to decrypt indefinitely — no migration is performed.

---

## Credential Mapping on Arweave

The credential mapping blob is **not encrypted**. It contains:

```json
{
  "data_lookup_key": "<64-char hex>",
  "wrapped_data_key": "<base64-encoded AES-KW ciphertext or v3/v4 envelope JSON>",
  "public_key": "<base64-encoded ECDSA P-256 SPKI public key>",
  "app": "<app_id>",
  "recovery_lookup_key": "<64-char hex>",
  "recovery_public_key": "<base64-encoded ECDSA P-256 SPKI public key>"
}
```

The `recovery_lookup_key` and `recovery_public_key` fields (issue #12) are written when the account has a recovery factor enrolled and omitted otherwise (pre-v4 accounts). On rebuild from Arweave, missing fields decode as NULL.

No value here is secret. Storing unencrypted enables:
- Single API call for registration (no second client round-trip)
- Full API self-healing from Arweave (all account fields recoverable)
- No asymmetric crypto complexity for negligible privacy gain

---

## Write Authorization Rules

Write access is controlled by a **rules** array on each user account. At write time, the API evaluates all rules — **every rule must pass**. Unknown rule types **fail closed** (deny).

Rules are set by authenticated app identities. The entire rules array is **replaced** on each update (no merging).

### Rule types (v1)

**`max_entries`** — user has fewer than N entries matching the filters

```json
{ "type": "max_entries", "limit": 1000, "since": "2026-04-01T00:00:00Z", "app": "bookish", "entry_type": "entry" }
```

**`max_bytes`** — this individual entry is smaller than N bytes

```json
{ "type": "max_bytes", "limit": 102400 }
```

**`expires`** — the current time is before this timestamp

```json
{ "type": "expires", "at": "2027-04-01T00:00:00Z" }
```

### Rule evaluation

```
For each rule: unknown type -> DENY; evaluates false -> DENY
All rules pass -> ALLOW
No rules (NULL) -> DENY (accounts require rules to be set by the app)
```

Note: with per-app accounts, the default for new accounts is DENY (no rules set). The app must set rules after the user registers. For free-tier apps, set `[{ "type": "max_entries", "limit": 5 }]` immediately after user creation.

---

## API State

**D1 `accounts` table:**
```sql
credential_lookup_key TEXT PRIMARY KEY,
public_key TEXT NOT NULL,
data_lookup_key TEXT NOT NULL UNIQUE,
wrapped_data_key TEXT NOT NULL,
app TEXT NOT NULL,
rules_json TEXT,
created_at INTEGER NOT NULL,
recovery_lookup_key TEXT,    -- nullable; UNIQUE when present (issue #12)
recovery_public_key TEXT     -- nullable (issue #12)
```

**D1 `apps` table:**
```sql
app_id TEXT PRIMARY KEY,
public_key TEXT NOT NULL,
created_at INTEGER NOT NULL
```

**D1 `entries` table** (authoritative store for live state; see "D1 authority" below):
```sql
txid TEXT PRIMARY KEY,
app TEXT, type TEXT,
lookup_key TEXT,
prev_txid TEXT, is_tombstone INTEGER, tombstone_ref TEXT,
block_timestamp INTEGER, tags_json TEXT, cached_at INTEGER
```

### D1 authority

Tarn is the sole write path for any data associated with a (`data_lookup_key`, `app`, `type`) tuple. Every successful write synchronously upserts into D1 before returning success to the client. As a consequence:

- **D1 is authoritative for live state.** Once a tuple has been bootstrapped, reads are served entirely from D1. Tarn does not periodically re-scan Arweave — there is no other writer to reconcile against.
- **Bootstrap markers** (stored in `cache_meta`) record that a tuple has been ingested. Set by the write path on first write, or by the read path on first read if no marker exists.
- **Arweave GraphQL is consulted only on cold bootstrap:** a first read for a tuple Tarn has never processed. After bootstrap, the marker short-circuits all subsequent queries.
- **`block_timestamp` / confirmation status** is set at write time (NULL = pending) and no longer updates once the marker is set. Clients that need Arweave confirmation status can check Turbo directly for a given txid.

**Rebuild from Arweave:** All tables fully rebuildable from Arweave blob scans. After rebuild, `cache_meta` markers are cleared so the next read for each tuple re-bootstraps from the restored `entries` rows.

---

## Flows

### 1. Register (new account)

```
CLIENT (local):
  1. Derive master_key from email + password (Argon2id v2; PBKDF2 v1 legacy only)
  2. Derive credential_lookup_key, credential_encryption_key, signing_key_pair
     (all include app_id in HKDF info)
  3. data_encryption_key (DEK) = crypto.getRandomValues(32)   // issue #11
  4. wrapped_data_key = v3 envelope:
       { v: 3, kdf, kdf_params,
         dek_chain: [{ gen: 1, wrapped: AES-KW-Wrap(DEK, credential_encryption_key) }] }

CLIENT -> API:
  5. POST /api/v1/auth/register
     Body: { credential_lookup_key, public_key, wrapped_data_key, app }

API:
  6. Verify app is registered in apps table (-> 400 if not)
  7. Check credential_lookup_key not already in use (-> 409 if exists)
  8. Generate data_lookup_key (random, unique)
  9. Store in D1: { credential_lookup_key, public_key, data_lookup_key, wrapped_data_key, app }
  10. Persist credential mapping to Arweave
  11. Return: { data_lookup_key }
```

### 2. Sign in (existing account, any device)

```
CLIENT (local):
  1. Derive master_key, credential_lookup_key, credential_encryption_key, signing_key_pair
     (all include app_id in HKDF info)

CLIENT -> API:
  2. POST /api/v1/auth/challenge { credential_lookup_key }
     Returns: { nonce, data_lookup_key, wrapped_data_key }

CLIENT (local):
  3. Sign nonce with private_key -> signature
  4. data_encryption_key = AES-KW-Unwrap(wrapped_data_key, credential_encryption_key)

CLIENT -> API:
  5. POST /api/v1/auth/verify { credential_lookup_key, nonce, signature }
     Returns: { jwt }
     JWT contains: { sub: data_lookup_key, role: 'user', app: app_id }
```

### 3. Create data

```
CLIENT -> API:
  POST /api/v1/entries [JWT]
  Tags: { App, Type, Lk: data_lookup_key, Enc, V }
  Body: encrypted_blob

API:
  1. Verify JWT
  2. Check App tag matches jwt.app
  3. Check Lk tag matches jwt.sub (data_lookup_key)
  4. Evaluate write authorization rules -> 403 if denied
  5. Build + sign DataItem, cache in D1, upload to Turbo in background
  6. Return: { txid, status: 'pending' }
```

### 4. Retrieve data

```
GET /api/v1/entries?app={app}&type={type}&key={data_lookup_key}
No auth required. IP rate-limited.
Returns resolved entries (tombstones applied, Prev-chains resolved).
Client downloads + decrypts blobs from Arweave gateways.
```

### 5. Update data

```
PUT /api/v1/entries/{prior_txid} [JWT]
Tags include Prev: prior_txid. API verifies ownership. Old entry superseded.
```

### 6. Delete data

```
DELETE /api/v1/entries/{target_txid} [JWT]
Tags include Op: tombstone, Ref: target_txid. Entry hidden by resolution.
```

### 7. Change credentials

```
CLIENT (authenticated with old credentials, holds DEK chain DEK[1..N]):
  1. Derive NEW keys from new email + password (same app_id, same KDF version)
  2. Argon2id (v3 envelope) accounts — forward-secret rotation:
       - Mint DEK[N+1] = crypto.getRandomValues(32)
       - new_wrapped_data_key = v3 envelope with chain entries:
           [ { gen: i, wrapped: AES-KW(DEK[i], new_credential_encryption_key) }
             for i in 1..N+1 ]
       - Future writes use Gen=N+1
  3. PBKDF2 (v1 legacy) accounts — single-key rewrap, no rotation:
       - new_wrapped_data_key = bare base64 AES-KW(DEK[1], new_credential_encryption_key)

CLIENT -> API:
  PUT /api/v1/auth [JWT from old credentials]
  Body: { new_credential_lookup_key, new_public_key, new_wrapped_data_key }

data_lookup_key unchanged. Existing data untouched. Old gens stay readable;
new writes go to the new gen.
```

### 7a. Account recovery (via recovery phrase) — issue #12

When the user has lost their password (or wants a security-grade reset, per the design-doc positioning of recovery as the response to suspected compromise):

```
CLIENT (local — only the recovery phrase + new credentials):
  1. phrase_entropy = BIP39.mnemonicToEntropy(phrase)
  2. recovery_lookup_key  = HMAC(phrase_entropy, "tarn" || "recovery-lookup" || app_id || "1" || 0x01)
  3. recovery_signing_key = ECDSA P-256 from HMAC(phrase_entropy, "tarn" || "recovery-sign" || app_id || "1" || 0x01)

CLIENT -> API:
  4. POST /api/v1/auth/challenge { recovery_lookup_key }
     Returns: { nonce, data_lookup_key, wrapped_data_key }   (the existing v4 envelope)

CLIENT (local):
  5. Parse v4 envelope → recovery_salt + KDF params
  6. recovery_KEK = Argon2id(phrase, recovery_salt, params)
  7. Unwrap DEK chain via FACTOR_RECOVERY_PHRASE
  8. Sign nonce with recovery_signing_key.privateKey

CLIENT -> API:
  9. POST /api/v1/auth/verify { recovery_lookup_key, nonce, signature }
     Returns: { jwt }   (JWT carries via_recovery: true)

CLIENT (local):
  10. Derive new password keys from (newEmail, newPassword)
  11. Re-wrap entire DEK chain under {new_password_KEK, recovery_KEK} factors
      (preserving the existing recovery salt; recovery wrappings are byte-identical
       to the originals by AES-KW determinism)
  12. Build v4 envelope from re-wrapped chain

CLIENT -> API:
  13. PUT /api/v1/auth { new_credential_lookup_key, new_public_key,
                         new_wrapped_data_key,
                         new_recovery_lookup_key,
                         new_recovery_public_key }
     (recovery_lookup_key + recovery_public_key are unchanged by recovery — phrase is the same;
      we re-send them so a corrupted server-side row would self-heal.)

data_lookup_key unchanged. All pre-recovery data is decryptable under the new credentials.
```

### 8. D1 Recovery

All tables fully rebuildable from Arweave. Entries self-heal on cache miss. Accounts rebuilt from `Type=cred` blobs. Apps rebuilt from `Type=app-reg` blobs.

### 9. Delete account

```
DELETE /api/v1/auth [JWT]
Tombstones credential mapping on Arweave. Deletes D1 account row.
Data remains encrypted on Arweave permanently.
```

### 10. Set user write rules (app -> API)

```
PUT /api/v1/accounts/{data_lookup_key}/rules [JWT with role: 'app']
Body: { rules: [...] }
Replaces rules_json. Persists to Arweave as Type: 'app-config'.
```

---

## Client <-> API Summary

### Auth endpoints

```
POST /api/v1/auth/register
  Body: { credential_lookup_key, public_key, wrapped_data_key, app }
  Auth: none
  Returns: { data_lookup_key }
  Errors: 400 (unregistered app), 409 (credential_lookup_key in use)

POST /api/v1/auth/challenge
  Body: { credential_lookup_key }
     OR { recovery_lookup_key }   (issue #12 — recovery flow)
  Auth: none
  Returns: { nonce, data_lookup_key, wrapped_data_key }
  Errors: 404 (unknown lookup key)

POST /api/v1/auth/verify
  Body: { credential_lookup_key, nonce, signature }
     OR { recovery_lookup_key, nonce, signature }   (issue #12 — recovery flow)
  Auth: none (signature IS the auth — verified against the public key matching the lookup key type)
  Returns: { jwt }   (JWT carries via_recovery: true when the recovery_lookup_key path is used)
  Errors: 401 (invalid/expired nonce, bad signature)

PUT /api/v1/auth
  Body: { new_credential_lookup_key, new_public_key, new_wrapped_data_key,
          new_recovery_lookup_key?, new_recovery_public_key? }   (recovery fields optional, issue #12)
  Auth: JWT (works with both regular login JWTs and via_recovery: true JWTs)
  Returns: 200 OK
  Errors: 401, 409 (new credential_lookup_key OR new_recovery_lookup_key already in use)

DELETE /api/v1/auth
  Auth: JWT
  Returns: 200 OK
  Errors: 401

POST /api/v1/recovery/email                                       # issue #12
  Body: { recipient_email, pdf_base64, app_name?, subject? }
  Auth: JWT (user)
  Returns: { ok: true }
  Errors: 400 (validation), 401, 413 (PDF too large), 429 (5/hour/account),
          502 (relay rejected), 503 (relay not configured)
```

#### Recovery email forwarder (issue #12)

`POST /api/v1/recovery/email` forwards a client-rendered recovery PDF (containing the user's BIP39 phrase) to the named recipient via the configured email relay (Resend by default).

**No-storage guarantee, brief in-memory visibility.** The Tarn API holds the PDF bytes in memory only for the duration of the relay request and discards them on response. No D1 row, no KV entry, no Arweave write. The honest framing is "no storage, brief in-memory visibility during the forward" — Tarn briefly sees the bytes because forwarding requires it; persistence does not happen.

**Configuration.** Two Cloudflare Worker secrets must be set on the API:

```
EMAIL_FORWARDER_API_KEY   # Resend API key (re_...)
EMAIL_FORWARDER_FROM      # Verified sender, e.g. "Tarn <recovery@tarn.dev>"
```

If either is missing the endpoint returns 503 with `{error: "Email forwarder not configured"}`. Apps can opt out of email delivery at registration (`emailRecoveryKit: false`) and let the user save the PDF locally instead.

**Rate limit.** 5 sends/hour per `data_lookup_key`, enforced via the `write_rate_limits` D1 table with the key prefix `recovery-email:`.

### App endpoints

```
PUT /api/v1/accounts/{data_lookup_key}/rules
  Body: { rules: [...] }
  Auth: JWT with role: 'app'
  Returns: 200 OK
  Errors: 401, 403

GET /api/v1/status
  Auth: JWT (user or app)
  Returns: { users, entries, apps, wallet, protocol_version, timestamp }
```

### Data endpoints

```
POST /api/v1/entries
  Headers: Authorization: Bearer <jwt>, X-Arweave-Tags: [...]
  Body: <encrypted blob bytes>
  Auth: JWT
  Returns: { txid, status: 'pending' }
  Errors: 401, 403 (Lk/App mismatch or rules deny), 413

POST /api/v1/entries/batch
  Body: { entries: [{ data: "<base64 encrypted bytes>", tags: [...] }, ...] }
  Auth: JWT
  Returns: { entries: [{ txid, gateway }], count, status: 'pending' }
  Errors: 401, 403, 413
  Max 100 entries per batch. Counts as 1 rate-limit hit.
  Rules evaluated once for the entire batch (max_entries checks count + batchSize).

GET /api/v1/entries?app={app}&type={type}&key={data_lookup_key}
  Auth: none (IP rate-limited)
  Returns: { entries: [{ txid, tags }], total }

PUT /api/v1/entries/{prior_txid}
  Auth: JWT
  Returns: { txid, prevTxid, status: 'pending' }

DELETE /api/v1/entries/{target_txid}
  Auth: JWT
  Returns: { txid, tombstoneRef, status: 'pending' }
```

---

## Design Decisions

### Why HKDF-Expand (HMAC) for sub-key derivation
Raw `SHA-256(key || domain)` is vulnerable to length-extension attacks. HMAC (which is HKDF-Expand for a single output block, per RFC 5869) is immune by construction. The structured info string `protocol || purpose || app_id || version || counter` replaces ad-hoc domain strings with a defined, versioned format that naturally accommodates per-app isolation.

### Why AES-KW for key wrapping
AES-KW (RFC 3394) is purpose-built for key wrapping: deterministic (no IV management), minimal overhead (8 bytes), built-in integrity checking, and available in WebCrypto natively via `wrapKey`/`unwrapKey`. AES-GCM works but is not the specialist tool.

### Why per-app account isolation
Same email+password produces independent identities per app via the `app_id` in the HKDF info string. This prevents cross-app data leakage, cross-app session sharing, and cross-app identity correlation on Arweave. It also means apps must be registered before users can create accounts, which closes the "anyone can freeload on Tarn's Arweave wallet" gap.

### Why app validation at registration
Write endpoints check `App` tag against `jwt.app`. The JWT's `app` claim is set at login based on the account's registered app. Unregistered apps cannot create accounts, therefore cannot get JWTs, therefore cannot write data. This is enforced at the identity layer, not the write layer.

### Why default rules are DENY
New accounts have `rules_json = NULL`, which means DENY. The app must explicitly set rules after user creation (e.g., free tier: `max_entries=5`). This prevents orphaned accounts from writing unlimited data on the app's Arweave wallet.

### Why reads are unauthenticated
Data is on Arweave permanently (encrypted). Auth on reads only protects the cache layer. A permanent, auditable, API-independent data export page must be possible.

### Why a fresh random DEK at registration (issue #11)
Earlier versions of Tarn self-wrapped the credential_encryption_key as the DEK at registration, redundantly but uniformly. Issue #11 replaced this with a fresh `crypto.getRandomValues(32)` DEK at gen 1. This is a prerequisite for forward-secret DEK rotation (different gens must be independent random keys, not derived from credentials) and for the planned recovery-phrase factor (different KDFs must be able to wrap the *same* DEK independently).

### Why per-content CEKs (issue #11)
Each blob is encrypted with its own freshly-generated 32-byte CEK; the CEK is wrapped under the current generation's DEK and prepended to the blob. This adds 73 bytes per blob but enables granular access control for the future sharing protocol (a CEK can be shared to another user without exposing the DEK), per-content rotation on revocation, and simpler capability delegation. The 5-byte magic prefix `0x54 0x41 0x52 0x4e 0x02` makes the format unambiguously distinguishable from legacy direct-DEK blobs.

### Why the generation tag lives in Arweave tags, not in the blob
Section 5 (sharing protocol) requires that a recipient holding only a CEK can decrypt the content portion of a blob without knowing or parsing the owner-side wrapped CEK header. Encoding the generation in the blob bytes would shift the content offset and break that invariant. Putting the generation in an Arweave `Gen` tag keeps bytes 5..44 reserved for the wrapped CEK and bytes 45..end as CEK-only-decryptable content — independent of who's reading.

---

## Sharing primitives — terminology

The full sharing protocol (HPKE handshake, per-pair stealth-addressed share log, identity rotation, revocation) is specified in [`notes/2026-04-28-tarn-sharing-design.md`](../notes/2026-04-28-tarn-sharing-design.md). Section 6 of the implementation plan (issue #18) renamed the public surface from "friend" to "connection" so the SDK is product-neutral. The on-the-wire protocol identifiers are now:

| Layer | Identifier |
|---|---|
| HPKE info (request) | `tarn-connection-request-v1` |
| HPKE info (accept) | `tarn-connection-accept-v1` |
| Inbox tag prefix | `tarn-connection-inbox-v1-` |
| Connections record content_id | `tarn-connections-v1` |
| Pending requests record content_id | `tarn-pending-requests-v1` |
| Server-recognized inbox blob types | `connection-request-v1`, `connection-accept-v1` |

The persisted connections record's inner array field is `connections: [...]` (was `friends: [...]` in the design doc).

## Muted-connections record (issue #18)

The mutual-connection primitive is symmetric — both sides see each other's share-log entries by default. Apps that want a Strava-style asymmetric "follow" feel build it on top of the mutual primitive plus a per-side mute filter. The SDK persists the filter as an encrypted Tarn data blob:

```
content_id = "tarn-muted-connections-v1"
plaintext  = JSON({
  app_id:  <string>,
  version: 1,
  muted:   [{ share_pub: B(32 bytes), muted_at: <unix_seconds> }, ...]
})
```

DEK-encrypted via the per-content CEK pattern (same as the connections + pending-requests records). Stored on Arweave as a normal `tarn-share-state` entry with `Eid=tarn-muted-connections-v1`, so it syncs across the user's own devices via the existing data-blob storage path. No new D1 schema, no API change.

**Semantics — explicitly local:**

- **Per-side, per-user.** Mute is set by the muting party only. The muted party receives no signal and continues publishing share-log entries to the muting party's outbound log as normal. Only the muting party's *view* changes.
- **No protocol-level effect.** Mute does NOT alter what the muted party can see, what they can publish, or what tags either side polls. It is purely a UI hint.
- **App-driven filtering.** `readShareLog` and `syncShareLog` do NOT short-circuit on muted connections. Apps still need programmatic access to muted-connection state (e.g., to render a "Muted" tab). The SDK exposes `isMuted(connection)` and `listMutedConnections()` so apps can filter at the call sites that should be filtered (the main feed) without losing access at the call sites that shouldn't (the muted tab).

SDK surface: `tarn.muteConnection(c)` / `tarn.unmuteConnection(c)` / `tarn.listMutedConnections()` / `tarn.isMuted(c)`.

---

## Cryptographic References

- **HKDF:** RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function
- **AES-KW:** RFC 3394 — Advanced Encryption Standard Key Wrap Algorithm
- **PBKDF2:** RFC 8018 — Password-Based Key Derivation Function 2
- **AES-GCM:** NIST SP 800-38D — Galois/Counter Mode
- **ECDSA P-256:** FIPS 186-4 — Digital Signature Standard
- **Pattern:** Bitwarden-style architecture (PBKDF2 → master key → sub-keys → wrapped data key) with LUKS-style key slot wrapping

---

## Open Questions

1. **Protocol versioning:** The `V` tag and the `version` field in the HKDF info string allow future derivation changes (e.g., PBKDF2 → Argon2id). Migration path needs design.

2. **Rate limiting on registration:** Registration is unauthenticated. IP rate limiting sufficient for now. CAPTCHA or proof-of-work at scale.

3. **Multiple credential mappings after changes:** Old credential mappings persist on Arweave. On rebuild, latest wins. Minor information leak (credential change history via shared data_lookup_key).

4. **App wallet monitoring:** Turbo balance monitoring and top-up. Operational concern, not protocol.
