-- 0022_arweave_mirror_failures.sql
--
-- Durable failure ledger for BACKGROUND ("waitUntil") Arweave mirror uploads
-- (Tarn issue #47).
--
-- THE PROBLEM this closes: the synchronous /entries write path is Turbo-first —
-- it fails the request if the Turbo upload (or D1 cache write) errors, so a
-- caller always knows. The identity- and share-plane writes are the opposite:
-- they commit to D1 first and fire the Turbo upload in `ctx.waitUntil(...)`,
-- previously swallowing any failure with only a console.warn. If Turbo is down
-- or the app wallet is dry, D1 advances but Arweave never receives the mirror —
-- a SILENT divergence. A future "rebuild D1 from Arweave" can't recover what
-- Arweave never got, and the drift cron's count-compare deliberately does NOT
-- flag this case (it only flags Arweave-ahead-of-D1, never D1-ahead, to avoid
-- false alarms from indexing lag and GraphQL page caps). This table makes those
-- background failures DURABLE and OBSERVABLE.
--
-- SELF-HEALING DESIGN DECISION (store bytes, not just metadata):
--   We persist the already-signed ANS-104 DataItem (`signed_data_item`) so the
--   hourly cron can RE-UPLOAD it directly via uploadSignedDataItem() — no
--   re-signing, no access to plaintext required. The DataItem ID is content-
--   addressed from the signature, so re-uploading the SAME bytes lands the SAME
--   txid that D1 already cached: the mirror converges, no divergence.
--
--   Size cap: the runtime payload cap is 100 KB (MAX_UPLOAD_BYTES) / 64 KB
--   (MAX_SCHEMA_BYTES); a signed DataItem adds only signature + tag header
--   overhead (a few KB). The recorder enforces a 256 KB cap on the stored bytes
--   as defense-in-depth; a row whose bytes exceed the cap (should never happen
--   for these namespaces) is still recorded for ALERTING with signed_data_item
--   left NULL — the cron skips retry for it and an operator reconciles manually.
--
-- ZERO-KNOWLEDGE NOTE: `signed_data_item` holds the signed ANS-104 bundle bytes
-- whose payload is ALREADY-encrypted ciphertext (credential blobs wrap only
-- opaque wrapped_data_key / wrapped_account_key envelopes; share blobs are HPKE
-- ciphertext; app-config / schema are public app metadata). These are exactly
-- the bytes already destined for permanent public Arweave storage, so persisting
-- them in D1 leaks nothing the platform wasn't already publishing. This table
-- MUST NEVER carry plaintext, an account key, a DEK/CEK, or kit material — and
-- it does not: it only ever stores the same signed bytes Turbo would have taken.
--
-- This table is OPERATIONAL state (a retry queue + failure log), not user data,
-- and like health_reports / sessions is deliberately NOT rebuilt from Arweave.
--
-- Columns:
--   id               - autoincrement PK.
--   created_at       - unix ms the failure was first recorded.
--   namespace        - logical mirror namespace (e.g. 'cred', 'app-config',
--                      'share-inbox', 'share-log', 'passkey-reg', 'app-reg',
--                      'app-schema', 'account-key-republish', 'cred-tombstone').
--                      Free-form string set by the call site; used for grouping
--                      and reporting.
--   intended_txid    - the content-addressed DataItem ID the upload would have
--                      produced (already cached in `entries` for most sites).
--                      Lets an operator cross-reference the cached row.
--   data_lookup_key  - the Lk/To/log_tag identifier for the affected record,
--                      when known (nullable). Used for operator triage; this is
--                      a lookup key (a hash), never plaintext.
--   tags_json        - JSON of the Arweave tags (App/Type/Lk/...) for the blob.
--                      No payload — just the routing tags, which are public.
--   signed_data_item - the signed ANS-104 DataItem bytes for self-healing
--                      re-upload (BLOB, nullable; NULL when over the size cap).
--   error_message    - the Turbo error (status + truncated body) or thrown
--                      message. Bounded; carries no payload.
--   attempt_count    - number of upload attempts so far (1 at first record;
--                      incremented each cron retry).
--   last_attempt_at  - unix ms of the most recent attempt (record or retry).
--   resolved_at      - unix ms when the mirror finally succeeded (NULL while
--                      unresolved). The "open failure count" surfaced to the
--                      health report / /status counts rows WHERE resolved_at IS
--                      NULL.

CREATE TABLE IF NOT EXISTS arweave_mirror_failures (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at       INTEGER NOT NULL,
  namespace        TEXT NOT NULL,
  intended_txid    TEXT,
  data_lookup_key  TEXT,
  tags_json        TEXT,
  signed_data_item BLOB,
  error_message    TEXT,
  attempt_count    INTEGER NOT NULL DEFAULT 1,
  last_attempt_at  INTEGER NOT NULL,
  resolved_at      INTEGER
);

-- The open-failure count (resolved_at IS NULL) is read every cron tick and on
-- every /status call; index it so that scan is cheap as the log grows.
CREATE INDEX IF NOT EXISTS idx_amf_resolved_at ON arweave_mirror_failures(resolved_at);

-- The cron's retry selection orders unresolved rows by created_at; the resolved
-- retention prune scans by resolved_at (covered above). created_at supports the
-- oldest-first retry ordering.
CREATE INDEX IF NOT EXISTS idx_amf_created_at ON arweave_mirror_failures(created_at);

-- De-dupe guard: a repeated failure for the same intended_txid should bump the
-- existing open row's attempt_count rather than spawn a new row each cron tick.
-- Partial unique index over (intended_txid) for UNRESOLVED rows only — once a
-- row is resolved its intended_txid may legitimately recur (re-publish of the
-- same content), so the constraint applies only while resolved_at IS NULL.
CREATE UNIQUE INDEX IF NOT EXISTS idx_amf_open_txid
  ON arweave_mirror_failures(intended_txid)
  WHERE resolved_at IS NULL AND intended_txid IS NOT NULL;
