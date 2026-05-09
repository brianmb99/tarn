# `@tarn/recover` Fixture Vault

This directory is the **structural enforcement** of the
forward-compatibility contract for `@tarn/recover`. Read
[`docs/STANDALONE_RECOVERY_PLAN.md`](../../docs/STANDALONE_RECOVERY_PLAN.md)
"Forward-compatibility contract" section for the constitutional commitment;
this README is its operational mechanism.

## The contract, in one sentence

**A user's data, once written and confirmed-on-Arweave, must remain
decryptable by `@tarn/recover@vN` for any future `N`, given only the user's
account key (or username + password) and a working Arweave gateway.**

Scope: **owned content only.** Share-log and HPKE shapes are best-effort
and explicitly NOT under this contract — see the plan doc §1 (revised
2026-05-08) for why.

## How this directory enforces the contract

Every file under `fixtures/envelope-vN/` is a **frozen artifact**:

- One specific synthetic account (deterministic credentials, random salts/IVs
  captured at generation time).
- The exact wire envelope it produced.
- The expected DEK chain after unwrap.
- The expected plaintext after content-blob decode.

The fixture-suite test (`recover/tests/forward-compat.test.ts`) loads each
file, runs it through the full `@tarn/recover` pipeline, and asserts
byte-for-byte equality on the recovered DEKs and plaintext. It runs on
every CI build of every release, forever.

The fixture-vault meta-test (`recover/tests/fixture-vault.test.ts`) reads
`manifest.json` and re-hashes the filesystem. If any tracked file is
missing, modified, or if a new file is present that is not in the manifest,
the test fails. This is the CI-time guard against accidental fixture
mutation.

## The rules

### Files in here are NEVER deleted or modified.

A green forward-compat test on a fixture file proves `@tarn/recover` can
still decrypt that exact wire shape. Modifying the file invalidates that
proof; deleting it removes the proof entirely. Either is a contract
violation.

### Adding a new envelope version is the ONLY allowed mutation.

When envelope `vN+1` ships:

1. Add the decoder code (`src/crypto/envelope/v{N+1}.ts`, registered in
   `src/crypto/envelope/index.ts`'s `DECODERS_BY_VERSION` table).
2. Run `node scripts/generate-fixtures.mjs` (after teaching it to emit
   `vN+1` shapes) — it emits new files into `fixtures/envelope-v{N+1}/`
   and regenerates `manifest.json`.
3. Commit the new fixture files alongside the unchanged old ones.

Old fixtures must continue to pass on every release of `@tarn/recover`
forever.

### The generator script is for adding new versions, NOT regenerating old ones.

`scripts/generate-fixtures.mjs` checks whether each output file already
exists and skips it if so. This is intentional — the script is an
**append-only** tool. To add new fixture variants (a new edge case worth
pinning, or a new envelope version), edit the script and run it; existing
files are untouched.

## Manifest format

`manifest.json` is a sorted list of `{ path, sha256, sizeBytes }` for every
fixture file. The meta-test treats this as the source of truth: any
filesystem state that doesn't match it (missing files, hash mismatches,
unlisted new files) fails the test.

To extend the manifest, run `scripts/generate-fixtures.mjs` — it
recomputes the manifest from the (immutable) filesystem state at the end.

## Inputs in the fixture files are NOT real credentials

The username/password/account-key triplet inside each fixture file is
public, fixed test material. It exists only so the test suite can derive
the same KEKs the writer used. Re-using these credentials for a real Tarn
account would be a security failure on the user's part — they are
documented as test-only.

## Current fixture set (envelope v1)

| File                              | Scenario                                                        |
| --------------------------------- | --------------------------------------------------------------- |
| `envelope-v1/single-gen-model-a.json` | Just-registered account; 1 DEK gen; no `wrapped_account_key`. |
| `envelope-v1/single-gen-model-b.json` | Just-registered account; 1 DEK gen; with `wrapped_account_key`. |
| `envelope-v1/multi-gen-model-a.json`  | 3 DEK gens (account through 2 changeCredentials runs).         |
| `envelope-v1/multi-gen-model-b.json`  | 2 DEK gens AND `wrapped_account_key` (full combination).       |

Every fixture exercises:

- Envelope dispatch (`src/crypto/envelope/index.ts` routes `v: 1` to the v1 decoder).
- Both factor unwraps (`password` and `recovery_phrase`).
- DEK chain reconstruction (every gen → byte-equal raw DEK).
- Content-blob decode (`decryptWithCEK` round-trips `expected.contentBlob.plaintext`).

Model B fixtures additionally exercise `unwrapAccountKey` — the gen-1 DEK
must decrypt the `wrapped_account_key` ciphertext back to the original
24-word phrase.

## Out of scope (deliberately)

- Share-log fixture files. Best-effort by the plan; not under contract.
- HPKE-inbox fixture files. Same reason.
- Real Arweave transactions. Synthetic envelopes are sufficient — the
  Arweave-direct read path is exercised separately in
  `tests/multi-gateway.test.ts` and `tests/queries.test.ts`.
