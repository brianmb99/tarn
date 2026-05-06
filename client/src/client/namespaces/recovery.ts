/**
 * `tarn.accountKey.*` — account-key lifecycle namespace.
 *
 * Phase 3 (RECOVERY_PLAN.md): `view()` retrieves the stored account key
 *   for Model B accounts via a step-up gated flow.
 * Phase 4: `enableKeyStorage()` / `disableKeyStorage()` toggle Model A↔B,
 *   and `rotate()` rotates the account key entirely.
 *
 * The SDK does not render recovery kits — apps render their own from the
 * account-key string returned by `register()` / `recoverAccount()` /
 * `view()` / `rotate()`. The namespace's job is orchestration; it never
 * persists the decrypted account key.
 */

export interface IAccountKeyClient {
  viewAccountKey(opts: { password: string }): Promise<{ accountKey: string }>;
  enableKeyStorage(opts: { password: string; accountKey: string }): Promise<{ stored: true }>;
  disableKeyStorage(opts: { password: string }): Promise<{ stored: false; alreadyDisabled?: boolean }>;
  rotateAccountKey(opts: { password: string }): Promise<{ accountKey: string }>;
  isAccountKeyStored(): boolean | null;
}

export class AccountKeyNamespace {
  readonly #client: IAccountKeyClient;

  constructor(client: IAccountKeyClient, _appId: string) {
    this.#client = client;
  }

  /**
   * Retrieve the user's account key from server-side storage (Model B).
   *
   * Requires a freshly-entered password — the orchestration runs a step-up
   * auth dance against the API to prove possession of the password, then
   * fetches the wrapped ciphertext, decrypts it client-side under the
   * gen-1 DEK, and verifies a wrap-pinning check before returning.
   *
   * Throws `AccountKeyPinningError` (re-exported from the SDK root) when
   * the decrypted phrase derives a `recovery_lookup_key` that does NOT
   * match the server-stored value — surface this distinctly from
   * "wrong password" or "network error" since it is security-relevant.
   *
   * Throws an Error with `no_account_key_stored` in the message for
   * accounts in Model A (no backup stored). Render the appropriate
   * "no backup" Settings affordance and offer the toggle (`enableKeyStorage`)
   * to enable storage.
   *
   * The returned `accountKey` is a 24-word string. The SDK does not
   * cache or retain it — surface it to the user and drop the in-memory
   * copy promptly.
   */
  async view(opts: { password: string }): Promise<{ accountKey: string }> {
    return this.#client.viewAccountKey(opts);
  }

  /**
   * Enable Model B storage (Model A → Model B).
   *
   * Caller passes the freshly-entered password (powers the step-up proof
   * + DEK derivation) AND the user's existing account key (the SDK does
   * not retain it post-registration). Apps prompt the user to type their
   * saved phrase, validate it via `validateAccountKey`, then call this.
   *
   * Failure modes:
   *   - Invalid phrase (BIP39 checksum) → Error
   *   - Wrong password → Error (step-up auth fails)
   *   - Pin-check mismatch (the supplied phrase derives a different
   *     `recovery_lookup_key` than the one on file for this account) →
   *     `AccountKeyPinningError`. Indicates the user typed a valid 24-word
   *     phrase that doesn't actually belong to this account.
   *
   * Idempotent on the wire: if storage was already enabled, the new wrap
   * overwrites the old (the caller proved possession of the phrase via
   * the pin check). Documented behavior.
   */
  async enableKeyStorage(opts: { password: string; accountKey: string }): Promise<{ stored: true }> {
    return this.#client.enableKeyStorage(opts);
  }

  /**
   * Disable Model B storage (Model B → Model A).
   *
   * Caller passes only the freshly-entered password (powers step-up).
   * The wrap is removed from D1 + Arweave; subsequent `view()` calls
   * fail with `no_account_key_stored`.
   *
   * Idempotent: on an already-Model-A account the call returns
   * `{ stored: false, alreadyDisabled: true }` instead of erroring. UI
   * code can treat both responses identically.
   *
   * Failure modes: wrong password (step-up fails) → Error.
   */
  async disableKeyStorage(opts: { password: string }): Promise<{ stored: false; alreadyDisabled?: boolean }> {
    return this.#client.disableKeyStorage(opts);
  }

  /**
   * Rotate the account key — generate a new one, re-wrap the entire DEK
   * chain under {existing password KEK, new recovery KEK}, and atomically
   * publish the bundle. The OLD account key is no longer usable for
   * `recoverAccount` after this call returns.
   *
   * Use this when the user suspects their existing account key has been
   * compromised, or as a routine hygiene step. The rotation does NOT
   * change the user's password or username — only the account-key half
   * of the recovery factor.
   *
   * Returns the new account key string so the app can present it to the
   * user (downloadable kit, printable page, etc.). The SDK does not
   * retain it.
   *
   * Failure modes:
   *   - Wrong password → Error (credential mismatch tripwire)
   *   - 409 conflict on lookup-key collision (astronomically unlikely;
   *     retry yields a different key) → Error
   *   - Network failure → Error; D1 is atomic so partial state cannot
   *     occur. Safe to retry.
   *
   * If the account is in Model B, the new account key is also stored
   * (re-wrapped under DEK_gen1). If Model A, the wrap stays absent.
   */
  async rotate(opts: { password: string }): Promise<{ accountKey: string }> {
    return this.#client.rotateAccountKey(opts);
  }

  /**
   * Whether the server stores a wrap of this account's account key
   * (Model B). Reflects the most recent `/auth/verify` response.
   *
   * - `true` — Model B. `view()` is available.
   * - `false` — Model A (no backup stored). `view()` will fail with
   *   `no_account_key_stored`.
   * - `null` — unknown (fresh client that has not yet completed an auth
   *   round trip).
   *
   * Apps render the appropriate Settings affordance based on this:
   * "View your account key" for true, "No backup stored — enable in
   * settings" for false.
   */
  isStored(): boolean | null {
    return this.#client.isAccountKeyStored();
  }
}
