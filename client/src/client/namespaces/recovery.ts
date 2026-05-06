/**
 * `tarn.accountKey.*` — account-key lifecycle namespace.
 *
 * Phase 3 (RECOVERY_PLAN.md): `view()` retrieves the stored account key
 * for Model B accounts via a step-up gated flow.
 *
 * Future phases land here:
 *   - Phase 4: `rotate()` (account-key rotation)
 *   - Phase 4: `enableKeyStorage()` / `disableKeyStorage()` (Model A/B toggle)
 *
 * The SDK does not render recovery kits — apps render their own from the
 * account-key string returned by `register()` / `recoverAccount()` /
 * `view()`. The namespace's job is orchestration; it never persists the
 * decrypted account key.
 */

export interface IAccountKeyClient {
  viewAccountKey(opts: { password: string }): Promise<{ accountKey: string }>;
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
   * "no backup" Settings affordance and offer the toggle (Phase 4) to
   * enable storage.
   *
   * The returned `accountKey` is a 24-word string. The SDK does not
   * cache or retain it — surface it to the user and drop the in-memory
   * copy promptly.
   */
  async view(opts: { password: string }): Promise<{ accountKey: string }> {
    return this.#client.viewAccountKey(opts);
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
