/**
 * `tarn.accountKey.*` — account-key lifecycle namespace.
 *
 * Currently a stub. Future phases land here:
 *   - Phase 3: `view()` (Model B step-up retrieval of the stored account key)
 *   - Phase 4: `rotate()` (account-key rotation)
 *   - Phase 4: `enableKeyStorage()` / `disableKeyStorage()` (Model A/B toggle)
 *
 * The SDK no longer renders recovery kits — apps render their own from the
 * account-key string returned by `register()` / `recoverAccount()` / future
 * `view()`. There is therefore no underlying-client interface to thread
 * through yet; namespace state below is intentionally empty.
 */

// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface IAccountKeyClient {}

export class AccountKeyNamespace {
  // Future methods (view, rotate, enable/disableKeyStorage) land here.
  constructor(_client: IAccountKeyClient, _appId: string) {
    // no-op
  }
}
