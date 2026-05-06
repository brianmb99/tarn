/**
 * `tarn.passkeys.*` — WebAuthn-PRF passkey factor (Phase 6).
 *
 * Apps surface passkey support as opt-in: feature-detect via
 * `isSupported()` first, hide the affordance on devices that lack PRF
 * (Firefox, older Chrome/Safari, no platform authenticator). When
 * available, registration requires a logged-in session and adds a
 * `passkey_prf` wrapping per gen to the DEK chain envelope. A registered
 * passkey can then be used as the auth credential to establish a fresh
 * session via `tarn.authenticateWithPasskey()`.
 *
 * Removal is step-up gated (caller passes a fresh password), same posture
 * as the account-key toggle endpoints.
 */

export type PasskeyInfo = {
  credentialId: string;
  deviceLabel: string | null;
  createdAt: number;
  lastUsedAt: number | null;
};

export interface IPasskeysClient {
  passkeysSupported(): Promise<boolean>;
  registerPasskey(opts?: { deviceLabel?: string }): Promise<{ credentialId: string; deviceLabel: string | null }>;
  authenticateWithPasskey(opts?: { deviceLabel?: string; credentialId?: string }): Promise<{ dataLookupKey: string }>;
  listPasskeys(): Promise<PasskeyInfo[]>;
  removePasskey(opts: { credentialId: string; password: string }): Promise<void>;
}

export class PasskeysNamespace {
  readonly #client: IPasskeysClient;

  constructor(client: IPasskeysClient) {
    this.#client = client;
  }

  /**
   * Feature-detect WebAuthn + PRF support on the current device.
   * Apps render passkey UX only when this returns true. Returns false in
   * environments without `navigator.credentials`, without a platform
   * authenticator, or without browser-level PRF extension support
   * (Firefox <141, older Safari/Chrome).
   */
  async isSupported(): Promise<boolean> {
    return this.#client.passkeysSupported();
  }

  /**
   * Register a new passkey for the logged-in account. Triggers the
   * platform authenticator prompt (Touch ID / Face ID / Windows Hello /
   * security key). Adds a `passkey_prf` wrapping per gen to the DEK
   * chain so the resulting passkey can independently unwrap data.
   *
   * On success the returned `credentialId` should be displayed in the
   * Settings list of registered passkeys (truncated for readability).
   */
  async register(opts: { deviceLabel?: string } = {}): Promise<{ credentialId: string; deviceLabel: string | null }> {
    return this.#client.registerPasskey(opts);
  }

  /**
   * List the passkeys registered against this account. Each entry is one
   * device the user has enrolled. `lastUsedAt` is null for credentials
   * that have never authenticated since registration.
   */
  async list(): Promise<PasskeyInfo[]> {
    return this.#client.listPasskeys();
  }

  /**
   * Remove a registered passkey. Step-up gated — caller passes the
   * freshly-entered password to prove possession. Strips the
   * corresponding `passkey_prf` wrappings from the envelope and
   * republishes the credential blob.
   *
   * @throws on wrong password, unknown credentialId, or network failure.
   */
  async remove(opts: { credentialId: string; password: string }): Promise<void> {
    return this.#client.removePasskey(opts);
  }
}
