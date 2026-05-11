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
  /**
   * Phase 6.2 — true when this credential has no `passkey_prf` wrapping
   * at the latest gen of the account's envelope. Stale credentials still
   * authenticate (older gens unwrap normally) but cannot read post-stale
   * writes until repaired via `tarn.authenticateWithPasskey({
   * stalePasskeyHandler })` or by re-registering the credential.
   *
   * Surface this in Settings so users can see "Refresh recommended" next
   * to stale entries before they hit a stale credential at login time.
   */
  stale: boolean;
};

export interface IPasskeysClient {
  passkeysSupported(): Promise<boolean>;
  registerPasskey(opts?: { deviceLabel?: string }): Promise<{ credentialId: string; deviceLabel: string | null }>;
  authenticateWithPasskey(opts?: {
    deviceLabel?: string;
    credentialId?: string;
    stalePasskeyHandler?: () => Promise<{ username: string; password: string } | null>;
  }): Promise<{ dataLookupKey: string }>;
  listPasskeys(): Promise<PasskeyInfo[]>;
  removePasskey(opts: { credentialId: string; password: string }): Promise<void>;
}

export class PasskeysNamespace {
  readonly #client: IPasskeysClient;

  constructor(client: IPasskeysClient) {
    this.#client = client;
  }

  /**
   * Feature-detect WebAuthn + likely PRF support on the current device.
   *
   * Returns true when the basic WebAuthn shapes are present (navigator.
   * credentials, PublicKeyCredential, a platform authenticator like Touch
   * ID / Face ID / Windows Hello). Apps render passkey UX based on this.
   *
   * Does NOT gate on a positive PRF advertisement from
   * `getClientCapabilities()` — that advertisement is browser-level while
   * PRF support is per-authenticator. Chrome on Windows reports
   * `prf: false` but PRF actually works there for synced passkeys (Google
   * Password Manager). The actual PRF determination happens at register
   * time; if PRF turns out to be unavailable, `register()` throws with a
   * useful error.
   *
   * Returns false in environments without `navigator.credentials` (Node,
   * very old browsers), without `PublicKeyCredential`, or where
   * `isUserVerifyingPlatformAuthenticatorAvailable()` returns false.
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
   *
   * Each entry also carries a `stale` flag (Phase 6.2) — true when the
   * credential has no `passkey_prf` wrapping at the latest gen of the
   * envelope (typically because changeCredentials ran without a re-tap).
   * Stale entries still authenticate but can't read post-stale writes
   * until the user repairs the wrap. Surface the flag in Settings so
   * users see a "Refresh" affordance before they hit it at login time.
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
