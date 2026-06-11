/**
 * `tarn.session.*` — active session state and multi-device management.
 *
 * Session storage (where the session blob is persisted across reloads) is
 * configured via `TarnStorage` at `TarnClient.create()` time. This namespace
 * surfaces operations on the SERVER-SIDE sessions table — list logged-in
 * devices, revoke individual or all-other devices, revoke the current
 * session.
 */

export type SessionRecord = {
  sid: string;
  createdAt: number;
  lastSeenAt: number;
  deviceLabel: string | null;
  viaRecovery: boolean;
  isCurrent: boolean;
};

export interface ISessionClient {
  isLoggedIn(): boolean;
  clearSession(): Promise<void>;
  listSessions(): Promise<SessionRecord[]>;
  revokeSession(sid: string): Promise<unknown>;
  revokeAllSessions(): Promise<unknown>;
  revokeOtherSessions(): Promise<unknown>;
}

export class SessionNamespace {
  readonly #client: ISessionClient;
  readonly #onLogout: () => void;

  constructor(client: ISessionClient, onLogout: () => void) {
    this.#client = client;
    this.#onLogout = onLogout;
  }

  /** Whether the client currently has the keys needed for authenticated calls. */
  isLoggedIn(): boolean {
    return this.#client.isLoggedIn();
  }

  /**
   * Forget the local session — clears the persisted blob and any in-process
   * key material. After this, `isLoggedIn()` returns false and the user
   * must re-authenticate via `tarn.login()` or `tarn.register()`.
   *
   * Also wipes the SDK's per-account IndexedDB caches for the current
   * account (delta-sync cursors + ciphertext blob cache, issue #71), so
   * apps do NOT need to delete `tarn-sync-cursors` / `tarn-blob-cache`
   * themselves on logout (doing so anyway is harmless). The wipe is
   * best-effort and scoped to the signed-out account — other accounts'
   * cached state on the same origin is untouched.
   */
  async clear(): Promise<void> {
    await this.#client.clearSession();
    this.#onLogout();
  }

  /**
   * List the active server-side sessions for this account. Each entry is
   * one device that has authenticated successfully and not been revoked.
   */
  async listDevices(): Promise<SessionRecord[]> {
    return this.#client.listSessions();
  }

  /** Revoke a specific device by sid. The device's next request will 401. */
  async revokeDevice(sid: string): Promise<void> {
    await this.#client.revokeSession(sid);
  }

  /**
   * Revoke every session including this one. The next request from any
   * device — including this one — will 401. Use after credential
   * compromise concerns.
   */
  async revokeAll(): Promise<void> {
    await this.#client.revokeAllSessions();
    this.#onLogout();
  }

  /**
   * Revoke every other device's session except this one. This device stays
   * logged in. Useful for "log out everywhere else" UX.
   */
  async revokeAllOthers(): Promise<void> {
    await this.#client.revokeOtherSessions();
  }
}
