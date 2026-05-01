/**
 * `tarn.account.*` — credential and account lifecycle.
 *
 * `register`, `login`, `recoverAccount` live as TOP-LEVEL methods on the
 * TarnClient (they're how you go from "no session" to "session") rather
 * than under this namespace. This namespace covers operations on an
 * already-authenticated account.
 */

export interface IAccountClient {
  changeCredentials(
    newEmail: string,
    newPassword: string,
    opts?: Record<string, unknown>,
  ): Promise<unknown>;
  deleteAccount(): Promise<unknown>;
}

export class AccountNamespace {
  readonly #client: IAccountClient;
  readonly #onLogout: () => void;

  constructor(client: IAccountClient, onLogout: () => void) {
    this.#client = client;
    this.#onLogout = onLogout;
  }

  /**
   * Rotate the credentials encrypting the user's data key. New email +
   * password derive a new master key; the data key is re-wrapped under it.
   * All entries previously written remain decryptable (forward-secret DEK
   * chain). Existing sessions on other devices continue to work.
   */
  async changeCredentials(
    newEmail: string,
    newPassword: string,
    opts: Record<string, unknown> = {},
  ): Promise<unknown> {
    return this.#client.changeCredentials(newEmail, newPassword, opts);
  }

  /**
   * Permanently delete the account. Tombstones the credential mapping on
   * Arweave; clears server-side state. Local session state is wiped via
   * the storage adapter (the SDK clears the persisted blob automatically).
   */
  async delete(): Promise<void> {
    await this.#client.deleteAccount();
    this.#onLogout();
  }
}
