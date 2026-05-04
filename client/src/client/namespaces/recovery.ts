/**
 * `tarn.recovery.*` — re-render the recovery kit for a phrase the user
 * already holds.
 *
 * The kit format options:
 *   - 'pdf'  → PDF bytes with the default Tarn-branded layout (uses the
 *     existing `renderRecoveryPDF` from the recovery module).
 *   - 'json' → structured object with `phrase` and `appName` for apps
 *     that want to render their own format. Bytes only — no PDF library.
 *
 * Tarn never delivers the kit anywhere — apps are responsible for surfacing
 * the bytes to the user (download, print, or any other channel the app
 * decides is appropriate). The phrase is also never persisted by the SDK;
 * the caller must pass it back in for every re-export.
 */

export type RecoveryFormat = 'pdf' | 'json';

export type RecoveryJson = {
  phrase: string;
  appName: string;
  generatedAt: string; // ISO 8601
};

export interface IRecoveryClient {
  regenerateRecoveryKit(opts: {
    phrase: string;
    appName?: string;
  }): Promise<{ phrase: string; pdfBytes: Uint8Array }>;
}

export class RecoveryNamespace {
  readonly #client: IRecoveryClient;
  readonly #appId: string;

  constructor(client: IRecoveryClient, appId: string) {
    this.#client = client;
    this.#appId = appId;
  }

  /**
   * Re-render the recovery kit for a phrase the user already has. With
   * `format: 'pdf'` returns the rendered PDF as `Uint8Array` (wrap in
   * `new Blob([bytes], { type: 'application/pdf' })` if you need a Blob).
   * With `format: 'json'` returns the structured kit data for apps that
   * want to render their own format.
   *
   * Pure client-side — no network call, no auth requirement. The phrase is
   * validated against the BIP39 wordlist + checksum; an invalid phrase
   * throws synchronously. The same (phrase, appName) tuple always produces
   * an identical kit — re-export is idempotent and does NOT rotate any
   * server-side state. (Phrase rotation is a separate, deliberately-absent
   * operation — losing your phrase requires recoverAccount + a new
   * registration-equivalent flow, not a casual re-export.)
   */
  async export(opts: {
    format: RecoveryFormat;
    phrase: string;
    appName?: string;
  }): Promise<Uint8Array | RecoveryJson> {
    const appName = opts.appName ?? this.#appId;
    const result = await this.#client.regenerateRecoveryKit({ phrase: opts.phrase, appName });
    if (opts.format === 'pdf') {
      return result.pdfBytes;
    }
    return {
      phrase: result.phrase,
      appName,
      generatedAt: new Date().toISOString(),
    };
  }
}
