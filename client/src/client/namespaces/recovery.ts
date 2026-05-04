/**
 * `tarn.recovery.*` — generate recovery kits.
 *
 * The kit format options:
 *   - 'pdf'  → PDF Blob with the default Tarn-branded layout (uses the
 *     existing `renderRecoveryPDF` from the recovery module).
 *   - 'json' → structured object with `phrase` and `appName` for apps
 *     that want to render their own format. Bytes only — no PDF library.
 *
 * Tarn never delivers the kit anywhere — apps are responsible for surfacing
 * the bytes to the user (download, print, or any other channel the app
 * decides is appropriate).
 */

export type RecoveryFormat = 'pdf' | 'json';

export type RecoveryJson = {
  phrase: string;
  appName: string;
  generatedAt: string; // ISO 8601
};

export interface IRecoveryClient {
  regenerateRecoveryKit(opts?: Record<string, unknown>): Promise<{ phrase: string; pdfBytes: Uint8Array }>;
}

export class RecoveryNamespace {
  readonly #client: IRecoveryClient;
  readonly #appId: string;

  constructor(client: IRecoveryClient, appId: string) {
    this.#client = client;
    this.#appId = appId;
  }

  /**
   * Generate a recovery kit. With `format: 'pdf'` returns the PDF as
   * `Uint8Array` (Blob-equivalent — wrap in `new Blob([bytes], { type: 'application/pdf' })`
   * if you need a Blob). With `format: 'json'` returns the structured data
   * for apps that render their own kit.
   *
   * Idempotent at the protocol level — calling twice produces a fresh phrase
   * each time and rotates the recovery factor on Arweave. The previously-
   * generated phrase stops working after the next call (this is intentional
   * — the user is replacing their recovery material).
   */
  async export(opts: { format: RecoveryFormat; appName?: string }): Promise<Uint8Array | RecoveryJson> {
    const appName = opts.appName ?? this.#appId;
    const result = await this.#client.regenerateRecoveryKit({ appName });
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
