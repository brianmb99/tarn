/** Hand-written declarations for build-bootstrap.mjs (typed test access). */

export type BuildFlags = {
  appId: string | null;
  appName: string | null;
  ownerAddress: string | null;
  fallbackTxid: string | null;
  gateways: string[];
  out: string | null;
  help?: boolean;
};

export type BootstrapBuildConfig = {
  appId: string;
  appName: string;
  ownerAddress: string;
  gateways: string[];
  fallbackTxid: string;
};

export function parseArgs(argv: string[]): BuildFlags;
export function buildConfig(flags: BuildFlags): BootstrapBuildConfig;
export function renderPage(opts: {
  template: string;
  css: string;
  js: string;
  config: BootstrapBuildConfig;
}): string;
export function build(argv: string[], opts?: { logger?: Pick<Console, 'log' | 'error'> }): Promise<{
  ok: boolean;
  exitCode: number;
  outPath?: string;
  sha256?: string;
  config?: BootstrapBuildConfig;
  error?: string;
  help?: boolean;
}>;
