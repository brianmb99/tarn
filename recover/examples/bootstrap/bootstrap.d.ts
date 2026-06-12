/**
 * Hand-written declarations for bootstrap.js.
 *
 * The page source is deliberately plain JS (it is inlined verbatim into
 * the published artifact — no bundler, no transpile — so the shipped
 * bytes are the audited source). This file gives the test suite typed
 * access to the exported helpers.
 */

export type BootstrapConfig = {
  appId: string;
  appName: string;
  ownerAddress: string;
  gateways: string[];
  fallbackTxid: string;
};

export type PointerRecord = {
  pointerTxid: string;
  version: string;
  confirmed: boolean;
  timestamp: number | null;
};

export type ResolvedPage = {
  pageTxid: string;
  url: string;
  pageVersion: string;
  sha256: string | null;
};

type FetchLike = (url: string, opts?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<{
  ok: boolean;
  status?: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}>;

export function isValidTxid(s: unknown): boolean;
export function readConfig(doc: { getElementById(id: string): { textContent: string | null } | null }): BootstrapConfig;
export function buildPointerQuery(opts: { appId: string; ownerAddress: string; limit?: number }): string;
export function buildPageVerifyQuery(opts: { pageTxid: string; appId: string; ownerAddress: string }): string;
export function tagValue(tags: unknown, name: string): string | null;
export function parsePointerEdges(json: unknown): PointerRecord[];
export function orderPointers<T extends { confirmed: boolean }>(pointers: T[]): T[];
export function resolvePointer(opts: {
  pointer: { pointerTxid: string; version?: string };
  config: BootstrapConfig;
  gateway: string;
  fetchImpl: FetchLike;
}): Promise<ResolvedPage>;
export function discover(opts: { config: BootstrapConfig; fetchImpl: FetchLike }): Promise<{
  resolved: ResolvedPage;
  pointer: PointerRecord;
  pointers: PointerRecord[];
  gateway: string;
  errors: string[];
}>;
export function init(opts?: { doc?: unknown; fetchImpl?: FetchLike }): Promise<void>;
