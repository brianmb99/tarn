/**
 * Wrapped-data-key envelope parsing and DEK-chain unwrap.
 *
 * Borrowed near-verbatim from `client/src/crypto.ts` lines 812-1075. The
 * envelope shape is the v1 multi-factor chain (the only shape currently in
 * use; legacy v1 bare-base64 / v2 / v3 were cut cleanly — see
 * `docs/TARN_PROTOCOL.md` §4 "Note on prior envelope versions").
 *
 * Phase 6 (forward-compat decoder framework) will introduce a `v: 2`
 * envelope alongside this one. The unwrap entry point here is structured
 * so a new shape can be added without disturbing v1: dispatch on `parsed.v`
 * before the chain walk.
 */

import {
  ARGON2ID_ITERATIONS,
  ARGON2ID_MEMORY_KIB,
  ARGON2ID_PARALLELISM,
  FACTOR_PASSKEY_PRF,
  FACTOR_PASSWORD,
  RECOVERY_SALT_LEN,
} from './constants.js';
import { base64ToBytes, bs } from './encoding.js';
import type { Argon2idParams, DataKeyPair, RecoveryMetadata } from './types.js';

export type EnvelopeVersion = 1;
export const ENVELOPE_VERSION: EnvelopeVersion = 1;

export type ChainWrapping = {
  factor: string; // narrowed to `Factor` by the wrap helpers
  wrappedBase64: string;
  /** Populated for `passkey_prf` wrappings only (Phase 6). */
  credentialId?: string;
};

export type DekChainEntry = {
  gen: number;
  wrappings: ChainWrapping[];
};

export type ParsedWrappedDataKey = {
  envelopeVersion: EnvelopeVersion;
  dekChain: DekChainEntry[];
  /** Convenience: highest-gen `password` wrapping bytes (always present). */
  wrappedBase64: string;
  kdfParams: Argon2idParams;
  recovery: RecoveryMetadata;
};

/**
 * Inspect a wire-format `wrapped_data_key` without unwrapping. Validates
 * that it is a v1 multi-factor envelope; throws on any other shape.
 */
export function parseWrappedDataKey(wireValue: string): ParsedWrappedDataKey {
  if (typeof wireValue !== 'string' || wireValue.length === 0) {
    throw new Error('wrapped_data_key must be a non-empty string');
  }
  if (wireValue[0] !== '{') {
    throw new Error('wrapped_data_key must be a JSON envelope');
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(wireValue) as Record<string, unknown>;
  } catch {
    throw new Error('wrapped_data_key looks like an envelope but is not valid JSON');
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('wrapped_data_key envelope is missing required fields');
  }
  if (parsed['v'] !== 1 || parsed['kdf'] !== 'argon2id') {
    throw new Error(
      `wrapped_data_key: unsupported envelope (expected v=1 kdf=argon2id, got v=${String(parsed['v'])} kdf=${String(parsed['kdf'])})`,
    );
  }

  const dekChainRaw = parsed['dek_chain'];
  if (!Array.isArray(dekChainRaw) || dekChainRaw.length === 0) {
    throw new Error('wrapped_data_key envelope must have a non-empty dek_chain');
  }
  const chain: DekChainEntry[] = dekChainRaw.map((entry: unknown, idx: number) => {
    const e = entry as Record<string, unknown> | null;
    if (
      !e ||
      typeof e !== 'object' ||
      typeof e['gen'] !== 'number' ||
      !Number.isInteger(e['gen']) ||
      (e['gen'] as number) < 1 ||
      !Array.isArray(e['wrappings']) ||
      (e['wrappings'] as unknown[]).length === 0
    ) {
      throw new Error(`wrapped_data_key envelope dek_chain[${idx}] is malformed`);
    }
    const wrappings: ChainWrapping[] = (e['wrappings'] as unknown[]).map((w: unknown, wIdx: number) => {
      const wo = w as Record<string, unknown> | null;
      if (
        !wo ||
        typeof wo !== 'object' ||
        typeof wo['factor'] !== 'string' ||
        (wo['factor'] as string).length === 0 ||
        typeof wo['wrapped'] !== 'string'
      ) {
        throw new Error(`wrapped_data_key envelope dek_chain[${idx}].wrappings[${wIdx}] is malformed`);
      }
      const factor = wo['factor'] as string;
      const wrapping: ChainWrapping = {
        factor,
        wrappedBase64: wo['wrapped'] as string,
      };
      if (factor === FACTOR_PASSKEY_PRF) {
        if (typeof wo['credential_id'] !== 'string' || (wo['credential_id'] as string).length === 0) {
          throw new Error(`wrapped_data_key envelope dek_chain[${idx}].wrappings[${wIdx}] passkey_prf entry missing credential_id`);
        }
        wrapping.credentialId = wo['credential_id'] as string;
      }
      return wrapping;
    });
    // Dedupe across (factor, credentialId).
    const factorSeen = new Set<string>();
    for (const w of wrappings) {
      const key = w.factor === FACTOR_PASSKEY_PRF
        ? `${w.factor}:${w.credentialId ?? ''}`
        : w.factor;
      if (factorSeen.has(key)) {
        throw new Error(`wrapped_data_key envelope dek_chain[${idx}] has duplicate factor: ${key}`);
      }
      factorSeen.add(key);
    }
    return { gen: e['gen'] as number, wrappings };
  });
  const seen = new Set<number>();
  for (const e of chain) {
    if (seen.has(e.gen)) {
      throw new Error(`wrapped_data_key envelope has duplicate gen: ${e.gen}`);
    }
    seen.add(e.gen);
  }
  chain.sort((a, b) => a.gen - b.gen);

  const recoveryRaw = parsed['recovery'];
  if (!recoveryRaw || typeof recoveryRaw !== 'object') {
    throw new Error('wrapped_data_key envelope is missing required recovery block');
  }
  const r = recoveryRaw as Record<string, unknown>;
  if (
    r['kdf'] !== 'argon2id' ||
    !r['kdf_params'] ||
    typeof r['salt'] !== 'string'
  ) {
    throw new Error('wrapped_data_key envelope has malformed recovery block');
  }
  const saltBytes = base64ToBytes(r['salt'] as string);
  if (saltBytes.length !== RECOVERY_SALT_LEN) {
    throw new Error(`recovery.salt must decode to ${RECOVERY_SALT_LEN} bytes, got ${saltBytes.length}`);
  }
  const recovery: RecoveryMetadata = {
    kdf: 'argon2id',
    kdfParams: r['kdf_params'] as Argon2idParams,
    salt: saltBytes,
  };

  // Convenience field: highest-gen `password` wrapping (current write-side).
  const top = chain[chain.length - 1]!;
  const pw = top.wrappings.find(w => w.factor === FACTOR_PASSWORD);
  if (!pw) {
    throw new Error('wrapped_data_key envelope: current gen is missing the password wrapping');
  }
  const kdfParams = (parsed['kdf_params'] as Argon2idParams | undefined) ?? {
    m_kib: ARGON2ID_MEMORY_KIB,
    t: ARGON2ID_ITERATIONS,
    p: ARGON2ID_PARALLELISM,
  };

  return {
    envelopeVersion: 1,
    dekChain: chain,
    wrappedBase64: pw.wrappedBase64,
    kdfParams,
    recovery,
  };
}

/** Result of unwrapping every DEK in a chain via a chosen factor's KEK. */
export type UnwrappedDekChain = {
  dekByGen: Map<number, DataKeyPair>;
  currentGen: number;
  envelopeVersion: EnvelopeVersion;
  kdfParams: Argon2idParams;
  recovery: RecoveryMetadata;
};

/**
 * Unwrap every DEK in the chain via the named factor (defaults to
 * `FACTOR_PASSWORD`). Returns a Map keyed by generation plus the current
 * (highest) generation number. Each value is a pair of WebCrypto handles
 * for the same 32-byte DEK:
 *   - `gcmKey`: AES-GCM, extractable
 *   - `kwKey`:  AES-KW, used to unwrap per-content CEKs
 *
 * For `FACTOR_PASSKEY_PRF`, an additional `credentialId` argument selects
 * which passkey wrapping to consume (an account may have multiple).
 */
export async function unwrapDataKeyChain(
  wireValue: string,
  unwrappingKey: CryptoKey,
  factor: string = FACTOR_PASSWORD,
  credentialId?: string,
): Promise<UnwrappedDekChain> {
  const parsed = parseWrappedDataKey(wireValue);
  const dekByGen = new Map<number, DataKeyPair>();
  for (const entry of parsed.dekChain) {
    const wrapping = entry.wrappings.find(w => {
      if (w.factor !== factor) return false;
      if (factor === FACTOR_PASSKEY_PRF) {
        return w.credentialId === credentialId;
      }
      return true;
    });
    if (!wrapping) {
      const detail = factor === FACTOR_PASSKEY_PRF
        ? `'${factor}' (credentialId=${credentialId})`
        : `'${factor}'`;
      throw new Error(`No ${detail} wrapping for gen ${entry.gen}`);
    }
    const wrapped = base64ToBytes(wrapping.wrappedBase64);
    const [gcmKey, kwKey] = await Promise.all([
      crypto.subtle.unwrapKey(
        'raw', bs(wrapped), unwrappingKey, 'AES-KW',
        { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'],
      ),
      crypto.subtle.unwrapKey(
        'raw', bs(wrapped), unwrappingKey, 'AES-KW',
        'AES-KW', false, ['wrapKey', 'unwrapKey'],
      ),
    ]);
    dekByGen.set(entry.gen, { gcmKey, kwKey });
  }
  const currentGen = parsed.dekChain[parsed.dekChain.length - 1]!.gen;
  return {
    dekByGen,
    currentGen,
    envelopeVersion: parsed.envelopeVersion,
    kdfParams: parsed.kdfParams,
    recovery: parsed.recovery,
  };
}
