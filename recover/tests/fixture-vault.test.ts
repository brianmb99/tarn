/**
 * Fixture-vault meta-test — guards against accidental fixture mutation.
 *
 * The fixture vault (`recover/fixtures/`) is the structural enforcement of
 * the forward-compatibility contract. Files in there must NEVER be deleted
 * or modified after they're committed; the only allowed mutation is adding
 * new files.
 *
 * `recover/fixtures/manifest.json` is the source of truth: a sorted list of
 * `{ path, sha256, sizeBytes }` for every fixture file under `fixtures/`.
 * This test:
 *
 *   1. Hashes every file under `fixtures/` (excluding the manifest itself
 *      and the README).
 *   2. Compares the result to the manifest's `fixtures` array.
 *   3. Fails on any drift: missing manifest entry, missing filesystem
 *      file, hash mismatch, or size mismatch.
 *
 * To extend the manifest legitimately (when shipping a new envelope
 * version): run `node scripts/generate-fixtures.mjs`, which appends new
 * files and rewrites the manifest. The new files plus the updated
 * manifest are committed together.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const fixturesRoot = resolve(here, '..', 'fixtures');
const manifestPath = join(fixturesRoot, 'manifest.json');

type ManifestEntry = {
  path: string;
  sha256: string;
  sizeBytes: number;
};

type Manifest = {
  comment: string;
  generatedBy: string;
  fixtures: ManifestEntry[];
};

function loadManifest(): Manifest {
  const raw = readFileSync(manifestPath, 'utf8');
  return JSON.parse(raw) as Manifest;
}

/** Recursively collect every JSON fixture file — excludes manifest.json itself. */
function discoverFixtureFiles(): { relPath: string; absPath: string }[] {
  const out: { relPath: string; absPath: string }[] = [];
  function walk(dir: string): void {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const st = statSync(full);
      if (st.isDirectory()) {
        walk(full);
      } else if (entry.endsWith('.json') && entry !== 'manifest.json') {
        const rel = relative(fixturesRoot, full).replaceAll('\\', '/');
        out.push({ relPath: rel, absPath: full });
      }
    }
  }
  walk(fixturesRoot);
  out.sort((a, b) => a.relPath.localeCompare(b.relPath));
  return out;
}

describe('fixture vault: manifest is the immutable source of truth', () => {
  it('manifest exists and parses', () => {
    const m = loadManifest();
    assert.ok(Array.isArray(m.fixtures), 'manifest.fixtures must be an array');
    assert.ok(m.fixtures.length > 0, 'manifest must list at least one fixture');
    assert.equal(typeof m.comment, 'string', 'manifest.comment must be a string');
  });

  it('every manifest entry exists on disk with the recorded hash + size', () => {
    const manifest = loadManifest();
    for (const entry of manifest.fixtures) {
      const full = join(fixturesRoot, entry.path);
      let bytes: Buffer;
      try {
        bytes = readFileSync(full);
      } catch (err) {
        assert.fail(
          `manifest references ${entry.path} but the file is missing: ${(err as Error).message}. ` +
          `Fixtures are immutable — files in the vault must never be deleted.`,
        );
      }
      assert.equal(
        bytes.length,
        entry.sizeBytes,
        `${entry.path}: size on disk (${bytes.length}) != manifest.sizeBytes (${entry.sizeBytes}). ` +
        `Fixture file appears to have been modified.`,
      );
      const observed = createHash('sha256').update(bytes).digest('hex');
      assert.equal(
        observed,
        entry.sha256,
        `${entry.path}: SHA-256 on disk (${observed}) != manifest.sha256 (${entry.sha256}). ` +
        `Fixture file appears to have been modified — this is a forward-compat contract violation. ` +
        `If you intended to add a NEW fixture, run scripts/generate-fixtures.mjs (which only ` +
        `appends), then commit the new files plus the regenerated manifest.`,
      );
    }
  });

  it('every fixture file on disk has a manifest entry', () => {
    const manifest = loadManifest();
    const known = new Set(manifest.fixtures.map((e) => e.path));
    const onDisk = discoverFixtureFiles();
    const unlisted: string[] = [];
    for (const f of onDisk) {
      if (!known.has(f.relPath)) unlisted.push(f.relPath);
    }
    if (unlisted.length > 0) {
      assert.fail(
        `Fixture files exist on disk but are not in manifest.json: [${unlisted.join(', ')}]. ` +
        `Run scripts/generate-fixtures.mjs to regenerate the manifest, then commit it ` +
        `alongside the new fixture files.`,
      );
    }
  });

  it('manifest entries are sorted by path (stable canonical order)', () => {
    const manifest = loadManifest();
    const paths = manifest.fixtures.map((e) => e.path);
    const sorted = [...paths].sort((a, b) => a.localeCompare(b));
    assert.deepEqual(
      paths,
      sorted,
      'manifest.fixtures must be sorted by path for stable diffs',
    );
  });

  it('every manifest entry has a non-empty 64-char SHA-256 hex', () => {
    const manifest = loadManifest();
    for (const entry of manifest.fixtures) {
      assert.match(
        entry.sha256,
        /^[0-9a-f]{64}$/,
        `${entry.path}: sha256 must be 64 lowercase hex chars`,
      );
      assert.ok(
        Number.isInteger(entry.sizeBytes) && entry.sizeBytes > 0,
        `${entry.path}: sizeBytes must be a positive integer`,
      );
    }
  });
});
