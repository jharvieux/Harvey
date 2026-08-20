import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { readRecursiveSafe } from "../fs-walk.js";
import { compareM9TaxonomyDocs, type SourceText } from "./m9-taxonomy-docs.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "node_modules", ".bin", "tsx");
const DOC = readFileSync(join(REPO_ROOT, "docs", "m9-app-router.md"), "utf8");
const SOURCES: SourceText[] = readRecursiveSafe(join(REPO_ROOT, "src"))
  .filter((path) => /\.(?:ts|tsx|mts|cts)$/.test(path) && !path.endsWith(".test.ts") && !path.endsWith(".test.tsx"))
  .map((path) => ({ path: `src/${path}`, text: readFileSync(join(REPO_ROOT, "src", path), "utf8") }));
const SCRATCH: string[] = [];

afterEach(() => {
  for (const path of SCRATCH.splice(0)) rmSync(path, { recursive: true, force: true });
});

function withUndocumentedTaxonomy(sources: readonly SourceText[]): SourceText[] {
  return sources.map((source) =>
    source.path === "src/detectors/remix-adapter.ts"
      ? {
          ...source,
          text: source.text.replace(
            'taxonomy: "M9 — Server→client data leak"',
            'taxonomy: "M9 — Seeded undocumented family"',
          ),
        }
      : source,
  );
}

function withStaleHeader(doc: string): string {
  return doc.replace(
    "\n## Calibration corpus coverage",
    "\n### Seeded stale check (`M9 — Seeded stale documented family`)\n\n## Calibration corpus coverage",
  );
}

function fixtureRoot(sources: readonly SourceText[], doc: string): string {
  const root = mkdtempSync(join(tmpdir(), "harvey-m9-taxonomy-docs-"));
  SCRATCH.push(root);
  const sourcePaths = compareM9TaxonomyDocs(sources, doc).registry.sourcePaths;
  for (const path of sourcePaths) {
    const source = sources.find((candidate) => candidate.path === path);
    if (!source) throw new Error(`missing source fixture ${path}`);
    const target = join(root, path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, source.text);
  }
  mkdirSync(join(root, "docs"), { recursive: true });
  writeFileSync(join(root, "docs", "m9-app-router.md"), doc);
  return root;
}

function runCli(root: string): ReturnType<typeof spawnSync> {
  return spawnSync(CLI, [join(REPO_ROOT, "src", "cli", "validate-m9-taxonomy-docs.ts"), "--root", root], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
}

describe("#1640 — source-derived M9 taxonomy/document parity", () => {
  it("matches every current shipped family to the operator-facing Checks headers", () => {
    const report = compareM9TaxonomyDocs(SOURCES, DOC);
    expect(report.violations).toEqual([]);
    expect(report.registry.canonicalM9Families.length).toBeGreaterThan(0);
    expect(report.registry.sourcePaths).toEqual(expect.arrayContaining([
      "src/detectors/app-router.ts",
      "src/detectors/boundary-model.ts",
      "src/detectors/remix-adapter.ts",
      "src/detectors/tanstack-adapter.ts",
    ]));
  });

  it("fails in both drift directions through the real comparator", () => {
    expect(compareM9TaxonomyDocs(withUndocumentedTaxonomy(SOURCES), DOC).violations).toContain(
      "shipped M9 taxonomy has no Checks header: M9 — Seeded undocumented family",
    );
    expect(compareM9TaxonomyDocs(SOURCES, withStaleHeader(DOC)).violations).toContain(
      "Checks header names an M9 taxonomy that no longer ships: M9 — Seeded stale documented family",
    );
  });

  it("normalizes adapter spellings and enumerates every scope/not-assessed output site", () => {
    const registry = compareM9TaxonomyDocs(SOURCES, DOC).registry;
    expect(registry.aliases).toContainEqual({
      emitted: "M9 — route action missing input validation",
      documentedAs: "M9 — Server Action missing input validation",
    });
    expect(registry.aliases).toContainEqual({
      emitted: "M9 — server function missing input validation",
      documentedAs: "M9 — Server Action missing input validation",
    });
    expect(new Set(registry.exclusions.map((row) => row.kind))).toEqual(new Set(["scope", "not-assessed", "not-applicable"]));
    expect(registry.exclusions.map((row) => row.expression)).toEqual(expect.arrayContaining([
      "`M9 — ${checkLabel} — not assessed (${label})`",
      "`${taxonomy} — not assessed`",
    ]));
  });

  it("returns non-zero/non-zero/zero for emitted-only, header-only, then restored inputs", () => {
    const root = fixtureRoot(SOURCES, DOC);
    const remixAdapter = join(root, "src", "detectors", "remix-adapter.ts");
    const doc = join(root, "docs", "m9-app-router.md");
    const originalSource = readFileSync(remixAdapter, "utf8");

    writeFileSync(
      remixAdapter,
      originalSource.replace(
        'taxonomy: "M9 — Server→client data leak"',
        'taxonomy: "M9 — Seeded undocumented family"',
      ),
    );
    const emittedOnly = runCli(root);
    expect(emittedOnly.status, `${emittedOnly.stdout}\n${emittedOnly.stderr}`).toBe(1);

    writeFileSync(remixAdapter, originalSource);
    writeFileSync(doc, withStaleHeader(DOC));
    const headerOnly = runCli(root);
    expect(headerOnly.status, `${headerOnly.stdout}\n${headerOnly.stderr}`).toBe(1);

    writeFileSync(doc, DOC);
    const restored = runCli(root);
    expect(restored.status, `${restored.stdout}\n${restored.stderr}`).toBe(0);
  });
});
