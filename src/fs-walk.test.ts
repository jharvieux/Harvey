// #1451 — the regression suite for the dangling-symlink walk crash, plus the gate that stops the
// next one. `statSync(p).isDirectory()` follows the link and throws; #944 fixed one site, #1044
// reintroduced it in another the next day, and #1455 fixed two more. The per-site table below is
// what makes "fixed the class" a measurement rather than a claim: every walker Harvey can hand a
// client directory to is called against a tree containing the exact shapes found in the wild.

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import type { Finding } from "./findings.js";
import { isDirectorySafe, readEntriesSafe, statSafe } from "./fs-walk.js";
import { BANNED, GUARD_MODULE, discoverSourceFiles, findBannedStatSites, readSourceFiles } from "./fs-walk-guard.js";
import { walkSourceFiles } from "./scan/common.js";
import { measureCodebaseSize } from "./scan/codebase-size.js";
import { MechanicalScanContext } from "./scan/mechanical-context.js";
import { checkWebExtensionManifest } from "./scan/webext-manifest.js";
import { annotateCveReachability } from "./scan/dep-reachability.js";
import { checkUnreadSourceExtensions } from "./scan/ext-coverage.js";
import { checkInfrastructureScope } from "./scan/infra-scope.js";
import { checkUnanalysedLanguages } from "./scan/language-coverage.js";
import { checkUnassessedSfcFiles } from "./scan/sfc-coverage.js";
import { resolveScanScope } from "./scan/scan-scope.js";
import { isGitRepoRoot } from "./scan/secrets.js";
import { checkMigrationPolicySemantics, checkMigrationRlsStatic, checkMigrationStorageBuckets, checkUnreadSqlSurfaces, inferAuthMethodsFromSource } from "./scan/supabase-static.js";
import { checkWorkflowPermissions } from "./scan/gha-permissions.js";
import { parseViteBundleStats } from "./detectors/bundle-stats.js";
import { loadSources } from "./detectors/load-sources.js";
import { scanAssetWeight } from "./detectors/asset-weight.js";

const REPO_ROOT = new URL("../", import.meta.url).pathname;
const dirs: string[] = [];
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

// The three shapes a committed link fails to resolve as, all three MEASURED against real repos or
// node itself: a link to a missing path (liam's `frontend/apps/app/.env`, dub's EE `LICENSE.md`,
// cal-diy's `packages/prisma/.env` — the three that crashed the 2026-07-28 breadth sweep), a link
// THROUGH a non-directory, and a link cycle. A `.ts` link is in the set deliberately: a walker that
// merely stops treating the link as a directory would then hit readFileSync on it and throw anyway.
function plantTarget(): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-dangling-"));
  dirs.push(dir);
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "t", dependencies: { next: "14.0.0" } }));
  writeFileSync(join(dir, "src", "real.ts"), "export const handler = async () => ({ ok: true });\n");
  writeFileSync(join(dir, "real.js"), "module.exports = {};\n");
  symlinkSync("../.env.local", join(dir, "src", "missing.env"));
  symlinkSync("./nowhere.ts", join(dir, "src", "missing.ts"));
  symlinkSync("real.js/child", join(dir, "src", "through-a-file"));
  symlinkSync("cycle-b", join(dir, "src", "cycle-a"));
  symlinkSync("cycle-a", join(dir, "src", "cycle-b"));
  // The mechanical context inventories ordered migration history, so include that surface rather
  // than letting its walker row pass on a tree it never read. Same reason the CVE row below hands
  // annotateCveReachability a real finding.
  mkdirSync(join(dir, "supabase", "migrations"), { recursive: true });
  writeFileSync(join(dir, "supabase", "migrations", "001_init.sql"), "create table t (id uuid, org_id uuid);\n");
  symlinkSync("../../nowhere.sql", join(dir, "supabase", "migrations", "002_missing.sql"));
  // The SECOND shape, which contains no stat at all: a names-only walk keeps the unresolvable link
  // (it is not a directory) and the readFileSync after it throws. MEASURED 2026-07-28 — six live
  // sites, none of which a `statSync` ban alone would have seen.
  mkdirSync(join(dir, ".github", "workflows"), { recursive: true });
  writeFileSync(join(dir, ".github", "workflows", "ci.yml"), "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n");
  symlinkSync("./nowhere.yml", join(dir, ".github", "workflows", "broken.yml"));
  mkdirSync(join(dir, "dist", "assets"), { recursive: true });
  writeFileSync(join(dir, "dist", "assets", "app.js"), "console.log(1);\n");
  symlinkSync("./nowhere.js", join(dir, "dist", "assets", "broken.js"));
  return dir;
}

const CVE_FINDING: Finding = {
  id: "DEP-CVE-01",
  title: "next 14.0.0 — CVE",
  severity: "High",
  confidence: "Likely",
  category: "Dependency CVE",
  taxonomy: "Dependency CVE",
  location: "package.json",
  status: "Open",
  evidence: "next@14.0.0",
  impact: "-",
  fix: "-",
  dependency: "next",
  value: 3,
  ease: 3,
  safety: 3,
  mechanical: true,
};

describe("statSafe / readEntriesSafe (#1451)", () => {
  it("returns undefined for every way a committed link fails to resolve, and a Stats for one that does", () => {
    const dir = plantTarget();
    expect(statSafe(join(dir, "src", "missing.env"))).toBeUndefined(); // ENOENT
    expect(statSafe(join(dir, "src", "through-a-file"))).toBeUndefined(); // ENOTDIR
    expect(statSafe(join(dir, "src", "cycle-a"))).toBeUndefined(); // ELOOP — NOT covered by throwIfNoEntry
    expect(statSafe(join(dir, "src", "real.ts"))?.isFile()).toBe(true);
    expect(isDirectorySafe(join(dir, "src"))).toBe(true);
    expect(isDirectorySafe(join(dir, "src", "missing.ts"))).toBe(false);
  });

  it("omits unresolvable links from entries and names them in dangling, so a caller cannot forget the guard", () => {
    const dir = plantTarget();
    const { entries, dangling } = readEntriesSafe(join(dir, "src"));
    expect(entries.map((e) => e.name)).toEqual(["real.ts"]);
    expect([...dangling].sort()).toEqual(["cycle-a", "cycle-b", "missing.env", "missing.ts", "through-a-file"]);
  });

  it("still classifies a symlink that DOES resolve to a directory as one", () => {
    const dir = plantTarget();
    symlinkSync("src", join(dir, "linked"));
    const { entries } = readEntriesSafe(dir);
    expect(entries.find((e) => e.name === "linked")?.isDirectory).toBe(true);
  });
});

// Each row is one fixed site. A bare `statSync(...).isDirectory()` in any of these throws ENOENT on
// the planted tree — verified by reverting the source files and watching every row below fail.
const WALKERS: [name: string, run: (dir: string) => unknown][] = [
  ["scan/common.ts walkSourceFiles — M1 AST tier (21 detectors), M7 prisma-app-perf, migration drift (fixed #1455; standing regression)", (d) => walkSourceFiles(d)],
  ["scan/mechanical-context.ts MechanicalScanContext — shared M1/M6 detector inventory", (d) => new MechanicalScanContext(d).dispose()],
  ["scan/codebase-size.ts measureCodebaseSize — quick-scan pricing + the run-audit orchestrator (fixed #1455; standing regression)", (d) => measureCodebaseSize(d)],
  ["detectors/load-sources.ts loadSources — the shared loader for M5/M6/M7/M8/M9 and the M1 AST tier", (d) => loadSources(d)],
  ["detectors/asset-weight.ts scanAssetWeight — M7", (d) => scanAssetWeight(d)],
  ["scan/scan-scope.ts resolveScanScope — every module's scratch copy, non-git (zip-export) target", (d) => resolveScanScope(d).cleanup()],
  ["scan/webext-manifest.ts checkWebExtensionManifest — M1", (d) => checkWebExtensionManifest(d)],
  ["scan/dep-reachability.ts annotateCveReachability — M1 CVE ranking", (d) => annotateCveReachability([CVE_FINDING], d, new Set(["next"]))],
  ["scan/ext-coverage.ts checkUnreadSourceExtensions — M1-EXT-00", (d) => checkUnreadSourceExtensions(d, [])],
  ["scan/infra-scope.ts checkInfrastructureScope — INFRA-SCOPE-00", (d) => checkInfrastructureScope(d)],
  ["scan/language-coverage.ts checkUnanalysedLanguages — M1-LANG-00", (d) => checkUnanalysedLanguages(d)],
  ["scan/sfc-coverage.ts checkUnassessedSfcFiles — M1-SFC-00", (d) => checkUnassessedSfcFiles(d)],
  ["scan/supabase-static.ts inferAuthMethodsFromSource — M1 (names-only shape, no stat)", (d) => inferAuthMethodsFromSource(d)],
  ["scan/supabase-static.ts checkMigrationRlsStatic — M1 (names-only shape)", (d) => checkMigrationRlsStatic(d)],
  ["scan/supabase-static.ts checkMigrationPolicySemantics — M1 (names-only shape)", (d) => checkMigrationPolicySemantics(d)],
  ["scan/supabase-static.ts checkMigrationStorageBuckets — M1 (names-only shape)", (d) => checkMigrationStorageBuckets(d)],
  ["scan/supabase-static.ts checkUnreadSqlSurfaces — M1-SQL-SCOPE-00 (#1323)", (d) => checkUnreadSqlSurfaces(d)],
  ["scan/gha-permissions.ts checkWorkflowPermissions — M1 GITHUB_TOKEN scope (names-only shape)", (d) => checkWorkflowPermissions(d)],
  ["detectors/bundle-stats.ts parseViteBundleStats — M7 (names-only shape)", (d) => parseViteBundleStats(join(d, "dist"))],
  ["scan/secrets.ts isGitRepoRoot — M1 git-history secret pass (already safe via its own catch; routed through the guard so the ban has no exception)", (d) => isGitRepoRoot(d)],
];

describe("every walker survives a committed dangling symlink (#1451)", () => {
  for (const [name, run] of WALKERS) {
    it(name, () => {
      const dir = plantTarget();
      expect(() => run(dir)).not.toThrow();
    });
  }

  // The one MEASURED-reachable site with no importable entry point: simplify-scan is a top-level
  // script, and it is handed the ORIGINAL target directory (M6), so this crash was live.
  it("cli/simplify-scan.ts — M6, invoked on the original target dir", () => {
    const dir = plantTarget();
    expect(() =>
      execFileSync("./node_modules/.bin/tsx", ["src/cli/simplify-scan.ts", dir], { cwd: REPO_ROOT, encoding: "utf8", stdio: "pipe" }),
    ).not.toThrow();
  });
});

describe("M1-EXT-00 counts the links every walk now skips (#1451 residual)", () => {
  it("names a source-extension dangling link rather than letting it vanish between present and loaded", () => {
    const dir = plantTarget();
    const [finding] = checkUnreadSourceExtensions(dir, []);
    expect(finding?.evidence).toContain("committed symlink(s) with a source extension whose target does not resolve");
  });

  it("says nothing when the unresolvable links are not source-like", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-dangling-"));
    dirs.push(dir);
    writeFileSync(join(dir, "a.ts"), "export const a = 1;\n");
    symlinkSync("../nowhere", join(dir, ".env"));
    expect(checkUnreadSourceExtensions(dir, ["a.ts"])).toEqual([]);
  });
});

describe("the gate (#1451)", () => {
  it("reports every raw statSync call and points at the guard module", () => {
    const planted = [
      { path: "src/scan/new-detector.ts", text: "for (const e of readdirSync(d)) if (statSync(join(d, e)).isDirectory()) walk(e);\n" },
      { path: "src/scan/namespaced.ts", text: "if (fs.statSync(p).isFile()) read(p);\n" },
      // The shape with no statSync in it at all: names-only walk, then a read that throws.
      { path: "src/scan/names-only.ts", text: "for (const f of readdirSync(d)) if (f.endsWith('.sql')) readFileSync(join(d, f));\n" },
    ];
    const hits = findBannedStatSites(planted);
    expect(hits.map((h) => h.file)).toEqual([
      "src/scan/new-detector.ts", // readdirSync AND statSync on one line
      "src/scan/new-detector.ts",
      "src/scan/namespaced.ts",
      "src/scan/names-only.ts",
    ]);
  });

  it("does not fire on lstatSync, on a mention in a comment, or on the guard module itself", () => {
    const benign = [
      { path: "src/scan/a.ts", text: "if (lstatSync(p).isSymbolicLink()) skip(p);\n" },
      { path: "src/scan/b.ts", text: "// a bare statSync(p).isDirectory() throws on a dangling link\nconst s = \"statSync(x)\";\n" },
      { path: GUARD_MODULE, text: "export const s = statSync(p, { throwIfNoEntry: false });\n" },
    ];
    expect(findBannedStatSites(benign)).toEqual([]);
  });

  it("holds over the real tree, and the tree it swept is not empty", () => {
    const paths = discoverSourceFiles(REPO_ROOT);
    expect(paths.length).toBeGreaterThan(100);
    expect(paths).toContain(GUARD_MODULE);
    expect(findBannedStatSites(readSourceFiles(REPO_ROOT, paths))).toEqual([]);
  });

  it("bans the tokens it says it bans, and not lstatSync", () => {
    expect([...BANNED]).toEqual(["statSync", "readdirSync"]);
  });
});
