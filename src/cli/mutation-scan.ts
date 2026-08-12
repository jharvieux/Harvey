// M8 mutation scan — runs StrykerJS against a target repo and shapes its JSON reporter
// output into the summary shape docs/m8-test-quality.md documents (mutation score overall +
// per module, ranked surviving-mutant list).
//
// StrykerJS is an EXTERNAL CLI TOOL, not an npm dependency of this repo. The wrapper prefers the
// target's own node_modules/.bin/stryker, falling back to PATH; it throws if neither exists.
//
// Config (#513): a target that ships its own Stryker config (`stryker.conf.json/.mjs/...`) is run
// under it (the config SHOULD set `coverageAnalysis: "perTest"` and enable the `json` reporter —
// a JSON config missing perTest draws a warning). A target with a suite but NO config — most
// third-party clients — gets a minimal config SCAFFOLDED for its detected test runner
// (vitest/jest/mocha) into an off-tree temp dir. When the Stryker packages are absent too, they
// are installed into the target via `npm install --no-save` ONLY under --install (an implicit
// install runs package lifecycle scripts inside a client repo — operator consent, not a default);
// without --install the run degrades loudly, naming the exact command. The M8 degradation ladder
// (full mutation → --stub-check deletion survival → detect-static test-intent → M8-00) is always
// stated in the machine-readable moduleRecord — a lower rung is recorded, never a silent drop.
//
// Env (#503): the wrapper detects the test env the target declares (TZ/LANG/LC_ALL in its runner
// config/setup, test script, or CI workflow) and replicates it when invoking Stryker/stub-check.
// A failed initial dry run — the suite failing unmutated — is surfaced as its own verdict (M8-03
// finding + partial moduleRecord), never a generic void.
//
// Scope (#504): the report's covered file set is verified against the configured mutate globs;
// a scoped subset run emits a partial moduleRecord alongside its summary so it can never be
// recorded as the module's measurement.
//
//   pnpm mutation-scan <target-dir> [--config <path>] [--concurrency <n>] [--incremental]
//                       [--report <path>] [--hotspots <file>] [--out <file>] [--install]
//                       [--stub-check [--test-cmd "<cmd>"]] [--detect-only]
//
// --detect-only (#470) runs ONLY the suite-absent detection (#224/#252) and never invokes
// Stryker: if the target has no meaningful suite it emits the M8-00 zero-coverage finding
// exactly as a full run would; if a suite is present it writes an empty findings array and
// says so on stderr. This is what corpus-drift.ts calls — that job deliberately does not
// provision a Stryker install (mutation scoring is corpus-m8.yml's job), and before this flag
// it crashed mid-run on "stryker binary not found" for every target with a real suite.
//
// --stub-check (#373) runs the fast pre-Stryker deletion-survival pass INSTEAD of Stryker:
// each covered exported function is stubbed to `return undefined`, the covering test files are
// re-run via --test-cmd (default `npm test --`, which gets the covering test paths appended),
// and a suite that still passes yields an M8-01-* finding (src/stub-check.ts). O(exported
// functions) suite runs, no Stryker install needed.
//
// #600: for --stub-check ONLY, the mutation happens on a DISPOSABLE COPY of the target (node_modules
// symlinked in, not copied), never on the live checkout — a target's own tree is never opened for
// writing, so a SIGTERM/SIGKILL/timeout mid-run cannot leave it stubbed (a real engagement did: a
// killed run left AoP's reporting.ts stubbed in the operator's checkout). This is crash-safe by
// construction, not by a try/finally racing a signal — a signal handler can't run cleanup code
// while the process is blocked inside a synchronous child-process wait, and nothing can run at
// all after SIGKILL.
//
// #1285: a FULL mutation run (no --stub-check) is covered too, by a different mechanism. It still
// invokes Stryker with `cwd: targetDir` — the target's own suite has to run from its own tree — but
// every location Stryker writes to is REDIRECTED off-tree first: `tempDirName` (mutant sandboxes),
// `jsonReporter.fileName` (the JSON report) and `incrementalFile` are rewritten to absolute paths
// under a temp dir, in a COPY of whichever config is about to run (never the target's own file).
// Stryker honours an absolute value for all three — MEASURED, see withOffTreeScratch in
// src/mutation-scan.ts for the two-run control/treatment and the exact commands. Ordinarily no
// copy of the target is made: Stryker already copies the project into its sandbox on every run
// (Harvey never sets `inPlace`), so this moves an existing copy rather than adding one — EXCEPT the
// #773 TS7 tsconfig-chain fix below, which does stage its own disposable copy (stageTs7TsconfigFix)
// because getting a rewritten file into Stryker's sandbox means it has to already be on disk at the
// path Stryker copies from, and #1285 forbids writing that into the target itself.
//
// The redirect only reaches what STRYKER writes. #819's line-coverage pass runs the target's OWN
// test runner, whose caches no Stryker option can move (MEASURED: boxyhq's next/jest writes
// `.swc/plugins/<platform>/`), so that rung uses #600's other mechanism instead — a disposable copy
// with node_modules mirrored in.
//
// Enforced, not merely stated: assertTreePristine below snapshots every path under the target
// (and, for a #655 root-scoped run, under the workspace root) before Stryker is invoked, re-checks
// straight after it, and re-checks once more after the coverage pass — throwing
// `#1285 invariant violated` on a path added, removed, or changed in size/mtime, and on any source
// file whose bytes moved. That is the same invariant #600 already ran for --stub-check, widened
// from --stub-check to every Stryker rung and from content drift to the whole tree.
//
// The one config shape this cannot cover is a target-owned NON-JSON Stryker config
// (stryker.conf.mjs/.js/.cjs): reading it means executing code out of the target, which this CLI
// never does (same boundary #773's bypass draws). That degrades loudly, naming the remedy, rather
// than running Stryker into the client's tree.
//
// --report points at the mutation.json Stryker already wrote (skips re-running Stryker — use
// this to shape a report from a prior run). Without --report, this invokes `stryker run` and
// reads the json report back from the off-tree path #1285 redirected it to.
// --hotspots points at a text file, one repo-relative path per line (e.g. the M3 hotspot file
// list), used to flag surviving mutants that sit on a security/perf hotspot as top priority.
//
// TS7 (#773): TypeScript 7's native/Go rewrite broke Stryker's own sandbox tsconfig preprocessor
// (it calls the classic compiler API, which TS7's restructured package no longer exports) — every
// Stryker run against a TS7 target used to crash with no report written. Detected proactively from
// the installed `typescript/package.json` and worked around by patching a COPY of whichever Stryker
// config is about to run (see src/mutation-scan.ts's TS7_TSCONFIG_BYPASS_FILENAME comment); a
// non-JSON target config that can't be safely patched, or a crash the proactive check missed,
// degrades to a precise partial verdict naming the incompatibility instead of an opaque failure.
// Bypassing the preprocessor also disables its REAL job (rewriting a tsconfig `extends`/`references`
// chain that reaches outside the sandboxed dir — the standard monorepo shape) — MEASURED live
// against a real TS7 target: the bypass alone stops the crash but the target's own test-runner
// transform pipeline then fails with "Tsconfig not found". stageTs7TsconfigFix replicates that
// rewrite (planTsconfigRewrites, in src/mutation-scan.ts) in a disposable copy of the target, and
// Stryker runs against the copy instead of the target itself whenever there's something to rewrite.

import "./sync-stdio.js";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { isDirectorySafe, readEntriesSafe, statSafe, type SafeDirEntry } from "../fs-walk.js";
import type { SourceInput } from "../detectors/common.js";
import { detectPackageManager, installExtraCommand, withRestoredManifest } from "../package-manager.js";
import { discoverTargets } from "../pentest/targets.js";
import { digestObservedPaths, writeCorpusScannerScope } from "../corpus-scanner-scope.js";
import { runStubCheck, stubSurvivalFindings, type StubTestRunner } from "../stub-check.js";
import { mirrorNodeModules } from "../stub-worktree.js";
import {
  coveredScopeLine,
  detectDryRunFailure,
  detectNoTestSuite,
  detectRootWorkspaceTestSuite,
  detectTestEnv,
  detectTestRunner,
  detectTs7TsconfigCrash,
  detectWorkspaceTestSuites,
  dryRunFailureFinding,
  dryRunFailureModuleRecord,
  isIncompatibleTypeScript7,
  mutationNotRunModuleRecord,
  noTestSuiteFinding,
  noTestSuiteModuleRecord,
  planTsconfigRewrites,
  reRootReportToApp,
  resolveJsonReporterPath,
  rootScopedMutateGlobs,
  rootWorkspaceTestFinding,
  rootWorkspaceTestModuleRecord,
  SCAFFOLD_SOURCE_DIRS,
  scaffoldStrykerConfig,
  scopedRunModuleRecord,
  noCoverageFindings,
  stubCheckBaselineModuleRecord,
  summarizeLineCoverage,
  summarizeMutationReport,
  strykerPhaseDurations,
  survivingMutantFindings,
  toReportRows,
  unverifiableScopeModuleRecord,
  vacuousTestFindings,
  verifyMutationScope,
  withOffTreeScratch,
  withTs7TsconfigBypass,
  workspaceTestSuiteFinding,
  workspaceTestSuiteModuleRecord,
  type AncestorTestSignals,
  type DetectedEnvVar,
  type IstanbulCoverageSummary,
  type PackageJsonForTestDetection,
  type StrykerReport,
} from "../mutation-scan.js";

const args = process.argv.slice(2);

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

// Positional target-dir: the first bare token, expected before any flags (matches
// src/cli/quality-scan.ts's convention — usage is always `<target-dir> [--flags...]`).
const targetArg = args.find((a) => !a.startsWith("--"));

if (!targetArg) {
  console.error("usage: pnpm mutation-scan <target-dir> [--config <path>] [--concurrency <n>] [--incremental] [--report <path>] [--hotspots <file>] [--out <file>] [--install] [--stub-check [--test-cmd \"<cmd>\"]] [--detect-only]");
  process.exit(2);
}

const targetDir = resolve(targetArg);
const stubCheck = process.argv.includes("--stub-check");
const detectOnly = process.argv.includes("--detect-only");
// #655: mutable — a successful root-scoped run (see attemptRootScopedRun below) redirects these to
// its own re-rooted report + reference config so the rest of the file's normal report-shaping path
// (report reading, scope verification, findings) runs unchanged, as if this were an ordinary
// per-app --report/--config invocation.
let configPath = arg("--config");
const concurrency = arg("--concurrency");
const incremental = process.argv.includes("--incremental");
let reportPath = arg("--report");
const hotspotsPath = arg("--hotspots");
const outPath = arg("--out");
const scopeOutPath = arg("--scope-out");
// #819: where/whose package.json the line-coverage tool run should invoke — the target itself for
// an ordinary per-app run, redirected to the workspace root by a successful #655 root-scoped run
// below (the same case where reportPath/configPath are redirected).
let coverageCwd = targetDir;
const install = process.argv.includes("--install");

function warnIfNotPerTest(cfgPath: string): void {
  if (!cfgPath.endsWith(".json")) return; // .mjs/.cjs configs aren't statically inspectable here
  try {
    const cfg = JSON.parse(readFileSync(cfgPath, "utf8")) as { coverageAnalysis?: string };
    if (cfg.coverageAnalysis !== "perTest") {
      console.error(`⚠ ${cfgPath}: coverageAnalysis is "${cfg.coverageAnalysis ?? "unset"}", expected "perTest" — this scan will be slower and less precise than intended.`);
    }
  } catch {
    console.error(`⚠ could not read ${cfgPath} to verify coverageAnalysis`);
  }
}

const STRYKER_CONFIG_NAMES = ["stryker.conf.json", "stryker.conf.js", "stryker.conf.mjs", "stryker.conf.cjs", "stryker.config.json", "stryker.config.js", "stryker.config.mjs", "stryker.config.cjs"];

// #820: the json reporter's declared output path, read back from whichever JSON config actually
// ran (a non-JSON config can't be statically read here, same limitation as warnIfNotPerTest —
// falls back to Stryker's documented default rather than guessing).
function reporterFileNameFromConfig(cfgPath: string | undefined): string | undefined {
  if (!cfgPath || !cfgPath.endsWith(".json")) return undefined;
  try {
    return resolveJsonReporterPath(JSON.parse(readFileSync(cfgPath, "utf8")) as { jsonReporter?: { fileName?: string } });
  } catch {
    return undefined;
  }
}

// #820: fallback for when neither the config-declared nor Stryker's documented default path has a
// report — a Stryker major version can move where its json reporter writes by default. Walks `cwd`
// for a file with the expected basename, preferring the most-recently-modified match (a stale
// report from a prior run must never win over the one this invocation just produced). Excludes
// node_modules/.git only — unlike the rest of this CLI's walk, "reports" itself must stay in scope
// since that is exactly where the file usually lives.
const REPORT_SEARCH_EXCLUDED_DIR = /^(node_modules|\.git)$/;

function findReportByGlob(cwd: string, wantedBasename: string): string | undefined {
  const matches: { path: string; mtimeMs: number }[] = [];
  const walk = (dir: string) => {
    let entries: SafeDirEntry[];
    try {
      entries = readEntriesSafe(dir).entries;
    } catch {
      return;
    }
    for (const { name: entry, path: full, isDirectory } of entries) {
      if (isDirectory) {
        if (!REPORT_SEARCH_EXCLUDED_DIR.test(entry)) walk(full);
      } else if (entry === wantedBasename) {
        matches.push({ path: full, mtimeMs: statSafe(full)?.mtimeMs ?? 0 });
      }
    }
  };
  walk(cwd);
  return matches.sort((a, b) => b.mtimeMs - a.mtimeMs)[0]?.path;
}

// #820: resolves the actual report location for a completed Stryker run — the config-declared (or
// default) path first, falling back to a glob search of `cwd` when that exact path is absent (a
// Stryker version writing its json reporter's default somewhere else). Returns the config-declared
// path unchanged when nothing is found anywhere, so callers' existing "report not found at <path>"
// messaging still names the path they expected.
//
// #1285: `resolve`, not `join` — the config-declared fileName is now an ABSOLUTE off-tree path on
// every run this CLI drives (withOffTreeScratch), and `join(cwd, "/abs/path")` silently produces
// `<cwd>/abs/path`, which never exists. This is the producer→consumer seam the redirect has to
// survive; it is not enough for Stryker to write the report somewhere safe. `searchRoot` is where
// the #820 glob fallback looks — the off-tree scratch dir when the report was redirected there, so
// a run that wrote nothing can no longer resolve to a STALE in-tree report from a previous run.
function resolveReportPath(cfgPath: string | undefined, cwd: string, searchRoot: string = cwd): string {
  const expected = resolve(cwd, reporterFileNameFromConfig(cfgPath) ?? "reports/mutation/mutation.json");
  if (existsSync(expected)) return expected;
  const found = existsSync(searchRoot) ? findReportByGlob(searchRoot, basename(expected)) : undefined;
  if (found) {
    console.error(`#820: no report at the configured/default path ${expected} — found one at ${found} instead (Stryker version difference in the default reporter path)`);
    return found;
  }
  return expected;
}

function readPackageJsonAt(dir: string): PackageJsonForTestDetection | undefined {
  const pkgPath = join(dir, "package.json");
  if (!existsSync(pkgPath)) return undefined;
  try {
    return JSON.parse(readFileSync(pkgPath, "utf8")) as PackageJsonForTestDetection;
  } catch {
    return undefined;
  }
}

function readTargetPackageJson(): PackageJsonForTestDetection | undefined {
  return readPackageJsonAt(targetDir);
}

function readTypeScriptVersionAt(pkgPath: string): string | undefined {
  if (!existsSync(pkgPath)) return undefined;
  try {
    return (JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: string }).version;
  } catch {
    return undefined;
  }
}

// #1818: resolve TypeScript from STRYKER CORE'S physical module location, not merely from the
// directory Stryker is invoked in. pnpm can link an app-local `.bin/stryker` to core in the
// workspace root; when the app also has its own TypeScript version, `app/node_modules/typescript`
// and Stryker's dynamic `import("typescript")` are then different packages. Saas-Lite exposed the
// consequence: the former was 5.9 while core imported 7.0 and still crashed in
// parseConfigFileTextToJson. Resolving core first mirrors Node's lookup boundary without importing
// or executing any target code. The direct path remains a fallback for PATH-provided/fake binaries.
function readStrykerTypeScriptVersion(dir: string): string | undefined {
  try {
    const fromTarget = createRequire(join(dir, "package.json"));
    const coreEntry = fromTarget.resolve("@stryker-mutator/core");
    const fromCore = createRequire(coreEntry);
    return readTypeScriptVersionAt(fromCore.resolve("typescript/package.json"));
  } catch {
    return readTypeScriptVersionAt(join(dir, "node_modules", "typescript", "package.json"));
  }
}

// #252: the census behind the suite-absent threshold — every test file in the tree
// (*.test.*/*.spec.* or under __tests__/), with text, so detectNoTestSuite can tell a harness
// with a meaningful suite from one with zero test files or a single placeholder spec.
const TEST_FILE = /(\.(test|spec)\.[cm]?[jt]sx?$)/;
const WALK_EXCLUDED_DIR = /^(node_modules|\.next|\.git|dist|build|coverage|out|reports|stryker-tmp)$/;

// One tree walk shared by every census below (test files, env sources, source paths) — they only
// differ in which relative paths they keep.
//
// #944: `statSync` FOLLOWS symlinks and throws ENOENT on a dangling one (committed routinely —
// liam-hq/liam's gitignored .env symlink, dub's EE LICENSE.md symlink, both real repos the #899
// breadth sweep crashed on). `readEntriesSafe(...).entries`'s Dirent classifies the
// entry ITSELF, not its resolved target, so `isSymbolicLink()` is safe to call on a dangling link;
// `existsSync` (which also follows the link but swallows ENOENT into `false`) is what actually
// tells dangling from resolvable. A dangling link is skipped outright — there is nothing to read.
// A resolvable symlink keeps the pre-#944 behavior (recurse if it resolves to a directory, else
// treat as a file) via one more `statSync`, now only reached once existence is confirmed.
function walkRelPaths(root: string): string[] {
  const paths: string[] = [];
  const walk = (dir: string) => {
    for (const { name, path: full, isDirectory } of readEntriesSafe(dir).entries) {
      if (isDirectory) {
        if (!WALK_EXCLUDED_DIR.test(name)) walk(full);
      } else {
        paths.push(relative(root, full).split(sep).join("/"));
      }
    }
  };
  walk(root);
  return paths;
}

const readRel = (root: string, rel: string): { path: string; text: string } => ({ path: rel, text: readFileSync(join(root, ...rel.split("/")), "utf8") });

// The cpSync filter shared by the two disposable-copy rungs (#600's stub-check, #1285's coverage
// pass): skip the same heavy/irrelevant directories walkRelPaths already skips. `existsSync` first
// because statSync throws on a dangling symlink, which real repos commit (#944).
const excludeHeavyDirs = (src: string): boolean => !(WALK_EXCLUDED_DIR.test(basename(src)) && isDirectorySafe(src));

// #773: planTsconfigRewrites is pure (fixture-testable), but ACTING on its plan means physically
// putting a rewritten tsconfig.json somewhere Stryker's own sandbox-copy step will read it from —
// and #1285 forbids writing into `dir` itself, even transiently, even restored after. So (same
// mechanism as #600/#819's other disposable copies) this stages a throwaway copy of `dir`, mirrors
// node_modules in rather than recopying it, writes the rewritten tsconfig(s) INTO the copy only,
// and hands back the copy's path for Stryker to run against instead of the real `dir`. Returns
// undefined when there is nothing to rewrite (no tsconfig.json, or its extends/references chain
// never leaves `dir`) — the ordinary in-place invocation is unaffected either way.
function stageTs7TsconfigFix(dir: string, label: string): string | undefined {
  if (!existsSync(join(dir, "tsconfig.json"))) return undefined;
  const rewrites = planTsconfigRewrites(dir, "tsconfig.json", (p) => (existsSync(p) ? readFileSync(p, "utf8") : undefined));
  if (rewrites.length === 0) return undefined;
  const runDir = mkdtempSync(join(tmpdir(), `harvey-stryker-ts7-copy-${label}-`));
  cpSync(dir, runDir, { recursive: true, filter: excludeHeavyDirs });
  if (existsSync(join(dir, "node_modules"))) mirrorNodeModules(dir, runDir);
  for (const r of rewrites) writeFileSync(join(runDir, relative(dir, r.path)), r.text);
  process.on("exit", () => rmSync(runDir, { recursive: true, force: true }));
  console.error(`#773: ${rewrites.length} tsconfig(s) under ${dir} reach outside it via extends/references — rewrote them to absolute paths in a disposable copy at ${runDir} (Stryker's own preprocessor would do this, but its TS7-incompatible compiler-API call is bypassed here) so the target's test-runner transform pipeline still resolves them post-sandbox`);
  return runDir;
}

// #1285: the tree census the pristine invariant compares. Deliberately NOT walkRelPaths: that walk
// excludes `reports` and `stryker-tmp` by name, which are exactly the two directories a Stryker run
// leaves behind — a snapshot built from it could never see the thing this invariant exists to
// catch. Only node_modules and .git are skipped here (an install rung legitimately writes the
// first, and neither is what "the client's checkout gained two directories" means). Directories are
// recorded as entries too, so an EMPTY leftover dir is still a violation.
const PRISTINE_WALK_EXCLUDED_DIR = /^(node_modules|\.git)$/;

// Path → a cheap identity stamp ("dir", or size:mtime for a file). Size+mtime rather than a content
// hash: the walk already stats each entry, and a tree the size of inbox-zero's apps/web would
// otherwise be read end-to-end twice per run. Source files get a real byte comparison on top
// (assertTreePristine below), so the stamp is the second line, not the only one.
function snapshotTreePaths(root: string): Map<string, string> {
  const paths = new Map<string, string>();
  const walk = (dir: string) => {
    for (const { name, path: full } of readEntriesSafe(dir).entries) {
      const st = statSafe(full);
      if (!st) continue; // a link that resolved during readEntriesSafe but not now
      const rel = relative(root, full).split(sep).join("/");
      paths.set(rel, st.isDirectory() ? "dir" : `${st.size}:${st.mtimeMs}`);
      if (st.isDirectory() && !PRISTINE_WALK_EXCLUDED_DIR.test(name)) walk(full);
    }
  };
  walk(root);
  return paths;
}

interface PristineSnapshot {
  root: string;
  paths: Map<string, string>;
  sources: SourceInput[];
}

function snapshotPristine(root: string, sources: SourceInput[]): PristineSnapshot {
  return { root, paths: snapshotTreePaths(root), sources };
}

// #600's acceptance check, widened by #1285 from --stub-check to every Stryker rung and from
// "did a source file's bytes change" to "did the tree gain ANY path". Throws — a scanner that
// wrote into a client's checkout and then reported success is the silent-omission shape this
// repo's coverage guard exists to prevent, and a wrong-but-loud exit is the lesser harm.
function assertTreePristine(before: PristineSnapshot, issueRef: string): void {
  for (const s of before.sources) {
    const now = readFileSync(join(before.root, ...s.path.split("/")), "utf8");
    if (now !== s.text) throw new Error(`${issueRef} invariant violated: ${s.path} in ${before.root} changed during the run — the target checkout is no longer pristine`);
  }
  const now = snapshotTreePaths(before.root);
  const drift = [
    ...[...now.keys()].filter((p) => !before.paths.has(p)).map((p) => `+${p}`),
    ...[...before.paths.keys()].filter((p) => !now.has(p)).map((p) => `-${p}`),
    ...[...now].filter(([p, stamp]) => before.paths.has(p) && before.paths.get(p) !== stamp).map(([p]) => `~${p}`),
  ].sort();
  if (drift.length) {
    throw new Error(`${issueRef} invariant violated: ${before.root} is no longer byte-identical — ${drift.length} path(s) added(+)/removed(-)/changed(~) during the run: ${drift.slice(0, 10).join(", ")}${drift.length > 10 ? ` (+${drift.length - 10} more)` : ""}`);
  }
}

// Every source file this CLI reads back for a byte-identity check or walks for #504 scope. One
// definition rather than three identical local regexes (#1285 needed a third).
const SOURCE_PATH = /\.([cm]?[jt]s|[jt]sx)$/;

const loadSourceFiles = (root: string): SourceInput[] => walkRelPaths(root).filter((p) => SOURCE_PATH.test(p)).map((rel) => readRel(root, rel));

// #1285: where every Stryker write goes instead of the target tree. Created lazily — a
// --detect-only/--report run never invokes Stryker and has nothing to redirect. `process.on("exit")`
// rather than a try/finally because this CLI's degrade rungs all leave through process.exit(), which
// terminates before a finally can unwind; a SIGKILL still leaks the dir, and that is deliberately
// the same trade #600 already accepts — what must never leak is a write into the client's checkout,
// which no signal can now cause because nothing is ever opened for writing there.
let strykerScratchRoot: string | undefined;
function scratchRoot(): string {
  if (!strykerScratchRoot) {
    // realpathSync, and it is load-bearing on macOS: os.tmpdir() returns /var/folders/..., which is
    // a SYMLINK to /private/var/folders/.... Stryker hands the sandboxed file's path to
    // `vitest --related`, whose module graph is keyed by real paths — an unresolved /var prefix
    // matches nothing there, and Stryker exits "No tests were executed" before running a mutant.
    // MEASURED 2026-07-28 against the pinned proposit clone: identical config under
    // /var/folders/... → "Vitest failed to find test files related to mutated files", the same
    // config under /private/var/folders/... → 100% (21/21). The old in-target sandbox never met
    // this because a path inside the target tree is already real.
    const root = realpathSync(mkdtempSync(join(tmpdir(), "harvey-stryker-scratch-")));
    strykerScratchRoot = root;
    process.on("exit", () => rmSync(root, { recursive: true, force: true }));
  }
  return strykerScratchRoot;
}

// #1285: the ONE Stryker write that is deliberately NOT under the per-run scratch dir. `--incremental`
// exists so a re-run after a client fixes findings only re-runs affected mutants (docs/m8-test-quality.md),
// which needs the file to outlive the run — so it gets a stable, target-keyed path under the OS temp
// dir. Off-tree either way; the cost of moving it out of the target is that an OS temp sweep (or a
// reboot) discards the incremental state, where the old in-target location survived one.
function incrementalFileFor(dir: string): string {
  return join(realpathSync(tmpdir()), "harvey-m8-incremental", `${basename(dir)}-${createHash("sha1").update(dir).digest("hex").slice(0, 16)}.json`);
}

// #1285: patch a COPY of whichever config is about to run so Stryker's three write locations point
// outside the target, and hand back where the report will land. `label` keeps a root-scoped run's
// scratch from colliding with the per-app one in the same process.
function redirectStrykerWritesOffTree(cfgPath: string | undefined, label: string, dir: string): { cfgPath: string; scratchRoot: string } | { blocked: string } {
  const cannotRedirect = (why: string): { blocked: string } => ({
    blocked: `M8 must never write into the target's own checkout (#1285), and ${why} — so Stryker's sandbox parent (tempDirName) and JSON report path cannot be redirected out of ${dir}. Re-run with --config pointing at a JSON copy of that config.`,
  });
  if (!cfgPath) return cannotRedirect("this run reached Stryker with no config file at all");
  if (!cfgPath.endsWith(".json")) {
    // Same boundary #773's bypass draws: reading a .mjs/.js/.cjs config means executing code out of
    // the target, which this scanner does not do.
    return cannotRedirect(`the Stryker config at ${cfgPath} is not JSON, so Harvey cannot read it without executing code out of the target`);
  }
  let cfg: Record<string, unknown>;
  try {
    cfg = JSON.parse(readFileSync(cfgPath, "utf8")) as Record<string, unknown>;
  } catch (err) {
    return cannotRedirect(`${cfgPath} could not be parsed as JSON (${(err as Error).message.slice(0, 200)})`);
  }
  const root = join(scratchRoot(), label);
  const paths = { tempDir: join(root, "stryker-tmp"), reportFile: join(root, "reports", "mutation", "mutation.json"), incrementalFile: incrementalFileFor(dir) };
  mkdirSync(root, { recursive: true });
  mkdirSync(dirname(paths.incrementalFile), { recursive: true });
  const redirectedPath = join(root, "stryker.offtree-scratch.config.json");
  writeFileSync(redirectedPath, JSON.stringify(withOffTreeScratch(cfg, paths), null, 2) + "\n");
  return { cfgPath: redirectedPath, scratchRoot: root };
}

function collectTestFiles(root: string): { path: string; text: string }[] {
  return walkRelPaths(root)
    .filter((p) => TEST_FILE.test(p.split("/").at(-1)!) || (/(^|\/)__tests__\//.test(p) && /\.[cm]?[jt]sx?$/.test(p)))
    .map((rel) => readRel(root, rel));
}

// #503: the files a target can declare its test env in, ordered most-authoritative-first for
// detectTestEnv's first-wins rule: test-runner config/setup files, then package.json's scripts,
// then CI workflows (where ATC's TZ lived — the env CI sets is why CI is green).
const RUNNER_CONFIG_FILE = /^(vitest|jest)\.(config|setup|workspace)\.[cm]?[jt]sx?$|^setupTests\.[cm]?[jt]sx?$/;

function collectEnvSourceFiles(root: string): { path: string; text: string }[] {
  const all = walkRelPaths(root);
  const runnerConfigs = all.filter((p) => RUNNER_CONFIG_FILE.test(p.split("/").at(-1)!)).map((rel) => readRel(root, rel));
  const scripts = readTargetPackageJson()?.scripts;
  const pkgScripts = scripts ? [{ path: "package.json (scripts)", text: JSON.stringify(scripts) }] : [];
  const workflows = all.filter((p) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(p)).map((rel) => readRel(root, rel));
  return [...runnerConfigs, ...pkgScripts, ...workflows];
}

// #623: a per-app invocation whose package.json has no test suite might still be an app in a
// workspace monorepo whose tests live at the ROOT (vitest workspace/projects, root test:* scripts).
// Walk the target's ancestors (bounded at the repo root) so detectRootWorkspaceTestSuite can tell
// "this app has no tests" from "this app's tests are run from the workspace root".
const VITEST_WORKSPACE_FILES = ["vitest.workspace.ts", "vitest.workspace.js", "vitest.workspace.mjs", "vitest.workspace.cjs", "vitest.workspace.json"];
const VITEST_CONFIG_FILES = ["vitest.config.ts", "vitest.config.js", "vitest.config.mjs", "vitest.config.cjs", "vite.config.ts", "vite.config.js", "vite.config.mjs"];
const VITEST_PROJECTS_KEY = /\b(?:projects|workspace)\s*:/;

function hasVitestWorkspaceConfig(dir: string): boolean {
  if (VITEST_WORKSPACE_FILES.some((f) => existsSync(join(dir, f)))) return true;
  for (const f of VITEST_CONFIG_FILES) {
    const p = join(dir, f);
    if (existsSync(p)) {
      try {
        if (VITEST_PROJECTS_KEY.test(readFileSync(p, "utf8"))) return true;
      } catch {
        /* unreadable config — no signal from it */
      }
    }
  }
  return false;
}

function collectAncestorSignals(dir: string): AncestorTestSignals[] {
  const out: AncestorTestSignals[] = [];
  let cur = resolve(dir);
  for (let i = 0; i < 12; i++) {
    const parent = dirname(cur);
    if (parent === cur) break;
    cur = parent;
    const pkgPath = join(cur, "package.json");
    let pkg: PackageJsonForTestDetection | undefined;
    if (existsSync(pkgPath)) {
      try {
        pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as PackageJsonForTestDetection;
      } catch {
        /* unparseable ancestor package.json — no signal from it */
      }
    }
    const hasGit = existsSync(join(cur, ".git"));
    out.push({
      dir: cur,
      pkg,
      hasPnpmWorkspaceYaml: existsSync(join(cur, "pnpm-workspace.yaml")) || existsSync(join(cur, "pnpm-workspace.yml")),
      hasVitestWorkspaceConfig: hasVitestWorkspaceConfig(cur),
      hasGit,
    });
    if (hasGit) break;
  }
  return out;
}

// #932: the inverse of collectAncestorSignals — a monorepo ROOT invoked directly whose own
// package.json has no test script/runner dep, while its own workspace CHILDREN carry the actual
// suites. discoverTargets' app enumeration already reads pnpm-workspace.yaml / package.json
// workspaces (the same glob walk quality-scan uses for per-workspace knip, #505); it falls back to
// [targetDir] itself when there's no workspace manifest, so filtering that self-entry out here
// leaves an empty list for a genuine single-package target — no false positive.
function collectWorkspaceSignals(dir: string): { path: string; pkg?: PackageJsonForTestDetection }[] {
  return discoverTargets(dir)
    .apps.map((a) => a.path)
    .filter((p) => resolve(p) !== resolve(dir))
    .map((p) => ({ path: relative(dir, p), pkg: readPackageJsonAt(p) }));
}

// #503: replicate the test env the target itself declares (TZ/LANG/LC_ALL from its runner config,
// test script, or CI workflow) when running its suite — under the audit machine's ambient env an
// env-fragile suite fails its dry run and M8 voids. Applies to stub-check, ordinary Stryker runs,
// and the root-scoped run below — computed here (ahead of the no-test-suite check) because the
// root-scoped attempt needs it before that check has finished.
const detectedEnv: DetectedEnvVar[] = detectTestEnv(collectEnvSourceFiles(targetDir));
const suiteEnv = { ...process.env, ...Object.fromEntries(detectedEnv.map((e) => [e.key, e.value])) };
if (detectedEnv.length) {
  console.error(`replicating target-declared test env (#503): ${detectedEnv.map((e) => `${e.key}=${e.value} (from ${e.source})`).join(", ")}`);
}

// #655: given a detected workspace-root suite, try to actually MEASURE this app by invoking the
// root's own runner with mutate globs scoped to this app — the #623 gap disclosure is the fallback
// when that isn't possible, not the only outcome. Never called under --detect-only (which must
// never invoke Stryker, #470) or --stub-check (a different, non-Stryker measurement tier).
function attemptRootScopedRun(rootSuite: { root: string; reason: string }, ancestors: AncestorTestSignals[]): { reportPath: string; refConfigPath: string } | { degradeReason: string } {
  const rootPkg = ancestors.find((a) => a.dir === rootSuite.root)?.pkg;
  const runner = detectTestRunner(rootPkg);
  if (!runner) return { degradeReason: `no recognized test runner (vitest/jest/mocha) detected in the root package.json at ${rootSuite.root} to scaffold a Stryker config for` };

  const presentDirs = SCAFFOLD_SOURCE_DIRS.filter((d) => existsSync(join(targetDir, d)));
  if (presentDirs.length === 0) return { degradeReason: `no recognized source directory (${SCAFFOLD_SOURCE_DIRS.join(", ")}) under ${targetDir} to scope root-scoped mutate globs to` };

  const missingPkgs = ["@stryker-mutator/core", runner.plugin].filter((p) => !existsSync(join(rootSuite.root, "node_modules", ...p.split("/"))));
  // #1284/#1268: the package manager the ROOT's own lockfile implies, not a hardcoded npm — see
  // src/package-manager.ts's header for why npm was never a safe default for a pnpm/yarn tree.
  const rootPm = detectPackageManager(rootSuite.root);
  if (missingPkgs.length && !install) {
    const { bin, args } = installExtraCommand(rootPm, missingPkgs);
    return { degradeReason: `the workspace root has a ${runner.runner} suite but no Stryker install there (${missingPkgs.join(", ")} missing) — re-run with --install to provision them at the root via \`${bin} ${args.join(" ")}\` and measure this app via a root-scoped run` };
  }
  if (missingPkgs.length) {
    const { bin, args } = installExtraCommand(rootPm, missingPkgs);
    console.error(`#655/#1284: installing ${missingPkgs.join(" + ")} into the workspace root ${rootSuite.root} (${bin} ${args.join(" ")})...`);
    try {
      withRestoredManifest(rootSuite.root, rootPm, () => execFileSync(bin, args, { cwd: rootSuite.root, stdio: ["ignore", "inherit", "inherit"] }));
    } catch (err) {
      return { degradeReason: `could not install ${missingPkgs.join(" + ")} at the workspace root (${bin} ${args.join(" ")} failed: ${(err as Error).message.slice(0, 200)})` };
    }
  }

  const appCfg = scaffoldStrykerConfig(runner.runner, presentDirs);
  const appRelFromRoot = relative(rootSuite.root, targetDir).split(sep).join("/");
  const rootCfg = { ...appCfg, mutate: rootScopedMutateGlobs(appRelFromRoot, (appCfg.mutate as string[] | undefined) ?? []) };

  // #773: the reference config (rootCfg's mutate globs are read back from this for #504 scope
  // verification, not passed to Stryker) stays UNpatched — only the config Stryker actually runs
  // needs the bypass.
  const tsVersion = readStrykerTypeScriptVersion(rootSuite.root);
  const ts7 = isIncompatibleTypeScript7(tsVersion);
  const rootCfgForStryker = ts7 ? withTs7TsconfigBypass(rootCfg) : rootCfg;
  // #773: a TS7 root whose tsconfig chain reaches outside rootSuite.root needs Harvey's own
  // preprocessor replacement staged BEFORE Stryker runs — see stageTs7TsconfigFix. Falls back to
  // rootSuite.root itself (the ordinary, unmodified path) when there's nothing to rewrite.
  const runCwd = (ts7 && stageTs7TsconfigFix(rootSuite.root, "root-scoped")) || rootSuite.root;

  const scaffoldDir = mkdtempSync(join(tmpdir(), "harvey-stryker-root-scaffold-"));
  const rootCfgPath = join(scaffoldDir, "stryker.root.config.json");
  const refCfgPath = join(scaffoldDir, "stryker.app-reference.config.json");
  writeFileSync(rootCfgPath, JSON.stringify(rootCfgForStryker, null, 2) + "\n");
  writeFileSync(refCfgPath, JSON.stringify(appCfg, null, 2) + "\n");
  console.error(`#655: root-scoped mutation run — invoking the ${runner.runner} suite at ${rootSuite.root} (${rootSuite.reason}), mutate scoped to ${appRelFromRoot} (${JSON.stringify(rootCfg.mutate)})`);
  if (ts7) {
    console.error(`#773: workspace root TypeScript is v${tsVersion} — bypassing Stryker's incompatible tsconfig preprocessor for this root-scoped run`);
  }

  // #1285: the root-scoped rung writes into the WORKSPACE ROOT, not the app dir — same redirect,
  // same invariant, a different tree to keep pristine.
  const redirect = redirectStrykerWritesOffTree(rootCfgPath, "root-scoped", rootSuite.root);
  if ("blocked" in redirect) return { degradeReason: redirect.blocked };
  const pristineRoot = snapshotPristine(rootSuite.root, loadSourceFiles(rootSuite.root));

  // Package directories existing (checked above) doesn't guarantee node_modules/.bin/stryker was
  // hoisted there too — pnpm workspace hoisting can differ from a plain npm install's layout — so
  // this still degrades rather than lets runStryker's ENOENT throw crash the whole CLI.
  let run: { dryRunFailure?: string; ts7Crash?: boolean };
  try {
    run = runStryker(redirect.cfgPath, runCwd);
  } catch (err) {
    assertTreePristine(pristineRoot, "#1285");
    return { degradeReason: (err as Error).message };
  }
  assertTreePristine(pristineRoot, "#1285");
  if (run.dryRunFailure) return { degradeReason: `root-scoped Stryker's initial dry run failed: ${run.dryRunFailure}` };
  if (run.ts7Crash) {
    return { degradeReason: `root-scoped Stryker crashed with the known Stryker/TypeScript-7 tsconfig-preprocessor incompatibility signature (#773: "parseConfigFileTextToJson is not a function") — a tooling gap, not a defect in the target` };
  }

  const rawReportPath = resolveReportPath(redirect.cfgPath, rootSuite.root, redirect.scratchRoot);
  if (!existsSync(rawReportPath)) return { degradeReason: `root-scoped Stryker run produced no report at ${rawReportPath} (see the Stryker output above)` };

  const rawReport = JSON.parse(readFileSync(rawReportPath, "utf8")) as StrykerReport;
  const { report, dropped } = reRootReportToApp(rawReport, appRelFromRoot);
  if (dropped.length) {
    console.error(`⚠ #655: ${dropped.length} mutated file(s) from the root run fell outside ${appRelFromRoot} and were dropped from this app's measurement (e.g. ${dropped.slice(0, 3).join(", ")}) — should not happen when mutate globs are scoped correctly`);
  }
  if (Object.keys(report.files).length === 0) {
    return { degradeReason: `root-scoped Stryker run covered zero files under ${appRelFromRoot} (${dropped.length} file(s) reported, all outside the app's scope)` };
  }

  const reRootedReportPath = join(scaffoldDir, "mutation.app-scoped.json");
  writeFileSync(reRootedReportPath, JSON.stringify(report, null, 2) + "\n");
  return { reportPath: reRootedReportPath, refConfigPath: refCfgPath };
}

// #224: no test script / no known test-runner dep / no Stryker config means Stryker literally
// can't run here — that's itself a High-severity M8 finding (zero automated coverage on a
// codebase in an audit's scope), not a wrapper failure. Report it and mark M8 coverage partial
// instead of falling through to runStryker()'s "binary not found"-shaped error. #252 widens the
// same finding to a harness with no meaningful suite: zero test files, or one placeholder spec.
if (!reportPath) {
  const hasStrykerConfig = configPath ? existsSync(resolve(configPath)) : STRYKER_CONFIG_NAMES.some((f) => existsSync(join(targetDir, f)));
  const detectOnlyTestFiles = collectTestFiles(targetDir);
  const targetPackageManifest = readTargetPackageJson();
  let ancestorWorkspaceSuite: string | null = null;
  let childWorkspaceSuites: string[] = [];
  const emitDetectOnlyScope = (zeroTestDisposition?: {
    status: "no-suite" | "not-applicable";
    reason: string;
    provenance: string;
    falsifier: string;
  }): void => writeCorpusScannerScope(scopeOutPath, "mutation-detect-only", {
    unitsExamined: detectOnlyTestFiles.length,
    description: detectOnlyTestFiles.length > 0
      ? `${detectOnlyTestFiles.length} test source file(s) opened by mutation detect-only suite detection`
      : "package/config suite-presence signals examined by mutation detect-only (zero test source files found)",
    observation: {
      scanner: "mutation-detect-only",
      testSources: {
        count: detectOnlyTestFiles.length,
        pathsDigest: digestObservedPaths(detectOnlyTestFiles.map((file) => file.path)),
      },
      suiteSignals: {
        packageManifest: targetPackageManifest !== undefined,
        strykerConfig: hasStrykerConfig,
        ancestorWorkspaceSuite,
        childWorkspaceSuites,
      },
      ...(detectOnlyTestFiles.length === 0 ? { zeroTestDisposition } : {}),
    },
  });
  const { missing, reason } = detectNoTestSuite(targetPackageManifest, hasStrykerConfig, detectOnlyTestFiles);
  if (missing) {
    // #623: before declaring suite-absent, check whether the target is an app whose tests live at
    // a monorepo root — a false "no test suite" on a well-tested app reads as zero coverage.
    const ancestors = collectAncestorSignals(targetDir);
    const rootSuite = detectRootWorkspaceTestSuite(ancestors);
    if (rootSuite) {
      ancestorWorkspaceSuite = rootSuite.reason;
      // #655: attempt a real root-scoped measurement — but never under --detect-only (must never
      // invoke Stryker) or --stub-check (a distinct, non-Stryker measurement tier).
      const attempt = !detectOnly && !stubCheck ? attemptRootScopedRun(rootSuite, ancestors) : undefined;
      if (attempt && "reportPath" in attempt) {
        console.error(`✓ ${targetDir}: measured via a root-scoped mutation run at ${rootSuite.root} (#655) — an app-scoped measurement, not the #623 gap disclosure.`);
        reportPath = attempt.reportPath;
        configPath = attempt.refConfigPath;
        coverageCwd = rootSuite.root; // #819: the runnable suite lives at the root, not this app
      } else {
        const why = attempt ? ` — attempted a root-scoped run but could not complete it (${attempt.degradeReason})` : "";
        console.error(`✗ ${targetDir}: no per-app test suite, but a workspace-ROOT suite exists at ${rootSuite.root} (${rootSuite.reason}) — measurement gap, not 'no test suite' (#623)${why}.`);
        console.error(`M8 coverage: partial (root-workspace suite not reachable per-app, #623) — emitting the measurement-gap finding instead of M8-00.`);
        // #655: an attempted-and-failed root-scoped run gets its reason folded into the
        // machine-readable note too, not just stderr — this repo's doctrine is "say so in the
        // OUTPUT", and a client report only ever sees the artifact, never this process's stderr.
        const baseRecord = rootWorkspaceTestModuleRecord(rootSuite);
        const moduleRecord = attempt
          ? { ...baseRecord, note: `${baseRecord.note} Attempted a root-scoped run (#655) but could not complete it: ${attempt.degradeReason}.` }
          : baseRecord;
        const output = { finding: rootWorkspaceTestFinding(rootSuite), moduleRecord };
        const json = JSON.stringify(output, null, 2);
        if (outPath) {
          writeFileSync(outPath, json + "\n");
          console.error(`wrote M8 finding to ${outPath}`);
        } else {
          console.log(json);
        }
        if (detectOnly) emitDetectOnlyScope();
        process.exit(0);
      }
    } else {
      // #932: the inverse of #623 — this target has no ancestor-root suite covering it, but it
      // may ITSELF be a monorepo root whose test scripts/runner deps live in its own workspaces
      // (documenso: root has neither, packages/lib declares `"test": "vitest run"`, 128 tracked
      // spec files). Checked here, not before detectRootWorkspaceTestSuite, so a target that's
      // both (unusual, but not impossible) reports the ancestor-root gap first.
      const workspaceSuites = detectWorkspaceTestSuites(collectWorkspaceSignals(targetDir));
      if (workspaceSuites.length) {
        childWorkspaceSuites = workspaceSuites.map((suite) => suite.path).sort();
        console.error(`✗ ${targetDir}: no root-level test suite, but ${workspaceSuites.length} workspace(s) carry their own (e.g. ${workspaceSuites[0]!.path}) — measurement gap, not 'no test suite' (#932).`);
        console.error(`M8 coverage: partial (workspace test suites not reachable from the root, #932) — emitting the measurement-gap finding instead of M8-00.`);
        const output = { finding: workspaceTestSuiteFinding(workspaceSuites), moduleRecord: workspaceTestSuiteModuleRecord(workspaceSuites) };
        const json = JSON.stringify(output, null, 2);
        if (outPath) {
          writeFileSync(outPath, json + "\n");
          console.error(`wrote M8 finding to ${outPath}`);
        } else {
          console.log(json);
        }
        if (detectOnly) emitDetectOnlyScope();
        process.exit(0);
      }
    }
  }
  if (missing && !reportPath) {
    const why = reason ?? "no automated test suite detected";
    console.error(`✗ ${targetDir}: no automated test suite detected (${why}) — mutation testing has nothing to run against.`);
    console.error(`M8 coverage: partial (no test suite) — emitting the "no automated test suite" finding instead.`);
    const output = { finding: noTestSuiteFinding(why), moduleRecord: noTestSuiteModuleRecord(why) };
    const json = JSON.stringify(output, null, 2);
    if (outPath) {
      writeFileSync(outPath, json + "\n");
      console.error(`wrote M8 finding to ${outPath}`);
    } else {
      console.log(json);
    }
    if (detectOnly) emitDetectOnlyScope({
      status: targetPackageManifest === undefined ? "not-applicable" : "no-suite",
      reason: why,
      provenance: "mutation-scan inspected package, Stryker, ancestor-workspace, child-workspace, and test-source suite signals",
      falsifier: "A discovered test source, Stryker configuration, ancestor suite, or child workspace suite invalidates this zero-unit observation",
    });
    process.exit(0);
  }

  if (detectOnly) {
    console.error(`✓ ${targetDir}: test suite detected — mutation scoring skipped (--detect-only; a real run needs a provisioned Stryker install)`);
    const json = "[]";
    if (outPath) writeFileSync(outPath, json + "\n");
    else console.log(json);
    emitDetectOnlyScope();
    process.exit(0);
  }
}

// #470: detect-only stops here when a suite IS present — the caller (corpus-drift) wants the
// suite-absent finding when it applies, never a Stryker invocation. An empty findings array,
// not silence: the caller can tell "suite present, mutation deferred" from a crashed run.
if (detectOnly) throw new Error("mutation detect-only reached a report-backed path without emitting its scanner-owned scope receipt");

// #373: the fast pre-Stryker deletion-survival pass. Everything below (Stryker invocation,
// report shaping) is bypassed — this mode's output is stub-check runs + M8-01 findings.
if (stubCheck) {
  // The test command is split into an argv (bin + base args) and NEVER goes through a shell:
  // covering-test paths below are walked out of the untrusted target, and a filename may legally
  // contain shell metacharacters (`x;curl evil|sh.test.ts`), so any shell-string exec here is
  // RCE on the auditor (#765). Whitespace-tokenizing a target- or operator-supplied string is safe
  // only because each token becomes a literal argv element — no token is ever shell-interpreted.
  const [testBin, ...testBaseArgs] = (arg("--test-cmd") ?? "npm test --").trim().split(/\s+/);
  if (!testBin) {
    console.error("--test-cmd is empty");
    process.exit(2);
  }

  // #600: copy the target into a scratch dir the stubbing writes to, excluding the same heavy/
  // irrelevant dirs walkRelPaths already skips (node_modules is symlinked back in below rather
  // than copied, so the target's real dependency install is reused without re-copying it).
  const copyDir = mkdtempSync(join(tmpdir(), "harvey-stub-check-"));
  const sources = loadSourceFiles(targetDir); // read from the ORIGINAL — read-only, and the copy is a byte-identical mirror
  const pristineBefore = snapshotPristine(targetDir, sources);
  // process.exit() does NOT run pending finally blocks (it terminates before the stack unwinds),
  // so the copyDir cleanup is a real try/finally and the exit happens AFTER it, not inside it.
  let stubJson: string;
  try {
    cpSync(targetDir, copyDir, { recursive: true, filter: excludeHeavyDirs });
    if (existsSync(join(targetDir, "node_modules"))) {
      // #607: mirror node_modules as a real dir, re-pointing workspace-package symlinks at the copy
      // so a stub in packages/* is honored across package boundaries instead of resolving to the
      // original (unstubbed) source through a wholesale node_modules symlink.
      const mirror = mirrorNodeModules(targetDir, copyDir);
      if (mirror.repointed.length) {
        console.error(`M8 stub-check: re-pointed ${mirror.repointed.length} workspace-package symlink(s) into the copy so cross-package stubs are honored (#607): ${mirror.repointed.slice(0, 5).join(", ")}${mirror.repointed.length > 5 ? " ..." : ""}`);
      }
      if (mirror.unresolvedWorkspacePkgs.length) {
        console.error(`⚠ ${mirror.unresolvedWorkspacePkgs.length} workspace-package symlink(s) could NOT be re-pointed (source not in the copy) — stubs in these resolve to ORIGINAL source and may be bypassed (#607): ${mirror.unresolvedWorkspacePkgs.join(", ")}`);
      }
    }
    console.error(`M8 stub-check: mutating a disposable copy at ${copyDir} — ${targetDir} is never opened for writing (#600)`);

    // In-place stub with backup/restore on the COPY. The finally here is about correctness
    // between iterations (the next stubbed export in the same file must start from unstubbed
    // text), not crash-safety — the target directory this could leak into was never written to
    // in the first place.
    const runner: StubTestRunner = (stub, tests) => {
      const copyAbs = join(copyDir, stub.file);
      const original = readFileSync(copyAbs, "utf8");
      writeFileSync(copyAbs, stub.stubbedText);
      try {
        execFileSync(testBin, [...testBaseArgs, ...tests], { cwd: copyDir, stdio: "ignore", env: suiteEnv });
        return true; // exit 0 with the body deleted — the suite survived
      } catch {
        return false;
      } finally {
        writeFileSync(copyAbs, original);
      }
    };

    // #1067: the baseline. `suitePassed` is true ONLY on exit 0, so every other outcome — a wrong
    // --test-cmd, deps missing from the scratch copy, an already-red suite, OOM — became `false`,
    // which stubSurvivalFindings reads as "the test caught the deletion". Without proof that the
    // suite passes UNMUTATED, wholesale execution failure is indistinguishable from a perfect test
    // suite, and this CLI printed the strongest possible test-quality result having measured
    // nothing. Stryker's own ladder already has this rung (dryRunFailureModuleRecord, #503); the
    // stub-check tier did not.
    const baseline = ((): { passed: boolean; detail: string } => {
      try {
        execFileSync(testBin, testBaseArgs, { cwd: copyDir, stdio: ["ignore", "ignore", "pipe"], env: suiteEnv });
        return { passed: true, detail: "" };
      } catch (err) {
        const e = err as { stderr?: Buffer; message?: string };
        const tail = e.stderr?.toString().trim().split("\n").slice(-4).join(" | ");
        return { passed: false, detail: tail || (e.message ?? "non-zero exit, no output") };
      }
    })();

    if (!baseline.passed) {
      console.error(`✗ M8 stub-check: the target suite FAILED its own UNMUTATED run under \`${[testBin, ...testBaseArgs].join(" ")}\` — nothing was measured. ${baseline.detail}`);
      stubJson = JSON.stringify({ runs: [], findings: [], baselineFailed: true, moduleRecord: stubCheckBaselineModuleRecord([testBin, ...testBaseArgs].join(" "), baseline.detail) }, null, 2);
    } else {
      const runs = runStubCheck(sources, runner);
      const findings = stubSurvivalFindings(runs);
      const checkedFiles = new Set(runs.map((r) => r.file)).size;
      console.error(`M8 stub-check: ${runs.length} exported function(s) stubbed across ${checkedFiles} covered file(s); ${findings.length} suite(s) survive deletion`);
      if (runs.length === 0) {
        console.error("⚠ no covered source files found (no test file imports or sits beside a source file) — nothing was checked; this is NOT a clean result");
      }
      // Recorded because it is the shape a broken invocation used to wear: with the baseline green
      // it means every deletion was caught, but the number belongs in the artifact either way.
      const allRunsFailed = runs.length > 0 && runs.every((r) => !r.suitePassed);
      if (allRunsFailed) console.error(`M8 stub-check: every one of the ${runs.length} stubbed run(s) failed its covering tests — the suite is green unmutated, so this reads as full deletion coverage.`);
      stubJson = JSON.stringify({ runs, findings, baselineFailed: false, allRunsFailed }, null, 2);
    }

    // #600 acceptance: prove the live checkout is still exactly what it was — fail loud (not a
    // silent pass) if anything under targetDir drifted from what was read at the start. #1285
    // moved this into a shared assertion (and added the new-path half) so the full-mutation rung
    // is held to the identical invariant rather than a second, weaker mechanism of its own.
    assertTreePristine(pristineBefore, "#600");
  } finally {
    // Best-effort: a killed process can't run this either, but that only leaks a scratch temp
    // dir — never the client's checkout, which this branch never wrote to.
    rmSync(copyDir, { recursive: true, force: true });
  }
  if (outPath) {
    writeFileSync(outPath, stubJson + "\n");
    console.error(`wrote stub-check results to ${outPath}`);
  } else {
    console.log(stubJson);
  }
  process.exit(0);
}

// Machine-readable partial verdicts (dry-run failure, degraded ladder rungs) exit 0 with the
// artifact — the same shape as the #224 no-suite branch, so the M8 probe reads the moduleRecord
// instead of a bare non-zero exit it could only record as a generic requires-live-run.
function emitAndExit(output: Record<string, unknown>, stderrNote: string): never {
  console.error(stderrNote);
  const json = JSON.stringify(output, null, 2);
  if (outPath) {
    writeFileSync(outPath, json + "\n");
    console.error(`wrote M8 artifact to ${outPath}`);
  } else {
    console.log(json);
  }
  process.exit(0);
}

// #503: Stryker's output is captured (then echoed) rather than streamed, so a failed initial dry
// run — the target's own suite failing unmutated, which writes NO report — can be recognized and
// surfaced as its own verdict instead of falling through to "mutation report not found".
// #655: `cwd` defaults to the target (the ordinary per-app invocation) but a root-scoped run
// passes the workspace root instead — Stryker itself, and the local-bin lookup below, both need to
// execute from wherever the config's `mutate` globs are relative to.
function runStryker(cfgPath: string | undefined, cwd: string = targetDir): { dryRunFailure?: string; ts7Crash?: boolean; phases?: { testBaselineMs: number; mutationMs: number } } {
  const strykerArgs = ["run"];
  if (cfgPath) strykerArgs.push(cfgPath);
  if (concurrency) strykerArgs.push("--concurrency", concurrency);
  if (incremental) strykerArgs.push("--incremental");

  if (cfgPath) warnIfNotPerTest(cfgPath);

  // Prefer the target's own install over PATH — clients that ship Stryker have it in
  // node_modules/.bin, not globally.
  const localBin = join(cwd, "node_modules", ".bin", "stryker");
  const strykerBin = existsSync(localBin) ? localBin : "stryker";
  try {
    // Stryker exits non-zero when the mutation score is under its configured break threshold —
    // that's not a wrapper failure, the report is still written; only a missing binary should throw.
    const stdout = execFileSync(strykerBin, strykerArgs, { cwd, encoding: "utf8", env: suiteEnv, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 });
    process.stderr.write(stdout);
    const phases = strykerPhaseDurations(stdout);
    return phases ? { phases } : {};
  } catch (err) {
    const e = err as { code?: string; stdout?: string; stderr?: string };
    if (e.code === "ENOENT") {
      throw new Error("stryker binary not found (neither node_modules/.bin/stryker in the target nor on PATH) — install @stryker-mutator/core in the target repo (see this file's header comment)");
    }
    const captured = `${e.stdout ?? ""}\n${e.stderr ?? ""}`;
    process.stderr.write(captured);
    const dryRun = detectDryRunFailure(captured);
    if (dryRun.failed) {
      const phases = strykerPhaseDurations(captured);
      return { dryRunFailure: dryRun.detail, ...(phases ? { phases } : {}) };
    }
    // #773: the reactive safety net — fires when the proactive TS7 bypass below wasn't applied
    // (non-JSON target config) or missed the incompatibility (TypeScript resolved from outside the
    // dir this tool checked). Caught by exact crash signature so this never falls through to the
    // opaque "mutation report not found" this incompatibility used to produce.
    if (detectTs7TsconfigCrash(captured)) {
      const phases = strykerPhaseDurations(captured);
      return { ts7Crash: true, ...(phases ? { phases } : {}) };
    }
    // Non-ENOENT, no dry-run failure: (likely) a break-threshold exit; fall through to read the report.
    const phases = strykerPhaseDurations(captured);
    return phases ? { phases } : {};
  }
}

// #819: the headline "coverage-vs-mutation-score gap" needs line coverage, which Stryker's own
// report never carries — this runs the target's OWN coverage-capable runner (vitest/jest, the same
// two #513 can scaffold Stryker for) with its json-summary reporter forced on, regardless of
// whatever reporter the target's own config names, so the output is always the one Istanbul schema
// summarizeLineCoverage reads. mocha has no built-in coverage (nyc/c8 wrapping is too client-
// specific to assume) and any undetected runner both degrade to a disclosed reason rather than a
// silently blank column — the 2026-07-23 amendment on #819.
interface LineCoverageResult {
  status: "ran" | "partial";
  byModule?: Record<string, number>;
  reason?: string;
}

function runLineCoverage(pkg: PackageJsonForTestDetection | undefined, cwd: string): LineCoverageResult {
  const runner = detectTestRunner(pkg);
  if (!runner) {
    return { status: "partial", reason: "no recognized test runner (vitest/jest/mocha) detected to invoke a coverage tool for" };
  }
  if (runner.runner === "mocha") {
    return { status: "partial", reason: "mocha has no built-in coverage tool (nyc/c8 wrapping is target-specific and was not auto-detected) — line coverage was not auto-pulled" };
  }

  const outDir = mkdtempSync(join(tmpdir(), "harvey-line-coverage-"));
  // #1285: this rung runs the TARGET'S OWN test runner, whose writes no Stryker config option can
  // redirect — MEASURED 2026-07-28 against the pinned boxyhq clone, where `next/jest --coverage`
  // creates `.swc/plugins/<platform>/` in its cwd and the #1285 invariant caught it. So this one
  // uses #600's mechanism rather than the redirect: the runner executes in a disposable copy with
  // node_modules mirrored back in, and whatever cache it drops lands there.
  //
  // The copy root is realpath'd, and that incidentally closes a live #819 defect: coverage keys come
  // back as REAL paths, and summarizeLineCoverage relativizes them against the root it is handed —
  // so a target reached through a symlinked path (every macOS temp clone: /var → /private/var)
  // produced module keys like `../../private/var/...`, matched no module row, and left the Line-cov
  // column blank while lineCoverage.status still read "ran". MEASURED 2026-07-28 on `main` against
  // the pinned boxyhq clone: same clone, `/var/...` path → row has no lineCoverage,
  // `/private/var/...` path → row has lineCoverage 66.7.
  const runDir = mkdtempSync(join(realpathSync(tmpdir()), "harvey-line-coverage-run-"));
  const localBin = join(cwd, "node_modules", ".bin", runner.runner);
  const bin = existsSync(localBin) ? localBin : runner.runner;
  const runArgs =
    runner.runner === "vitest"
      ? ["run", "--coverage", "--coverage.reporter=json-summary", `--coverage.reportsDirectory=${outDir}`]
      : ["--coverage", "--coverageReporters=json-summary", `--coverageDirectory=${outDir}`];

  const cleanUp = () => {
    rmSync(outDir, { recursive: true, force: true });
    rmSync(runDir, { recursive: true, force: true });
  };

  try {
    cpSync(cwd, runDir, { recursive: true, filter: excludeHeavyDirs });
    if (existsSync(join(cwd, "node_modules"))) mirrorNodeModules(cwd, runDir);
  } catch (err) {
    cleanUp();
    return { status: "partial", reason: `could not stage a disposable copy of ${cwd} to run the coverage tool in (#1285 forbids running it in the target's own tree): ${(err as Error).message.slice(0, 200)}` };
  }

  try {
    execFileSync(bin, runArgs, { cwd: runDir, env: suiteEnv, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 });
  } catch {
    // A suite with failing tests still often writes coverage before exiting non-zero (both vitest
    // and jest do) — only give up once the summary file itself is confirmed absent, below.
  }

  const summaryPath = join(outDir, "coverage-summary.json");
  if (!existsSync(summaryPath)) {
    cleanUp();
    return { status: "partial", reason: `${runner.runner} --coverage produced no coverage-summary.json (is a coverage provider like @vitest/coverage-v8 installed, and does the suite pass?)` };
  }
  try {
    const coverage = JSON.parse(readFileSync(summaryPath, "utf8")) as IstanbulCoverageSummary;
    // Keys are absolute paths inside the disposable copy, so that is the root they relativize
    // against — relativizing against targetDir here would leave every key an unrecognizable `../..`.
    return { status: "ran", byModule: summarizeLineCoverage(coverage, runDir) };
  } catch (err) {
    return { status: "partial", reason: `could not parse ${summaryPath}: ${(err as Error).message.slice(0, 200)}` };
  } finally {
    cleanUp();
  }
}

const defaultConfigPath = STRYKER_CONFIG_NAMES.map((f) => join(targetDir, f)).find(existsSync);
let effectiveConfigPath = configPath ? resolve(configPath) : defaultConfigPath;

function degradeExit(reason: string): never {
  emitAndExit(
    { moduleRecord: mutationNotRunModuleRecord(reason) },
    `✗ M8 mutation tier did not run: ${reason}\nM8 coverage: partial (degraded ladder rung, #513) — emitting the machine-readable verdict instead.`,
  );
}

// #773: proactive TS7 fix — applied right before the real Stryker invocation, so it covers all
// three ways a config path reaches this point (the target's own default config, --config, or the
// #513 scaffold). Returns the ORIGINAL path unchanged when TS7 isn't detected. When it is, a JSON
// config gets a patched COPY (never rewrites the target's own file); a non-JSON config can't be
// safely rewritten without executing arbitrary code from the target, so that degrades immediately
// instead of guaranteeing a crash a few lines later.
function applyTs7BypassIfNeeded(cfgPath: string | undefined, cwd: string): string | undefined {
  const tsVersion = readStrykerTypeScriptVersion(cwd);
  if (!cfgPath || !isIncompatibleTypeScript7(tsVersion)) return cfgPath;
  const incompatibility = `the target's installed TypeScript is v${tsVersion} — Stryker's core sandbox tsconfig preprocessor (ts.parseConfigFileTextToJson) requires the classic TypeScript compiler API, which TypeScript 7's native/Go rewrite no longer exports (#773); this is a known Stryker/TS7 tooling incompatibility, not a defect in the target`;
  if (!cfgPath.endsWith(".json")) {
    degradeExit(`${incompatibility}, and the Stryker config at ${cfgPath} is not JSON so Harvey cannot safely patch it to bypass the incompatibility`);
  }
  let cfg: Record<string, unknown>;
  try {
    cfg = JSON.parse(readFileSync(cfgPath, "utf8")) as Record<string, unknown>;
  } catch (err) {
    degradeExit(`${incompatibility}, and ${cfgPath} could not be read to patch around it (${(err as Error).message.slice(0, 200)})`);
  }
  const bypassDir = mkdtempSync(join(tmpdir(), "harvey-stryker-ts7-bypass-"));
  const bypassPath = join(bypassDir, "stryker.ts7-bypass.config.json");
  writeFileSync(bypassPath, JSON.stringify(withTs7TsconfigBypass(cfg), null, 2) + "\n");
  console.error(`#773: target TypeScript is v${tsVersion} — patched a copy of the Stryker config at ${bypassPath} so Stryker's tsconfig preprocessor no-ops instead of crashing on TS7's restructured compiler API`);
  return bypassPath;
}

// #513: no Stryker config anywhere — scaffold one for the target's detected test runner instead of
// requiring the client to have Stryker set up. The config goes to an off-tree temp dir; the
// packages, when missing, are installed --no-save ONLY under --install: an implicit `npm install`
// runs the packages' lifecycle scripts inside a client repo mid-audit, which needs operator
// consent, not a default (decision recorded on the issue). Without --install and without the
// packages, the ladder degrades loudly with the exact command to unlock the rung.
let scaffolded: { runner: string } | undefined;
if (!reportPath && !effectiveConfigPath) {
  const runner = detectTestRunner(readTargetPackageJson());
  if (!runner) {
    degradeExit("target has no Stryker config and no recognized test runner (vitest/jest/mocha) to scaffold one for");
  }
  const missingPkgs = ["@stryker-mutator/core", runner.plugin].filter((p) => !existsSync(join(targetDir, "node_modules", ...p.split("/"))));
  // #1284/#1268: the package manager the TARGET's own lockfile implies, not a hardcoded npm — a
  // pnpm-workspace target's `npm install --no-save` here resolved only root packages (or, for a
  // pnpm-catalog dependency, failed outright with EUNSUPPORTEDPROTOCOL).
  const targetPm = detectPackageManager(targetDir);
  if (missingPkgs.length && !install) {
    const { bin, args } = installExtraCommand(targetPm, missingPkgs);
    degradeExit(`the target has a ${runner.runner} suite but no Stryker install (${missingPkgs.join(", ")} missing) — re-run with --install to provision them into the target via \`${bin} ${args.join(" ")}\` and score mutation with a scaffolded config`);
  }
  if (missingPkgs.length) {
    const { bin, args } = installExtraCommand(targetPm, missingPkgs);
    console.error(`#513/#1284: installing ${missingPkgs.join(" + ")} into the target (${bin} ${args.join(" ")})...`);
    try {
      withRestoredManifest(targetDir, targetPm, () => execFileSync(bin, args, { cwd: targetDir, stdio: ["ignore", "inherit", "inherit"] }));
    } catch (err) {
      degradeExit(`could not install ${missingPkgs.join(" + ")} into the target (${bin} ${args.join(" ")} failed: ${(err as Error).message.slice(0, 200)})`);
    }
  }
  const cfg = scaffoldStrykerConfig(runner.runner, SCAFFOLD_SOURCE_DIRS.filter((d) => existsSync(join(targetDir, d))));
  const scaffoldDir = mkdtempSync(join(tmpdir(), "harvey-stryker-scaffold-"));
  effectiveConfigPath = join(scaffoldDir, "stryker.config.json");
  writeFileSync(effectiveConfigPath, JSON.stringify(cfg, null, 2) + "\n");
  scaffolded = { runner: runner.runner };
  console.error(`#513: scaffolded minimal Stryker config for ${runner.runner} at ${effectiveConfigPath} (mutate: ${JSON.stringify(cfg.mutate ?? "stryker defaults")})`);
}

// #1285: where THIS run's Stryker writes were redirected to — undefined when --report replayed a
// prior run's report instead of invoking Stryker. Carried into the artifact so a client report
// reader sees the guarantee (and where the scratch went) without grepping stderr.
let strykerScratchUsed: string | undefined;
// Held past the Stryker step so the SAME snapshot can be re-checked once everything this CLI runs
// against the target — Stryker, then #819's line-coverage pass, which invokes the target's own
// runner in its own tree — has finished.
let pristine: PristineSnapshot | undefined;
let strykerPhases: { testBaselineMs: number; mutationMs: number } | undefined;

let resolvedReportPath: string;
if (reportPath) {
  resolvedReportPath = resolve(reportPath);
} else {
  // #1285: Stryker still runs with cwd: targetDir — the target's own suite has to run from its own
  // tree — but a patched COPY of the config points tempDirName, jsonReporter.fileName and
  // incrementalFile at an off-tree scratch dir first, and the invariant below proves the checkout
  // came through untouched rather than asserting it.
  // #773's bypass runs FIRST so a TS7 target with a non-JSON config still degrades naming the
  // incompatibility (the more specific diagnosis) rather than the redirect's; the redirect then
  // patches whichever config that step settled on.
  const redirect = redirectStrykerWritesOffTree(applyTs7BypassIfNeeded(effectiveConfigPath, targetDir), "target", targetDir);
  if ("blocked" in redirect) degradeExit(redirect.blocked);
  strykerScratchUsed = redirect.scratchRoot;
  // #773: a TS7 target whose tsconfig chain reaches outside targetDir needs the chain rewritten in
  // a disposable copy BEFORE Stryker runs (stageTs7TsconfigFix) — falls back to targetDir itself
  // (the ordinary in-place invocation) when there's nothing to rewrite.
  const runCwd = (isIncompatibleTypeScript7(readStrykerTypeScriptVersion(targetDir)) && stageTs7TsconfigFix(targetDir, "target")) || targetDir;
  console.error(`M8: invoking Stryker against ${targetDir} (#1285) — its mutant sandboxes, JSON report and incremental file are redirected to ${redirect.scratchRoot}, outside the target tree; ${targetDir} is not written to at all, and that is asserted after the run.`);
  pristine = snapshotPristine(targetDir, loadSourceFiles(targetDir));
  const run = runStryker(redirect.cfgPath, runCwd);
  strykerPhases = run.phases;
  // Before the degrade branches, not after: a crashed or dry-run-failed Stryker is exactly when a
  // half-written sandbox would be left behind, so that exit must not skip the check.
  assertTreePristine(pristine, "#1285");
  if (run.dryRunFailure) {
    emitAndExit(
      { finding: dryRunFailureFinding(run.dryRunFailure, detectedEnv), moduleRecord: dryRunFailureModuleRecord(run.dryRunFailure, detectedEnv) },
      `✗ Stryker's initial dry run failed — the target suite does not pass under the invoked env: ${run.dryRunFailure}\nM8 coverage: partial (dry-run failure, #503) — emitting the env-fragile-suite finding instead.`,
    );
  }
  if (run.ts7Crash) {
    degradeExit(
      `Stryker crashed with the exact signature of the known Stryker/TypeScript-7 tsconfig-preprocessor incompatibility (#773: "parseConfigFileTextToJson is not a function") — TypeScript 7's native/Go rewrite no longer exports the classic compiler API Stryker's core sandbox preprocessor calls unconditionally; this is a tooling gap, not a defect in the target`,
    );
  }
  resolvedReportPath = resolveReportPath(redirect.cfgPath, runCwd, redirect.scratchRoot);
}

if (!existsSync(resolvedReportPath)) {
  // #1284: a scaffolded run crashing without a report is a ladder degrade (#513) — the target never
  // promised Stryker works there. A target-configured run doing the same USED to fail hard (bare
  // exit 1, no artifact) on the theory that it was anomalous enough to warrant an immediate crash —
  // but "anomalous" is exactly when a downstream ledger most needs a reason, not silence. Any dry-run
  // failure whose phrasing DRY_RUN_FAILURE doesn't recognize (a future Stryker wording change, an
  // exotic runner crash) fell through to here and exited 1 with NO artifact at all — the "absent
  // status, not a wrong one" hazard #1284 exists to close. Both branches now degrade the same way.
  degradeExit(
    scaffolded
      ? `the scaffolded ${scaffolded.runner} Stryker run produced no report at ${resolvedReportPath} (see the Stryker output above)`
      : `mutation report not found at ${resolvedReportPath} — Stryker exited without producing one and no dry-run failure signature was recognized (see the Stryker output above; pass --report <path> if Stryker wrote it elsewhere)`,
  );
}

const report = JSON.parse(readFileSync(resolvedReportPath, "utf8")) as StrykerReport;
const hotspotFiles = hotspotsPath
  ? readFileSync(hotspotsPath, "utf8").split("\n").map((l) => l.trim()).filter(Boolean)
  : [];

const summary = summarizeMutationReport(report, hotspotFiles);

console.error(`M8 mutation score: ${summary.overall.mutationScore}% (${summary.overall.killed + summary.overall.timeout}/${summary.overall.totalMutants - summary.overall.ignored - summary.overall.compileErrors - summary.overall.runtimeErrors} valid mutants killed)`);
// #1076: Stryker's OTHER published score — detected/(detected+survived), i.e. over only the code
// the suite actually reached. Printed alongside so "your tests are bad" and "your tests are decent
// but reach half the code" don't collapse into one number.
console.error(`M8 mutation score (based on covered code only, excluding NoCoverage): ${summary.overall.mutationScoreBasedOnCoveredCode}%`);
// #319: never print the score without its scope — a high percentage over a scoped `mutate` set is
// "the covered files are tested well", not "the repo is tested".
console.error(`  ${coveredScopeLine(summary)}`);
console.error(`${summary.survivingMutants.length} surviving mutant(s), ${summary.survivingMutants.filter((m) => m.hotspot).length} on a flagged hotspot`);
// #386: survivors concentrated in the boundary/negation mutator families mean "the denial
// branch was never tested" — a sharper sentence than "some mutants survived".
for (const b of summary.mutatorBreakdown.filter((x) => x.denialBoundaryConcentrated)) {
  console.error(`⚠ ${b.file}: ${b.boundarySurvivors}/${b.boundarySurvivors + b.otherSurvivors} survivors are boundary/negation mutants (ConditionalExpression/EqualityOperator/BooleanLiteral) — denial/boundary path looks untested`);
}

// #504: verify the run covered the CONFIGURED mutate scope — a scoped subset (an alternate
// config, a --mutate override, or a replayed scoped report) must be recorded partial with its
// scope, never presented as the module's measurement. The reference scope is the target's own
// default config when one exists (the "configured" scope even when this run used --config or a
// scaffolded config); statically readable only from a JSON config's mutate array.
function readMutateGlobs(cfgPath: string | undefined): string[] | undefined {
  if (!cfgPath || !cfgPath.endsWith(".json")) return undefined;
  try {
    const cfg = JSON.parse(readFileSync(cfgPath, "utf8")) as { mutate?: unknown };
    return Array.isArray(cfg.mutate) && cfg.mutate.every((g) => typeof g === "string") ? (cfg.mutate as string[]) : undefined;
  } catch {
    return undefined;
  }
}

// #1076: the report's own `config` (the EFFECTIVE resolved config Stryker ran with, MEASURED
// 2026-07-25 against the mutation-testing-report-schema) sits in the JSON already loaded — read
// first, so a target using a non-JSON stryker.conf.mjs/.js (previously "not statically readable" no
// matter what) still gets its real scope. readMutateGlobs above (an external JSON config file) is
// the fallback for a report that omitted `config` (an older Stryker, or a hand-assembled report).
function configMutateGlobs(cfg: Record<string, unknown> | undefined): string[] | undefined {
  const mutate = cfg?.mutate;
  return Array.isArray(mutate) && mutate.every((g) => typeof g === "string") ? (mutate as string[]) : undefined;
}

const toTargetRelative = (file: string): string => (isAbsolute(file) ? relative(targetDir, file) : file).split(sep).join("/");

const referenceConfigPath = defaultConfigPath ?? effectiveConfigPath;
const scope = verifyMutationScope(
  Object.keys(report.files).map(toTargetRelative),
  configMutateGlobs(report.config) ?? readMutateGlobs(referenceConfigPath),
  walkRelPaths(targetDir).filter((p) => SOURCE_PATH.test(p)),
);
console.error(`M8 mutate scope (#504): ${scope.note}`);

// #819: auto-pull line coverage from the same suite Stryker just ran against, so the §3b
// "coverage-vs-mutation-score gap" no longer needs a hand-filled column. `coverageCwd`/its
// package.json follow wherever the runnable suite actually lives — the target for an ordinary
// run, the workspace root for a successful #655 root-scoped run.
const lineCoverageStarted = performance.now();
const lineCoverage = runLineCoverage(readPackageJsonAt(coverageCwd), coverageCwd);
const lineCoverageMs = performance.now() - lineCoverageStarted;
if (strykerPhases) {
  console.error(
    `M8 PHASES: test baseline ${(strykerPhases.testBaselineMs / 1000).toFixed(1)}s, `
    + `mutation ${(strykerPhases.mutationMs / 1000).toFixed(1)}s, line coverage ${(lineCoverageMs / 1000).toFixed(1)}s`,
  );
}
if (lineCoverage.status === "partial") {
  console.error(`⚠ M8 line coverage: partial — ${lineCoverage.reason} (#819; the Line-cov column is disclosed as ungenerated, not left blank/omitted)`);
} else {
  console.error(`M8 line coverage auto-pulled from ${coverageCwd}'s own coverage tool (#819)`);
}

// #435: findings from the denial/boundary-concentration mapper — a real Stryker run's survivors
// contribute report-schema findings the same way the no-test-suite branch's M8-00 already does.
// #1076: noCoverageFindings adds the "never executed at all" signal ModuleMutationSummary already
// counted but nothing turned into a Finding. #1100: vacuousTestFindings needs the raw report (the
// testFiles/coveredBy/killedBy join lives at that level, not in the collapsed MutationSummary).
const findings = [...survivingMutantFindings(summary), ...noCoverageFindings(summary), ...vacuousTestFindings(report)];
const output = {
  summary,
  reportRows: toReportRows(summary, lineCoverage.byModule),
  findings,
  scope,
  // #1285: machine-readable so a client-facing reader of THIS artifact sees it, not only stderr —
  // "say so in the OUTPUT" is this repo's standing rule. The claim is ASSERTED, not asserted-as-
  // belief: assertTreePristine throws before this artifact is written if the tree gained a path or
  // a source file's bytes moved, so `pristine: true` here can only mean the check ran and passed.
  ...(strykerScratchUsed
    ? { targetTreeUntouched: { pristine: true, scratchDir: strykerScratchUsed, note: `Stryker ran with its working directory set to ${targetDir}, but its mutant sandboxes, JSON report and incremental file were redirected out of the target tree to ${strykerScratchUsed}; the target's own checkout was verified unchanged (no new paths, no changed source bytes) after the run (#1285), extending --stub-check's #600 guarantee to this rung.` } }
    : {}),
  // #819: always present (never a silent blank column) — "ran" alongside the module rows above
  // when the coverage pull succeeded, "partial" + reason when it could not.
  lineCoverage: lineCoverage.status === "ran" ? { status: "ran" as const } : { status: "partial" as const, reason: lineCoverage.reason },
  phaseTimings: strykerPhases ? { ...strykerPhases, lineCoverageMs } : undefined,
  // #504: a scoped run carries the machine-readable partial verdict alongside its summary, so the
  // M8 probe records partial-with-scope instead of banking the subset score as `ran`.
  // #1309: `scope.scoped` is false on BOTH a verified full run (the only real `ran`) AND an
  // UNVERIFIABLE one (`verified: false` — a non-JSON config or unsupported glob) — the branch #504's
  // own tests skipped. Falling through to no moduleRecord on that second case let mutationVerdict
  // read a full `ran` over a scope nobody confirmed. Only `verified && !scoped` — a proven
  // full-scope run — earns no moduleRecord at all.
  ...(scope.scoped ? { moduleRecord: scopedRunModuleRecord(scope) } : !scope.verified ? { moduleRecord: unverifiableScopeModuleRecord(scope) } : {}),
  // #1076: the raw Stryker report, retained alongside the transformed summary — previously
  // discarded after JSON.parse (src/mutation-scan.ts's own header note: "No raw Stryker report is
  // retained anywhere in the repo... Retaining one would make these verifiable"). Every future
  // fixture/regression capture can now be pulled straight from a real --out artifact instead of
  // reconstructed by hand.
  rawReport: report,
};
if (scope.scoped) console.error(`⚠ M8 coverage: partial (scoped mutation run, #504) — this score is a subset measurement, not the module's result.`);
else if (!scope.verified) console.error(`⚠ M8 coverage: partial (mutate scope unverifiable, #1309) — this score cannot be confirmed to cover the target's full configured mutate scope.`);
// #1285: the whole-run re-check. The assertion after Stryker covers the mutation step (and has to,
// because the degrade rungs exit before reaching here); this one also covers #819's line-coverage
// pass, which runs the target's OWN test runner in the target's own tree.
if (pristine) assertTreePristine(pristine, "#1285");
const json = JSON.stringify(output, null, 2);
if (outPath) {
  writeFileSync(outPath, json + "\n");
  console.error(`wrote summary to ${outPath}`);
} else {
  console.log(json);
}
