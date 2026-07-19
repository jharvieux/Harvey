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
// #600: the mutation happens on a DISPOSABLE COPY of the target (node_modules symlinked in, not
// copied), never on the live checkout — a target's own tree is never opened for writing, so a
// SIGTERM/SIGKILL/timeout mid-run cannot leave it stubbed (a real engagement did: a killed run
// left AoP's reporting.ts stubbed in the operator's checkout). This is crash-safe by
// construction, not by a try/finally racing a signal — a signal handler can't run cleanup code
// while the process is blocked inside a synchronous child-process wait, and nothing can run at
// all after SIGKILL.
//
// --report points at the mutation.json Stryker already wrote (skips re-running Stryker — use
// this to shape a report from a prior run). Without --report, this invokes `stryker run` and
// reads the json reporter's default output path, reports/mutation/mutation.json (relative to
// <target-dir>) — confirm this matches the installed Stryker version's default; older/newer
// versions may differ, in which case pass --report explicitly.
// --hotspots points at a text file, one repo-relative path per line (e.g. the M3 hotspot file
// list), used to flag surviving mutants that sit on a security/perf hotspot as top priority.

import { execSync, execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { SourceInput } from "../detectors/common.js";
import { runStubCheck, stubSurvivalFindings, type StubTestRunner } from "../stub-check.js";
import {
  coveredScopeLine,
  detectDryRunFailure,
  detectNoTestSuite,
  detectTestEnv,
  detectTestRunner,
  dryRunFailureFinding,
  dryRunFailureModuleRecord,
  mutationNotRunModuleRecord,
  noTestSuiteFinding,
  noTestSuiteModuleRecord,
  SCAFFOLD_SOURCE_DIRS,
  scaffoldStrykerConfig,
  scopedRunModuleRecord,
  summarizeMutationReport,
  survivingMutantFindings,
  toReportRows,
  verifyMutationScope,
  type DetectedEnvVar,
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
const configPath = arg("--config");
const concurrency = arg("--concurrency");
const incremental = process.argv.includes("--incremental");
const reportPath = arg("--report");
const hotspotsPath = arg("--hotspots");
const outPath = arg("--out");
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

function readTargetPackageJson(): PackageJsonForTestDetection | undefined {
  const pkgPath = join(targetDir, "package.json");
  if (!existsSync(pkgPath)) return undefined;
  try {
    return JSON.parse(readFileSync(pkgPath, "utf8")) as PackageJsonForTestDetection;
  } catch {
    return undefined;
  }
}

// #252: the census behind the suite-absent threshold — every test file in the tree
// (*.test.*/*.spec.* or under __tests__/), with text, so detectNoTestSuite can tell a harness
// with a meaningful suite from one with zero test files or a single placeholder spec.
const TEST_FILE = /(\.(test|spec)\.[cm]?[jt]sx?$)/;
const WALK_EXCLUDED_DIR = /^(node_modules|\.next|\.git|dist|build|coverage|out|reports|stryker-tmp)$/;

// One tree walk shared by every census below (test files, env sources, source paths) — they only
// differ in which relative paths they keep.
function walkRelPaths(root: string): string[] {
  const paths: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        if (!WALK_EXCLUDED_DIR.test(entry)) walk(full);
      } else {
        paths.push(relative(root, full).split(sep).join("/"));
      }
    }
  };
  walk(root);
  return paths;
}

const readRel = (root: string, rel: string): { path: string; text: string } => ({ path: rel, text: readFileSync(join(root, ...rel.split("/")), "utf8") });

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

// #224: no test script / no known test-runner dep / no Stryker config means Stryker literally
// can't run here — that's itself a High-severity M8 finding (zero automated coverage on a
// codebase in an audit's scope), not a wrapper failure. Report it and mark M8 coverage partial
// instead of falling through to runStryker()'s "binary not found"-shaped error. #252 widens the
// same finding to a harness with no meaningful suite: zero test files, or one placeholder spec.
if (!reportPath) {
  const hasStrykerConfig = configPath ? existsSync(resolve(configPath)) : STRYKER_CONFIG_NAMES.some((f) => existsSync(join(targetDir, f)));
  const { missing, reason } = detectNoTestSuite(readTargetPackageJson(), hasStrykerConfig, collectTestFiles(targetDir));
  if (missing) {
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
    process.exit(0);
  }
}

// #470: detect-only stops here when a suite IS present — the caller (corpus-drift) wants the
// suite-absent finding when it applies, never a Stryker invocation. An empty findings array,
// not silence: the caller can tell "suite present, mutation deferred" from a crashed run.
if (detectOnly) {
  console.error(`✓ ${targetDir}: test suite detected — mutation scoring skipped (--detect-only; a real run needs a provisioned Stryker install)`);
  const json = "[]";
  if (outPath) writeFileSync(outPath, json + "\n");
  else console.log(json);
  process.exit(0);
}

// #503: replicate the test env the target itself declares (TZ/LANG/LC_ALL from its runner config,
// test script, or CI workflow) when running its suite — under the audit machine's ambient env an
// env-fragile suite fails its dry run and M8 voids. Applies to both stub-check and Stryker runs.
const detectedEnv: DetectedEnvVar[] = detectTestEnv(collectEnvSourceFiles(targetDir));
const suiteEnv = { ...process.env, ...Object.fromEntries(detectedEnv.map((e) => [e.key, e.value])) };
if (detectedEnv.length) {
  console.error(`replicating target-declared test env (#503): ${detectedEnv.map((e) => `${e.key}=${e.value} (from ${e.source})`).join(", ")}`);
}

// #373: the fast pre-Stryker deletion-survival pass. Everything below (Stryker invocation,
// report shaping) is bypassed — this mode's output is stub-check runs + M8-01 findings.
if (stubCheck) {
  const SOURCE_FILE = /\.([cm]?[jt]s|[jt]sx)$/;
  const loadSources = (root: string): SourceInput[] =>
    walkRelPaths(root).filter((p) => SOURCE_FILE.test(p)).map((rel) => readRel(root, rel));

  const testCmd = arg("--test-cmd") ?? "npm test --";

  // #600: copy the target into a scratch dir the stubbing writes to, excluding the same heavy/
  // irrelevant dirs walkRelPaths already skips (node_modules is symlinked back in below rather
  // than copied, so the target's real dependency install is reused without re-copying it).
  const copyDir = mkdtempSync(join(tmpdir(), "harvey-stub-check-"));
  const sources = loadSources(targetDir); // read from the ORIGINAL — read-only, and the copy is a byte-identical mirror
  // process.exit() does NOT run pending finally blocks (it terminates before the stack unwinds),
  // so the copyDir cleanup is a real try/finally and the exit happens AFTER it, not inside it.
  let stubJson: string;
  try {
    cpSync(targetDir, copyDir, {
      recursive: true,
      filter: (src) => !(WALK_EXCLUDED_DIR.test(basename(src)) && statSync(src).isDirectory()),
    });
    const targetNodeModules = join(targetDir, "node_modules");
    if (existsSync(targetNodeModules)) symlinkSync(targetNodeModules, join(copyDir, "node_modules"), "dir");
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
        execSync(`${testCmd} ${tests.join(" ")}`, { cwd: copyDir, stdio: "ignore", env: suiteEnv });
        return true; // exit 0 with the body deleted — the suite survived
      } catch {
        return false;
      } finally {
        writeFileSync(copyAbs, original);
      }
    };

    const runs = runStubCheck(sources, runner);
    const findings = stubSurvivalFindings(runs);
    const checkedFiles = new Set(runs.map((r) => r.file)).size;
    console.error(`M8 stub-check: ${runs.length} exported function(s) stubbed across ${checkedFiles} covered file(s); ${findings.length} suite(s) survive deletion`);
    if (runs.length === 0) {
      console.error("⚠ no covered source files found (no test file imports or sits beside a source file) — nothing was checked; this is NOT a clean result");
    }

    // #600 acceptance: prove the live checkout is still exactly what it was — fail loud (not a
    // silent pass) if anything under targetDir drifted from what was read at the start.
    for (const s of sources) {
      const now = readFileSync(join(targetDir, ...s.path.split("/")), "utf8");
      if (now !== s.text) throw new Error(`#600 invariant violated: ${s.path} in ${targetDir} changed during stub-check — the target checkout is no longer pristine`);
    }

    stubJson = JSON.stringify({ runs, findings }, null, 2);
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
function runStryker(cfgPath: string | undefined): { dryRunFailure?: string } {
  const strykerArgs = ["run"];
  if (cfgPath) strykerArgs.push(cfgPath);
  if (concurrency) strykerArgs.push("--concurrency", concurrency);
  if (incremental) strykerArgs.push("--incremental");

  if (cfgPath) warnIfNotPerTest(cfgPath);

  // Prefer the target's own install over PATH — clients that ship Stryker have it in
  // node_modules/.bin, not globally.
  const localBin = join(targetDir, "node_modules", ".bin", "stryker");
  const strykerBin = existsSync(localBin) ? localBin : "stryker";
  try {
    // Stryker exits non-zero when the mutation score is under its configured break threshold —
    // that's not a wrapper failure, the report is still written; only a missing binary should throw.
    const stdout = execFileSync(strykerBin, strykerArgs, { cwd: targetDir, encoding: "utf8", env: suiteEnv, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 });
    process.stderr.write(stdout);
    return {};
  } catch (err) {
    const e = err as { code?: string; stdout?: string; stderr?: string };
    if (e.code === "ENOENT") {
      throw new Error("stryker binary not found (neither node_modules/.bin/stryker in the target nor on PATH) — install @stryker-mutator/core in the target repo (see this file's header comment)");
    }
    const captured = `${e.stdout ?? ""}\n${e.stderr ?? ""}`;
    process.stderr.write(captured);
    const dryRun = detectDryRunFailure(captured);
    if (dryRun.failed) return { dryRunFailure: dryRun.detail };
    // Non-ENOENT, no dry-run failure: (likely) a break-threshold exit; fall through to read the report.
    return {};
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
  if (missingPkgs.length && !install) {
    degradeExit(`the target has a ${runner.runner} suite but no Stryker install (${missingPkgs.join(", ")} missing) — re-run with --install to provision them into the target via \`npm install --no-save\` and score mutation with a scaffolded config`);
  }
  if (missingPkgs.length) {
    console.error(`#513: installing ${missingPkgs.join(" + ")} into the target (npm install --no-save)...`);
    try {
      execFileSync("npm", ["install", "--no-save", "--no-audit", "--no-fund", "-D", ...missingPkgs], { cwd: targetDir, stdio: ["ignore", "inherit", "inherit"] });
    } catch (err) {
      degradeExit(`could not install ${missingPkgs.join(" + ")} into the target (npm install --no-save failed: ${(err as Error).message.slice(0, 200)})`);
    }
  }
  const cfg = scaffoldStrykerConfig(runner.runner, SCAFFOLD_SOURCE_DIRS.filter((d) => existsSync(join(targetDir, d))));
  const scaffoldDir = mkdtempSync(join(tmpdir(), "harvey-stryker-scaffold-"));
  effectiveConfigPath = join(scaffoldDir, "stryker.config.json");
  writeFileSync(effectiveConfigPath, JSON.stringify(cfg, null, 2) + "\n");
  scaffolded = { runner: runner.runner };
  console.error(`#513: scaffolded minimal Stryker config for ${runner.runner} at ${effectiveConfigPath} (mutate: ${JSON.stringify(cfg.mutate ?? "stryker defaults")})`);
}

let resolvedReportPath: string;
if (reportPath) {
  resolvedReportPath = resolve(reportPath);
} else {
  const run = runStryker(effectiveConfigPath);
  if (run.dryRunFailure) {
    emitAndExit(
      { finding: dryRunFailureFinding(run.dryRunFailure, detectedEnv), moduleRecord: dryRunFailureModuleRecord(run.dryRunFailure, detectedEnv) },
      `✗ Stryker's initial dry run failed — the target suite does not pass under the invoked env: ${run.dryRunFailure}\nM8 coverage: partial (dry-run failure, #503) — emitting the env-fragile-suite finding instead.`,
    );
  }
  resolvedReportPath = join(targetDir, "reports", "mutation", "mutation.json");
}

if (!existsSync(resolvedReportPath)) {
  // A scaffolded run crashing without a report is a ladder degrade (#513) — the target never
  // promised Stryker works there. A target-configured run doing the same is anomalous: fail hard.
  if (scaffolded) {
    degradeExit(`the scaffolded ${scaffolded.runner} Stryker run produced no report at ${resolvedReportPath} (see the Stryker output above)`);
  }
  console.error(`✗ mutation report not found at ${resolvedReportPath} — pass --report <path> if Stryker wrote it elsewhere`);
  process.exit(1);
}

const report = JSON.parse(readFileSync(resolvedReportPath, "utf8")) as StrykerReport;
const hotspotFiles = hotspotsPath
  ? readFileSync(hotspotsPath, "utf8").split("\n").map((l) => l.trim()).filter(Boolean)
  : [];

const summary = summarizeMutationReport(report, hotspotFiles);

console.error(`M8 mutation score: ${summary.overall.mutationScore}% (${summary.overall.killed + summary.overall.timeout}/${summary.overall.totalMutants - summary.overall.ignored - summary.overall.compileErrors} valid mutants killed)`);
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

const SOURCE_PATH = /\.([cm]?[jt]s|[jt]sx)$/;
const toTargetRelative = (file: string): string => (isAbsolute(file) ? relative(targetDir, file) : file).split(sep).join("/");

const referenceConfigPath = defaultConfigPath ?? effectiveConfigPath;
const scope = verifyMutationScope(
  Object.keys(report.files).map(toTargetRelative),
  readMutateGlobs(referenceConfigPath),
  walkRelPaths(targetDir).filter((p) => SOURCE_PATH.test(p)),
);
console.error(`M8 mutate scope (#504): ${scope.note}`);

// #435: findings from the denial/boundary-concentration mapper — a real Stryker run's survivors
// contribute report-schema findings the same way the no-test-suite branch's M8-00 already does.
const findings = survivingMutantFindings(summary);
const output = {
  summary,
  reportRows: toReportRows(summary),
  findings,
  scope,
  // #504: a scoped run carries the machine-readable partial verdict alongside its summary, so the
  // M8 probe records partial-with-scope instead of banking the subset score as `ran`.
  ...(scope.scoped ? { moduleRecord: scopedRunModuleRecord(scope) } : {}),
};
if (scope.scoped) console.error(`⚠ M8 coverage: partial (scoped mutation run, #504) — this score is a subset measurement, not the module's result.`);
const json = JSON.stringify(output, null, 2);
if (outPath) {
  writeFileSync(outPath, json + "\n");
  console.error(`wrote summary to ${outPath}`);
} else {
  console.log(json);
}
