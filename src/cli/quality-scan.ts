// M4 (jscpd duplication) + M5 (knip dead code) wiring — runs both against a
// target repo using Harvey's own installed tooling (no install needed in the
// client repo) and shapes the output into Finding[] for §3b of the report.
// Merge the result into the engagement's findings.json alongside the M1/M2/M3
// findings and meta, then `pnpm validate:findings`.
//
//   pnpm quality-scan <target-dir> [--out findings.quality.json] [--timeout <seconds>]
//
// #505: jscpd and knip hung indefinitely (0% CPU, no output, >16 min) run over a whole multi-app
// monorepo — knip in particular got stuck in its own workspace-resolution stage when pointed at a
// root it doesn't recognize as one package. Per-app scoped runs completed in ~1 min each. Fix: run
// KNIP per workspace — discovered from the target's pnpm-workspace.yaml / package.json workspaces
// field via the same enumeration src/pentest/targets.ts already uses for M2 target coverage (a
// target with no workspace file still gets exactly one scope, its own root, so a plain
// non-monorepo target's behavior and output are unchanged) — with a hard per-invocation timeout. A
// workspace that times out or crashes never takes the whole run down with it: it's recorded as a
// disclosed coverage gap (knipUnavailableFinding) alongside whatever the other workspaces
// produced — partial, not a silent stall or a silent skip.
//
// #544: jscpd, however, runs WHOLE-REPO. #519 swept it into the per-workspace change alongside
// knip, but jscpd is a text-based clone detector with NO workspace-resolution stage — it never hit
// the hang (measured: 1.9s over the whole saas-lite monorepo), and whole-repo is the CORRECT scope
// for duplication: a block copy-pasted ACROSS workspaces (a util duplicated between packages/shared
// and apps/web instead of imported) is exactly the cross-package maintenance signal M4 exists to
// surface, and per-workspace scoping structurally cannot see it. Per-workspace jscpd also silently
// dropped every workspace the shared discoverTargets glob can't expand (saas-lite's `packages/**`
// double-star) with no gap disclosure — the silent omission the coverage guard forbids. The hard
// timeout still guards a pathological tree: a jscpd that does hang is SIGKILL'd and disclosed as an
// M4-99 gap, never a silent under-count.

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { divergedCloneFindings, type SecurityPathFile, wholeRepoDivergedCloneFindings } from "../diverged-clones.js";
import type { Finding } from "../findings.js";
import { discoverTargets } from "../pentest/targets.js";
import { buildDegradedKnipConfig, buildInferredKnipConfig, detectTargetFramework } from "../scan/framework-detect.js";
import {
  duplicationSummary,
  JSCPD_IGNORE_GLOBS,
  jscpdAnalysedNothingReason,
  jscpdToFindings,
  jscpdUnavailableFinding,
  knipEntryUncertainFinding,
  knipEntryUncertainReason,
  knipReducedTierFinding,
  knipToFindings,
  knipUnavailableFinding,
  mergeJscpdReports,
  mergeKnipReports,
  touchesSecurityPath,
  touchesTenantSupabasePath,
  type JscpdReport,
  type KnipReport,
} from "../quality-scan.js";

// node_modules/.bin shims (not require.resolve — jscpd/knip's package.json
// "exports" maps don't expose their bin scripts as importable subpaths).
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const jscpdBin = join(repoRoot, "node_modules", ".bin", "jscpd");
const knipBin = join(repoRoot, "node_modules", ".bin", "knip");

// #810: knip's own installed plugin ids, read from its dist layout. Used to build the reduced
// (no-target-deps) retry config that disables every plugin so no target config file is loaded.
// Reading knip's REAL plugin set (not a hardcoded list) matters because knip validates config keys
// strictly — an unknown key aborts the run. If the layout can't be read (a future knip repackaging),
// the list is empty and runKnip skips the retry, falling back to the M5-00 gap disclosure — fail
// loud, never a silent degrade.
function knipPluginNames(): string[] {
  try {
    return readdirSync(join(repoRoot, "node_modules", "knip", "dist", "plugins"), { withFileTypes: true })
      .filter((e) => e.isDirectory() && !e.name.startsWith("_"))
      .map((e) => e.name);
  } catch {
    return [];
  }
}
const KNIP_PLUGIN_NAMES = knipPluginNames();

const args = process.argv.slice(2);
const targetArg = args.find((a) => !a.startsWith("--"));
const outIdx = args.indexOf("--out");
const outPath = outIdx >= 0 ? args[outIdx + 1] : undefined;
const timeoutIdx = args.indexOf("--timeout");
const timeoutSeconds = timeoutIdx >= 0 ? Number(args[timeoutIdx + 1]) : 120;
// #809: opt-in whole-codebase Type-3 near-miss pass, on top of the always-on security-path pass —
// see the header comment above securityPathFiles for why this stays opt-in (noisier, no security
// guarantee, review tier).
const wholeRepoDiverged = args.includes("--whole-repo-diverged");

if (!targetArg) {
  console.error("usage: pnpm quality-scan <target-dir> [--out findings.quality.json] [--timeout <seconds>] [--whole-repo-diverged]");
  process.exit(2);
}
if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) {
  console.error("--timeout must be a positive number of seconds");
  process.exit(2);
}
const TIMEOUT_MS = timeoutSeconds * 1000;

const targetDir = resolve(targetArg);

// #505: one scope per workspace. discoverTargets' app enumeration already falls back to the
// target's own root as a single app when there's no workspace manifest, so `scopes` is always
// non-empty; it only degrades to [targetDir] itself when the root carries no package.json at all
// (e.g. a bare source directory, as some calibration fixtures are) — same tree quality-scan always
// scanned in that case.
const workspaceDirs = discoverTargets(targetDir).apps.map((a) => a.path);
const scopes = workspaceDirs.length ? workspaceDirs : [targetDir];

interface ScanGap {
  scope: string;
  reason: string;
}

function scopeLabel(dir: string): string {
  const rel = relative(targetDir, dir);
  return rel === "" ? "(repo root)" : rel;
}

// jscpd/knip file paths come back relative to the SCOPE they were run against; re-anchor to
// relative-to-target so a monorepo's merged report still has one consistent, unambiguous location
// per file, and a single-scope run (workspaceRel === "") is untouched.
function prefixed(workspaceRel: string, relPath: string): string {
  return workspaceRel === "" ? relPath : join(workspaceRel, relPath);
}

// Node's execFileSync `timeout` option kills the child and sets `code: "ETIMEDOUT"` on the thrown
// error (MEASURED on Node 24 — the documented `killed` boolean is NOT set by execFileSync's own
// timeout path, unlike spawn's async API; a nonzero exit leaves `code` undefined, a missing binary
// sets `code: "ENOENT"`). "ETIMEDOUT" is the one code we can reach here — nothing else in this
// invocation sends a signal or times anything out — so it reliably distinguishes "we killed this
// for taking too long" from any other failure shape (missing deps, tool crash, ...).
function isTimeout(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: string }).code === "ETIMEDOUT";
}

function gapReason(err: unknown): string {
  if (isTimeout(err)) return `did not complete within ${timeoutSeconds}s (timed out)`;
  const e = err as { stderr?: Buffer | string; message?: string };
  const detail = (e.stderr ? e.stderr.toString() : undefined) || e.message || String(err);
  return detail.trim().slice(0, 300);
}

function runJscpd(dir: string): JscpdReport {
  const outDir = mkdtempSync(join(tmpdir(), "harvey-jscpd-"));
  try {
    // --threshold 100 overrides any client .jscpd.json so the scan never exits
    // non-zero on us — we want the raw report, not jscpd's own pass/fail gate.
    // JSCPD_IGNORE_GLOBS excludes generated/vendored/demo paths (M4-N-GENERATED, issue #72;
    // extended per #232) that aren't hand-maintained duplication.
    //
    // #948 (root-caused by instrumenting jscpd 4.2.5 + @jscpd/finder/fast-glob directly against a
    // real clone of documenso, the #931 repro): TWO cwd/path-relativity bugs compounded into the
    // "empty file list at some absolute paths" symptom.
    //  1. jscpd resolves its `.jscpd.json` auto-discovery AND (separately, via its own
    //     src/init/ignore.ts — a second, less-anchored .gitignore reader than the one
    //     @jscpd/finder uses for the scanned dir itself) a `.gitignore` at `process.cwd()` of the
    //     CHILD PROCESS — not the `dir` argument. Without an explicit `cwd`, the child inherits
    //     whatever cwd the calling Node process has (typically Harvey's own repo root), so it can
    //     pick up the WRONG repo's config/gitignore entirely. Fixed by `cwd: dir` below.
    //  2. Independent of (1): when the scanned PATH ITSELF is an absolute string, fast-glob (inside
    //     @jscpd/finder's getFilesToDetect) matches every gitignore-derived ignore glob against the
    //     FULL ABSOLUTE PATH, not path-relative-to-the-scan-root. A gitignore entry with no slash
    //     (e.g. documenso's own "tmp") is — CORRECTLY, per git's own semantics for a bare name —
    //     converted to an ANY-DEPTH "**/tmp/**" glob. Once matched against the full absolute path,
    //     that glob also matches any ANCESTOR directory literally named "tmp" — which is exactly
    //     what a scratch clone under `/tmp` (Linux's `os.tmpdir()`; macOS's is `/var/folders/.../T`,
    //     which is why this reproduced on ubuntu-latest but not on the one measured macOS run under
    //     a shallow scratch path, #931) sits inside — silently excluding the ENTIRE scanned tree.
    //     MEASURED: `getFilesToDetect({ path: [absoluteDir], gitignore: true, absolute: true })`
    //     against a real documenso clone under a `tmp`-prefixed scratch path returns 0 files;
    //     the identical call with `path: ["."]` (cwd already pinned to the scan root) returns 2334.
    //     Fixed by scanning "." instead of the absolute `dir` (cwd: dir anchors it) — fast-glob then
    //     matches everything relative-to-scan-root, so an ignore glob can only match WITHIN the
    //     scanned tree, never an ancestor directory of wherever that tree happens to be checked out.
    execFileSync(
      jscpdBin,
      [".", "--reporters", "json", "--output", outDir, "--threshold", "100", "--silent", "--noTips", "--ignore", JSCPD_IGNORE_GLOBS.join(",")],
      { cwd: dir, stdio: ["ignore", "ignore", "pipe"], timeout: TIMEOUT_MS, killSignal: "SIGKILL" },
    );
    const reportPath = join(outDir, "jscpd-report.json");
    // #505: per-workspace scopes surface a case a whole-repo run rarely hit — a workspace with
    // fewer than 2 comparable source files. jscpd exits 0 but writes NO report file at all (there
    // was nothing to compare), which is a clean zero-duplicates scan, not a coverage gap.
    // #931: that same missing-report shape is indistinguishable from "jscpd analysed nothing" —
    // countSourceFiles walks the same skip rules (node_modules/dist/generated/vendor/… +
    // database.types.ts/types_db.ts) JSCPD_IGNORE_GLOBS encode, so it's a reasonable proxy for
    // whether this scope actually had anything to compare, independent of jscpd's own file
    // discovery. jscpdAnalysedNothingReason throws that distinction; a thrown reason here is
    // caught by the existing per-call try/catch (below, in the CLI body) and folded into the M4-99
    // gap disclosure — partial with a reason, never a silent clean 0%.
    if (!existsSync(reportPath)) {
      const reason = jscpdAnalysedNothingReason(countSourceFiles(dir));
      if (!reason) return { statistics: { total: { percentage: 0, duplicatedLines: 0, lines: 0 } }, duplicates: [] };
      throw new Error(reason);
    }
    const report = JSON.parse(readFileSync(reportPath, "utf8")) as JscpdReport;
    // jscpd (now scanning "." from cwd: dir, #948) reports paths relative to the scan root already
    // in most cases, but normalize defensively: resolve against `dir` explicitly (not the ambient
    // process.cwd(), which need not equal `dir` — the exact class of bug this fix removes) so the
    // report never leaks local filesystem layout regardless of which form jscpd emits.
    for (const dup of report.duplicates) {
      dup.firstFile.name = relative(dir, resolve(dir, dup.firstFile.name));
      dup.secondFile.name = relative(dir, resolve(dir, dup.secondFile.name));
    }
    return report;
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
}

// #693/AoP#566: knip's `ignoreExportsUsedInFile` has no CLI flag (config-file only, verified on
// knip 5.88.1). We default it to { interface, type } so a type used only to annotate its own file —
// a component Props/option type exported by convention — is not reported as unused, while a type
// exported and referenced NOWHERE still is. We MERGE it into the scope's own knip config, never
// replace it: replacing would drop the target's entry config and re-flood the unused-files list.
const HARVEY_KNIP_CONFIG = ".knip.harvey.json";

// The scope's own knip config as a mergeable object, or "unmergeable" for a comment-bearing/code
// config we won't risk re-serializing, or undefined when there is none. A root config in an
// ANCESTOR dir is deliberately not consulted: knip run per-workspace treats the scope dir as its
// own root and auto-detects entries, so there is nothing there to preserve.
function scopeKnipConfig(dir: string): Record<string, unknown> | "unmergeable" | undefined {
  const jsonPath = join(dir, "knip.json");
  if (existsSync(jsonPath)) {
    try {
      return JSON.parse(readFileSync(jsonPath, "utf8")) as Record<string, unknown>;
    } catch {
      return "unmergeable";
    }
  }
  if (["knip.jsonc", "knip.ts", "knip.js", "knip.config.ts", "knip.config.js"].some((n) => existsSync(join(dir, n)))) {
    return "unmergeable";
  }
  const pkgPath = join(dir, "package.json");
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { knip?: Record<string, unknown> };
      if (pkg.knip) return pkg.knip;
    } catch {
      // a malformed package.json is knip's own error to report, not ours to merge
    }
  }
  return undefined;
}

// One knip invocation against `dir`. `config`, when given, is written as HARVEY_KNIP_CONFIG and
// forced with `-c`; when undefined, knip runs against the scope's own config untouched. Throws on
// timeout, a non-zero exit (knip aborts with exit 2 when it can't LOAD a config it needs to resolve
// — the #810 missing-deps case), or non-JSON stdout.
function execKnip(dir: string, config: Record<string, unknown> | undefined): KnipReport {
  const plainArgs = ["--reporter", "json", "--no-exit-code"];
  let args = plainArgs;
  let cleanup: (() => void) | undefined;
  if (config) {
    writeFileSync(join(dir, HARVEY_KNIP_CONFIG), JSON.stringify(config));
    args = ["-c", HARVEY_KNIP_CONFIG, ...plainArgs];
    cleanup = () => rmSync(join(dir, HARVEY_KNIP_CONFIG), { force: true });
  }
  try {
    const out = execFileSync(knipBin, args, {
      cwd: dir,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: TIMEOUT_MS,
      killSignal: "SIGKILL",
    });
    return JSON.parse(out.toString("utf8")) as KnipReport;
  } finally {
    cleanup?.();
  }
}

// #696: a config-less scope's unused-FILE findings are contingent on the entry graph WE inferred,
// so `entriesInferred` is threaded out to knipToFindings to down-rank them to review tier — a scope
// that supplied its own config keeps confirmed file findings.
// #810: `pluginsDisabled`/`reducedReason` mark a scope that only ran after the degraded retry
// (knip couldn't load the target's config/plugin configs — the missing-node_modules case).
function runKnip(dir: string): { report: KnipReport; entriesInferred: boolean; pluginsDisabled: boolean; reducedReason?: string } {
  // First-attempt config: an inferred config for a config-less scope (#696), the
  // ignoreExportsUsedInFile default merged into a mergeable scope config (#695), or undefined to run
  // the scope's own config untouched (unmergeable knip.ts/js, or one already setting the default).
  const existing = scopeKnipConfig(dir);
  let config: Record<string, unknown> | undefined;
  let entriesInferred = false;
  try {
    if (existing === undefined) {
      // No config of its own: knip can't infer non-app entries (tests above all) and floods the
      // unused-files list. Generate framework-derived + universal entry globs so it doesn't (#696).
      config = buildInferredKnipConfig(detectTargetFramework(dir));
      entriesInferred = true;
    } else if (existing !== "unmergeable" && !("ignoreExportsUsedInFile" in existing)) {
      // The scope HAS its own config: merge only the ignoreExportsUsedInFile default, never override
      // its entries — they know their app (#695).
      config = { ...existing, ignoreExportsUsedInFile: { interface: true, type: true } };
    }
  } catch {
    // a config read/detect failure falls back to an unmodified, non-inferred run
    config = undefined;
    entriesInferred = false;
  }
  try {
    return { report: execKnip(dir, config), entriesInferred, pluginsDisabled: false };
  } catch (err) {
    // #810: knip most often fails here because it tried to LOAD the target's own knip config or a
    // framework plugin config (vite.config.ts, next.config.ts, ...) whose imports don't resolve —
    // the "NEEDS the target's node_modules" prereq. Retry ONCE with every knip plugin disabled and
    // Harvey-inferred entries, so no target config file is loaded at all and dead code is reported
    // from source alone. A timeout is a different failure (a hang, #505) — don't retry it into a
    // second full timeout; and with no plugin list we can't build the retry config. Either way, let
    // the original error propagate to the M5-00 gap disclosure — fail loud, never a silent degrade.
    if (isTimeout(err) || KNIP_PLUGIN_NAMES.length === 0) throw err;
    const report = execKnip(dir, buildDegradedKnipConfig(detectTargetFramework(dir), KNIP_PLUGIN_NAMES));
    return { report, entriesInferred: true, pluginsDisabled: true, reducedReason: gapReason(err) };
  }
}

function lineCount(dir: string, relPath: string): number | undefined {
  try {
    return readFileSync(join(dir, relPath), "utf8").split("\n").length;
  } catch {
    return undefined;
  }
}

// #360/#399: collect the security-relevant source subset for the diverged-clone pass. Skips the
// same generated/vendored/build shapes JSCPD_IGNORE_GLOBS excludes from M4, plus tests — a
// drifted copy inside a test file is not a per-handler authorization drift, and test suites
// legitimately repeat near-identical setup. A file is admitted on EITHER signal: its path names
// an auth/guard/middleware/security concern (touchesSecurityPath, v1/#360), or its body scopes a
// supabase query by a tenant key regardless of path (touchesTenantSupabasePath, v2/#399) — the
// per-entity lib/ai/tools/*/lib/stores/* copy-paste vein #399 measured outside the v1 vocabulary.
// #505: this pass is an in-process directory walk (already excluding node_modules/dist/etc via
// SKIP_DIRS), not an external tool invocation — it isn't what the issue found hanging, so it stays
// whole-target rather than per-workspace.
const SKIP_DIRS = new Set(["node_modules", "dist", "build", ".next", ".git", "generated", "vendor", "patches", "__tests__", "e2e"]);
const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const SKIP_FILE = /(\.gen\.ts|\.test\.|\.spec\.)|^(database\.types|types_db)\.ts$/;

function securityPathFiles(dir: string, rel = ""): SecurityPathFile[] {
  const files: SecurityPathFile[] = [];
  for (const entry of readdirSync(join(dir, rel), { withFileTypes: true })) {
    const relPath = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.includes("demo")) files.push(...securityPathFiles(dir, relPath));
    } else if (SOURCE_EXT.test(entry.name) && !SKIP_FILE.test(entry.name)) {
      if (touchesSecurityPath(relPath)) {
        files.push({ path: relPath, source: readFileSync(join(dir, relPath), "utf8") });
      } else {
        const source = readFileSync(join(dir, relPath), "utf8");
        if (touchesTenantSupabasePath(source)) files.push({ path: relPath, source });
      }
    }
  }
  return files;
}

// #809: every eligible source file, for the opt-in --whole-repo-diverged pass. Same skip rules as
// securityPathFiles (generated/vendored/build dirs, test files) minus the security-relevance gate
// — the caller excludes securityPathFiles' admitted set from this to avoid double-reporting the
// same family once under each taxonomy.
function allSourceFiles(dir: string, rel = ""): SecurityPathFile[] {
  const files: SecurityPathFile[] = [];
  for (const entry of readdirSync(join(dir, rel), { withFileTypes: true })) {
    const relPath = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.includes("demo")) files.push(...allSourceFiles(dir, relPath));
    } else if (SOURCE_EXT.test(entry.name) && !SKIP_FILE.test(entry.name)) {
      files.push({ path: relPath, source: readFileSync(join(dir, relPath), "utf8") });
    }
  }
  return files;
}

// #580: filesystem facts for src/quality-scan.ts's knipEntryUncertainReason. countSourceFiles
// reuses the same SKIP_DIRS/SOURCE_EXT/SKIP_FILE walk shape as securityPathFiles above (total
// count instead of a security-relevant subset) so the ratio denominator matches what knip could
// plausibly have scanned.
function countSourceFiles(dir: string, rel = ""): number {
  let count = 0;
  for (const entry of readdirSync(join(dir, rel), { withFileTypes: true })) {
    const relPath = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.includes("demo")) count += countSourceFiles(dir, relPath);
    } else if (SOURCE_EXT.test(entry.name) && !SKIP_FILE.test(entry.name)) {
      count += 1;
    }
  }
  return count;
}

const VITE_CONFIG_NAMES = ["vite.config.ts", "vite.config.js", "vite.config.mjs", "vite.config.cjs", "vite.config.mts", "vite.config.cts"];

function hasViteEntryMarkers(dir: string): boolean {
  return VITE_CONFIG_NAMES.some((f) => existsSync(join(dir, f))) || existsSync(join(dir, "index.html"));
}

// Walks node_modules up the directory tree the way Node's own module resolution does — MEASURED
// (2026-07-18) as the actual gate on whether knip's Vite plugin excludes vite.config.ts from the
// unused-files list: a fixture with `vite` declared in package.json but not installed still
// reported vite.config.ts unused; installing it (`npm install vite`) stopped that. Declared-in-
// package.json alone is not enough signal — resolvability is.
function isViteResolvable(dir: string): boolean {
  let cur = dir;
  for (;;) {
    if (existsSync(join(cur, "node_modules", "vite"))) return true;
    const parent = dirname(cur);
    if (parent === cur) return false;
    cur = parent;
  }
}

const jscpdReports: JscpdReport[] = [];
const jscpdGaps: ScanGap[] = [];
const knipReports: KnipReport[] = [];
const knipGaps: ScanGap[] = [];
const knipUncertainScopes: ScanGap[] = [];
// #810: scopes that only produced findings after the degraded (all-plugins-disabled) retry.
const knipReducedScopes: ScanGap[] = [];
// #696: files whose scope had Harvey-inferred entries — their unused-FILE findings are review tier.
const inferredEntryFiles = new Set<string>();

// #544: one whole-repo jscpd pass — paths already come back relative to targetDir, so no
// per-workspace re-anchoring is needed. See the header for why duplication is measured whole-repo.
try {
  jscpdReports.push(runJscpd(targetDir));
} catch (err) {
  const reason = gapReason(err);
  jscpdGaps.push({ scope: "(whole repo)", reason });
  console.error(`⚠ jscpd ${isTimeout(err) ? "timed out" : "failed"} on the whole repo — M4 coverage incomplete: ${reason}`);
}

// #223/#505: knip has no dependency on M4 and runs per workspace — a knip gap on one workspace
// must not cost any other workspace's (or jscpd's) findings.
for (const scope of scopes) {
  const label = scopeLabel(scope);
  const workspaceRel = relative(targetDir, scope);
  try {
    const { report, entriesInferred, pluginsDisabled, reducedReason } = runKnip(scope);
    // #810: a scope that only ran after the degraded retry is disclosed as a reduced-mode partial
    // (M5-98). Its file findings are already review-tier via entriesInferred below. The #580
    // entry-uncertain heuristic is skipped for it — its high unused ratio is the EXPECTED cost of a
    // plugins-disabled run, already explained by M5-98, not a separate mis-resolution signal.
    if (pluginsDisabled) {
      knipReducedScopes.push({ scope: label, reason: reducedReason ?? "knip could not load the target's config" });
      console.error(`⚠ knip could not load ${label}'s config (likely no node_modules) — re-ran with plugins disabled; M5 file findings for it are review-tier (#810, see M5-98)`);
    } else {
      // #580: computed BEFORE re-anchoring report.files below — knipEntryUncertainReason's ratio
      // only cares about the count, and countSourceFiles/hasViteEntryMarkers/isViteResolvable all
      // operate on the real scope dir, not the merged-report-relative path.
      const uncertainReason = knipEntryUncertainReason(report, countSourceFiles(scope), hasViteEntryMarkers(scope), isViteResolvable(scope));
      if (uncertainReason) knipUncertainScopes.push({ scope: label, reason: uncertainReason });
    }
    report.files = report.files.map((f) => prefixed(workspaceRel, f));
    for (const issue of report.issues) issue.file = prefixed(workspaceRel, issue.file);
    // #696: record the (now target-relative) files whose entries Harvey inferred, so their file
    // findings are review-tier after mergeKnipReports flattens per-scope reports into one.
    if (entriesInferred) for (const f of report.files) inferredEntryFiles.add(f);
    knipReports.push(report);
  } catch (err) {
    const reason = gapReason(err);
    knipGaps.push({ scope: label, reason });
    console.error(`⚠ knip ${isTimeout(err) ? "timed out" : "failed"} on ${label} — M5 dead-code coverage skipped for this scope: ${reason}`);
  }
}

const jscpdReport = mergeJscpdReports(jscpdReports);

// #360/#399: the Type-3 near-miss layer jscpd structurally cannot provide — diverged copies of
// security checks. Scoped to securityPathFiles's admitted subset (touchesSecurityPath OR
// touchesTenantSupabasePath).
const narrowFiles = securityPathFiles(targetDir);
const divergedFindings = divergedCloneFindings(narrowFiles);

// #809: opt-in whole-codebase extension. Runs over the COMPLEMENT of narrowFiles — every other
// eligible source file — so a security-path family is never reported twice (once High under
// M4_DIVERGED_TAXONOMY above, once Medium under M4_DIVERGED_WIDE_TAXONOMY here).
let wholeRepoDivergedFindings: Finding[] = [];
if (wholeRepoDiverged) {
  const narrowPaths = new Set(narrowFiles.map((f) => f.path));
  const wideFiles = allSourceFiles(targetDir).filter((f) => !narrowPaths.has(f.path));
  wholeRepoDivergedFindings = wholeRepoDivergedCloneFindings(wideFiles);
}

const knipReport = knipReports.length ? mergeKnipReports(knipReports) : undefined;

const fileLineCounts: Record<string, number> = {};
if (knipReport) {
  for (const file of knipReport.files) {
    const n = lineCount(targetDir, file);
    if (n !== undefined) fileLineCounts[file] = n;
  }
}

const findings: Finding[] = [
  ...jscpdToFindings(jscpdReport),
  ...divergedFindings,
  ...wholeRepoDivergedFindings,
  ...(knipReport ? knipToFindings(knipReport, fileLineCounts, inferredEntryFiles) : []),
];
// #505: a gap disclosure coexists with real findings from the scopes that DID complete — unlike
// the old whole-repo-or-nothing shape, a monorepo run can be a genuine partial (2 of 3 workspaces
// scanned clean, 1 timed out).
if (knipGaps.length) findings.push(knipUnavailableFinding(knipGaps.map((g) => `${g.scope}: ${g.reason}`).join("; ")));
if (jscpdGaps.length) findings.push(jscpdUnavailableFinding(jscpdGaps.map((g) => `${g.scope}: ${g.reason}`).join("; ")));
// #580: a completed-without-error knip run that still looks untrustworthy — disclosed separately
// from knipGaps (which is "didn't complete at all") so the two failure shapes stay distinguishable
// in the report.
if (knipUncertainScopes.length) findings.push(knipEntryUncertainFinding(knipUncertainScopes.map((g) => `${g.scope}: ${g.reason}`).join("; ")));
// #810: scopes that produced findings only via the degraded (no-target-deps) retry — a visible
// reduced-mode partial, distinct from "didn't complete" (M5-00) and "completed but uncertain" (M5-99).
if (knipReducedScopes.length) findings.push(knipReducedTierFinding(knipReducedScopes.map((g) => `${g.scope}: ${g.reason}`).join("; ")));

const dup = duplicationSummary(jscpdReport);
console.error(
  `M4 duplication: ${dup.percentage}% (${dup.duplicatedLines}/${dup.totalLines} lines) — ${jscpdReport.duplicates.length} clone cluster(s), ${dup.subThresholdCloneCount} sub-threshold small clone(s) disclosed in M4-00 (#365), ${divergedFindings.length} diverged security-path clone pair(s) (#360, review tier)` +
    (jscpdGaps.length ? `, whole-repo scan incomplete (#544, see M4-99)` : "") +
    (wholeRepoDiverged ? `, ${wholeRepoDivergedFindings.filter((f) => f.id !== "M4-98").length} diverged clone(s) outside the security path (#809, review tier)` : ""),
);
if (knipReport) {
  console.error(
    `M5 dead code: ${knipReport.files.length} unused file(s), ${knipReport.issues.filter((i) => i.exports.length + i.types.length > 0).length} file(s) with unused exports` +
      (knipGaps.length ? `, ${knipGaps.length}/${scopes.length} scope(s) incomplete (#505, see M5-00)` : "") +
      (knipReducedScopes.length ? `, ${knipReducedScopes.length}/${scopes.length} scope(s) ran in reduced no-deps mode (#810, see M5-98)` : "") +
      (knipUncertainScopes.length ? `, ${knipUncertainScopes.length}/${scopes.length} scope(s) flagged as uncertain (#580, see M5-99)` : ""),
  );
} else {
  console.error("M5 dead code: skipped (knip failed on every scope — see warnings above)");
}

const json = JSON.stringify(findings, null, 2);
if (outPath) {
  writeFileSync(outPath, json + "\n");
  console.error(`wrote ${findings.length} findings to ${outPath}`);
} else {
  console.log(json);
}
