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
// non-monorepo target's behavior and output are unchanged) — with a hard per-invocation timeout.
// A configured root Knip workspace graph is run from that root so its overrides remain effective.
// A
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

import "./sync-stdio.js";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { existsSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
import { productSourceInventoryForScope, productSourceInventoryForTarget, readStaticConfigObject, sourceExclusionGlob, type ProductSourceInventory } from "../source-inventory.js";
import { fileURLToPath, pathToFileURL } from "node:url";
import { divergedCloneFindings, divergedScopeFinding, type SecurityPathFile, wholeRepoDivergedCloneFindings } from "../diverged-clones.js";
import type { Finding } from "../findings.js";
import { discoverTargets } from "../pentest/targets.js";
import { discoverWorkspaceInventory } from "../workspaces.js";
import { runJscpd as runJscpdLive } from "../scan/duplication.js";
import { buildDegradedKnipConfig, buildInferredKnipConfig, detectTargetFramework } from "../scan/framework-detect.js";
import { digestObservedPaths, writeCorpusScannerScope } from "../corpus-scanner-scope.js";
import {
  duplicationSummary,
  JSCPD_DISCLOSED_GLOBS,
  jscpdIgnoreScopeFinding,
  jscpdToFindings,
  jscpdUnavailableFinding,
  knipEntryUncertainFinding,
  knipEntryUncertainReason,
  knipReducedTierFinding,
  knipToFindings,
  knipUnavailableFinding,
  matchesGlob,
  mergeJscpdReports,
  mergeKnipReports,
  touchesSecurityPath,
  touchesTenantSupabasePath,
  unlistedImportNeedsResolvedConfig,
  type JscpdGlobMatch,
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
    return readEntriesSafe(join(repoRoot, "node_modules", "knip", "dist", "plugins")).entries
      .filter((e) => e.isDirectory && !e.name.startsWith("_"))
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
const scopeOutIdx = args.indexOf("--scope-out");
const scopeOutPath = scopeOutIdx >= 0 ? args[scopeOutIdx + 1] : undefined;
const timeoutIdx = args.indexOf("--timeout");
const timeoutSeconds = timeoutIdx >= 0 ? Number(args[timeoutIdx + 1]) : 120;
const degradedKnipIdx = args.indexOf("--degraded-knip-reason");
let degradedKnipReason = degradedKnipIdx >= 0 ? args[degradedKnipIdx + 1] : undefined;
const degradedKnipReasonStdin = args.includes("--degraded-knip-reason-stdin");
const degradedKnipUnresolvedDependencySurface = args.includes("--degraded-knip-unresolved-dependency-surface");
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
if (degradedKnipReasonStdin && degradedKnipIdx >= 0) {
  console.error("choose only one degraded Knip reason source");
  process.exit(2);
}
if (degradedKnipIdx >= 0 && (!degradedKnipReason || degradedKnipReason.startsWith("--"))) {
  console.error("--degraded-knip-reason requires a non-empty reason");
  process.exit(2);
}
if (degradedKnipUnresolvedDependencySurface && degradedKnipIdx < 0 && !degradedKnipReasonStdin) {
  console.error("--degraded-knip-unresolved-dependency-surface requires --degraded-knip-reason or --degraded-knip-reason-stdin");
  process.exit(2);
}
if (degradedKnipReasonStdin) {
  try {
    degradedKnipReason = readFileSync(0, "utf8");
  } catch {
    console.error("--degraded-knip-reason-stdin could not read stdin");
    process.exit(2);
  }
  if (!degradedKnipReason.trim()) {
    console.error("--degraded-knip-reason-stdin requires a non-empty reason");
    process.exit(2);
  }
}
const TIMEOUT_MS = timeoutSeconds * 1000;

const targetDir = resolve(targetArg);
const sourceInventory = productSourceInventoryForTarget(targetDir);

// #505: one scope per workspace. discoverTargets' app enumeration already falls back to the
// target's own root as a single app when there's no workspace manifest, so `scopes` is always
// non-empty; it only degrades to [targetDir] itself when the root carries no package.json at all
// (e.g. a bare source directory, as some calibration fixtures are) — same tree quality-scan always
// scanned in that case.
const packageWorkspaceDirs = discoverTargets(targetDir).apps.map((a) => a.path);
const knipWorkspaceDiscoveryFailures: string[] = [];

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
  // #1305: the invocation itself now lives in src/scan/duplication.ts so the free-tier health
  // scorecard can run the same pass. This wrapper keeps the CLI's own timeout and file-count walk.
  const inventory = productSourceInventoryForScope(targetDir, dir, sourceInventory);
  return runJscpdLive(dir, { timeoutMs: TIMEOUT_MS, sourceFileCount: () => countSourceFiles(dir, "", inventory), jscpdBin, ignoreGlobs: inventory.jscpdIgnoreGlobs });
}

// #693/AoP#566: knip's `ignoreExportsUsedInFile` has no CLI flag (config-file only, verified on
// knip 5.88.1). We default it to { interface, type } so a type used only to annotate its own file —
// a component Props/option type exported by convention — is not reported as unused, while a type
// exported and referenced NOWHERE still is. We MERGE it into the scope's own knip config, never
// replace it: replacing would drop the target's entry config and re-flood the unused-files list.
const HARVEY_KNIP_CONFIG = ".knip.harvey.json";

// The scope's own knip config as a mergeable object, or "unmergeable" for a comment-bearing/code
// config we won't risk re-serializing, or undefined when there is none.
type ScopeKnipConfig =
  | { value: Record<string, unknown>; executablePath?: string; packageConfig?: Record<string, unknown> }
  | { unresolved: string; executablePath?: string; packageConfig?: Record<string, unknown> };

function scopeKnipConfig(dir: string): ScopeKnipConfig | undefined {
  const pkgPath = join(dir, "package.json");
  let packageConfig: Record<string, unknown> | undefined;
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { knip?: Record<string, unknown> };
      if (pkg.knip) packageConfig = pkg.knip;
    } catch {
      // a malformed package.json is knip's own error to report, not ours to merge
    }
  }
  const configNames = ["knip.json", "knip.jsonc", ".knip.json", ".knip.jsonc", "knip.ts", "knip.js", "knip.config.ts", "knip.config.js"];
  const configPath = configNames.map((name) => join(dir, name)).find(existsSync);
  if (!configPath) return packageConfig ? { value: packageConfig } : undefined;
  const parsed = readStaticConfigObject(configPath);
  if (!parsed.value) {
    const executablePath = [".js", ".ts"].includes(extname(configPath)) ? configPath : undefined;
    return {
      unresolved: `${basename(configPath)}: ${parsed.error}`,
      ...(executablePath ? { executablePath } : {}),
      ...(packageConfig ? { packageConfig } : {}),
    };
  }
  // Installed Knip shallow-merges package.json#knip first and the config file second. Preserve that
  // exact precedence before Harvey adds its product-inventory ignores.
  return {
    value: { ...packageConfig, ...parsed.value },
    ...(parsed.executable ? { executablePath: configPath } : {}),
    ...(packageConfig ? { packageConfig } : {}),
  };
}

function hasWorkspaceKnipConfig(dir: string): boolean {
  const config = scopeKnipConfig(dir);
  if (config && "unresolved" in config) return true;
  return !!config && "value" in config && !!config.value.workspaces
    && typeof config.value.workspaces === "object" && !Array.isArray(config.value.workspaces);
}

// Knip's configured workspace keys can add directories that the package manager never declared.
// Use Knip's own glob implementation, as dependency preparation does, so brace/extglob keys and
// the scan's receipt resolve to the same physical directories as the child process.
async function configuredKnipWorkspaceDirs(root: string): Promise<string[]> {
  const config = scopeKnipConfig(root);
  if (!config || !("value" in config) || !config.value.workspaces
    || typeof config.value.workspaces !== "object" || Array.isArray(config.value.workspaces)) return [];
  const patterns = Object.keys(config.value.workspaces as Record<string, unknown>).filter((pattern) => pattern !== ".");
  if (patterns.length === 0) return [];
  try {
    const { _dirGlob } = await import(pathToFileURL(join(repoRoot, "node_modules", "knip", "dist", "util", "glob.js")).href) as {
      _dirGlob: (options: { cwd: string; patterns: string[]; gitignore: boolean }) => Promise<string[]>;
    };
    const physicalRoot = realpathSync(root);
    const dirs = await _dirGlob({ cwd: root, patterns, gitignore: false });
    return dirs.map((dir) => {
      const absolute = resolve(root, dir);
      const physical = realpathSync(absolute);
      if (physical !== physicalRoot && !physical.startsWith(`${physicalRoot}/`)) {
        throw new Error(`Knip configured workspace escapes its root: ${dir}`);
      }
      return absolute;
    });
  } catch (err) {
    knipWorkspaceDiscoveryFailures.push(`Knip configured workspace discovery at ${root} failed: ${err instanceof Error ? err.message : String(err)}`);
    return [];
  }
}

const workspaceDirs = [...new Set([...packageWorkspaceDirs, ...await configuredKnipWorkspaceDirs(targetDir)])];

// A direct member scan still belongs to the ancestor's configured Knip workspace. Run that graph
// from its root and select only the member's findings for the requested target.
async function configuredWorkspaceOwner(dir: string): Promise<{ root: string; member: string } | undefined> {
  let candidate = dirname(dir);
  while (candidate !== dirname(candidate)) {
    if (hasWorkspaceKnipConfig(candidate)) {
      const member = relative(candidate, dir).replaceAll("\\", "/");
      if (discoverWorkspaceInventory(candidate).packages.some((pkg) => pkg.dir === member)
        || (await configuredKnipWorkspaceDirs(candidate)).includes(dir)) {
        return { root: candidate, member };
      }
    }
    candidate = dirname(candidate);
  }
  return undefined;
}

const rootWorkspaceConfig = workspaceDirs.some((dir) => dir !== targetDir) && hasWorkspaceKnipConfig(targetDir);
const ancestorWorkspaceConfig = rootWorkspaceConfig ? undefined : await configuredWorkspaceOwner(targetDir);
const scopes = rootWorkspaceConfig
  ? [targetDir, ...workspaceDirs.filter((dir) => dir !== targetDir)]
  : ancestorWorkspaceConfig
    ? [targetDir, ...workspaceDirs.filter((dir) => dir !== targetDir)]
  : workspaceDirs.length ? workspaceDirs : [targetDir];
const workspacePackageNames = new Set<string>();
for (const scope of scopes) {
  try {
    const parsed = JSON.parse(readFileSync(join(scope, "package.json"), "utf8")) as { name?: unknown };
    if (typeof parsed.name === "string") workspacePackageNames.add(parsed.name);
  } catch {
    // A missing/malformed manifest asserts no workspace package identity.
  }
}

// One knip invocation against `dir`. `config`, when given, is written as HARVEY_KNIP_CONFIG and
// forced with `-c`; when undefined, knip runs against the scope's own config untouched. Throws on
// timeout, a non-zero exit (knip aborts with exit 2 when it can't LOAD a config it needs to resolve
// — the #810 missing-deps case), or non-JSON stdout.
function execKnip(
  dir: string,
  config: Record<string, unknown> | undefined,
  executablePath?: string,
  packageConfig: Record<string, unknown> = {},
  inventory: ProductSourceInventory = productSourceInventoryForTarget(dir),
): KnipReport {
  const plainArgs = ["--reporter", "json", "--no-exit-code"];
  let args = plainArgs;
  let cleanup: (() => void) | undefined;
  if (config) {
    const configName = executablePath ? ".knip.harvey.ts" : HARVEY_KNIP_CONFIG;
    const configPath = join(dir, configName);
    if (executablePath) {
      const importPath = `./${basename(executablePath)}`;
      const inventoryIgnore = productInventoryKnipIgnore(inventory);
      writeFileSync(configPath, [
        `import original from ${JSON.stringify(importPath)};`,
        `const packageConfig = ${JSON.stringify(packageConfig)};`,
        `const inventoryIgnore = ${JSON.stringify(inventoryIgnore)};`,
        "export default async function harveyKnipConfig(options: unknown) {",
        "  const resolved = typeof original === \"function\" ? await original(options) : await original;",
        "  if (!resolved || typeof resolved !== \"object\" || Array.isArray(resolved)) throw new Error(\"Knip config did not resolve to an object\");",
        "  const merged = { ...packageConfig, ...resolved };",
        "  const existingIgnore = typeof merged.ignore === \"string\" ? [merged.ignore] : Array.isArray(merged.ignore) ? merged.ignore.filter((value): value is string => typeof value === \"string\") : [];",
        "  return { ...merged, ignoreExportsUsedInFile: merged.ignoreExportsUsedInFile ?? { interface: true, type: true }, ignore: [...new Set([...existingIgnore, ...inventoryIgnore])] };",
        "}",
        "",
      ].join("\n"));
    } else writeFileSync(configPath, JSON.stringify(config));
    args = ["-c", configName, ...plainArgs];
    cleanup = () => rmSync(configPath, { force: true });
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

function productInventoryKnipIgnore(inventory: ProductSourceInventory): string[] {
  return inventory.excludedDirectories
    .filter((entry) => entry.path !== "node_modules" && entry.path !== ".git")
    .map(sourceExclusionGlob);
}

function withProductInventoryIgnore(config: Record<string, unknown>, inventory: ProductSourceInventory): Record<string, unknown> {
  const configured = config.ignore;
  const existing = typeof configured === "string"
    ? [configured]
    : Array.isArray(configured) ? configured.filter((value): value is string => typeof value === "string") : [];
  const generated = productInventoryKnipIgnore(inventory);
  return { ...config, ignore: [...new Set([...existing, ...generated])] };
}

// #696: a config-less scope's unused-FILE findings are contingent on the entry graph WE inferred,
// so `entriesInferred` is threaded out to knipToFindings to down-rank them to review tier — a scope
// that supplied its own config keeps confirmed file findings.
// #810: `pluginsDisabled`/`reducedReason` mark a scope that only ran after the degraded retry
// (knip couldn't load the target's config/plugin configs — the missing-node_modules case).
function runKnip(
  dir: string,
  inventory: ProductSourceInventory,
): { report: KnipReport; entriesInferred: boolean; pluginsDisabled: boolean; reducedReason?: string } {
  // First-attempt config: an inferred config for a config-less scope (#696), the
  // ignoreExportsUsedInFile default merged into a mergeable scope config (#695), or undefined to run
  // the scope's own config untouched (unmergeable knip.ts/js, or one already setting the default).
  const existing = scopeKnipConfig(dir);
  let config: Record<string, unknown> | undefined;
  let configurationError: unknown;
  let entriesInferred = false;
  try {
    if (existing && "unresolved" in existing) {
      if (!existing.executablePath) {
        throw new Error(`Knip config is not a fully static object, so Harvey's product-source exclusions were not applied: ${existing.unresolved}`);
      }
      // Executable configs are merged at runtime by a wrapper. That preserves provider imports and
      // dynamic values while still applying the same product inventory as every static config.
      config = {};
    } else if (existing === undefined) {
      // No config of its own: knip can't infer non-app entries (tests above all) and floods the
      // unused-files list. Generate framework-derived + universal entry globs so it doesn't (#696).
      const framework = detectTargetFramework(dir, { root: dir, inventory });
      config = buildInferredKnipConfig(framework);
      // A package-manager workspace may keep Vite in the root manifest while the member owns the
      // Vite config. Knip's direct-member run does not inherit that dependency declaration, so its
      // plugin stays off even though Node can resolve the installed provider. Explicitly enable the
      // plugin only at that proven boundary; it then executes the member config just as Knip's root
      // workspace run does, while an uninstalled provider still follows the existing reduced tier.
      if (framework === "vite" && isViteResolvable(dir)) config.vite = {};
      entriesInferred = true;
    } else if (!("ignoreExportsUsedInFile" in existing.value)) {
      // The scope HAS its own config: merge only the ignoreExportsUsedInFile default, never override
      // its entries — they know their app (#695).
      config = { ...existing.value, ignoreExportsUsedInFile: { interface: true, type: true } };
    } else {
      config = existing.value;
    }
  } catch (err) {
    // Preserve the failure for the existing source-only retry. Running the target config without
    // inventory exclusions could succeed while silently restoring generated or vendored files.
    configurationError = err;
    config = undefined;
    entriesInferred = false;
  }
  try {
    if (configurationError) throw configurationError;
    return {
      report: execKnip(
        dir,
        config ? withProductInventoryIgnore(config, inventory) : undefined,
        existing?.executablePath,
        existing?.packageConfig,
        inventory,
      ),
      entriesInferred,
      pluginsDisabled: false,
    };
  } catch (err) {
    // #810: knip most often fails here because it tried to LOAD the target's own knip config or a
    // framework plugin config (vite.config.ts, next.config.ts, ...) whose imports don't resolve —
    // the "NEEDS the target's node_modules" prereq. Retry ONCE with every knip plugin disabled and
    // Harvey-inferred entries, so no target config file is loaded at all and dead code is reported
    // from source alone. A timeout is a different failure (a hang, #505) — don't retry it into a
    // second full timeout; and with no plugin list we can't build the retry config. Either way, let
    // the original error propagate to the M5-00 gap disclosure — fail loud, never a silent degrade.
    if (isTimeout(err) || KNIP_PLUGIN_NAMES.length === 0) throw err;
    // An executed target config may have changed source or dependency inputs. Keep framework
    // detection fresh here instead of reusing the pre-child inventory across that boundary.
    const report = execKnip(
      dir,
      withProductInventoryIgnore(buildDegradedKnipConfig(detectTargetFramework(dir), KNIP_PLUGIN_NAMES), inventory),
      undefined,
      {},
      inventory,
    );
    return { report, entriesInferred: true, pluginsDisabled: true, reducedReason: gapReason(err) };
  }
}

// #1871: an incomplete dependency-preparation receipt means any surviving target node_modules is
// rejected input. Do not make the normal first attempt: it may execute the target's own Knip or
// framework/provider config against that partial tree. Start directly in the same source-only tier
// as #810's retry, with every plugin disabled and Harvey-inferred entries. An empty live plugin
// catalog leaves no complete disable list; abort into M5-00 before starting Knip.
function runKnipDegraded(
  dir: string,
  reason: string,
  inventory: ProductSourceInventory,
): { report: KnipReport; entriesInferred: true; pluginsDisabled: true; reducedReason: string } {
  if (KNIP_PLUGIN_NAMES.length === 0) throw new Error("Knip's live plugin catalog is empty; safe source-only execution cannot be proven");
  return {
    report: execKnip(
      dir,
      withProductInventoryIgnore(buildDegradedKnipConfig(detectTargetFramework(dir, { root: dir, inventory }), KNIP_PLUGIN_NAMES), inventory),
      undefined,
      {},
      inventory,
    ),
    entriesInferred: true,
    pluginsDisabled: true,
    reducedReason: reason,
  };
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
const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const SKIP_FILE = /(\.gen\.ts|\.test\.|\.spec\.)|^(database\.types|types_db)\.ts$/;

function excludedProductPath(relPath: string): boolean {
  return sourceInventory.excludedDirectoryFor(relPath) !== undefined;
}

function securityPathFiles(dir: string, rel = "", observed?: Set<string>): SecurityPathFile[] {
  const files: SecurityPathFile[] = [];
  for (const entry of readEntriesSafe(join(dir, rel)).entries) {
    const relPath = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory) {
      if (!excludedProductPath(relPath)) files.push(...securityPathFiles(dir, relPath, observed));
    } else if (!excludedProductPath(relPath) && SOURCE_EXT.test(entry.name) && !SKIP_FILE.test(entry.name)) {
      observed?.add(relPath);
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
  for (const entry of readEntriesSafe(join(dir, rel)).entries) {
    const relPath = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory) {
      if (!excludedProductPath(relPath)) files.push(...allSourceFiles(dir, relPath));
    } else if (!excludedProductPath(relPath) && SOURCE_EXT.test(entry.name) && !SKIP_FILE.test(entry.name)) {
      files.push({ path: relPath, source: readFileSync(join(dir, relPath), "utf8") });
    }
  }
  return files;
}

// #580: filesystem facts for src/quality-scan.ts's knipEntryUncertainReason. countSourceFiles
// reuses the same SKIP_DIRS/SOURCE_EXT/SKIP_FILE walk shape as securityPathFiles above (total
// count instead of a security-relevant subset) so the ratio denominator matches what knip could
// plausibly have scanned.
function countSourceFiles(dir: string, rel = "", inventory: ProductSourceInventory = sourceInventory): number {
  let count = 0;
  for (const entry of readEntriesSafe(join(dir, rel)).entries) {
    const relPath = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory) {
      if (!inventory.excludedDirectoryFor(relPath)) count += countSourceFiles(dir, relPath, inventory);
    } else if (!inventory.excludedDirectoryFor(relPath) && SOURCE_EXT.test(entry.name) && !SKIP_FILE.test(entry.name)) {
      count += 1;
    }
  }
  return count;
}

// #1080: deliberately its OWN walk, not countSourceFiles'/securityPathFiles' — those already skip
// generated/vendor/patches/demo-named directories before a file is ever seen, which would make every
// one of JSCPD_DISCLOSED_GLOBS's counts read as zero. This walk only skips the build-artifact dirs
// (node_modules/dist/.next/.git — the ones deliberately NOT in JSCPD_DISCLOSED_GLOBS, see its header)
// so it actually visits the files the disclosed globs are about.
function tallyJscpdIgnoredFiles(dir: string, rel = ""): JscpdGlobMatch[] {
  const configured = sourceInventory.excludedDirectories
    .filter((entry) => entry.path !== "node_modules" && entry.path !== ".git")
    .map((entry) => ({ glob: sourceExclusionGlob(entry), reason: entry.reason }));
  // Configured directories are the primary allocation. A generated filename inside a package store
  // is one physical exclusion, so it contributes once here while the configured reason remains visible.
  const entries: Array<{ glob: string; reason?: string }> = [...configured, ...JSCPD_DISCLOSED_GLOBS.map((glob) => ({ glob }))]
    .filter((entry, index, all) => all.findIndex((candidate) => candidate.glob === entry.glob) === index);
  const counts = new Map<string, { count: number; example?: string; reason?: string }>(entries.map((entry) => [entry.glob, { count: 0, reason: entry.reason }]));
  const walk = (curRel: string): void => {
    for (const entry of readEntriesSafe(join(dir, curRel)).entries) {
      const relPath = curRel ? `${curRel}/${entry.name}` : entry.name;
      if (entry.isDirectory) {
        // The M4 run skips configured output/store directories, but this disclosure walk must
        // enter them to count the exact omitted population. Git metadata and installed dependency
        // trees are universal exclusions and intentionally have no client-facing denominator.
        if (!sourceInventory.exclusionsFor(relPath).some((exclusion) => exclusion.path === "node_modules" || exclusion.path === ".git")) walk(relPath);
        continue;
      }
      const primary = entries.find(({ glob }) => matchesGlob(glob, relPath));
      if (!primary) continue;
      const hit = counts.get(primary.glob)!;
      hit.count += 1;
      if (!hit.example) hit.example = relPath;
    }
  };
  walk(rel);
  return [...counts.entries()].map(([glob, { count, example, reason }]) => ({ glob, count, example, reason }));
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
const knipGaps: ScanGap[] = knipWorkspaceDiscoveryFailures.map((reason) => ({ scope: "(repo root)", reason }));
for (const gap of sourceInventory.unresolvedConfigurations) {
  const reason = `${gap.path}: ${gap.reason}`;
  jscpdGaps.push({ scope: "(whole repo product inventory)", reason });
}
const knipUncertainScopes: ScanGap[] = [];
// #810: scopes that only produced findings after the degraded (all-plugins-disabled) retry.
const knipReducedScopes: ScanGap[] = [];

// A root Knip graph can deliberately omit a workspace. A successful child process alone cannot
// establish that every member in Harvey's product inventory was examined by that graph.
function rootGraphExclusion(root: string, scope: string): string | undefined {
  const config = scopeKnipConfig(root);
  const member = relative(root, scope).replaceAll("\\", "/") || ".";
  if (!config || "unresolved" in config) {
    return `Knip's root workspace configuration could not be inspected for ${member}; its examined population is unverified`;
  }
  const patterns = config.value.ignoreWorkspaces;
  if (!Array.isArray(patterns)) return undefined;
  const active = patterns.filter((pattern): pattern is string => typeof pattern === "string" && !pattern.endsWith("!"));
  const exceptions = active.filter((pattern) => pattern.startsWith("!")).map((pattern) => pattern.slice(1));
  let matcher: { isMatch: (path: string, pattern: string, options?: { ignore?: string[] }) => boolean };
  try {
    const knipRequire = createRequire(realpathSync(join(repoRoot, "node_modules", "knip", "package.json")));
    matcher = knipRequire("picomatch") as typeof matcher;
  } catch (err) {
    return `Knip's workspace matcher could not be loaded for ${member}; its examined population is unverified: ${err instanceof Error ? err.message : String(err)}`;
  }
  const ignored = active.find((pattern) => !pattern.startsWith("!")
    && matcher.isMatch(member, pattern.replace(/^\.\//, ""), { ignore: exceptions }));
  return ignored ? `Knip root configuration ignoreWorkspaces includes ${member} via ${ignored}; this product source population was not assessed` : undefined;
}
// #696: files whose scope had Harvey-inferred entries — their unused-FILE findings are review tier.
const inferredEntryFiles = new Set<string>();
// #1050: the same scopes' package.json paths — their unused-DEPENDENCY findings are review tier for
// the same reason (config-only usages are invisible when the config could not be resolved).
const unresolvedDepScopes = new Set<string>();
// #1871: package metadata from a no-lockfile preparation failure has neither an installed graph
// nor a reproducible resolved dependency surface. It remains visible but informational. This is
// narrower than `pluginsDisabled`: automatic config-load fallback and lockfile-backed install
// failure retain the established reduced-tier semantics and corpus conservation.
const unresolvedDependencySurfacePaths = new Set<string>();
// Config-file and type-only unlisted-import verdicts need the target's resolver/config context.
// In the plugins-disabled tier the references remain visible, but these paths are informational.
const unresolvedUnlistedImportPaths = new Set<string>();

// #544: one whole-repo jscpd pass — paths already come back relative to targetDir, so no
// per-workspace re-anchoring is needed. See the header for why duplication is measured whole-repo.
try {
  jscpdReports.push(runJscpd(targetDir));
} catch (err) {
  const reason = gapReason(err);
  jscpdGaps.push({ scope: "(whole repo)", reason });
  console.error(`⚠ jscpd ${isTimeout(err) ? "timed out" : "failed"} on the whole repo — M4 coverage incomplete: ${reason}`);
}

// A root Knip workspace config is a single configuration graph: splitting it into member cwd
// runs discards root workspaces.entry/project/ignore. A direct member entry point runs the same
// graph, then selects that member's results. Otherwise retain independent member runs from #505.
const ancestorMembers = ancestorWorkspaceConfig
  ? new Set([
      ...discoverWorkspaceInventory(ancestorWorkspaceConfig.root).packages.map((pkg) => join(ancestorWorkspaceConfig.root, pkg.dir)),
      ...await configuredKnipWorkspaceDirs(ancestorWorkspaceConfig.root),
    ])
  : new Set<string>();
const ancestorCovered = ancestorWorkspaceConfig
  ? scopes.filter((dir) => dir === targetDir || ancestorMembers.has(dir)) : [];
const knipRuns: Array<{ dir: string; covered: string[]; stripPrefix?: string; graphRoot?: string }> = rootWorkspaceConfig
  ? [{ dir: targetDir, covered: scopes, graphRoot: targetDir }]
  : ancestorWorkspaceConfig
    ? [
        { dir: ancestorWorkspaceConfig.root, covered: ancestorCovered, stripPrefix: `${ancestorWorkspaceConfig.member}/`, graphRoot: ancestorWorkspaceConfig.root },
        ...scopes.filter((dir) => !ancestorCovered.includes(dir)).map((dir) => ({ dir, covered: [dir] })),
      ]
    : scopes.map((dir) => ({ dir, covered: [dir] }));
const deepestScopes = [...scopes].sort((left, right) => right.length - left.length);
for (const run of knipRuns) {
  const label = run.covered.map(scopeLabel).join(", ");
  const runInventory = run.dir === targetDir ? sourceInventory : productSourceInventoryForTarget(run.dir);
  for (const gap of runInventory.unresolvedConfigurations) {
    for (const covered of run.covered) knipGaps.push({ scope: scopeLabel(covered), reason: `${gap.path}: ${gap.reason}` });
  }
  const targetRelativePath = (path: string): string => {
    if (run.stripPrefix) {
      if (!path.startsWith(run.stripPrefix)) throw new Error(`Knip emitted a path outside ${run.stripPrefix}: ${path}`);
      return path.slice(run.stripPrefix.length);
    }
    return prefixed(relative(targetDir, run.dir), path);
  };
  try {
    const { report, entriesInferred, pluginsDisabled, reducedReason } = degradedKnipReason
      ? runKnipDegraded(run.dir, degradedKnipReason, runInventory)
      : runKnip(run.dir, runInventory);
    const ownedByRun = (path: string): boolean => {
      if (run.stripPrefix && !path.startsWith(run.stripPrefix)) return false;
      const targetPath = targetRelativePath(path).replaceAll("\\", "/");
      const owner = deepestScopes.find((scope) => scope !== targetDir
        && targetPath.startsWith(`${relative(targetDir, scope).replaceAll("\\", "/")}/`)) ?? targetDir;
      return run.covered.includes(owner);
    };
    report.files = report.files.filter(ownedByRun);
    report.issues = report.issues.filter((issue) => ownedByRun(issue.file));
    if (pluginsDisabled) {
      for (const issue of report.issues) {
        let source: string | undefined;
        try {
          source = readFileSync(join(run.dir, issue.file), "utf8");
        } catch {
          // A source read failure leaves the narrow boundary unclassified.
        }
        if (unlistedImportNeedsResolvedConfig(issue, source, workspacePackageNames)) {
          unresolvedUnlistedImportPaths.add(targetRelativePath(issue.file));
        }
      }
    }
    // #810: a scope that only ran after the degraded retry is disclosed as a reduced-mode partial
    // (M5-98). Its file findings are already review-tier via entriesInferred below. The #580
    // entry-uncertain heuristic is skipped for it — its high unused ratio is the EXPECTED cost of a
    // plugins-disabled run, already explained by M5-98, not a separate mis-resolution signal.
    if (pluginsDisabled) {
      for (const covered of run.covered) knipReducedScopes.push({ scope: scopeLabel(covered), reason: reducedReason ?? "knip could not load the target's config" });
      console.error(
        degradedKnipReason
          ? `⚠ dependency preparation was incomplete for ${label} — ran knip directly with target configs/plugins disabled; M5 file findings for it are source-only review tier (#1871, see M5-98)`
          : `⚠ knip could not load ${label}'s config (likely no node_modules) — re-ran with plugins disabled; M5 file findings for it are review-tier (#810, see M5-98)`,
      );
    } else {
      // #580: computed BEFORE re-anchoring report.files below — knipEntryUncertainReason's ratio
      // only cares about the count. A root-config run spans its whole repo; direct member output
      // is selected first and uses the member's product population for that denominator.
      const observedDir = run.stripPrefix ? targetDir : run.dir;
      const observedInventory = run.stripPrefix ? sourceInventory : runInventory;
      const uncertainReason = knipEntryUncertainReason(report, countSourceFiles(observedDir, "", observedInventory), hasViteEntryMarkers(observedDir), isViteResolvable(observedDir));
      if (uncertainReason) knipUncertainScopes.push({ scope: label, reason: uncertainReason });
    }
    report.files = report.files.map(targetRelativePath);
    for (const issue of report.issues) issue.file = targetRelativePath(issue.file);
    if (pluginsDisabled && degradedKnipUnresolvedDependencySurface) {
      for (const issue of report.issues) unresolvedDependencySurfacePaths.add(issue.file);
    }
    // #696: record the (now target-relative) files whose entries Harvey inferred, so their file
    // findings are review-tier after mergeKnipReports flattens per-scope reports into one.
    if (entriesInferred) {
      for (const f of report.files) inferredEntryFiles.add(f);
      for (const issue of report.issues) unresolvedDepScopes.add(issue.file);
    }
    knipReports.push(report);
  } catch (err) {
    const reason = degradedKnipReason ? `${degradedKnipReason}; source-only Knip failed: ${gapReason(err)}` : gapReason(err);
    for (const covered of run.covered) knipGaps.push({ scope: scopeLabel(covered), reason });
    console.error(`⚠ knip ${isTimeout(err) ? "timed out" : "failed"} on ${label} — M5 dead-code coverage skipped for this scope: ${reason}`);
  }
}

for (const run of knipRuns) {
  if (!run.graphRoot) continue;
  for (const scope of run.covered) {
    const reason = rootGraphExclusion(run.graphRoot, scope);
    if (reason) knipGaps.push({ scope: scopeLabel(scope), reason });
  }
}

const jscpdReport = mergeJscpdReports(jscpdReports);

// #360/#399: the Type-3 near-miss layer jscpd structurally cannot provide — diverged copies of
// security checks. Scoped to securityPathFiles's admitted subset (touchesSecurityPath OR
// touchesTenantSupabasePath).
const observedProductSources = new Set<string>();
const narrowFiles = securityPathFiles(targetDir, "", observedProductSources);
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

// #1080: disclose the security-path-only scope of the pass above when nothing wider ran — suppressed
// once --whole-repo-diverged covers the remainder itself (nothing was skipped in that case).
const eligibleFileCount = observedProductSources.size;
const memberScopes = scopes.filter((scope) => scope !== targetDir)
  .sort((left, right) => right.length - left.length);
const excludedWorkspaceReasons = new Map<string, string>();
for (const observation of discoverWorkspaceInventory(targetDir).observations) {
  if (observation.kind !== "excluded") continue;
  const dir = observation.path.replace(/\/package\.json$/, "");
  if (dir === observation.path || dir === ".") continue;
  excludedWorkspaceReasons.set(dir, `${observation.sourcePath} declares ${observation.glob}, which excludes ${dir} (${observation.reason})`);
}
const excludedWorkspaceDirs = [...excludedWorkspaceReasons.keys()].sort((left, right) => right.length - left.length);
const sourcePathsByScope = new Map<string, string[]>(scopes.map((scope) => [scopeLabel(scope), []]));
for (const path of observedProductSources) {
  const member = memberScopes.find((scope) => path.startsWith(`${relative(targetDir, scope).replaceAll("\\", "/")}/`));
  const excluded = excludedWorkspaceDirs.find((dir) => path.startsWith(`${dir}/`));
  const label = member ? scopeLabel(member) : excluded ?? "(repo root)";
  const paths = sourcePathsByScope.get(label);
  if (paths) paths.push(path);
  else sourcePathsByScope.set(label, [path]);
}
for (const [dir, reason] of excludedWorkspaceReasons) {
  const paths = sourcePathsByScope.get(dir) ?? [];
  if (paths.length > 0) knipGaps.push({ scope: dir, reason: `${paths.length} product source file(s) were not assessed by Knip: ${reason}` });
}
const unexaminedRootPaths = scopes.includes(targetDir) ? [] : sourcePathsByScope.get("(repo root)") ?? [];
if (unexaminedRootPaths.length > 0) {
  knipGaps.push({
    scope: "(repo root)",
    reason: `${unexaminedRootPaths.length} root or undeclared product source file(s) were not assessed by Knip: this target has member-scoped runs and no root Knip workspace configuration; rerun after adding a root workspace config or a root-only Knip scope.`,
  });
}
const knipReceiptLabels = [...new Set([...scopes.map(scopeLabel), ...knipGaps.map((gap) => gap.scope)])].sort();
const zeroSourceDisposition = eligibleFileCount === 0 ? {
  status: "not-assessed" as const,
  reason: [
    "quality-scan read no eligible JavaScript/TypeScript product sources; its source passes were not assessed.",
    ...sourceInventory.unresolvedConfigurations.map((gap) => `${gap.path}: ${gap.reason}`),
  ].join(" "),
  provenance: "MEASURED: quality-scan completed its in-process product-source walk with 0 admitted files after applying the target source inventory.",
  falsifier: "Rerun quality-scan --scope-out after adding an admitted product source or repairing the disclosed source boundary; a nonempty observed path digest invalidates this zero-source disposition.",
} : undefined;
const knipIncompleteScopeLabels = [...new Set(knipGaps.map((gap) => gap.scope))].sort();
const knipReducedScopeLabels = [...new Set(knipReducedScopes.map((scope) => scope.scope))].sort();
const knipPopulations = knipReceiptLabels.map((scope) => {
  const paths = sourcePathsByScope.get(scope) ?? [];
  const gaps = knipGaps.filter((gap) => gap.scope === scope);
  const status = gaps.length > 0 ? "incomplete" as const
    : knipReducedScopeLabels.includes(scope) ? "reduced" as const : "completed" as const;
  const scopeDir = scope === "(repo root)" ? targetDir : join(targetDir, scope);
  const configuration = (scope === "(repo root)" && unexaminedRootPaths.length > 0) || excludedWorkspaceReasons.has(scope)
    ? "none" as const
    : rootWorkspaceConfig || (ancestorWorkspaceConfig && ancestorCovered.includes(scopeDir))
    ? "root-workspace-config" as const
    : scopeKnipConfig(scopeDir) ? "local-config" as const : "harvey-inferred" as const;
  return {
    scope, productSources: paths.length, pathsDigest: digestObservedPaths(paths), status, configuration,
    ...(gaps.length > 0 ? { reason: gaps.map((gap) => gap.reason).join("; ") } : {}),
  };
});
const divergedScopeDisclosure = wholeRepoDiverged || eligibleFileCount === 0
  ? undefined
  : divergedScopeFinding(narrowFiles.length, eligibleFileCount);

const knipReport = knipReports.length ? mergeKnipReports(knipReports) : undefined;

const fileLineCounts: Record<string, number> = {};
if (knipReport) {
  for (const file of knipReport.files) {
    const n = lineCount(targetDir, file);
    if (n !== undefined) fileLineCounts[file] = n;
  }
}

// #1080: file counts the ignore globs excluded, disclosed as M4-SCOPE-00 (see jscpdIgnoreScopeFinding's
// header for why this is its own walk rather than reusing countSourceFiles/securityPathFiles).
const jscpdGlobMatches = tallyJscpdIgnoredFiles(targetDir);
const jscpdScopeDisclosure = jscpdIgnoreScopeFinding(jscpdGlobMatches);

const findings: Finding[] = [
  ...jscpdToFindings(jscpdReport),
  ...divergedFindings,
  ...wholeRepoDivergedFindings,
  ...(divergedScopeDisclosure ? [divergedScopeDisclosure] : []),
  ...(jscpdScopeDisclosure ? [jscpdScopeDisclosure] : []),
  ...(knipReport
    ? knipToFindings(
        knipReport,
        fileLineCounts,
        inferredEntryFiles,
        unresolvedDepScopes,
        unresolvedDependencySurfacePaths,
        unresolvedUnlistedImportPaths,
      )
    : []),
];
// #505: a gap disclosure coexists with real findings from the scopes that DID complete — unlike
// the old whole-repo-or-nothing shape, a monorepo run can be a genuine partial (2 of 3 workspaces
// scanned clean, 1 timed out).
if (knipGaps.length) findings.push(knipUnavailableFinding(knipGaps.map((g) => `${g.scope}: ${g.reason}`).join("; ")));
else if (zeroSourceDisposition) findings.push(knipUnavailableFinding(zeroSourceDisposition.reason));
if (jscpdGaps.length) findings.push(jscpdUnavailableFinding(jscpdGaps.map((g) => `${g.scope}: ${g.reason}`).join("; ")));
else if (zeroSourceDisposition) findings.push(jscpdUnavailableFinding(zeroSourceDisposition.reason));
// #580: a completed-without-error knip run that still looks untrustworthy — disclosed separately
// from knipGaps (which is "didn't complete at all") so the two failure shapes stay distinguishable
// in the report.
if (knipUncertainScopes.length) findings.push(knipEntryUncertainFinding(knipUncertainScopes.map((g) => `${g.scope}: ${g.reason}`).join("; ")));
// #810: scopes that produced findings only via the degraded (no-target-deps) retry — a visible
// reduced-mode partial, distinct from "didn't complete" (M5-00) and "completed but uncertain" (M5-99).
if (knipReducedScopes.length) findings.push(knipReducedTierFinding(knipReducedScopes.map((g) => `${g.scope}: ${g.reason}`).join("; ")));

const dup = duplicationSummary(jscpdReport);
console.error(
  // #1109: `${dup.duplicatedLines}/${dup.totalLines} lines` is M4's unit of examination — the audit
  // orchestrator reads the total off stderr to say how much source jscpd actually compared.
  `M4 duplication: ${dup.percentage}% (${dup.duplicatedLines}/${dup.totalLines} lines) — ${jscpdReport.duplicates.length} clone cluster(s), ${dup.subThresholdCloneCount} sub-threshold small clone(s) disclosed in M4-00 (#365), ${dup.selfFileCloneCount} sub-threshold self-file clone(s) disclosed in M4-SELF-00 (#1080/#1095), ${divergedFindings.length} diverged security-path clone pair(s) (#360, review tier)` +
    (jscpdGaps.length ? `, whole-repo scan incomplete (#544, see M4-99)` : "") +
    (jscpdScopeDisclosure ? `, ${jscpdGlobMatches.reduce((sum, m) => sum + m.count, 0)} file(s) excluded by ignore globs disclosed in M4-SCOPE-00 (#1080)` : "") +
    (divergedScopeDisclosure ? `, diverged-clone pass covered ${narrowFiles.length}/${eligibleFileCount} eligible files (#1080, see M4-97)` : "") +
    (wholeRepoDiverged ? `, ${wholeRepoDivergedFindings.filter((f) => f.id !== "M4-98").length} diverged clone(s) outside the security path (#809, review tier)` : ""),
);
if (knipReport) {
  console.error(
    // #1109: the scope count leads the line because it is M5's unit of examination — the audit
    // orchestrator reads it off stderr to say what knip actually looked at (src/audit-runners.ts).
    `M5 dead code across ${scopes.length} scope(s): ${knipReport.files.length} unused file(s), ${knipReport.issues.filter((i) => i.exports.length + i.types.length > 0).length} file(s) with unused exports, ` +
      `${knipReport.issues.reduce((sum, i) => sum + (i.dependencies?.length ?? 0) + (i.devDependencies?.length ?? 0), 0)} unused dependenc(ies) (#1050)` +
      (knipIncompleteScopeLabels.length ? `, ${knipIncompleteScopeLabels.length}/${scopes.length} scope(s) incomplete (#505, see M5-00)` : "") +
      (knipReducedScopeLabels.length ? `, ${knipReducedScopeLabels.length}/${scopes.length} scope(s) ran in reduced no-deps mode (#810, see M5-98)` : "") +
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
writeCorpusScannerScope(scopeOutPath, "quality-scan", {
  unitsExamined: eligibleFileCount,
  description: `${eligibleFileCount} product source file(s) read by quality-scan's in-process source passes`,
  observation: {
    scanner: "quality-scan",
    productSources: { count: eligibleFileCount, pathsDigest: digestObservedPaths([...observedProductSources]) },
    jscpd: { status: jscpdGaps.length > 0 ? "incomplete" : "completed", comparedLines: dup.totalLines },
    knip: {
      discovered: knipReceiptLabels,
      completed: knipReceiptLabels.filter((scope) => !knipIncompleteScopeLabels.includes(scope)),
      reduced: knipReducedScopeLabels.filter((scope) => !knipIncompleteScopeLabels.includes(scope)),
      incomplete: knipIncompleteScopeLabels,
      populations: knipPopulations,
    },
    divergedClones: {
      securityPathSources: narrowFiles.length,
      wholeRepoEnabled: wholeRepoDiverged,
      complementSources: wholeRepoDiverged ? Math.max(0, eligibleFileCount - narrowFiles.length) : 0,
    },
    ...(zeroSourceDisposition ? { zeroSourceDisposition } : {}),
  },
});
