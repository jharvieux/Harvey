// Orchestrates the mechanical scan layer: secrets, dependency/framework CVEs, Semgrep
// footguns, supply chain, leftover-auth greps. Each sub-scanner shells out to its own CLI
// tool (see that module's header comment for install instructions) or walks the filesystem
// directly; this module runs them all and merges the resulting Finding[].
//
// CLI: `pnpm exec tsx src/cli/scan.ts --mechanical --dir <path> [--bundle <path>]`

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../findings.js";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { loadSources, NON_PRODUCT } from "../detectors/load-sources.js";
import { scanBolaOwner } from "./bola-owner.js";
import { scanCounterRace } from "./counter-race.js";
import { scanPgIdor } from "./pg-idor.js";
import { scanPgResponseExposure } from "./pg-response-exposure.js";
import { scanSecretRotation } from "./secret-rotation.js";
import { scanServiceRoleLiteral } from "./service-role-literal.js";
import { scanEnvSchema } from "./env-schema.js";
import { checkKnownDependencyCVEs, checkNextVersionCVEs, osvUnavailableFinding, parseOsvFindings, type OsvScanResult } from "./dependencies.js";
import { checkHostingConfigHeaders } from "./hosting-headers.js";
import { scanJobTenantScope } from "./job-tenant-scope.js";
import { scanLeftoverAuth } from "./leftover-auth.js";
import { resolveScanScope } from "./scan-scope.js";
import { resolveBundleScan, scanSecrets } from "./secrets.js";
import { checkMissingCsp, checkPublicDirSensitive, parseSemgrepFindings, runSemgrep } from "./semgrep.js";
import {
  checkEdgeFunctionVerifyJwt,
  checkMigrationDefinerAnonGrant,
  checkMigrationDefinerAuthz,
  checkMigrationDynamicSqlInjection,
  checkMigrationPolicySemantics,
  checkMigrationRlsInitplanStatic,
  checkMigrationRlsStatic,
  checkOpenSignupConfig,
  inferAuthMethodsFromSource,
  type TenancyOverride,
} from "./supabase-static.js";
import { checkInstallScripts, checkKnownIoc, checkLicenseCompliance, checkLockfilePresence, checkNonRegistryDependencies, checkSlopsquat, checkTyposquat, checkUnpinnedDependencies, type DependencyMap } from "./supply-chain.js";
import { checkWebExtensionManifest } from "./webext-manifest.js";

interface PackageJson {
  dependencies?: DependencyMap;
  devDependencies?: DependencyMap;
  scripts?: Record<string, string>;
}

function readPackageJson(dir: string): PackageJson | null {
  const path = join(dir, "package.json");
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as PackageJson;
}

const LOCKFILES = ["pnpm-lock.yaml", "package-lock.json", "yarn.lock"];

function runOsvScanner(dir: string): { result: OsvScanResult; failure?: string } {
  const lockfile = LOCKFILES.find((f) => existsSync(join(dir, f)));
  // No lockfile is a target property, not a tool failure — checkLockfilePresence discloses it.
  if (!lockfile) return { result: {} };
  let out: string;
  try {
    out = execFileSync("osv-scanner", ["--format", "json", "--lockfile", join(dir, lockfile)], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024 * 64,
    });
  } catch (err) {
    // osv-scanner exits 1 when it finds vulnerabilities — stdout still has the report.
    const e = err as { stdout?: string; code?: string; message?: string };
    if (typeof e.stdout === "string" && e.stdout.length > 0) out = e.stdout;
    // #512: a failure with no report (binary missing, crash) must not silently cost the
    // engagement its CVE pass — surface the reason so the caller emits the disclosure finding.
    else return { result: {}, failure: e.code === "ENOENT" ? "osv-scanner not found on PATH" : (e.message ?? "osv-scanner failed with no output") };
  }
  return { result: out.trim() ? (JSON.parse(out) as OsvScanResult) : {} };
}

interface MechanicalScanOptions {
  dir: string;
  bundleDir?: string; // .next/static after `next build`, if available — passed to the secret scan
  // #280 — the same tenancy declaration detect-deeper.ts accepts at the connected tier
  // (--tenant-key/--tenant-mode), so the static RLS-tenancy inference can be told the app's
  // convention instead of only inferring it from the built-in candidate list.
  tenancyOverride?: TenancyOverride;
  // #267 — also run the M6 "looks hand-rolled" indicator detectors (Info-only, non-grading).
  // Opt-in: the free-report path (quick-scan) wants them; the calibration gate and the other
  // M1-scoring callers keep the M1-only default so their answer keys stay one-question keys.
  handrolledIndicators?: boolean;
  // Skip checkLicenseCompliance/checkSlopsquat — the only two live npm-registry calls in this
  // scan. Default false (real engagements always run both). The deterministic dry-run harness
  // (src/cli/dry-run.ts) is the one caller that opts in: its committed findings.json is supposed
  // to be reproducible across machines, and a registry-reachability dependency would let it drift
  // on an offline/blipped CI run for reasons that have nothing to do with the scanner's own code.
  skipNetworkChecks?: boolean;
}

export async function runMechanicalScan(opts: MechanicalScanOptions): Promise<Finding[]> {
  const { dir, bundleDir, tenancyOverride, handrolledIndicators, skipNetworkChecks } = opts;

  // Scope the walk to what should actually be scanned (issue #101): git-tracked files only
  // when dir is a git repo (excludes .env.local, .claude/worktrees/, node_modules, .next —
  // whatever's untracked/gitignored — while keeping deliberately-committed fixtures), or a
  // hard exclude list for a non-git target (zip export). Every filesystem-walking tool below
  // gets the scoped copy; only the git-history secret pass needs the real `dir` (it clones
  // the actual .git, which the scoped copy doesn't have).
  const { scanDir, cleanup } = resolveScanScope(dir);
  try {
    const findings: Finding[] = [];

    // Secrets — source, git history, and built bundle (auto-detected .next/static or dist/, #588).
    const bundle = resolveBundleScan(dir, bundleDir);
    findings.push(...scanSecrets(scanDir, dir, bundle.bundleDir));
    if (bundle.disclosure) findings.push(bundle.disclosure);

    // Framework/dependency CVEs.
    const osv = runOsvScanner(scanDir);
    findings.push(...(osv.failure ? [osvUnavailableFinding(osv.failure)] : parseOsvFindings(osv.result)));
    const pkg = readPackageJson(scanDir);
    const nextVersion = pkg?.dependencies?.next ?? pkg?.devDependencies?.next;
    if (nextVersion) findings.push(...checkNextVersionCVEs(nextVersion.replace(/^[\^~]/, "")));

    // Semgrep footguns + missing-CSP config check.
    findings.push(...parseSemgrepFindings(runSemgrep(scanDir)));
    findings.push(...checkMissingCsp(scanDir));
    findings.push(...checkHostingConfigHeaders(scanDir));
    findings.push(...checkPublicDirSensitive(scanDir));
    findings.push(...checkMigrationRlsStatic(scanDir));
    findings.push(...checkMigrationPolicySemantics(scanDir, tenancyOverride));
    findings.push(...checkMigrationDefinerAuthz(scanDir));
    findings.push(...checkMigrationDefinerAnonGrant(scanDir));
    findings.push(...checkMigrationDynamicSqlInjection(scanDir));
    findings.push(...checkMigrationRlsInitplanStatic(scanDir));
    findings.push(...checkEdgeFunctionVerifyJwt(scanDir));
    // #671 — gate the email-confirmation advisor on whether email auth is actually used (source
    // heuristic): an OAuth-only app gets a conditional note, not an asserted Medium.
    findings.push(...checkOpenSignupConfig(scanDir, inferAuthMethodsFromSource(scanDir)));
    findings.push(...checkWebExtensionManifest(scanDir));

    // Supply chain.
    if (pkg) {
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      findings.push(...checkTyposquat(Object.keys(allDeps)));
      findings.push(...checkKnownIoc(Object.keys(allDeps)));
      findings.push(...checkKnownDependencyCVEs(allDeps));
      findings.push(...checkUnpinnedDependencies(allDeps));
      findings.push(...checkNonRegistryDependencies(allDeps));
      findings.push(...checkInstallScripts(pkg.scripts ?? {}));
      if (!skipNetworkChecks) {
        findings.push(...(await checkSlopsquat(Object.keys(allDeps))));
        // #456 — license compliance (SPDX + copyleft/unknown flags).
        findings.push(...(await checkLicenseCompliance(allDeps)));
      }
    }
    findings.push(...checkLockfilePresence(scanDir));

    // Leftover-auth greps.
    findings.push(...scanLeftoverAuth(scanDir));

    // #353 — non-atomic read-modify-write race (AST dataflow over source files, incl. plain .js).
    findings.push(...scanCounterRace(scanDir));

    // #433 — authenticated pages/api handler scoping a service-role query by a request-supplied
    // owner id (BOLA). AST dataflow, incl. plain .js.
    findings.push(...scanBolaOwner(scanDir));

    // #663 — Express + pg repo-function IDOR: an authenticated handler passes a client-supplied
    // id straight into a name-gated read-by-id repo function, no ownership comparison.
    findings.push(...scanPgIdor(scanDir));

    // #701 (#663 remainder) — Express + pg excessive data exposure: res.json(...) names a
    // curated sensitive field directly, spreads a same-function object that does, or hands
    // back a same-function "SELECT *" row untouched.
    findings.push(...scanPgResponseExposure(scanDir));

    // #664 — service_role key hardcoded as a JWT literal (same-file or cross-file const) and
    // passed to createClient. Real base64 decode + role/iss claim check, incl. plain .js.
    findings.push(...scanServiceRoleLiteral(scanDir));

    // #681 — service-role query in a background-job path (Inngest/cron/queue/worker) with no
    // tenant predicate at all. AST dataflow, incl. plain .js.
    findings.push(...scanJobTenantScope(scanDir));
    // #680 — a static secret verified with a single equality/HMAC check and no dual-secret
    // rotation window (inter-service seams only; inert when no verify site exists).
    findings.push(...scanSecretRotation(scanDir));
    // #679 — env-schema completeness: `process.env.X` reads not declared in the target's env
    // schema module (undeclared read → finding; declared-but-unread → Info). No schema, no diff.
    findings.push(...scanEnvSchema(scanDir));

    // M6 free-tier indicators (#267) — product code only; test/fixture files aren't audit
    // findings. package.json stays in the set: the class-merge dep-gate reads it.
    if (handrolledIndicators) {
      findings.push(...detectHandrolledFindings(loadSources(scanDir).filter((f) => !NON_PRODUCT.test(f.path))));
    }

    return findings;
  } finally {
    cleanup();
  }
}
