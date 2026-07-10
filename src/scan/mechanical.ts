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
import { checkKnownDependencyCVEs, checkNextVersionCVEs, parseOsvFindings, type OsvScanResult } from "./dependencies.js";
import { scanLeftoverAuth } from "./leftover-auth.js";
import { resolveScanScope } from "./scan-scope.js";
import { scanSecrets } from "./secrets.js";
import { checkMissingCsp, parseSemgrepFindings, runSemgrep } from "./semgrep.js";
import { checkInstallScripts, checkKnownIoc, checkLockfilePresence, checkNonRegistryDependencies, checkSlopsquat, checkTyposquat, checkUnpinnedDependencies, type DependencyMap } from "./supply-chain.js";

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

function runOsvScanner(dir: string): OsvScanResult {
  const lockfile = LOCKFILES.find((f) => existsSync(join(dir, f)));
  if (!lockfile) return {};
  let out: string;
  try {
    out = execFileSync("osv-scanner", ["--format", "json", "--lockfile", join(dir, lockfile)], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024 * 64,
    });
  } catch (err) {
    // osv-scanner exits 1 when it finds vulnerabilities — stdout still has the report.
    const e = err as { stdout?: string };
    if (typeof e.stdout === "string" && e.stdout.length > 0) out = e.stdout;
    else return {};
  }
  return out.trim() ? (JSON.parse(out) as OsvScanResult) : {};
}

interface MechanicalScanOptions {
  dir: string;
  bundleDir?: string; // .next/static after `next build`, if available — passed to the secret scan
}

export async function runMechanicalScan(opts: MechanicalScanOptions): Promise<Finding[]> {
  const { dir, bundleDir } = opts;

  // Scope the walk to what should actually be scanned (issue #101): git-tracked files only
  // when dir is a git repo (excludes .env.local, .claude/worktrees/, node_modules, .next —
  // whatever's untracked/gitignored — while keeping deliberately-committed fixtures), or a
  // hard exclude list for a non-git target (zip export). Every filesystem-walking tool below
  // gets the scoped copy; only the git-history secret pass needs the real `dir` (it clones
  // the actual .git, which the scoped copy doesn't have).
  const { scanDir, cleanup } = resolveScanScope(dir);
  try {
    const findings: Finding[] = [];

    // Secrets — source, git history, and built bundle if present.
    findings.push(...scanSecrets(scanDir, dir, bundleDir && existsSync(bundleDir) ? bundleDir : undefined));

    // Framework/dependency CVEs.
    findings.push(...parseOsvFindings(runOsvScanner(scanDir)));
    const pkg = readPackageJson(scanDir);
    const nextVersion = pkg?.dependencies?.next ?? pkg?.devDependencies?.next;
    if (nextVersion) findings.push(...checkNextVersionCVEs(nextVersion.replace(/^[\^~]/, "")));

    // Semgrep footguns + missing-CSP config check.
    findings.push(...parseSemgrepFindings(runSemgrep(scanDir)));
    findings.push(...checkMissingCsp(scanDir));

    // Supply chain.
    if (pkg) {
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      findings.push(...checkTyposquat(Object.keys(allDeps)));
      findings.push(...checkKnownIoc(Object.keys(allDeps)));
      findings.push(...checkKnownDependencyCVEs(allDeps));
      findings.push(...checkUnpinnedDependencies(allDeps));
      findings.push(...checkNonRegistryDependencies(allDeps));
      findings.push(...checkInstallScripts(pkg.scripts ?? {}));
      findings.push(...(await checkSlopsquat(Object.keys(allDeps))));
    }
    findings.push(...checkLockfilePresence(scanDir));

    // Leftover-auth greps.
    findings.push(...scanLeftoverAuth(scanDir));

    return findings;
  } finally {
    cleanup();
  }
}
