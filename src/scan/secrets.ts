// Secret exposure: TruffleHog (--only-verified) + gitleaks (custom Supabase rules).
//
// Both are external CLI binaries this module shells out to — neither is an npm dependency.
// Install: `brew install trufflehog gitleaks` (or see their GitHub releases). Requires each
// binary on PATH; runTruffleHog/runGitleaks throw if the binary is missing.
//
// Invocations (three passes each — source tree, git history, built bundle):
//   trufflehog filesystem --only-verified --json <dir>
//   trufflehog git --only-verified --json file://<repo>
//   gitleaks detect --no-git -s <dir> --config src/scan/rules/gitleaks-supabase.toml \
//     --max-decode-depth 2 --report-format json --report-path <tmp>
//
// TruffleHog verified hits and the gitleaks "supabase-service-role-jwt" rule are ~100%
// precision (live-verified / decoded-claim ground truth) → precisionTier "high". Every other
// gitleaks rule (default ruleset + our regex-only custom rules) is unverified pattern-match →
// "review". The anon key and .env.example are allowlisted in the gitleaks config, not here.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "../findings.js";
import { mechanicalFinding } from "./common.js";

const GITLEAKS_CONFIG = new URL("./rules/gitleaks-supabase.toml", import.meta.url).pathname;
// Rules whose match alone is ~100%-precision (no live verification needed): the decoded
// service_role JWT claim, the sb_secret_ / connection-string / private-key prefixes — all
// unambiguous committed credentials. Every other gitleaks rule (provider patterns that only
// TruffleHog verification would confirm, entropy/generic matches) stays "review".
const HIGH_PRECISION_GITLEAKS_RULES = new Set([
  "supabase-service-role-jwt",
  "supabase-secret-key",
  "harvey-db-uri-credentials",
  "private-key",
]);

export interface TruffleHogResult {
  DetectorName?: string;
  Verified?: boolean;
  Redacted?: string;
  SourceMetadata?: {
    Data?: {
      Filesystem?: { file?: string; line?: number };
      Git?: { file?: string; line?: number; commit?: string };
    };
  };
}

export interface GitleaksResult {
  RuleID: string;
  Description?: string;
  File: string;
  StartLine?: number;
  Commit?: string;
  Match?: string;
  Secret?: string;
}

function location(r: TruffleHogResult): string {
  const fs = r.SourceMetadata?.Data?.Filesystem;
  const git = r.SourceMetadata?.Data?.Git;
  if (git?.file) return `${git.file}:${git.line ?? "?"} (commit ${git.commit?.slice(0, 12) ?? "?"})`;
  if (fs?.file) return `${fs.file}:${fs.line ?? "?"}`;
  return "unknown location";
}

// scope labels the pass this batch of results came from (source / git-history / built bundle)
// so the Finding location makes clear where the secret actually lives.
export function parseTruffleHogFindings(results: TruffleHogResult[], scope: string): Finding[] {
  return results
    .filter((r) => r.Verified)
    .map((r, i) =>
      mechanicalFinding({
        id: `SEC-TH-${scope}-${i + 1}`,
        title: `Verified secret: ${r.DetectorName ?? "unknown detector"}`,
        severity: "Critical",
        category: "Secret exposure",
        taxonomy: "Committed credential",
        location: `[${scope}] ${location(r)}`,
        evidence: `TruffleHog verified detector "${r.DetectorName ?? "unknown"}" against the live provider: ${r.Redacted ?? "(redacted)"}.`,
        impact: "A verified, live credential is exposed; anyone with repo/bundle access can use it directly.",
        fix: "Rotate the credential immediately, then remove it from source (and git history if committed).",
        precisionTier: "high",
      }),
    );
}

export function parseGitleaksFindings(results: GitleaksResult[], scope: string): Finding[] {
  return results.map((r, i) => {
    const high = HIGH_PRECISION_GITLEAKS_RULES.has(r.RuleID);
    return mechanicalFinding({
      id: `SEC-GL-${scope}-${i + 1}`,
      title: `${r.Description ?? r.RuleID} (${r.RuleID})`,
      severity: high ? "Critical" : "High",
      category: "Secret exposure",
      taxonomy: high ? "Committed credential" : "Possible committed credential",
      location: `[${scope}] ${r.File}${r.StartLine ? `:${r.StartLine}` : ""}${r.Commit ? ` (commit ${r.Commit.slice(0, 12)})` : ""}`,
      evidence: `gitleaks rule "${r.RuleID}" matched: ${r.Match ?? r.Secret ?? "(match redacted)"}.`,
      impact: high
        ? "Decoded JWT role claim confirms this is a service-role key — full database bypass of RLS."
        : "Pattern match on a potential secret; confirm before treating as a live credential.",
      fix: "Rotate the credential if live, remove from source/history, and add to .gitignore.",
      precisionTier: high ? "high" : "review",
    });
  });
}

function runJson<T>(bin: string, args: string[]): T[] {
  let out: string;
  try {
    out = execFileSync(bin, args, { encoding: "utf8", maxBuffer: 1024 * 1024 * 64 });
  } catch (err) {
    const e = err as { stdout?: string; code?: number };
    // trufflehog/gitleaks exit non-zero when findings exist — stdout still has the report.
    if (typeof e.stdout === "string" && e.stdout.length > 0) out = e.stdout;
    else throw err;
  }
  if (!out.trim()) return [];
  // trufflehog emits newline-delimited JSON; gitleaks emits a single JSON array.
  const trimmed = out.trim();
  if (trimmed.startsWith("[")) return JSON.parse(trimmed) as T[];
  return trimmed
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as T);
}

function runTruffleHogFilesystem(dir: string): TruffleHogResult[] {
  return runJson<TruffleHogResult>("trufflehog", ["filesystem", "--only-verified", "--json", dir]);
}

// trufflehog's git pass clones the target as a repo, so it only works when the scan target is a
// git repo ROOT. A subdirectory of a repo (e.g. targets/calibration inside this repo) has no
// clonable .git and would error — there's simply no separate history to scan, so skip it.
function isGitRepoRoot(dir: string): boolean {
  try {
    const top = execFileSync("git", ["-C", dir, "rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
    return realpathSync(top) === realpathSync(dir);
  } catch {
    return false;
  }
}

function runTruffleHogGitHistory(repoDir: string): TruffleHogResult[] {
  if (!isGitRepoRoot(repoDir)) return [];
  return runJson<TruffleHogResult>("trufflehog", ["git", "--only-verified", "--json", `file://${repoDir}`]);
}

// gitleaks writes its report to a file (no stdout JSON mode), so scan into a scratch dir
// and read the report back.
function runGitleaks(dir: string): GitleaksResult[] {
  const scratch = mkdtempSync(join(tmpdir(), "harvey-gitleaks-"));
  const reportPath = join(scratch, "report.json");
  try {
    execFileSync(
      "gitleaks",
      [
        "detect", "--no-git", "-s", dir,
        "--config", GITLEAKS_CONFIG,
        "--max-decode-depth", "2",
        "--report-format", "json",
        "--report-path", reportPath,
        "--exit-code", "0",
      ],
      { encoding: "utf8", maxBuffer: 1024 * 1024 * 64 },
    );
    const data = JSON.parse(readFileSync(reportPath, "utf8")) as GitleaksResult[] | null;
    return data ?? [];
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

// Runs all three secret-scan passes (source tree, git history, built .next/static bundle if
// present) and merges the results. bundleDir is optional — pass it only when a production
// build exists (`.next/static` after `next build`).
export function scanSecrets(sourceDir: string, bundleDir?: string): Finding[] {
  const findings: Finding[] = [
    ...parseTruffleHogFindings(runTruffleHogFilesystem(sourceDir), "source"),
    ...parseTruffleHogFindings(runTruffleHogGitHistory(sourceDir), "git-history"),
    ...parseGitleaksFindings(runGitleaks(sourceDir), "source"),
  ];
  if (bundleDir) {
    findings.push(
      ...parseTruffleHogFindings(runTruffleHogFilesystem(bundleDir), "bundle"),
      ...parseGitleaksFindings(runGitleaks(bundleDir), "bundle"),
    );
  }
  return findings;
}
