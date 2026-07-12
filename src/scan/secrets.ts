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
  // B9 (#71) additions — each is a dedicated-format prefix or a published constant whose match
  // alone is ~100% precision: the unrotated self-hosted default JWT secret, non-DB URIs with
  // inline creds, a hardcoded Authorization Bearer literal, an npm automation token (npm_ + 36),
  // and a Slack incoming-webhook URL (hooks.slack.com/services/…).
  "supabase-default-jwt-secret",
  "harvey-uri-credentials",
  "harvey-http-authorization-bearer",
  "npm-access-token",
  "slack-webhook-url",
]);

// Rule IDs used purely as internal correlation markers (gitleaks-supabase.toml) — never a
// user-facing finding on their own. See parseGitleaksFindings below.
const CORRELATION_MARKER_RULES = new Set(["supabase-demo-key-marker", "harvey-test-idp-marker"]);

// Per-rule "why it matters" text for high-precision hits. Only supabase-service-role-jwt's claim
// is actually about a decoded JWT role — every other high-precision rule (private-key,
// sb_secret_, DB URIs, …) was previously getting that same JWT-specific sentence (#211).
const HIGH_PRECISION_IMPACT: Partial<Record<string, string>> = {
  "supabase-service-role-jwt": "Decoded JWT role claim confirms this is a service-role key — full database bypass of RLS.",
};
const DEFAULT_HIGH_IMPACT = "An unambiguous committed credential; treat it as live until proven otherwise.";

const CI_WORKFLOW_PATH = /(^|\/)\.github\/workflows\//;

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

// Known-public/test-credential recognizer (#225, generalizing #210 + #211). gitleaks decodes JWT
// bodies and reports each rule match independently, so a demo/test credential and the marker that
// identifies it as such land as separate GitleaksResult entries sharing a file (and often a line):
//   - a high-precision hit sharing a file+line with the decoded "supabase-demo" iss claim is the
//     well-known local-dev demo key (public by design, ships with every `supabase start`) —
//     dropped entirely, same as the anon key allowlist above (#210).
//   - a `private-key` hit sharing a FILE with a test/example SAML IdP marker, inside a CI
//     workflow, is a test-fixture keypair — down-ranked to review instead of dropped, since a
//     private key still deserves a human look (#211).
export function parseGitleaksFindings(results: GitleaksResult[], scope: string): Finding[] {
  const demoKeyLocations = new Set(
    results.filter((r) => r.RuleID === "supabase-demo-key-marker").map((r) => `${r.File}:${r.StartLine ?? 0}`),
  );
  const testIdpFiles = new Set(results.filter((r) => r.RuleID === "harvey-test-idp-marker").map((r) => r.File));

  return results
    .filter((r) => !CORRELATION_MARKER_RULES.has(r.RuleID))
    .filter((r) => !demoKeyLocations.has(`${r.File}:${r.StartLine ?? 0}`))
    .map((r, i) => {
      const testIdpPrivateKey = r.RuleID === "private-key" && CI_WORKFLOW_PATH.test(r.File) && testIdpFiles.has(r.File);
      const high = HIGH_PRECISION_GITLEAKS_RULES.has(r.RuleID) && !testIdpPrivateKey;
      const evidence = `gitleaks rule "${r.RuleID}" matched: ${r.Match ?? r.Secret ?? "(match redacted)"}.`;
      return mechanicalFinding({
        id: `SEC-GL-${scope}-${i + 1}`,
        title: `${r.Description ?? r.RuleID} (${r.RuleID})`,
        severity: high ? "Critical" : "High",
        category: "Secret exposure",
        taxonomy: high ? "Committed credential" : "Possible committed credential",
        location: `[${scope}] ${r.File}${r.StartLine ? `:${r.StartLine}` : ""}${r.Commit ? ` (commit ${r.Commit.slice(0, 12)})` : ""}`,
        evidence: testIdpPrivateKey
          ? `${evidence} Down-ranked from Critical: this file also carries a test/example SAML IdP marker (ENTITY_ID / *.example.com) in a CI workflow — treat as a test fixture, confirm before escalating.`
          : evidence,
        impact: high ? (HIGH_PRECISION_IMPACT[r.RuleID] ?? DEFAULT_HIGH_IMPACT) : "Pattern match on a potential secret; confirm before treating as a live credential.",
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
//
// sourceDir and historyDir are usually the same directory, but mechanical.ts passes a scoped,
// tracked-files-only copy as sourceDir (issue #101) — that copy has no `.git`, so the
// git-history pass needs the real, clonable original directory instead (historyDir).
export function scanSecrets(sourceDir: string, historyDir: string, bundleDir?: string): Finding[] {
  const findings: Finding[] = [
    ...parseTruffleHogFindings(runTruffleHogFilesystem(sourceDir), "source"),
    ...parseTruffleHogFindings(runTruffleHogGitHistory(historyDir), "git-history"),
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
