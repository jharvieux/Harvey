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
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
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

// #934: documentation / example-deployment context. A gitleaks format match proves a string LOOKS
// like a credential, not that it is live — and in these paths the prior inverts: a credential-shaped
// string in docs, contrib/, an example file, or a *.dev.yml compose file is overwhelmingly a
// placeholder/default the project ships on purpose (measured on crbnos/carbon: all 14 Criticals the
// free tier graded F (0/100) on were exactly this — self-hosting docs, contrib/ deployment examples,
// dev docker-composes). The DECIDED product rule: such a hit is reported at Low, in full, with this
// reason stated — reclassified and routed to the free report's non-grading informational section
// (src/quick-scan.ts keys on the taxonomy below), NEVER dropped and never a graded Critical. A
// committed default password does get deployed, so it stays visible; it is just not the same finding
// as a live key in application source. TruffleHog VERIFIED hits are deliberately exempt — live
// verification against the provider outranks any path prior, so a real key pasted into docs still
// grades Critical.
const DOC_EXAMPLE_SEGMENT_RE = /(^|\/)(docs?|documentation|examples?|samples?|contrib)(\/|$)/i;
const DOC_EXAMPLE_FILE_RE = /(\.mdx?$)|(\.dev\.ya?ml$)|((example|sample)[^/]*$)/i;

export function isDocExamplePath(file: string): boolean {
  return DOC_EXAMPLE_SEGMENT_RE.test(file) || DOC_EXAMPLE_FILE_RE.test(file);
}

// The taxonomy quick-scan's non-grading routing keys on — the finding-level marker that this is a
// fact-precise format match whose exploitability prior is "placeholder until proven otherwise".
export const DOC_CONTEXT_CREDENTIAL_TAXONOMY = "Committed credential — docs/example context";

// DECISION (#308): findings render into a client-facing HTML/PDF report, so evidence must NOT
// reproduce a matched credential verbatim — on a real engagement that string is a LIVE secret.
// Default is to REDACT the matched value to a short identifying prefix + its length, e.g.
// `sk_test_51Q…[redacted, 44 chars]`. That keeps enough for triage to tell two hits on the same
// rule+file apart (prefix format marker + a few discriminating chars + length, plus file:line in
// the location) without quoting the secret back. Exception: rules whose "match" is a structural,
// non-secret claim — the decoded "role":"service_role" JWT body — are quoted as-is; they reveal
// nothing sensitive and the literal string is the whole signal. (TruffleHog evidence already
// carries only its own pre-redacted representation, so it needs no handling here.)
const NON_SECRET_MATCH_RULES = new Set(["supabase-service-role-jwt"]);

function redactMatch(raw: string): string {
  const prefixLen = Math.min(12, Math.ceil(raw.length / 2));
  return `${raw.slice(0, prefixLen)}…[redacted, ${raw.length} chars]`;
}

function gitleaksEvidenceMatch(r: GitleaksResult): string {
  const raw = r.Match ?? r.Secret;
  if (raw === undefined) return "(match redacted)";
  return NON_SECRET_MATCH_RULES.has(r.RuleID) ? raw : redactMatch(raw);
}

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
// gitleaks scans files concurrently and reports matches in whatever order its workers finish,
// so two runs over the same target can return the same finding set in different order — and
// since ids below are assigned positionally (SEC-GL-<scope>-N), that reshuffles ids across
// identical findings (#302). Sort into a stable order — file, line, rule, match — before the
// id-assigning map so reruns produce identical ids for the same finding.
function gitleaksSortKey(r: GitleaksResult): string {
  return `${r.File} ${String(r.StartLine ?? 0).padStart(10, "0")} ${r.RuleID} ${r.Match ?? r.Secret ?? ""}`;
}

export function parseGitleaksFindings(results: GitleaksResult[], scope: string): Finding[] {
  const demoKeyLocations = new Set(
    results.filter((r) => r.RuleID === "supabase-demo-key-marker").map((r) => `${r.File}:${r.StartLine ?? 0}`),
  );
  const testIdpFiles = new Set(results.filter((r) => r.RuleID === "harvey-test-idp-marker").map((r) => r.File));

  return results
    .filter((r) => !CORRELATION_MARKER_RULES.has(r.RuleID))
    .filter((r) => !demoKeyLocations.has(`${r.File}:${r.StartLine ?? 0}`))
    .sort((a, b) => gitleaksSortKey(a).localeCompare(gitleaksSortKey(b)))
    .map((r, i) => {
      const testIdpPrivateKey = r.RuleID === "private-key" && CI_WORKFLOW_PATH.test(r.File) && testIdpFiles.has(r.File);
      const high = HIGH_PRECISION_GITLEAKS_RULES.has(r.RuleID) && !testIdpPrivateKey;
      // #934: doc/example context only reclassifies a hit that would otherwise be a graded
      // Critical — review-tier matches are already out of the free grade and keep their tier.
      const docContext = high && isDocExamplePath(r.File);
      const evidence = `gitleaks rule "${r.RuleID}" matched: ${gitleaksEvidenceMatch(r)}.`;
      return mechanicalFinding({
        id: `SEC-GL-${scope}-${i + 1}`,
        title: `${r.Description ?? r.RuleID} (${r.RuleID})`,
        severity: docContext ? "Low" : high ? "Critical" : "High",
        category: "Secret exposure",
        taxonomy: docContext ? DOC_CONTEXT_CREDENTIAL_TAXONOMY : high ? "Committed credential" : "Possible committed credential",
        location: `[${scope}] ${r.File}${r.StartLine ? `:${r.StartLine}` : ""}${r.Commit ? ` (commit ${r.Commit.slice(0, 12)})` : ""}`,
        evidence: testIdpPrivateKey
          ? `${evidence} Down-ranked from Critical: this file also carries a test/example SAML IdP marker (ENTITY_ID / *.example.com) in a CI workflow — treat as a test fixture, confirm before escalating.`
          : docContext
            ? `${evidence} Reclassified from Critical (#934): the file sits in documentation/example-deployment content (docs, contrib, an example/sample file, or a *.dev.yml compose), where a credential-format match is overwhelmingly a shipped placeholder/default, not an application secret.`
            : evidence,
        impact: docContext
          ? "A default/placeholder-shaped credential in docs or an example deployment file. Not graded as a live secret — but a committed default does get deployed by whoever copies this file, so confirm it is a placeholder and that your own deployment rotated it."
          : high
            ? (HIGH_PRECISION_IMPACT[r.RuleID] ?? DEFAULT_HIGH_IMPACT)
            : "Pattern match on a potential secret; confirm before treating as a live credential.",
        fix: docContext
          ? "If this is a real credential, rotate it and remove it; if it is the intended placeholder, keep an obviously-fake value and a rotate-me instruction next to it."
          : "Rotate the credential if live, remove from source/history, and add to .gitignore.",
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
export function isGitRepoRoot(dir: string): boolean {
  try {
    const top = execFileSync("git", ["-C", dir, "rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
    // Compare by filesystem identity (device + inode), not realpath string equality (#619): on a
    // case-insensitive filesystem (macOS default) git reports the toplevel in the case it recorded
    // for the work tree, which can differ from the caller's `dir` (e.g. .../atc vs .../ATC). Two
    // realpath strings differing only in case then compare unequal and false-negative a valid repo
    // root — silently skipping the git-history secret scan on a full checkout. dev+ino identity is
    // case-insensitive and symlink-safe: the same file has one (dev, ino) regardless of path case.
    const a = statSync(top);
    const b = statSync(dir);
    return a.dev === b.dev && a.ino === b.ino;
  } catch {
    return false;
  }
}

function runTruffleHogGitHistory(repoDir: string): TruffleHogResult[] {
  return runJson<TruffleHogResult>("trufflehog", ["git", "--only-verified", "--json", `file://${repoDir}`]);
}

// #528: previously the isGitRepoRoot guard (added for #55) just returned [] with no disclosure,
// so a cold engagement delivered as an archive/subdirectory had the git-history secret tier
// silently unassessed — an unstated limitation that reads as a clean bill of health. Same
// disclosure contract as DEP-OSV-00/M4-99/M5-00: a visible not-assessed row, never a silent skip.
export function gitHistorySecretsUnavailableFinding(reason: string): Finding {
  return {
    id: "SEC-TH-GH-00",
    title: "Git-history secret scan (TruffleHog) did not run",
    severity: "Info",
    confidence: "N/A",
    category: "Secret exposure",
    taxonomy: "Committed credential — coverage not assessed",
    location: "(repo-wide)",
    status: "Open",
    evidence: `TruffleHog git-history pass did not run: ${reason}`,
    impact: "Git-history secret coverage for this engagement is incomplete for this pass — a disclosed coverage gap, not a finding of zero secrets committed to history.",
    fix: "Deliver the engagement as a full git checkout (not an archive/subdirectory export) and re-run the scan, or run `trufflehog git` directly against the client's repository.",
    value: 1,
    ease: 3,
    safety: 5,
  };
}

// #588 — the built bundle is where a client-inlined secret (Vite VITE_*, CRA REACT_APP_*, Next
// NEXT_PUBLIC_*) actually lands: the source has the reference, the BUILD OUTPUT has the value baked
// in. Auto-detect the build output generically when the caller passes no explicit --bundle:
// `.next/static` (Next) or `dist/` (Vite/rollup). The build output is normally gitignored, so this
// resolves against the real target dir (not the tracked-only scan copy). If neither exists, DISCLOSE
// that the bundle pass did not run rather than skipping silently — a "no bundle scanned" that reads
// as "no bundle secrets" is the #345 clean-bill-of-health trap.
const BUNDLE_CANDIDATES = [join(".next", "static"), "dist"];

export function resolveBundleScan(dir: string, explicit?: string): { bundleDir?: string; disclosure?: Finding } {
  if (explicit) {
    return existsSync(explicit)
      ? { bundleDir: explicit }
      : { disclosure: bundleScanUnavailableFinding(`the --bundle path ${explicit} does not exist`) };
  }
  for (const rel of BUNDLE_CANDIDATES) {
    const candidate = join(dir, rel);
    if (existsSync(candidate)) return { bundleDir: candidate };
  }
  return {
    disclosure: bundleScanUnavailableFinding(
      "no built bundle found (.next/static or dist/) — run a production build so client-inlined secrets can be scanned",
    ),
  };
}

// Same disclosure contract as SEC-TH-GH-00/DEP-OSV-00: a visible not-assessed row, never a silent
// skip. Info severity — a coverage gap, not a finding of zero bundle secrets.
function bundleScanUnavailableFinding(reason: string): Finding {
  return {
    id: "SEC-BUNDLE-00",
    title: "Built-bundle secret scan did not run",
    severity: "Info",
    confidence: "N/A",
    category: "Secret exposure",
    taxonomy: "Client-inlined secret — coverage not assessed",
    location: "(bundle)",
    status: "Open",
    evidence: `Built-bundle secret pass did not run: ${reason}.`,
    impact: "Client-inlined secrets (VITE_*/NEXT_PUBLIC_*/REACT_APP_* baked into the shipped JS) are not covered — a disclosed coverage gap, not a finding of zero secrets in the bundle.",
    fix: "Produce a production build (`next build` -> .next/static, or `vite build` -> dist/) and re-run the scan, or pass --bundle <dir> at the built assets.",
    value: 1,
    ease: 3,
    safety: 5,
  };
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
  // Reason deliberately omits historyDir itself: on a real engagement the path is just the
  // target root (no signal beyond what location "(repo-wide)" already says), and on the
  // deterministic dry-run harness (src/cli/dry-run.ts) historyDir is a freshly minted scratch
  // path — embedding it would make the committed findings.json non-reproducible across runs.
  const gitHistoryFindings = isGitRepoRoot(historyDir)
    ? parseTruffleHogFindings(runTruffleHogGitHistory(historyDir), "git-history")
    : [gitHistorySecretsUnavailableFinding("target directory is not a git repository root (an archive export or a subdirectory of a repo, not a full checkout)")];
  const findings: Finding[] = [
    ...parseTruffleHogFindings(runTruffleHogFilesystem(sourceDir), "source"),
    ...gitHistoryFindings,
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
