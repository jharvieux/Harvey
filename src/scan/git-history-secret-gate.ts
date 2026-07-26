// Dedicated validation path for P-SECRET-GIT-HISTORY (#129). TruffleHog's git-history pass
// (`trufflehog git`, see runTruffleHogGitHistory in secrets.ts) only works against a clonable
// repo ROOT — but the calibration corpus lives in the targets/calibration SUBDIRECTORY of this
// repo, so a fixture planted there is invisible to that pass the way a real client repo's
// history would be (GROUND-TRUTH.md's former B1 "Deferred" note). This builds a throwaway git
// repo in a temp dir at runtime (deterministic, no network — `--no-verification` skips every
// live provider call, which a FAKE secret could never pass anyway) with a fake secret added in
// one commit and removed in the next, then scores whether TruffleHog recovers it from history
// while a benign add/remove of a non-secret file stays silent.
//
// Wired into `pnpm validate:calibration` (src/cli/validate-calibration.ts) so a single operator
// command regression-locks this class alongside the rest of the corpus.

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Fake, valid-shape-only GitHub PAT (never a live token) — the shape TruffleHog's Github
// detector recognizes by regex; --no-verification means no network call is ever made against it.
const FAKE_TOKEN = "ghp_Z9Qm2vXcW8rNpKdLhGfYsAe4Uo1Bx6Vt0Zi7N";
const POSITIVE_FILE = "lib/leaked-token.js";
const NEGATIVE_FILE = "lib/build-info.js";

interface GitHistoryFixture {
  dir: string;
  cleanup: () => void;
}

function git(dir: string, args: string[]): void {
  execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" });
}

// init -> add+commit a fake secret -> remove it (still recoverable from history) -> add+commit
// a benign lookalike -> remove it too. HEAD ends with neither file present, so any hit trufflehog
// reports can only have come from walking history, not scanning the working tree.
export function buildGitHistoryFixture(): GitHistoryFixture {
  const dir = mkdtempSync(join(tmpdir(), "harvey-git-history-secret-"));
  git(dir, ["init", "-q"]);
  git(dir, ["config", "user.email", "calibration@harvey.test"]);
  git(dir, ["config", "user.name", "Harvey Calibration"]);

  writeFileSync(join(dir, "README.md"), "throwaway fixture repo for #129 — never pushed anywhere.\n");
  git(dir, ["add", "README.md"]);
  git(dir, ["commit", "-q", "-m", "init"]);

  mkdirSync(join(dir, "lib"));
  writeFileSync(join(dir, POSITIVE_FILE), `const GITHUB_TOKEN = "${FAKE_TOKEN}";\n`);
  git(dir, ["add", POSITIVE_FILE]);
  git(dir, ["commit", "-q", "-m", "add integration token"]);
  git(dir, ["rm", "-q", POSITIVE_FILE]);
  git(dir, ["commit", "-q", "-m", "rotate token, remove from repo"]);

  // git rm removed the now-empty lib/ dir along with the positive file — recreate it.
  mkdirSync(join(dir, "lib"), { recursive: true });
  writeFileSync(join(dir, NEGATIVE_FILE), 'const BUILD_ID = "release-2026-07-10-a1";\n');
  git(dir, ["add", NEGATIVE_FILE]);
  git(dir, ["commit", "-q", "-m", "add build metadata"]);
  git(dir, ["rm", "-q", NEGATIVE_FILE]);
  git(dir, ["commit", "-q", "-m", "clean up build metadata"]);

  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

export interface TruffleHogGitResult {
  DetectorName?: string;
  SourceMetadata?: { Data?: { Git?: { file?: string; commit?: string } } };
}

// --no-verification skips every live provider call (deterministic, no network — a fake token
// could never verify anyway). --results=unverified surfaces the pattern match itself, which is
// exactly the git-history-recovery capability under test.
//
// #1078 — these are NOT the flags production runs. Production is `trufflehog git --only-verified`
// (runTruffleHogGitHistory in secrets.ts), so this gate proves TruffleHog can WALK HISTORY and
// nothing about what production's verification filter then discards. The divergence is forced,
// not an oversight: the fixture's token is fake by construction and could never verify, so a gate
// on production's flags would fail on every run and prove nothing. The gap it leaves — an
// unverifiable history secret — is disclosed to the client by secretScanScopeFinding (SEC-SCOPE-00)
// rather than left implicit.
//
// REASON: this gate cannot run production's --only-verified flags, because its fixture secret is fake and can never verify
// KIND: decisional
// PROVENANCE: MEASURED 2026-07-26
// OWNER: operator
// DECISION: #1078 — gate proves history recovery; production's verified-only scope is disclosed via SEC-SCOPE-00 instead
function runTruffleHogGitHistory(dir: string): TruffleHogGitResult[] {
  let out: string;
  try {
    out = execFileSync(
      "trufflehog",
      ["git", "--no-verification", "--results=unverified", "--json", `file://${dir}`],
      { encoding: "utf8", maxBuffer: 1024 * 1024 * 16 },
    );
  } catch (err) {
    const e = err as { stdout?: string };
    if (typeof e.stdout === "string") out = e.stdout;
    else throw err;
  }
  return out
    .split("\n")
    .filter((line) => line.trim().startsWith("{"))
    .map((line) => JSON.parse(line) as TruffleHogGitResult);
}

interface GitHistoryGateResult {
  pass: boolean;
  positiveCaught: boolean;
  negativeClear: boolean;
  detail: string;
}

// Pure scoring, independent of the live trufflehog call — unit-testable with mocked results.
export function scoreGitHistoryResults(results: TruffleHogGitResult[]): GitHistoryGateResult {
  const positiveHits = results.filter((r) => r.SourceMetadata?.Data?.Git?.file === POSITIVE_FILE);
  const negativeHits = results.filter((r) => r.SourceMetadata?.Data?.Git?.file === NEGATIVE_FILE);
  const positiveCaught = positiveHits.length > 0;
  const negativeClear = negativeHits.length === 0;
  const detail =
    `P-SECRET-GIT-HISTORY: ${positiveCaught ? "caught" : "MISSED"} ` +
    `(${positiveHits.length} hit(s), detector ${positiveHits[0]?.DetectorName ?? "-"}) — ` +
    `secret added then removed from HEAD, recovered from git history\n` +
    `  N-GIT-HISTORY-BENIGN: ${negativeClear ? "clear" : "FALSE POSITIVE"} ` +
    `(${negativeHits.length} hit(s)) — benign add/remove of a non-secret value\n` +
    `  SCOPE (#1078): scored with --no-verification --results=unverified, NOT production's ` +
    `--only-verified — this proves history recovery only, never what verification then discards`;
  return { pass: positiveCaught && negativeClear, positiveCaught, negativeClear, detail };
}

// Full live gate: build the fixture, run trufflehog against it, score, clean up. Requires
// `trufflehog` on PATH (same requirement as the rest of the mechanical secret scan).
export function runGitHistorySecretGate(): GitHistoryGateResult {
  const { dir, cleanup } = buildGitHistoryFixture();
  try {
    return scoreGitHistoryResults(runTruffleHogGitHistory(dir));
  } finally {
    cleanup();
  }
}
