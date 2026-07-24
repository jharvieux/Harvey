// Live calibration validation gate (issue #61). Runs the REAL mechanical scan (semgrep,
// gitleaks, trufflehog, osv-scanner — all must be on PATH) against targets/calibration and
// scores it against the corpus answer key (src/scan/calibration.ts).
//
//   pnpm validate:calibration            # scan the default calibration target
//   pnpm validate:calibration --dir <p>  # scan another labeled corpus
//   pnpm validate:calibration --json     # emit the raw matrix as JSON
//
// Exit code: 1 (gate FAIL) if any benign NEGATIVE is flagged in the free count, or any
// positive expected at "high" isn't caught at high. Review-tier recall gaps (documented
// follow-ups, e.g. OSV needing a lockfile) are reported but do not fail the gate.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { buildCoverageMatrix, CORPUS, mechanicalCorpus, moduleCensus, type MatrixRow } from "../scan/calibration.js";
import { formatMetrics } from "../scan/detection-metrics.js";
import { measureHeuristicPrecision } from "../scan/heuristic-precision.js";
import type { Finding } from "../findings.js";
import { checkKnownDependencyCVEs, checkNextVersionCVEs } from "../scan/dependencies.js";
import { runGitHistorySecretGate } from "../scan/git-history-secret-gate.js";
import { runMechanicalScan } from "../scan/mechanical.js";
import { checkKnownIoc, checkLockfilePresence } from "../scan/supply-chain.js";

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const dir = arg("--dir") ?? join(repoRoot, "targets", "calibration");

// Secondary manifest fixtures: each targets/calibration/fixtures/<app>/ is a STANDALONE project
// root (its own package.json, its own — or absent — lockfile), scanned independently of the main
// target with the offline manifest checks. This is how the corpus models scenarios that can't
// coexist in the single root manifest: an EOL vs. a supported `next`, a project root that ships no
// lockfile, a known-malicious dependency. Findings are located by a stable "fixtures/<app>/…"
// label so the corpus can attribute them. The network/binary passes (slopsquat, OSV, semgrep,
// gitleaks) are deliberately NOT re-run here — those are already gated on the main target, and the
// deferred #71 classes this scan exercises are all offline manifest facts.
function scanManifestFixtures(targetDir: string): Finding[] {
  const fixturesDir = join(targetDir, "fixtures");
  if (!existsSync(fixturesDir)) return [];
  const findings: Finding[] = [];
  for (const entry of readdirSync(fixturesDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const appDir = join(fixturesDir, entry.name);
    const manifestFile = join(appDir, "package.json");
    if (existsSync(manifestFile)) {
      const label = `fixtures/${entry.name}/package.json`;
      const pkg = JSON.parse(readFileSync(manifestFile, "utf8")) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      const nextVersion = allDeps.next;
      if (nextVersion) findings.push(...checkNextVersionCVEs(nextVersion.replace(/^[\^~]/, ""), label));
      findings.push(...checkKnownDependencyCVEs(allDeps, label));
      findings.push(...checkKnownIoc(Object.keys(allDeps), label));
    }
    findings.push(...checkLockfilePresence(appDir, `fixtures/${entry.name}`));
  }
  return findings;
}

// CORPUS also carries modules with their own live pipeline outside runMechanicalScan (e.g.
// M10's name/type classifier, fed from parsed migration SQL — see calibration/m10.entries.ts and
// src/cli/dry-run.ts). Score only the mechanical-scan modules here so this gate isn't spuriously
// broken by a module runMechanicalScan was never going to detect. The filter itself lives in
// mechanicalCorpus() (src/scan/calibration.ts), not re-implemented here, so calibration.test.ts
// can hold the ONE exclusion rule accountable — see its "#398 mechanicalCorpus" block, which
// fails loud if a module-tagged entry ever leaks into this scored subset or drops out of the
// per-module census below (the two things that make an exclusion silent instead of documented).
const scoredCorpus = mechanicalCorpus(CORPUS);
console.log(
  `Scoring ${scoredCorpus.length}/${CORPUS.length} corpus entries against runMechanicalScan (M1 mechanical); ` +
    `${CORPUS.length - scoredCorpus.length} module-tagged entries are excluded by design — see the per-module census below for where each is gated instead.`,
);

const findings = [...(await runMechanicalScan({ dir })), ...scanManifestFixtures(dir)];
const matrix = buildCoverageMatrix(findings, scoredCorpus);

if (process.argv.includes("--json")) {
  console.log(JSON.stringify(matrix, null, 2));
  process.exit(0);
}

const mark = (r: MatrixRow): string => (r.pass ? (r.expectedTier === "connected" ? "N/A " : r.expectedTier === "none" ? "GAP " : "PASS") : "FAIL");
const line = (r: MatrixRow): string =>
  `  ${mark(r)}  ${r.id.padEnd(22)} ${(r.caughtTier ?? "-").padEnd(7)} ${r.detail}`;

console.log(`\nCalibration coverage matrix — ${dir}\n`);
console.log("POSITIVES (planted vulns — must be caught):");
for (const r of matrix.rows.filter((r) => r.kind === "positive")) console.log(line(r));
console.log("\nNEGATIVES (benign lookalikes — must NOT be flagged in the free count):");
for (const r of matrix.rows.filter((r) => r.kind === "negative")) console.log(line(r));

// The credibility-critical gate: zero free-count FPs on negatives, and every high-expected
// positive caught at high. Review-tier recall gaps are surfaced but non-fatal.
const negFps = matrix.rows.filter((r) => r.kind === "negative" && r.highFlagged);
const highMisses = matrix.rows.filter((r) => r.kind === "positive" && r.expectedTier === "high" && !r.highFlagged);
const reviewMisses = matrix.rows.filter((r) => r.kind === "positive" && r.expectedTier === "review" && !r.pass);
// A "none"-tier positive is an accepted no-mechanical-rule gap (e.g. WEBHOOK-REPLAY, #425). It
// scores an intended gap while nothing of its class fires; a relevant finding means a rule
// graduated — that is a GATE FAIL, forcing a re-tier so a by-design gap can't silently become a
// claimed catch. It never fails while the gap holds, and never passes silently once a rule lands.
const noRuleBroken = matrix.rows.filter((r) => r.kind === "positive" && r.expectedTier === "none" && !r.pass);

// DECISION (#341): this live gate is security-weighted BY CONSTRUCTION — it scores only the M1
// mechanical corpus (entries with no `module` label) because runMechanicalScan produces only M1
// findings, and M1 is the credibility-critical lead where a wrong Critical is fatal. The other
// nine modules are gated by their OWN suites (calibration.test.ts's recorded-output + live-detector
// blocks, mutation-scan.test.ts, etc.), not by this number. So the recall count below is M1's, not
// the suite's — labelled as such, and preceded by a per-module census so a 1-positive module reads
// as visibly thin rather than being averaged into the M1-dominated total.
//
// PARITY MINIMUM (#427): every module carries >= MIN_POSITIVES_PER_MODULE positive fixtures
// (static + connected), each paired with >= 1 boundary negative. Rationale: a single positive
// fails only on a TOTAL outage (its module's recall drops to 0); two positives exercising
// DISTINCT rule surfaces let a PARTIAL regression — one shape breaks while another still fires —
// show up as a drop, which is what the module's own suite must catch. This block enforces the
// fixtures EXIST; the partial-regression detection itself lives in each module's suite. The
// number is deliberately low: 2 is the floor at which partial and total become distinguishable.
const MIN_POSITIVES_PER_MODULE = 2;
console.log("\nPer-module corpus census (fixture counts only — this gate scores M1; other modules are gated by their own suites):");
const census = moduleCensus(CORPUS);
const parityThin = census.filter((c) => c.positivesStatic + c.positivesConnected < MIN_POSITIVES_PER_MODULE);
for (const c of census) {
  const connected = c.positivesConnected ? ` +${c.positivesConnected} connected` : "";
  const where = c.module === "M1" ? "SCORED BY THIS GATE" : "own unit suite (src/scan/calibration/*.entries.ts)";
  const parity = c.positivesStatic + c.positivesConnected < MIN_POSITIVES_PER_MODULE ? "  THIN (< parity min)" : "";
  console.log(`  ${c.module.padEnd(4)} positives=${String(c.positivesStatic).padEnd(3)}${connected.padEnd(14)} negatives=${String(c.negatives).padEnd(3)}  ${where}${parity}`);
}
console.log(`  parity minimum: ${MIN_POSITIVES_PER_MODULE} positives/module (#427) — ${parityThin.length ? `THIN: ${parityThin.map((c) => c.module).join(", ")}` : "all modules meet it"}`);
// #881: fixture counts are not performance. Name the modules that actually have a scored
// precision/recall metric, so the M1 metric block below cannot be read as a suite-wide figure.
const METRIC_GATED_MODULES = ["M1", "M7", "M8"];
console.log(
  `  scored detection metrics exist for ${METRIC_GATED_MODULES.join("/")} only (printed below); every other module above has FIXTURE COUNTS, which say what the answer key covers and nothing about what fires.`,
);

console.log(
  `\nM1 mechanical corpus — positives caught: ${matrix.positivesCaught}/${matrix.positivesTotal} static ` +
    `(${matrix.positivesCaughtHigh} at high/free-count; ${matrix.connectedNa} connected-tier N/A). ` +
    `This is M1 recall, NOT suite recall — see the census above.`,
);
console.log(`M1 negatives cleared: ${matrix.negativesCleared}/${matrix.negativesTotal} static`);

// #881: the same two counts in the metric set a prospect's security lead already reads (the OWASP
// Benchmark scoring model — precision/recall/F1 plus Youden's Index, TPR − FPR). Printed under an
// M1-only heading and immediately followed by what it is NOT, because a single blended Youden
// number would hide this gate's construction skew exactly as the raw count does (#341/#427).
console.log(`\nM1 mechanical corpus — detection metrics (OWASP Benchmark scoring model, #881):`);
console.log(`  ${formatMetrics(matrix.metrics)}`);
console.log(
  "  Basis: a planted positive is a TP when a rule caught it; a benign negative is an FP when a FREE-COUNT (high-tier)\n" +
    "  finding lands on it — the same test this gate passes/fails on, so the metrics can never disagree with the verdict.\n" +
    "  NOT a suite number and NOT a field number: it scores the M1 MECHANICAL corpus only (M7/M8 have their own metrics\n" +
    "  below; the other seven modules have fixture counts above and no metric anywhere), and precision over a corpus is a\n" +
    "  property of the positive:negative ratio WE chose, not of how often each shape occurs in a real repo.",
);
if (matrix.noRuleTotal) console.log(`No-mechanical-rule gaps (by design, excluded from recall): ${matrix.noRuleHeld}/${matrix.noRuleTotal} held — a rule firing on one is a GATE FAIL`);
if (reviewMisses.length) console.log(`Review-tier recall gaps (non-fatal, tracked): ${reviewMisses.map((r) => r.id).join(", ")}`);

// #823: the M7 code-tier / M8 test-intent heuristics are gated by their own labeled fixture
// corpus (src/scan/heuristic-precision.ts — pure detectors, no binaries), so the calibration
// report carries a measured precision number for the two noisiest heuristic modules, not just
// M1. Per-row detail: `pnpm exec tsx src/cli/validate-precision.ts`.
console.log("\nHeuristic precision (M7 code tier / M8 test intent — labeled fixture corpus, #823):");
const heuristic = measureHeuristicPrecision();
for (const m of heuristic.modules) {
  console.log(`  ${m.module.padEnd(4)} ${formatMetrics(m.metrics)}`);
}

// P-SECRET-GIT-HISTORY (#129): a dedicated pass, not part of the matrix above — TruffleHog's
// git-history scan needs a clonable repo ROOT, which targets/calibration (a subdirectory of
// this repo) isn't. Builds its own throwaway git repo at runtime; see git-history-secret-gate.ts.
console.log("\nGIT-HISTORY SECRET GATE (#129, dedicated throwaway-repo fixture):");
const gitHistoryGate = runGitHistorySecretGate();
console.log(`  ${gitHistoryGate.detail.replace(/\n/g, "\n  ")}`);

const gatePass = negFps.length === 0 && highMisses.length === 0 && noRuleBroken.length === 0 && gitHistoryGate.pass && parityThin.length === 0 && heuristic.ok;
if (!gatePass) {
  if (negFps.length) console.log(`\nGATE FAIL — free-count false positives: ${negFps.map((r) => r.id).join(", ")}`);
  if (!heuristic.ok) console.log(`GATE FAIL — M7/M8 heuristic precision corpus (#823): ${heuristic.rows.filter((r) => !r.pass).map((r) => r.id).join(", ")} — run pnpm exec tsx src/cli/validate-precision.ts`);
  if (highMisses.length) console.log(`GATE FAIL — high-tier positives not caught: ${highMisses.map((r) => r.id).join(", ")}`);
  if (noRuleBroken.length) console.log(`GATE FAIL — a mechanical rule now fires on a by-design no-rule gap (re-tier it): ${noRuleBroken.map((r) => r.id).join(", ")}`);
  if (!gitHistoryGate.pass) console.log("GATE FAIL — git-history secret gate (#129) did not pass, see detail above");
  if (parityThin.length) console.log(`GATE FAIL — parity minimum (#427): ${parityThin.map((c) => c.module).join(", ")} below ${MIN_POSITIVES_PER_MODULE} positives`);
  process.exit(1);
}
console.log("\nGATE PASS — no free-count false positives; every high-tier rule fired on its positive.");
