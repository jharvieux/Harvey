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

import { existsSync, readFileSync } from "node:fs";
import { arg, assertKnownFlags } from "./args.js";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
import { AUDIT_MODULES, buildCoverageMatrix, CORPUS, formatSelfMatchingKeys, mechanicalCorpus, MIN_NEGATIVES_PER_MODULE, MIN_POSITIVES_PER_MODULE, moduleCensus, parityVerdict, scoreEntry, selfMatchingMatchKeys, type MatrixRow } from "../scan/calibration.js";
import { formatMetrics } from "../scan/detection-metrics.js";
import { measureHeuristicPrecision } from "../scan/heuristic-precision.js";
import { SEVERITIES, type Finding, type Severity } from "../findings.js";
import { checkKnownDependencyCVEs, checkNextVersionCVEs } from "../scan/dependencies.js";
import { runGitHistorySecretGate } from "../scan/git-history-secret-gate.js";
import { runMechanicalScan } from "../scan/mechanical.js";
import { harveySemgrepRules, ruleCorpusPairings } from "../scan/rule-corpus-pairing.js";
import { checkKnownIoc, checkLockfilePresence } from "../scan/supply-chain.js";

const FLAGS = [
  "--dir",
  "--target",
  "--json",
] as const;

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
assertKnownFlags(FLAGS);
const dir = arg("--dir") ?? arg("--target") ?? join(repoRoot, "targets", "calibration");

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
  for (const entry of readEntriesSafe(fixturesDir).entries) {
    if (!entry.isDirectory) continue;
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
// #1344: a negative that draws an UNRECORDED review-tier hit. Distinct from a free-count FP — it
// costs no precision today, but it is a rule that moved onto benign code, and until now no gate
// could fail on it (#1251).
const negReviewDrift = matrix.rows.filter((r) => r.kind === "negative" && !r.highFlagged && !r.pass);
const highMisses = matrix.rows.filter((r) => r.kind === "positive" && r.expectedTier === "high" && !r.highFlagged);
const reviewMisses = matrix.rows.filter((r) => r.kind === "positive" && r.expectedTier === "review" && !r.pass);
// A "none"-tier positive is an accepted no-mechanical-rule gap (e.g. WEBHOOK-REPLAY, #425). It
// scores an intended gap while nothing of its class fires; a relevant finding means a rule
// graduated — that is a GATE FAIL, forcing a re-tier so a by-design gap can't silently become a
// claimed catch. It never fails while the gap holds, and never passes silently once a rule lands.
const noRuleBroken = matrix.rows.filter((r) => r.kind === "positive" && r.expectedTier === "none" && !r.pass);

// #1157: severity-correctness. Every gate above asserts a finding APPEARS; this asserts a CAUGHT
// positive with an answer-keyed severity is RATED right — the #1063 (every CVE shipped Medium) /
// #1060 (data-class escalation never fired) failure mode, where a real Critical shown as Medium is
// nearly as harmful as a miss. Only entries carrying expectedSeverity are scored; a mismatch fails
// the gate exactly like a missing high-tier positive.
const severityAnnotated = matrix.rows.filter((r) => r.kind === "positive" && r.expectedSeverity !== undefined);
const severityMismatches = severityAnnotated.filter((r) => r.severityMismatch);

// DECISION (#341): this live gate is security-weighted BY CONSTRUCTION — it scores only the M1
// mechanical corpus (entries with no `module` label) because runMechanicalScan produces only M1
// findings, and M1 is the credibility-critical lead where a wrong Critical is fatal. The other
// nine modules are gated by their OWN suites (calibration.test.ts's recorded-output + live-detector
// blocks, mutation-scan.test.ts, etc.), not by this number. So the recall count below is M1's, not
// the suite's — labelled as such, and preceded by a per-module census so a 1-positive module reads
// as visibly thin rather than being averaged into the M1-dominated total.
//
// PARITY MINIMUM (#427, exhaustive since #1314): the rule, the numbers and the disclosed
// exemptions live in src/scan/calibration.ts (parityVerdict) so this gate and the unit control in
// calibration.test.ts share one implementation. The census is seeded from AUDIT_MODULES, so a
// module with ZERO entries renders as a row reading 0 and trips the minimum — before #1314 it
// emitted no row at all, and M2/M6 (zero fixtures each) were the only two modules the gate
// structurally could not flag while it printed "all modules meet it".
console.log("\nPer-module corpus census (fixture counts only — this gate scores M1; other modules are gated by their own suites):");
const census = moduleCensus(CORPUS);
const parity = parityVerdict(CORPUS);
const parityThin = parity.thin;
const exemptModules = new Map(parity.exempt.map((e) => [e.module, e]));
for (const c of census) {
  const connected = c.positivesConnected ? ` +${c.positivesConnected} connected` : "";
  const shortfall = parityThin.find((t) => t.module === c.module);
  const where = c.module === "M1" ? "SCORED BY THIS GATE" : exemptModules.has(c.module) ? "NO CORPUS — substitute gate named below" : "own unit suite (src/scan/calibration/*.entries.ts)";
  const flag = shortfall ? `  THIN (${shortfall.missing})` : "";
  console.log(`  ${c.module.padEnd(4)} positives=${String(c.positivesStatic).padEnd(3)}${connected.padEnd(14)} negatives=${String(c.negatives).padEnd(3)}  ${where}${flag}`);
}
console.log(`  parity minimum: ${MIN_POSITIVES_PER_MODULE} positives + ${MIN_NEGATIVES_PER_MODULE} boundary negative per module, over all ${AUDIT_MODULES.length} modules (#427/#1314) — ${parityThin.length ? `THIN: ${parityThin.map((c) => `${c.module} (${c.missing})`).join(", ")}` : "every non-exempt module meets it"}`);
for (const e of parity.exempt) console.log(`  EXEMPT ${e.module}: ${e.reason}`);
if (parity.stale.length) console.log(`  STALE EXEMPTION: ${parity.stale.join(", ")} now meet(s) the minimum on real fixtures — delete the PARITY_EXEMPTIONS row so the corpus, not the substitute gate, is what the module stands on.`);
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
console.log("\nHeuristic precision (M1 tenant-scope / M7 code tier / M8 test intent — labeled fixture corpus, #823/#896):");
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

// #1157: severity correctness — a caught positive rated wrong fails the gate like a miss. The
// negative control proves the check can FAIL: take a real annotated entry, feed it a copy of its
// own finding re-stamped to a DIFFERENT severity, and assert scoreEntry flags the mismatch. A green
// severity line therefore means "every annotated positive rated right AND the check still fires" —
// the same "passed AND can fail" contract the conservation gate's negative-control steps enforce.
console.log(`\nSEVERITY CORRECTNESS (#1157) — delivered severity vs. answer key, scored on ${severityAnnotated.length} annotated positive(s):`);
for (const r of severityAnnotated) {
  const flag = r.severityMismatch ? "MISRATED" : "OK  ";
  console.log(`  ${flag}  ${r.id.padEnd(24)} expected ${String(r.expectedSeverity).padEnd(9)} delivered ${(r.deliveredSeverities?.join("/") || "none")}`);
}
const severityControl = (() => {
  const sample = severityAnnotated[0];
  if (!sample) return { ok: false, detail: "no annotated positive to build a negative control from — the severity check is unproven" };
  const entry = mechanicalCorpus(CORPUS).find((e) => e.id === sample.id && e.expectedSeverity !== undefined);
  if (!entry?.expectedSeverity) return { ok: false, detail: `could not resolve annotated entry ${sample.id} to build a negative control` };
  const wrong = SEVERITIES.find((s) => s !== entry.expectedSeverity) as Severity;
  // Re-stamp EVERY finding to the wrong severity; scoreEntry selects the entry's own relevant ones,
  // which are now all mis-rated, so a working check must flag it.
  const misrated = findings.map((f) => ({ ...f, severity: wrong }));
  const row = scoreEntry(entry, misrated);
  return { ok: row.severityMismatch, detail: `entry ${entry.id}: expected ${entry.expectedSeverity}, forced its finding to ${wrong} → severity check ${row.severityMismatch ? "FIRED" : "DID NOT FIRE"}` };
})();
console.log(`  negative control: ${severityControl.detail}`);

// #1344: the review-tier ratchet's own negative control. Until this gate change a planted negative
// passed on `!highFlagged`, so a widened rule that lit one up at REVIEW tier scored "cleared
// (review-tier hit only)" and every check stayed green — #1251 hit exactly that shape, and it
// surfaced only because someone hand-diffed dry-run/findings.json. The control replays it: take
// N-STORAGE-DB-PATH (measured silent today) and hand scoreEntry the harvey-path-traversal finding
// #1251 saw, at review tier. A working ratchet must FAIL that row.
const reviewRatchetControl = (() => {
  const entry = mechanicalCorpus(CORPUS).find((e) => e.id === "N-STORAGE-DB-PATH");
  if (!entry) return { ok: false, detail: "N-STORAGE-DB-PATH is gone from the corpus — the #1251 review-tier ratchet is unproven" };
  const planted: Finding = {
    id: "CONTROL-1251",
    status: "Open",
    category: "Security",
    title: "Path traversal (negative control)",
    severity: "High",
    confidence: "Review",
    precisionTier: "review",
    taxonomy: "src.scan.rules.semgrep.harvey-path-traversal",
    location: `app/api/${entry.location}.ts:1`,
    evidence: "synthetic — #1344 negative control, never a real finding",
    impact: "n/a",
    fix: "n/a",
    value: 1,
    ease: 1,
    safety: 1,
  };
  const row = scoreEntry(entry, [...findings, planted]);
  return { ok: !row.pass, detail: `entry ${entry.id}: planted a review-tier harvey-path-traversal hit -> ratchet ${row.pass ? "DID NOT FIRE" : "FIRED"}` };
})();
console.log(`\nREVIEW-TIER RATCHET (#1344, replaying #1251): ${reviewRatchetControl.detail}`);

// #1355: corpus integrity, not scanner behaviour — a `match` key that is a substring of its own
// fixture path is satisfied by every finding on that fixture, so a positive row can stay green
// while the detection it exists to score goes silent. Enforced under `pnpm verify` too
// (calibration.test.ts); reported here so the number a client's report stands on is visibly
// scored against an answer key whose keys still discriminate.
const selfMatching = selfMatchingMatchKeys(CORPUS);
console.log(`\nCORPUS SELF-MATCH (#1355): ${selfMatching.length === 0 ? `0 of ${CORPUS.filter((e) => e.match?.length).length} keyed entries carry a key that is a substring of their own location` : `${selfMatching.length} vacuous entr(ies)`}`);
if (selfMatching.length) console.log(formatSelfMatchingKeys(selfMatching).replace(/^/gm, "  "));

// #1314's negative control: delete a module's entries and prove the parity gate fails. It must be
// a module that PASSES today, so the fixtures being removed are the only thing holding it up — the
// exhaustive census is what makes the resulting zero visible at all (before it, the module simply
// stopped emitting a row and parityThin shrank).
const parityControl = (() => {
  const victim = census.find((c) => !exemptModules.has(c.module) && c.module !== "M1" && c.positivesStatic + c.positivesConnected >= MIN_POSITIVES_PER_MODULE);
  if (!victim) return { ok: false, detail: "no non-exempt module above the minimum to remove — the parity gate is unproven" };
  const without = CORPUS.filter((e) => (e.module ?? "M1") !== victim.module);
  const thin = parityVerdict(without).thin;
  return { ok: thin.some((t) => t.module === victim.module), detail: `removed every ${victim.module} entry (${victim.positivesStatic} positives, ${victim.negatives} negatives) -> parity minimum ${thin.some((t) => t.module === victim.module) ? "FIRED" : "DID NOT FIRE"}` };
})();
console.log(`\nPARITY NEGATIVE CONTROL (#1314): ${parityControl.detail}`);

// #1301: every `harvey-*` rule must be claimed by a positive it caught and a benign twin it stayed
// silent on, or it can enter the client-facing free count with no evidence it works. The unit gate
// (src/scan/rule-corpus-pairing.test.ts) scores the committed dry-run artifact so it runs binary-
// free under `pnpm verify`; here it is scored against THIS run's live findings, which is the
// stronger reading — the artifact could be stale, a live scan cannot be.
const pairings = ruleCorpusPairings(harveySemgrepRules(), findings);
const unpaired = pairings.filter((p) => p.unpaired);
console.log(`\nRULE ↔ CORPUS PAIRING (#1301), scored against this run: ${pairings.length - unpaired.length}/${pairings.length} harvey-* rules have a positive they caught and a benign twin they stayed silent on`);
for (const p of unpaired) console.log(`  UNPAIRED  ${p.rule} — ${p.unpaired}`);

const gatePass = unpaired.length === 0 && parityControl.ok && parity.stale.length === 0 && selfMatching.length === 0 && negFps.length === 0 && negReviewDrift.length === 0 && highMisses.length === 0 && noRuleBroken.length === 0 && gitHistoryGate.pass && parityThin.length === 0 && heuristic.ok && severityMismatches.length === 0 && severityControl.ok && reviewRatchetControl.ok;
if (!gatePass) {
  if (unpaired.length) console.log(`\nGATE FAIL — unvalidated rule (#1301): ${unpaired.map((p) => `${p.rule} (${p.unpaired})`).join(", ")}. A rule with no corpus pair can enter a client's free count and grade with no evidence it works.`);
  if (selfMatching.length) console.log(`\nGATE FAIL — corpus self-match (#1355): ${selfMatching.map((r) => r.id).join(", ")} — a key that is a substring of its own location scores every finding on that fixture`);
  if (negFps.length) console.log(`\nGATE FAIL — free-count false positives: ${negFps.map((r) => r.id).join(", ")}`);
  if (negReviewDrift.length) console.log(`GATE FAIL — review-tier regression on planted negatives (#1344): ${negReviewDrift.map((r) => `${r.id} — ${r.detail}`).join(" | ")}`);
  if (!heuristic.ok) console.log(`GATE FAIL — M7/M8 heuristic precision corpus (#823): ${heuristic.rows.filter((r) => !r.pass).map((r) => r.id).join(", ")} — run pnpm exec tsx src/cli/validate-precision.ts`);
  if (highMisses.length) console.log(`GATE FAIL — high-tier positives not caught: ${highMisses.map((r) => r.id).join(", ")}`);
  if (noRuleBroken.length) console.log(`GATE FAIL — a mechanical rule now fires on a by-design no-rule gap (re-tier it): ${noRuleBroken.map((r) => r.id).join(", ")}`);
  if (!gitHistoryGate.pass) console.log("GATE FAIL — git-history secret gate (#129) did not pass, see detail above");
  if (parityThin.length) console.log(`GATE FAIL — parity minimum (#427/#1314): ${parityThin.map((c) => `${c.module} has ${c.missing}`).join(", ")}. Add fixtures, or add a PARITY_EXEMPTIONS row naming the gate that covers the module instead.`);
  if (parity.stale.length) console.log(`GATE FAIL — stale parity exemption (#1314): ${parity.stale.join(", ")} now meet the minimum on real fixtures; the exemption is a claim that they cannot, and it is no longer true`);
  if (!parityControl.ok) console.log(`GATE FAIL — the #1314 parity negative control did not fire: ${parityControl.detail} — a module's fixtures could be deleted without the gate noticing`);
  if (severityMismatches.length) console.log(`GATE FAIL — delivered severity != answer key (#1157): ${severityMismatches.map((r) => `${r.id} (expected ${r.expectedSeverity}, got ${r.deliveredSeverities?.join("/") || "none"})`).join(", ")}`);
  if (!reviewRatchetControl.ok) console.log(`GATE FAIL — the #1344 review-tier ratchet did not fire on its negative control: ${reviewRatchetControl.detail} — a widened rule could light up a planted negative unseen again`);
  if (!severityControl.ok) console.log(`GATE FAIL — severity-correctness negative control did not fire (#1157): ${severityControl.detail} — the check is not proven able to fail`);
  process.exit(1);
}
console.log("\nGATE PASS — no free-count false positives; every high-tier rule fired on its positive; every annotated severity delivered as rated.");
