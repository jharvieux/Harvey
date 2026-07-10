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
import { buildCoverageMatrix, CORPUS, type MatrixRow } from "../scan/calibration.js";
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
// broken by a module runMechanicalScan was never going to detect.
const mechanicalCorpus = CORPUS.filter((e) => e.module === undefined);

const findings = [...(await runMechanicalScan({ dir })), ...scanManifestFixtures(dir)];
const matrix = buildCoverageMatrix(findings, mechanicalCorpus);

if (process.argv.includes("--json")) {
  console.log(JSON.stringify(matrix, null, 2));
  process.exit(0);
}

const mark = (r: MatrixRow): string => (r.pass ? (r.expectedTier === "connected" ? "N/A " : "PASS") : "FAIL");
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

console.log(
  `\nPositives caught: ${matrix.positivesCaught}/${matrix.positivesTotal} static ` +
    `(${matrix.positivesCaughtHigh} at high/free-count; ${matrix.connectedNa} connected-tier N/A)`,
);
console.log(`Negatives cleared: ${matrix.negativesCleared}/${matrix.negativesTotal} static`);
if (reviewMisses.length) console.log(`Review-tier recall gaps (non-fatal, tracked): ${reviewMisses.map((r) => r.id).join(", ")}`);

// P-SECRET-GIT-HISTORY (#129): a dedicated pass, not part of the matrix above — TruffleHog's
// git-history scan needs a clonable repo ROOT, which targets/calibration (a subdirectory of
// this repo) isn't. Builds its own throwaway git repo at runtime; see git-history-secret-gate.ts.
console.log("\nGIT-HISTORY SECRET GATE (#129, dedicated throwaway-repo fixture):");
const gitHistoryGate = runGitHistorySecretGate();
console.log(`  ${gitHistoryGate.detail.replace(/\n/g, "\n  ")}`);

const gatePass = negFps.length === 0 && highMisses.length === 0 && gitHistoryGate.pass;
if (!gatePass) {
  if (negFps.length) console.log(`\nGATE FAIL — free-count false positives: ${negFps.map((r) => r.id).join(", ")}`);
  if (highMisses.length) console.log(`GATE FAIL — high-tier positives not caught: ${highMisses.map((r) => r.id).join(", ")}`);
  if (!gitHistoryGate.pass) console.log("GATE FAIL — git-history secret gate (#129) did not pass, see detail above");
  process.exit(1);
}
console.log("\nGATE PASS — no free-count false positives; every high-tier rule fired on its positive.");
