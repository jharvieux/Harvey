// Detector re-run (design §2.3). A fix is not green until the detector that found the problem no
// longer fires. This resolves a Finding's taxonomy to a runnable detector and re-runs it SCOPED to the
// fixed file, so an unrelated instance of the same class elsewhere in the target does not keep the fix
// red forever. Two honesty rules from CLAUDE.md's coverage doctrine are load-bearing here:
//   • detectorBefore is carried VERBATIM from the original scan (§2.4), never re-derived.
//   • a taxonomy with no resolver — or an external engine that isn't available — is reported `notRun`,
//     which computeGreen treats as not-green. An unrun detector is never a clean detector.

import type { Finding } from "../findings.js";
import type { SourceInput } from "../detectors/common.js";
import { loadSources, NON_PRODUCT } from "../detectors/load-sources.js";
import { detectAppRouterFindings } from "../detectors/app-router.js";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { detectPerfCodeFindings } from "../detectors/perf-code.js";
import { detectSlopFindings } from "../detectors/slop.js";
import { detectOrm, detectTargetFramework, nonNextWorkspaces } from "../scan/framework-detect.js";
import { fileOfLocation } from "./produce-plan.js";
import type { DetectorRun } from "./verify.js";

// Each AST engine owns a taxonomy family and knows how to run itself over a source set. The runners
// take a target dir only to derive framework/orm context — the sources are always passed in, so the
// re-run reads the FIXED worktree the caller loaded, not a fresh scan of the original checkout.
interface AstEngine {
  matches: (taxonomy: string) => boolean;
  run: (sources: SourceInput[], targetDir: string) => Finding[];
}

const AST_ENGINES: AstEngine[] = [
  { matches: (t) => t.startsWith("M5 —"), run: (s) => detectSlopFindings(s) },
  { matches: (t) => t.startsWith("M6 —"), run: (s) => detectHandrolledFindings(s) },
  { matches: (t) => t.startsWith("M7 —"), run: (s, dir) => detectPerfCodeFindings(s, detectTargetFramework(dir)) },
  {
    matches: (t) => t.startsWith("M9 —"),
    run: (s, dir) => detectAppRouterFindings(s, detectTargetFramework(dir), nonNextWorkspaces(dir), detectOrm(dir)),
  },
];

export function resolvesToDetector(taxonomy: string): boolean {
  return AST_ENGINES.some((e) => e.matches(taxonomy));
}

// §2.4: the before-state goes verbatim into the PR body — it is the finding the scan already produced,
// not a re-derivation. fired is true by construction (the scan fired to produce the finding).
export function detectorBefore(finding: Finding): DetectorRun {
  return { detectorId: finding.taxonomy, fired: true, output: finding.evidence };
}

// Re-run the detector for `finding` against `targetDir` (the fixed worktree), scoped to the finding's
// own file. `sources` lets a caller that already walked the tree avoid a second read; absent, the tree
// is loaded here (product-code detectors, so test/story/fixture files are excluded — matching
// src/cli/static-detect.ts). A taxonomy with no resolver is reported notRun, not clean.
export function rerunDetector(finding: Finding, targetDir: string, sources?: SourceInput[]): DetectorRun {
  const engine = AST_ENGINES.find((e) => e.matches(finding.taxonomy));
  if (!engine) {
    return {
      detectorId: finding.taxonomy,
      fired: false,
      output: "",
      notRun: `no detector re-run resolver for taxonomy "${finding.taxonomy}" — fix cannot be scored green`,
    };
  }
  const file = fileOfLocation(finding.location);
  const srcs = (sources ?? loadSources(targetDir)).filter((f) => !NON_PRODUCT.test(f.path));
  const hits = engine
    .run(srcs, targetDir)
    .filter((f) => fileOfLocation(f.location) === file && f.taxonomy === finding.taxonomy);
  return {
    detectorId: finding.taxonomy,
    fired: hits.length > 0,
    output: hits.length ? `still firing at ${hits.map((h) => h.location).join(", ")}` : `clean at ${file}`,
  };
}
