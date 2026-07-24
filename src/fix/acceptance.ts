// The §8 acceptance gate as a function (issue #957, remainder of #927). For one planted class it runs
// the FULL §2 contract against a MATERIALIZED standalone corpus: executeFixDiff proves the mechanical
// fix applies clean and clears the §3 rails, and rerunDetector (#924) proves the finding's detector no
// longer fires against the fixed source (§2.3, the detector-after gate). Green iff BOTH hold — which is
// exactly the §8 clause-1 requirement that "the detector no longer fires after the fix", not merely
// that the diff applies. This closes acceptance-doc blockers 2 (detector-after re-run) and 3 (corpus
// materialization) for the classes whose detector rerunDetector can resolve; the remaining autonomous
// gap (an LLM implementer generating the diffs, and a semgrep/M1 detector-after resolver) is #957's
// split remainder, disclosed by the accompanying test — never faked green.

import type { Finding } from "../findings.js";
import { detectorBefore, rerunDetector } from "./detector-rerun.js";
import { executeFixDiff, type FixExecution } from "./execute.js";
import { capturePatch, disposeCorpus, materialize } from "./materialize-calibration.js";
import type { DiffCap } from "./rails.js";
import { computeGreen, type DetectorRun } from "./verify.js";

interface PlantedClass {
  file: string; // repo-relative path within targets/calibration
  original: string; // the planted (vulnerable) source
  fixed: string; // the mechanical fix's fixed source
}

interface AcceptanceResult {
  findingId: string;
  execution: FixExecution; // apply-clean + §3 rails (diff-verified on success)
  detectorBefore: DetectorRun; // verbatim from the scan (§2.4)
  detectorAfter: DetectorRun; // re-run against the fixed source (§2.3)
  green: boolean; // diff-verified AND detector-after clean — the §8 clause-1 gate
}

export function runFixAcceptance(finding: Finding, planted: PlantedClass, opts: { allowlist: string[]; diffCap?: DiffCap }): AcceptanceResult {
  const baseline = materialize({ [planted.file]: planted.original });
  const fixedRepo = materialize({ [planted.file]: planted.fixed });
  try {
    const patch = capturePatch(baseline, planted.file, planted.fixed);
    const execution = executeFixDiff(finding.id, patch, {
      targetDir: baseline.dir,
      baselineCommit: baseline.commit,
      allowlist: opts.allowlist,
      diffCap: opts.diffCap,
    });
    const after = rerunDetector(finding, fixedRepo.dir);
    const green = execution.outcome === "diff-verified" && computeGreen({ detectorAfter: after, clientChecks: [] });
    return { findingId: finding.id, execution, detectorBefore: detectorBefore(finding), detectorAfter: after, green };
  } finally {
    disposeCorpus(baseline);
    disposeCorpus(fixedRepo);
  }
}
