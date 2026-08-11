// The §8 acceptance gate as a function (issue #957, remainder of #927). For one planted class it runs
// the FULL §2 contract against a MATERIALIZED standalone corpus: executeFixDiff proves the mechanical
// fix applies clean and clears the §3 rails, and rerunDetector (#924) proves the finding's detector no
// longer fires against the fixed source (§2.3, the detector-after gate). Green iff BOTH hold — which is
// exactly the §8 clause-1 requirement that "the detector no longer fires after the fix", not merely
// that the diff applies. This closes acceptance-doc blockers 2 (detector-after re-run) and 3 (corpus
// materialization) for the classes whose detector rerunDetector can resolve; the remaining autonomous
// gap (an LLM implementer generating the diffs, and a semgrep/M1 detector-after resolver) is #957's
// split remainder, disclosed by the accompanying test — never faked green.
//
// `runFixAcceptance` is deliberately a calibration-only answer-key gate: its caller supplies both
// the planted vulnerable source and the expected fixed source, then this function materializes both
// into disposable repositories. A production fix run must instead accept a client-authored diff and
// prove it through `ingestFixDiff`; importing this answer-key path there would fabricate the result.
//
// REASON: runFixAcceptance is test-only by design because it evaluates a caller-supplied planted source and expected fixed answer; production fix verification must consume the client's authored diff through ingestFixDiff instead of an answer key.
// KIND: empirical
// PROVENANCE: MEASURED 2026-08-11 (#1547) — `pnpm test-only-exports --list` reports the whole src/fix/acceptance.ts file unreachable outside tests, while `git grep -n runFixAcceptance -- src` names only this definition and src/fix/calibration-acceptance.test.ts; the falsifier was exercised as committed (1), with a temporary production import (0), and with this file absent (127).
// FALSIFIER: test -f src/fix/acceptance.ts || exit 127; o=$(pnpm test-only-exports --list 2>&1); case "$o" in *"test-only-exports gate (#1307)"*) ;; *) exit 127;; esac; case "$o" in *"    file   src/fix/acceptance.ts — every export unreachable"*) exit 1;; *) exit 0;; esac
// TOUCHES: src/fix/acceptance.ts src/fix/interactive.ts

import type { Finding } from "../findings.js";
import { detectorBefore, rerunDetector } from "./detector-rerun.js";
import { executeFixDiff, type FixExecution } from "./execute.js";
import { capturePatch, disposeCorpus, materialize } from "./materialize-calibration.js";
import type { DiffCap } from "./rails.js";
import { detectorHalfClean, type DetectorRun } from "./verify.js";

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
  // #1272: what this gate did NOT score, stated on every result rather than left to be inferred.
  // A materialized corpus is the planted file and nothing else — no package.json, no workflows — so
  // the §2.1 client half has nothing to discover and is out of scope here BY CONSTRUCTION, not
  // skipped. The path that does score it is ingestFixDiff, against a real client checkout.
  clientChecksScope: string;
}

const CLIENT_CHECKS_OUT_OF_SCOPE =
  "not assessed: a materialized single-file corpus carries no package.json and no workflows, so there are no client verify commands to discover; the §8 gate scores the apply/rails + detector-after halves only";

export async function runFixAcceptance(
  finding: Finding,
  planted: PlantedClass,
  opts: { allowlist: string[]; diffCap?: DiffCap },
): Promise<AcceptanceResult> {
  const baseline = materialize({ [planted.file]: planted.original });
  const fixedRepo = materialize({ [planted.file]: planted.fixed });
  try {
    const patch = capturePatch(baseline, planted.file, planted.fixed);
    const execution = await executeFixDiff(finding.id, patch, {
      targetDir: baseline.dir,
      baselineCommit: baseline.commit,
      allowlist: opts.allowlist,
      diffCap: opts.diffCap,
    });
    const after = await rerunDetector(finding, fixedRepo.dir);
    const green = execution.outcome === "diff-verified" && detectorHalfClean(after);
    return { findingId: finding.id, execution, detectorBefore: detectorBefore(finding), detectorAfter: after, green, clientChecksScope: CLIENT_CHECKS_OUT_OF_SCOPE };
  } finally {
    disposeCorpus(baseline);
    disposeCorpus(fixedRepo);
  }
}
