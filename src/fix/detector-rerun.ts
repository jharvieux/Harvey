// Detector re-run (design §2.3). A fix is not green until the detector that found the problem no
// longer fires. This resolves a Finding's taxonomy to a runnable detector and re-runs it SCOPED to the
// fixed file, so an unrelated instance of the same class elsewhere in the target does not keep the fix
// red forever. Two resolver families: the in-process AST engines (M5/M6/M7/M9), and — since #1012 —
// the harvey-* semgrep rules, which cover the §8 in-scope M1 classes (open redirect, verbose error,
// SQLi, …) and are replayed by running the rule directory against the one fixed file.
//
// Two honesty rules from CLAUDE.md's coverage doctrine are load-bearing here:
//   • detectorBefore is carried VERBATIM from the original scan (§2.4), never re-derived.
//   • a taxonomy with no resolver — or an external engine that isn't available — is reported `notRun`,
//     which computeGreen treats as not-green. An unrun detector is never a clean detector. That is
//     why the semgrep path distinguishes "the rule ran and matched nothing" from "semgrep was absent,
//     the file was unreadable, or the source did not parse": only the first is a clean detector.

import { existsSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import type { Finding } from "../findings.js";
import type { SourceInput } from "../detectors/common.js";
import { loadSources, NON_PRODUCT } from "../detectors/load-sources.js";
import { detectAppRouterFindings } from "../detectors/app-router.js";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { detectPerfCodeFindings } from "../detectors/perf-code.js";
import { detectSlopFindings } from "../detectors/slop.js";
import { detectOrm, detectTargetFramework, nonNextWorkspaces } from "../scan/framework-detect.js";
import { harveyRuleIds, runSemgrepOnFile } from "../scan/semgrep.js";
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

// A semgrep finding's taxonomy IS its check_id, and semgrep derives that id from how the rules were
// loaded: a `--config <dir>` run prefixes the rule's own id with the config path
// (`src.scan.rules.semgrep.harvey-open-redirect`). Strip to the last segment so the same finding
// resolves whichever way the scan loaded the rules. Cached: the id set is read off the rule files,
// and resolvesToDetector is called per finding.
let ruleIds: Set<string> | undefined;
function harveyRuleOf(taxonomy: string): string | undefined {
  const id = taxonomy.trim().split(".").pop() ?? "";
  return (ruleIds ??= harveyRuleIds()).has(id) ? id : undefined;
}

// A taxonomy has a resolver if an AST engine owns it, or it names a harvey-* semgrep rule that still
// exists in the rule directory. Whether the semgrep BINARY is available is a separate question,
// answered at re-run time as notRun — an engagement machine without semgrep must not silently
// downgrade to "clean".
export function resolvesToDetector(taxonomy: string): boolean {
  return AST_ENGINES.some((e) => e.matches(taxonomy)) || harveyRuleOf(taxonomy) !== undefined;
}

// #1012: replay one harvey-* semgrep rule against the finding's own file in the fixed worktree. The
// rule is matched by id (not by the config-path-prefixed check_id), and the location filter is the
// file, so an instance of the same rule elsewhere in the target does not keep this fix red — the
// same scoping the AST path uses.
function rerunSemgrep(finding: Finding, ruleId: string, targetDir: string): DetectorRun {
  const notRun = (reason: string): DetectorRun => ({ detectorId: finding.taxonomy, fired: false, output: "", notRun: reason });
  const file = fileOfLocation(finding.location);
  const abs = isAbsolute(file) ? file : join(targetDir, file);
  if (!existsSync(abs)) return notRun(`semgrep rule ${ruleId} could not be re-run: ${file} does not exist under ${targetDir}`);

  const { result, failure } = runSemgrepOnFile(abs, targetDir);
  if (failure !== undefined) return notRun(`semgrep rule ${ruleId} could not be re-run: ${failure}`);

  const hits = (result.results ?? []).filter((r) => (r.check_id.split(".").pop() ?? "") === ruleId);
  return {
    detectorId: finding.taxonomy,
    fired: hits.length > 0,
    output: hits.length
      ? `${ruleId} still firing at ${hits.map((h) => `${file}${h.start?.line ? `:${h.start.line}` : ""}`).join(", ")}`
      : `${ruleId} clean at ${file}`,
  };
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
    const ruleId = harveyRuleOf(finding.taxonomy);
    if (ruleId !== undefined) return rerunSemgrep(finding, ruleId, targetDir);
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
