// The FixPlan producer (design §1.2). A cheap, deterministic pass that reads a screened Finding plus
// the client source and drafts a FixPlan — critically, a blast radius derived from a real grep over
// the tree (importers of the changed file), not a guess. The plan exists to make batching and
// rail-checking possible BEFORE any code changes, and to give the operator something reviewable when a
// fix is downgraded. It carries NO diff — turning an approved plan into a unified diff is the
// implementer pass (an operator/LLM pass that emits Finding.suggestedFix.diff, executed by
// src/cli/fix-execute.ts). See docs/design/fix-implementation.md §1.2/§1.4.

import type { Finding } from "../findings.js";
import type { SourceInput } from "../detectors/common.js";
import { loadSources } from "../detectors/load-sources.js";
import type { BlastRadius, FixPlan, Screen } from "./plan.js";

// "path/to/file.ts:42" or ":42-58" → "path/to/file.ts". A location with no line suffix is the file.
export function fileOfLocation(location: string): string {
  const m = /^(.*?):\d+(?:-\d+)?$/.exec(location.trim());
  return (m ? (m[1] as string) : location).trim();
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Importers of the changed file, from the source tree — §1.2's "callers/importers of changed code
// (from a grep pass, not guesswork)". Matches an ES import or CJS require whose specifier ends in the
// changed file's module name (basename without extension), which is how a relative or aliased import
// of `actions/save.ts` reads at the call site (`from "…/save"`, `require("…/save")`).
export function deriveCallers(file: string, sources: SourceInput[]): string[] {
  const moduleName = (file.split("/").pop() ?? file).replace(/\.[cm]?[jt]sx?$/, "");
  if (moduleName === "") return [];
  const importRe = new RegExp(`(?:from|require\\(|import\\()\\s*['"][^'"]*/?${escapeRegExp(moduleName)}(?:\\.[cm]?[jt]sx?)?['"]`);
  const callers = new Set<string>();
  for (const s of sources) {
    if (s.path === file) continue;
    if (importRe.test(s.text)) callers.add(s.path);
  }
  return [...callers].sort();
}

interface ProducePlanOptions {
  screen: Screen; // from screenFinding — the mode/tier/reason this finding was bucketed at
  targetDir?: string; // client checkout; the tree grepped for callers (ignored when `sources` given)
  sources?: SourceInput[]; // pre-loaded sources (tests / a caller that already walked the tree)
  verifyCommands?: string[]; // client verify commands this fix must pass (§2), discovered separately
}

export function producePlan(finding: Finding, opts: ProducePlanOptions): FixPlan {
  const file = fileOfLocation(finding.location);
  const sources = opts.sources ?? (opts.targetDir ? loadSources(opts.targetDir) : []);
  const callers = deriveCallers(file, sources);

  const blastRadius: BlastRadius = {
    files: [file],
    createdFiles: [],
    symbols: [],
    // A mechanical MVP fix is behavior-preserving by default; a caller that knows otherwise overrides
    // downstream. estimatedChangedLines stays 0 until a real diff exists — the plan never invents a
    // line count, and the hard cap is enforced on the actual diff at execute time (src/fix/execute.ts).
    callers,
    behaviorPreserving: true,
    estimatedChangedLines: 0,
  };

  return {
    findingId: finding.id,
    severity: finding.severity,
    category: finding.category,
    mode: opts.screen.mode,
    detectorId: finding.taxonomy, // the detector re-run in verify (§2.3) resolves off the taxonomy
    approach: finding.fix.trim(),
    blastRadius,
    verifyCommands: opts.verifyCommands ?? [],
    testPlan: "",
    tier: opts.screen.tier,
    risks: [],
    downgradeReason: opts.screen.mode === "auto" ? undefined : opts.screen.reason,
  };
}
