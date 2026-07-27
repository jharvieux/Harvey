// The INTERACTIVE fix-implementer (#1056, §8's diff-generating half). Operator ruling 2026-07-26: no
// automated Anthropic SDK, no API key — the diff is authored in the operator's own interactive Claude
// session, not by a call this repo makes. So the "implementer" splits into two halves that bracket that
// manual step:
//
//   1. emitFixPrompt — turn a verified finding + its FixPlan into a self-contained SPEC the operator
//      pastes into their session. It carries the finding, the source in scope, the intended change, the
//      write rails, and the acceptance criterion (the detector must STOP firing), so the diff comes back
//      already aimed at what the pipeline will check.
//   2. ingestFixDiff — take the operator's resulting diff and run it through the EXISTING rails
//      unchanged: executeFixDiff (rails + apply-clean + verifySuggestedFix) plus the detector-after
//      re-run, scored by computeGreen. The diff is UNTRUSTED, exactly as an LLM's was — a diff that does
//      not make the detector stop firing is rejected (fail loud), never delivered. Only a green result
//      reaches the transport (a DRAFT PR), which the caller drives via deliverFix.
//
// Nothing here calls a model or reimplements a rail; it composes the pieces #885/#922/#923/#930 built.

import type { Finding } from "../findings.js";
import type { SourceInput } from "../detectors/common.js";
import { detectorBefore, rerunDetector } from "./detector-rerun.js";
import { executeFixDiff, type FixExecution } from "./execute.js";
import { fileOfLocation } from "./produce-plan.js";
import type { FixPlan } from "./plan.js";
import { DEFAULT_DIFF_CAP, type DiffCap } from "./rails.js";
import { computeGreen, type DetectorRun, type VerificationEvidence } from "./verify.js";

interface FixPromptInput {
  finding: Finding;
  plan: FixPlan;
  baselineCommit: string; // the pinned engagement commit the diff must apply against
  allowlist: string[]; // engagement path allowlist — the only paths the diff may touch
  diffCap?: DiffCap;
  sources: SourceInput[]; // the in-scope file(s), read from the target checkout, for code context
}

function sourceBlock(sources: SourceInput[], focusFile: string): string {
  const ordered = [...sources].sort((a, b) => (a.path === focusFile ? -1 : b.path === focusFile ? 1 : a.path.localeCompare(b.path)));
  return ordered
    .map((s) => `### ${s.path}${s.path === focusFile ? " (the finding is here)" : ""}\n\n\`\`\`\n${s.text.replace(/\n+$/, "")}\n\`\`\``)
    .join("\n\n");
}

// A self-contained prompt/spec the operator pastes into an interactive Claude session. Everything the
// session needs to author a correct diff — and nothing that assumes access to this repo — lives inline.
export function emitFixPrompt(input: FixPromptInput): string {
  const { finding, plan } = input;
  const focusFile = fileOfLocation(finding.location);
  const cap = input.diffCap ?? DEFAULT_DIFF_CAP;
  const capText = `${cap.maxLines} changed lines across ${cap.maxFiles} files`;

  return `# Fix implementation task — finding ${finding.id}

You are implementing a single, surgical, behavior-preserving code fix. Return ONLY a unified diff
(\`git apply\`-compatible, with \`a/\` and \`b/\` path prefixes) — no prose, no code fences around the diff.

## The finding
- **id**: ${finding.id}
- **title**: ${finding.title}
- **severity / category / confidence**: ${finding.severity} / ${finding.category} / ${finding.confidence}
- **detector (taxonomy)**: ${finding.taxonomy}
- **location**: ${finding.location}
- **evidence**: ${finding.evidence.trim()}
- **impact**: ${finding.impact.trim()}

## Intended change
${plan.approach.trim()}

## The code in scope
${sourceBlock(input.sources, focusFile)}

## Write rails — the diff is rejected if it breaks any of these
- Applies cleanly against baseline commit \`${input.baselineCommit}\`.
- Touches ONLY paths matching this allowlist: ${input.allowlist.map((p) => `\`${p}\``).join(", ")}.
- Never touches secrets/\`.env\`, keys, CI workflows, \`.git\`, migrations, lockfiles, or dependency/config manifests.
- Stays within the engagement diff cap (${capText}).
- Behavior-preserving: fixes the finding without changing unrelated behavior; adds no new dependency.

## Acceptance criterion — this is exactly what the pipeline re-checks
The detector **${finding.taxonomy}** must STOP firing at \`${finding.location}\` once your diff is applied.
Applying cleanly is necessary but NOT sufficient: a cosmetic edit that leaves the detector firing is
rejected. Aim the change at the evidence above.

## When done
Save the diff to a file and hand it back to the pipeline:

    pnpm exec tsx src/cli/fix-interactive.ts <findings.json> <manifest.json> --target <client-checkout> --finding ${finding.id} --apply-diff <your-diff-file>
`;
}

interface IngestInput {
  finding: Finding;
  diff: string;
  targetDir: string; // the client checkout — a git repo, never Harvey's
  baselineCommit: string;
  allowlist: string[];
  diffCap?: DiffCap;
}

interface IngestResult {
  execution: FixExecution; // rails + apply-clean gate, verbatim from executeFixDiff
  evidence: VerificationEvidence; // detector-before/after + green, decided by computeGreen
  green: boolean;
  rejected: boolean; // !green — the diff is not shippable
  rejectReason?: string; // named reason, for the operator and the handoff (fail loud, never silent)
}

// Run the operator's diff through the existing rails and score it. `green` is DECIDED by computeGreen —
// this never asserts it. A non-green result is REJECTED with a reason; only a green result should reach
// deliverFix (the caller's transport step). The detector re-run rides inside executeFixDiff's single
// worktree, so the same applied source both clears the apply gate and answers "does it still fire".
export function ingestFixDiff(input: IngestInput): IngestResult {
  const execution = executeFixDiff(input.finding.id, input.diff, {
    targetDir: input.targetDir,
    baselineCommit: input.baselineCommit,
    allowlist: input.allowlist,
    diffCap: input.diffCap,
    detectorAfter: (worktree) => rerunDetector(input.finding, worktree),
  });

  const detectorAfter: DetectorRun = execution.detectorAfter ?? {
    detectorId: input.finding.taxonomy,
    fired: false,
    output: "",
    notRun: `detector was not re-run — the diff did not clear the apply gate (outcome "${execution.outcome}": ${execution.abortReason ?? execution.verification ?? (execution.railViolations.join("; ") || "no verified worktree")})`,
  };

  const evidence: VerificationEvidence = {
    findingId: input.finding.id,
    worktreeCommit: input.baselineCommit, // the fixed source lived in a disposable worktree cut here
    baselineCommit: input.baselineCommit,
    detectorBefore: detectorBefore(input.finding),
    detectorAfter,
    clientChecks: [], // the client-verify half (§2.1) is the verify-harness's job; not gathered here
    green: false,
    attempts: 1,
  };
  const green = computeGreen(evidence);

  const rejectReason = green
    ? undefined
    : execution.outcome !== "diff-verified"
      ? `diff did not clear the rails/apply gate (${execution.outcome}): ${execution.abortReason ?? execution.verification ?? (execution.railViolations.join("; ") || "unknown")}`
      : detectorAfter.notRun !== undefined
        ? `detector ${input.finding.taxonomy} could not be re-run: ${detectorAfter.notRun}`
        : `detector ${input.finding.taxonomy} still fires after the fix — the diff applies but does not resolve the finding`;

  return { execution, evidence: { ...evidence, green }, green, rejected: !green, rejectReason };
}
