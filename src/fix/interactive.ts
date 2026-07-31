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
//      re-run AND the §2.1 client-verification half (#1272: the verify-harness discovers the client's
//      own commands, baselines them at the pinned commit, and re-runs them against the fixed source),
//      scored by computeGreen. The diff is UNTRUSTED, exactly as an LLM's was — a diff that does not
//      make the detector stop firing, or that breaks the client's own suite, is rejected (fail loud),
//      never delivered. Only a green result reaches the transport (a DRAFT PR), via deliverFix.
//
// Nothing here calls a model or reimplements a rail; it composes the pieces #885/#922/#923/#930 built.

import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Finding } from "../findings.js";
import type { SourceInput } from "../detectors/common.js";
import { detectorBefore, rerunDetector } from "./detector-rerun.js";
import { executeFixDiff, type FixExecution } from "./execute.js";
import { fileOfLocation } from "./produce-plan.js";
import type { FixPlan } from "./plan.js";
import { DEFAULT_DIFF_CAP, parseDiffFacts, type DiffCap } from "./rails.js";
import {
  baselineCacheKey,
  buildVerificationEvidence,
  cmdKey,
  detectRunner,
  discoverClientCommands,
  extractCiRunSteps,
  linkNodeModules,
  runBaseline,
  withBaselineWorktree,
  type BaselineCache,
  type DiscoveredCommand,
} from "./verify-harness.js";
import { computeGreen, type CommandRun, type DetectorRun, type VerificationEvidence } from "./verify.js";

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
  // #1272: overrides the lockfile-derived runner for the §2.1 client checks, which used to be
  // hardcoded `clientChecks: []`. Absent ⇒ detectRunner reads it off the target's own lockfile.
  runner?: string;
  attempts?: number; // which escalation attempt produced this diff — recorded in the evidence
  /**
   * #1529: a baseline run is the most expensive thing in the pipeline and it is IDENTICAL for every
   * finding in one batch — same checkout, same pinned commit, same discovered command. Caching it
   * per call made an N-fix batch run the client's own suite 2N times where it used to run it zero.
   * Supply one map for the whole batch and each distinct command is baselined once. Absent ⇒ the
   * old per-call behaviour, which is what a single interactive ingest wants.
   */
  baselineCache?: BaselineCache;
}

// The monorepo rule (§2.1): each workspace the diff touches, plus the root. A file's workspace is
// the nearest ancestor directory that has its own package.json.
function affectedWorkspaces(targetDir: string, files: string[]): string[] {
  const out = new Set<string>();
  for (const f of files) {
    for (let dir = dirname(f); dir !== "." && dir !== "/" && dir !== ""; dir = dirname(dir)) {
      if (existsSync(join(targetDir, dir, "package.json"))) {
        out.add(dir);
        break;
      }
    }
  }
  return [...out].sort();
}

// A workflow `run:` step carrying a GitHub expression (`${{ secrets.X }}`, `${{ matrix.y }}`) has no
// meaning outside Actions, so it is recorded skipped:"needs-ci" rather than run locally and failed
// for a reason that is not the fix's fault (§2.2).
function needsCi(c: DiscoveredCommand): boolean {
  return c.source.startsWith("ci-workflow") && c.command.includes("${{");
}

interface IngestResult {
  execution: FixExecution; // rails + apply-clean gate, verbatim from executeFixDiff
  evidence: VerificationEvidence; // detector-before/after + green, decided by computeGreen
  green: boolean;
  rejected: boolean; // !green — the diff is not shippable
  rejectReason?: string; // named reason, for the operator and the handoff (fail loud, never silent)
  /**
   * What the §2.1 baseline actually cost THIS ingest (#1529). `requested` is every discovered
   * command; `executed` is the subset this call had to run because no shared cache already held it.
   * Reported rather than inferred: a batch that shares a cache and a batch that does not are
   * otherwise indistinguishable in the artifact, which is how the 2N cost went unnoticed.
   */
  baseline: { requested: number; executed: number; durationMs: number };
}

// Run the operator's diff through the existing rails and score it. `green` is DECIDED by computeGreen —
// this never asserts it. A non-green result is REJECTED with a reason; only a green result should reach
// deliverFix (the caller's transport step). The detector re-run rides inside executeFixDiff's single
// worktree, so the same applied source both clears the apply gate and answers "does it still fire".
export function ingestFixDiff(input: IngestInput): IngestResult {
  const facts = parseDiffFacts(input.diff);
  const commands = discoverClientCommands(
    input.targetDir,
    affectedWorkspaces(input.targetDir, [...facts.files, ...facts.createdFiles]),
    input.runner ?? detectRunner(input.targetDir),
    extractCiRunSteps(join(input.targetDir, ".github/workflows")),
  );

  // §2.1 step 3, computed LAZILY: a baseline run of the client's own suite is the most expensive
  // thing in the pipeline, and a rails-blocked or non-applying diff never needs one. The hook below
  // is only reached once the diff has cleared the apply gate.
  //
  // And computed ONCE PER DISTINCT COMMAND across a batch when a cache is supplied (#1529). Only the
  // commands the cache is missing are run, in one worktree; the results are written back so the next
  // finding reads them. A FAILING baseline caches exactly like a passing one — that is the point, not
  // a side effect: every finding sharing that command must still record
  // `skipped: "pre-existing-failure-on-baseline"`, and dropping the failure from the second fix's
  // evidence would re-attribute a pre-existing break to the fix.
  let baselineRuns: Map<string, CommandRun> | undefined;
  let baselineRequested = 0;
  let baselineExecuted = 0;
  let baselineMs = 0;
  const baseline = (): Map<string, CommandRun> => {
    if (baselineRuns) return baselineRuns;
    const cache = input.baselineCache;
    const missing = cache ? commands.filter((c) => !cache.has(baselineCacheKey(input.targetDir, input.baselineCommit, c))) : commands;
    baselineRequested = commands.length;
    baselineExecuted = missing.length;
    const started = Date.now();
    const fresh = missing.length === 0
      ? new Map<string, CommandRun>()
      : withBaselineWorktree(input.targetDir, input.baselineCommit, (root) => runBaseline(missing, root));
    baselineMs = Date.now() - started;
    if (!cache) return (baselineRuns = fresh);
    for (const c of missing) {
      const run = fresh.get(cmdKey(c));
      if (run) cache.set(baselineCacheKey(input.targetDir, input.baselineCommit, c), run);
    }
    return (baselineRuns = new Map(
      commands.flatMap((c) => {
        const run = cache.get(baselineCacheKey(input.targetDir, input.baselineCommit, c));
        return run ? [[cmdKey(c), run] as const] : [];
      }),
    ));
  };

  const execution = executeFixDiff(input.finding.id, input.diff, {
    targetDir: input.targetDir,
    baselineCommit: input.baselineCommit,
    allowlist: input.allowlist,
    diffCap: input.diffCap,
    detectorAfter: (worktree) => rerunDetector(input.finding, worktree),
    evidence: (worktree, detectorAfter) => {
      linkNodeModules(input.targetDir, worktree);
      return buildVerificationEvidence(
        {
          findingId: input.finding.id,
          baselineCommit: input.baselineCommit,
          worktreeCommit: input.baselineCommit, // the fixed source lived in a disposable worktree cut here
          detectorBefore: detectorBefore(input.finding),
          detectorAfter,
          commands,
          baseline: baseline(),
          needsCi,
          attempts: input.attempts ?? 1,
        },
        worktree,
      );
    },
  });

  const detectorAfter: DetectorRun = execution.detectorAfter ?? {
    detectorId: input.finding.taxonomy,
    fired: false,
    output: "",
    notRun: `detector was not re-run — the diff did not clear the apply gate (outcome "${execution.outcome}": ${execution.abortReason ?? execution.verification ?? (execution.railViolations.join("; ") || "no verified worktree")})`,
  };

  // The harness assembles the evidence inside the fixed worktree; when the diff never got there,
  // the fallback record says so and carries an empty clientChecks, which is NOT green (#1272).
  const evidence: VerificationEvidence = execution.evidence ?? {
    findingId: input.finding.id,
    worktreeCommit: input.baselineCommit,
    baselineCommit: input.baselineCommit,
    detectorBefore: detectorBefore(input.finding),
    detectorAfter,
    clientChecks: [],
    green: false,
    attempts: input.attempts ?? 1,
  };
  const green = computeGreen(evidence);
  const failedChecks = evidence.clientChecks.filter((c) => c.skipped === undefined && c.exitCode !== 0);

  const rejectReason = green
    ? undefined
    : execution.outcome !== "diff-verified"
      ? `diff did not clear the rails/apply gate (${execution.outcome}): ${execution.abortReason ?? execution.verification ?? (execution.railViolations.join("; ") || "unknown")}`
      : detectorAfter.notRun !== undefined
        ? `detector ${input.finding.taxonomy} could not be re-run: ${detectorAfter.notRun}`
        : detectorAfter.fired
          ? `detector ${input.finding.taxonomy} still fires after the fix — the diff applies but does not resolve the finding`
          : failedChecks.length > 0
            ? `the detector is clean but the client's own checks FAIL after the fix: ${failedChecks.map((c) => `${c.command} (exit ${c.exitCode})`).join(", ")}`
            : `no client verify command could be discovered under ${input.targetDir} — the §2.1 client half cannot be evidenced, so this fix is not verifiable green (add a verify/check/ci/test script, or a pull_request-triggered workflow, to the target)`;

  return {
    execution,
    evidence: { ...evidence, green },
    green,
    rejected: !green,
    rejectReason,
    // Zeroes here mean the baseline was never REACHED (a rails-blocked or non-applying diff), which
    // is a different fact from "it ran and cost nothing".
    baseline: { requested: baselineRequested, executed: baselineExecuted, durationMs: baselineMs },
  };
}
