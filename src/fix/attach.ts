// The producer→deliverable seam for #825: a VERIFIED fix diff becomes `Finding.suggestedFix`, which
// is what `ticketBody` (src/trackers/findings-to-tickets.ts) renders under the prose `**Fix:**`.
//
// Why this module exists. #825's headline criterion is "a confirmed paid-tier finding yields a valid
// unified diff embedded in its ticket body". Every OTHER part of that sentence has been built for
// months: the schema field (#828), the verification gate (src/trackers/fix-diff.ts), the renderer
// (renderFixSection), the paid gate (findings-to-tickets.ts:153), and — since #885/#998/#1056/#1272 —
// a whole implementer pipeline that takes a diff, runs it through the rails, re-runs the detector,
// runs the client's own checks, and scores the result green.
//
// And yet `grep suggestedFix src/ --include='*.ts' | grep -v test` finds only the schema, the
// renderer and the CONSUMERS. Nothing ever wrote the field. A pipeline that verifies a diff to green
// and a ticket body that renders a verified diff have never been connected, so the paid gate could
// not fire on any real engagement. This is CLAUDE.md's "accounted for is not delivered" class exactly:
// the detector works, the finding is dropped at a producer→consumer seam, every status reads clean.
//
// The rule this module enforces is fail-closed in three independent ways, because a diff is a thing a
// client may `git apply` to their own codebase — a wrong diff is worse than vague prose, since prose
// invites judgment and a patch invites application:
//   1. NOT GREEN ⇒ NOT ATTACHED. `green` is decided by computeGreen upstream; this module never
//      re-decides it, never softens it, and never attaches on a partial pass.
//   2. NOT PAID ⇒ NOT ATTACHED. Free tier keeps the indicator only (#825's third criterion).
//   3. INFO/REVIEW ⇒ NOT ATTACHED. The same severity/confidence floor the ticket filer already
//      applies, so a diff can never ride into a ticket the filer would itself have excluded.
// Every refusal is a ROW WITH A REASON, never a silent drop — attachAll's arithmetic makes that
// checkable rather than merely intended.

import type { Confidence, Finding, Severity } from "../findings.js";
import type { VerificationEvidence } from "./verify.js";

// Mirrors findings-to-tickets.ts's filing floor. Kept as its own list rather than imported so a
// diff can never become MORE permissive than the ticket filer by accident; the pair is pinned by a
// test that fails if they diverge.
const NO_DIFF_SEVERITIES: readonly Severity[] = ["Info", "Watch"];
const NO_DIFF_CONFIDENCES: readonly Confidence[] = ["Review", "N/A"];

export interface AttachInput {
  finding: Finding;
  diff: string;
  green: boolean; // computeGreen's verdict, passed in verbatim — never recomputed here
  evidence: VerificationEvidence;
  rejectReason?: string; // the upstream's named reason when !green
}

interface AttachOptions {
  paid: boolean; // the engagement tier; default-false at every call site, same as the ticket filer
}

interface AttachOutcome {
  finding: Finding; // with suggestedFix set, or unchanged
  attached: boolean;
  reason: string; // why it was attached, or why it was not — always populated
}

// What was actually checked, in the client's own words, surfaced in the ticket under the diff. This
// is the "_Mechanically verified: …_" line, and it must describe the REAL checks — a generic
// "verified" would be a claim with no content behind it.
export function verificationSentence(evidence: VerificationEvidence): string {
  const ran = evidence.clientChecks.filter((c) => c.skipped === undefined);
  const skipped = evidence.clientChecks.filter((c) => c.skipped !== undefined);
  const parts = [
    "applies cleanly to the pinned baseline",
    `the detector that found it (${evidence.detectorAfter.detectorId}) no longer fires`,
    ran.length === 1 ? `your own check \`${ran[0]!.command}\` passes` : `${ran.length} of your own checks pass (${ran.map((c) => `\`${c.command}\``).join(", ")})`,
  ];
  const tail = skipped.length ? ` ${skipped.length} check(s) were skipped: ${skipped.map((c) => `\`${c.command}\` (${c.skipped})`).join(", ")}.` : "";
  return `${parts.join("; ")}.${tail}`;
}

export function attachSuggestedFix(input: AttachInput, opts: AttachOptions): AttachOutcome {
  const { finding, diff } = input;

  if (!opts.paid) {
    return { finding, attached: false, reason: "free-tier engagement — an applicable diff is a paid-tier deliverable; the finding keeps its prose fix only" };
  }
  if (NO_DIFF_SEVERITIES.includes(finding.severity)) {
    return { finding, attached: false, reason: `${finding.severity}-severity indicator — below the floor at which a diff is offered` };
  }
  if (NO_DIFF_CONFIDENCES.includes(finding.confidence)) {
    return { finding, attached: false, reason: `${finding.confidence}-confidence indicator — a diff is only offered for a confirmed finding` };
  }
  if (!input.green) {
    return {
      finding,
      attached: false,
      reason: `the proposed diff did not verify, so it is NOT attached: ${input.rejectReason ?? "no reason was recorded by the verification pass"}`,
    };
  }
  if (diff.trim() === "") {
    // Reachable only if an upstream scored an empty diff green. It would render an empty ```diff
    // fence in a client's ticket, which reads as "we produced a fix" — the exact false-clean shape.
    return { finding, attached: false, reason: "the verification pass reported green but the diff is empty — refusing to file an empty patch" };
  }

  const verification = verificationSentence(input.evidence);
  return {
    finding: { ...finding, suggestedFix: { diff, verified: true, verification } },
    attached: true,
    reason: `verified and attached — ${verification}`,
  };
}

interface AttachLedger {
  findings: Finding[]; // every input finding, in order; the attached ones carry suggestedFix
  attached: { findingId: string; reason: string }[];
  refused: { findingId: string; reason: string }[];
}

// Batch form with the conservation property stated as an assertion, not a comment: every proposal is
// either attached or refused with a reason, and the two lists must account for all of them. A silent
// drop here would put a fix nobody can see back into the gap this module exists to close.
export function attachAll(findings: Finding[], proposals: Map<string, AttachInput>, opts: AttachOptions): AttachLedger {
  const attached: AttachLedger["attached"] = [];
  const refused: AttachLedger["refused"] = [];
  const out = findings.map((f) => {
    const proposal = proposals.get(f.id);
    if (!proposal) return f;
    const outcome = attachSuggestedFix(proposal, opts);
    (outcome.attached ? attached : refused).push({ findingId: f.id, reason: outcome.reason });
    return outcome.finding;
  });

  const seen = attached.length + refused.length;
  const known = [...proposals.keys()].filter((id) => findings.some((f) => f.id === id));
  if (seen !== known.length) {
    throw new Error(`attachAll dropped a proposal: ${known.length} proposal(s) matched a finding but only ${seen} were accounted for (attached ${attached.length}, refused ${refused.length})`);
  }
  const orphans = [...proposals.keys()].filter((id) => !findings.some((f) => f.id === id));
  if (orphans.length) {
    throw new Error(`attachAll was given diff(s) for finding id(s) not in the document: ${orphans.join(", ")}. A diff written against an unknown finding is never silently ignored.`);
  }
  return { findings: out, attached, refused };
}
