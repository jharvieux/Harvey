import { describe, expect, it } from "vitest";
import { attachAll, attachSuggestedFix, verificationSentence, type AttachInput } from "./attach.js";
import { filingEligibility, findingToTicket } from "../trackers/findings-to-tickets.js";
import type { Confidence, Finding, Severity } from "../findings.js";
import type { CommandRun, VerificationEvidence } from "./verify.js";

const DIFF = `--- a/app/route.ts\n+++ b/app/route.ts\n@@ -1,2 +1,2 @@\n-export async function GET(request: Request) {\n+export async function GET() {\n`;

const check = (over: Partial<CommandRun> = {}): CommandRun => ({
  command: "npm run test",
  cwd: ".",
  exitCode: 0,
  durationMs: 90,
  outputTail: "ok",
  ...over,
});

const evidence = (over: Partial<VerificationEvidence> = {}): VerificationEvidence => ({
  findingId: "F-1",
  worktreeCommit: "abc123",
  baselineCommit: "abc123",
  detectorBefore: { detectorId: "M5 — Unused parameter", fired: true, output: "" },
  detectorAfter: { detectorId: "M5 — Unused parameter", fired: false, output: "" },
  clientChecks: [check()],
  green: true,
  attempts: 1,
  ...over,
});

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: "F-1",
  title: "Unused parameter",
  severity: "Low",
  confidence: "Confirmed",
  category: "Maintainability",
  taxonomy: "M5 — Unused parameter",
  location: "app/route.ts:1",
  status: "Open",
  evidence: "GET(request) never reads request",
  impact: "Dead parameter",
  fix: "Drop the unread parameter.",
  value: 2,
  ease: 5,
  safety: 5,
  ...over,
});

const proposal = (over: Partial<AttachInput> = {}): AttachInput => ({
  finding: finding(),
  diff: DIFF,
  green: true,
  evidence: evidence(),
  ...over,
});

describe("#825 — a verified diff reaches Finding.suggestedFix", () => {
  it("attaches a green diff on a paid engagement, marked verified", () => {
    const out = attachSuggestedFix(proposal(), { paid: true });
    expect(out.attached).toBe(true);
    expect(out.finding.suggestedFix?.diff).toBe(DIFF);
    expect(out.finding.suggestedFix?.verified).toBe(true);
  });

  it("puts the attached diff into the ticket body under the prose fix — the criterion's actual claim", () => {
    // The whole point of the seam: not "a field was set" but "a client reads the patch in the ticket".
    const out = attachSuggestedFix(proposal(), { paid: true });
    const body = findingToTicket(out.finding, { paid: true }).body;
    expect(body).toContain("**Fix:** Drop the unread parameter.");
    expect(body).toContain("```diff");
    expect(body).toContain("+export async function GET() {");
    expect(body).toContain("Mechanically verified");
    expect(body.indexOf("**Fix:**")).toBeLessThan(body.indexOf("```diff"));
  });

  it("states what was actually checked, not a bare 'verified'", () => {
    const sentence = verificationSentence(evidence());
    expect(sentence).toContain("applies cleanly");
    expect(sentence).toContain("M5 — Unused parameter");
    expect(sentence).toContain("npm run test");
  });

  it("names skipped client checks rather than counting them as passes", () => {
    const sentence = verificationSentence(evidence({ clientChecks: [check(), check({ command: "npm run e2e", skipped: "needs-ci" })] }));
    expect(sentence).toContain("1 check(s) were skipped");
    expect(sentence).toContain("needs-ci");
  });
});

describe("#825 — a diff that is not verified is never filed", () => {
  it("REFUSES a non-green diff and carries the upstream's reason verbatim", () => {
    const out = attachSuggestedFix(proposal({ green: false, rejectReason: "detector M5 — Unused parameter still fires after the fix" }), { paid: true });
    expect(out.attached).toBe(false);
    expect(out.finding.suggestedFix).toBeUndefined();
    expect(out.reason).toContain("still fires");
  });

  it("leaves the ticket body on prose only when the diff was refused — no empty fence, no half-fix", () => {
    const out = attachSuggestedFix(proposal({ green: false, rejectReason: "client checks FAIL after the fix" }), { paid: true });
    const body = findingToTicket(out.finding, { paid: true }).body;
    expect(body).toContain("**Fix:** Drop the unread parameter.");
    expect(body).not.toContain("```diff");
  });

  it("refuses a green verdict over an empty diff rather than filing an empty patch", () => {
    const out = attachSuggestedFix(proposal({ diff: "   \n" }), { paid: true });
    expect(out.attached).toBe(false);
    expect(out.reason).toContain("diff is empty");
  });

  it("never re-decides green — a refusal reason cannot rescue a false, and a green is taken verbatim", () => {
    // computeGreen upstream owns the verdict. If this module could second-guess it, the #1272 class
    // of vacuous pass would have a second place to hide.
    expect(attachSuggestedFix(proposal({ green: false }), { paid: true }).attached).toBe(false);
    expect(attachSuggestedFix(proposal({ green: false }), { paid: true }).reason).toContain("no reason was recorded");
  });
});

describe("#825 — no diff for free-tier or Info/Review findings", () => {
  it("attaches nothing on a free-tier engagement, even for a Confirmed Critical", () => {
    const out = attachSuggestedFix(proposal({ finding: finding({ severity: "Critical" }) }), { paid: false });
    expect(out.attached).toBe(false);
    expect(out.reason).toContain("free-tier");
    expect(out.finding.suggestedFix).toBeUndefined();
  });

  it.each<[Severity | Confidence, Partial<Finding>]>([
    ["Info", { severity: "Info" }],
    ["Watch", { severity: "Watch" }],
    ["Review", { confidence: "Review" }],
    ["N/A", { confidence: "N/A" }],
  ])("attaches nothing to a %s finding", (_label, over) => {
    const out = attachSuggestedFix(proposal({ finding: finding(over) }), { paid: true });
    expect(out.attached).toBe(false);
    expect(out.finding.suggestedFix).toBeUndefined();
  });

  it("never offers a diff to a finding the ticket filer would itself exclude", () => {
    // The two floors are written independently on purpose (a diff must never be MORE permissive than
    // the filer). This test is what keeps them from silently diverging.
    const cases = [finding({ severity: "Info" }), finding({ severity: "Watch" }), finding({ confidence: "Review" }), finding({ confidence: "N/A" })];
    for (const f of cases) {
      expect(filingEligibility([f], true).fileable, `${f.severity}/${f.confidence} is fileable but gets no diff`).toEqual([]);
      expect(attachSuggestedFix(proposal({ finding: f }), { paid: true }).attached).toBe(false);
    }
    // …and the converse: a finding the filer accepts is one the seam will attach to.
    expect(filingEligibility([finding()], true).fileable).toHaveLength(1);
    expect(attachSuggestedFix(proposal(), { paid: true }).attached).toBe(true);
  });
});

describe("#825 — the batch form accounts for every proposal", () => {
  it("attaches only the findings a diff was proposed for, and leaves the rest untouched", () => {
    const docFindings = [finding(), finding({ id: "F-2" })];
    const ledger = attachAll(docFindings, new Map([["F-1", proposal()]]), { paid: true });
    expect(ledger.attached.map((a) => a.findingId)).toEqual(["F-1"]);
    expect(ledger.refused).toEqual([]);
    expect(ledger.findings.find((f) => f.id === "F-1")?.suggestedFix).toBeDefined();
    expect(ledger.findings.find((f) => f.id === "F-2")?.suggestedFix).toBeUndefined();
  });

  it("records a refusal as a ROW WITH A REASON — never a silent drop", () => {
    const ledger = attachAll([finding()], new Map([["F-1", proposal({ green: false, rejectReason: "did not apply" })]]), { paid: true });
    expect(ledger.attached).toEqual([]);
    expect(ledger.refused).toHaveLength(1);
    expect(ledger.refused[0]!.reason).toContain("did not apply");
  });

  it("throws on a diff written against a finding that is not in the document", () => {
    // A stale finding id is exactly how a fix silently applies to the wrong thing. Fail loud.
    expect(() => attachAll([finding()], new Map([["F-GHOST", proposal({ finding: finding({ id: "F-GHOST" }) })]]), { paid: true })).toThrow(/not in the document/);
  });
});
