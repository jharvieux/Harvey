import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { buildOwaspWatchDecision, encodeOwaspReceipt, type OwaspProposalSnapshot } from "./owasp-ack-watch.js";

const issue = (number: number, state: "open" | "closed", labels: string[], comments = 0): OwaspProposalSnapshot => ({
  number, state, labels, comments, url: `https://github.com/OWASP/CheatSheetSeries/issues/${number}`,
  ...(comments ? { latestComment: { author: "maintainer", createdAt: "2026-09-24T00:00:00Z", body: "Please update the proposal." } } : {}),
});
const decide = (current: OwaspProposalSnapshot[], previous?: OwaspProposalSnapshot[]) => buildOwaspWatchDecision(current, previous ? encodeOwaspReceipt(previous) : undefined, "https://example.test/actions/runs/1");

describe("OWASP acknowledgement actionability", () => {
  it("never turns closed + ACK_OBTAINED into a drafting instruction", () => {
    const result = decide([issue(2308, "closed", ["ACK_OBTAINED"], 2), issue(2309, "closed", ["ACK_OBTAINED"], 3)]);
    expect(result.notify).toBe(true);
    expect(result.actionable).toEqual([]);
    expect(result.body).toContain("no new drafting instruction is active");
    expect(result.body).not.toContain("drafting can begin or resume");
  });

  it("keeps an open newly acknowledged proposal actionable and represents the mixed terminal peer", () => {
    const result = decide([issue(2308, "open", ["ACK_OBTAINED"], 1), issue(2309, "closed", ["ACK_OBTAINED"], 2)]);
    expect(result.actionable).toEqual([2308]);
    expect(result.headline).toContain("Only #2308 is actionable");
    expect(result.body).toContain("drafting can begin or resume");
    expect(result.body).toContain("Terminal: the proposal is closed");
  });

  it("surfaces a new maintainer request while acknowledgement is waiting", () => {
    const previous = [issue(2308, "open", ["ACK_WAITING"], 0), issue(2309, "open", [], 0)];
    const result = decide([issue(2308, "open", ["ACK_WAITING"], 1), issue(2309, "open", [], 0)], previous);
    expect(result.actionable).toEqual([2308]);
    expect(result.body).toContain("review the latest maintainer request");
  });

  it("surfaces a reopened proposal even without ACK_OBTAINED", () => {
    const previous = [issue(2308, "closed", ["ACK_WAITING"], 1), issue(2309, "closed", ["ACK_OBTAINED"], 2)];
    const result = decide([issue(2308, "open", ["ACK_WAITING"], 1), issue(2309, "closed", ["ACK_OBTAINED"], 2)], previous);
    expect(result.actionable).toEqual([2308]);
    expect(result.body).toContain("proposal was reopened");
  });

  it("uses a completed-state receipt even after the tracking issue is closed", () => {
    const completed = [issue(2308, "closed", ["ACK_OBTAINED"], 2), issue(2309, "closed", ["ACK_OBTAINED"], 3)];
    const first = decide(completed);
    const repeated = buildOwaspWatchDecision(completed, first.receipt, "https://example.test/actions/runs/2");
    expect(first.notify).toBe(true);
    expect(repeated.notify).toBe(false);
  });

  it("the workflow invokes this shipping decision path and searches closed receipts", () => {
    const workflow = readFileSync(resolve(import.meta.dirname, "../.github/workflows/owasp-ack-watch.yml"), "utf8");
    expect(workflow).toContain("src/owasp-ack-watch.ts");
    expect(workflow).toContain("gh issue list --state all");
    expect(workflow).toContain("owasp-ack-receipt:");
  });
});
