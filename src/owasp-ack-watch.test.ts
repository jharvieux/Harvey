import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { buildOwaspWatchDecision, encodeOwaspReceipt, type OwaspProposalSnapshot } from "./owasp-ack-watch.js";

const issue = (number: number, state: "open" | "closed", labels: string[], comments = 0): OwaspProposalSnapshot => ({
  number, state, labels, comments, url: `https://github.com/OWASP/CheatSheetSeries/issues/${number}`,
  ...(comments ? { latestComment: { author: "maintainer", createdAt: "2026-09-24T00:00:00Z", body: "Please update the proposal." } } : {}),
});
const decide = (current: OwaspProposalSnapshot[], previous?: OwaspProposalSnapshot[]) => buildOwaspWatchDecision(current, previous ? encodeOwaspReceipt(previous) : undefined, "https://example.test/actions/runs/1");
const OWASP_WATCH = resolve(import.meta.dirname, "owasp-ack-watch.ts");

function runShippingWatch(script: string, snapshots: OwaspProposalSnapshot[], previous: string): { status: number | null; stdout: string; stderr: string; body: string } {
  const directory = mkdtempSync(join(tmpdir(), "harvey-owasp-watch-"));
  try {
    const input = join(directory, "snapshots.json");
    const body = join(directory, "message.md");
    writeFileSync(input, JSON.stringify(snapshots));
    const result = spawnSync(process.execPath, ["--experimental-strip-types", script, "--input", input, "--body", body, "--run-url", "https://example.test/actions/runs/1", "--previous", previous], { encoding: "utf8" });
    return { status: result.status, stdout: result.stdout, stderr: result.stderr, body: existsSync(body) ? readFileSync(body, "utf8") : "" };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

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

  it("alerts when a closed receipt reopens into the filing baseline through the shipping CLI", () => {
    const closed = [issue(2308, "closed", []), issue(2309, "closed", [])];
    const reopened = [issue(2308, "open", []), issue(2309, "open", [])];
    const previous = encodeOwaspReceipt(closed);
    const shipping = runShippingWatch(OWASP_WATCH, reopened, previous);
    expect(shipping.status, shipping.stderr).toBe(0);
    expect(shipping.stdout).toContain("notify=true");
    expect(shipping.body).toContain("proposal was reopened");

    const directory = mkdtempSync(join(tmpdir(), "harvey-owasp-watch-revert-"));
    try {
      const copied = join(realpathSync(directory), "owasp-ack-watch.ts");
      const source = readFileSync(OWASP_WATCH, "utf8");
      const reverted = source.replace(
        "const initialFilingBaseline = previousRows === undefined && baseline(snapshots);",
        "const initialFilingBaseline = baseline(snapshots);",
      );
      expect(reverted).not.toBe(source);
      writeFileSync(copied, reverted);
      const revertedRun = runShippingWatch(copied, reopened, previous);
      expect(revertedRun.status, revertedRun.stderr).toBe(0);
      expect(revertedRun.stdout).toContain("notify=false");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
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
