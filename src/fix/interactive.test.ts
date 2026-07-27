// End-to-end proof of the INTERACTIVE fix-implementer (#1056): emit a prompt from a verified finding,
// then ingest a hand-authored diff through the SAME rails an LLM's diff would have hit. Offline: the M5
// unused-parameter class resolves through the in-process AST engine, so this runs without semgrep and
// belongs in the light `pnpm verify` suite. It proves both outcomes the ruling cares about — a correct
// diff clears computeGreen and reaches the DRAFT-PR transport; a wrong diff is rejected before any PR.

import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import type { FixPlan } from "./plan.js";
import { emitFixPrompt, ingestFixDiff } from "./interactive.js";
import { capturePatch, disposeCorpus, materialize, readCalibration, type MaterializedCorpus } from "./materialize-calibration.js";
import { deliverFix, createClient, type CommandRunner } from "./transport.js";

const M5_FILE = "app/api/ar-cors-reflected-safe/route.ts";
const finding: Finding = {
  id: "CAL-UNUSED-PARAM", title: "Unused parameter", severity: "Low", confidence: "Confirmed",
  category: "Maintainability", taxonomy: "M5 — Unused parameter", location: `${M5_FILE}:8`,
  status: "Open", evidence: "GET(request: Request) never reads request", impact: "dead surface",
  fix: "drop the unused parameter", value: 3, ease: 5, safety: 5,
};
const plan: FixPlan = {
  findingId: finding.id, severity: "Low", category: "Maintainability", mode: "auto",
  detectorId: finding.taxonomy, approach: "Drop the unread `request` parameter from GET.",
  blastRadius: { files: [M5_FILE], createdFiles: [], symbols: [], callers: [], behaviorPreserving: true, estimatedChangedLines: 1 },
  verifyCommands: [], testPlan: "", tier: "cheap", risks: [],
};
const dropParam = (src: string) => src.replace("export async function GET(request: Request) {", "export async function GET() {");

const created: MaterializedCorpus[] = [];
afterEach(() => {
  for (const c of created.splice(0)) disposeCorpus(c);
});
function corpus(files: Record<string, string>): MaterializedCorpus {
  const c = materialize(files);
  created.push(c);
  return c;
}

// Recording git/gh runner (mirrors transport.test.ts): the transport never touches a real remote, and a
// draft PR can be proven to open without a network.
function recorder(responses: Record<string, string> = {}) {
  const calls: { file: string; args: string[] }[] = [];
  const run: CommandRunner = (file, args) => {
    calls.push({ file, args });
    const key = `${file} ${args.join(" ")}`;
    for (const [prefix, out] of Object.entries(responses)) if (key.startsWith(prefix)) return out;
    return "";
  };
  return { calls, run };
}

describe("interactive fix — prompt emit", () => {
  it("emits a self-contained spec: the finding, the in-scope source, the write rails, and the detector-stop acceptance criterion", () => {
    const src = readCalibration(M5_FILE);
    const prompt = emitFixPrompt({ finding, plan, baselineCommit: "abc123", allowlist: ["app/**"], sources: [{ path: M5_FILE, text: src }] });
    expect(prompt).toContain(finding.id);
    expect(prompt).toContain(finding.taxonomy); // the detector to silence
    expect(prompt).toContain(finding.location);
    expect(prompt).toContain(plan.approach); // the intended change
    expect(prompt).toContain("export async function GET(request: Request)"); // the actual source in scope
    expect(prompt).toContain("must STOP firing"); // the acceptance criterion
    expect(prompt).toContain("`app/**`"); // the allowlist rail
    expect(prompt).toContain("abc123"); // the baseline the diff must apply against
    expect(prompt).toContain("--apply-diff"); // how the operator hands the diff back
  });
});

describe("interactive fix — diff ingest through the existing rails", () => {
  it("a CORRECT diff clears computeGreen and reaches the draft-PR transport", () => {
    const src = readCalibration(M5_FILE);
    const c = corpus({ [M5_FILE]: src });
    const diff = capturePatch(c, M5_FILE, dropParam(src));

    const ingest = ingestFixDiff({ finding, diff, targetDir: c.dir, baselineCommit: c.commit, allowlist: ["app/**"] });
    expect(ingest.execution.outcome).toBe("diff-verified");
    expect(ingest.evidence.detectorAfter.notRun).toBeUndefined(); // the detector really re-ran
    expect(ingest.evidence.detectorAfter.fired).toBe(false); // and it stopped firing
    expect(ingest.green).toBe(true);
    expect(ingest.rejected).toBe(false);

    // Only a green ingest reaches the transport — and it opens a DRAFT PR, nothing more.
    const { calls, run } = recorder({ "gh pr create": "https://github.com/acme/app/pull/1" });
    const client = createClient({ targetDir: c.dir, dryRun: false, run });
    const delivered = deliverFix(client, {
      finding, plan, evidence: ingest.evidence, operator: "op", baseBranch: "main", summary: finding.title, tiersUsed: ["cheap"],
    });
    expect(delivered.outcome).toBe("pr-opened");
    expect(delivered.prUrl).toBe("https://github.com/acme/app/pull/1");
    const gh = calls.find((x) => x.file === "gh");
    expect(gh?.args).toContain("--draft"); // draft only — the operator flips it to ready
    expect(gh?.args.includes("merge")).toBe(false);
  });

  it("a WRONG diff (applies clean but leaves the detector firing) is REJECTED, and the transport is never reached", () => {
    const src = readCalibration(M5_FILE);
    const c = corpus({ [M5_FILE]: src });
    const noop = src.replace("export async function GET(request: Request) {", "export async function GET(request: Request) { // touched");
    expect(noop).not.toEqual(src);
    const diff = capturePatch(c, M5_FILE, noop);

    const ingest = ingestFixDiff({ finding, diff, targetDir: c.dir, baselineCommit: c.commit, allowlist: ["app/**"] });
    expect(ingest.execution.outcome).toBe("diff-verified"); // it DID apply
    expect(ingest.evidence.detectorAfter.fired).toBe(true); // but the bug is still there
    expect(ingest.green).toBe(false);
    expect(ingest.rejected).toBe(true);
    expect(ingest.rejectReason).toContain("still fires");

    // deliverFix on a non-green evidence never opens a PR — it downgrades to recommend-only.
    const { calls, run } = recorder();
    const client = createClient({ targetDir: c.dir, dryRun: false, run });
    const delivered = deliverFix(client, {
      finding, plan, evidence: ingest.evidence, operator: "op", baseBranch: "main", summary: finding.title, tiersUsed: ["cheap"],
    });
    expect(delivered.outcome).toBe("recommend-only");
    expect(calls.some((x) => x.file === "gh")).toBe(false); // no PR command issued at all
  });

  it("a diff touching a denylisted path is rails-blocked, the detector is never re-run, and the result is rejected", () => {
    const src = readCalibration(M5_FILE);
    const c = corpus({ [M5_FILE]: src, ".env": "SECRET=1\n" });
    const diff = ["--- a/.env", "+++ b/.env", "@@ -1 +1 @@", "-SECRET=1", "+SECRET=2", ""].join("\n");

    const ingest = ingestFixDiff({ finding, diff, targetDir: c.dir, baselineCommit: c.commit, allowlist: ["**"] });
    expect(ingest.execution.outcome).toBe("rails-blocked");
    expect(ingest.evidence.detectorAfter.notRun).toBeDefined(); // fail loud: unrun ≠ clean
    expect(ingest.green).toBe(false);
    expect(ingest.rejected).toBe(true);
    expect(ingest.rejectReason).toContain("rails/apply gate");
  });
});
