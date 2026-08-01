// End-to-end proof of the INTERACTIVE fix-implementer (#1056): emit a prompt from a verified finding,
// then ingest a hand-authored diff through the SAME rails an LLM's diff would have hit. Offline: the M5
// unused-parameter class resolves through the in-process AST engine, so this runs without semgrep and
// belongs in the light `pnpm verify` suite. It proves both outcomes the ruling cares about — a correct
// diff clears computeGreen and reaches the DRAFT-PR transport; a wrong diff is rejected before any PR.
//
// #1272 adds the half that was hardcoded `clientChecks: []`. The corpora below carry a real
// package.json whose `test` script is really executed by `npm run test` — in a baseline worktree cut at
// the pinned commit AND in the fixed worktree — so the four states the contract distinguishes are each
// proven against an actual exit code, not a stub: the client suite passes (green), the fix BREAKS the
// client suite (rejected, and green before this wiring), the suite was already red at baseline
// (skipped, green survives), and nothing was discoverable at all (rejected — never a vacuous pass).

import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import type { FixPlan } from "./plan.js";
import { emitFixPrompt, ingestFixDiff } from "./interactive.js";
import type { BaselineCache } from "./verify-harness.js";
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

// A client check that is REALLY spawned (`npm run test`, no dependencies needed). Two flavours:
// `contract` asserts the unused parameter is still present, so the correct fix BREAKS it — the
// "satisfies the scanner, breaks the app" case §2 exists to catch; `ok`/`red` are unconditional.
const CLIENT_TESTS = {
  ok: "console.log('client suite ok');\n",
  red: "console.error('client suite was already failing');\nprocess.exit(1);\n",
  contract:
    `const src = require("node:fs").readFileSync(${JSON.stringify(M5_FILE)}, "utf8");\n` +
    `if (!src.includes("request: Request")) { console.error("client contract broken by the fix"); process.exit(1); }\n` +
    `console.log("client suite ok");\n`,
};
const clientRepo = (src: string, suite: keyof typeof CLIENT_TESTS) => ({
  [M5_FILE]: src,
  "package.json": `${JSON.stringify({ name: "client", private: true, scripts: { test: "node client-test.js" } }, null, 2)}\n`,
  "client-test.js": CLIENT_TESTS[suite],
});
// The client's own runner. npm is used rather than pnpm because a materialized corpus has no lockfile
// and pnpm's deps-status check would fail the command for a reason unrelated to any fix.
const NPM = "npm";

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
  it("a CORRECT diff clears computeGreen and reaches the draft-PR transport", async () => {
    const src = readCalibration(M5_FILE);
    const c = corpus(clientRepo(src, "ok"));
    const diff = capturePatch(c, M5_FILE, dropParam(src));

    const ingest = await ingestFixDiff({ finding, diff, targetDir: c.dir, baselineCommit: c.commit, allowlist: ["app/**"], runner: NPM });
    expect(ingest.execution.outcome).toBe("diff-verified");
    expect(ingest.evidence.detectorAfter.notRun).toBeUndefined(); // the detector really re-ran
    expect(ingest.evidence.detectorAfter.fired).toBe(false); // and it stopped firing
    // The client half is EVIDENCE now, not an empty array: the discovered command really ran.
    expect(ingest.evidence.clientChecks.map((x) => x.command)).toEqual(["npm run test"]);
    expect(ingest.evidence.clientChecks[0]!.exitCode).toBe(0);
    expect(ingest.evidence.clientChecks[0]!.skipped).toBeUndefined();
    expect(ingest.evidence.clientChecks[0]!.outputTail).toContain("client suite ok");
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

  it("a WRONG diff (applies clean but leaves the detector firing) is REJECTED, and the transport is never reached", async () => {
    const src = readCalibration(M5_FILE);
    const c = corpus(clientRepo(src, "ok"));
    const noop = src.replace("export async function GET(request: Request) {", "export async function GET(request: Request) { // touched");
    expect(noop).not.toEqual(src);
    const diff = capturePatch(c, M5_FILE, noop);

    const ingest = await ingestFixDiff({ finding, diff, targetDir: c.dir, baselineCommit: c.commit, allowlist: ["app/**"], runner: NPM });
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

  it("a diff touching a denylisted path is rails-blocked, the detector is never re-run, and the result is rejected", async () => {
    const src = readCalibration(M5_FILE);
    const c = corpus({ [M5_FILE]: src, ".env": "SECRET=1\n" });
    const diff = ["--- a/.env", "+++ b/.env", "@@ -1 +1 @@", "-SECRET=1", "+SECRET=2", ""].join("\n");

    const ingest = await ingestFixDiff({ finding, diff, targetDir: c.dir, baselineCommit: c.commit, allowlist: ["**"], runner: NPM });
    expect(ingest.execution.outcome).toBe("rails-blocked");
    expect(ingest.evidence.detectorAfter.notRun).toBeDefined(); // fail loud: unrun ≠ clean
    expect(ingest.green).toBe(false);
    expect(ingest.rejected).toBe(true);
    expect(ingest.rejectReason).toContain("rails/apply gate");
  });
});

// #1272 — the client half of the §2 contract, each state proven against a real exit code. Before this
// wiring every one of these ingests returned green: `clientChecks` was hardcoded `[]` and
// `[].every(...)` is vacuously true, so "the detector stopped firing" was the whole decision.
describe("interactive fix — the §2.1 client-check half (#1272)", () => {
  it("REJECTS a fix that silences the detector but BREAKS the client's own suite", async () => {
    const src = readCalibration(M5_FILE);
    const c = corpus(clientRepo(src, "contract"));
    const diff = capturePatch(c, M5_FILE, dropParam(src));

    const ingest = await ingestFixDiff({ finding, diff, targetDir: c.dir, baselineCommit: c.commit, allowlist: ["app/**"], runner: NPM });
    expect(ingest.execution.outcome).toBe("diff-verified"); // it applies
    expect(ingest.evidence.detectorAfter.fired).toBe(false); // and the detector IS clean
    const check = ingest.evidence.clientChecks[0]!;
    expect(check.skipped).toBeUndefined(); // it ran on the baseline too, and passed there
    expect(check.exitCode).toBe(1);
    expect(check.outputTail).toContain("client contract broken by the fix");
    expect(ingest.green).toBe(false); // …so it is NOT a verified fix
    expect(ingest.rejectReason).toContain("the client's own checks FAIL");
  });

  it("does NOT go green when no client verify command can be discovered at all", async () => {
    // No package.json, no pull_request workflow: nothing to run. The old code called that green.
    const src = readCalibration(M5_FILE);
    const c = corpus({ [M5_FILE]: src });
    const diff = capturePatch(c, M5_FILE, dropParam(src));

    const ingest = await ingestFixDiff({ finding, diff, targetDir: c.dir, baselineCommit: c.commit, allowlist: ["app/**"], runner: NPM });
    expect(ingest.evidence.detectorAfter.fired).toBe(false);
    expect(ingest.evidence.clientChecks).toEqual([]);
    expect(ingest.green).toBe(false);
    expect(ingest.rejectReason).toContain("no client verify command could be discovered");
  });

  it("a check already RED at the pinned baseline is skipped, named, and does not cost the fix its green", async () => {
    // §2.1 step 3: the baseline run exists so a pre-existing failure is never charged to the fix.
    const src = readCalibration(M5_FILE);
    const c = corpus(clientRepo(src, "red"));
    const diff = capturePatch(c, M5_FILE, dropParam(src));

    const ingest = await ingestFixDiff({ finding, diff, targetDir: c.dir, baselineCommit: c.commit, allowlist: ["app/**"], runner: NPM });
    const check = ingest.evidence.clientChecks[0]!;
    expect(check.skipped).toBe("pre-existing-failure-on-baseline");
    expect(check.outputTail).toContain("client suite was already failing"); // visible, not swallowed
    expect(ingest.green).toBe(true);
  });

  // #1529. The baseline is a property of (targetDir, baselineCommit, workspace, command) — identical
  // for every finding in one batch — and running it per fix made an N-fix batch execute the client's
  // own suite 2N times. These two tests are the same workload with and without the shared map, so the
  // saving is a measured difference rather than an assertion about one run.
  it("runs a distinct baseline command ONCE across two ingests that share a cache", async () => {
    const src = readCalibration(M5_FILE);
    const c = corpus(clientRepo(src, "ok"));
    const diff = capturePatch(c, M5_FILE, dropParam(src));
    const baselineCache: BaselineCache = new Map();
    const args = { finding, diff, targetDir: c.dir, baselineCommit: c.commit, allowlist: ["app/**"], runner: NPM, baselineCache };

    const first = await ingestFixDiff(args);
    const second = await ingestFixDiff(args);
    expect(first.baseline).toMatchObject({ requested: 1, executed: 1 });
    expect(second.baseline).toMatchObject({ requested: 1, executed: 0 });
    // The saving is real time, not just a counter: the second ingest spends none of it on a baseline.
    // Stated as a RATIO, not as an exact 0 (#1674). `durationMs` is `Date.now() - started` around the
    // work, so a cache hit that does no work still reads 1 whenever the clock ticks between the two
    // reads — a real elapsed measurement, and the exact-zero form failed CI on that (run 30618536115,
    // `expected 1 to be +0`). The ratio keeps the failing direction the exact form had: with the cache
    // removed the second ingest re-runs the same worktree + client suite, so the two are comparable
    // and 10x apart is unreachable. It is also more robust on a slow runner, not less — load inflates
    // the executed run, while the cache hit spawns nothing.
    expect(first.baseline.durationMs).toBeGreaterThan(0);
    expect(second.baseline.durationMs * 10).toBeLessThan(first.baseline.durationMs);
    // And the second fix is still scored on the same evidence — a cheaper run, not a weaker one.
    expect(second.green).toBe(true);
    expect(second.evidence.clientChecks.map((x) => x.command)).toEqual(["npm run test"]);
  });

  // NEGATIVE CONTROL for the test above: without the shared map the SAME workload runs the baseline
  // twice. If this ever reported 1 the assertion above would be measuring nothing.
  it("NEGATIVE CONTROL: with no shared cache the same two ingests baseline the command twice", async () => {
    const src = readCalibration(M5_FILE);
    const c = corpus(clientRepo(src, "ok"));
    const diff = capturePatch(c, M5_FILE, dropParam(src));
    const args = { finding, diff, targetDir: c.dir, baselineCommit: c.commit, allowlist: ["app/**"], runner: NPM };

    const runs = [await ingestFixDiff(args), await ingestFixDiff(args)];
    expect(runs.map((r) => r.baseline.executed)).toEqual([1, 1]);
    expect(runs.reduce((n, r) => n + r.baseline.executed, 0)).toBe(2);
  });

  // #1464. #1529's saving was written for a SERIAL batch: a map of finished runs is only populated
  // once the first ingest returns, so the moment the ingest chain became async two overlapping
  // ingests would both find it empty and both run the client's own suite. The cache holds the
  // in-flight PROMISE, registered before the first await, which is what makes this hold. Reverting
  // `cache.set(..., fresh.then(...))` in src/fix/interactive.ts to a post-await value write turns
  // this red (executed reads [1, 1]) while the serial test above stays green.
  it("runs a distinct baseline command ONCE across two CONCURRENT ingests that share a cache", async () => {
    const src = readCalibration(M5_FILE);
    const c = corpus(clientRepo(src, "ok"));
    const diff = capturePatch(c, M5_FILE, dropParam(src));
    const baselineCache: BaselineCache = new Map();
    const args = { finding, diff, targetDir: c.dir, baselineCommit: c.commit, allowlist: ["app/**"], runner: NPM, baselineCache };

    const [first, second] = await Promise.all([ingestFixDiff(args), ingestFixDiff(args)]);
    expect(first!.baseline.requested + second!.baseline.requested).toBe(2); // both asked for it
    expect(first!.baseline.executed + second!.baseline.executed).toBe(1); // exactly one ran it
    expect(first!.green).toBe(true);
    expect(second!.green).toBe(true);
    expect(second!.evidence.clientChecks.map((x) => x.command)).toEqual(["npm run test"]);
  });

  // A cache keyed only on (workspace, command) would serve one engagement's baseline to another.
  it("keys the shared baseline on the checkout and the pinned commit, not on the command alone", async () => {
    const src = readCalibration(M5_FILE);
    const c = corpus(clientRepo(src, "ok"));
    const diff = capturePatch(c, M5_FILE, dropParam(src));
    const baselineCache: BaselineCache = new Map();
    await ingestFixDiff({ finding, diff, targetDir: c.dir, baselineCommit: c.commit, allowlist: ["app/**"], runner: NPM, baselineCache });
    const key = [...baselineCache.keys()][0] as string;
    expect(key).toContain(c.commit);
    expect(key).toContain(c.dir);
  });

  it("discovers a pull_request-triggered workflow's run: steps alongside the package.json scripts", async () => {
    const src = readCalibration(M5_FILE);
    const c = corpus({
      ...clientRepo(src, "ok"),
      ".github/workflows/ci.yml": "on:\n  pull_request:\njobs:\n  x:\n    steps:\n      - run: node client-test.js\n",
      ".github/workflows/deploy.yml": "on:\n  push:\njobs:\n  y:\n    steps:\n      - run: node -e \"process.exit(1)\"\n",
    });
    const diff = capturePatch(c, M5_FILE, dropParam(src));

    const ingest = await ingestFixDiff({ finding, diff, targetDir: c.dir, baselineCommit: c.commit, allowlist: ["app/**"], runner: NPM });
    // The PR-triggered step is in; the push-only workflow's failing step is NOT (it would have made
    // this red for a reason no pull request would ever have surfaced).
    expect(ingest.evidence.clientChecks.map((x) => x.command)).toEqual(["npm run test", "node client-test.js"]);
    expect(ingest.green).toBe(true);
  });
});
