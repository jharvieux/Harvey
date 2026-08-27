import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "../findings.js";
import type { FixPlan } from "./plan.js";
import { renderPrBody } from "./result.js";
import type { VerificationEvidence } from "./verify.js";
import { createClient, deliverFix, openDraftPr, pushFixBranch, violatesRollback, type CommandRunner } from "./transport.js";

// A recording runner: captures every git/gh invocation so a refusal can be proven to happen BEFORE any
// command is issued, and the happy path can be inspected without a real remote or network.
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

const finding: Finding = {
  id: "F-1", title: "Unused param", severity: "Low", confidence: "Confirmed", category: "Maintainability",
  taxonomy: "M5 — Unused parameter", location: "src/a.ts:8", status: "Open", evidence: "e", impact: "i",
  fix: "drop it", value: 3, ease: 5, safety: 5,
};

const plan: FixPlan = {
  findingId: "F-1", severity: "Low", category: "Maintainability", mode: "auto", detectorId: "M5 — Unused parameter",
  approach: "Drop the unused param.", blastRadius: { files: ["src/a.ts"], createdFiles: [], symbols: [], callers: [], behaviorPreserving: true, estimatedChangedLines: 2 },
  verifyCommands: [], testPlan: "", tier: "cheap", risks: [],
};

function evidence(green: boolean): VerificationEvidence {
  return {
    findingId: "F-1", worktreeCommit: "w", baselineCommit: "base",
    detectorBefore: { detectorId: "M5 — Unused parameter", fired: true, output: "" },
    detectorAfter: { detectorId: "M5 — Unused parameter", fired: green ? false : true, output: "" },
    clientChecks: [], green, attempts: 1,
  };
}

const prUrl = "https://github.com/acme/app/pull/7";
const draftArgs = ["api", "--method", "POST", "repos/{owner}/{repo}/pulls", "--input", "-", "--jq", "{url: .html_url, draft: .draft}"];
const canary = "SYNTHETIC_PR_1778_";
const tempDirs: string[] = [];

afterEach(() => {
  vi.unstubAllEnvs();
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

interface ProcessCall {
  file: string;
  args: string[];
  cwd: string;
  stdin: string;
  canaryInEnvironment: boolean;
}

// Exercise the shipping execFileSync binding. These local executables only record argv/stdin;
// neither contains a real git/gh invocation, a remote, or any network operation.
function recordingExecutables(opts: { selfTarget?: boolean; fail?: boolean; response?: string } = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "harvey-pr-transport-")));
  tempDirs.push(root);
  const bin = join(root, "bin");
  const targetDir = join(root, "client");
  const selfCommon = join(root, "harvey-common");
  const targetCommon = join(root, "client-common");
  for (const dir of [bin, targetDir, selfCommon, targetCommon]) mkdirSync(dir);
  const log = join(root, "calls.jsonl");
  writeFileSync(log, "");
  const script = `#!${process.execPath}
const { appendFileSync, readFileSync } = require("node:fs");
const { basename } = require("node:path");
const file = basename(process.argv[1]);
const args = process.argv.slice(2);
const stdin = readFileSync(0, "utf8");
appendFileSync(${JSON.stringify(log)}, JSON.stringify({
  file, args, cwd: process.cwd(), stdin,
  canaryInEnvironment: Object.values(process.env).some(value => value?.includes(${JSON.stringify(canary)})),
}) + "\\n");
if (file === "git" && args[2] === "rev-parse") {
  process.stdout.write(args[1] === ${JSON.stringify(targetDir)} ? ${JSON.stringify(opts.selfTarget ? selfCommon : targetCommon)} : ${JSON.stringify(selfCommon)});
} else if (file === "gh") {
  if (${opts.fail ?? false}) {
    process.stdout.write(stdin);
    process.stderr.write(stdin);
    process.exitCode = 17;
  } else {
    process.stdout.write(${JSON.stringify(opts.response ?? JSON.stringify({ url: prUrl, draft: true }))});
  }
}
`;
  for (const file of ["git", "gh"]) writeFileSync(join(bin, file), script, { mode: 0o700 });
  vi.stubEnv("PATH", `${bin}${delimiter}${process.env.PATH ?? ""}`);
  return {
    targetDir,
    calls: (): ProcessCall[] => readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as ProcessCall),
  };
}

describe("default PR process transport", () => {
  it("delivers the full rendered finding, plan, and verification through stdin, never argv or environment", () => {
    const fixture = recordingExecutables();
    const payloadFinding = { ...finding, title: `${canary}FINDING`, evidence: `${canary}EVIDENCE: "quoted"\n\t$() literal`, impact: `${canary}IMPACT` };
    const payloadPlan = { ...plan, approach: `${canary}PLAN: keep \\paths\\ and résumé\r\n  whitespace  ` };
    const payloadEvidence = { ...evidence(true), newTestAdded: `${canary}VERIFICATION` };
    const summary = `${canary}TITLE: preserve "quotes", $(), and résumé`;
    const operator = `${canary}OPERATOR`;
    const result = deliverFix(createClient({ targetDir: fixture.targetDir, dryRun: false }), {
      finding: payloadFinding, plan: payloadPlan, evidence: payloadEvidence,
      operator, baseBranch: "main", summary, tiersUsed: ["cheap"],
    });
    const calls = fixture.calls();
    for (const call of calls) {
      expect(call.args.join("\n")).not.toContain(canary);
      expect(call.canaryInEnvironment).toBe(false);
      if (call.file === "git") expect(call.stdin).toBe("");
    }
    const ghCalls = calls.filter((call) => call.file === "gh");
    expect(ghCalls).toHaveLength(1);
    expect(ghCalls[0]!.args).toEqual(draftArgs);
    expect(ghCalls[0]!.cwd).toBe(fixture.targetDir);
    const request = JSON.parse(ghCalls[0]!.stdin);
    expect(request).toEqual({
      base: "main", head: "harvey/fix/F-1", title: `[F-1] ${summary}`,
      body: renderPrBody(result, payloadFinding, operator), draft: true, maintainer_can_modify: true,
    });
    for (const field of ["FINDING", "EVIDENCE", "IMPACT", "PLAN", "VERIFICATION", "OPERATOR"]) {
      expect(request.body).toContain(`${canary}${field}`);
    }
    expect(result.outcome).toBe("pr-opened");
    expect(result.prUrl).toBe(prUrl);
  });

  it("preserves an explicit title and body exactly and does not accept a caller's draft override", () => {
    const fixture = recordingExecutables();
    const input = {
      base: "main", head: "harvey/fix/F-1", draft: false,
      title: `  ${canary}TITLE "quotes" 'single' \\backslash\\ \t résumé  `,
      body: `\r\n${canary}BODY\n\t"quotes" 'single' $() \\paths\\ résumé\r\n  `,
    };
    expect(openDraftPr(createClient({ targetDir: fixture.targetDir, dryRun: false }), input)).toEqual({ opened: true, url: prUrl });
    const gh = fixture.calls().find((call) => call.file === "gh")!;
    expect(JSON.parse(gh.stdin)).toEqual({
      base: input.base, head: input.head, title: input.title, body: input.body, draft: true, maintainer_can_modify: true,
    });
    expect(gh.args).toEqual(draftArgs);
  });

  it("withholds both push and draft creation by default before spawning any process", () => {
    const fixture = recordingExecutables();
    const client = createClient({ targetDir: fixture.targetDir });
    expect(pushFixBranch(client, "harvey/fix/F-1").pushed).toBe(false);
    expect(openDraftPr(client, { base: "main", head: "harvey/fix/F-1", title: "t", body: "b" }).opened).toBe(false);
    expect(fixture.calls()).toEqual([]);
  });

  it("refuses invalid and protected PR heads before spawning any process", () => {
    const fixture = recordingExecutables();
    const client = createClient({ targetDir: fixture.targetDir, dryRun: false, protectedBranches: ["harvey/fix/protected"] });
    for (const head of ["main", "feature/x", "harvey/fix/protected"]) {
      expect(() => openDraftPr(client, { base: "main", head, title: "t", body: "b" })).toThrow(/refusing/);
    }
    expect(fixture.calls()).toEqual([]);
  });

  it("refuses pushes and draft creation against Harvey's own shared git directory", () => {
    const fixture = recordingExecutables({ selfTarget: true });
    const client = createClient({ targetDir: fixture.targetDir, dryRun: false });
    expect(() => pushFixBranch(client, "harvey/fix/F-1")).toThrow(/Harvey's own repository/);
    expect(() => openDraftPr(client, { base: "main", head: "harvey/fix/F-1", title: "t", body: "b" })).toThrow(/Harvey's own repository/);
    const calls = fixture.calls();
    expect(calls).toHaveLength(4);
    expect(calls.every((call) => call.file === "git" && call.args[2] === "rev-parse")).toBe(true);
  });

  it("withholds echoed stdin, stdout, and stderr from process-failure diagnostics", () => {
    const fixture = recordingExecutables({ fail: true });
    let failure: unknown;
    try {
      openDraftPr(createClient({ targetDir: fixture.targetDir, dryRun: false }), {
        base: "main", head: "harvey/fix/F-1", title: `${canary}TITLE`, body: `${canary}BODY`,
      });
    } catch (error) { failure = error; }
    expect(failure).toBeInstanceOf(Error);
    expect(String(failure)).toMatch(/gh transport failed.*exit 17.*output withheld/);
    expect(String(failure)).not.toContain(canary);
    expect(JSON.stringify(failure)).not.toContain(canary);
    for (const key of ["cause", "stdout", "stderr", "output", "spawnargs"]) expect(failure).not.toHaveProperty(key);
  });

  it.each([
    "", `${canary}NOT_JSON`,
    JSON.stringify({ url: prUrl, draft: false }),
    JSON.stringify({ url: `${canary}NOT_A_URL`, draft: true }),
    JSON.stringify({ url: "https://github.com/acme/app/settings", draft: true }),
  ])("refuses malformed or non-draft replies without exposing their payload (%#)", (response) => {
    const fixture = recordingExecutables({ response });
    expect(() => openDraftPr(createClient({ targetDir: fixture.targetDir, dryRun: false }), {
      base: "main", head: "harvey/fix/F-1", title: "t", body: "b",
    })).toThrow("gh draft PR creation returned an invalid draft response; output withheld (verify the remote before retrying)");
  });
});

describe("wrapper-enforced push rails", () => {
  it("refuses a non-harvey/fix ref at the wrapper, before any command runs", () => {
    const { calls, run } = recorder();
    const client = createClient({ targetDir: "/x", dryRun: false, run });
    expect(() => pushFixBranch(client, "feature/x")).toThrow(/non-fix ref/);
    expect(calls).toHaveLength(0); // refused before git was touched
  });

  it("refuses a protected-branch target (main) at the wrapper, before any command runs", () => {
    const { calls, run } = recorder();
    const client = createClient({ targetDir: "/x", dryRun: false, run });
    expect(() => pushFixBranch(client, "main")).toThrow();
    expect(calls).toHaveLength(0);
  });

  it("withholds the push under the default dry-run and never calls git push", () => {
    const { calls, run } = recorder();
    const client = createClient({ targetDir: "/x", run }); // dryRun defaults true
    const r = pushFixBranch(client, "harvey/fix/F-1");
    expect(r.pushed).toBe(false);
    expect(r.reason).toContain("dry-run");
    expect(calls.some((c) => c.file === "git" && c.args[0] === "push")).toBe(false);
  });

  it("opens a draft PR with --draft and only when not dry-run", () => {
    const { calls, run } = recorder({ "gh pr create": "https://github.com/acme/app/pull/7" });
    const dry = openDraftPr(createClient({ targetDir: "/x", run }), { base: "main", head: "harvey/fix/F-1", title: "t", body: "b" });
    expect(dry.opened).toBe(false);

    // A live client needs the self-check to pass; that path is covered by deliverFix's guard test.
    expect(calls.some((c) => c.file === "gh")).toBe(false);
  });
});

describe("deliverFix", () => {
  it("recommend-only for a non-green fix, with the evidence attached and no transport", () => {
    const { calls, run } = recorder();
    const client = createClient({ targetDir: "/x", dryRun: false, run });
    const r = deliverFix(client, { finding, plan, evidence: evidence(false), operator: "jane", baseBranch: "main", summary: "Drop unused param", tiersUsed: ["cheap"] });
    expect(r.outcome).toBe("recommend-only");
    expect(r.evidence?.green).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it("aborts a green fix whose diff would falsify the rollback paragraph (touches a migration)", () => {
    const { run } = recorder();
    const client = createClient({ targetDir: "/x", dryRun: false, run });
    const migPlan = { ...plan, blastRadius: { ...plan.blastRadius, files: ["supabase/migrations/001.sql"] } };
    const r = deliverFix(client, { finding, plan: migPlan, evidence: evidence(true), operator: "jane", baseBranch: "main", summary: "x", tiersUsed: ["cheap"] });
    expect(r.outcome).toBe("aborted");
    expect(r.downgradeOrAbortReason).toContain("rollback-unsafe");
  });

  it("under dry-run, a green fix creates the branch but withholds the PR", () => {
    const { calls, run } = recorder();
    const client = createClient({ targetDir: "/x", run }); // dry-run default
    const r = deliverFix(client, { finding, plan, evidence: evidence(true), operator: "jane", baseBranch: "main", summary: "Drop unused param", tiersUsed: ["cheap"] });
    expect(r.outcome).toBe("recommend-only");
    expect(r.branch).toBe("harvey/fix/F-1");
    expect(r.downgradeOrAbortReason).toContain("withheld");
    expect(calls.some((c) => c.file === "gh")).toBe(false);
  });
});

describe("violatesRollback", () => {
  it("flags migrations, dependency manifests, lockfiles, and config", () => {
    expect(violatesRollback(["supabase/migrations/001.sql"])).toBeTruthy();
    expect(violatesRollback(["package.json"])).toBe("package.json");
    expect(violatesRollback(["pnpm-lock.yaml"])).toBe("pnpm-lock.yaml");
    expect(violatesRollback(["next.config.js"])).toBeTruthy();
  });
  it("passes an ordinary source-only fix", () => {
    expect(violatesRollback(["apps/main/src/a.ts", "apps/main/src/b.ts"])).toBeUndefined();
  });
});

// §6: the fixed draft-create endpoint is the only PR-affecting command — merge/ready/settings are ABSENT, not
// merely unused. This guards the source itself so a future edit can't quietly add one.
describe("no privileged PR mutations exist in the transport source", () => {
  it("contains no merge, ready-for-review, or repo-settings gh call", () => {
    const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "transport.ts"), "utf8");
    // Strip line comments — the guard is about the CODE, and the header comment documents these very
    // absences by name.
    const code = src.replace(/\/\/.*$/gm, "");
    const withoutDraftEndpoint = code.replace('"repos/{owner}/{repo}/pulls"', '"fixed-draft-endpoint"');
    for (const forbidden of [/"merge"/, /"ready"/, /--merge\b/, /ready-for-review/, /"repos\//, /"repo", "edit"/]) {
      expect(withoutDraftEndpoint, `forbidden token ${forbidden} present in transport code`).not.toMatch(forbidden);
    }
    expect(code).toContain('"api", "--method", "POST", "repos/{owner}/{repo}/pulls", "--input", "-"');
    expect(code).toContain('draft: true, maintainer_can_modify: true');
  });
});
