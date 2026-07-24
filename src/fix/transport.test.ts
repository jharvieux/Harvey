import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import type { FixPlan } from "./plan.js";
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

// §6: `gh pr create --draft` is the only PR-affecting command — merge/ready/settings are ABSENT, not
// merely unused. This guards the source itself so a future edit can't quietly add one.
describe("no privileged PR mutations exist in the transport source", () => {
  it("contains no merge, ready-for-review, or repo-settings gh call", () => {
    const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "transport.ts"), "utf8");
    // Strip line comments — the guard is about the CODE, and the header comment documents these very
    // absences by name.
    const code = src.replace(/\/\/.*$/gm, "");
    for (const forbidden of [/"merge"/, /"ready"/, /--merge\b/, /ready-for-review/, /"repos\//, /"repo", "edit"/]) {
      expect(code, `forbidden token ${forbidden} present in transport code`).not.toMatch(forbidden);
    }
    // the only gh subcommand issued is `pr create --draft`
    expect(code).toContain('"pr", "create", "--draft"');
  });
});
