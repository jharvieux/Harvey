import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { buildWorkflowAlert, type WorkflowRunIdentity } from "./workflow-alert.js";

const run = (event: string, ref: string, head: string): WorkflowRunIdentity => ({ event, ref, head, runUrl: `https://github.test/actions/runs/${head}` });

describe("CI alert identity and recovery", () => {
  it.each([
    ["branch dispatch", run("workflow_dispatch", "refs/heads/feature/work", "1111111111111111"), "branch dispatch for feature/work", "same ref"],
    ["scheduled main", run("schedule", "refs/heads/main", "2222222222222222"), "scheduled main run", "scheduled default-branch"],
    ["pushed main", run("push", "refs/heads/main", "3333333333333333"), "main push 333333333333", "push-to-main"],
  ])("constructs the production message for %s from actual event/ref/head/run", (_name, identity, titlePart, recoveryPart) => {
    const message = buildWorkflowAlert("aggregate", identity);
    expect(message.title).toContain(titlePart);
    expect(message.body).toContain(`event \`${identity.event}\``);
    expect(message.body).toContain(`ref \`${identity.ref}\``);
    expect(message.body).toContain(`head \`${identity.head}\``);
    expect(message.body).toContain(identity.runUrl);
    expect(message.recovery).toContain(recoveryPart);
  });

  it("gives branch dispatches their own stable dedup partition without changing the main partition", () => {
    const branch = buildWorkflowAlert("heavy", run("workflow_dispatch", "refs/heads/feature/work", "1"), "shard 1 of 3");
    const branchAgain = buildWorkflowAlert("heavy", run("workflow_dispatch", "refs/heads/feature/work", "2"), "shard 2 of 3");
    const main = buildWorkflowAlert("heavy", run("schedule", "refs/heads/main", "3"));
    expect(branch.incident).toBe(branchAgain.incident);
    expect(branch.incident).toMatch(/^branch-dispatch-/);
    expect(main.incident).toBe("main");
  });

  it("describes a setup-stage heavy failure without claiming tests ran", () => {
    const message = buildWorkflowAlert("heavy", run("workflow_dispatch", "refs/heads/feature/work", "4"), "setup step before test execution");
    expect(message.body).toContain("heavy-cli job failed at setup step before test execution");
    expect(message.body).toContain("event `workflow_dispatch`");
    expect(message.body).not.toContain("tests ran with the real mechanical binaries");
  });

  it("rejects the former hard-coded scheduled/main wording across the three real identities", () => {
    const identities = [
      run("workflow_dispatch", "refs/heads/feature/work", "1111111111111111"),
      run("schedule", "refs/heads/main", "2222222222222222"),
      run("push", "refs/heads/main", "3333333333333333"),
    ];
    const messages = identities.map((identity) => buildWorkflowAlert("aggregate", identity));
    expect(new Set(messages.map((message) => message.title)).size).toBe(3);
    expect(messages[0]!.title).not.toBe("main is red — the merged result does not pass verify");
    expect(messages[0]!.body).not.toContain("Every subsequent PR now inherits this failure");
  });

  it("the workflow feeds both shipping alert action call sites from this constructor", () => {
    const workflow = readFileSync(resolve(import.meta.dirname, "../.github/workflows/ci.yml"), "utf8");
    expect(workflow.match(/node --experimental-strip-types src\/workflow-alert\.ts/g)).toHaveLength(2);
    expect(workflow.match(/incident: \$\{\{ steps\.(?:heavy-alert-message|main-alert-message)\.outputs\.incident \}\}/g)).toHaveLength(2);
  });
});
