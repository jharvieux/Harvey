import { createHash } from "node:crypto";
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

export interface WorkflowRunIdentity {
  event: string;
  ref: string;
  head: string;
  runUrl: string;
}

export type WorkflowAlertScope = "heavy" | "aggregate";

export interface WorkflowAlertMessage {
  kind: "branch-dispatch" | "scheduled-main" | "pushed-main" | "manual-main" | "other";
  incident: string;
  title: string;
  body: string;
  recovery: string;
}

function branchName(ref: string): string {
  return ref.replace(/^refs\/heads\//, "") || ref;
}

function classify(identity: WorkflowRunIdentity): WorkflowAlertMessage["kind"] {
  if (identity.event === "schedule") return "scheduled-main";
  if (identity.event === "push" && identity.ref === "refs/heads/main") return "pushed-main";
  if (identity.event === "workflow_dispatch" && identity.ref === "refs/heads/main") return "manual-main";
  if (identity.event === "workflow_dispatch") return "branch-dispatch";
  return "other";
}

/** Build the exact title/body consumed by the shipping alert action. */
export function buildWorkflowAlert(scope: WorkflowAlertScope, identity: WorkflowRunIdentity, shard?: string): WorkflowAlertMessage {
  const kind = classify(identity);
  const branch = branchName(identity.ref);
  const shortHead = identity.head.slice(0, 12);
  const incident = kind === "branch-dispatch"
    ? `branch-dispatch-${createHash("sha256").update(identity.ref).digest("hex").slice(0, 12)}`
    : "main";
  const context = `event \`${identity.event}\`, ref \`${identity.ref}\`, head \`${identity.head}\`, run ${identity.runUrl}${shard ? `, ${shard}` : ""}`;
  let subject: string;
  let recovery: string;
  switch (kind) {
    case "branch-dispatch":
      subject = `branch dispatch for ${branch}`;
      recovery = `Fix or intentionally dismiss the failure on \`${branch}\`, then rerun the workflow on that same ref and close this issue once that dispatch is green. This branch incident does not establish that main or unrelated pull requests are red.`;
      break;
    case "scheduled-main":
      subject = "scheduled main run";
      recovery = "Investigate the scheduled default-branch run, then rerun it or confirm a later scheduled/main run is green before closing this issue.";
      break;
    case "pushed-main":
      subject = `main push ${shortHead}`;
      recovery = "Fix or revert the failing merged state, then close this issue only after a later push-to-main CI run is green.";
      break;
    case "manual-main":
      subject = `manual main dispatch ${shortHead}`;
      recovery = "Investigate the manual default-branch run and close this issue once the same main head, or a superseding main head, is green.";
      break;
    default:
      subject = `${identity.event} run on ${branch}`;
      recovery = "Investigate this exact run identity and close the issue only after the corresponding ref is green.";
  }
  const title = scope === "heavy" ? `heavy-cli ${subject} failing` : `CI ${subject} is red`;
  const detail = scope === "heavy"
    ? `The heavy-cli job failed${shard ? ` at ${shard}` : ""}; inspect the failed job before attributing the cause.`
    : "The aggregate verify job failed; inspect the contributing job before attributing the cause.";
  return { kind, incident, title, recovery, body: `${title}. Identity: ${context}. ${detail} ${recovery}` };
}

function arg(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function output(name: string, value: string): void {
  const line = `${name}=${value.replaceAll("\n", " ")}\n`;
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, line);
  else process.stdout.write(line);
}

function main(): void {
  const scope = arg("--scope") as WorkflowAlertScope | undefined;
  if (scope !== "heavy" && scope !== "aggregate") throw new Error("--scope must be heavy or aggregate");
  const identity = { event: process.env.ALERT_EVENT ?? "", ref: process.env.ALERT_REF ?? "", head: process.env.ALERT_HEAD ?? "", runUrl: process.env.ALERT_RUN_URL ?? "" };
  if (Object.values(identity).some((value) => !value)) throw new Error("ALERT_EVENT, ALERT_REF, ALERT_HEAD and ALERT_RUN_URL are required");
  const message = buildWorkflowAlert(scope, identity, arg("--shard"));
  output("incident", message.incident);
  output("title", message.title);
  output("body", message.body);
  output("kind", message.kind);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); }
  catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}
