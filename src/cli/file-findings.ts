// Findings -> tickets CLI (#736). Reads an engagement's findings.json, maps each finding to a
// tracker item, and either previews the plan (default) or files it to the chosen tracker.
//
//   pnpm exec tsx src/cli/file-findings.ts <findings.json> --tracker github|jira|azure \
//     [--grouping flat|grouped] [--engagement <label>] [--confirm]
//
// GUARDRAIL: dry-run is the default. Nothing is written without --confirm AND the tracker's token
// in the environment — a preview never needs a token and never touches the network. Tokens come
// only from env vars (never a flag), so they don't land in shell history or a process list.

import { readFileSync } from "node:fs";
import { GitHubTracker } from "../trackers/github.js";
import { JiraTracker } from "../trackers/jira.js";
import { AzureDevOpsTracker } from "../trackers/azure-devops.js";
import type { Tracker } from "../trackers/types.js";
import type { Finding } from "../findings.js";
import { fileFindings, planTickets, type FileOptions, type Grouping } from "../trackers/findings-to-tickets.js";

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required to file tickets (omit --confirm to preview without it)`);
  return v;
}

// Dispatch to the chosen adapter, mirroring epic.ts's makeTracker. Each reads its own least-
// privilege, create-issue-scoped token from the environment.
function makeTracker(kind: string): Tracker {
  switch (kind) {
    case "github":
      return new GitHubTracker({ token: requireEnv("GITHUB_TOKEN"), owner: requireEnv("GITHUB_OWNER"), repo: requireEnv("GITHUB_REPO") });
    case "jira":
      return new JiraTracker({
        baseUrl: requireEnv("JIRA_BASE_URL"), email: requireEnv("JIRA_EMAIL"),
        apiToken: requireEnv("JIRA_API_TOKEN"), projectKey: requireEnv("JIRA_PROJECT_KEY"),
      });
    case "azure":
      return new AzureDevOpsTracker({ orgUrl: requireEnv("AZURE_ORG_URL"), project: requireEnv("AZURE_PROJECT"), pat: requireEnv("AZURE_PAT") });
    default:
      throw new Error(`unknown --tracker "${kind}" (expected github|jira|azure)`);
  }
}

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function loadFindings(path: string): Finding[] {
  const doc = JSON.parse(readFileSync(path, "utf8")) as { findings?: Finding[] };
  if (!Array.isArray(doc.findings)) throw new Error(`${path} has no findings[] array`);
  return doc.findings;
}

function printPreview(findings: Finding[], opts: FileOptions): void {
  const plan = planTickets(findings, opts);
  console.log(`[dry-run] ${plan.grouping} — ${plan.tickets.length} finding(s), ${plan.epics.length} epic(s):\n`);
  for (const e of plan.epics) console.log(`  EPIC  ${e.title}`);
  for (const t of plan.tickets) console.log(`  ITEM  ${t.title}  [${t.labels.join(", ")}]`);
  console.log(`\nRe-run with --confirm and the tracker's token in the environment to file these.`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const path = args.find((a) => !a.startsWith("--"));
  if (!path) throw new Error("usage: file-findings <findings.json> --tracker github|jira|azure [--grouping flat|grouped] [--engagement <label>] [--confirm]");

  const grouping = (flag(args, "--grouping") ?? "grouped") as Grouping;
  if (grouping !== "flat" && grouping !== "grouped") throw new Error(`--grouping must be flat|grouped`);
  const opts: FileOptions = { grouping, engagement: flag(args, "--engagement") };
  const findings = loadFindings(path);

  if (!args.includes("--confirm")) {
    printPreview(findings, opts);
    return;
  }

  const kind = flag(args, "--tracker");
  if (!kind) throw new Error("--tracker is required to file (github|jira|azure)");
  const res = await fileFindings(makeTracker(kind), findings, opts);
  console.log(`filed ${res.created.length}, skipped ${res.skipped.length} already-present; epics: ${res.epicsCreated} created, ${res.epicsReused} reused.`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
