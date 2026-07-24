// Fix-verification gate CLI (#883) — the findings → tickets → re-audit loop, runnable per change
// (locally or in the client's CI on a PR checkout) with zero operator time.
//
//   pnpm exec tsx src/cli/fix-verify.ts <findings.json> --target <client-checkout> \
//     [--prior <prior fix-verify.json>] [--out <file>] [--engagement <label>] \
//     [--tracker github|gitlab|jira|linear|azure] [--confirm]
//
// Scope: ONLY the engagement's delivered findings — the gate re-runs the detectors that produced
// them and never scans beyond what was already reported. Read-only against the target checkout;
// the sole outbound write is the ticket write-back, and only with --confirm AND the tracker's
// token in the environment (mirroring file-findings' guardrail — the default run is a preview
// that provably cannot touch the network, and never needs a token).
//
// Exit codes: 1 when any finding REGRESSED (a verified fix was reintroduced — the red-gate signal
// for CI) or any ticket write-back failed; 0 otherwise. `unverifiable` rows do not fail the gate,
// but they are always printed with their reason and their tickets are never closed — a detector
// that could not re-run is not a clean detector.

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { validateFindings, type FindingsDocument } from "../findings.js";
import { runGate, type GateReport } from "../fix/gate.js";
import { GitHubTracker } from "../trackers/github.js";
import { GitLabTracker } from "../trackers/gitlab.js";
import { JiraTracker } from "../trackers/jira.js";
import { LinearTracker } from "../trackers/linear.js";
import { AzureDevOpsTracker } from "../trackers/azure-devops.js";
import type { TicketWriteback } from "../trackers/types.js";
import { planWriteback, writeBackVerification } from "../trackers/verify-writeback.js";

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required for ticket write-back (omit --confirm to preview without it)`);
  return v;
}

// Mirrors file-findings' makeTracker credential intake: tokens only from env, never a flag.
function makeWriteback(kind: string): TicketWriteback {
  switch (kind) {
    case "github":
      return new GitHubTracker({ token: requireEnv("GITHUB_TOKEN"), owner: requireEnv("GITHUB_OWNER"), repo: requireEnv("GITHUB_REPO") });
    case "gitlab":
      return new GitLabTracker({ token: requireEnv("GITLAB_TOKEN"), projectId: requireEnv("GITLAB_PROJECT_ID") });
    case "jira":
      return new JiraTracker({
        baseUrl: requireEnv("JIRA_BASE_URL"), email: requireEnv("JIRA_EMAIL"),
        apiToken: requireEnv("JIRA_API_TOKEN"), projectKey: requireEnv("JIRA_PROJECT_KEY"),
      });
    case "linear":
      return new LinearTracker({ apiKey: requireEnv("LINEAR_API_KEY"), teamId: requireEnv("LINEAR_TEAM_ID") });
    case "azure":
      return new AzureDevOpsTracker({ orgUrl: requireEnv("AZURE_ORG_URL"), project: requireEnv("AZURE_PROJECT"), pat: requireEnv("AZURE_PAT") });
    default:
      throw new Error(`unknown --tracker "${kind}" (expected github|gitlab|jira|linear|azure)`);
  }
}

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

const STATUS_MARK: Record<string, string> = { resolved: "✓", persistent: "·", regressed: "✗", unverifiable: "?" };

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const VALUE_FLAGS = new Set(["--target", "--prior", "--out", "--engagement", "--tracker"]);
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string;
    if (VALUE_FLAGS.has(a)) i++;
    else if (!a.startsWith("--")) positional.push(a);
  }
  const [findingsPath] = positional;
  const targetArg = flag(args, "--target");
  if (!findingsPath || !targetArg) {
    throw new Error(
      "usage: fix-verify <findings.json> --target <client-checkout> [--prior <fix-verify.json>] [--out <file>] [--engagement <label>] [--tracker github|gitlab|jira|linear|azure] [--confirm]",
    );
  }

  const doc = JSON.parse(readFileSync(findingsPath, "utf8")) as FindingsDocument;
  const { ok, errors } = validateFindings(doc);
  if (!ok) {
    console.error(`✗ ${findingsPath} is not a valid findings document:`);
    for (const e of errors) console.error(`  ${e}`);
    process.exit(1);
  }

  const priorPath = flag(args, "--prior");
  const prior = priorPath ? (JSON.parse(readFileSync(priorPath, "utf8")) as GateReport) : undefined;
  const targetDir = resolve(targetArg);
  const outPath = resolve(flag(args, "--out") ?? "fix-verify.json");

  const report = runGate(doc.findings, targetDir, { engagement: flag(args, "--engagement"), prior });
  writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`);

  const c = report.counts;
  console.log(`Fix-verification gate — ${doc.meta.client} · ${report.results.length} delivered finding(s) re-verified against ${targetDir} @ ${report.commit}`);
  console.log(`  resolved ${c.resolved} · persistent ${c.persistent} · regressed ${c.regressed} · unverifiable ${c.unverifiable}   →  ${outPath}\n`);
  for (const r of report.results) {
    const delta = r.previousStatus && r.previousStatus !== r.status ? `  (was ${r.previousStatus})` : "";
    console.log(`  ${STATUS_MARK[r.status]} ${r.findingId}  [${r.status}]${delta}  ${r.taxonomy} @ ${r.location} — ${r.detail}`);
  }
  if (c.unverifiable > 0) {
    console.log(`\n${c.unverifiable} finding(s) UNVERIFIABLE — their detectors could not be mechanically re-run here, so their tickets stay open; verify them via a re-audit of that tier.`);
  }

  // Ticket write-back: plan is always shown; writes need --confirm + --tracker + env token.
  const plan = planWriteback(report);
  const actionable = plan.filter((p) => p.intent !== "none");
  const trackerKind = flag(args, "--tracker");
  if (!args.includes("--confirm")) {
    if (actionable.length) {
      console.log(`\n[dry-run] ticket write-back plan (${actionable.length} action(s)) — re-run with --tracker <kind> --confirm and the tracker's token in the environment to apply:`);
      for (const p of actionable) console.log(`  ${p.intent === "closed" ? "close " : "reopen"} ticket of ${p.findingId} — ${p.reason}`);
    }
  } else if (actionable.length) {
    if (!trackerKind) throw new Error("--tracker is required with --confirm (github|gitlab|jira|linear|azure)");
    const res = await writeBackVerification(makeWriteback(trackerKind), report);
    console.log(`\nWrite-back: closed ${res.closed}, reopened ${res.reopened}, failed ${res.failed}.`);
    for (const rec of res.records) {
      if (rec.error) console.error(`  ✗ ${rec.findingId}: ${rec.reason} — write-back FAILED: ${rec.error}`);
      else if (rec.action !== "none") console.log(`  ✓ ${rec.findingId}: ${rec.action} ${rec.ticket?.url ?? ""}`);
      else if (rec.reason.includes("no ticket found")) console.log(`  · ${rec.findingId}: ${rec.reason}`);
    }
    if (res.failed > 0) process.exitCode = 1;
  } else {
    console.log("\nNo ticket write-back needed: nothing newly resolved or regressed.");
  }

  // A reintroduced finding is the gate's red signal — a delivered, verified fix is gone.
  if (c.regressed > 0) {
    console.error(`\n✗ ${c.regressed} previously-verified finding(s) REINTRODUCED.`);
    process.exitCode = 1;
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
