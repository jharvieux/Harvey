// Findings -> tickets CLI (#736). Reads an engagement's findings.json, maps each finding to a
// tracker item, and either previews the plan (default) or files it to the chosen tracker.
//
//   pnpm exec tsx src/cli/file-findings.ts <findings.json> --tracker github|jira|azure \
//     [--grouping flat|grouped] [--engagement <label>] [--connected] [--confirm]
//
// GUARDRAIL: dry-run is the default. Nothing is written without --confirm AND the tracker's token
// in the environment — a preview never needs a token and never touches the network. Tokens come
// only from env vars (never a flag), so they don't land in shell history or a process list.
//
// #824 PAID-TIER GATE: ticket filing is a paid-tier add-on. The engagement tier is declared with the
// same flags run-audit uses (--connected / --dynamic / --llm); paid = --connected (CLAUDE.md: "paid =
// a connected engagement"). Without it the run is free-tier and NOTHING is filed — free-tier output
// is Info/Review indicators, too noisy for a client's tracker. The gate also drops Info/Watch-severity
// and Review/N-A-confidence indicators on a paid run. Held-back findings are always disclosed, never
// silently dropped.
//
// #747 full CLI: --config <file> (JSON defaults, flags override), --category <name> (repeatable,
// file only matching categories), --update (patch an already-filed ticket instead of skipping),
// --interval/--max-retries (rate-limit pacing), and --auth-intake <tracker> (print the least-
// privilege token setup and exit). Script alias: `pnpm file-findings`.

import "./sync-stdio.js";
import { readFileSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { isDirectorySafe } from "../fs-walk.js";
import { GitHubTracker } from "../trackers/github.js";
import { JiraTracker } from "../trackers/jira.js";
import { AzureDevOpsTracker } from "../trackers/azure-devops.js";
import type { Tracker } from "../trackers/types.js";
import type { Finding } from "../findings.js";
import { fileFindings, planTickets, type FileOptions, type Grouping } from "../trackers/findings-to-tickets.js";
import { makePacer } from "../trackers/rate-limit.js";
import { intakeDoc, TRACKER_INTAKE, type TrackerKind } from "../trackers/scoped-tokens.js";

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

// Collect every occurrence of a repeatable flag (e.g. --category X --category Y), each value also
// splittable on commas (--category X,Y).
function flags(args: string[], name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const next = args[i + 1];
    if (args[i] === name && next) out.push(...next.split(",").map((s) => s.trim()).filter(Boolean));
  }
  return out;
}

function loadFindings(path: string): Finding[] {
  const doc = JSON.parse(readFileSync(path, "utf8")) as { findings?: Finding[] };
  if (!Array.isArray(doc.findings)) throw new Error(`${path} has no findings[] array`);
  return doc.findings;
}

// #747: optional JSON config supplying defaults; explicit flags win over it.
interface CliConfig {
  tracker?: string;
  grouping?: Grouping;
  engagement?: string;
  categories?: string[];
  connected?: boolean;
  update?: boolean;
  intervalMs?: number;
  maxRetries?: number;
}

function loadConfig(path: string | undefined): CliConfig {
  if (!path) return {};
  const cfg = JSON.parse(readFileSync(path, "utf8")) as CliConfig;
  if (typeof cfg !== "object" || cfg === null) throw new Error(`${path} is not a JSON object`);
  return cfg;
}

// #824: disclose what the paid-tier / content gate held back — never a silent drop. Groups the
// per-finding reasons so the operator sees "N not filed, why".
function printExcluded(excluded: { finding: Finding; reason: string }[]): void {
  if (excluded.length === 0) return;
  const byReason = new Map<string, number>();
  for (const e of excluded) byReason.set(e.reason, (byReason.get(e.reason) ?? 0) + 1);
  console.log(`\n${excluded.length} finding(s) below the paid-tier filing threshold, not filed:`);
  for (const [reason, n] of byReason) console.log(`  ${n}× ${reason}`);
}

function printPreview(findings: Finding[], opts: FileOptions): void {
  const plan = planTickets(findings, opts);
  console.log(`[dry-run] ${plan.grouping} — ${plan.tickets.length} finding(s), ${plan.epics.length} epic(s):\n`);
  for (const e of plan.epics) console.log(`  EPIC  ${e.title}`);
  for (const t of plan.tickets) console.log(`  ITEM  ${t.title}  [${t.labels.join(", ")}]`);
  printExcluded(plan.excluded);
  if (plan.tickets.length > 0) console.log(`\nRe-run with --confirm and the tracker's token in the environment to file these.`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // #747: --auth-intake <tracker> prints the least-privilege token setup and exits (no findings file).
  const intakeKind = flag(args, "--auth-intake");
  if (intakeKind) {
    if (!(intakeKind in TRACKER_INTAKE)) throw new Error(`--auth-intake must be one of ${Object.keys(TRACKER_INTAKE).join("|")}`);
    console.log(intakeDoc(intakeKind as TrackerKind));
    return;
  }

  const valueFlags = new Set([
    "--target", "--tracker", "--grouping", "--engagement", "--category", "--interval",
    "--max-retries", "--config", "--auth-intake",
  ]);
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (valueFlags.has(arg)) i++;
    else if (!arg.startsWith("--")) positional.push(arg);
  }

  const [path] = positional;
  const targetArg = flag(args, "--target");
  if (!path || !targetArg) {
    throw new Error("usage: file-findings <findings.json> --target <repo-root> --tracker github|jira|azure [--grouping flat|grouped] [--engagement <label>] [--category <name>] [--connected] [--update] [--interval <ms>] [--max-retries <n>] [--config <file>] [--confirm]  |  file-findings --auth-intake <tracker>");
  }

  const resolvedTarget = resolve(targetArg);
  let targetDir: string;
  try {
    if (!isDirectorySafe(resolvedTarget)) throw new Error("not a directory");
    targetDir = realpathSync.native(resolvedTarget);
  } catch {
    throw new Error(`--target must name an existing directory: ${resolvedTarget}`);
  }

  const cfg = loadConfig(flag(args, "--config"));
  const grouping = (flag(args, "--grouping") ?? cfg.grouping ?? "grouped") as Grouping;
  if (grouping !== "flat" && grouping !== "grouped") throw new Error(`--grouping must be flat|grouped`);
  // Tier flags mirror run-audit; paid = a connected engagement (CLAUDE.md). --dynamic/--llm are
  // accepted for parity but, like run-audit's "Validation" mode, do not by themselves grant paid.
  const paid = args.includes("--connected") || cfg.connected === true;
  const update = args.includes("--update") || cfg.update === true;
  const intervalMs = Number(flag(args, "--interval") ?? cfg.intervalMs ?? 0);
  const maxRetries = flag(args, "--max-retries") !== undefined ? Number(flag(args, "--max-retries")) : cfg.maxRetries;
  const pacer = makePacer({ minIntervalMs: intervalMs, ...(maxRetries !== undefined ? { maxRetries } : {}) });

  const opts: FileOptions = { grouping, engagement: flag(args, "--engagement") ?? cfg.engagement, paid, update, pacer, root: targetDir };

  // #747: --category filters the findings set to the named categories before planning.
  const categories = [...flags(args, "--category"), ...(cfg.categories ?? [])];
  let findings = loadFindings(path);
  if (categories.length) {
    const before = findings.length;
    findings = findings.filter((f) => categories.includes(f.category));
    console.log(`Category filter [${categories.join(", ")}]: ${findings.length} of ${before} finding(s) selected.\n`);
  }

  if (!args.includes("--confirm")) {
    if (!paid) console.log("Free-tier engagement (no --connected): ticket filing is a paid-tier add-on — nothing will be filed.\n");
    printPreview(findings, opts);
    return;
  }

  const kind = flag(args, "--tracker") ?? cfg.tracker;
  if (!kind) throw new Error("--tracker is required to file (github|jira|azure)");
  const res = await fileFindings(makeTracker(kind), findings, opts);
  console.log(`filed ${res.created.length}, ${update ? `updated ${res.updated.length}` : `skipped ${res.skipped.length}`} already-present; epics: ${res.epicsCreated} created, ${res.epicsReused} reused.`);
  printExcluded(res.excluded);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
