import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

export interface OwaspProposalSnapshot {
  number: number;
  state: "open" | "closed";
  labels: string[];
  comments: number;
  url: string;
  latestComment?: { author: string; createdAt: string; body: string };
}

interface ReceiptRow {
  number: number;
  state: "open" | "closed";
  labels: string[];
  comments: number;
}

export interface OwaspWatchDecision {
  notify: boolean;
  receipt: string;
  headline: string;
  body: string;
  actionable: number[];
}

function rows(snapshots: readonly OwaspProposalSnapshot[]): ReceiptRow[] {
  return snapshots.map((snapshot) => ({ number: snapshot.number, state: snapshot.state, labels: [...snapshot.labels].sort(), comments: snapshot.comments })).sort((a, b) => a.number - b.number);
}

export function encodeOwaspReceipt(snapshots: readonly OwaspProposalSnapshot[]): string {
  return Buffer.from(JSON.stringify(rows(snapshots))).toString("base64url");
}

export function decodeOwaspReceipt(receipt: string | undefined): ReceiptRow[] | undefined {
  if (!receipt) return undefined;
  try {
    const value = JSON.parse(Buffer.from(receipt, "base64url").toString("utf8")) as unknown;
    if (!Array.isArray(value) || value.some((row) => typeof row !== "object" || row === null || typeof (row as ReceiptRow).number !== "number")) return undefined;
    return value as ReceiptRow[];
  } catch { return undefined; }
}

function sameRows(left: readonly ReceiptRow[] | undefined, right: readonly ReceiptRow[]): boolean {
  return left !== undefined && JSON.stringify(left) === JSON.stringify(right);
}

function baseline(snapshots: readonly OwaspProposalSnapshot[]): boolean {
  return snapshots.every((snapshot) => snapshot.state === "open" && snapshot.labels.length === 0 && snapshot.comments === 0);
}

function esc(text: string): string {
  return text.replaceAll("\n", "\n    > ");
}

/** The shipping watcher decision and message path, shared directly by the workflow and tests. */
export function buildOwaspWatchDecision(snapshots: readonly OwaspProposalSnapshot[], previousReceipt: string | undefined, runUrl: string): OwaspWatchDecision {
  const currentRows = rows(snapshots);
  const previousRows = decodeOwaspReceipt(previousReceipt);
  const receipt = encodeOwaspReceipt(snapshots);
  const previousByNumber = new Map(previousRows?.map((row) => [row.number, row]));
  const actionable: number[] = [];
  const lines: string[] = [];

  for (const snapshot of [...snapshots].sort((a, b) => a.number - b.number)) {
    const ack = snapshot.labels.includes("ACK_OBTAINED");
    const previous = previousByNumber.get(snapshot.number);
    let instruction: string;
    if (snapshot.state === "closed") {
      instruction = ack
        ? "Terminal: the proposal is closed with ACK_OBTAINED retained; drafting is complete or superseded, so no new drafting work is requested."
        : "Terminal: the proposal is closed; no drafting work is requested."
    } else if (previous?.state === "closed") {
      actionable.push(snapshot.number);
      instruction = "Action: the proposal was reopened; review the renewed upstream work before deciding the next drafting step."
    } else if (ack) {
      actionable.push(snapshot.number);
      instruction = "Action: the proposal is open and newly acknowledged; drafting can begin or resume."
    } else {
      const changedActivity = previous === undefined || previous.comments !== snapshot.comments || JSON.stringify(previous.labels) !== JSON.stringify([...snapshot.labels].sort());
      if (changedActivity && (snapshot.comments > 0 || snapshot.labels.length > 0)) actionable.push(snapshot.number);
      instruction = changedActivity && (snapshot.comments > 0 || snapshot.labels.length > 0)
        ? "Action: acknowledgement is still waiting; review the latest maintainer request or status change."
        : "Waiting: the proposal remains open without ACK_OBTAINED."
    }
    const latest = snapshot.latestComment
      ? `\n  - latest comment — **@${snapshot.latestComment.author}** at ${snapshot.latestComment.createdAt}:\n\n    > ${esc(snapshot.latestComment.body)}`
      : "";
    lines.push(`- **#${snapshot.number}** — labels: \`[${[...snapshot.labels].sort().join(",")}]\` · comments: **${snapshot.comments}** · state: \`${snapshot.state}\` · ${snapshot.url}\n  - ${instruction}${latest}`);
  }

  const completed = snapshots.filter((snapshot) => snapshot.state === "closed").map((snapshot) => snapshot.number);
  let headline = "OWASP proposal state changed; review the per-proposal instructions below.";
  if (actionable.length === 1) headline = `Only #${actionable[0]} is actionable; the other proposal's current state is represented separately below.`;
  else if (actionable.length > 1) headline = `OWASP proposals ${actionable.map((number) => `#${number}`).join(" and ")} require action.`;
  else if (completed.length > 0) headline = "The watched proposals are in terminal or waiting states; no new drafting instruction is active.";

  const initialFilingBaseline = previousRows === undefined && baseline(snapshots);
  const notify = !initialFilingBaseline && !sameRows(previousRows, currentRows);
  const body = `${headline}\n\n${lines.join("\n")}\n\nBaseline at filing (2026-07-26): both issues open, zero labels, zero comments.\n\nAn acknowledgement is actionable only while its proposal is open. A retained ACK_OBTAINED label on a closed proposal is completion evidence, not permission to recreate drafting work.\n\n<sub>Watch: ${runUrl} · <!-- owasp-ack-receipt: ${receipt} --></sub>`;
  return { notify, receipt, headline, body, actionable };
}

function arg(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function output(name: string, value: string | boolean): void {
  const line = `${name}=${String(value).replaceAll("\n", " ")}\n`;
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, line);
  else process.stdout.write(line);
}

function main(): void {
  const input = arg("--input");
  const bodyPath = arg("--body");
  const runUrl = arg("--run-url");
  if (!input || !bodyPath || !runUrl) throw new Error("Usage: owasp-ack-watch.ts --input snapshots.json --body message.md --run-url URL [--previous RECEIPT]");
  const snapshots = JSON.parse(readFileSync(input, "utf8")) as OwaspProposalSnapshot[];
  const decision = buildOwaspWatchDecision(snapshots, arg("--previous"), runUrl);
  writeFileSync(bodyPath, decision.body);
  output("notify", decision.notify);
  output("receipt", decision.receipt);
  output("headline", decision.headline);
  console.log(decision.notify ? decision.headline : "State is baseline or already has a matching receipt; no alert will be recreated.");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); }
  catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}
