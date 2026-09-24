import "./sync-stdio.js";
import { appendFileSync } from "node:fs";
import { resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { classifyDryRunChanges, compareDryRunFamilies } from "../dry-run-drift.js";

function arg(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function output(name: string, value: string | number | boolean): void {
  const line = `${name}=${String(value).replaceAll("\n", " ")}\n`;
  const target = process.env.GITHUB_OUTPUT;
  if (target) appendFileSync(target, line);
  else process.stdout.write(line);
}

function changedPaths(repoRoot: string, base: string, head: string): string[] {
  return execFileSync("git", ["diff", "--name-only", base, head], { cwd: repoRoot, encoding: "utf8" }).split("\n").filter(Boolean);
}

function main(): void {
  const command = process.argv[2];
  const repoRoot = resolve(arg("--repo") ?? process.cwd());
  if (command === "relevance") {
    const explicit = process.argv.filter((value, index) => process.argv[index - 1] === "--changed");
    const paths = explicit.length > 0 ? explicit : changedPaths(repoRoot, arg("--base") ?? "origin/main", arg("--head") ?? "HEAD");
    const decision = classifyDryRunChanges(repoRoot, paths);
    output("relevant", decision.relevant);
    output("reason", decision.reason);
    output("dependency_count", decision.dependencyCount);
    console.log(`Dry-run relevance: ${decision.reason}; changed=${paths.join(", ") || "<empty>"}; matched=${decision.matches.join(", ") || "<none>"}`);
    if (decision.unresolved.length > 0) console.log(`Unresolved producer edges (regeneration selected): ${decision.unresolved.join(", ")}`);
    return;
  }
  if (command === "compare") {
    const committed = resolve(arg("--committed") ?? "dry-run");
    const fresh = resolve(arg("--fresh") ?? "/tmp/dry-run-regen");
    const comparison = compareDryRunFamilies(committed, fresh);
    output("units", comparison.members.length);
    output("timing_excluded", comparison.timingExcluded);
    console.log(`Compared ${comparison.members.length} deterministic members through the dry-run family contract: ${comparison.members.join(", ")}. timing.json excluded because it records wall-clock observations.`);
    if (!comparison.ok) throw new Error(`Dry-run family drift: ${comparison.differences.join("; ")}`);
    return;
  }
  throw new Error("Usage: dry-run-drift.ts relevance [--base REF --head REF | --changed PATH ...] | compare [--committed DIR --fresh DIR]");
}

try { main(); }
catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
