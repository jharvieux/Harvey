import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLI_SOURCE = join(REPO_ROOT, "src", "cli", "validate-memory.ts");
const TSX_LOADER = join(REPO_ROOT, "node_modules", "tsx", "dist", "esm", "index.mjs");
const scratch: string[] = [];

afterEach(() => {
  for (const path of scratch.splice(0)) rmSync(path, { recursive: true, force: true });
});

function runCli(args: readonly string[], cwd = REPO_ROOT): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolveRun, reject) => {
    const child = spawn(process.execPath, ["--import", TSX_LOADER, CLI_SOURCE, ...args], {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (code) => resolveRun({ code, stdout, stderr }));
  });
}

function decision(number: number, title: string): string {
  const decisionId = `D-${String(number).padStart(3, "0")}`;
  return [
    `## ${decisionId} — 2026-09-07 — ${title}`,
    "",
    `**Decision.** Record ${title}.`,
    "",
    "**Why.**",
    "- The integration fixture needs a real committed decision.",
    "",
    "**Rejected.**",
    "- *Skip it.* That would not exercise Git history.",
    "",
    "**Related artifacts.** `MEMORY.md`.",
    "",
    "---",
    "",
  ].join("\n");
}

function writeLedger(repo: string, entries: readonly { number: number; title: string }[]): void {
  const body = entries.map(({ number, title }) => decision(number, title)).join("\n");
  const pointers = entries
    .map(({ number, title }) => `- D-${String(number).padStart(3, "0")} — 2026-09-07 — ${title}`)
    .join("\n");
  writeFileSync(join(repo, "MEMORY.md"), `# Test memory\n\nNewest first.\n\n---\n\n${body}`);
  writeFileSync(join(repo, "MEMORY-INDEX.md"), `# Test index\n\n## Entries\n\n${pointers}\n`);
  writeFileSync(join(repo, "MEMORY-INDEX-ARCHIVE.md"), "# Test archive\n\n## Entries\n");
}

function git(repo: string, ...args: string[]): void {
  execFileSync("git", args, { cwd: repo, stdio: "ignore" });
}

describe("the production memory CLI against real files and Git refs", () => {
  it("keeps the checked-in Harvey files consistent and collision-free against origin/main", async () => {
    const result = await runCli(["--repo", REPO_ROOT, "--base", "origin/main"]);
    expect(result.code, `${result.stdout}\n${result.stderr}`).toBe(0);
    expect(result.stdout).toContain("MEMORY POPULATION 1 full entries; 1 startup index; 0 archive");
    expect(result.stdout).toContain("MEMORY GATE PASS");
  });

  it("NEGATIVE CONTROL — detects the same D-number committed independently on the target base", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-memory-collision-"));
    scratch.push(repo);
    git(repo, "init", "-q", "-b", "main");
    git(repo, "config", "user.email", "memory-test@example.invalid");
    git(repo, "config", "user.name", "Memory Test");

    writeLedger(repo, [{ number: 1, title: "Initial decision" }]);
    git(repo, "add", "MEMORY.md", "MEMORY-INDEX.md", "MEMORY-INDEX-ARCHIVE.md");
    git(repo, "commit", "-q", "-m", "Seed memory");
    git(repo, "checkout", "-q", "-b", "feature");

    git(repo, "checkout", "-q", "main");
    writeLedger(repo, [
      { number: 2, title: "Sibling claim" },
      { number: 1, title: "Initial decision" },
    ]);
    git(repo, "add", "MEMORY.md", "MEMORY-INDEX.md");
    git(repo, "commit", "-q", "-m", "Claim D-002 on main");

    git(repo, "checkout", "-q", "feature");
    writeLedger(repo, [
      { number: 2, title: "Feature claim" },
      { number: 1, title: "Initial decision" },
    ]);
    git(repo, "add", "MEMORY.md", "MEMORY-INDEX.md");
    git(repo, "commit", "-q", "-m", "Claim D-002 on feature");

    const result = await runCli(["--repo", repo, "--base", "main"], repo);
    expect(result.code, `${result.stdout}\n${result.stderr}`).toBe(1);
    expect(result.stderr).toContain("[base-decision-collision]");
    expect(result.stderr).toContain("D-002");
  });
});
