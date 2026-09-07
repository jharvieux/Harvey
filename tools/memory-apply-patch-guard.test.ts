import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(REPO_ROOT, "tools", "memory-apply-patch-guard.mjs");
const scratch: string[] = [];

afterEach(() => {
  for (const path of scratch.splice(0)) rmSync(path, { recursive: true, force: true });
});

function runGuard(
  command: string,
  options: { repo?: string; base?: string; toolName?: string } = {},
): Promise<{ code: number | null; stderr: string }> {
  const repo = options.repo ?? REPO_ROOT;
  return new Promise((resolveRun, reject) => {
    const child = spawn("node", [GUARD], {
      cwd: repo,
      env: {
        ...process.env,
        HARVEY_REPO_ROOT: repo,
        ...(options.base ? { HARVEY_MEMORY_BASE_REF: options.base } : {}),
      },
      stdio: ["pipe", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (code) => resolveRun({ code, stderr }));
    child.stdin.end(
      JSON.stringify({
        cwd: repo,
        tool_name: options.toolName ?? "apply_patch",
        tool_input: { command },
      }),
    );
  });
}

function entryLines(number: number, title = "Test-only decision"): string[] {
  const decisionId = `D-${String(number).padStart(3, "0")}`;
  return [
    `## ${decisionId} — 2026-09-07 — ${title}`,
    "",
    "**Decision.** Exercise the prepend boundary.",
    "",
    "**Why.**",
    "- The guard needs a positive control.",
    "",
    "**Rejected.**",
    "- *Rewrite history.* It destroys provenance.",
    "",
    "**Related artifacts.** `MEMORY.md`.",
    "",
    "---",
    "",
  ];
}

function prependPatch(path = "MEMORY.md", number = 2): string {
  const lines = readFileSync(join(REPO_ROOT, "MEMORY.md"), "utf8").split("\n");
  const firstEntry = lines.findIndex((line) => /^## D-\d{3,}\b/.test(line));
  const before = lines.slice(firstEntry - 2, firstEntry).map((line) => ` ${line}`);
  const after = lines.slice(firstEntry, firstEntry + 1).map((line) => ` ${line}`);
  return [
    "*** Begin Patch",
    `*** Update File: ${path}`,
    "@@",
    ...before,
    ...entryLines(number).map((line) => `+${line}`),
    ...after,
    "*** End Patch",
  ].join("\n");
}

function git(repo: string, ...args: string[]): void {
  execFileSync("git", args, { cwd: repo, stdio: "ignore" });
}

describe("memory apply_patch guard subprocess", () => {
  it("allows a complete next-number entry inserted at the log boundary", async () => {
    expect((await runGuard(prependPatch())).code).toBe(0);
  });

  it("NEGATIVE CONTROL — blocks a rewrite of existing history", async () => {
    const result = await runGuard(`*** Begin Patch
*** Update File: MEMORY.md
@@
-# MEMORY.md — Harvey decision log
+# Rewritten decision log
*** End Patch`);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("prior history is immutable");
  });

  it("blocks an insertion inside an existing entry even when it deletes nothing", async () => {
    const result = await runGuard(`*** Begin Patch
*** Update File: MEMORY.md
@@
 **Why.**
+- Injected into old history.
 - Durable decisions need to survive compaction, task boundaries, and replacement of transient session state without relying on any one client's private recall.
*** End Patch`);
    expect(result.code).toBe(2);
  });

  it("blocks a duplicate or skipped id before the repository validator has to", async () => {
    const duplicate = await runGuard(prependPatch("MEMORY.md", 1));
    const skipped = await runGuard(prependPatch("MEMORY.md", 3));
    expect(duplicate.code).toBe(2);
    expect(skipped.code).toBe(2);
  });

  it.each(["memory.md", "Memory.md", "nested/../MEMORY.md"])("protects path spelling %s", async (path) => {
    const result = await runGuard(`*** Begin Patch
*** Update File: ${path}
@@
-# MEMORY.md — Harvey decision log
+# Rewritten decision log
*** End Patch`);
    expect(result.code).toBe(2);
  });

  it("allows ordinary apply_patch calls that do not target the durable log", async () => {
    const result = await runGuard(`*** Begin Patch
*** Update File: src/example.ts
@@
-const before = true;
+const after = true;
*** End Patch`);
    expect(result.code).toBe(0);
  });

  it("fails closed when an apply_patch payload cannot be parsed", async () => {
    const result = await runGuard("*** Begin Patch\n*** Update File: MEMORY.md\n@@\n-old\n+new");
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("could not parse apply_patch input");
  });

  it("does nothing when invoked for a tool outside its narrow matcher", async () => {
    const result = await runGuard("not a patch", { toolName: "Bash" });
    expect(result.code).toBe(0);
  });

  it("allows a pure renumber only when the edited entry is branch-local", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-memory-renumber-"));
    scratch.push(repo);
    git(repo, "init", "-q", "-b", "main");
    git(repo, "config", "user.email", "memory-test@example.invalid");
    git(repo, "config", "user.name", "Memory Test");
    writeFileSync(join(repo, "seed.txt"), "seed\n");
    git(repo, "add", "seed.txt");
    git(repo, "commit", "-q", "-m", "Seed repository");
    git(repo, "checkout", "-q", "-b", "feature");
    writeFileSync(join(repo, "MEMORY.md"), `# Test memory\n\n---\n\n${entryLines(1).join("\n")}`);
    git(repo, "add", "MEMORY.md");
    git(repo, "commit", "-q", "-m", "Add branch-local memory");

    const result = await runGuard(
      `*** Begin Patch
*** Update File: MEMORY.md
@@
-## D-001 — 2026-09-07 — Test-only decision
+## D-002 — 2026-09-07 — Test-only decision
*** End Patch`,
      { repo, base: "main" },
    );
    expect(result.code, result.stderr).toBe(0);
  });
});
