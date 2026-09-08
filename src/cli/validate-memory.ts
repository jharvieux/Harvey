import "./sync-stdio.js";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  validateBranchMemory,
  validateMemorySnapshot,
  type MemoryFiles,
  type MemoryIssue,
} from "../memory-validation.js";

const DEFAULT_REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

interface Options {
  repo: string;
  base: string;
}

function usage(): string {
  return [
    "Usage: pnpm exec tsx src/cli/validate-memory.ts [--repo <path>] [--base <ref>]",
    "",
    "Validates MEMORY.md, both indexes, append-only history, and target-base D-number collisions.",
    "The default base is HARVEY_MEMORY_BASE_REF or origin/main.",
  ].join("\n");
}

function options(argv: readonly string[]): Options | null {
  let repo = DEFAULT_REPO_ROOT;
  let base = process.env.HARVEY_MEMORY_BASE_REF ?? "origin/main";
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === "--help" || argument === "-h") return null;
    if (argument !== "--repo" && argument !== "--base") {
      throw new Error(`unknown argument: ${argument}`);
    }
    const value = argv[index + 1];
    if (!value) throw new Error(`${argument} requires a value`);
    if (argument === "--repo") repo = resolve(value);
    else base = value;
    index += 1;
  }
  return { repo, base };
}

function gitRaw(repo: string, args: readonly string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function git(repo: string, args: readonly string[]): string {
  return gitRaw(repo, args).trim();
}

function memoryAt(repo: string, ref: string): string | null {
  const paths = git(repo, ["ls-tree", "--name-only", ref, "--", "MEMORY.md"]);
  if (paths.split("\n").filter(Boolean).length === 0) return null;
  return gitRaw(repo, ["show", `${ref}:MEMORY.md`]);
}

function currentFiles(repo: string): MemoryFiles {
  return {
    memory: readFileSync(resolve(repo, "MEMORY.md"), "utf8"),
    index: readFileSync(resolve(repo, "MEMORY-INDEX.md"), "utf8"),
    archive: readFileSync(resolve(repo, "MEMORY-INDEX-ARCHIVE.md"), "utf8"),
  };
}

function printIssues(issues: readonly MemoryIssue[]): void {
  for (const entry of issues) console.error(`GATE FAIL [${entry.code}] ${entry.message}`);
}

function main(): number {
  let parsed: Options | null;
  try {
    parsed = options(process.argv.slice(2));
  } catch (error) {
    console.error(`memory validation could not parse arguments: ${(error as Error).message}`);
    console.error(usage());
    return 2;
  }
  if (parsed === null) {
    console.log(usage());
    return 0;
  }

  try {
    const repo = git(parsed.repo, ["rev-parse", "--show-toplevel"]);
    const targetBase = git(repo, ["rev-parse", "--verify", `${parsed.base}^{commit}`]);
    const mergeBase = git(repo, ["merge-base", "HEAD", targetBase]);
    const files = currentFiles(repo);
    const snapshot = validateMemorySnapshot(files);
    const branch = validateBranchMemory({
      ancestorMemory: memoryAt(repo, mergeBase),
      targetBaseMemory: memoryAt(repo, targetBase),
      currentMemory: files.memory,
    });
    const issues = [...snapshot.issues, ...branch.issues];

    console.log(
      `MEMORY POPULATION ${snapshot.population.memory} full entries; ` +
        `${snapshot.population.index} startup index; ${snapshot.population.archive} archive; ` +
        `${branch.addedIds.length} added since merge base`,
    );
    console.log(`MEMORY BASE ${parsed.base} -> ${targetBase.slice(0, 12)}; merge base ${mergeBase.slice(0, 12)}`);

    if (issues.length > 0) {
      printIssues(issues);
      console.error(`MEMORY GATE FAIL — ${issues.length} violation(s).`);
      return 1;
    }
    console.log("MEMORY GATE PASS — history, indexes, numbering, and target-base ownership agree.");
    return 0;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    console.error(`MEMORY GATE COULD NOT RUN — ${detail}`);
    return 2;
  }
}

process.exit(main());
