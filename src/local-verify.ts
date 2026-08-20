import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export type LocalVerificationTier = "focused" | "full";

const FOCUSED_ROOT_DOCS = new Set([
  "AGENTS.md",
  "CLAUDE.md",
  "MODULES.md",
  "README.md",
  "SESSION.md",
]);

export function isFocusedLocalVerificationPath(path: string): boolean {
  return (
    FOCUSED_ROOT_DOCS.has(path) ||
    (/^docs\/.+\.md$/.test(path) && !path.includes("/../")) ||
    /^\.codex\/agents\/[^/]+\.toml$/.test(path)
  );
}

export function localVerificationTier(paths: readonly string[]): LocalVerificationTier {
  return paths.length > 0 && paths.every(isFocusedLocalVerificationPath) ? "focused" : "full";
}

function capture(command: string, args: string[]): string | null {
  const result = spawnSync(command, args, { encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : null;
}

function run(command: string, args: string[]): void {
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

function changedPaths(base: string): { mergeBase: string; paths: string[] } | null {
  const mergeBase = capture("git", ["merge-base", base, "HEAD"]);
  if (!mergeBase) return null;
  const changed = capture("git", ["diff", "--name-only", mergeBase]);
  if (changed === null) return null;
  return { mergeBase, paths: changed.split("\n").filter(Boolean) };
}

function parseChangedToml(paths: readonly string[]): void {
  const tomlPaths = paths.filter((path) => path.endsWith(".toml") && existsSync(path));
  if (tomlPaths.length === 0) return;
  run("python3", [
    "-c",
    "import sys,tomllib; [tomllib.load(open(path,'rb')) for path in sys.argv[1:]]",
    ...tomlPaths,
  ]);
}

export function main(): void {
  const base = process.env.HARVEY_VERIFY_BASE || "origin/main";
  const changed = changedPaths(base);
  if (!changed || localVerificationTier(changed.paths) === "full") {
    console.log(`local verify: full gate (base ${base}; source, executable input, or unknown path changed)`);
    run("pnpm", ["verify"]);
    return;
  }

  console.log(`local verify: focused policy/docs gate (${changed.paths.length} path(s) against ${base})`);
  run("git", ["diff", "--check", changed.mergeBase]);
  parseChangedToml(changed.paths);
  run("pnpm", [
    "exec",
    "vitest",
    "run",
    "src/local-verify.test.ts",
    "src/recorded-reasons.test.ts",
    "src/ci-tier-router.test.ts",
  ]);
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) main();
