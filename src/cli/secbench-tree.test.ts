import { spawnSync } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { SECBENCH_CLASSES } from "../scan/secbench.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "secbench-tree.ts");
const TSX_LOADER = join(REPO_ROOT, "node_modules", "tsx", "dist", "loader.mjs");
const directories: string[] = [];

function temporary(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  directories.push(dir);
  return dir;
}

afterEach(() => {
  while (directories.length) rmSync(directories.pop()!, { recursive: true, force: true });
});

function corpus(): string {
  const root = temporary("harvey-secbench-tree-corpus-");
  for (const cls of SECBENCH_CLASSES) {
    const entry = join(root, cls, "case");
    mkdirSync(entry, { recursive: true });
    writeFileSync(join(entry, "package.json"), JSON.stringify({ id: "CVE-2026-0001", dependencies: { [`fixture-${cls}`]: "1.0.0" } }));
  }
  return root;
}

function npmShim(): { bin: string; calls: string } {
  const bin = temporary("harvey-secbench-tree-bin-");
  const calls = join(bin, "npm-calls.jsonl");
  writeFileSync(
    join(bin, "npm"),
    `#!${process.execPath}\nconst fs=require("node:fs"); fs.appendFileSync(process.env.HARVEY_NPM_CALLS, JSON.stringify({cwd:process.cwd(), mode:process.env.HARVEY_NPM_MODE})+"\\n"); if(process.env.HARVEY_NPM_MODE==="fail") process.exit(1); if(process.env.HARVEY_NPM_MODE==="lockfile") fs.writeFileSync("package-lock.json", JSON.stringify({lockfileVersion:3, packages:{}}));\n`,
  );
  chmodSync(join(bin, "npm"), 0o755);
  return { bin, calls };
}

function run(args: string[], options: { cli?: string; mode?: "lockfile" | "no-artifact" | "fail" } = {}) {
  const shim = npmShim();
  return {
    result: spawnSync(process.execPath, ["--import", TSX_LOADER, options.cli ?? CLI, ...args], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${shim.bin}:${process.env.PATH ?? ""}`,
        HARVEY_NPM_CALLS: shim.calls,
        HARVEY_NPM_MODE: options.mode ?? "lockfile",
      },
    }),
    calls: () => existsSync(shim.calls) ? readFileSync(shim.calls, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as { cwd: string; mode: string }) : [],
  };
}

describe("secbench-tree preparation CLI (#2106)", () => {
  it.each([
    ["missing", ["--concurrency"]],
    ["empty", ["--concurrency", ""]],
    ["nonnumeric", ["--concurrency", "not-a-number"]],
    ["zero", ["--concurrency", "0"]],
    ["negative", ["--concurrency", "-1"]],
    ["fractional", ["--concurrency", "1.5"]],
    ["positive infinity", ["--concurrency", "Infinity"]],
    ["negative infinity", ["--concurrency", "-Infinity"]],
  ])("rejects %s concurrency before preparation", (_name, concurrency) => {
    const out = temporary("harvey-secbench-tree-out-");
    const { result, calls } = run(["--dir", corpus(), "--out", out, ...concurrency]);
    expect(result.status).toBe(2);
    expect(`${result.stdout}${result.stderr}`).toContain("--concurrency: expected a finite positive integer value");
    expect(calls()).toEqual([]);
  });

  it("builds every local entry through the controlled npm executable without registry access", () => {
    const input = corpus();
    const out = temporary("harvey-secbench-tree-out-");
    const { result, calls } = run(["--dir", input, "--out", out, "--concurrency", "1"]);
    expect(result.status, `${result.stdout}${result.stderr}`).toBe(0);
    expect(result.stdout).toContain(`5/5 lockfiles built.`);
    expect(calls().map((call) => realpathSync(call.cwd)).sort()).toEqual(SECBENCH_CLASSES.map((cls) => realpathSync(join(out, cls, "case"))).sort());
    for (const cls of SECBENCH_CLASSES) expect(existsSync(join(out, cls, "case", "package-lock.json"))).toBe(true);
  });

  it("bounds a large valid concurrency value to the loaded local corpus", () => {
    const input = corpus();
    const out = temporary("harvey-secbench-tree-out-");
    const { result, calls } = run(["--dir", input, "--out", out, "--concurrency", "1000000000"]);
    expect(result.status, `${result.stdout}${result.stderr}`).toBe(0);
    expect(result.stdout).toContain("5/5 lockfiles built.");
    expect(calls()).toHaveLength(SECBENCH_CLASSES.length);
  });

  it.each(["no-artifact", "fail"] as const)("names every failed entry and refuses a %s run with no generated tree", (mode) => {
    const input = corpus();
    const out = temporary("harvey-secbench-tree-out-");
    const { result, calls } = run(["--dir", input, "--out", out, "--concurrency", "1", "--max-failure-pct", "100"], { mode });
    const output = `${result.stdout}${result.stderr}`;
    expect(result.status, output).toBe(1);
    expect(output).toContain("no lockfile was generated; refusing to call an empty tree usable");
    for (const cls of SECBENCH_CLASSES) {
      expect(output).toContain(`${cls}/case`);
      expect(existsSync(join(out, cls, "case", "package-lock.json"))).toBe(false);
    }
    expect(calls()).toHaveLength(SECBENCH_CLASSES.length);
  });

  it("physical parser reversion turns an invalid concurrency rejection into a failed runtime control", () => {
    const clone = temporary("harvey-secbench-tree-reverted-");
    cpSync(join(REPO_ROOT, "package.json"), join(clone, "package.json"));
    cpSync(join(REPO_ROOT, "src"), join(clone, "src"), { recursive: true });
    symlinkSync(join(REPO_ROOT, "node_modules"), join(clone, "node_modules"), "dir");
    const reverted = join(clone, "src", "cli", "secbench-tree.ts");
    const source = readFileSync(reverted, "utf8");
    const mutated = source.replace('const concurrency = positiveIntegerFlag("--concurrency", 8);', 'const concurrency = Number(arg("--concurrency") ?? 8);');
    expect(mutated).not.toBe(source);
    writeFileSync(reverted, mutated);
    const { result } = run(["--dir", corpus(), "--out", temporary("harvey-secbench-tree-out-"), "--concurrency", "not-a-number"], { cli: reverted });
    expect(result.status, `${result.stdout}${result.stderr}`).toBe(1);
    expect(`${result.stdout}${result.stderr}`).toContain("completion accounting failed: 0 generated + 0 named failures = 0, but 5 entries were loaded");
  });

  it("physical removal of completion accounting lets a partial worker regression report success", () => {
    const clone = temporary("harvey-secbench-tree-reverted-");
    cpSync(join(REPO_ROOT, "package.json"), join(clone, "package.json"));
    cpSync(join(REPO_ROOT, "src"), join(clone, "src"), { recursive: true });
    symlinkSync(join(REPO_ROOT, "node_modules"), join(clone, "node_modules"), "dir");
    const reverted = join(clone, "src", "cli", "secbench-tree.ts");
    const source = readFileSync(reverted, "utf8");
    const partialWorkers = source.replace("const queue = [...entries];", "const queue = entries.slice(0, 1);");
    expect(partialWorkers).not.toBe(source);
    writeFileSync(reverted, partialWorkers);
    const args = ["--dir", corpus(), "--out", temporary("harvey-secbench-tree-out-"), "--concurrency", "1"];
    const accounted = run(args, { cli: reverted });
    expect(accounted.result.status, `${accounted.result.stdout}${accounted.result.stderr}`).toBe(1);
    expect(`${accounted.result.stdout}${accounted.result.stderr}`).toContain("completion accounting failed: 1 generated + 0 named failures = 1, but 5 entries were loaded");

    const unguarded = partialWorkers.replace("if (completed !== entries.length) {", "if (false) {");
    expect(unguarded).not.toBe(partialWorkers);
    writeFileSync(reverted, unguarded);
    const unchecked = run(["--dir", corpus(), "--out", temporary("harvey-secbench-tree-out-"), "--concurrency", "1"], { cli: reverted });
    expect(unchecked.result.status, `${unchecked.result.stdout}${unchecked.result.stderr}`).toBe(0);
    expect(unchecked.result.stdout).toContain("✓ tree usable: 0.0% failures");
  });
});
