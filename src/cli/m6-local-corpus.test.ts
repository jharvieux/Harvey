// Exercises the M6 reporting commands at their process boundary with a local corpus. The source
// files and Git history are deliberately real; a mocked clone or copied selector could prove a
// helper while leaving the shipped CLI's denominator unchanged.

import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const FREQUENCY_CLI = join(REPO_ROOT, "src", "cli", "handrolled-frequency.ts");
const ADMISSION_CLI = join(REPO_ROOT, "src", "cli", "genai-admission-census.ts");
const suffixes = ["ts", "tsx", "jsx", "mjs", "js", "cjs", "mts", "cts"];
const dirs: string[] = [];
const positive = "const uniq = arr.filter((v, i, a) => a.indexOf(v) === i);\n";
const generatedPositive = `${positive}${"x".repeat(1_200)}\n`;

afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

function makeSourceTree(): string {
  const root = mkdtempSync(join(tmpdir(), "harvey-m6-local-corpus-"));
  dirs.push(root);
  for (const suffix of suffixes) {
    const source = join(root, "src", `shape.${suffix}`);
    mkdirSync(dirname(source), { recursive: true });
    writeFileSync(source, positive);
    writeFileSync(join(root, "src", `shape.test.${suffix}`), positive);
    const fixture = join(root, "src", "__fixtures__", `shape.${suffix}`);
    mkdirSync(dirname(fixture), { recursive: true });
    writeFileSync(fixture, positive);
    writeFileSync(join(root, "src", `generated-shape.${suffix}`), generatedPositive);
  }
  return root;
}

function run(cli: string, args: string[], env: NodeJS.ProcessEnv = {}) {
  const result = spawnSync(process.execPath, ["--import", "tsx", cli, ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
  if (result.error) throw result.error;
  return result;
}

function runLocal(cli: string, root: string) {
  return run(cli, ["--local", root]);
}

function gitSentinel(): { bin: string; sentinel: string } {
  const root = mkdtempSync(join(tmpdir(), "harvey-m6-git-sentinel-"));
  dirs.push(root);
  const bin = join(root, "bin");
  mkdirSync(bin);
  const sentinel = join(root, "git-invoked");
  const git = join(bin, "git");
  writeFileSync(git, '#!/bin/sh\nprintf invoked > "$HARVEY_M6_GIT_SENTINEL"\nexit 99\n');
  chmodSync(git, 0o755);
  return { bin, sentinel };
}

describe("M6 local corpus reporting (#2105/#2103)", () => {
  it("reports all eight selected source identities, exact LOC, and the summed repeated shape through the frequency CLI", () => {
    const root = makeSourceTree();
    const result = runLocal(FREQUENCY_CLI, root);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Corpus (1 local source tree):");
    expect(result.stdout).toContain("local] " + root + " — 16 product LOC");
    expect(result.stdout).toContain("Product source population: shared SOURCE_FILE JS/TS suffixes, minus NON_PRODUCT.");
    for (const suffix of suffixes) {
      expect(result.stdout).toContain(`src/shape.${suffix}`);
      expect(result.stdout).not.toContain(`src/shape.test.${suffix}`);
      expect(result.stdout).not.toContain(`src/__fixtures__/shape.${suffix}`);
      expect(result.stdout).not.toContain(`src/generated-shape.${suffix}`);
    }
    expect(result.stdout).toContain("| 3 | YES | unique via filter + indexOf self-compare | matches | 8 | 8 |");
  });

  it("reports every suffix's product commits while excluding test and fixture commits from GenAI admission", () => {
    const root = makeSourceTree();
    const git = (...args: string[]) => execFileSync("git", args, { cwd: root, stdio: "ignore" });
    git("init", "-q");
    git("config", "user.email", "fixture@example.test");
    git("config", "user.name", "Fixture");
    for (const [index, suffix] of suffixes.entries()) {
      git("add", join("src", `shape.${suffix}`));
      const message = index === 0
        ? "feat: add ts shape\n\nCo-authored-by: Claude <noreply@anthropic.com>"
        : `feat: add ${suffix} shape`;
      git("commit", "-q", "-m", message);
    }
    for (const suffix of suffixes) {
      git("add", join("src", `shape.test.${suffix}`), join("src", "__fixtures__", `shape.${suffix}`));
      git("commit", "-q", "-m", `test: add excluded ${suffix} sources`);
    }

    const result = runLocal(ADMISSION_CLI, root);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Commit-level self-admitted-GenAI census over the local source tree (1 repos).");
    expect(result.stdout).toContain("Product-touching commits: shared SOURCE_FILE JS/TS suffixes, minus NON_PRODUCT");
    expect(result.stdout).toContain("History read at the local tree's current HEAD; results move when that history moves.");
    expect(result.stdout).not.toContain("local fixture");
    expect(result.stdout).not.toContain("local tree's PINNED commit");
    expect(result.stdout).toContain("| local | local | local HEAD | 16 | 8 | 1 | 0 | 1 | 7 | no |");
    expect(result.stdout).toContain("touching product source              : 8");
    expect(result.stdout).toContain("...self-admitted                     : 1");
    expect(result.stdout).toContain("...not self-admitted                 : 7");
  });

  it("rejects malformed command lines before any corpus clone can begin", () => {
    const cases: Array<{ cli: string; args: string[]; error: string }> = [
      { cli: FREQUENCY_CLI, args: ["--loacl", "missing-tree"], error: "unknown argument" },
      { cli: FREQUENCY_CLI, args: ["--local"], error: "requires exactly one" },
      { cli: FREQUENCY_CLI, args: ["--local", "one", "--local", "two"], error: "requires exactly one" },
      { cli: ADMISSION_CLI, args: ["--loacl", "missing-tree"], error: "unknown argument" },
      { cli: ADMISSION_CLI, args: ["--local"], error: "requires exactly one" },
      { cli: ADMISSION_CLI, args: ["--local", "one", "--local", "two"], error: "only once" },
      { cli: ADMISSION_CLI, args: ["--density", "--density"], error: "only once" },
    ];
    for (const { cli, args, error } of cases) {
      const { bin, sentinel } = gitSentinel();
      const result = run(cli, args, { PATH: `${bin}:${process.env.PATH}`, HARVEY_M6_GIT_SENTINEL: sentinel });
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(error);
      expect(existsSync(sentinel), `${cli} ${args.join(" ")}`).toBe(false);
    }
  });
});
