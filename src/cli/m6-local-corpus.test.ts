// Exercises the M6 reporting commands at their process boundary with a local corpus. The source
// files and Git history are deliberately real; a mocked clone or copied selector could prove a
// helper while leaving the shipped CLI's denominator unchanged.

import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const FREQUENCY_CLI = join(REPO_ROOT, "src", "cli", "handrolled-frequency.ts");
const ADMISSION_CLI = join(REPO_ROOT, "src", "cli", "genai-admission-census.ts");
const suffixes = ["ts", "tsx", "jsx", "mjs", "js", "cjs", "mts", "cts"];
const dirs: string[] = [];

afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

function makeSourceTree(): string {
  const root = mkdtempSync(join(tmpdir(), "harvey-m6-local-corpus-"));
  dirs.push(root);
  for (const suffix of suffixes) {
    const file = join(root, "src", `shape.${suffix}`);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, "const uniq = arr.filter((v, i, a) => a.indexOf(v) === i);\n");
  }
  writeFileSync(join(root, "src", "shape.test.js"), "const ignored = true;\n");
  mkdirSync(join(root, "public"), { recursive: true });
  writeFileSync(join(root, "public", "vendor.min.js"), "var bundled = true;\n");
  return root;
}

function run(cli: string, root: string) {
  const result = spawnSync(process.execPath, ["--import", "tsx", cli, "--local", root], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  if (result.error) throw result.error;
  return result;
}

describe("M6 local corpus reporting (#2105/#2103)", () => {
  it("reports all eight selected source identities, exact LOC, and the summed repeated shape through the frequency CLI", () => {
    const root = makeSourceTree();
    const result = run(FREQUENCY_CLI, root);

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Corpus (1 local fixture):");
    expect(result.stdout).toContain("local] " + root + " — 16 product LOC");
    expect(result.stdout).toContain("Product source population: shared SOURCE_FILE JS/TS suffixes, minus NON_PRODUCT.");
    for (const suffix of suffixes) expect(result.stdout).toContain(`src/shape.${suffix}`);
    expect(result.stdout).not.toContain("src/shape.test.js");
    expect(result.stdout).not.toContain("public/vendor.min.js");
    expect(result.stdout).toContain("| 3 | YES | unique via filter + indexOf self-compare | matches | 8 | 8 |");
  });

  it("reports the same eight product commits and their GenAI admission split through the census CLI", () => {
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
    git("add", "src/shape.test.js");
    git("commit", "-q", "-m", "test: add ignored source");

    const result = run(ADMISSION_CLI, root);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Commit-level self-admitted-GenAI census over the local fixture (1 repos).");
    expect(result.stdout).toContain("Product-touching commits: shared SOURCE_FILE JS/TS suffixes, minus NON_PRODUCT");
    expect(result.stdout).toContain("| local | local | live | 9 | 8 | 1 | 0 | 1 | 7 | no |");
    expect(result.stdout).toContain("touching product source              : 8");
    expect(result.stdout).toContain("...self-admitted                     : 1");
    expect(result.stdout).toContain("...not self-admitted                 : 7");
  });
});
