// The fail-loud contract of the brief-freshness guard (#678): exit 1 when the vendored copy is
// behind a target that ships its own catalog, exit 0 when the target ships none.
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "brief-freshness.ts");

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function targetWithCatalog(md: string): string {
  const target = mkdtempSync(join(tmpdir(), "harvey-brief-target-"));
  dirs.push(target);
  mkdirSync(join(target, "docs", "runbooks"), { recursive: true });
  writeFileSync(join(target, "docs", "runbooks", "anti-patterns.md"), md);
  return target;
}

function run(args: string[]): { status: number; stdout: string; stderr: string } {
  try {
    const stdout = execFileSync("node_modules/.bin/tsx", [CLI, ...args], { cwd: REPO_ROOT, encoding: "utf8" });
    return { status: 0, stdout, stderr: "" };
  } catch (e) {
    const err = e as { status?: number; stdout?: string; stderr?: string };
    return { status: err.status ?? 1, stdout: err.stdout ?? "", stderr: err.stderr ?? "" };
  }
}

describe("brief-freshness CLI fail-loud contract (#678)", () => {
  it("exits 1 and names the missing class when the vendored copy is behind", () => {
    const vendored = targetWithCatalog("## 1. Stub-shaped code\n");
    const target = targetWithCatalog("## 1. Stub-shaped code\n### 2. Brand-new class the vendored brief lacks\n");
    const r = run([target, "--vendored", join(vendored, "docs", "runbooks", "anti-patterns.md")]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("brand-new class the vendored brief lacks");
  });

  it("exits 0 when the target ships no D-091 catalog", () => {
    const target = mkdtempSync(join(tmpdir(), "harvey-brief-nocatalog-"));
    dirs.push(target);
    const r = run([target]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("nothing to diff");
  });
});
