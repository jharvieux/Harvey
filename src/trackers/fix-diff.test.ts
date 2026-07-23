import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { SuggestedFix } from "../findings.js";
import { renderFixSection, verifySuggestedFix } from "./fix-diff.js";

// A real git repo under tmp so the verification runs against actual `git apply` + a real effect
// command — the mechanical ground truth #825 asks for, not a mock of it. The scenario mirrors M8:
// `calc.js` ships a surviving mutant (add returns a-b); the suggested diff fixes it; the effect
// command is the test that only passes once the mutant is dead.
let dir: string;

function git(args: string[]): void {
  execFileSync("git", args, { cwd: dir, stdio: "ignore" });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "harvey-fixdiff-"));
  git(["init"]);
  git(["config", "user.email", "t@t.co"]);
  git(["config", "user.name", "t"]);
  writeFileSync(join(dir, "calc.js"), "module.exports.add = (a, b) => a - b;\n"); // the surviving mutant
  git(["add", "."]);
  git(["commit", "-m", "seed"]);
});

afterEach(() => rmSync(dir, { recursive: true, force: true }));

// A unified diff that flips the mutant (a-b) back to the correct a+b.
const CORRECT_DIFF = [
  "--- a/calc.js",
  "+++ b/calc.js",
  "@@ -1 +1 @@",
  "-module.exports.add = (a, b) => a - b;",
  "+module.exports.add = (a, b) => a + b;",
  "",
].join("\n");

// The effect check: passes (exit 0) only when add(2,3) === 5, i.e. only after the mutant is fixed.
const EFFECT = ["node", "-e", "process.exit(require('./calc.js').add(2, 3) === 5 ? 0 : 1)"];

describe("verifySuggestedFix", () => {
  it("verifies a diff that applies cleanly and achieves its stated effect (mutant killed)", () => {
    const res = verifySuggestedFix(CORRECT_DIFF, { targetDir: dir, effectCommand: EFFECT });
    expect(res.verified).toBe(true);
    expect(res.detail).toContain("effect confirmed");
  });

  it("leaves the target untouched after the effect check (diff reverted)", () => {
    verifySuggestedFix(CORRECT_DIFF, { targetDir: dir, effectCommand: EFFECT });
    const status = execFileSync("git", ["status", "--porcelain"], { cwd: dir, encoding: "utf8" });
    expect(status.trim()).toBe("");
  });

  it("rejects a diff that applies but does NOT achieve the effect", () => {
    const wrong = CORRECT_DIFF.replace("a + b", "a * b"); // applies, but add(2,3)=6 ≠ 5
    const res = verifySuggestedFix(wrong, { targetDir: dir, effectCommand: EFFECT });
    expect(res.verified).toBe(false);
    expect(res.detail).toContain("effect check failed");
  });

  it("rejects a diff that does not apply cleanly", () => {
    const stale = CORRECT_DIFF.replace("a - b", "a / b"); // context no longer matches the file
    const res = verifySuggestedFix(stale, { targetDir: dir, effectCommand: EFFECT });
    expect(res.verified).toBe(false);
    expect(res.detail).toContain("does not apply cleanly");
  });

  it("verifies apply-clean alone when no effect command is given", () => {
    const res = verifySuggestedFix(CORRECT_DIFF, { targetDir: dir });
    expect(res.verified).toBe(true);
    expect(res.detail).toContain("applies cleanly");
  });
});

describe("renderFixSection", () => {
  it("wraps the diff in a diff fence and surfaces the verification note", () => {
    const fix: SuggestedFix = { diff: CORRECT_DIFF, verified: true, verification: "git apply clean; node effect check" };
    const md = renderFixSection(fix).join("\n");
    expect(md).toContain("```diff");
    expect(md).toContain("module.exports.add = (a, b) => a + b;");
    expect(md).toContain("_Mechanically verified: git apply clean; node effect check_");
  });
});
