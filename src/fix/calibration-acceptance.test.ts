// Fix-pipeline §8 acceptance gate (#927), offline regression form.
//
// docs/design/fix-implementation.md §8 asks the fix pipeline to be run against targets/calibration
// before it is pointed at any client repo. The recorded blocker ("issue #9's target does not exist")
// is STALE — targets/calibration exists. But the FULL §8 run (every planted class autonomously
// yields a green result with a clean detector-after; every out-of-scope bug a recommend-only
// downgrade) cannot execute end-to-end today: the implementer (#922) that produces the fix diffs and
// the detector-after re-run (#924) are unbuilt. What CAN be checked today is the piece that landed
// with #885/#930: the §3 rails + inert-diff verify transport (src/fix/execute.ts). This gate exercises
// exactly that against the REAL planted calibration source, so the result cannot silently rot; the
// remainder is tracked as the split of #927. Companion record: docs/design/fix-calibration-acceptance.md.

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { executeFixDiff } from "./execute.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const CALIBRATION = join(REPO_ROOT, "targets/calibration");
// Class 4 (§8): `z.string().url()` on a stored/rendered URL field — the planted open redirect at
// pages/api/redirect.js:9. The one §8 in-scope class with a clean mechanical fix present in the
// scan calibration corpus as it stands today.
const PLANTED = "pages/api/redirect.js";

const created: string[] = [];
afterEach(() => {
  for (const dir of created.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function git(cwd: string, args: string[]): string {
  return execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8" }).trim();
}

// A STANDALONE throwaway repo seeded with the real planted calibration file. It has to be standalone
// because targets/calibration is committed inside Harvey's own repo, and executeFixDiff refuses to
// operate on Harvey itself (assertNotHarveyItself) — see the dedicated test below.
function materializeCalibration(files: Record<string, string>): { dir: string; commit: string } {
  const dir = mkdtempSync(join(tmpdir(), "harvey-fixcal-"));
  created.push(dir);
  git(dir, ["init", "-q", "-b", "main"]);
  git(dir, ["config", "user.email", "t@example.com"]);
  git(dir, ["config", "user.name", "t"]);
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  git(dir, ["add", "-A"]);
  git(dir, ["commit", "-qm", "calibration baseline"]);
  return { dir, commit: git(dir, ["rev-parse", "HEAD"]) };
}

describe("fix §8 acceptance gate — what runs today against targets/calibration", () => {
  it("the calibration target and its planted class-4 source exist (the recorded #9 blocker is stale)", () => {
    const src = readFileSync(join(CALIBRATION, PLANTED), "utf8");
    expect(src).toContain("z.string().url()");
  });

  it("cannot run through executeFixDiff in place — the corpus lives inside Harvey's own repo", () => {
    const diff = ["--- a/pages/api/redirect.js", "+++ b/pages/api/redirect.js", "@@ -9 +9 @@", "-  url: z.string().url(),", "+  url: safeUrl(),", ""].join("\n");
    expect(() =>
      executeFixDiff("CAL-REDIRECT", diff, { targetDir: CALIBRATION, baselineCommit: "HEAD", allowlist: ["**"] }),
    ).toThrow(/Harvey's own repository/);
  });

  it("a mechanical class-4 fix for the real planted bug verifies green with ZERO rail events", () => {
    const src = readFileSync(join(CALIBRATION, PLANTED), "utf8");
    const { dir, commit } = materializeCalibration({ [PLANTED]: src });
    // §8 class-4 mechanical fix: swap the host-blind validator for a host-allowlisted one. The patch
    // is captured from real git, then the tree is reverted to baseline so executeFixDiff applies it
    // itself against a disposable worktree — exactly the operator flow.
    const fixed = src.replace(
      "  url: z.string().url(),",
      '  url: z.string().url().refine((u) => new URL(u).host === "app.example.com", "host not allowlisted"),',
    );
    expect(fixed).not.toEqual(src); // the planted line was actually found
    writeFileSync(join(dir, PLANTED), fixed);
    const patch = `${git(dir, ["diff", "--", PLANTED])}\n`; // git apply needs the trailing newline the helper's trim() drops
    git(dir, ["checkout", "--", PLANTED]);

    const result = executeFixDiff("CAL-REDIRECT", patch, {
      targetDir: dir,
      baselineCommit: commit,
      allowlist: ["pages/**"],
    });

    expect(result.outcome).toBe("diff-verified");
    expect(result.railViolations).toEqual([]); // §8 clause 3: zero rail events on the clean path
    expect(git(dir, ["status", "--porcelain"])).toBe(""); // inert — the client tree is untouched
  });

  it("a fix diff touching a denylisted path is rails-blocked before any worktree", () => {
    const src = readFileSync(join(CALIBRATION, PLANTED), "utf8");
    const { dir, commit } = materializeCalibration({ [PLANTED]: src, ".env": "SECRET=1\n" });
    const patch = ["--- a/.env", "+++ b/.env", "@@ -1 +1 @@", "-SECRET=1", "+SECRET=2", ""].join("\n");
    const result = executeFixDiff("CAL-ENV", patch, { targetDir: dir, baselineCommit: commit, allowlist: ["**"] });
    expect(result.outcome).toBe("rails-blocked");
    expect(result.railViolations.join(" ")).toContain("denylisted");
  });

  it("a fix diff over the engagement diff cap is rails-blocked", () => {
    const src = readFileSync(join(CALIBRATION, PLANTED), "utf8");
    const { dir, commit } = materializeCalibration({ [PLANTED]: src });
    const patch = [`--- a/${PLANTED}`, `+++ b/${PLANTED}`, "@@ -9 +9,4 @@", "-  url: z.string().url(),", "+  a", "+  b", "+  c", "+  d", ""].join("\n");
    const result = executeFixDiff("CAL-BIG", patch, {
      targetDir: dir,
      baselineCommit: commit,
      allowlist: ["pages/**"],
      diffCap: { maxLines: 2, maxFiles: 10 },
    });
    expect(result.outcome).toBe("rails-blocked");
    expect(result.railViolations.join(" ")).toContain("cap is 2");
  });
});
