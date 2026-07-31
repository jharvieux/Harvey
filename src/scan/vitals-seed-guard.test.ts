// #1707 — `assert_no_background_gc()` in src/__fixtures__/vitals-recapture/seed.py is the guard that
// stops #1703 recurring, and until now nothing in the repo tested it: deleting the guard together
// with build_repo's two `gc.auto=0` / `maintenance.auto=false` lines left `pnpm verify` green. The
// only thing that would have noticed was a conservation CI run on a runner with git >= 2.54, and it
// would have noticed indirectly, via the vitals drift check failing again — which is the symptom the
// guard exists to stop anyone diagnosing a second time.
//
// VENUE, decided rather than defaulted (#1707's criterion 2). It runs in `pnpm verify`, from vitest,
// by shelling out to python3.
//   • WHY HERE: `verify` is a required status check on `main` and runs on every PR and every local
//     push, so a deletion is refused at the point it is made. The conservation workflow already
//     EXECUTES the seed, but only on its own cadence and only ever in the guard's silent direction —
//     a green conservation run is evidence the guard did not fire, never that it can.
//   • WHY NOT a text check that the two config lines are present in build_repo: that proves the
//     lines were typed, not that the corpus ends up configured, and it would pass on a build_repo
//     that set them on the wrong repo.
//   • COST: the guard needs no vitals and no seeded corpus, so nothing here builds the real 72-commit
//     fixture. Measured under 3s for the file.
//
// #1707's criterion 3: the guard's job is to detect that a background pack EXISTS, so the firing
// direction below creates a REAL pack with `git repack -d` and hands the guard the resulting repo.
// It does not simulate the consequence (an unlinked object), which would prove the fault detectable
// rather than proving the guard fires.

import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SEED_DIR = join(REPO_ROOT, "src", "__fixtures__", "vitals-recapture");

function hasBinary(name: string): boolean {
  try {
    execFileSync("which", [name], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
const PYTHON3 = hasBinary("python3");
if (!PYTHON3) console.warn("⚠ vitals-seed-guard.test.ts SKIPPED: python3 is not on PATH, so seed.py's guard cannot be exercised here.");

/** Run a snippet with seed.py importable as `seed`. Returns its exit code and combined output. */
function py(snippet: string): { code: number; out: string } {
  const r = spawnSync("python3", ["-c", `import sys\nsys.path.insert(0, ${JSON.stringify(SEED_DIR)})\nimport seed\n${snippet}`], { encoding: "utf8" });
  return { code: r.status ?? -1, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

function git(repo: string, ...args: string[]): void {
  const r = spawnSync("git", ["-C", repo, ...args], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${r.stderr}`);
}

// A throwaway repo with one commit and NO auto-maintenance config — deliberately not seed.py's
// corpus, so the two directions below turn on the pack alone and nothing else.
function repoWithOneCommit(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-seed-guard-"));
  dirs.push(repo);
  git(repo, "init", "-q", "-b", "main");
  git(repo, "config", "user.name", "t");
  git(repo, "config", "user.email", "t@example.com");
  spawnSync("bash", ["-c", `echo x > ${JSON.stringify(join(repo, "a.txt"))}`]);
  git(repo, "add", "a.txt");
  git(repo, "commit", "-q", "-m", "one");
  return repo;
}

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

// The CI runners this repo uses ship python3, and the conservation job runs seed.py directly, so a
// skip here in CI would mean the guard is unproven in the one venue that matters.
it("python3 is present in CI, so the guard's controls below cannot be skipped into silence", () => {
  expect(PYTHON3 || !process.env.CI).toBe(true);
});

describe.skipIf(!PYTHON3)("#1707 assert_no_background_gc() — the #1703 guard has a failing direction", () => {
  it("FIRES on a corpus something has packed, naming the pack contents", () => {
    const repo = repoWithOneCommit();
    git(repo, "repack", "-d");
    const r = py(`seed.assert_no_background_gc(${JSON.stringify(repo)})`);
    expect(r.code).toBe(1);
    expect(r.out).toContain("background gc ran against the seed corpus");
    expect(r.out).toMatch(/\.git\/objects\/pack contains \[.*pack-/);
  });

  it("is SILENT on the same corpus unpacked, so the check above is not always-on", () => {
    const repo = repoWithOneCommit();
    const r = py(`seed.assert_no_background_gc(${JSON.stringify(repo)})`);
    expect(r.out).toBe("");
    expect(r.code).toBe(0);
  });

  // The other half of #1707's criterion 1: the two config lines. Asserted through build_repo's real
  // execution against a one-file corpus, not by reading the source — a build_repo that set them on
  // the wrong repo would pass a text check and fail this.
  it("build_repo leaves gc.auto=0 and maintenance.auto=false ON the corpus it built", () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-seed-build-"));
    dirs.push(repo);
    const r = py(
      [
        `seed.FILES = {"core/checkout.ts": ("export const x = 1;", 1, [seed.ALICE])}`,
        `seed.AB_CHURN = 0`,
        `seed.build_repo(${JSON.stringify(repo)})`,
      ].join("\n"),
    );
    expect(r.out, r.out).toBe("");
    expect(r.code).toBe(0);
    const read = (key: string) => spawnSync("git", ["-C", repo, "config", "--local", "--get", key], { encoding: "utf8" }).stdout.trim();
    expect(read("gc.auto")).toBe("0");
    expect(read("maintenance.auto")).toBe("false");
  });

  // The call site, which the two directions above leave untouched: deleting `assert_no_background_gc(repo)`
  // from main() leaves the function, its message and both controls intact. Proven by running the real
  // main() with run_vitals stubbed (vitals itself is not installed on most machines) and the guard
  // replaced by a recorder — so this asserts main CALLS it, and calls it AFTER the vitals run, which
  // is the ordering the detached maintenance process makes load-bearing.
  it("main() calls the guard, and calls it after run_vitals", () => {
    const out = join(mkdtempSync(join(tmpdir(), "harvey-seed-main-")), "report.json");
    dirs.push(dirname(out));
    const r = py(
      [
        `order = []`,
        `seed.assert_no_background_gc = lambda repo: order.append("guard")`,
        `def fake_vitals(repo):`,
        `    order.append("vitals")`,
        `    return {"hotspots": [], "knowledge_risk": [], "coupling": [], "provenance": {"ai_files": []}}`,
        `seed.run_vitals = fake_vitals`,
        `seed.FILES = {"core/checkout.ts": ("export const x = 1;", 1, [seed.ALICE])}`,
        `seed.AB_CHURN = 0`,
        `sys.argv = ["seed.py", "--out", ${JSON.stringify(out)}]`,
        `seed.main()`,
        `print("ORDER=" + ",".join(order))`,
      ].join("\n"),
    );
    expect(r.code, r.out).toBe(0);
    expect(r.out).toContain("ORDER=vitals,guard");
  });
});
