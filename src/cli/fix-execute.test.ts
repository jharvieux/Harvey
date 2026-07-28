// #926/#1272: the scheduler is wired into the executing CLI, and its two products are asserted from
// the artifact the operator actually reads — not from the module's own unit test.
//
//   • scheduleFixes drives execution (components, ordered) instead of a plain `for` loop, and the
//     observed peak slot count is REPORTED in fix-execution.json rather than assumed.
//   • detectLateConflict fires on the overlap batch time could not see: the schedule nodes carry the
//     finding's own file, and a diff that touches a SECOND file is exactly the "grew a file
//     mid-implementation" case §4 describes. The control is the same run's non-overlapping fix.
//
// Spawned asynchronously so the file never blocks a vitest worker (#1120/#1133).

import { describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import type { Finding } from "../findings.js";
import { disposeCorpus, materialize, type MaterializedCorpus } from "../fix/materialize-calibration.js";

const execFileAsync = promisify(execFile);
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = "src/cli/fix-execute.ts";

const finding = (id: string, file: string, diff: string): Finding => ({
  id, title: `fix ${id}`, severity: "Low", confidence: "Confirmed", category: "Maintainability",
  taxonomy: "M5 — Unused parameter", location: `${file}:1`, status: "Open",
  evidence: "e", impact: "i", fix: "f", value: 3, ease: 5, safety: 5,
  suggestedFix: { diff, verified: false },
});

// A one-line replacement patch for `app/<name>.ts`, whose committed body is `const <name> = 0;`.
const patch = (name: string, value: number) =>
  [`--- a/app/${name}.ts`, `+++ b/app/${name}.ts`, "@@ -1 +1 @@", `-const ${name} = 0;`, `+const ${name} = ${value};`, ""].join("\n");

// A patch that touches a SECOND file as well — the overlap that only exists once the diff is written.
const widePatch = (name: string, alsoName: string, value: number) =>
  [
    `--- a/app/${name}.ts`, `+++ b/app/${name}.ts`, "@@ -1 +1 @@", `-const ${name} = 0;`, `+const ${name} = ${value};`,
    `--- a/app/${alsoName}.ts`, `+++ b/app/${alsoName}.ts`, "@@ -1 +1 @@", `-const ${alsoName} = 0;`, `+const ${alsoName} = ${value};`,
    "",
  ].join("\n");

function engagement(corpus: MaterializedCorpus, findings: Finding[]): string {
  const dir = join(corpus.dir, ".harvey");
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, "findings.json"),
    JSON.stringify({
      meta: {
        client: "cal", subtitle: "s", date: "2026-07-28", commit: corpus.commit, auditor: "a",
        confidential: false, overallHealth: 7, tenantIsolation: "n/a", authModel: "n/a",
        headline: "n/a", scope: "n/a", methodology: "n/a", outOfScope: "n/a",
      },
      findings,
    }),
  );
  writeFileSync(
    join(dir, "manifest.json"),
    JSON.stringify({
      client: "cal", baselineCommit: corpus.commit, approvedFindingIds: findings.map((f) => f.id),
      enabledCategories: ["Maintainability"], allowlist: ["app/**"], operator: "t",
    }),
  );
  return dir;
}

async function run(cfg: string, targetDir: string): Promise<{ code: number; out: string; artifact: Record<string, never> }> {
  const outDir = join(cfg, "out");
  const args = [CLI, join(cfg, "findings.json"), join(cfg, "manifest.json"), "--target", targetDir, "--out", outDir];
  let code = 0;
  let out = "";
  try {
    const r = await execFileAsync("node_modules/.bin/tsx", args, { cwd: REPO_ROOT, encoding: "utf8" });
    out = `${r.stdout}${r.stderr}`;
  } catch (e) {
    const err = e as { code: number; stdout: string; stderr: string };
    code = err.code;
    out = `${err.stdout}${err.stderr}`;
  }
  return { code, out, artifact: JSON.parse(readFileSync(join(outDir, "fix-execution.json"), "utf8")) };
}

describe("fix-execute CLI — the scheduler is the execution driver, and it reports what it observed", () => {
  it("schedules independent fixes as separate components and writes the observed peak concurrency", async () => {
    const c = materialize({ "app/a.ts": "const a = 0;\n", "app/b.ts": "const b = 0;\n" });
    try {
      const cfg = engagement(c, [finding("F-A", "app/a.ts", patch("a", 1)), finding("F-B", "app/b.ts", patch("b", 1))]);
      const { code, out, artifact } = await run(cfg, c.dir);
      expect(code).toBe(0);
      const concurrency = artifact.concurrency as unknown as { componentsScheduled: number; peakSlots: number; maxSlots: number; note: string };
      expect(concurrency.componentsScheduled).toBe(2); // disjoint files ⇒ parallel-eligible components
      expect(concurrency.maxSlots).toBe(4);
      // MEASURED, not asserted: executeFixDiff is synchronous end to end, so nothing overlaps yet and
      // the number says so out loud instead of the cap looking exercised.
      expect(concurrency.peakSlots).toBe(1);
      expect(concurrency.note).toContain("synchronous");
      expect(out).toContain("peak slots observed 1");
      expect(artifact.lateConflicts as unknown as unknown[]).toEqual([]); // control: no overlap here
    } finally {
      disposeCorpus(c);
    }
  }, 60_000);

  it("flags the LATE conflict a diff introduced — the overlap batch time could not have seen", async () => {
    const c = materialize({ "app/a.ts": "const a = 0;\n", "app/b.ts": "const b = 0;\n" });
    try {
      // Both findings look independent from their locations alone; F-A's diff also rewrites app/b.ts.
      const cfg = engagement(c, [
        finding("F-A", "app/a.ts", widePatch("a", "b", 1)),
        finding("F-B", "app/b.ts", patch("b", 2)),
      ]);
      const { artifact, out } = await run(cfg, c.dir);
      expect((artifact.concurrency as unknown as { componentsScheduled: number }).componentsScheduled).toBe(2);
      const late = artifact.lateConflicts as unknown as { findingId: string; conflictsWith: { findingId: string; files: string[] }[] }[];
      expect(late).toHaveLength(1);
      expect(late[0]!.findingId).toBe("F-B");
      expect(late[0]!.conflictsWith[0]!.findingId).toBe("F-A");
      expect(late[0]!.conflictsWith[0]!.files).toEqual(["app/b.ts"]);
      expect(out).toContain("late conflict");
    } finally {
      disposeCorpus(c);
    }
  }, 60_000);
});
