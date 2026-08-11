// #926/#1272: the scheduler is wired into the executing CLI, and its products are asserted from
// the artifact the operator actually reads — not from the module's own unit test.
//
//   • scheduleFixes drives execution (components, ordered) instead of a plain `for` loop, and the
//     observed peak slot / peak client-check counts are REPORTED in fix-execution.json, not assumed.
//   • detectLateConflict fires on the overlap batch time could not see: the schedule nodes carry the
//     finding's own file, and a diff that touches a SECOND file is exactly the "grew a file
//     mid-implementation" case §4 describes. The control is the same run's non-overlapping fix.
//   • #1272 remainder: this CLI ran executeFixDiff with NEITHER §2 hook, so a diff that merely
//     APPLIED reached the client handoff as `verified-inert` with a merge rank. The last describe
//     block below drives the real planted M5 class through the batch path in all four directions —
//     the ✓ has to be watched refusing, or it reads exactly like one with no refusal path at all.
//
// Spawned asynchronously so the file never blocks a vitest worker (#1120/#1133).

import { describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import type { Finding } from "../findings.js";
import { capturePatch, disposeCorpus, materialize, readCalibration, type MaterializedCorpus } from "../fix/materialize-calibration.js";

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

// Every corpus carries a real client suite: since #1272 the §2.1 half must actually execute, and a
// target with no discoverable verify command stays short of green (its own direction, asserted below).
// npm rather than pnpm because a materialized corpus has no lockfile.
const clientRepo = (files: Record<string, string>, suite = "console.log('client suite ok');\n"): Record<string, string> => ({
  ...files,
  "package.json": `${JSON.stringify({ name: "cal-client", private: true, scripts: { test: "node client-test.js" } }, null, 2)}\n`,
  "client-test.js": suite,
});

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

async function run(cfg: string, targetDir: string): Promise<{ code: number; out: string; artifact: Record<string, never>; handoff: { rows: { findingId: string; status: string; mergeRank?: number; reason?: string }[] } }> {
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
  return {
    code,
    out,
    artifact: JSON.parse(readFileSync(join(outDir, "fix-execution.json"), "utf8")),
    handoff: JSON.parse(readFileSync(join(outDir, "fix-handoff.json"), "utf8")),
  };
}

describe("fix-execute CLI — the scheduler is the execution driver, and it reports what it observed", () => {
  it("schedules independent fixes as separate components and writes the observed peak concurrency", async () => {
    const c = materialize(clientRepo({ "app/a.ts": "const a = 0;\n", "app/b.ts": "const b = 0;\n" }));
    try {
      const cfg = engagement(c, [finding("F-A", "app/a.ts", patch("a", 1)), finding("F-B", "app/b.ts", patch("b", 1))]);
      const { code, out, artifact } = await run(cfg, c.dir);
      expect(code).toBe(0);
      const concurrency = artifact.concurrency as unknown as {
        componentsScheduled: number; peakSlots: number; peakClientChecks: number; maxSlots: number; maxClientChecks: number; note: string;
      };
      expect(concurrency.componentsScheduled).toBe(2); // disjoint files ⇒ parallel-eligible components
      expect(concurrency.maxSlots).toBe(4);
      expect(concurrency.maxClientChecks).toBe(2);
      // MEASURED, not asserted. Since #1464 the ingest chain is async, so BOTH numbers are real
      // overlap: two components are in flight together and both are inside the client-check phase
      // at the same instant. peakClientChecks used to read 1 here whatever the component count.
      expect(concurrency.peakSlots).toBe(2);
      expect(concurrency.peakClientChecks).toBe(2);
      expect(concurrency.note).toContain("async end to end");
      expect(out).toContain("peak slots observed 2");
      expect(out).toContain("peak client checks observed 2");
      expect(artifact.lateConflicts as unknown as unknown[]).toEqual([]); // control: no overlap here
    } finally {
      disposeCorpus(c);
    }
  }, 60_000);

  // #926's criterion was "concurrency caps are enforced and observable, not documented", and #1463
  // could only record that the cap had nothing to hold back. BOTH caps hold now: six disjoint
  // components would peak at 6 slots and 6 client checks without the semaphores, and each observed
  // number is its own cap. The client-check half is #1464's — it read 1 on every run until the
  // ingest chain became async, because the worker held that semaphore without ever yielding.
  it("HOLDS AT BOTH CAPS: six independent components peak at maxSlots and maxClientChecks, not at six", async () => {
    const names = ["a", "b", "c", "d", "e", "f"];
    const c = materialize(clientRepo(Object.fromEntries(names.map((n) => [`app/${n}.ts`, `const ${n} = 0;\n`]))));
    try {
      const cfg = engagement(c, names.map((n) => finding(`F-${n.toUpperCase()}`, `app/${n}.ts`, patch(n, 1))));
      const { code, artifact } = await run(cfg, c.dir);
      expect(code).toBe(0);
      const concurrency = artifact.concurrency as unknown as {
        componentsScheduled: number; peakSlots: number; maxSlots: number; peakClientChecks: number; maxClientChecks: number;
      };
      expect(concurrency.componentsScheduled).toBe(6);
      expect(concurrency.peakSlots).toBe(concurrency.maxSlots); // the cap is the binding constraint
      expect(concurrency.peakSlots).toBeLessThan(6); // and it is the semaphore doing it, not the workload
      expect(concurrency.peakClientChecks).toBe(concurrency.maxClientChecks); // #1464: real wall-clock overlap
      expect(concurrency.peakClientChecks).toBeLessThan(6); // …and the semaphore, not the workload, is what stopped it
    } finally {
      disposeCorpus(c);
    }
  }, 120_000);

  // #1464, and it is a DIFFERENT fact from the assertion above. peakClientChecks is occupancy of the
  // client-check gate, which a worker holds through its git work too — MEASURED 2026-07-31, it still
  // reported 2 with runCommand reverted to spawnSync, so occupancy and overlap are separate readings.
  // peakClientCommands is counted at the spawn boundary (src/fix/verify.ts), so it answers the
  // question criterion 1 actually asks. The suite here sleeps 400ms so the window is not a race:
  // with a blocking runner this reads 1, with the async one it reads the cap.
  it("GENUINELY OVERLAPS: two of the client's own suites are spawned at the same time", async () => {
    const names = ["a", "b", "c", "d"];
    const slowSuite = "setTimeout(() => console.log('client suite ok'), 400);\n";
    const c = materialize(clientRepo(Object.fromEntries(names.map((n) => [`app/${n}.ts`, `const ${n} = 0;\n`])), slowSuite));
    try {
      const cfg = engagement(c, names.map((n) => finding(`F-${n.toUpperCase()}`, `app/${n}.ts`, patch(n, 1))));
      const { code, artifact, out } = await run(cfg, c.dir);
      expect(code).toBe(0);
      const concurrency = artifact.concurrency as unknown as { peakClientCommands: number; maxClientChecks: number };
      expect(concurrency.peakClientCommands).toBe(concurrency.maxClientChecks); // 2 suites in flight at once
      expect(out).toContain("peak client commands actually spawned together 2");
    } finally {
      disposeCorpus(c);
    }
  }, 120_000);

  it("keeps client commands concurrent while two semgrep detector re-runs yield to the event loop (#1792)", async () => {
    const names = ["a", "b"];
    const vulnerable = "export default function handler(req, res) { res.redirect(302, req.query.next); }\n";
    const fixed = "export default function handler(req, res) { res.redirect(302, '/'); }\n";
    const slowSuite = "setTimeout(() => console.log('client suite ok'), 600);\n";
    const c = materialize(clientRepo(Object.fromEntries(names.map((n) => [`app/${n}.js`, vulnerable])), slowSuite));
    try {
      const findings = names.map((n) => ({
        ...finding(`F-${n.toUpperCase()}`, `app/${n}.js`, capturePatch(c, `app/${n}.js`, fixed)),
        taxonomy: "harvey-open-redirect",
        location: `app/${n}.js:1`,
      }));
      const cfg = engagement(c, findings);
      const { code, artifact, out } = await run(cfg, c.dir);
      expect(code, out).toBe(0);
      const concurrency = artifact.concurrency as unknown as { peakClientCommands: number; peakSemgrepCommands: number };
      expect(concurrency.peakSemgrepCommands).toBeGreaterThan(1);
      expect(concurrency.peakClientCommands).toBeGreaterThan(1);
      expect(out).toContain("peak client commands actually spawned together 2");
    } finally {
      disposeCorpus(c);
    }
  }, 120_000);

  it("flags the LATE conflict a diff introduced — the overlap batch time could not have seen", async () => {
    const c = materialize(clientRepo({ "app/a.ts": "const a = 0;\n", "app/b.ts": "const b = 0;\n" }));
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

  // #1529. #1272's batch wiring made the client's own suite run 2N times per N-fix batch, disclosed
  // rather than hidden. The whole batch is pinned to one commit against one checkout, so the baseline
  // half is identical for every finding and belongs to the BATCH, not the fix. Asserted from
  // fix-execution.json, which is the artifact the operator reads.
  it("baselines each distinct client command ONCE across the batch, not once per fix", async () => {
    const c = materialize(clientRepo({ "app/a.ts": "const a = 0;\n", "app/b.ts": "const b = 0;\n" }));
    try {
      const cfg = engagement(c, [finding("F-A", "app/a.ts", patch("a", 1)), finding("F-B", "app/b.ts", patch("b", 1))]);
      const { code, out, artifact } = await run(cfg, c.dir);
      expect(code).toBe(0);
      const baseline = artifact.baseline as unknown as { commandsRequested: number; commandsExecuted: number; cacheHits: number };
      // Two fixes, one root workspace, one discovered `npm run test`: requested twice, run once.
      expect(baseline.commandsRequested).toBe(2);
      expect(baseline.commandsExecuted).toBe(1);
      expect(baseline.cacheHits).toBe(1);
      expect(out).toContain("1 of 2 requested command run(s) actually executed");
      // Both fixes still cleared BOTH halves — sharing the baseline must not cost the client half.
      expect((artifact.executions as unknown as { green: boolean }[]).every((e) => e.green)).toBe(true);
    } finally {
      disposeCorpus(c);
    }
  }, 60_000);

  // The shared cache must carry a FAILING baseline exactly as faithfully as a passing one: every
  // finding that discovers that command has to keep its `pre-existing-failure-on-baseline` row, or
  // sharing the cache would silently re-attribute a pre-existing break to the second fix.
  it("records the pre-existing baseline failure for EVERY fix that shares the command", async () => {
    const c = materialize(clientRepo({ "app/a.ts": "const a = 0;\n", "app/b.ts": "const b = 0;\n" }, "process.exit(1);\n"));
    try {
      const cfg = engagement(c, [finding("F-A", "app/a.ts", patch("a", 1)), finding("F-B", "app/b.ts", patch("b", 1))]);
      const { artifact } = await run(cfg, c.dir);
      const baseline = artifact.baseline as unknown as { commandsExecuted: number; cacheHits: number };
      expect(baseline.commandsExecuted).toBe(1);
      expect(baseline.cacheHits).toBe(1);
      const executions = artifact.executions as unknown as { findingId: string; evidence?: { clientChecks: { skipped?: string }[] } }[];
      expect(executions).toHaveLength(2);
      for (const e of executions) {
        expect(e.evidence!.clientChecks.map((ch) => ch.skipped)).toEqual(["pre-existing-failure-on-baseline"]);
      }
    } finally {
      disposeCorpus(c);
    }
  }, 60_000);
});

// #1272 remainder. The batch CLI used to score a diff on `git apply --check` alone: MEASURED
// 2026-07-30 against the pre-fix code, the cosmetic diff below produced "✓ F-COSMETIC
// [diff-verified]", exit 0, and a `verified-inert` handoff row at merge rank 1 — a fix that changes a
// comment and nothing else, recommended to the client. These four directions are the same §2 contract
// the interactive path enforces, now asserted from the artifacts on the batch path.
describe("fix-execute CLI — a diff that merely APPLIES is not verified (#1272)", () => {
  const M5_FILE = "app/api/ar-cors-reflected-safe/route.ts"; // the planted M5 unused-param class
  const m5 = (id: string, diff: string): Finding => ({
    ...finding(id, M5_FILE, diff),
    location: `${M5_FILE}:8`,
    evidence: "GET(request: Request) never reads request",
  });
  // The client's own suite, written so the CORRECT fix breaks it — the #1272 shape: detector clean,
  // client red. Nothing but an executed client check can tell this apart from a good fix.
  const brittleSuite =
    `const s = require('fs').readFileSync(${JSON.stringify(M5_FILE)}, 'utf8');\n` +
    `if (!s.includes('request: Request')) { console.error('client contract broken by the fix'); process.exit(1); }\n`;
  const realFix = (src: string) => src.replace("export async function GET(request: Request) {", "export async function GET() {");
  const cosmetic = (src: string) => src.replace("export async function GET(request: Request) {", "export async function GET(request: Request) { // touched");

  async function batch(variant: (src: string) => string, suite?: string, withClient = true) {
    const src = readCalibration(M5_FILE);
    const files = { [M5_FILE]: src };
    const c = materialize(withClient ? clientRepo(files, suite) : files);
    try {
      const cfg = engagement(c, [m5("F-1", capturePatch(c, M5_FILE, variant(src)))]);
      return await run(cfg, c.dir);
    } finally {
      disposeCorpus(c);
    }
  }

  it("GREEN: the real fix clears the detector AND the client's own suite, and only then gets a merge rank", async () => {
    const { code, out, handoff } = await batch(realFix);
    expect(code).toBe(0);
    expect(out).toContain("✓ F-1  [verified-inert]");
    expect(out).toContain("detector clean");
    expect(handoff.rows[0]).toMatchObject({ findingId: "F-1", status: "verified-inert", mergeRank: 1 });
  }, 120_000);

  it("REJECTS a cosmetic diff — it applies clean, and the detector is still firing", async () => {
    const { code, out, handoff } = await batch(cosmetic);
    expect(code).toBe(1);
    expect(out).toContain("✗ F-1  [verify-failed]");
    expect(out).toContain("STILL FIRING");
    expect(handoff.rows[0]!.status).toBe("verify-failed");
    expect(handoff.rows[0]!.mergeRank).toBeUndefined(); // never recommended to the client
    expect(handoff.rows[0]!.reason).toContain("still fires");
  }, 120_000);

  it("REJECTS a real fix that breaks the client's own suite — the half that used to pass vacuously", async () => {
    const { code, out, handoff } = await batch(realFix, brittleSuite);
    expect(code).toBe(1);
    expect(out).toContain("detector clean"); // the detector half is genuinely satisfied
    expect(handoff.rows[0]!.status).toBe("verify-failed");
    expect(handoff.rows[0]!.reason).toContain("the client's own checks FAIL after the fix");
  }, 120_000);

  it("REJECTS when NO client command is discoverable — nothing ran, so nothing passed", async () => {
    const { code, out, handoff } = await batch(realFix, undefined, false);
    expect(code).toBe(1);
    expect(out).toContain("NONE DISCOVERED");
    expect(handoff.rows[0]!.status).toBe("verify-failed");
    expect(handoff.rows[0]!.reason).toContain("client half cannot be evidenced");
  }, 120_000);
});
