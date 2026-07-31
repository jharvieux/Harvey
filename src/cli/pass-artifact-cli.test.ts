// #1407: the M3 / M6 / M1-live round trips, driven through the CLI ENTRY POINTS.
//
// #1364 shipped `hotspot-scan --artifacts-dir`, `m6-agreement --target/--artifacts-dir` and
// `detect-deeper --findings-out`, and covered each with a LIBRARY-level test that calls
// `buildM3PassArtifact` / `buildM6PassArtifact` / a hand-copied `writeFileSync` mirror. An
// independent verifier then checked out the pre-#1364 versions of all three `src/cli/*.ts` files on
// top of those library changes and reran the suite: everything still passed. The flag parsing and
// the write call are what those flags ARE, and nothing could fail if they were deleted outright.
//
// So every test here SPAWNS the CLI. The assertion is the same one the library tests make — the
// artifact the CLI wrote is read back by `findFreshPass` and derives `ran` — but the write now has
// to come out of the real argv parse. `src/dynamic-validate.test.ts` is the M2 leg of the same
// pattern and was the standard to match.
//
// Each block records BOTH directions in its own comment: the file reverted, and the exit code /
// failure observed. A guard nobody has watched fail is indistinguishable from an inert one. And no
// block may depend on what happens to be installed on the machine running it — the M3 block did,
// and passed on a developer laptop while failing on every CI runner (see its comment).
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { findFreshPass, ranFromPass } from "../audit-pass-artifact.js";
import { readNamesSafe } from "../fs-walk.js";
import type { RunContext } from "../audit-runner.js";
import type { AuditModule } from "../audit-coverage.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const dir = mkdtempSync(join(tmpdir(), "harvey-pass-cli-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** Spawn a repo CLI through tsx, exactly as `pnpm exec tsx <cli>` does. */
function runCli(cli: string, args: string[], env: NodeJS.ProcessEnv = {}, extraNodeArgs: string[] = []): string {
  return execFileSync("node", [...extraNodeArgs, "--import", "tsx", join(REPO_ROOT, cli), ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, ...env },
  });
}

/** The #416 read side, pointed at an artifacts dir the CLI just wrote into. */
function derives(artifactsDir: string, module: AuditModule, targetDir: string) {
  const ctx: RunContext = {
    targetDir,
    env: { connected: true, dynamic: false, llm: true },
    exec: () => ({ ok: true, output: "" }),
    exists: (p) => existsSync(p),
    artifactsDir,
    readArtifact: (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : undefined),
    now: Date.now(),
  };
  return findFreshPass(ctx, module);
}

// REVERTED src/cli/m6-agreement.ts to its pre-#1364 state (the `--target`/`--artifacts-dir` parse
// and the buildM6PassArtifact/writePassArtifact block deleted): this block FAILED, exit 1, on
// `expect(existsSync(join(out, "M6.pass.json"))).toBe(true)` — the CLI printed the agreement report
// and wrote nothing. Restored: PASS. The pre-existing library test in src/m6-agreement.test.ts
// passed in BOTH states, which is #1407.
describe("m6-agreement --target/--artifacts-dir writes M6.pass.json (#1407, CLI venue)", () => {
  const out = join(dir, "m6-artifacts");
  const verdict = (reviewer: string, framework: "flag" | "spare") => {
    const p = join(dir, `${reviewer}.verdict.json`);
    writeFileSync(
      p,
      JSON.stringify({
        reviewer,
        target: "targets/calibration/simplify",
        verdicts: [
          { file: "debounce.ts", verdict: "flag", replacement: "lodash-es debounce" },
          { file: "framework-adapter.ts", verdict: framework, reason: "SupportedStorage contract" },
        ],
      }),
    );
    return p;
  };

  it("the artifact the CLI wrote is read back fresh and derives ran, with the unanimous flag intact", () => {
    mkdirSync(out, { recursive: true });
    const stdout = runCli("src/cli/m6-agreement.ts", [
      verdict("reviewer-a", "spare"),
      verdict("reviewer-b", "flag"),
      "--target",
      "/engagement/target",
      "--artifacts-dir",
      out,
    ]);

    expect(stdout).toContain("M6 pass artifact →");
    expect(existsSync(join(out, "M6.pass.json"))).toBe(true);

    const fresh = derives(out, "M6", "/engagement/target");
    expect(fresh.fresh).toBe(true);
    if (!fresh.fresh) return;
    expect(fresh.artifact.pass).toBe("verdict");
    const ran = ranFromPass(fresh.artifact, "mech");
    expect(ran.status).toBe("ran");
    // debounce.ts is the unanimous flag; framework-adapter.ts is a SPLIT and must never ship as a
    // finding — it still needs the human adjudicator the report sends it to.
    expect(ran.findings?.map((f) => f.location)).toEqual(["debounce.ts"]);
  });

  it("NEGATIVE CONTROL: --target without --artifacts-dir is refused, so a half-given pair cannot silently write nothing", () => {
    expect(() => runCli("src/cli/m6-agreement.ts", [verdict("reviewer-a", "spare"), verdict("reviewer-b", "flag"), "--target", "/engagement/target"])).toThrow(
      /must be given together/,
    );
  });
});

// REVERTED src/cli/hotspot-scan.ts to its pre-#1364 state (the `--artifacts-dir` parse and the
// buildM3PassArtifact/writePassArtifact block deleted): both blocks FAILED, exit 1 — the round trip
// on `expect(stdout).toContain("M3 pass artifact →")`, the control on the flagged half of its pair.
// Restored: PASS. src/hotspot-scan.ts's own round-trip test passed in both states.
//
// The vitals report is SUPPLIED, not derived. The first version of this block ran the CLI against a
// bare non-git temp dir on the theory that "no git history and no vitals binary" lands it in the
// `unranked` tier with the artifact still written. That is not what happens: with neither, the CLI
// fails loud and exits 1 down buildReducedReport's `git log` branch (src/cli/hotspot-scan.ts), and
// the block only passed on a developer machine because the vitals plugin resolves out of
// ~/.claude/plugins there. MEASURED 2026-07-31: `HOME=$(mktemp -d)` makes the plugin unresolvable
// and reproduces the CI failure verbatim, `fatal: not a git repository`. What is under
// test is the --artifacts-dir parse and the write, so --report now feeds the CLI
// src/__fixtures__/vitals-report.json — a real `vitals 0.2.0 report --json` capture (#1146) —
// which loadReport consumes before it ever looks for the plugin. Both directions now run the same:
// plugin present and plugin absent, exit 0, identical stdout modulo the temp paths.
describe("hotspot-scan --artifacts-dir writes M3.pass.json (#1407, CLI venue)", () => {
  const out = join(dir, "m3-artifacts");
  const target = join(dir, "m3-target");
  const report = join(REPO_ROOT, "src/__fixtures__/vitals-report.json");
  mkdirSync(out, { recursive: true });
  mkdirSync(target, { recursive: true });

  it("the artifact the CLI wrote is read back fresh and derives ran, with the ranked table intact", () => {
    const stdout = runCli("src/cli/hotspot-scan.ts", [target, "--report", report, "--artifacts-dir", out]);
    expect(stdout).toContain("M3 pass artifact →");
    expect(existsSync(join(out, "M3.pass.json"))).toBe(true);

    const fresh = derives(out, "M3", target);
    expect(fresh.fresh).toBe(true);
    if (!fresh.fresh) return;
    // The top-K list and the fact findings are what a downstream consumer reads off this artifact —
    // asserting only that a file exists would pass on an empty one.
    expect(fresh.artifact.hotspots?.[0]).toBe("core/checkout.ts");
    const ran = ranFromPass(fresh.artifact, "mech");
    expect(ran.status).toBe("ran");
    expect(ran.findings?.map((f) => f.id)).toContain("M3-TRUCKFACTOR-core/billing.ts");
  });

  it("NEGATIVE CONTROL: no artifact reaches the directory until --artifacts-dir names it", () => {
    const control = join(dir, "m3-control");
    mkdirSync(control, { recursive: true });

    // The absence alone proves nothing — nothing tells this run about `control`, so it would hold
    // just as well if --artifacts-dir were ignored outright. The second half is the control: the
    // identical command, one flag added, pointed at the same directory.
    const unflagged = runCli("src/cli/hotspot-scan.ts", [target, "--report", report]);
    expect(unflagged).not.toContain("M3 pass artifact →");
    expect(readNamesSafe(control)).toEqual([]);

    const flagged = runCli("src/cli/hotspot-scan.ts", [target, "--report", report, "--artifacts-dir", control]);
    expect(flagged).toContain(`M3 pass artifact → ${join(control, "M3.pass.json")}`);
    expect(readNamesSafe(control)).toEqual(["M3.pass.json"]);
  });
});

// REVERTED src/cli/detect-deeper.ts to its pre-#1364 state (the `--findings-out` parse and its
// writeFileSync deleted): both blocks FAILED, exit 1 — the round trip on
// `expect(existsSync(findingsOut)).toBe(true)`, the control on the flagged half of its pair.
// Restored: PASS. src/cli/detect-deeper.test.ts — which hand-copies that writeFileSync into the
// test — passed in both states, which is exactly the defect #1407 records.
//
// The database is stubbed (src/cli/testing/stub-postgres*.mjs) rather than stood up: what is under
// test is the CLI's own argv parse and file write, and a live Postgres would put a 60s-class
// dependency in the light suite to prove nothing extra. The QUERIES are still the real ones and the
// classifiers are the real ones — only the transport is replaced.
describe("detect-deeper --findings-out → record-pass → M1 live (#1407, CLI venue)", () => {
  const out = join(dir, "m1-artifacts");
  const findingsOut = join(dir, "m1-live-findings.json");
  const stubHook = ["--import", join(REPO_ROOT, "src/cli/testing/stub-postgres-hook.mjs")];
  const stubEnv = (rows: Record<string, unknown[]>) => ({ SUPABASE_DB_URL: "postgres://stubbed", HARVEY_STUB_PG_ROWS: JSON.stringify(rows) });
  // Keyed on a distinctive fragment of each real query in src/cli/detect-deeper.ts.
  const oneGrantFinding = { "t.rowsecurity": [{ schema: "public", table: "invoices" }], role_table_grants: [{ grantee: "anon", privilege: "SELECT" }] };

  it("both CLIs run for real and the M1 live pass derives ran with the findings intact", () => {
    mkdirSync(out, { recursive: true });
    runCli("src/cli/detect-deeper.ts", ["--findings-out", findingsOut], stubEnv(oneGrantFinding), stubHook);

    expect(existsSync(findingsOut)).toBe(true);
    const findings = JSON.parse(readFileSync(findingsOut, "utf8"));
    // A bare Finding[] is the shape `record-pass --findings` reads; the combined
    // { definer, grants, findings } blob on stdout is not, which is why this flag exists.
    expect(Array.isArray(findings)).toBe(true);
    expect(findings.map((f: { id: string }) => f.id)).toEqual(["M1-GRANT-01"]);

    runCli("src/cli/record-pass.ts", [
      "--module", "M1",
      "--target", "/engagement/target",
      "--pass", "live",
      "--findings", findingsOut,
      "--out", out,
    ]);

    const fresh = derives(out, "M1", "/engagement/target");
    expect(fresh.fresh).toBe(true);
    if (!fresh.fresh) return;
    expect(fresh.artifact.pass).toBe("live");
    const ran = ranFromPass(fresh.artifact, "mech");
    expect(ran.status).toBe("ran");
    expect(ran.findings).toEqual(findings);
  });

  it("NEGATIVE CONTROL: no findings file reaches the path until --findings-out names it", () => {
    const control = join(dir, "m1-control-findings.json");

    // Same pairing as the M3 control: the absence half would hold if --findings-out were ignored
    // outright, so the flagged half runs the identical command with the flag pointed at that path.
    runCli("src/cli/detect-deeper.ts", [], stubEnv(oneGrantFinding), stubHook);
    expect(existsSync(control)).toBe(false);

    runCli("src/cli/detect-deeper.ts", ["--findings-out", control], stubEnv(oneGrantFinding), stubHook);
    expect(existsSync(control)).toBe(true);
    expect(JSON.parse(readFileSync(control, "utf8")).map((f: { id: string }) => f.id)).toEqual(["M1-GRANT-01"]);
  });
});
