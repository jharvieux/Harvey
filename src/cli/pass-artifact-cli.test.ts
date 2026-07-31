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
// failure observed. A guard nobody has watched fail is indistinguishable from an inert one.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { findFreshPass, ranFromPass } from "../audit-pass-artifact.js";
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
// buildM3PassArtifact/writePassArtifact block deleted): this block FAILED, exit 1, on
// `expect(existsSync(join(out, "M3.pass.json"))).toBe(true)`. Restored: PASS. src/hotspot-scan.ts's
// own round-trip test passed in both states.
describe("hotspot-scan --artifacts-dir writes M3.pass.json (#1407, CLI venue)", () => {
  const out = join(dir, "m3-artifacts");
  const target = join(dir, "m3-target");

  it("the artifact the CLI wrote is read back fresh and derives ran", () => {
    mkdirSync(out, { recursive: true });
    mkdirSync(target, { recursive: true });
    // A target with no git history and no vitals binary lands hotspot-scan in its `unranked` tier —
    // which is the point: the pass artifact must still be written and must name that tier, so a
    // reduced run records itself rather than looking like a run that never happened.
    writeFileSync(join(target, "index.ts"), "export const a = 1;\n");

    const stdout = runCli("src/cli/hotspot-scan.ts", [target, "--artifacts-dir", out]);
    expect(stdout).toContain("M3 pass artifact →");
    expect(existsSync(join(out, "M3.pass.json"))).toBe(true);

    const fresh = derives(out, "M3", target);
    expect(fresh.fresh).toBe(true);
    if (!fresh.fresh) return;
    expect(ranFromPass(fresh.artifact, "mech").status).toBe("ran");
  });

  it("NEGATIVE CONTROL: the same run WITHOUT --artifacts-dir writes no artifact, so the flag is what produces it", () => {
    const bare = join(dir, "m3-artifacts-bare");
    mkdirSync(bare, { recursive: true });
    runCli("src/cli/hotspot-scan.ts", [target]);
    expect(existsSync(join(bare, "M3.pass.json"))).toBe(false);
  });
});

// REVERTED src/cli/detect-deeper.ts to its pre-#1364 state (the `--findings-out` parse and its
// writeFileSync deleted): this block FAILED, exit 1, on
// `expect(existsSync(findingsOut)).toBe(true)`. Restored: PASS. src/cli/detect-deeper.test.ts —
// which hand-copies that writeFileSync into the test — passed in both states, which is exactly the
// defect #1407 records.
//
// The database is stubbed (src/cli/testing/stub-postgres*.mjs) rather than stood up: what is under
// test is the CLI's own argv parse and file write, and a live Postgres would put a 60s-class
// dependency in the light suite to prove nothing extra. The QUERIES are still the real ones and the
// classifiers are the real ones — only the transport is replaced.
describe("detect-deeper --findings-out → record-pass → M1 live (#1407, CLI venue)", () => {
  const out = join(dir, "m1-artifacts");
  const findingsOut = join(dir, "m1-live-findings.json");

  it("both CLIs run for real and the M1 live pass derives ran with the findings intact", () => {
    mkdirSync(out, { recursive: true });
    runCli(
      "src/cli/detect-deeper.ts",
      ["--findings-out", findingsOut],
      {
        SUPABASE_DB_URL: "postgres://stubbed",
        // Keyed on a distinctive fragment of each real query in src/cli/detect-deeper.ts.
        HARVEY_STUB_PG_ROWS: JSON.stringify({
          "t.rowsecurity": [{ schema: "public", table: "invoices" }],
          role_table_grants: [{ grantee: "anon", privilege: "SELECT" }],
        }),
      },
      ["--import", join(REPO_ROOT, "src/cli/testing/stub-postgres-hook.mjs")],
    );

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

  it("NEGATIVE CONTROL: the same run WITHOUT --findings-out writes no findings file", () => {
    const unrequested = join(dir, "not-requested.json");
    runCli(
      "src/cli/detect-deeper.ts",
      [],
      { SUPABASE_DB_URL: "postgres://stubbed", HARVEY_STUB_PG_ROWS: "{}" },
      ["--import", join(REPO_ROOT, "src/cli/testing/stub-postgres-hook.mjs")],
    );
    expect(existsSync(unrequested)).toBe(false);
  });
});
