// Fix-pipeline §8 acceptance gate (#927 → remainder #957).
//
// docs/design/fix-implementation.md §8 asks the fix pipeline to be run against targets/calibration
// before it is pointed at any client repo, with acceptance = every in-scope planted class yields a
// GREEN result whose detector-after is clean, every out-of-scope bug a recommend-only downgrade, and
// zero rail events on the clean path. What is checkable AUTONOMOUSLY today, now that #924 landed the
// detector-after re-run (rerunDetector) and materialization gives a standalone corpus:
//
//   • The FULL §2 gate (apply-clean + §3 rails + detector-after clean) for a class rerunDetector can
//     resolve — the M5 "Unused parameter" planting. This is the "detector-after gate actually re-runs"
//     proof the acceptance requires: it fires on the unfixed source and is clean after the fix.
//   • The §3 rails + inert-diff transport for the semgrep class-4 (open redirect), whose detector-after
//     is DISCLOSED not-autonomously-resolvable (notRun) — the honest split remainder, never faked green.
//   • Clause 2: an out-of-scope planted bug downgraded to recommend-only through intake/screening.
//
// Companion record: docs/design/fix-calibration-acceptance.md.

import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding, FindingsDocument, ReportMeta } from "../findings.js";
import { runFixAcceptance } from "./acceptance.js";
import { rerunDetector, resolvesToDetector } from "./detector-rerun.js";
import { executeFixDiff } from "./execute.js";
import { CALIBRATION_ROOT, disposeCorpus, materialize, readCalibration, type MaterializedCorpus } from "./materialize-calibration.js";
import { intake, type EngagementManifest } from "./pipeline.js";

const created: MaterializedCorpus[] = [];
afterEach(() => {
  for (const c of created.splice(0)) disposeCorpus(c);
});
function track(c: MaterializedCorpus): MaterializedCorpus {
  created.push(c);
  return c;
}

// The one §8 in-scope class whose detector rerunDetector CAN resolve today (M5 AST): the unused-param
// slop planted at app/api/ar-cors-reflected-safe/route.ts:8 — the same planting detector-rerun.test.ts
// exercises. Its mechanical fix drops the unread `request` param.
const M5_FILE = "app/api/ar-cors-reflected-safe/route.ts";
const m5Finding = (o: Partial<Finding> = {}): Finding => ({
  id: "CAL-UNUSED-PARAM", title: "Unused parameter", severity: "Low", confidence: "Confirmed",
  category: "Maintainability", taxonomy: "M5 — Unused parameter", location: `${M5_FILE}:8`,
  status: "Open", evidence: "GET(request: Request) never reads request", impact: "dead surface",
  fix: "drop the unused parameter", value: 3, ease: 5, safety: 5, ...o,
});
const m5Fixed = (src: string) => src.replace("export async function GET(request: Request) {", "export async function GET() {");

// Class 4 (§8): z.string().url() open redirect at pages/api/redirect.js:9 — detected by a SEMGREP rule
// (harvey-open-redirect), which rerunDetector cannot resolve. Its detector-after is a disclosed gap.
const CLASS4_FILE = "pages/api/redirect.js";

describe("fix §8 acceptance — the FULL gate for a resolvable-detector class (M5)", () => {
  it("yields GREEN: the mechanical fix applies clean, clears the rails, and the detector-after is clean", () => {
    const src = readCalibration(M5_FILE);
    const fixed = m5Fixed(src);
    expect(fixed).not.toEqual(src); // the planted signature was actually present
    const r = runFixAcceptance(m5Finding(), { file: M5_FILE, original: src, fixed }, { allowlist: ["app/**"] });
    expect(r.execution.outcome).toBe("diff-verified");
    expect(r.execution.railViolations).toEqual([]); // §8 clause 3: zero rail events on the clean path
    expect(r.detectorAfter.fired).toBe(false);
    expect(r.detectorAfter.notRun).toBeUndefined(); // the detector really re-ran, it wasn't skipped
    expect(r.green).toBe(true);
  });

  it("the detector-after gate genuinely discriminates — it FIRES on the unfixed source", () => {
    // Proves green isn't an always-clean detector: re-run against the UNFIXED corpus and it must fire.
    const baseline = track(materialize({ [M5_FILE]: readCalibration(M5_FILE) }));
    const before = rerunDetector(m5Finding(), baseline.dir);
    expect(before.fired).toBe(true);
    expect(before.notRun).toBeUndefined();
  });

  it("does NOT go green if the 'fix' leaves the detector still firing (a no-op edit)", () => {
    // A cosmetic edit that keeps the unused param: applies clean, but detector-after still fires ⇒ not green.
    const src = readCalibration(M5_FILE);
    const noop = src.replace("export async function GET(request: Request) {", "export async function GET(request: Request) { // touched");
    expect(noop).not.toEqual(src);
    const r = runFixAcceptance(m5Finding(), { file: M5_FILE, original: src, fixed: noop }, { allowlist: ["app/**"] });
    expect(r.execution.outcome).toBe("diff-verified"); // it applied
    expect(r.detectorAfter.fired).toBe(true); // but the bug is still there
    expect(r.green).toBe(false); // so the §8 gate refuses to call it green
  });
});

describe("fix §8 acceptance — disclosed gap: a semgrep-detected class is NOT autonomously green (fail loud)", () => {
  it("class-4 (open redirect) detector-after is notRun — rerunDetector has no semgrep resolver, so it can never fake green", () => {
    const src = readCalibration(CLASS4_FILE);
    const fixed = src.replace(
      "  url: z.string().url(),",
      '  url: z.string().url().refine((u) => new URL(u).host === "app.example.com", "host not allowlisted"),',
    );
    expect(fixed).not.toEqual(src);
    const finding = m5Finding({ id: "CAL-REDIRECT", taxonomy: "harvey-open-redirect", location: `${CLASS4_FILE}:9` });
    const r = runFixAcceptance(finding, { file: CLASS4_FILE, original: src, fixed }, { allowlist: ["pages/**"] });
    expect(r.execution.outcome).toBe("diff-verified"); // the diff still applies + clears rails
    expect(r.detectorAfter.notRun).toContain("no detector re-run resolver");
    expect(r.green).toBe(false); // an unrun detector is NOT clean — never a false autonomous green
    expect(resolvesToDetector("harvey-open-redirect")).toBe(false);
  });
});

describe("fix §8 acceptance — clause 2: an out-of-scope planted bug downgrades to recommend-only", () => {
  const meta = { client: "cal", commit: "cal-base" } as ReportMeta;
  const manifest: EngagementManifest = {
    client: "cal", baselineCommit: "cal-base", approvedFindingIds: ["RLS-USING-TRUE"],
    enabledCategories: ["Maintainability"], allowlist: ["**"], operator: "t",
  };

  it("RLS-off (needs a DB migration, not an enabled category) is screened recommend-only, not auto", () => {
    const doc: FindingsDocument = {
      meta,
      findings: [{
        id: "RLS-USING-TRUE", title: "documents SELECT policy is USING (true)", severity: "Critical",
        confidence: "Confirmed", category: "Security", taxonomy: "D-091 #2",
        location: "supabase/migrations/20260708000002_rls.sql:31", status: "Open",
        evidence: "USING (true)", impact: "cross-tenant read", fix: "scope the policy to the tenant",
        value: 5, ease: 3, safety: 3,
      }],
    };
    const r = intake(doc, manifest);
    expect(r.auto).toEqual([]);
    expect(r.recommendOnly.map((e) => e.finding.id)).toEqual(["RLS-USING-TRUE"]);
    expect(r.recommendOnly[0]!.screen.reason).toContain("not enabled");
  });
});

describe("fix §8 acceptance — rails + in-place refusal (unchanged from #885/#930)", () => {
  it("the calibration target and its planted class-4 source exist (the recorded #9 blocker is stale)", () => {
    expect(readFileSync(`${CALIBRATION_ROOT}/${CLASS4_FILE}`, "utf8")).toContain("z.string().url()");
  });

  it("cannot run through executeFixDiff in place — the corpus lives inside Harvey's own repo", () => {
    const diff = ["--- a/pages/api/redirect.js", "+++ b/pages/api/redirect.js", "@@ -9 +9 @@", "-  url: z.string().url(),", "+  url: safeUrl(),", ""].join("\n");
    expect(() =>
      executeFixDiff("CAL-REDIRECT", diff, { targetDir: CALIBRATION_ROOT, baselineCommit: "HEAD", allowlist: ["**"] }),
    ).toThrow(/Harvey's own repository/);
  });

  it("a fix diff touching a denylisted path is rails-blocked before any worktree", () => {
    const c = track(materialize({ [CLASS4_FILE]: readCalibration(CLASS4_FILE), ".env": "SECRET=1\n" }));
    const patch = ["--- a/.env", "+++ b/.env", "@@ -1 +1 @@", "-SECRET=1", "+SECRET=2", ""].join("\n");
    const result = executeFixDiff("CAL-ENV", patch, { targetDir: c.dir, baselineCommit: c.commit, allowlist: ["**"] });
    expect(result.outcome).toBe("rails-blocked");
    expect(result.railViolations.join(" ")).toContain("denylisted");
  });

  it("a fix diff over the engagement diff cap is rails-blocked", () => {
    const c = track(materialize({ [CLASS4_FILE]: readCalibration(CLASS4_FILE) }));
    const patch = [`--- a/${CLASS4_FILE}`, `+++ b/${CLASS4_FILE}`, "@@ -9 +9,4 @@", "-  url: z.string().url(),", "+  a", "+  b", "+  c", "+  d", ""].join("\n");
    const result = executeFixDiff("CAL-BIG", patch, {
      targetDir: c.dir, baselineCommit: c.commit, allowlist: ["pages/**"], diffCap: { maxLines: 2, maxFiles: 10 },
    });
    expect(result.outcome).toBe("rails-blocked");
    expect(result.railViolations.join(" ")).toContain("cap is 2");
  });
});
