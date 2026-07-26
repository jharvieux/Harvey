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
//   • The SAME full gate for the §8 classes detected by a harvey-* semgrep rule (open redirect,
//     raw error egress, SQLi) — #1012's semgrep resolver, which retired their disclosed `notRun`.
//   • The same gate again for §8 classes 1/2/5 (zero-row update, unchecked mutation, void-prefixed
//     async), which had no detector at all until #1021 added src/scan/rules/semgrep/silent-failure.yml
//     and the §B21 corpus fixtures they score against.
//   • What is STILL disclosed rather than scored: a semgrep REGISTRY-pack rule (needs a network
//     fetch to replay). The diff-GENERATING implementer is still absent — every fixed source below
//     is a hand-authored mechanical edit, not one the pipeline produced (tracked separately).
//   • Clause 2: an out-of-scope planted bug downgraded to recommend-only through intake/screening.
//
// Companion record: docs/design/fix-calibration-acceptance.md.

import { execFileSync } from "node:child_process";
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

// The §8 classes detected by a harvey-* SEMGREP rule. Since #1012 rerunDetector resolves these too,
// so they run the same full gate as the M5 class above (they were disclosed `notRun` before).
const CLASS4_FILE = "pages/api/redirect.js"; // class 4: z.string().url() open redirect (harvey-open-redirect)
const CLASS3_FILE = "pages/api/verbose.js"; // class 3: raw error egress (harvey-verbose-error)
const SQLI_FILE = "pages/api/search.js"; // planted bug #4: SQLi via template literal (harvey-sql-injection-template)

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

// #1009/#1012: the semgrep resolver landed, so the §8 in-scope classes detected by a harvey-* rule
// now run the SAME full gate as the M5 class — they were `notRun` (a disclosed gap) before. The
// `semgrep` binary is external and the CI `verify` job deliberately does not install it, so these
// skip with a named reason when it is absent rather than passing silently.
function hasBinary(name: string): boolean {
  try {
    execFileSync("which", [name], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
const SEMGREP_PRESENT = hasBinary("semgrep");
// Each of these runs semgrep over the whole rule directory on top of a git materialize+apply cycle,
// comfortably over vitest's 5s default when the full suite runs in parallel.
const SEMGREP_TIMEOUT_MS = 30_000;

describe.skipIf(!SEMGREP_PRESENT)("fix §8 acceptance — the FULL gate for the semgrep-detected classes (#1009)", () => {
  it("class 4 (open redirect) reaches GREEN: the redirect target becomes a literal picked by an enum key", () => {
    const src = readCalibration(CLASS4_FILE);
    const fixed = src
      .replace("  url: z.string().url(),", '  dest: z.enum(["home", "settings"]),')
      .replace(
        "  res.redirect(302, parsed.data.url);",
        '  if (parsed.data.dest === "settings") {\n    return res.redirect(302, "/settings");\n  }\n  res.redirect(302, "/");',
      );
    expect(fixed).not.toEqual(src);
    const finding = m5Finding({ id: "CAL-REDIRECT", taxonomy: "harvey-open-redirect", location: `${CLASS4_FILE}:18` });
    const r = runFixAcceptance(finding, { file: CLASS4_FILE, original: src, fixed }, { allowlist: ["pages/**"] });
    expect(r.execution.outcome).toBe("diff-verified");
    expect(r.execution.railViolations).toEqual([]); // §8 clause 3
    expect(r.detectorAfter.notRun).toBeUndefined(); // the rule really re-ran
    expect(r.detectorAfter.fired).toBe(false);
    expect(r.green).toBe(true);
    expect(resolvesToDetector("harvey-open-redirect")).toBe(true);
  }, SEMGREP_TIMEOUT_MS);

  it("class 4 does NOT go green on a host-allowlist `.refine()` the rule still flags — the gate follows the DETECTOR, not the intent", () => {
    // A plausible-looking fix (a zod .refine host check) that harvey-open-redirect's taint path still
    // reaches. Whether the rule is over-strict here is a detector question; what matters for §8 is that
    // the gate reports what the detector says, never what the fix author meant.
    const src = readCalibration(CLASS4_FILE);
    const fixed = src.replace(
      "  url: z.string().url(),",
      '  url: z.string().url().refine((u) => new URL(u).host === "app.example.com", "host not allowlisted"),',
    );
    expect(fixed).not.toEqual(src);
    const finding = m5Finding({ id: "CAL-REDIRECT-REFINE", taxonomy: "harvey-open-redirect", location: `${CLASS4_FILE}:18` });
    const r = runFixAcceptance(finding, { file: CLASS4_FILE, original: src, fixed }, { allowlist: ["pages/**"] });
    expect(r.execution.outcome).toBe("diff-verified"); // it applies + clears the rails
    expect(r.detectorAfter.fired).toBe(true);
    expect(r.green).toBe(false);
  }, SEMGREP_TIMEOUT_MS);

  it("class 3 (raw error egress) reaches GREEN: the stack is logged server-side and the client gets a generic error", () => {
    const src = readCalibration(CLASS3_FILE);
    const fixed = src.replace(
      "    res.status(500).json({ ok: false, stack: err.stack });",
      '    console.error(err);\n    res.status(500).json({ ok: false, error: "Server error" });',
    );
    expect(fixed).not.toEqual(src);
    const finding = m5Finding({ id: "CAL-VERBOSE", taxonomy: "harvey-verbose-error", location: `${CLASS3_FILE}:8` });
    const r = runFixAcceptance(finding, { file: CLASS3_FILE, original: src, fixed }, { allowlist: ["pages/**"] });
    expect(r.execution.outcome).toBe("diff-verified");
    expect(r.execution.railViolations).toEqual([]);
    expect(r.detectorAfter.notRun).toBeUndefined();
    expect(r.green).toBe(true);
  }, SEMGREP_TIMEOUT_MS);

  it("the SQLi class reaches GREEN once the tainted value is a bound parameter instead of SQL text", () => {
    const src = readCalibration(SQLI_FILE);
    const fixed = src.replace(
      "  const sql = `select id, tenant_id, title from documents where title ilike '%${q}%'`;\n\n  const { rows } = await pool.query(sql);",
      '  const sql = "select id, tenant_id, title from documents where title ilike $1";\n\n  const { rows } = await pool.query(sql, [`%${q}%`]);',
    );
    expect(fixed).not.toEqual(src);
    const finding = m5Finding({ id: "CAL-SQLI", taxonomy: "harvey-sql-injection-template", location: `${SQLI_FILE}:9` });
    const r = runFixAcceptance(finding, { file: SQLI_FILE, original: src, fixed }, { allowlist: ["pages/**"] });
    expect(r.execution.outcome).toBe("diff-verified");
    expect(r.detectorAfter.notRun).toBeUndefined();
    expect(r.green).toBe(true);
  }, SEMGREP_TIMEOUT_MS);
});

describe("fix §8 acceptance — still-disclosed gaps, never faked green (#1009 remainder)", () => {
  it("a semgrep REGISTRY rule stays notRun — only the local harvey-* rules are replayable without a network fetch", () => {
    const src = readCalibration(CLASS4_FILE);
    const fixed = src.replace("  res.redirect(302, parsed.data.url);", '  res.redirect(302, "/");');
    expect(fixed).not.toEqual(src);
    const registryRule = "javascript.browser.security.open-redirect.js-open-redirect";
    const finding = m5Finding({ id: "CAL-REG", taxonomy: registryRule, location: `${CLASS4_FILE}:18` });
    const r = runFixAcceptance(finding, { file: CLASS4_FILE, original: src, fixed }, { allowlist: ["pages/**"] });
    expect(r.execution.outcome).toBe("diff-verified");
    expect(r.detectorAfter.notRun).toContain("no detector re-run resolver");
    expect(r.green).toBe(false);
    expect(resolvesToDetector(registryRule)).toBe(false);
  }, SEMGREP_TIMEOUT_MS);
});

// #1021: §8 classes 1, 2 and 5 (D-091 #7 zero-row update, #3 unchecked mutation, #8 void-prefixed
// async) had NO detector anywhere in src/ — no semgrep rule, no AST engine — so a planted before/after
// fixture would have produced notRun rows, not green ones. src/scan/rules/semgrep/silent-failure.yml
// supplies all three, targets/calibration plants a positive and a safe negative for each
// (GROUND-TRUTH.md §B21), and they now run the SAME full §8 gate as the classes above.
const CLASS1_FILE = "pages/api/payout-claim.js"; // class 1: CAS update with no .select() (harvey-zero-row-update)
const CLASS2_FILE = "pages/api/subscribe.js"; // class 2: awaited insert whose { error } is discarded (harvey-unchecked-mutation)
const CLASS5_FILE = "pages/api/receipt.js"; // class 5: void-prefixed async in a handler (harvey-void-async)

describe.skipIf(!SEMGREP_PRESENT)("fix §8 acceptance — the FULL gate for §8 classes 1, 2 and 5 (#1021)", () => {
  it("class 1 (zero-row update) reaches GREEN: the CAS chains .select() and the handler asserts the row count", () => {
    const src = readCalibration(CLASS1_FILE);
    const fixed = src
      .replace('  await admin\n    .from("payouts")', '  const { data, error } = await admin\n    .from("payouts")')
      .replace(
        '    .eq("status", "pending");',
        '    .eq("status", "pending")\n    .select("id");\n\n  if (error) return res.status(500).json({ error: "claim failed" });\n  if (data.length !== 1) return res.status(409).json({ error: "already claimed" });',
      );
    expect(fixed).not.toEqual(src);
    const finding = m5Finding({ id: "CAL-ZERO-ROW", taxonomy: "harvey-zero-row-update", location: `${CLASS1_FILE}:7` });
    const r = runFixAcceptance(finding, { file: CLASS1_FILE, original: src, fixed }, { allowlist: ["pages/**"] });
    expect(r.execution.outcome).toBe("diff-verified");
    expect(r.execution.railViolations).toEqual([]);
    expect(r.detectorAfter.notRun).toBeUndefined();
    expect(r.detectorAfter.fired).toBe(false);
    expect(r.green).toBe(true);
  }, SEMGREP_TIMEOUT_MS);

  it("class 2 (unchecked mutation) reaches GREEN once { error } is destructured and returned on", () => {
    const src = readCalibration(CLASS2_FILE);
    const fixed = src.replace(
      "  await admin.from(",
      '  const { error } = await admin.from(',
    ).replace(
      "\n\n  return res.status(200).json({ subscribed: true });",
      '\n\n  if (error) return res.status(500).json({ error: "subscribe failed" });\n\n  return res.status(200).json({ subscribed: true });',
    );
    expect(fixed).not.toEqual(src);
    const finding = m5Finding({ id: "CAL-UNCHECKED", taxonomy: "harvey-unchecked-mutation", location: `${CLASS2_FILE}:7` });
    const r = runFixAcceptance(finding, { file: CLASS2_FILE, original: src, fixed }, { allowlist: ["pages/**"] });
    expect(r.execution.outcome).toBe("diff-verified");
    expect(r.execution.railViolations).toEqual([]);
    expect(r.detectorAfter.notRun).toBeUndefined();
    expect(r.detectorAfter.fired).toBe(false);
    expect(r.green).toBe(true);
  }, SEMGREP_TIMEOUT_MS);

  it("class 5 (void-prefixed async) reaches GREEN once the background work is awaited", () => {
    const src = readCalibration(CLASS5_FILE);
    const fixed = src.replace("  void writeReceiptAudit(req.body.orderId);", "  await writeReceiptAudit(req.body.orderId);");
    expect(fixed).not.toEqual(src);
    const finding = m5Finding({ id: "CAL-VOID", taxonomy: "harvey-void-async", location: `${CLASS5_FILE}:12` });
    const r = runFixAcceptance(finding, { file: CLASS5_FILE, original: src, fixed }, { allowlist: ["pages/**"] });
    expect(r.execution.outcome).toBe("diff-verified");
    expect(r.execution.railViolations).toEqual([]);
    expect(r.detectorAfter.notRun).toBeUndefined();
    expect(r.detectorAfter.fired).toBe(false);
    expect(r.green).toBe(true);
  }, SEMGREP_TIMEOUT_MS);

  it("none of the three goes green on a cosmetic edit — each detector still fires on the unfixed shape", () => {
    // The green results above are only worth something if the detectors discriminate. A comment-only
    // edit applies clean and clears the rails, so the ONLY thing that can refuse it is detector-after.
    const cases: [string, string, string][] = [
      [CLASS1_FILE, "harvey-zero-row-update", "export default async function handler(req, res) {"],
      [CLASS2_FILE, "harvey-unchecked-mutation", "export default async function handler(req, res) {"],
      [CLASS5_FILE, "harvey-void-async", "export default async function handler(req, res) {"],
    ];
    for (const [file, taxonomy, anchor] of cases) {
      const src = readCalibration(file);
      const noop = src.replace(anchor, `${anchor} // touched`);
      expect(noop, file).not.toEqual(src);
      const r = runFixAcceptance(m5Finding({ id: `CAL-NOOP-${taxonomy}`, taxonomy, location: `${file}:7` }), { file, original: src, fixed: noop }, { allowlist: ["pages/**"] });
      expect(r.execution.outcome, file).toBe("diff-verified");
      expect(r.detectorAfter.fired, file).toBe(true);
      expect(r.green, file).toBe(false);
    }
  }, SEMGREP_TIMEOUT_MS * 3);

  it("each rule stays silent on its committed safe negative — the corpus pair, checked live", () => {
    // GROUND-TRUTH §B21's negatives, re-run through the same resolver. N-ZERO-ROW-TENANT-SCOPE is the
    // load-bearing one: it has D-091's literal sketch shape (update + two .eq(), no .select()) but
    // scopes by tenant rather than guarding a literal state, so flagging it would make the rule fire
    // on routine multi-tenant writes.
    const negatives: [string, string][] = [
      ["pages/api/payout-claim-safe.js", "harvey-zero-row-update"],
      ["pages/api/rename-workspace.js", "harvey-zero-row-update"],
      ["pages/api/subscribe-safe.js", "harvey-unchecked-mutation"],
      ["pages/api/receipt-safe.js", "harvey-void-async"],
    ];
    for (const [file, taxonomy] of negatives) {
      const c = track(materialize({ [file]: readCalibration(file) }));
      const run = rerunDetector(m5Finding({ id: `CAL-NEG-${file}`, taxonomy, location: `${file}:1` }), c.dir);
      expect(run.notRun, file).toBeUndefined();
      expect(run.fired, file).toBe(false);
    }
  }, SEMGREP_TIMEOUT_MS * 4);
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
