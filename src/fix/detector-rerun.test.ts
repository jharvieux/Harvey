// §2.3 detector re-run, proven against the REAL planted calibration source. The class used is the M5
// "Unused parameter" slop planting at targets/calibration/app/api/ar-cors-reflected-safe/route.ts:8
// (the `request` param is never read) — an AST detector that takes only sources, so the re-run is
// hermetic (no external binary). detectorBefore fires; after the mechanical fix (drop the unused
// param) the scoped re-run is clean.

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import { computeGreen } from "./verify.js";
import { detectorBefore, rerunDetector, resolvesToDetector } from "./detector-rerun.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const PLANTED = "app/api/ar-cors-reflected-safe/route.ts";

const created: string[] = [];
afterEach(() => {
  for (const dir of created.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function scratch(rel: string, body: string): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-rerun-"));
  created.push(dir);
  mkdirSync(dirname(join(dir, rel)), { recursive: true });
  writeFileSync(join(dir, rel), body);
  return dir;
}

function finding(o: Partial<Finding> = {}): Finding {
  return {
    id: "F-slop", title: "Unused parameter", severity: "Low", confidence: "Confirmed",
    category: "Maintainability", taxonomy: "M5 — Unused parameter", location: `${PLANTED}:8`,
    status: "Open", evidence: "GET(request: Request) never reads request", impact: "dead surface",
    fix: "drop the unused parameter", value: 3, ease: 5, safety: 5, ...o,
  };
}

describe("rerunDetector — §2.3 against targets/calibration", () => {
  const planted = readFileSync(join(REPO_ROOT, "targets/calibration", PLANTED), "utf8");

  it("fires on the real planted class before the fix", () => {
    const dir = scratch(PLANTED, planted);
    const run = rerunDetector(finding(), dir);
    expect(run.fired).toBe(true);
    expect(run.notRun).toBeUndefined();
  });

  it("is clean after the mechanical fix (drop the unused param)", () => {
    const fixed = planted.replace("export async function GET(request: Request) {", "export async function GET() {");
    expect(fixed).not.toEqual(planted); // the planted signature was actually present
    const dir = scratch(PLANTED, fixed);
    const after = rerunDetector(finding(), dir);
    expect(after.fired).toBe(false);
    expect(after.notRun).toBeUndefined();
    expect(computeGreen({ detectorAfter: after, clientChecks: [] })).toBe(true);
  });

  it("scopes to the fixed file — an instance of the same class elsewhere does not keep it red", () => {
    // Same unused-param class planted in a SECOND file; the fix targets only PLANTED, which is clean.
    const fixed = planted.replace("export async function GET(request: Request) {", "export async function GET() {");
    const dir = scratch(PLANTED, fixed);
    mkdirSync(join(dir, "app/api/other"), { recursive: true });
    writeFileSync(join(dir, "app/api/other/route.ts"), "export async function GET(request: Request) {\n  return new Response('x');\n}\n");
    expect(rerunDetector(finding(), dir).fired).toBe(false); // the other file's instance is out of scope
  });

  it("reports notRun for a taxonomy with no resolver — never a false clean", () => {
    // A semgrep REGISTRY rule (p/owasp-top-ten et al): #1012 replays only the local harvey-* rule
    // directory, because a registry pack needs a network fetch. So this stays deliberately unresolvable.
    const registryRule = "javascript.browser.security.open-redirect.js-open-redirect";
    const dir = scratch(PLANTED, planted);
    const run = rerunDetector(finding({ taxonomy: registryRule, location: "pages/api/redirect.js:9" }), dir);
    expect(run.notRun).toContain("no detector re-run resolver");
    expect(run.fired).toBe(false);
    // fail loud: an unrun detector is not clean, so a fix over it can never be green
    expect(computeGreen({ detectorAfter: run, clientChecks: [] })).toBe(false);
    expect(resolvesToDetector(registryRule)).toBe(false);
  });

  it("a harvey-* rule id that no longer exists in the rule directory does NOT resolve — a deleted rule is not a fixed bug", () => {
    expect(resolvesToDetector("harvey-rule-that-was-deleted")).toBe(false);
    const run = rerunDetector(finding({ taxonomy: "harvey-rule-that-was-deleted" }), scratch(PLANTED, planted));
    expect(run.notRun).toContain("no detector re-run resolver");
  });

  it("carries detectorBefore verbatim from the scan (§2.4), fired by construction", () => {
    const before = detectorBefore(finding());
    expect(before).toEqual({ detectorId: "M5 — Unused parameter", fired: true, output: "GET(request: Request) never reads request" });
  });
});

// #1012 — the semgrep resolver. Proven against the REAL planted calibration sources for two §8
// in-scope M1 classes (open redirect, verbose error), same fixture discipline as the M5 block above.
// The `semgrep` binary is external (the CI `verify` job deliberately does not install it, per
// .github/workflows/ci.yml), so the firing tests skip with a NAMED reason when it is absent —
// matching src/cli/quick-scan.test.ts's convention. The honesty tests below (semgrep-absent ⇒
// notRun) run unconditionally, because those are the ones that must never regress silently.
function hasBinary(name: string): boolean {
  try {
    execFileSync("which", [name], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
const SEMGREP_PRESENT = hasBinary("semgrep");
// Each semgrep invocation loads the whole rule directory and takes seconds, comfortably over
// vitest's 5s default when the full suite runs in parallel.
const SEMGREP_TIMEOUT_MS = 30_000;

const REDIRECT = "pages/api/redirect.js";
const VERBOSE = "pages/api/verbose.js";
const redirectFinding = (o: Partial<Finding> = {}): Finding =>
  finding({
    id: "F-redirect", title: "Open redirect", taxonomy: "harvey-open-redirect", location: `${REDIRECT}:18`,
    category: "Next.js/web footgun", evidence: "z.string().url() validates shape, not host", ...o,
  });

describe.skipIf(!SEMGREP_PRESENT)("rerunDetector — the semgrep resolver (#1012), against targets/calibration", () => {
  const redirectSrc = readFileSync(join(REPO_ROOT, "targets/calibration", REDIRECT), "utf8");
  const verboseSrc = readFileSync(join(REPO_ROOT, "targets/calibration", VERBOSE), "utf8");

  it("fires on the real planted open redirect before the fix", () => {
    const run = rerunDetector(redirectFinding(), scratch(REDIRECT, redirectSrc));
    expect(run.notRun).toBeUndefined();
    expect(run.fired).toBe(true);
    expect(run.output).toContain("harvey-open-redirect still firing");
  }, SEMGREP_TIMEOUT_MS);

  it("is clean after the mechanical fix (redirect to a literal chosen by an enum key, no URL from the request)", () => {
    const fixed = redirectSrc
      .replace("  url: z.string().url(),", '  dest: z.enum(["home", "settings"]),')
      .replace(
        "  res.redirect(302, parsed.data.url);",
        '  if (parsed.data.dest === "settings") {\n    return res.redirect(302, "/settings");\n  }\n  res.redirect(302, "/");',
      );
    expect(fixed).not.toEqual(redirectSrc);
    const after = rerunDetector(redirectFinding(), scratch(REDIRECT, fixed));
    expect(after.notRun).toBeUndefined(); // the rule really re-ran
    expect(after.fired).toBe(false);
    expect(computeGreen({ detectorAfter: after, clientChecks: [] })).toBe(true);
  }, SEMGREP_TIMEOUT_MS);

  it("a cosmetic edit that leaves the bug in place still FIRES — the resolver is not an always-clean stub", () => {
    const noop = redirectSrc.replace("export default function handler(req, res) {", "export default function handler(req, res) { // touched");
    expect(noop).not.toEqual(redirectSrc);
    expect(rerunDetector(redirectFinding(), scratch(REDIRECT, noop)).fired).toBe(true);
  }, SEMGREP_TIMEOUT_MS);

  it("resolves a second §8 class (verbose error) — fires planted, clean once the stack stops being echoed", () => {
    const f = (o: Partial<Finding> = {}) =>
      finding({ id: "F-verbose", taxonomy: "harvey-verbose-error", location: `${VERBOSE}:8`, ...o });
    expect(rerunDetector(f(), scratch(VERBOSE, verboseSrc)).fired).toBe(true);

    const fixed = verboseSrc.replace(
      "    res.status(500).json({ ok: false, stack: err.stack });",
      '    console.error(err);\n    res.status(500).json({ ok: false, error: "Server error" });',
    );
    expect(fixed).not.toEqual(verboseSrc);
    const after = rerunDetector(f(), scratch(VERBOSE, fixed));
    expect(after.notRun).toBeUndefined();
    expect(after.fired).toBe(false);
  }, SEMGREP_TIMEOUT_MS);

  it("scopes to the fixed file — the same rule firing elsewhere in the target does not keep the fix red", () => {
    const fixed = redirectSrc.replace("  res.redirect(302, parsed.data.url);", '  res.redirect(302, "/");');
    const dir = scratch(REDIRECT, fixed);
    mkdirSync(join(dir, "pages/api/other"), { recursive: true });
    writeFileSync(join(dir, "pages/api/other/go.js"), "export default function handler(req, res) {\n  res.redirect(302, req.query.next);\n}\n");
    expect(rerunDetector(redirectFinding(), dir).fired).toBe(false);
  }, SEMGREP_TIMEOUT_MS);

  it("carries the config-path-prefixed check_id a --config <dir> scan produces (that IS the finding's taxonomy)", () => {
    const prefixed = "src.scan.rules.semgrep.harvey-open-redirect";
    expect(resolvesToDetector(prefixed)).toBe(true);
    expect(rerunDetector(redirectFinding({ taxonomy: prefixed }), scratch(REDIRECT, redirectSrc)).fired).toBe(true);
  }, SEMGREP_TIMEOUT_MS);

  // #1021: a rule's own `paths:` filter is matched against the path RELATIVE TO THE SCANNING ROOT.
  // The re-run used to point semgrep straight at the file, which makes that root the file itself and
  // collapses the relative path to a bare basename — so every path-filtered rule matched nothing and
  // was reported CLEAN. A false clean is the worst outcome this gate can produce: it reads as a fixed
  // bug. harvey-void-async (paths: *api*) is the standing case, and this test fails if the re-run
  // ever stops rooting the scan at the target dir.
  it("re-runs a rule that carries a `paths:` filter — a path-scoped rule is not silently clean", () => {
    const receipt = "pages/api/receipt.js";
    const src = readFileSync(join(REPO_ROOT, "targets/calibration", receipt), "utf8");
    const f = finding({ id: "F-void", taxonomy: "harvey-void-async", location: `${receipt}:12`, category: "Next.js/web footgun" });

    const before = rerunDetector(f, scratch(receipt, src));
    expect(before.notRun).toBeUndefined();
    expect(before.fired).toBe(true);

    const fixed = src.replace("  void writeReceiptAudit(req.body.orderId);", "  await writeReceiptAudit(req.body.orderId);");
    expect(fixed).not.toEqual(src);
    const after = rerunDetector(f, scratch(receipt, fixed));
    expect(after.notRun).toBeUndefined();
    expect(after.fired).toBe(false);
  }, SEMGREP_TIMEOUT_MS);
});

describe("rerunDetector — the semgrep resolver never manufactures a clean detector (#1012)", () => {
  const redirectSrc = readFileSync(join(REPO_ROOT, "targets/calibration", REDIRECT), "utf8");

  it("a file the fix's location names but that is absent from the worktree is notRun, not clean", () => {
    const dir = scratch("unrelated.js", "export default 1;\n");
    const run = rerunDetector(redirectFinding(), dir);
    expect(run.notRun).toContain("does not exist");
    expect(computeGreen({ detectorAfter: run, clientChecks: [] })).toBe(false);
  });

  it.skipIf(!SEMGREP_PRESENT)("source semgrep cannot parse is notRun — an unevaluated file is not a fixed file", () => {
    // Semgrep exits 0 on a syntax error, reporting it in `errors` with zero results. Read naively that
    // is indistinguishable from "the rule matched nothing" — the exact shape of the repo's signature defect.
    const dir = scratch(REDIRECT, `${redirectSrc}\nexport default function handler(req, res) { res.redirect(302, req.query.u\n`);
    const run = rerunDetector(redirectFinding(), dir);
    expect(run.notRun).toContain("could not be re-run");
    expect(run.fired).toBe(false);
    expect(computeGreen({ detectorAfter: run, clientChecks: [] })).toBe(false);
  }, SEMGREP_TIMEOUT_MS);

  it.skipIf(SEMGREP_PRESENT)("semgrep absent from PATH is notRun on this machine — resolvable ≠ runnable", () => {
    const run = rerunDetector(redirectFinding(), scratch(REDIRECT, redirectSrc));
    expect(run.notRun).toContain("semgrep not found on PATH");
    expect(computeGreen({ detectorAfter: run, clientChecks: [] })).toBe(false);
  }, SEMGREP_TIMEOUT_MS);
});
