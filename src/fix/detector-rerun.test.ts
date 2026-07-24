// §2.3 detector re-run, proven against the REAL planted calibration source. The class used is the M5
// "Unused parameter" slop planting at targets/calibration/app/api/ar-cors-reflected-safe/route.ts:8
// (the `request` param is never read) — an AST detector that takes only sources, so the re-run is
// hermetic (no external binary). detectorBefore fires; after the mechanical fix (drop the unused
// param) the scoped re-run is clean.

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
    const dir = scratch(PLANTED, planted);
    const run = rerunDetector(finding({ taxonomy: "harvey-open-redirect", location: "pages/api/redirect.js:9" }), dir);
    expect(run.notRun).toContain("no detector re-run resolver");
    expect(run.fired).toBe(false);
    // fail loud: an unrun detector is not clean, so a fix over it can never be green
    expect(computeGreen({ detectorAfter: run, clientChecks: [] })).toBe(false);
    expect(resolvesToDetector("harvey-open-redirect")).toBe(false);
  });

  it("carries detectorBefore verbatim from the scan (§2.4), fired by construction", () => {
    const before = detectorBefore(finding());
    expect(before).toEqual({ detectorId: "M5 — Unused parameter", fired: true, output: "GET(request: Request) never reads request" });
  });
});
