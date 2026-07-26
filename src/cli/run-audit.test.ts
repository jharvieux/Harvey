// Two capture gaps, both proven end-to-end through the real CLI because both were invisible from
// inside the orchestrator — the coverage ledger rode along intact in each case, so the output read
// as an honest, complete export.
//
// #1061: findings capture was gated on --findings-out ALONE, so `run-audit --sarif-out` exported a
// SARIF built from whatever happened to survive on stdout. MEASURED 2026-07-25 on
// targets/calibration: 15 results vs 503, all 51 Critical dropped, both runs exit 0 with
// COVERAGE PASS.
//
// #1062: the M7 code tier shelled out to detect-static with no --out, so the M7 row asserted the
// tier ran while carrying zero findings. On a single-app target M9's unfiltered per-app sweep
// incidentally re-collected them; on a MONOREPO, M9 runs per app, so a code-tier finding outside an
// enumerated package (here shared/Widget.tsx) was lost from the deliverable outright. Hence the
// two-workspace fixture: it is the only shape in which the loss is observable.

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FindingsDocument } from "../findings.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "run-audit.ts");

let scratch: string;
let sarifOnly: { runs: { results: unknown[] }[] };
let engagement: FindingsDocument;

// A two-workspace monorepo with one M7-detectable `<img>` INSIDE an enumerated app and one OUTSIDE
// any of them. Deliberately tiny: the point is the capture wiring, not detector breadth.
function buildMonorepo(root: string): void {
  mkdirSync(join(root, "apps", "web", "app"), { recursive: true });
  mkdirSync(join(root, "apps", "api"), { recursive: true });
  mkdirSync(join(root, "shared"), { recursive: true });
  writeFileSync(join(root, "pnpm-workspace.yaml"), 'packages:\n  - "apps/*"\n');
  writeFileSync(join(root, "package.json"), '{"name":"mono-root","private":true}\n');
  writeFileSync(join(root, "apps", "web", "package.json"), '{"name":"web","dependencies":{"next":"14.0.0"}}\n');
  writeFileSync(join(root, "apps", "api", "package.json"), '{"name":"api"}\n');
  writeFileSync(join(root, "apps", "web", "app", "page.tsx"), 'export default function Page() {\n  return <img src="/hero.png" alt="hero" />;\n}\n');
  writeFileSync(join(root, "shared", "Widget.tsx"), 'export function Widget() {\n  return <img src="/w.png" alt="w" />;\n}\n');
}

const run = (args: string[]): void => {
  execFileSync("node_modules/.bin/tsx", [CLI, ...args], { cwd: REPO_ROOT, stdio: ["ignore", "ignore", "ignore"] });
};

describe("run-audit CLI export capture", () => {
  // 300s: two full ten-module runs of the real orchestrator as child processes.
  beforeAll(() => {
    scratch = mkdtempSync(join(tmpdir(), "harvey-run-audit-test-"));
    buildMonorepo(join(scratch, "target"));
    run([join(scratch, "target"), "--sarif-out", join(scratch, "only.sarif")]);
    run([join(scratch, "target"), "--findings-out", join(scratch, "engagement.json")]);
    sarifOnly = JSON.parse(readFileSync(join(scratch, "only.sarif"), "utf8"));
    engagement = JSON.parse(readFileSync(join(scratch, "engagement.json"), "utf8")) as FindingsDocument;
  }, 300000);

  afterAll(() => rmSync(scratch, { recursive: true, force: true }));

  it("--sarif-out alone exports the same result count as a --findings-out run (#1061)", () => {
    expect(engagement.findings.length).toBeGreaterThan(0); // sanity: the fixture DOES produce findings
    expect(sarifOnly.runs[0]!.results).toHaveLength(engagement.findings.length);
  });

  it("--sarif-out alone carries the classes only capture can produce, not just the stdout fallback (#1061)", () => {
    const ruleIds = new Set(sarifOnly.runs[0]!.results.map((r) => (r as { ruleId: string }).ruleId));
    expect([...ruleIds].some((id) => id.startsWith("M7 — "))).toBe(true);
  });

  it("a code-tier M7 finding outside every enumerated workspace reaches the deliverable (#1062)", () => {
    const m7 = engagement.findings.filter((f) => f.taxonomy.startsWith("M7 — "));
    expect(m7.map((f) => f.location).some((l) => l.includes("shared/Widget.tsx"))).toBe(true);
    expect(m7.map((f) => f.location).some((l) => l.includes("page.tsx"))).toBe(true);
  });

  it("the M7 coverage row still names the code tier it ran", () => {
    const m7 = (engagement.coverage ?? []).filter((r) => r.module === "M7");
    expect(m7).not.toHaveLength(0);
    expect(m7.some((r) => /detect-static \(code tier\)/.test(r.detail ?? ""))).toBe(true);
  });
});
