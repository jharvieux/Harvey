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

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ReadinessPlanV1 } from "../audit-readiness.js";
import type { FindingsDocument, ReportMeta } from "../findings.js";

// #1470: a valid meta to mutate one field of, for the refused-export negative control below.
const m1470Meta: ReportMeta = {
  client: "C", subtitle: "s", date: "2026-07-28", commit: "abc", auditor: "a", confidential: true,
  overallHealth: 7, tenantIsolation: "HOLDS", authModel: "oauth", headline: "h", scope: "sc",
  methodology: "m", outOfScope: "none",
};

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "run-audit.ts");

let scratch: string;
let sarifOnly: { runs: { results: unknown[] }[] };
let engagement: FindingsDocument;
let readinessEngagement: FindingsDocument;
let readinessPlan: ReadinessPlanV1;
let baselineEngagement: FindingsDocument;
let baselineFindingId: string;

// A two-workspace monorepo with one M7-detectable `<img>` INSIDE an enumerated app and one OUTSIDE
// any of them. Deliberately tiny: the point is the capture wiring, not detector breadth.
function buildMonorepo(root: string): void {
  mkdirSync(join(root, "apps", "web", "app"), { recursive: true });
  mkdirSync(join(root, "apps", "api"), { recursive: true });
  mkdirSync(join(root, "apps", "scratch"), { recursive: true });
  mkdirSync(join(root, "shared"), { recursive: true });
  writeFileSync(join(root, "pnpm-workspace.yaml"), 'packages:\n  - "apps/*"\n  - "!apps/scratch"\n');
  writeFileSync(join(root, "package.json"), '{"name":"mono-root","private":true}\n');
  writeFileSync(join(root, "apps", "web", "package.json"), '{"name":"web","dependencies":{"next":"14.0.0"}}\n');
  writeFileSync(join(root, "apps", "api", "package.json"), '{"name":"api"}\n');
  writeFileSync(join(root, "apps", "scratch", "package.json"), '{"name":"scratch"}\n');
  writeFileSync(join(root, "apps", "web", "app", "page.tsx"), 'export default function Page() {\n  return <img src="/hero.png" alt="hero" />;\n}\n');
  writeFileSync(join(root, "shared", "Widget.tsx"), 'export function Widget() {\n  return <img src="/w.png" alt="w" />;\n}\n');
}

// #1120: spawn + await, NOT execFileSync. This was the last unfixed instance of the flake and the
// only one serializing the heavy files did not cure. execFileSync blocks the vitest worker's event
// loop, and a blocked worker cannot service the birpc ack for the task update it already sent; that
// ack has a 60s window vitest hardcodes. The beforeAll below is FOUR full ten-module orchestrator
// runs, each awaited independently; the original two-run block was MEASURED 2026-07-26 at 62s on a
// GitHub ubuntu runner, over the line, so it failed the run with `Timeout calling "onTaskUpdate"`
// and ZERO failing tests even
// with nothing else on the machine. Awaiting a spawned child leaves the loop free, so the ack lands.
//
// This is the constraint for every heavy CLI test, not just this one: no single blocking window may
// approach 60s. The others each block ~15s at most, which is why they were not converted with it.
const run = (args: string[]): Promise<void> =>
  new Promise((res, rej) => {
    const child = spawn("node_modules/.bin/tsx", [CLI, ...args], { cwd: REPO_ROOT, stdio: "ignore" });
    child.on("error", rej);
    child.on("close", (code) => (code === 0 ? res() : rej(new Error(`run-audit ${args.join(" ")} exited ${code}`))));
  });

describe("run-audit CLI export capture", () => {
  // 300s: four full ten-module runs of the real orchestrator as child processes.
  beforeAll(async () => {
    scratch = mkdtempSync(join(tmpdir(), "harvey-run-audit-test-"));
    buildMonorepo(join(scratch, "target"));
    await run([join(scratch, "target"), "--sarif-out", join(scratch, "only.sarif")]);
    await run([join(scratch, "target"), "--findings-out", join(scratch, "engagement.json")]);
    await run([
      join(scratch, "target"),
      "--findings-out", join(scratch, "readiness-engagement.json"),
      // Keep this inside the target: emitting the optional artifact must not perturb the scan that
      // is running beside it, even when downstream source discovery accepts JSON files.
      "--readiness-plan-out", join(scratch, "target", "readiness-plan.json"),
    ]);
    sarifOnly = JSON.parse(readFileSync(join(scratch, "only.sarif"), "utf8"));
    engagement = JSON.parse(readFileSync(join(scratch, "engagement.json"), "utf8")) as FindingsDocument;
    readinessEngagement = JSON.parse(readFileSync(join(scratch, "readiness-engagement.json"), "utf8")) as FindingsDocument;
    readinessPlan = JSON.parse(readFileSync(join(scratch, "target", "readiness-plan.json"), "utf8")) as ReadinessPlanV1;
    rmSync(join(scratch, "target", "readiness-plan.json"));
    const baselineFinding = engagement.findings.find((finding) => finding.location.includes("shared/Widget.tsx"));
    if (!baselineFinding) throw new Error("fixture produced no shared/Widget.tsx finding");
    baselineFindingId = baselineFinding.id;
    writeFileSync(
      join(scratch, "baseline.json"),
      JSON.stringify({ ...engagement, findings: [{ ...baselineFinding, location: join(scratch, "target", baselineFinding.location) }] }),
    );
    await run([
      join(scratch, "target"),
      "--findings-out", join(scratch, "baseline-engagement.json"),
      "--baseline", join(scratch, "baseline.json"),
    ]);
    baselineEngagement = JSON.parse(readFileSync(join(scratch, "baseline-engagement.json"), "utf8")) as FindingsDocument;
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

  it("passes the target root into baseline identity matching", () => {
    expect(baselineEngagement.findings.find((finding) => finding.id === baselineFindingId)?.baselineStatus).toBe("persistent");
    expect(baselineEngagement.baseline?.counts.resolved).toBe(0);
  });

  it("emits readiness from the same app inventory without changing M1-M10 execution", () => {
    expect(readinessPlan.schemaVersion).toBe(1);
    expect(readinessPlan.workspaceInventory.applicationWorkspaceIds).toEqual([
      "workspace:apps/api",
      "workspace:apps/scratch",
      "workspace:apps/web",
    ]);
    expect(readinessPlan.workspaces.map((workspace) => workspace.id)).not.toContain("workspace:apps/scratch");
    expect(readinessPlan.workspaceInventory.observations).toContainEqual(expect.objectContaining({
      kind: "excluded", path: "apps/scratch/package.json", reason: "negative-workspace-glob",
    }));
    const auditedApps = [...new Set((readinessEngagement.coverage ?? [])
      .filter((row) => row.module === "M4" && row.instance)
      .map((row) => `workspace:${row.instance}`))].sort();
    expect(auditedApps).toEqual(readinessPlan.workspaceInventory.applicationWorkspaceIds);
    expect(readinessEngagement.coverage).toEqual(engagement.coverage);
    expect(readinessEngagement.findings).toEqual(engagement.findings);
  });
});

// #1470 — the run that produced 589 findings and exported nothing.
//
// MEASURED 2026-07-28 on JakeLeoDev/proposit @ 82838cef with main @ e7e3d1e: all ten modules ran,
// `produced 589 = delivered_from_produced 589 + … + UNACCOUNTED 0`, `LEDGER PASS`, and then
// `Assembled findings document is invalid — refusing to export it` on two duplicate ids. Exit 1,
// no findings.json, no SARIF. Every ledger green, nothing delivered.
//
// Two properties are proven here, both through the real CLI because both were invisible from inside
// the orchestrator: (1) the tree that used to export NOTHING now exports BOTH formats, and (2) on a
// run whose export is refused, the last word is never a PASS — the DELIVERED NOTHING banner
// contradicts the ledger explicitly, and the delivery gate leaves no file behind to be mistaken for
// a deliverable.
const runCapturing = (args: string[]): Promise<{ code: number; out: string }> =>
  new Promise((res, rej) => {
    const child = spawn("node_modules/.bin/tsx", [CLI, ...args], { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    // setEncoding, never `out += <Buffer>.toString()` (#1759): string-concatenating a per-chunk
    // Buffer decodes THAT CHUNK in isolation, so a multi-byte character straddling a chunk boundary
    // decodes to U+FFFD on both sides and the assembled string no longer contains it.
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (d: string) => (out += d));
    child.stderr.on("data", (d: string) => (out += d));
    child.on("error", rej);
    child.on("close", (code) => res({ code: code ?? -1, out }));
  });

describe("run-audit never exits having delivered nothing (#1470)", () => {
  let dupScratch: string;
  let target: string;
  let ok: { code: number; out: string };
  let refused: { code: number; out: string };

  // proposit's exact shape: one SECURITY DEFINER function declared in an initial schema and
  // redefined by a later migration. Under the signature-only id both rows carried ONE id.
  beforeAll(async () => {
    dupScratch = mkdtempSync(join(tmpdir(), "harvey-1470-"));
    target = join(dupScratch, "target");
    mkdirSync(join(target, "supabase", "migrations"), { recursive: true });
    writeFileSync(join(target, "package.json"), '{"name":"dup-definer","dependencies":{"next":"14.0.0","@supabase/supabase-js":"2.45.0"}}\n');
    // Real application source, or the M1 probe reports NotAssessed ("0 application files measured",
    // #1109) and drops its capture — the definer rows would never reach the deliverable at all.
    mkdirSync(join(target, "app"), { recursive: true });
    writeFileSync(join(target, "app", "page.tsx"), 'export default function Page() {\n  return <img src="/hero.png" alt="hero" />;\n}\n');
    const secdef = `create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, role) values (new.id, 'member');
  return new;
end;
$$;`;
    writeFileSync(join(target, "supabase", "migrations", "0001_initial_schema.sql"), secdef);
    writeFileSync(join(target, "supabase", "migrations", "0002_fix_handle_new_user.sql"), secdef);
    ok = await runCapturing([target, "--findings-out", join(dupScratch, "eng.json"), "--sarif-out", join(dupScratch, "out.sarif")]);

    // The negative control: an assembled document that genuinely fails the report schema, via
    // a --meta the operator supplied with a non-string field. Without one, "the banner exists" is a
    // claim about a branch nobody has watched execute.
    writeFileSync(join(dupScratch, "bad-meta.json"), JSON.stringify({ ...m1470Meta, client: 42 }));
    refused = await runCapturing([target, "--meta", join(dupScratch, "bad-meta.json"), "--findings-out", join(dupScratch, "never.json"), "--sarif-out", join(dupScratch, "never.sarif")]);
  }, 300000);

  afterAll(() => rmSync(dupScratch, { recursive: true, force: true }));

  it("exports BOTH formats on the tree that used to export neither", () => {
    expect(ok.code, ok.out).toBe(0);
    const doc = JSON.parse(readFileSync(join(dupScratch, "eng.json"), "utf8")) as FindingsDocument;
    const definer = doc.findings.filter((f) => f.id.startsWith("SB-DEFINER-AUTHZ-"));
    expect(definer).toHaveLength(2); // both migrations reported — disambiguated, not de-duplicated
    expect(new Set(doc.findings.map((f) => f.id)).size).toBe(doc.findings.length);
    expect(JSON.parse(readFileSync(join(dupScratch, "out.sarif"), "utf8")).runs[0].results.length).toBe(doc.findings.length);
  });

  it("on a run that cannot export, the last word is DELIVERED NOTHING, not a ledger PASS", () => {
    expect(refused.code).toBe(1);
    expect(refused.out).toMatch(/DELIVERED NOTHING/);
    expect(refused.out).toMatch(/nothing reached the client/);
    // The banner has to come AFTER the ledger, or the reassuring line is still the one left on screen.
    expect(refused.out.lastIndexOf("DELIVERED NOTHING")).toBeGreaterThan(refused.out.lastIndexOf("LEDGER PASS"));
  });

  it("writes no partial deliverable on that run — neither export exists", () => {
    expect(existsSync(join(dupScratch, "never.json"))).toBe(false);
    expect(existsSync(join(dupScratch, "never.sarif"))).toBe(false);
  });
});
