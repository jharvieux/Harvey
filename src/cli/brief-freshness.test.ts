// The fail-loud contract of the brief-freshness guard (#678): exit 1 when the vendored copy is
// behind a target that ships its own catalog, exit 0 when the target ships none.
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { briefFreshnessBanner, catalogProvenance, formatCatalogProvenance } from "../brief-freshness.js";
import { buildHtml } from "../../report-template/render.mjs";
import { esc } from "../../report-template/sections.mjs";
import { assembleEngagementDocument } from "../audit-report.js";
import { AUDIT_RUNNERS } from "../audit-runners.js";
import { renderFidelityBreaches } from "../render-fidelity.js";
import type { Finding } from "../findings.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "brief-freshness.ts");

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function targetWithCatalog(md: string): string {
  const target = mkdtempSync(join(tmpdir(), "harvey-brief-target-"));
  dirs.push(target);
  mkdirSync(join(target, "docs", "runbooks"), { recursive: true });
  writeFileSync(join(target, "docs", "runbooks", "anti-patterns.md"), md);
  return target;
}

function run(args: string[]): Promise<{ status: number; stdout: string; stderr: string }> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn("node_modules/.bin/tsx", [CLI, ...args], { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
    child.once("error", rejectRun);
    child.once("close", (code) => resolveRun({ status: code ?? 1, stdout, stderr }));
  });
}

describe("brief-freshness CLI fail-loud contract (#678)", () => {
  it("exits 1 and names the missing class when the vendored copy is behind", async () => {
    const vendored = targetWithCatalog("## 1. Stub-shaped code\n");
    const target = targetWithCatalog("## 1. Stub-shaped code\n### 2. Brand-new class the vendored brief lacks\n");
    const r = await run([target, "--vendored", join(vendored, "docs", "runbooks", "anti-patterns.md")]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("brand-new class the vendored brief lacks");
  });

  it("exits 0 when the target ships no D-091 catalog", async () => {
    const target = mkdtempSync(join(tmpdir(), "harvey-brief-nocatalog-"));
    dirs.push(target);
    const r = await run([target]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("nothing to diff");
  });
});


// #678 criteria 1 and 2, at the layer they were actually unmet. The CLI above has existed since
// #689 and was wired into NOTHING — MEASURED 2026-07-31, `git grep brief-freshness` reached only
// package.json, so the engagement-start check ran when someone remembered. These cover the banner
// the orchestrator now prints (src/cli/run-audit.ts) and the provenance it derives.
describe("engagement bootstrap: freshness banner and catalog provenance (#678)", () => {
  const VENDORED_HEAD =
    "# Anti-patterns (D-091)\n\n**Provenance**: Last synced from ATC @ `04a565d` (2026-07-19), which carries 28 classes.\n\n";

  it("reads the version off the vendored catalog rather than restating it", () => {
    const p = catalogProvenance(VENDORED_HEAD + "## 1. Stub-shaped code\n### 2. Fail-open\n");
    expect(p).toEqual({ commit: "04a565d", synced: "2026-07-19", classes: 2 });
  });

  // The reason it is parsed and not hardcoded: a re-sync edits the catalog, and a constant here
  // would keep printing the old commit while every status stayed green.
  it("follows the catalog when the provenance line moves, and says so when there is none", () => {
    const moved = catalogProvenance(VENDORED_HEAD.replace("04a565d", "deadbee") + "## 1. Stub\n");
    expect(moved?.commit).toBe("deadbee");
    expect(catalogProvenance("# Anti-patterns\n## 1. Stub\n")).toBeUndefined();
    expect(formatCatalogProvenance(undefined)).toContain("NO provenance line");
  });

  it("reports BEHIND, naming each class, when the target catalogues one the vendored copy lacks", () => {
    const { lines, behind } = briefFreshnessBanner(
      VENDORED_HEAD + "## 1. Stub-shaped code\n",
      "## 1. Stub-shaped code\n### 2. Brand-new class the vendored brief lacks\n",
    );
    expect(behind).toEqual(["brand-new class the vendored brief lacks"]);
    expect(lines.join(" ")).toContain("BEHIND the target by 1 class");
  });

  // The other direction, and it is the state Harvey is actually in: 29 vendored vs 28 in ATC. If
  // this reported `behind`, every real engagement would fail at bootstrap.
  it("is NOT behind when the vendored copy is ahead, and says how far", () => {
    const { lines, behind } = briefFreshnessBanner(
      VENDORED_HEAD + "## 1. Stub-shaped code\n### 2. Harvey-only class\n",
      "## 1. Stub-shaped code\n",
    );
    expect(behind).toEqual([]);
    expect(lines.join(" ")).toContain("1 vendored-only class");
  });

  it("still states the catalog version for a target that ships no catalog — the common client case", () => {
    const { lines, behind } = briefFreshnessBanner(VENDORED_HEAD + "## 1. Stub-shaped code\n", undefined);
    expect(behind).toEqual([]);
    expect(lines[0]).toContain("vendored from ATC @ 04a565d");
    expect(lines.join(" ")).toContain("nothing to diff");
  });

  // Not a hypothetical: Harvey's real catalog against ATC's real one, both read from disk. A
  // renumbering (Harvey's item 21 has no ATC counterpart, so everything after it is offset by one)
  // must not read as drift — the diff keys on the class TITLE.
  it("Harvey's shipped catalog is not behind ATC's canonical one", () => {
    const atc = join(homedir(), "ClaudeCodeProjects", "atc", "docs", "runbooks", "anti-patterns.md");
    if (!existsSync(atc)) return; // ATC is not checked out on CI runners; the unit cases above still gate the logic.
    const { behind } = briefFreshnessBanner(
      readFileSync(join(REPO_ROOT, "briefs", "anti-patterns.md"), "utf8"),
      readFileSync(atc, "utf8"),
    );
    expect(behind).toEqual([]);
  });
});


// #1407's lesson: a round-trip proven at the LIBRARY level leaves the CLI wiring unguarded, and the
// wiring is the whole point of #678 — the diff logic already existed and was reachable from no run.
// So this spawns the real orchestrator. The check runs BEFORE any module, so it is a sub-second
// child process, not a ten-module audit.
describe("run-audit refuses to start on a stale brief (#678 criterion 1, CLI wiring)", () => {
  function targetShippingCatalog(extra: string): string {
    const target = mkdtempSync(join(tmpdir(), "harvey-runaudit-brief-"));
    dirs.push(target);
    mkdirSync(join(target, "docs", "runbooks"), { recursive: true });
    mkdirSync(join(target, "src"), { recursive: true });
    writeFileSync(join(target, "package.json"), '{"name":"t","version":"1.0.0"}\n');
    writeFileSync(join(target, "src", "index.ts"), "export const x = 1;\n");
    writeFileSync(
      join(target, "docs", "runbooks", "anti-patterns.md"),
      readFileSync(join(REPO_ROOT, "briefs", "anti-patterns.md"), "utf8") + extra,
    );
    return target;
  }

  // Bounded on purpose. The bootstrap check runs BEFORE any module, so a stale brief exits in about
  // a second; a fresh one goes on to a ten-module audit that has no business inside this suite. The
  // bound is therefore also the assertion for the passing direction: still running at the cap means
  // the check let the run through.
  function runAudit(target: string): Promise<{ status: number | null; out: string }> {
    return new Promise((resolveRun, rejectRun) => {
      const child = spawn("node_modules/.bin/tsx", [join(REPO_ROOT, "src", "cli", "run-audit.ts"), target], {
        cwd: REPO_ROOT,
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "";
      let stderr = "";
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk: string) => (stdout += chunk));
      child.stderr.on("data", (chunk: string) => (stderr += chunk));
      const timeout = setTimeout(() => child.kill("SIGTERM"), 4_000);
      child.once("error", (error) => {
        clearTimeout(timeout);
        rejectRun(error);
      });
      child.once("close", (code) => {
        clearTimeout(timeout);
        resolveRun({ status: code, out: `${stdout}${stderr}` });
      });
    });
  }

  it("exits 1 and names the class before a single module runs", async () => {
    const { status, out } = await runAudit(targetShippingCatalog("\n### 99. Brand-new class the vendored brief lacks\n"));
    expect(status).toBe(1);
    expect(out).toContain("BRIEF STALE");
    expect(out).toContain("brand-new class the vendored brief lacks");
    // The refusal has to precede the audit, or a stale brief costs a full ten-module run first.
    expect(out).not.toContain("COVERAGE PASS");
    expect(out).not.toContain("Hotspot analysis");
  });

  // Both directions on the SAME target shape: the identical tree with a catalog the vendored copy
  // does cover must get past the check. Without this the test above passes for a bad reason
  // (anything that makes run-audit exit 1) instead of for the stale brief.
  it("gets past the check on the same tree when the catalog holds no new class", async () => {
    const { status, out } = await runAudit(targetShippingCatalog(""));
    expect(out).toContain("vendored brief covers every class the target catalogues");
    expect(out).not.toContain("BRIEF STALE");
    // It ran ON past the check rather than refusing: the run was still going when the cap killed it.
    expect(status).not.toBe(1);
  });
});


// #678 criterion 2 delivered, not merely produced. The bootstrap banner is console output; the
// criterion asks the ENGAGEMENT DOC to record the version, so this follows the row from M1's own
// probe through the real assembler to the real renderer. Deleting the `briefProvenanceFinding(...)`
// spread in src/audit-runners.ts turns every assertion below red.
describe("M1-BRIEF-00 reaches the assembled deliverable and the rendered report (#678 criterion 2)", () => {
  function m1Findings(targetDir: string): Finding[] {
    const runner = AUDIT_RUNNERS.find((r) => r.module === "M1")!;
    const ctx = {
      targetDir,
      env: { connected: false, dynamic: false, llm: false },
      // The probe needs a codebase-size line to accept the scan as non-empty (#1065/#1109).
      exec: () => ({ ok: true, output: "1,200 lines of application code across 12 file(s)", stderr: "" }),
      exists: () => false,
    } as unknown as Parameters<typeof runner.run>[0];
    const result = runner.run(ctx) as { findings?: Finding[] };
    return result.findings ?? [];
  }

  it("M1's probe emits the provenance row with the catalog version in its own words", () => {
    const row = m1Findings(REPO_ROOT).find((f) => f.id === "M1-BRIEF-00");
    expect(row).toBeDefined();
    expect(row?.confidence).toBe("N/A");
    expect(row?.evidence).toMatch(/vendored from ATC @ [0-9a-f]{7}/);
    expect(row?.evidence).toContain("29 classes");
  });

  it("survives the assembler and the renderer, reason included", () => {
    const findings = m1Findings(REPO_ROOT);
    const doc = assembleEngagementDocument(
      (["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10"] as const).map((module) => ({ module, status: "ran" as const })),
      { connected: false, dynamic: false, llm: false },
      findings,
      {
        client: "Acme", subtitle: "s", date: "2026-07-31", commit: "abc1234", auditor: "Harvey", confidential: true,
        overallHealth: 6, tenantIsolation: "Not verified", authModel: "Supabase", headline: "h", scope: "s",
        methodology: "M1–M10", outOfScope: "infrastructure",
      },
    );
    expect(doc.findings.some((f) => f.id === "M1-BRIEF-00")).toBe(true);

    const html = buildHtml(doc);
    const row = doc.findings.find((f) => f.id === "M1-BRIEF-00")!;
    expect(html).toContain(esc(row.evidence));
    expect(renderFidelityBreaches(doc, html)).toEqual([]);
  });
});
