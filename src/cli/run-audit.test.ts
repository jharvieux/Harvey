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
import { once } from "node:events";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { AUDIT_MODULES } from "../audit-coverage.js";
import { discoverReadinessPlan, type ReadinessPlanV1 } from "../audit-readiness.js";
import { bindReadinessPlanV1 } from "../audit-readiness-authority.js";
import { parseReadinessArtifactsV1 } from "../audit-readiness-artifacts.js";
import { captureSourceSentinel } from "../disposable-target.js";
import { createReadinessReceiptContext, validateReadinessExecutionV1, type ReadinessExecutionV1 } from "../audit-readiness-receipts.js";
import { createAuditReplayBinding, writeAuditReplayBundle, type AuditEvidenceInput } from "../audit-replay.js";
import type { Finding, FindingsDocument, ReportMeta } from "../findings.js";

// #1470: a valid meta to mutate one field of, for the refused-export negative control below.
const m1470Meta: ReportMeta = {
  client: "C", subtitle: "s", date: "2026-07-28", commit: "abc", auditor: "a", confidential: true,
  overallHealth: 7, tenantIsolation: "HOLDS", authModel: "oauth", headline: "h", scope: "sc",
  methodology: "m", outOfScope: "none",
};

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "run-audit.ts");

let scratch: string;
let sarifOnly: { runs: { results: unknown[]; properties: { harveyAuditContext?: FindingsDocument["auditContext"] } }[] };
let engagement: FindingsDocument;

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
  writeFileSync(join(root, "apps", "web", "schema.sql"), "CREATE TABLE public.people (\n  id uuid PRIMARY KEY,\n  email text\n);\n");
  writeFileSync(join(root, "shared", "Widget.tsx"), 'export function Widget() {\n  return <img src="/w.png" alt="w" />;\n}\n');
}

// #1970: each hook/test owns ONE audit. Four unrelated exports in one 300s beforeAll
// exhausted that shared budget on main even though the worker was awaiting its children.
// A child deadline is shorter than its Vitest deadline so the process tree has exited before
// fixture teardown. Awaited spawn still preserves the worker's RPC-ack window (#1120).
const CHILD_TIMEOUT_MS = 120_000;
const CASE_TIMEOUT_MS = CHILD_TIMEOUT_MS + 30_000;
const OUTPUT_TAIL_LENGTH = 128 * 1024;

type ChildResult = { code: number; out: string };

function killChildGroup(pid: number | undefined): void {
  if (pid === undefined) return;
  try {
    process.kill(-pid, "SIGKILL");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
  }
}

function startChild(command: string, args: string[], env: Record<string, string> = {}) {
  // tsx -> run-audit -> pnpm -> scanner all belong to this group. Killing only tsx leaves
  // scanners writing into a fixture after its suite has failed and begun removing it.
  const child = spawn(command, args, { cwd: REPO_ROOT, detached: true, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...env } });
  const completion = new Promise<ChildResult>((res, rej) => {
    let out = "";
    let timedOut = false;
    const deadline = setTimeout(() => {
      timedOut = true;
      try {
        killChildGroup(child.pid);
      } catch (error) {
        rej(error);
      }
    }, CHILD_TIMEOUT_MS);
    // Decode across chunk boundaries (#1759), and retain both streams even for successful runs.
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    const capture = (chunk: string) => { out = (out + chunk).slice(-OUTPUT_TAIL_LENGTH); };
    child.stdout.on("data", capture);
    child.stderr.on("data", capture);
    child.once("error", (error) => {
      clearTimeout(deadline);
      rej(new Error(`${command} ${args.join(" ")} failed to start: ${error.message}`));
    });
    child.once("close", (code, signal) => {
      clearTimeout(deadline);
      // close, not exit: inherited pipes must also have closed before teardown may proceed.
      if (timedOut) rej(new Error(`${command} ${args.join(" ")} timed out after ${CHILD_TIMEOUT_MS}ms (signal ${signal})\n${out}`));
      else res({ code: code ?? -1, out });
    });
  });
  return { child, completion };
}

async function runCapturing(args: string[], env: Record<string, string> = {}): Promise<ChildResult> {
  const started = performance.now();
  const result = await startChild("node_modules/.bin/tsx", [CLI, ...args], env).completion;
  console.info(`run-audit ${args.filter((arg) => arg.startsWith("--")).join(" ")}: exit ${result.code} in ${Math.round(performance.now() - started)}ms`);
  return result;
}

async function run(args: string[]): Promise<void> {
  const result = await runCapturing(args);
  if (result.code !== 0) throw new Error(`run-audit ${args.join(" ")} exited ${result.code}\n${result.out}`);
}

describe("run-audit child lifecycle", () => {
  it("retains diagnostics and a nonzero exit without treating it as a timeout", async () => {
    const result = await startChild(process.execPath, ["-e", 'process.stdout.write("stdout evidence\\n"); process.stderr.write("stderr evidence\\n"); process.exitCode = 7;']).completion;
    expect(result.code).toBe(7);
    expect(result.out).toContain("stdout evidence");
    expect(result.out).toContain("stderr evidence");
  });

  it("kills a timed-out child and its pipe-holding descendant before rejecting", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const running = startChild(process.execPath, ["-e", `
      const { spawn } = require("node:child_process");
      const descendant = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: ["ignore", "inherit", "inherit"] });
      descendant.once("spawn", () => process.stdout.write("child-ready\\n"));
      setInterval(() => {}, 1000);
    `]);
    const settled = running.completion.then((value) => ({ value, error: undefined }), (error: unknown) => ({ value: undefined, error }));
    try {
      // Advance only after the child's first byte. Startup speed must not decide whether the
      // control ever reached its intended hanging state (#1768).
      const [firstByte] = await once(running.child.stdout, "data", { signal: AbortSignal.timeout(5000) });
      expect(firstByte).toContain("child-ready");
      const closed = once(running.child, "close", { signal: AbortSignal.timeout(5000) });
      await vi.advanceTimersByTimeAsync(CHILD_TIMEOUT_MS);
      await closed;
      const result = await settled;
      expect(result.error).toHaveProperty("message", expect.stringContaining(`timed out after ${CHILD_TIMEOUT_MS}ms`));
      expect(result.error).toHaveProperty("message", expect.stringContaining("child-ready"));
      expect(running.child.signalCode).toBe("SIGKILL");
    } finally {
      // The negative control must clean up even when the deadline's group kill is
      // deliberately removed: otherwise its inherited pipe would leave this test pending.
      killChildGroup(running.child.pid);
      await settled;
      vi.useRealTimers();
    }
  });
});

describe("run-audit CLI export capture", () => {
  beforeAll(() => {
    scratch = mkdtempSync(join(tmpdir(), "harvey-run-audit-test-"));
    buildMonorepo(join(scratch, "target"));
  });

  beforeAll(async () => {
    await run([join(scratch, "target"), "--sarif-out", join(scratch, "only.sarif")]);
    sarifOnly = JSON.parse(readFileSync(join(scratch, "only.sarif"), "utf8"));
  }, CASE_TIMEOUT_MS);

  beforeAll(async () => {
    await run([join(scratch, "target"), "--findings-out", join(scratch, "engagement.json"), "--retain-artifacts", join(scratch, "fresh-bundle")]);
    engagement = JSON.parse(readFileSync(join(scratch, "engagement.json"), "utf8")) as FindingsDocument;
  }, CASE_TIMEOUT_MS);

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

  it("passes the target root into baseline identity matching", async () => {
    // Fresh-run documents from before receipt-bound retention are intentionally unbound. Keep
    // accepting them as historical input, but never turn their unmatched rows into remediation.
    const unboundBaselinePath = join(scratch, "unbound-baseline.json");
    const unbound = structuredClone(engagement);
    delete unbound.auditContext;
    delete unbound.meta.auditContext;
    writeFileSync(unboundBaselinePath, JSON.stringify(unbound));
    await run([
      join(scratch, "target"), "--findings-out", join(scratch, "unbound-comparison.json"),
      "--baseline", unboundBaselinePath,
    ]);
    const unboundComparison = JSON.parse(readFileSync(join(scratch, "unbound-comparison.json"), "utf8")) as FindingsDocument;
    expect(unboundComparison.baseline?.comparison?.kind).toBe("incompatible");
    expect(unboundComparison.baseline?.counts).toMatchObject({ resolved: 0, new: 0, persistent: 0 });
    expect(unboundComparison.baseline?.comparison?.denominators.unresolvedCurrent).toBe(unboundComparison.findings.length);
    expect(unboundComparison.baseline?.comparison?.limitations.join(" ")).toContain("Missing engagement");
    expect(new Set(unboundComparison.findings.map((finding) => finding.baselineStatus))).toEqual(new Set(["incompatible"]));

    // Retained assembly independently derives producer/scope provenance from bound receipts.
    // Exercise the shipping assembly path, which derives that provenance from bound receipts,
    // and make only one prior location absolute so omitting target root breaks this exact match.
    const bundle = join(scratch, "baseline-bundle");
    const raw = join(scratch, "baseline-raw.json");
    const sbom = join(scratch, "baseline-sbom.json");
    writeFileSync(raw, '{"source":"baseline identity fixture"}\n');
    writeFileSync(sbom, '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}\n');
    const passes: AuditEvidenceInput[] = AUDIT_MODULES.map((module): AuditEvidenceInput => {
      const finding: Finding = {
        id: `${module}-BASELINE`, title: `${module} baseline identity`, severity: "Low",
        confidence: "Review", category: "Maintainability", taxonomy: `${module} — baseline identity`,
        location: module === "M7" ? "shared/Widget.tsx:1" : `src/${module}.ts:1`, status: "Open",
        evidence: "Bound fixture evidence", impact: "Measured impact", fix: "Repair", value: 1, ease: 1, safety: 1,
      };
      return {
        scope: { module, workspace: ".", tier: "source", surface: "module", wholeModule: true },
        generatedAt: new Date().toISOString(), producer: { name: module, version: "fixture" },
        rawArtifacts: [raw], result: { kind: "examined", unitsExamined: 1, scope: "fixture source", detail: "Bound fixture source", findings: [finding] },
      };
    });
    writeAuditReplayBundle(bundle, {
      binding: createAuditReplayBinding(join(scratch, "target"), { network: false }),
      scopes: passes.map((pass) => pass.scope), passes, sbomPath: sbom, meta: m1470Meta,
    });
    const baselinePath = join(scratch, "baseline.json");
    await run([join(scratch, "target"), "--assemble", bundle, "--findings-out", baselinePath]);
    const baseline = JSON.parse(readFileSync(baselinePath, "utf8")) as FindingsDocument;
    const baselineFinding = baseline.findings.find((finding) => finding.id === "M7-BASELINE")!;
    writeFileSync(baselinePath, JSON.stringify({
      ...baseline,
      findings: baseline.findings.map((finding) => finding.id === baselineFinding.id
        ? { ...finding, location: join(scratch, "target", finding.location) }
        : finding),
    }));
    await run([
      join(scratch, "target"),
      "--assemble", bundle,
      "--findings-out", join(scratch, "baseline-engagement.json"),
      "--baseline", baselinePath,
    ]);
    const baselineEngagement = JSON.parse(readFileSync(join(scratch, "baseline-engagement.json"), "utf8")) as FindingsDocument;
    expect(baselineEngagement.findings.find((finding) => finding.id === baselineFinding.id)?.baselineStatus).toBe("checkpoint");
    expect(baselineEngagement.findings.find((finding) => finding.id === baselineFinding.id)?.baselineReason).toContain("normalized location");
    expect(baselineEngagement.baseline?.counts.persistent).toBeGreaterThan(0);
    expect(baselineEngagement.baseline?.counts.resolved).toBe(0);

    // Require explicit incompatibility when strict provenance is absent.
    delete baseline.auditContext;
    writeFileSync(baselinePath, JSON.stringify(baseline));
    await run([
      join(scratch, "target"), "--assemble", bundle,
      "--findings-out", join(scratch, "incompatible-baseline-engagement.json"),
      "--baseline", baselinePath,
    ]);
    const incompatible = JSON.parse(readFileSync(join(scratch, "incompatible-baseline-engagement.json"), "utf8")) as FindingsDocument;
    expect(incompatible.baseline?.comparison?.kind).toBe("incompatible");
    expect(incompatible.baseline?.counts).toMatchObject({ resolved: 0, new: 0, persistent: 0 });
  }, CASE_TIMEOUT_MS);

  it("binds fresh exports and later comparisons while preserving the verified retained engagement identity", async () => {
    expect(engagement.auditContext?.kind).toBe("client-audit");
    expect(engagement.auditContext?.target.revision).toMatch(/^content:[a-f0-9]{64}$/);
    expect(engagement.auditContext?.provenance?.moduleObservations).toContainEqual(expect.objectContaining({ module: "M7", status: "examined", unitsExamined: expect.any(Number) }));
    expect(engagement.auditContext?.scopeComplete).toBe(false);
    expect(Object.keys(engagement.auditContext?.producerAssignments ?? {}).sort()).toEqual(engagement.auditContext?.assessedScope);
    expect(sarifOnly.runs[0]?.properties.harveyAuditContext?.target).toEqual(engagement.auditContext?.target);
    expect(sarifOnly.runs[0]?.properties.harveyAuditContext?.engagementId).not.toBe(engagement.auditContext?.engagementId);
    const meta = join(scratch, "forged-context-meta.json");
    writeFileSync(meta, JSON.stringify({ ...m1470Meta, auditContext: { ...engagement.auditContext, engagementId: "operator-forged", scopeComplete: true } }));
    const later = join(scratch, "fresh-later.json");
    await run([join(scratch, "target"), "--findings-out", later, "--baseline", join(scratch, "engagement.json"), "--meta", meta]);
    const current = JSON.parse(readFileSync(later, "utf8")) as FindingsDocument;
    expect(current.auditContext?.engagementId).not.toBe("operator-forged");
    expect(current.auditContext?.engagementId).not.toBe(engagement.auditContext?.engagementId);
    expect(current.auditContext?.target).toEqual(engagement.auditContext?.target);
    expect(current.baseline?.comparison?.kind).toBe("scope-change");
    expect(current.baseline?.comparison?.limitations.join(" ")).toContain("nested scanner");
    expect(current.baseline?.counts.new).toBe(0);
    expect(current.baseline?.counts.resolved).toBe(0);
    expect(current.baseline?.counts.persistent).toBeGreaterThan(0);
    const replay = join(scratch, "fresh-replay.json");
    await run([join(scratch, "target"), "--assemble", join(scratch, "fresh-bundle"), "--findings-out", replay, "--meta", meta, "--baseline", join(scratch, "engagement.json")]);
    const assembled = JSON.parse(readFileSync(replay, "utf8")) as FindingsDocument;
    expect(assembled.auditContext).toEqual(engagement.auditContext);
    expect(assembled.baseline?.comparison?.kind).toBe("same-run-checkpoint");
    expect(assembled.conservation?.ok).toBe(true);
    const evidence = assembled as FindingsDocument & { auditEvidence: { current: { rawArtifacts: { path: string; sourcePath?: string }[] }[] } };
    const raw = evidence.auditEvidence.current.flatMap((receipt) => receipt.rawArtifacts);
    expect(raw.some((artifact) => /M10-datamap.*invocation-/.test(artifact.sourcePath ?? ""))).toBe(true);
    const m4 = raw.find((artifact) => artifact.sourcePath?.endsWith("M4-owning-run.json"))!;
    const owner = JSON.parse(readFileSync(join(scratch, "fresh-bundle", m4.path), "utf8")) as { commandExecutionReceipts: { artifacts: { path: string }[] }[] };
    const paths = owner.commandExecutionReceipts.flatMap((receipt) => receipt.artifacts.map((artifact) => artifact.path));
    expect(paths.length).toBeGreaterThan(1);
    expect(new Set(paths).size).toBe(paths.length);
  }, CASE_TIMEOUT_MS);

  it("emits readiness from the same app inventory without changing M1-M10 execution", async () => {
    await run([
      join(scratch, "target"),
      "--findings-out", join(scratch, "readiness-engagement.json"),
      // Keep this inside the target: emitting the optional artifact must not perturb the scan that
      // is running beside it, even when downstream source discovery accepts JSON files.
      "--readiness-plan-out", join(scratch, "target", "readiness-plan.json"),
    ]);
    const readinessEngagement = JSON.parse(readFileSync(join(scratch, "readiness-engagement.json"), "utf8")) as FindingsDocument;
    const readinessPlan = JSON.parse(readFileSync(join(scratch, "target", "readiness-plan.json"), "utf8")) as ReadinessPlanV1;
    rmSync(join(scratch, "target", "readiness-plan.json"));
    expect(readinessPlan.schemaVersion).toBe(1);
    expect(readinessPlan.workspaceInventory.applicationWorkspaceIds).toEqual([
      "workspace:apps/api",
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
  }, CASE_TIMEOUT_MS);
});

describe("run-audit readiness continuity through real CLI children (#1897)", () => {
  let root: string, target: string, authority: string;
  let plan: ReadinessPlanV1;
  let baseline: FindingsDocument;
  let source: Awaited<ReturnType<typeof captureSourceSentinel>>;
  const approvedEnvNames = ["READINESS_MODE", "READINESS_TOKEN"];
  const environment = (mode: string) => ({ READINESS_MODE: mode, READINESS_TOKEN: "cli-readiness-secret-canary" });

  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), "harvey-readiness-cli-"));
    target = join(root, "source");
    const tools = join(root, "tools");
    mkdirSync(target); mkdirSync(tools);
    const scripts = { codegen: "node generator.cjs", build: "node builder.cjs", typecheck: "node checker.cjs", lint: "node linter.cjs", test: "node tester.cjs" };
    const pkg = { name: "readiness-cli", version: "1.0.0", private: true, packageManager: "npm@10.9.2", scripts };
    writeFileSync(join(target, "package.json"), JSON.stringify(pkg));
    writeFileSync(join(target, "package-lock.json"), JSON.stringify({ name: pkg.name, version: pkg.version, lockfileVersion: 3, packages: { "": pkg } }));
    writeFileSync(join(target, "application.ts"), "export const sourceCanary = 'unchanged';\n");
    for (const [kind, command] of Object.entries(scripts)) {
      writeFileSync(join(target, command.split(" ")[1]!), `const fs = require('node:fs');
fs.writeFileSync('${kind}.marker', process.cwd());
process.stdout.write('${kind} ' + process.env.READINESS_TOKEN + '\\n');
if (!process.env.READINESS_TOKEN) process.exitCode = 8;
if ('${kind}' === 'codegen' && process.env.READINESS_MODE === 'failed') process.exitCode = 7;
`);
    }
    const npm = join(tools, "npm");
    writeFileSync(npm, `#!${process.execPath}
const fs = require('node:fs');
const args = process.argv.slice(2);
if (args[0] === 'ci' || args[0] === 'install') { fs.writeFileSync('install.marker', process.cwd()); process.stdout.write('install complete\\n'); }
else {
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const file = pkg.scripts[args[1]].split(' ')[1];
  const result = require('node:child_process').spawnSync(process.execPath, [file], { stdio: 'inherit', env: process.env });
  process.exitCode = result.status === null ? 9 : result.status;
}
`);
    chmodSync(npm, 0o755);
    source = await captureSourceSentinel(target);
    plan = discoverReadinessPlan(target);
    const binding = bindReadinessPlanV1(plan, source);
    authority = join(root, "authority.json");
    writeFileSync(authority, JSON.stringify({
      schemaVersion: 1, planSha256: binding.planSha256, approvedEnvNames, toolchainPath: tools, timeoutMs: 5_000,
      stageAuthorizations: plan.stages.filter((stage) => stage.assessment === "planned").map((stage) => ({
        stageId: stage.id, effect: stage.kind === "install" ? "target-install" : "disposable-local",
        source: "reviewed CLI fixture", reason: "These commands write only disposable markers.",
        falsifier: "A command writes in the original source or reaches a service.",
      })),
    }));
  });
  afterAll(() => { if (root) rmSync(root, { recursive: true, force: true }); });

  it("retains the disabled audit's exact module population, findings and conservation", async () => {
    const out = join(root, "disabled.json");
    const result = await runCapturing([target, "--allow-target-install", "--findings-out", out], environment("success"));
    expect(result.code, result.out).toBe(0);
    baseline = JSON.parse(readFileSync(out, "utf8")) as FindingsDocument;
    expect(new Set(baseline.coverage?.map((row) => row.module))).toEqual(new Set(AUDIT_MODULES));
    expect(baseline.findings.length).toBeGreaterThan(0);
    expect(baseline.conservation?.ok).toBe(true);
    expect(await captureSourceSentinel(target)).toEqual(source);
  }, CASE_TIMEOUT_MS);

  it.each(["success", "failed"])("preserves every module after %s readiness and delivers bounded independent receipts", async (mode) => {
    const out = join(root, `${mode}-findings.json`);
    // Emitting into the source tests the production ordering as well as disposable isolation.
    const receiptPath = join(target, "readiness-execution.json");
    const planPath = join(target, "readiness-plan.json");
    const result = await runCapturing([target, "--allow-target-install", "--findings-out", out,
      "--readiness-plan-out", planPath, "--readiness-execute-out", receiptPath,
      "--readiness-authorizations", authority], environment(mode));
    const bytes = readFileSync(receiptPath, "utf8");
    const execution: ReadinessExecutionV1 = validateReadinessExecutionV1(
      createReadinessReceiptContext(plan, { approvedEnvNames, environment: environment(mode) }), JSON.parse(bytes),
    );
    const descriptorPath = `${receiptPath}.validation.json`;
    expect(parseReadinessArtifactsV1({ descriptorJson: readFileSync(descriptorPath, "utf8"), executionJson: bytes }).execution).toEqual(execution);
    expect(JSON.parse(readFileSync(planPath, "utf8"))).toEqual(plan);
    rmSync(receiptPath); rmSync(planPath); rmSync(descriptorPath);
    expect(result.code, result.out).toBe(mode === "success" ? 0 : 1);
    const engagement = JSON.parse(readFileSync(out, "utf8")) as FindingsDocument;
    expect(engagement.coverage).toEqual(baseline.coverage);
    expect(engagement.findings).toEqual(baseline.findings);
    expect(engagement.conservation).toEqual(baseline.conservation);
    expect(engagement.auditContext?.provenance?.moduleObservations).toEqual(baseline.auditContext?.provenance?.moduleObservations);
    expect(execution.stages.map((stage) => stage.stageId).sort()).toEqual(plan.stages.map((stage) => stage.id).sort());
    expect(execution.cleanup).toMatchObject({ status: "passed", removal: { status: "removed" }, source: { status: "passed" } });
    expect(bytes).not.toContain(environment(mode).READINESS_TOKEN);
    expect(await captureSourceSentinel(target)).toEqual(source);
    const row = (kind: string) => execution.stages.find((stage) => stage.kind === kind)!;
    expect(row("install"), JSON.stringify(row("install"))).toMatchObject({ status: "passed", execution: { kind: "process" } });
    expect(row("lint")).toMatchObject({ status: "passed", execution: { kind: "process" } });
    if (mode === "success") {
      expect(execution.status).toBe("passed");
      expect(execution.stages.every((stage) => stage.status === "passed")).toBe(true);
    } else {
      expect(execution.status).toBe("failed");
      expect(row("codegen")).toMatchObject({ status: "failed", execution: { kind: "process", process: { exit: { code: 7 }, close: { code: 7 } } } });
      for (const kind of ["build", "typecheck", "test"]) expect(row(kind)).toMatchObject({ status: "not-assessed", diagnostic: { reasonCode: "prerequisite-not-passed" } });
      expect(result.out).toContain("READINESS FAIL");
    }
  }, CASE_TIMEOUT_MS);

  it("withholds a secret-bearing raw plan even when every stage is denied and an old export exists", async () => {
    const canary = "plan-export-private-value-1897";
    const manifestPath = join(target, "package.json");
    const originalManifest = readFileSync(manifestPath, "utf8");
    const manifest = JSON.parse(originalManifest) as { scripts: Record<string, string> };
    manifest.scripts.build = `node -e 'console.log("${canary}")'`;
    writeFileSync(manifestPath, JSON.stringify(manifest));
    try {
      const before = await captureSourceSentinel(target);
      const deniedPlan = discoverReadinessPlan(target);
      const binding = bindReadinessPlanV1(deniedPlan, before);
      const deniedAuthority = join(root, "denied-authority.json");
      writeFileSync(deniedAuthority, JSON.stringify({ schemaVersion: 1, planSha256: binding.planSha256, approvedEnvNames: ["PROOF_TOKEN"], stageAuthorizations: [] }));
      const planPath = join(root, "withheld-plan.json");
      const receiptPath = join(root, "denied-execution.json");
      const findingsPath = join(root, "denied-findings.json");
      writeFileSync(planPath, "previous export must be preserved\n");
      const result = await runCapturing([target, "--findings-out", findingsPath,
        "--readiness-plan-out", planPath, "--readiness-execute-out", receiptPath,
        "--readiness-authorizations", deniedAuthority], { PROOF_TOKEN: canary });
      const executionJson = readFileSync(receiptPath, "utf8");
      const descriptorJson = readFileSync(`${receiptPath}.validation.json`, "utf8");
      const artifacts = parseReadinessArtifactsV1({ descriptorJson, executionJson }, { originalPlanSha256: binding.planSha256, sourceContentSha256: before.contentSha256 });
      expect(result.code, result.out).toBe(1);
      expect(result.out).toContain("READINESS PLAN EXPORT WITHHELD");
      expect(result.out).toContain("DELIVERY FAIL");
      expect(result.out).not.toContain(canary);
      expect(executionJson).not.toContain(canary);
      expect(descriptorJson).not.toContain(canary);
      expect(readFileSync(planPath, "utf8")).toBe("previous export must be preserved\n");
      expect(artifacts.execution.stages.every((stage) => stage.status === "not-assessed" && stage.execution.kind === "not-run")).toBe(true);
      const engagement = JSON.parse(readFileSync(findingsPath, "utf8")) as FindingsDocument;
      expect(new Set(engagement.coverage?.map((row) => row.module))).toEqual(new Set(AUDIT_MODULES));
      expect(engagement.conservation?.ok).toBe(true);
      expect(await captureSourceSentinel(target)).toEqual(before);
    } finally {
      writeFileSync(manifestPath, originalManifest);
    }
  }, CASE_TIMEOUT_MS);

  it("redacts an approved value from source/output paths when unsupported grant fields force a not-run disclosure", async () => {
    const canary = "cli-approved-path-canary-1897";
    const sourceAlias = join(root, canary);
    if (!existsSync(sourceAlias)) symlinkSync(target, sourceAlias);
    const invalidAuthority = join(root, "unsupported-authority.json");
    writeFileSync(invalidAuthority, JSON.stringify({
      schemaVersion: 1,
      planSha256: bindReadinessPlanV1(plan, source).planSha256,
      approvedEnvNames: ["READINESS_TOKEN"],
      stageAuthorizations: [],
      unsupportedOption: true,
    }));
    const outputDir = join(root, `outputs-${canary}`);
    mkdirSync(outputDir);
    const findingsPath = join(outputDir, "findings.json");
    const executionPath = join(outputDir, "execution.json");
    const result = await runCapturing([sourceAlias, "--findings-out", findingsPath,
      "--readiness-execute-out", executionPath, "--readiness-authorizations", invalidAuthority], {
      READINESS_TOKEN: canary,
    });
    expect(result.code, result.out).toBe(1);
    expect(result.out).not.toContain(canary);
    const executionJson = readFileSync(executionPath, "utf8");
    const descriptorJson = readFileSync(`${executionPath}.validation.json`, "utf8");
    const artifacts = parseReadinessArtifactsV1({ descriptorJson, executionJson });
    expect(artifacts.execution.stages.every((stage) => stage.status === "not-assessed" && stage.execution.kind === "not-run")).toBe(true);
    expect(artifacts.execution.stages.every((stage) => stage.environment.approvedNames.length === 0 && stage.environment.presentNames.length === 0)).toBe(true);
    expect(executionJson).not.toContain(canary);
    expect(descriptorJson).not.toContain(canary);
    const engagement = JSON.parse(readFileSync(findingsPath, "utf8")) as FindingsDocument;
    expect(new Set(engagement.coverage?.map((row) => row.module))).toEqual(new Set(AUDIT_MODULES));
    expect(engagement.conservation?.ok).toBe(true);
  }, CASE_TIMEOUT_MS);

  it("redacts an approved value from a readiness export write failure", async () => {
    const canary = "cli-write-error-canary-1897";
    const invalidAuthority = join(root, "write-error-authority.json");
    writeFileSync(invalidAuthority, JSON.stringify({
      schemaVersion: 1,
      planSha256: bindReadinessPlanV1(plan, source).planSha256,
      approvedEnvNames: ["READINESS_TOKEN"],
      stageAuthorizations: [],
      unsupportedOption: true,
    }));
    const findingsPath = join(root, "write-error-findings.json");
    const executionPath = join(root, `missing-${canary}`, "execution.json");
    const result = await runCapturing([target, "--findings-out", findingsPath,
      "--readiness-execute-out", executionPath, "--readiness-authorizations", invalidAuthority], {
      READINESS_TOKEN: canary,
    });
    expect(result.code, result.out).toBe(1);
    expect(result.out).not.toContain(canary);
    expect(result.out).toContain("--readiness-execute-out export failed at the public CLI boundary");
    expect(result.out).toContain("DELIVERY FAIL");
    const engagement = JSON.parse(readFileSync(findingsPath, "utf8")) as FindingsDocument;
    expect(new Set(engagement.coverage?.map((row) => row.module))).toEqual(new Set(AUDIT_MODULES));
    expect(engagement.conservation?.ok).toBe(true);
  }, CASE_TIMEOUT_MS);

  it("reads the authorization file once before discovery", async () => {
    const capturedAuthority = join(root, "single-capture-authority.json");
    writeFileSync(capturedAuthority, readFileSync(authority));
    const executionPath = join(root, "single-capture-execution.json");
    const running = startChild("node_modules/.bin/tsx", [CLI, target, "--allow-target-install",
      "--readiness-execute-out", executionPath, "--readiness-authorizations", capturedAuthority], environment("success"));
    await once(running.child.stdout, "data", { signal: AbortSignal.timeout(10_000) });
    writeFileSync(capturedAuthority, "{\"changedAfterCapture\":true}\n");
    const result = await running.completion;
    expect(result.code, result.out).toBe(0);
    expect(parseReadinessArtifactsV1({
      executionJson: readFileSync(executionPath, "utf8"),
      descriptorJson: readFileSync(`${executionPath}.validation.json`, "utf8"),
    }).execution.status).toBe("passed");
  }, CASE_TIMEOUT_MS);

  it("does not read unsafe authorization names or replace old files with an unproven safe artifact", async () => {
    const canary = "unsafe-name-value-must-remain-unread-1897";
    const unsafeAuthority = join(root, "unsafe-name-authority.json");
    writeFileSync(unsafeAuthority, JSON.stringify({
      schemaVersion: 1,
      planSha256: bindReadinessPlanV1(plan, source).planSha256,
      approvedEnvNames: ["unsafe_name"],
      stageAuthorizations: [],
    }));
    const executionPath = join(root, "unsafe-name-execution.json");
    const descriptorPath = `${executionPath}.validation.json`;
    writeFileSync(executionPath, "old execution\n");
    writeFileSync(descriptorPath, "old descriptor\n");
    const result = await runCapturing([target, "--readiness-execute-out", executionPath,
      "--readiness-authorizations", unsafeAuthority], { unsafe_name: canary });
    expect(result.code, result.out).toBe(1);
    expect(result.out).not.toContain(canary);
    expect(result.out).toContain("DELIVERY FAIL");
    expect(readFileSync(executionPath, "utf8")).toBe("old execution\n");
    expect(readFileSync(descriptorPath, "utf8")).toBe("old descriptor\n");
  }, CASE_TIMEOUT_MS);

  it("refuses aliased requested destinations before writing either artifact", async () => {
    const alias = join(root, "aliased-readiness.json");
    writeFileSync(alias, "old artifact must survive\n");
    const result = await runCapturing([target, "--readiness-plan-out", alias, "--readiness-execute-out", alias]);
    expect(result.code, result.out).toBe(2);
    expect(result.out).toMatch(/Requested artifact destinations.*alias/);
    expect(readFileSync(alias, "utf8")).toBe("old artifact must survive\n");
    expect(existsSync(`${alias}.validation.json`)).toBe(false);
  }, CASE_TIMEOUT_MS);

  it("does not let old execution files satisfy a run whose readiness producer emitted no current bytes", async () => {
    // Unix-domain socket paths are tightly bounded on macOS, so this one uses its own short root.
    const isolatedRoot = mkdtempSync(join(tmpdir(), "h1897-"));
    const isolated = join(isolatedRoot, "t");
    mkdirSync(isolated);
    writeFileSync(join(isolated, "package.json"), JSON.stringify({ name: "sentinel-refusal", private: true }));
    const socketPath = join(isolated, "unsupported.sock");
    const server = createServer();
    await new Promise<void>((resolveListen, reject) => {
      server.once("error", reject);
      server.listen(socketPath, resolveListen);
    });
    const executionPath = join(root, "stale-execution.json");
    const descriptorPath = `${executionPath}.validation.json`;
    writeFileSync(executionPath, "old execution\n");
    writeFileSync(descriptorPath, "old descriptor\n");
    try {
      const result = await runCapturing([isolated, "--readiness-execute-out", executionPath]);
      expect(result.code, result.out).toBe(1);
      expect(result.out).toContain("DELIVERY FAIL");
      expect(result.out).toContain("--readiness-execute-out");
      expect(readFileSync(executionPath, "utf8")).toBe("old execution\n");
      expect(readFileSync(descriptorPath, "utf8")).toBe("old descriptor\n");
      for (const module of AUDIT_MODULES) expect(result.out).toContain(module);
    } finally {
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
      rmSync(isolatedRoot, { recursive: true, force: true });
    }
  }, CASE_TIMEOUT_MS);
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
  }, CASE_TIMEOUT_MS);

  beforeAll(async () => {
    // The negative control: an assembled document that genuinely fails the report schema, via
    // a --meta the operator supplied with a non-string field. Without one, "the banner exists" is a
    // claim about a branch nobody has watched execute.
    writeFileSync(join(dupScratch, "bad-meta.json"), JSON.stringify({ ...m1470Meta, client: 42 }));
    refused = await runCapturing([target, "--meta", join(dupScratch, "bad-meta.json"), "--findings-out", join(dupScratch, "never.json"), "--sarif-out", join(dupScratch, "never.sarif")]);
  }, CASE_TIMEOUT_MS);

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
    expect(refused.out).toContain("LEDGER PASS");
    expect(refused.out).not.toContain("LEDGER FAIL");
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
