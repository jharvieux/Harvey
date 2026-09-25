import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { setImmediate } from "node:timers/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parse } from "yaml";
import { buildDryRunFamily, DETERMINISTIC_DRY_RUN_FILES, publishDryRunFamily } from "./dry-run-artifacts.js";
import { classifyDryRunChanges, compareDryRunFamilies, discoverDryRunDependencies } from "./dry-run-drift.js";
import type { Finding } from "./findings.js";

const ROOT = resolve(import.meta.dirname, "..");
const temporary: string[] = [];
const execFileAsync = promisify(execFile);
afterEach(async () => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
  await setImmediate();
});

describe("dry-run PR relevance", () => {
  it("discovers the real entrypoint's transitive imports, including the historically omitted producers", async () => {
    const closure = discoverDryRunDependencies(ROOT);
    expect(closure.unresolved.some((edge) => edge.includes("runtime inputs") || edge.includes("computed"))).toBe(true);
    for (const path of ["tools/pii-classify.mjs", "src/definer-classifier.ts", "src/grant-classifier.ts", "src/migration-sql-parse.ts", "src/cwe-map.ts", "src/dry-run-artifacts.ts"]) {
      expect(closure.files.has(path), path).toBe(true);
      expect(classifyDryRunChanges(ROOT, [path])).toMatchObject({ relevant: true, reason: "producer-dependency" });
      await setImmediate();
    }
  });

  it("selects literal executable/data inputs and fails closed on unknown paths", () => {
    expect(classifyDryRunChanges(ROOT, ["src/scan/rules/semgrep/auth.yml"])).toMatchObject({ relevant: true, reason: "producer-data" });
    expect(classifyDryRunChanges(ROOT, ["new-producer-shape.bin"])).toMatchObject({ relevant: true, reason: "unknown" });
  });

  it("selects regeneration when the discovered producer graph has an unresolved edge", () => {
    const repo = mkdtempSync(join(tmpdir(), "dry-run-unresolved-"));
    temporary.push(repo);
    mkdirSync(join(repo, "src/cli"), { recursive: true });
    writeFileSync(join(repo, "src/cli/dry-run.ts"), 'import "../missing-producer.js";\n');
    const result = classifyDryRunChanges(repo, ["docs/runbooks/example.md"]);
    expect(result).toMatchObject({ relevant: true, reason: "unknown" });
    expect(result.unresolved).toEqual(["src/cli/dry-run.ts -> ../missing-producer.js"]);
  });

  it("preserves a proved unrelated documentation no-op", async () => {
    const result = await runShippingFilter("export {};\n", "docs/input.md");
    expect(result.output).toContain("relevant=false\n");
    expect(result.output).toContain("reason=proved-unrelated-docs\n");
  });

  it.each([
    'import { readFileSync } from "node:fs"; console.log(readFileSync("docs/input.md", "utf8"));',
    'import { readFileSync } from "node:fs"; console.log(readFileSync("tools/input-link.md", "utf8"));',
    'import { readFileSync as read } from "node:fs"; const input = "docs/input.md"; console.log(read(input, "utf8"));',
    'import { readFileSync } from "node:fs"; const read = readFileSync; console.log(read("docs/input.md", "utf8"));',
    'import * as fs from "node:fs"; const read = fs.readFileSync.bind(fs); console.log(read("docs/input.md", "utf8"));',
    'const fs = await import("node:fs"); const method = "readFileSync"; console.log(fs[method]("docs/input.md", "utf8"));',
    'const module = process.env.PRODUCER; await import(module);',
    'import { execFileSync as launch } from "node:child_process"; console.log(launch(process.execPath, ["tools/producer.mjs"], { encoding: "utf8" }));',
  ])("executes the shipping selector for data input %s", async (source) => {
    const result = await runShippingFilter(source, "docs/input.md", true);
    expect(result.before?.trim(), source).toBe("before");
    expect(result.after?.trim(), source).toBe("after");
    expect(result.output, source).toContain("relevant=true\n");
  });

  it("does not certify operating docs when the current producer has unresolved runtime inputs", () => {
    const decision = classifyDryRunChanges(ROOT, ["docs/runbooks/example.md"]);
    expect(decision).toMatchObject({ relevant: true, reason: "unknown" });
    expect(decision.unresolved.length).toBeGreaterThan(0);
  });

  it("tracks a literal directory read across a newly added documentation member", async () => {
    const result = await runShippingFilter('import { readdirSync } from "node:fs"; console.log(readdirSync("docs").sort().join(","));', "docs/new.md", true);
    expect(result.before?.trim()).toBe("input.md");
    expect(result.after?.trim()).toBe("input.md,new.md");
    expect(result.output).toContain("relevant=true\n");
  });

  it.each(["statSync", "lstatSync"])("regenerates for filesystem metadata from %s", async (api) => {
    const result = await runShippingFilter(`import { ${api} as inspect } from "node:fs"; console.log(inspect("docs/input.md").size);`, "docs/input.md", true);
    expect(result.before?.trim()).toBe("7");
    expect(result.after?.trim()).toBe("6");
    expect(result.output, api).toContain("relevant=true\n");
  });

  it.each([
    'import { existsSync as present } from "node:fs"; console.log(present("docs/new.md"));',
    'import * as fs from "node:fs"; console.log(fs.existsSync("docs/new.md"));',
    'import * as fs from "node:fs"; console.log(fs["existsSync"]("docs/new.md"));',
  ])("regenerates for filesystem existence input %s", async (source) => {
    const result = await runShippingFilter(source, "docs/new.md", true);
    expect(result.before?.trim()).toBe("false");
    expect(result.after?.trim()).toBe("true");
    expect(result.output).toContain("relevant=true\n");
  });

  it("executes the shipping selector for known producer and unknown-path changes", async () => {
    let workerYielded = false;
    const heartbeat = setImmediate().then(() => { workerYielded = true; });
    expect((await runShippingFilter('import "../producer.ts";', "src/producer.ts")).output).toContain("relevant=true\n");
    expect(workerYielded, "shipping child execution must service the worker event loop").toBe(true);
    await heartbeat;
    expect((await runShippingFilter("export {};", "unclassified.bin")).output).toContain("relevant=true\n");
  });
});

async function runShippingFilter(source: string, changed: string, executeProducer = false): Promise<{ output: string; before?: string; after?: string }> {
  const repo = mkdtempSync(join(tmpdir(), "dry-run-shipping-filter-"));
  temporary.push(repo);
  for (const directory of ["src/cli", "tools", "docs", "bin"]) mkdirSync(join(repo, directory), { recursive: true });
  writeFileSync(join(repo, "package.json"), '{"type":"module"}');
  writeFileSync(join(repo, "src/cli/dry-run.ts"), source);
  writeFileSync(join(repo, "src/producer.ts"), "export {};\n");
  writeFileSync(join(repo, "tools/producer.mjs"), 'import { readFileSync } from "node:fs"; console.log(readFileSync("docs/input.md", "utf8"));');
  writeFileSync(join(repo, "docs/input.md"), "before\n");
  symlinkSync("../docs/input.md", join(repo, "tools/input-link.md"));
  writeFileSync(join(repo, "unclassified.bin"), "before\n");
  const git = async (args: string[]): Promise<string> => (await execFileAsync("git", args, { cwd: repo, encoding: "utf8" })).stdout.trim();
  for (const args of [["init", "-q"], ["config", "user.email", "fixture@example.test"], ["config", "user.name", "Fixture"], ["add", "."], ["commit", "-qm", "base"]]) await git(args);
  const base = await git(["rev-parse", "HEAD"]);
  const loader = join(ROOT, "node_modules/tsx/dist/loader.mjs");
  const producer = async (): Promise<string> => (await execFileAsync(process.execPath, ["--import", loader, join(repo, "src/cli/dry-run.ts")], {
    cwd: repo, encoding: "utf8", env: { ...process.env, PRODUCER: join(repo, "tools/producer.mjs") },
  })).stdout;
  const before = executeProducer ? await producer() : undefined;
  writeFileSync(join(repo, changed), changed.endsWith(".ts") ? "export const changed = true;\n" : "after\n");
  await git(["add", "."]); await git(["commit", "-qm", "change"]);
  const after = executeProducer ? await producer() : undefined;
  const workflow = parse(readFileSync(join(ROOT, ".github/workflows/dry-run-drift.yml"), "utf8")) as { jobs: { drift: { steps: { id?: string; run?: string }[] } } };
  const script = workflow.jobs.drift.steps.find((step) => step.id === "filter")?.run;
  if (!script) throw new Error("Shipping dry-run filter step is missing");
  const outputs = join(repo, "outputs");
  writeFileSync(outputs, "");
  writeFileSync(join(repo, "bin/pnpm"), '#!/bin/sh\nset -eu\n[ "$1" = exec ] && [ "$2" = tsx ] && [ "$3" = src/cli/dry-run-drift.ts ]\nshift 3\nexec "$HARVEY_FILTER_NODE" --import "$HARVEY_FILTER_LOADER" "$HARVEY_FILTER_CLI" "$@"\n', { mode: 0o755 });
  await execFileAsync("bash", ["-e", "-o", "pipefail", "-c", script.replaceAll("${{ github.event_name }}", "pull_request").replaceAll("${{ github.event.pull_request.base.sha }}", base)], {
    cwd: repo, encoding: "utf8", env: {
      ...process.env, PATH: `${join(repo, "bin")}:${process.env.PATH}`, GITHUB_OUTPUT: outputs,
      HARVEY_FILTER_NODE: process.execPath, HARVEY_FILTER_LOADER: loader, HARVEY_FILTER_CLI: join(ROOT, "src/cli/dry-run-drift.ts"),
    },
  });
  return { output: readFileSync(outputs, "utf8"), before, after };
}

function family(dir: string, id = "F-1"): void {
  const findings: Finding[] = [{ id, title: "finding", severity: "Low", confidence: "Confirmed", category: "test", taxonomy: "M1-TEST", location: "a.ts:1", evidence: "e", status: "Open", impact: "impact", fix: "f", value: 3, ease: 3, safety: 3 }];
  publishDryRunFamily(dir, buildDryRunFamily(findings, { public: ["email"] }, { target: "targets/calibration", targetTree: "a".repeat(40) }), [{ phase: "test", ms: Math.random() }]);
}

describe("complete deterministic dry-run family comparison", () => {
  it("derives membership from the owning contract and excludes timing observations", () => {
    const left = mkdtempSync(join(tmpdir(), "dry-run-left-"));
    const right = mkdtempSync(join(tmpdir(), "dry-run-right-"));
    temporary.push(left, right);
    family(left); family(right);
    const result = compareDryRunFamilies(left, right);
    expect(result.ok).toBe(true);
    expect(result.members).toBe(DETERMINISTIC_DRY_RUN_FILES);
    expect(result.members).not.toContain("timing.json");
    expect(readFileSync(join(left, "timing.json"), "utf8")).not.toBe(readFileSync(join(right, "timing.json"), "utf8"));
  });

  it("fails on derived-only drift even when raw findings and PII are unchanged", () => {
    const committed = mkdtempSync(join(tmpdir(), "dry-run-committed-"));
    const fresh = mkdtempSync(join(tmpdir(), "dry-run-fresh-"));
    temporary.push(committed, fresh);
    family(committed); family(fresh);
    const reportPath = join(fresh, "findings-report.json");
    const report = JSON.parse(readFileSync(reportPath, "utf8")) as { findings: unknown[] };
    report.findings = [];
    writeFileSync(reportPath, JSON.stringify(report));
    const result = compareDryRunFamilies(committed, fresh);
    expect(result.ok).toBe(false);
    expect(result.differences.join("\n")).toContain("fresh family violates its semantic/provenance contract");
    expect(result.differences).toContain("findings-report.json differs");
  });
});
