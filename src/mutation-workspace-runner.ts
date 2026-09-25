import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { readEntriesSafe } from "./fs-walk.js";
import { copyFilteredSourceTree } from "./source-copy.js";
import { mutationWorkspaceFinding, type MutationWorkspace, type MutationWorkspacePlan } from "./mutation-workspace.js";
import { detectDryRunFailure, detectTestEnv, noTestSuiteFinding, summarizeMutationReport, toReportRows, type StrykerReport } from "./mutation-scan.js";
import { createCommandExecutionReceipt, type CommandExecutionReceipt } from "./producer-execution-receipt.js";
import type { Finding } from "./findings.js";

type State = "complete" | "bounded" | "no-production" | "no-tests" | "discovery-failed" | "dry-run-failed" | "unsupported-runner" | "missing-report" | "not-selected" | "runner-invalid";
interface WorkspaceResult {
  id: string;
  state: State;
  reason: string;
  relatedTests: string[];
  projects: string[];
  testCount: number;
  reportedSources: string[];
  unassessedSources: string[];
  receipts: CommandExecutionReceipt[];
  artifactPath?: string;
  artifact?: Record<string, unknown>;
}

const posix = (path: string): string => path.split(sep).join("/");
const inside = (root: string, path: string): boolean => {
  const rel = relative(root, path);
  return rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`));
};
const excludedCopy = (path: string): boolean => path.split("/").some(part => part === ".git" || part === "node_modules");

function assertCopiedInputs(plan: MutationWorkspacePlan, copy: string): void {
  for (const file of plan.files) {
    const path = join(copy, file.path);
    if (!existsSync(path) || createHash("sha256").update(readFileSync(path)).digest("hex") !== file.sha256) throw new Error(`Native test execution changed a planned source/configuration input: ${file.path}`);
  }
}

// Rebase first-party links against the whole repository, including links from sibling packages.
function dependencies(root: string, copy: string, directories: string[]): void {
  for (const directory of directories) {
    const source = join(root, directory, "node_modules");
    const dest = join(copy, directory, "node_modules");
    if (!existsSync(source)) continue;
    mkdirSync(dest, { recursive: true });
    const mirror = (part: string): void => {
      const input = join(source, part), output = join(dest, part);
      if (/^\.(?:cache|vite|vite-temp)$/.test(basename(part))) return;
      if (lstatSync(input).isDirectory() && part.startsWith("@") && !part.includes("/")) {
        mkdirSync(output, { recursive: true });
        const scoped = readEntriesSafe(input);
        if (scoped.dangling.length) throw new Error(`Unresolved installed dependency links: ${directory}/${part}: ${scoped.dangling.join(", ")}`);
        for (const child of scoped.entries) mirror(`${part}/${child.name}`);
        return;
      }
      const physical = realpathSync(input);
      const rel = relative(root, physical);
      const workspace = inside(root, physical) && !rel.split(sep).includes("node_modules");
      const target = workspace ? join(copy, rel) : physical;
      if (workspace && !existsSync(target)) throw new Error(`Workspace dependency source missing from isolated copy: ${rel}`);
      symlinkSync(target, output, lstatSync(physical).isDirectory() ? "dir" : "file");
    };
    const entries = readEntriesSafe(source);
    if (entries.dangling.length) throw new Error(`Unresolved installed dependency links: ${directory}: ${entries.dangling.join(", ")}`);
    for (const entry of entries.entries) mirror(entry.name);
  }
}

function packageInfo(cwd: string, name: string): { version: string; directory?: string } {
  try {
    const require = createRequire(join(cwd, "package.json"));
    let path: string;
    try { path = require.resolve(`${name}/package.json`); }
    catch { path = join(dirname(require.resolve(name)), "..", "package.json"); }
    const value = JSON.parse(readFileSync(path, "utf8")) as { version: string };
    return { version: value.version, directory: dirname(path) };
  } catch { return { version: "unavailable" }; }
}

function command(bin: string, argv: string[], cwd: string, output: string, plan: MutationWorkspacePlan, workspace: MutationWorkspace, toolchain: CommandExecutionReceipt["toolchain"], report?: string): { receipt: CommandExecutionReceipt; stdout: string; stderr: string; exit: number | null } {
  const startedAt = new Date().toISOString();
  const declared = detectTestEnv(plan.files.filter(file => /(?:package\.json|(?:vitest|jest)\.(?:config|setup)\.[cm]?[jt]s|\.github\/workflows\/[^/]+\.ya?ml)$/.test(file.path)).map(file => ({ path: file.path, text: readFileSync(join(plan.root, file.path), "utf8") })));
  const result = spawnSync(bin, argv, { cwd, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, env: { ...process.env, ...Object.fromEntries(declared.map(row => [row.key, row.value])), CI: "true" } });
  const stdout = result.stdout ?? "", stderr = result.stderr ?? "";
  const errorCode = (result.error as NodeJS.ErrnoException | undefined)?.code;
  writeFileSync(`${output}.stdout`, stdout); writeFileSync(`${output}.stderr`, stderr);
  const receipt = createCommandExecutionReceipt({
    invocationId: randomUUID(), command: { executable: bin, argv, cwd },
    target: { identity: `${plan.root}#${workspace.id}`, value: { sourceSha256: plan.sourceSha256, sources: workspace.selectedSources } },
    configuration: { identity: workspace.id, value: workspace }, toolchain,
    startedAt, finishedAt: new Date().toISOString(), stdout, stderr,
    outcome: errorCode === "ENOBUFS"
      ? { state: "output-limit-exceeded", exitCode: null, signal: result.signal, errorCode }
      : errorCode === "ETIMEDOUT"
        ? { state: "timed-out", exitCode: null, signal: result.signal, errorCode }
        : result.error
          ? { state: "spawn-failed", exitCode: null, signal: result.signal, ...(errorCode ? { errorCode } : {}) }
          : { state: result.signal ? "signaled" : "exited", exitCode: result.status, signal: result.signal },
    ...(errorCode === "ENOBUFS" ? {
      outputCompleteness: stdout && !stderr
        ? { stdout: "truncated" as const, stderr: "unknown" as const }
        : stderr && !stdout
          ? { stdout: "unknown" as const, stderr: "truncated" as const }
          : { stdout: "unknown" as const, stderr: "unknown" as const },
    } : {}),
    artifacts: [{ role: "stdout", path: `${output}.stdout` }, { role: "stderr", path: `${output}.stderr` }, ...(report ? [{ role: "report" as const, path: report }] : [])],
  });
  writeFileSync(`${output}.receipt.json`, JSON.stringify(receipt, null, 2) + "\n");
  return { receipt, stdout, stderr, exit: result.status };
}

function parseJson(path: string): Record<string, unknown> | undefined {
  try { const value: unknown = JSON.parse(readFileSync(path, "utf8")); return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined; } catch { return undefined; }
}

// Resolve the generated wrapper's roots and imports within Stryker's sandbox.
function vitestConfig(copy: string, workspace: MutationWorkspace): string {
  const cwd = join(copy, workspace.invocationDirectory);
  const path = join(cwd, `.harvey-workspace-${randomUUID()}.config.ts`);
  const configPath = workspace.runnerConfig ? join(copy, workspace.runnerConfig) : undefined;
  if (configPath && (!inside(copy, configPath) || !existsSync(configPath))) throw new Error(`Runner configuration is missing or outside the copied repository: ${workspace.runnerConfig}`);
  const imported = configPath ? `import original from ${JSON.stringify(`./${posix(relative(cwd, configPath))}`)};` : "const original = {};";
  const sources = workspace.selectedSources.map(source => `./${posix(relative(cwd, join(copy, source)))}`);
  const invocation = posix(relative(cwd, join(copy, workspace.configurationDirectory)));
  const runnerOptions = workspace.configuration.vitest as { dir?: unknown } | undefined;
  if (runnerOptions?.dir !== undefined && typeof runnerOptions.dir !== "string") throw new Error("Vitest dir must be a statically declared directory string");
  writeFileSync(path, `${imported}\nimport { resolve, relative, isAbsolute, sep } from 'node:path';\nimport { writeFileSync } from 'node:fs';\nexport default async env => {\n const config = await (typeof original === 'function' ? original(env) : original);\n const originalCwd = resolve(__dirname, ${JSON.stringify(invocation)});\n const repository = resolve(__dirname, ${JSON.stringify(posix(relative(cwd, copy)))});\n if (config.root !== undefined && typeof config.root !== 'string') throw new Error('Vitest root must resolve to a directory string');\n const root = config.root === undefined ? originalCwd : resolve(originalCwd, config.root);\n const directory = ${JSON.stringify(runnerOptions?.dir)} ?? config.test?.dir;\n if (directory !== undefined && typeof directory !== 'string') throw new Error('Vitest dir must resolve to a directory string');\n const dir = directory === undefined ? root : resolve(originalCwd, directory);\n for (const value of [root, dir]) { const part = relative(repository, value); if (isAbsolute(part) || part === '..' || part.startsWith('..' + sep)) throw new Error('Vitest root/dir resolves outside the isolated repository'); }\n writeFileSync(resolve(__dirname, ${JSON.stringify(`${basename(path)}.native.json`)}), JSON.stringify({ root, dir }));\n return {...config, root, test: {...config.test, dir, related: ${JSON.stringify(sources)}.map(path => resolve(__dirname, path)), passWithNoTests: false, coverage: {...config.test?.coverage, enabled: false}}};\n};\n`);
  return path;
}

function execute(plan: MutationWorkspacePlan, workspace: MutationWorkspace, storage: string, cliPath: string, flags: string[]): WorkspaceResult {
  const result: WorkspaceResult = { id: workspace.id, state: "discovery-failed", reason: "Workspace execution did not complete", relatedTests: [], projects: [], testCount: 0, reportedSources: [], unassessedSources: [...new Set([...workspace.productionSources, ...workspace.configuredSources])], receipts: [] };
  const stop = (state: State, reason: string): WorkspaceResult => ({ ...result, state, reason });
  if (workspace.gaps.length) return stop("discovery-failed", workspace.gaps.join("; "));
  if (result.unassessedSources.length === 0) return stop("no-production", "No executable production sources assigned to this package");
  if (workspace.selectedSources.length === 0) return stop("not-selected", "The bounded production selection omits this workspace; its complete population remains unassessed");
  if (!["vitest", "jest", "mocha"].includes(workspace.runner)) return stop("unsupported-runner", `Runner ${workspace.runner} has no supported Stryker adapter. Fallback: source test-intent review or an explicitly configured supported runner; ${workspace.candidateTests.length} candidate test files remain unassessed`);
  if (workspace.candidateTests.length === 0 && !workspace.runnerConfig) return stop("no-tests", "No candidate tests were discovered for the production population");
  mkdirSync(storage, { recursive: true });
  const copy = join(storage, "source"); mkdirSync(copy);
  try {
    copyFilteredSourceTree(plan.root, copy, path => !excludedCopy(path));
    dependencies(plan.root, copy, plan.inventory.packages.map(pkg => pkg.dir));
    const cwd = join(copy, workspace.invocationDirectory);
    const versions = [workspace.runner, "@stryker-mutator/core", `@stryker-mutator/${workspace.runner}-runner`, "typescript"].map(name => {
      const local = packageInfo(join(copy, workspace.directory), name);
      return { name, ...(local.directory ? local : packageInfo(cwd, name)) };
    });
    versions.push({ name: "node", version: process.version });
    // Make each selected package's installed tooling reachable from the repository execution root.
    for (const tool of versions.filter(row => row.name.startsWith("@stryker-mutator/") && row.directory)) {
      const local = join(cwd, "node_modules", tool.name);
      if (existsSync(local)) continue;
      mkdirSync(dirname(local), { recursive: true });
      if (!inside(copy, realpathSync(dirname(local)))) throw new Error("Tool dependency destination leaves the isolated copy");
      symlinkSync(tool.directory!, local, "dir");
    }
    const config = structuredClone(workspace.configuration);
    config.mutate = workspace.selectedSources.map(path => posix(relative(cwd, join(copy, path))));
    config.inPlace = false;
    let nativeConfig: string | undefined;
    if (workspace.runner === "vitest") {
      nativeConfig = vitestConfig(copy, workspace);
      writeFileSync(join(storage, "effective-vitest.ts.txt"), readFileSync(nativeConfig));
      config.vitest = { ...(config.vitest as object ?? {}), configFile: posix(relative(cwd, nativeConfig)), related: true };
      const vitest = versions.find(row => row.name === "vitest")!;
      if (!vitest.directory) return stop("discovery-failed", "Vitest is not installed in the workspace or its ancestors; native related-test discovery did not run");
      const bin = join(vitest.directory, "vitest.mjs");
      const discoveryFile = join(storage, "related-tests.json");
      const discovery = command(process.execPath, [bin, "list", "--config", nativeConfig, `--json=${discoveryFile}`], cwd, join(storage, "discovery"), plan, workspace, versions, discoveryFile);
      result.receipts.push(discovery.receipt);
      assertCopiedInputs(plan, copy);
      let rows: Array<{ file?: string; name?: string; projectName?: string }>;
      try { const parsed: unknown = JSON.parse(readFileSync(discoveryFile, "utf8")); if (!Array.isArray(parsed)) throw new Error("not an array"); rows = parsed; }
      catch { return stop("discovery-failed", `Native related-test discovery produced no readable population (exit ${discovery.exit}); inspect discovery receipt`); }
      if (discovery.exit !== 0) return stop("discovery-failed", `Native related-test discovery failed (exit ${discovery.exit}); ${rows.length} discovered test cases are not a completed measurement`);
      // Native evaluation owns root/dir semantics, including portable import.meta expressions.
      const observedConfigPath = `${nativeConfig}.native.json`;
      const observedConfig = parseJson(observedConfigPath);
      if (typeof observedConfig?.root !== "string" || typeof observedConfig.dir !== "string" || !inside(copy, observedConfig.root) || !inside(copy, observedConfig.dir)) return stop("discovery-failed", "Native Vitest root/dir did not resolve inside the isolated repository");
      (config.vitest as { dir?: string }).dir = posix(relative(cwd, observedConfig.dir)) || ".";
      writeFileSync(join(storage, "native-vitest-directories.json"), JSON.stringify(observedConfig, null, 2) + "\n");
      result.relatedTests = [...new Set(rows.flatMap(row => typeof row.file === "string" ? [posix(relative(copy, row.file))] : []))].sort();
      result.projects = [...new Set(rows.flatMap(row => typeof row.projectName === "string" ? [row.projectName] : []))].sort();
      if (rows.length === 0 || result.relatedTests.length === 0) return stop(workspace.candidateTests.length === 0 ? "no-tests" : "discovery-failed", `Native runner found zero related tests for ${workspace.selectedSources.length} selected production files; ${workspace.candidateTests.length === 0 ? "no candidate test files exist for this configuration" : "this is incomplete discovery, not proof of a missing suite"}`);
      if (result.relatedTests.some(path => !inside(copy, resolve(copy, path)))) return stop("discovery-failed", "Related tests resolved outside the isolated repository");
      const baselineFile = join(storage, "baseline.json");
      const baseline = command(process.execPath, [bin, "related", "--run", "--config", nativeConfig, "--reporter=json", "--outputFile", baselineFile, ...workspace.selectedSources.map(path => join(copy, path))], cwd, join(storage, "baseline"), plan, workspace, versions, baselineFile);
      result.receipts.push(baseline.receipt);
      assertCopiedInputs(plan, copy);
      if (JSON.stringify(parseJson(observedConfigPath)) !== JSON.stringify(observedConfig)) return stop("discovery-failed", "Native Vitest root/dir changed between discovery and baseline; no mutation score is certified");
      const baselineReport = parseJson(baselineFile);
      result.testCount = typeof baselineReport?.numPassedTests === "number" ? baselineReport.numPassedTests : 0;
      if (baseline.exit !== 0 || result.testCount === 0 || baselineReport?.success !== true) return stop("dry-run-failed", `Native unmutated related-test baseline failed or completed zero tests (exit ${baseline.exit}, passed ${result.testCount}); no mutation score is certified`);
    }
    const configPath = join(storage, "effective-stryker.json");
    writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
    const artifactPath = join(storage, "mutation.json");
    const run = command(process.execPath, ["--import", createRequire(import.meta.url).resolve("tsx"), cliPath, cwd, "--single-workspace", "--config", configPath, "--out", artifactPath, ...flags], cwd, join(storage, "mutation"), plan, workspace, versions, artifactPath);
    result.receipts.push(run.receipt);
    result.artifactPath = artifactPath;
    const artifact = parseJson(artifactPath); result.artifact = artifact;
    if (!artifact) return stop("missing-report", `Mutation child produced no readable machine report (exit ${run.exit}); original command receipt remains retained`);
    const raw = artifact.rawReport as StrykerReport | undefined;
    if (!raw?.files) {
      const note = (artifact.moduleRecord as { note?: string } | undefined)?.note ?? "No Stryker JSON report was produced";
      const diagnostic = `${run.stdout}\n${run.stderr}`;
      return stop(/No tests were (?:found|executed)|failed to find test files related/i.test(diagnostic) ? "discovery-failed" : (artifact.finding as Finding | undefined)?.id === "M8-03" || detectDryRunFailure(diagnostic).failed ? "dry-run-failed" : "missing-report", note);
    }
    const observedTests = Object.keys(raw.testFiles ?? {});
    if (observedTests.length === 0) return stop("discovery-failed", "Stryker produced a report but reported zero related test files");
    const normalized = (path: string): string => posix(join(workspace.invocationDirectory, path));
    if (workspace.runner !== "vitest") {
      result.relatedTests = observedTests.map(normalized);
      result.testCount = Object.values(raw.testFiles ?? {}).reduce((count, file) => count + file.tests.length, 0);
    }
    result.reportedSources = Object.keys(raw.files).map(normalized).filter(path => workspace.selectedSources.includes(path));
    const missingTests = result.relatedTests.filter(path => !observedTests.map(normalized).includes(path));
    if (missingTests.length) return stop("discovery-failed", `Stryker omitted native related test files: ${missingTests.join(", ")}`);
    const extraTests = observedTests.map(normalized).filter(path => !result.relatedTests.includes(path));
    if (extraTests.length) return stop("discovery-failed", `Stryker executed test files outside native related discovery: ${extraTests.join(", ")}; the runner configuration populations are not equivalent`);
    const reason = (artifact.moduleRecord as { note?: string } | undefined)?.note;
    if (reason) return stop("runner-invalid", reason);
    if (workspace.runner !== "vitest") return stop("runner-invalid", "Stryker executed the supported runner and retained its test/report population; independent native related-test baseline verification is supported for Vitest only. Other runner populations remain explicitly unverified");
    if (run.exit !== 0) return stop("runner-invalid", `Mutation child exited ${run.exit}; retained report is partial`);
    result.unassessedSources = result.unassessedSources.filter(path => !result.reportedSources.includes(path));
    return stop(result.unassessedSources.length ? "bounded" : "complete", `${result.reportedSources.length} production files reported; ${result.relatedTests.length || observedTests.length} related test files; ${result.unassessedSources.length} production files remain unassessed`);
  } catch (error) { return stop("discovery-failed", error instanceof Error ? error.message : String(error)); }
  finally { rmSync(copy, { recursive: true, force: true }); }
}

export function runMutationWorkspaces(plan: MutationWorkspacePlan, options: { storage: string; cliPath: string; flags?: string[]; planOnly?: boolean }): Record<string, unknown> {
  const results: WorkspaceResult[] = [];
  const findings: Finding[] = [];
  const combined: StrykerReport = { files: {}, testFiles: {} };
  for (const workspace of plan.workspaces) {
    const key = createHash("sha256").update(workspace.id).digest("hex").slice(0, 12);
    const result = options.planOnly
      ? { id: workspace.id, state: "not-selected" as const, reason: "Plan-only invocation; native discovery and mutation execution have not run", relatedTests: [], projects: [], testCount: 0, reportedSources: [], unassessedSources: workspace.productionSources, receipts: [] }
      : execute(plan, workspace, join(options.storage, key), options.cliPath, options.flags ?? []);
    results.push(result);
    const raw = result.artifact?.effectiveReport as StrykerReport | undefined;
    const label = plan.workspaces.filter(row => row.directory === workspace.directory).length > 1 ? `[${workspace.id}]/` : "";
    if (raw?.files && (result.state === "complete" || result.state === "bounded")) {
      for (const [path, row] of Object.entries(raw.files)) combined.files[`${label}${posix(join(workspace.invocationDirectory, path))}`] = row;
    }
    const childFindings = (result.artifact?.findings as Finding[] | undefined) ?? [];
    const singular = result.artifact?.finding as Finding | undefined;
    for (const finding of singular && !childFindings.some(row => row.id === singular.id) ? [...childFindings, singular] : childFindings) {
      findings.push({ ...finding, id: `${finding.id}-${key}`, location: finding.location ? posix(join(workspace.invocationDirectory, finding.location)) : workspace.manifest });
    }
    if (result.state === "no-tests") findings.push({ ...noTestSuiteFinding(`${workspace.directory}: ${result.reason}`), id: `M8-00-${key}`, location: workspace.manifest });
    if (result.state !== "complete" && result.state !== "no-production") findings.push(mutationWorkspaceFinding(workspace, result.state, `${result.reason} Related tests: ${result.relatedTests.join(", ") || "not established"}.`));
  }
  const missing = plan.workspaces.filter(workspace => !results.some(result => result.id === workspace.id));
  const incomplete = plan.gaps.length > 0 || missing.length > 0 || results.some(result => !["complete", "no-production"].includes(result.state));
  const summary = summarizeMutationReport(combined);
  return {
    schemaVersion: 1, mutationWorkspacePlan: plan, workspaces: results, findings,
    ...(Object.keys(combined.files).length ? { summary, reportRows: toReportRows(summary) } : {}),
    workspaceCoverage: { complete: !incomplete, planned: plan.workspaces.length, observed: results.length, missing: missing.map(row => row.id), production: [...new Set(plan.workspaces.flatMap(row => [...row.productionSources, ...row.configuredSources]))].length, reported: new Set(results.flatMap(result => result.reportedSources)).size },
    ...(incomplete ? { moduleRecord: { status: "partial", note: `Workspace mutation coverage is incomplete. ${plan.gaps.join("; ")} ${missing.map(row => `${row.id}: missing execution`).join("; ")} ${results.filter(row => !["complete", "no-production"].includes(row.state)).map(row => `${row.id}: ${row.state}: ${row.reason}`).join("; ")}` } } : {}),
    rawReports: results.flatMap(result => result.artifact?.rawReport ? [{ workspace: result.id, report: result.artifact.rawReport }] : []),
  };
}

/** Allocation belongs to the caller's already-validated off-target storage prefix. */
export function allocateMutationWorkspaceStorage(prefix: string): string { return realpathSync(mkdtempSync(prefix)); }
