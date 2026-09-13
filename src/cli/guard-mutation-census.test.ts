import { execFileSync, spawn } from "node:child_process";
import { chmodSync, copyFileSync, cpSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { guardMutationDigest, guardMutationReviewRequirements, normalizeGuardMutationCensus, type GuardMutationBaseline, type GuardMutationReceipt } from "../guard-mutation-baseline.js";
import type { StrykerMutant } from "../mutation-scan.js";
import { GUARD_SET } from "../guard-mutation-census.js";
import { writeGuardJson, type GuardShardManifest, type GuardShardTerminal } from "../guard-mutation-bundle.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(ROOT, "src", "cli", "guard-mutation-census.ts");
const FIXTURES = join(ROOT, "src", "__fixtures__", "guard-mutation");
const dirs: string[] = [];
type Report = { files: Record<string, { source: string; mutants: StrykerMutant[] }> };

afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function prepare(name = "measured.json", change?: (r: Report, receipt: GuardMutationReceipt) => void) {
  const dir = mkdtempSync(join(tmpdir(), "harvey-guard-cmp-")); dirs.push(dir);
  const baselinePath = join(dir, "baseline.json"); copyFileSync(join(FIXTURES, "baseline.json"), baselinePath);
  const raw = JSON.parse(readFileSync(join(FIXTURES, name), "utf8")) as Report;
  const receipt = JSON.parse(readFileSync(join(FIXTURES, "measured.receipt.json"), "utf8")) as GuardMutationReceipt;
  if (name === "exclusion-measurable.json") receipt.exclusionChecks = [];
  change?.(raw, receipt);
  for (const [file, entry] of Object.entries(raw.files)) receipt.sourceSha256[file] = guardMutationDigest(entry.source);
  const bytes = `${JSON.stringify(raw, null, 2)}\n`;
  receipt.reportSha256 = guardMutationDigest(bytes);
  const reportPath = join(dir, "report.json"); writeFileSync(reportPath, bytes);
  const receiptPath = join(dir, "receipt.json"); writeFileSync(receiptPath, JSON.stringify(receipt));
  const args = ["--report", reportPath, "--receipt", receiptPath, "--baseline", baselinePath];
  return { dir, baselinePath, reportPath, receiptPath, raw, receipt, args };
}

function run(args: string[], env: NodeJS.ProcessEnv = process.env, cli = CLI, cwd = ROOT, onOutput?: (output: string) => void): Promise<{ status: number; output: string }> {
  return new Promise((done, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", cli, ...args], { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
    const collect = (text: string) => { output += text; onOutput?.(output); };
    child.stdout.on("data", collect); child.stderr.on("data", collect);
    child.once("error", reject);
    child.once("close", (status) => done({ status: status ?? 1, output }));
  });
}

describe("guard mutation production CLI comparison (#1890)", () => {
  it("exits 0 for a matching capture, prints all seven populations, and never rewrites the baseline", async () => {
    const p = prepare(); const before = readFileSync(p.baselinePath, "utf8");
    const result = await run(p.args);
    expect(result.status, result.output).toBe(0);
    expect(result.output).toContain("GUARD BASELINE PASS");
    expect(result.output).toContain("src/recorded-reasons.ts: excluded");
    expect(result.output).toContain('"unscored":0');
    expect(result.output).not.toContain("REPORT ONLY");
    expect(readFileSync(p.baselinePath, "utf8")).toBe(before);
  });

  it.each(["Survived", "NoCoverage", "CompileError"] as const)("exits 1 when a killed guard becomes %s and leaves the baseline unchanged", async (status) => {
    const p = prepare("measured.json", (r) => { r.files["src/ci-liveness.ts"]!.mutants[0]!.status = status; });
    const before = readFileSync(p.baselinePath, "utf8"); const result = await run(p.args);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain(status === "Survived" ? "new-survivor:" : status === "NoCoverage" ? "new-unexercised-guard:" : "new-unscored-guard:");
    expect(readFileSync(p.baselinePath, "utf8")).toBe(before);
  });

  it("exits 1 for a missing guard with no retained survivors", async () => {
    const p = prepare("measured.json", (r) => { delete r.files["src/ci-liveness.ts"]; });
    const result = await run(p.args);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain("missing-guard: src/ci-liveness.ts");
    expect((await run([...p.args, "--update-baseline"])).status).toBe(1);
  });

  it("exits 1 when an exclusion's fresh falsifier exits 0; no empty scored row can reduce it", async () => {
    const p = prepare("measured.json", (_, r) => { r.exclusionChecks[0]!.outcome = "measurable"; r.exclusionChecks[0]!.exitCode = 0; });
    const result = await run(p.args);
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain("stale-exclusion: src/recorded-reasons.ts");
    expect((await run([...p.args, "--update-baseline"])).status).toBe(1);
  });

  it.each(["survivor-killed.json", "exclusion-measurable.json"])("keeps the %s improvement stale until explicit reduction, then exits 0", async (name) => {
    const p = prepare(name); const before = readFileSync(p.baselinePath, "utf8");
    const stale = await run(p.args);
    expect(stale.status, stale.output).toBe(1);
    expect(stale.output).toContain(name.startsWith("survivor") ? "stale-survivor:" : "stale-exclusion:");
    expect(readFileSync(p.baselinePath, "utf8")).toBe(before);
    const update = await run([...p.args, "--update-baseline"]);
    expect(update.status, update.output).toBe(0);
    expect(update.output).toContain("SEMANTIC DELTA");
    expect(update.output).toContain(name.startsWith("survivor") ? "REMOVE survivor:" : "REMOVE exclusion:");
    expect(update.output).toContain("BASELINE UPDATED explicitly");
    expect(readFileSync(p.baselinePath, "utf8")).not.toBe(before);
    const pass = await run(p.args);
    expect(pass.status, pass.output).toBe(0);
    expect(pass.output).toContain("GUARD BASELINE PASS");
  });

  it("will not accept a new survivor without a current owner/review; explicit update prints its actual semantic delta", async () => {
    const p = prepare("measured.json", (r) => { r.files["src/ci-liveness.ts"]!.mutants[0]!.status = "Survived"; });
    const refused = await run([...p.args, "--update-baseline"]);
    expect(refused.status, refused.output).toBe(1);
    expect(refused.output).toContain("missing owner/remediation review");
    const census = normalizeGuardMutationCensus(p.raw, p.receipt, p.receipt.reportSha256);
    const row = guardMutationReviewRequirements(census).find((r) => r.key.startsWith("survivor:src/ci-liveness.ts:"))!;
    const review = { key: row.key, owner: "fixture-maintainer", reviewedAt: new Date().toISOString(), reviewedBy: "fixture-reviewer", sourceCommit: p.receipt.sourceCommit, sourceSha256: row.guard.sourceSha256, reportSha256: p.receipt.reportSha256, reason: "Bounded synthetic transition control.", expiresAt: new Date(Date.now() + 86400000).toISOString() };
    const reviewPath = join(p.dir, "reviews.json"); writeFileSync(reviewPath, JSON.stringify([review]));
    const updated = await run([...p.args, "--update-baseline", "--reviews", reviewPath]);
    expect(updated.status, updated.output).toBe(0);
    expect(updated.output).toContain(`ADD ${row.key}`);
    expect(updated.output).toContain("POPULATION src/ci-liveness.ts survived: 0 -> 1");
    expect(updated.output).toContain(`REVIEW ${row.key}: owner=fixture-maintainer`);
    expect((await run(p.args)).status).toBe(0);
  });

  it("rejects missing ownership, malformed population fields, empty reports and missing capture identity", async () => {
    const p = prepare(); const before = readFileSync(p.baselinePath, "utf8");
    const unowned = JSON.parse(before) as { reviews: { owner: string }[] }; unowned.reviews[0]!.owner = "";
    writeFileSync(p.baselinePath, JSON.stringify(unowned));
    const owner = await run(p.args);
    expect(owner.status, owner.output).toBe(1); expect(owner.output).toContain("review owner must be nonblank");
    const missing = JSON.parse(before) as { census: { guards: { population: Record<string, number> }[] } }; delete missing.census.guards[0]!.population.killed;
    writeFileSync(p.baselinePath, JSON.stringify(missing));
    const population = await run(p.args);
    expect(population.status, population.output).toBe(1); expect(population.output).toContain("population fields");
    writeFileSync(p.baselinePath, before);
    const historical = await run(["--report", p.reportPath, "--baseline", p.baselinePath]);
    expect(historical.status, historical.output).toBe(1); expect(historical.output).toContain("--report requires --receipt");
    const empty = prepare("measured.json", (r) => { r.files = {}; });
    const absent = await run(empty.args);
    expect(absent.status, absent.output).toBe(1); expect(absent.output).toContain("empty-census:");
  });

  it("does not verify a nonexistent remediation issue by trusting its URL", async () => {
    const p = prepare("measured.json", (r) => { r.files["src/ci-liveness.ts"]!.mutants[0]!.status = "Survived"; });
    const census = normalizeGuardMutationCensus(p.raw, p.receipt, p.receipt.reportSha256);
    const row = guardMutationReviewRequirements(census).find((r) => r.key.startsWith("survivor:src/ci-liveness.ts:"))!;
    const reviewPath = join(p.dir, "reviews.json");
    writeFileSync(reviewPath, JSON.stringify([{ key: row.key, owner: "fixture-maintainer", reviewedAt: new Date().toISOString(), reviewedBy: "fixture-reviewer", sourceCommit: p.receipt.sourceCommit, sourceSha256: row.guard.sourceSha256, reportSha256: p.receipt.reportSha256, remediationIssue: "https://github.com/jharvieux/Harvey/issues/999999999" }]));
    const bin = join(p.dir, "bin"); mkdirSync(bin); const gh = join(bin, "gh");
    writeFileSync(gh, "#!/bin/sh\nexit 1\n"); chmodSync(gh, 0o755);
    const before = readFileSync(p.baselinePath, "utf8");
    const result = await run([...p.args, "--update-baseline", "--reviews", reviewPath], { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` });
    expect(result.status, result.output).toBe(1); expect(result.output).toContain("remediation issue could not be verified");
    expect(readFileSync(p.baselinePath, "utf8")).toBe(before);
  });

  it("prevents output aliases from overwriting the baseline or the raw capture in default mode", async () => {
    const p = prepare(); const before = readFileSync(p.baselinePath, "utf8"); const raw = readFileSync(p.reportPath, "utf8");
    const alias = join(p.dir, "alias.json"); symlinkSync(p.baselinePath, alias);
    for (const path of [p.baselinePath, alias, p.reportPath, p.receiptPath]) {
      const result = await run([...p.args, "--normalized-out", path]);
      expect(result.status, result.output).toBe(1); expect(result.output).toContain("output would overwrite");
    }
    expect(readFileSync(p.baselinePath, "utf8")).toBe(before); expect(readFileSync(p.reportPath, "utf8")).toBe(raw);
  });
});

describe("guard census output identity and atomic ownership", () => {
  it.each(["hardlink", "symlink to hardlink", "filesystem-order symlink"])("rejects a %s of a protected replay input", async (kind) => {
    const p = prepare(); const alias = join(p.dir, "alias.json");
    if (kind === "hardlink") linkSync(p.baselinePath, alias);
    if (kind === "symlink to hardlink") { const linked = join(p.dir, "linked.json"); linkSync(p.baselinePath, linked); symlinkSync(linked, alias); }
    if (kind === "filesystem-order symlink") {
      mkdirSync(join(p.dir, "child")); mkdirSync(join(p.dir, "links"));
      symlinkSync(join(p.dir, "child"), join(p.dir, "links", "directory"));
      symlinkSync("directory/../baseline.json", join(p.dir, "links", "output.json"));
      symlinkSync(join(p.dir, "links", "output.json"), alias);
    }
    const before = readFileSync(p.baselinePath);
    const result = await run([...p.args, "--normalized-out", alias]);
    expect(result.status, result.output).toBe(1); expect(result.output).toContain("output would overwrite");
    expect(readFileSync(p.baselinePath)).toEqual(before);
  });

  it.each(["baseline", "unrelated file"])("retains a preexisting atomic sibling owned by %s", async (role) => {
    const p = prepare(); const output = join(p.dir, "normalized.json"); const wrapper = join(p.dir, "atomic-wrapper.mts");
    writeFileSync(wrapper, `import {copyFileSync, writeFileSync} from 'node:fs';
const temporary=${JSON.stringify(output)}+'.'+process.pid+'.tmp';
${role === "baseline" ? `copyFileSync(${JSON.stringify(p.baselinePath)},temporary);` : "writeFileSync(temporary,'unrelated sentinel');"}
console.log('TEMP_PATH '+temporary);
process.argv=[process.execPath,${JSON.stringify(CLI)},...${JSON.stringify(role === "baseline" ? ["--report", p.reportPath, "--receipt", p.receiptPath] : p.args)},${role === "baseline" ? "'--baseline',temporary," : ""}'--normalized-out',${JSON.stringify(output)}];
await import(${JSON.stringify(CLI)});
`);
    const result = await run([], process.env, wrapper); const marker = /TEMP_PATH (.+)/.exec(result.output); expect(marker, result.output).toBeTruthy(); const temporary = marker![1]!;
    expect(result.status, result.output).toBe(1);
    expect(result.output).toContain(role === "baseline" ? "output would overwrite" : "EEXIST");
    expect(readFileSync(temporary, "utf8")).toBe(role === "baseline" ? readFileSync(p.baselinePath, "utf8") : "unrelated sentinel");
    expect(existsSync(output)).toBe(false);
  });

  it("keeps an unowned bundle-writer temporary file on exclusive-create failure", async () => {
    const p = prepare(); const output = join(p.dir, "artifact.json"); const temporary = `${output}.${process.pid}.tmp`;
    writeFileSync(temporary, "retained evidence");
    await expect(writeGuardJson(output, { value: true })).rejects.toThrow("EEXIST");
    expect(readFileSync(temporary, "utf8")).toBe("retained evidence"); expect(existsSync(output)).toBe(false);
  });
});

function freshProject(mode: "blocked" | "measurable" | "main-fails" | "no-report" | "hang" | "isolation" | "new-survivor" = "blocked") {
  const dir = mkdtempSync(join(tmpdir(), "harvey-guard-fresh-")); dirs.push(dir);
  const copy = (file: string, destination = file) => {
    mkdirSync(dirname(join(dir, destination)), { recursive: true });
    copyFileSync(join(ROOT, file), join(dir, destination));
  };
  for (const file of ["package.json", "pnpm-lock.yaml", "vitest.config.ts", "stryker.guards.config.json", "src/cli/guard-mutation-census.ts", "src/cli/args.ts", "src/cli/sync-stdio.ts", "src/guard-mutation-census.ts", "src/guard-mutation-baseline.ts", "src/guard-mutation-shards.ts", "src/guard-mutation-process.ts", "src/guard-mutation-bundle.ts", "src/mutation-scan.ts"]) copy(file);
  copy("src/__fixtures__/guard-mutation/baseline.json", "guard-mutation-baseline.json");
  const fixtureReport = JSON.parse(readFileSync(join(FIXTURES, "measured.json"), "utf8")) as Report & { framework: { version: string } };
  const measuredExclusion = JSON.parse(readFileSync(join(FIXTURES, "exclusion-measurable.json"), "utf8")) as Report;
  for (const file of GUARD_SET) {
    mkdirSync(dirname(join(dir, file)), { recursive: true });
    writeFileSync(join(dir, file), (fixtureReport.files[file] ?? measuredExclusion.files[file])!.source);
  }
  const capture = JSON.parse(readFileSync(join(FIXTURES, "measured.receipt.json"), "utf8")) as GuardMutationReceipt;
  writeFileSync(join(dir, "fixture-exclusion.json"), JSON.stringify(capture.exclusionChecks[0]));
  writeFileSync(join(dir, "fixture-mode.txt"), mode);
  writeFileSync(join(dir, ".gitignore"), "node_modules/\nreports/\n");
  // These are dedicated test-owned command seams. Installed/shared dependencies stay read-only;
  // the real Stryker execution is separately captured in the committed baseline's provenance.
  for (const name of ["tsx", "typescript", "vitest", "@stryker-mutator/core", "@stryker-mutator/vitest-runner"]) {
    const path = join(dir, "node_modules", name); mkdirSync(dirname(path), { recursive: true });
    symlinkSync(join(ROOT, "node_modules", name), path);
  }
  // The orchestration fixture models a capture on this test runtime. The committed real capture
  // keeps its original identities; it must not make a synthetic process seam require one Node patch.
  const baselinePath = join(dir, "guard-mutation-baseline.json");
  const baseline = JSON.parse(readFileSync(baselinePath, "utf8")) as GuardMutationBaseline;
  const identity = baseline.census.receipt.toolchain;
  const requireFromProject = createRequire(join(dir, "package.json"));
  baseline.census.receipt.configSha256 = guardMutationDigest(readFileSync(join(dir, "stryker.guards.config.json")));
  identity.node = process.version;
  identity.packageManager = (JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as { packageManager: string }).packageManager;
  identity.packageJsonSha256 = guardMutationDigest(readFileSync(join(dir, "package.json")));
  identity.lockfileSha256 = guardMutationDigest(readFileSync(join(dir, "pnpm-lock.yaml")));
  for (const [name, installed] of Object.entries(identity.packages)) {
    const manifest = readFileSync(requireFromProject.resolve(`${name}/package.json`));
    installed.version = (JSON.parse(manifest.toString("utf8")) as { version: string }).version;
    installed.packageJsonSha256 = guardMutationDigest(manifest);
  }
  fixtureReport.framework.version = identity.packages["@stryker-mutator/core"]!.version;
  const rawBytes = JSON.stringify(fixtureReport);
  writeFileSync(join(dir, "fixture-report.json"), rawBytes);
  baseline.census.receipt.reportSha256 = guardMutationDigest(rawBytes);
  for (const review of baseline.reviews) review.reportSha256 = baseline.census.receipt.reportSha256;
  writeFileSync(baselinePath, JSON.stringify(baseline));
  const executable = join(dir, "fixture-stryker.cjs");
  writeFileSync(executable, `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const config = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const mode = fs.readFileSync('fixture-mode.txt', 'utf8');
fs.mkdirSync('reports/guard-mutation', {recursive:true});
fs.appendFileSync('reports/guard-mutation/calls.jsonl', JSON.stringify(config.mutate)+'\\n');
if (config.dryRunOnly) {
  const probe = JSON.parse(fs.readFileSync('fixture-exclusion.json', 'utf8'));
  console.log('01:00:00 (1) INFO Instrumenter Instrumented 1 source file(s) with '+probe.attempted+' mutant(s)');
  if (mode === 'measurable') process.exit(0);
  console.error('01:00:00 (1) ERROR DryRunExecutor '+probe.detail);
  console.error('01:00:00 (1) ERROR Stryker There were failed tests in the initial test run.');
  process.exit(1);
}
if (mode === 'main-fails' && config.mutate[0] === 'src/alert-paths.ts') { console.error('distinct-shard-cause'); process.exit(9); }
if (mode === 'no-report' && config.mutate[0] === 'src/alert-paths.ts') process.exit(0);
if (mode === 'hang' && config.mutate[0] === 'src/alert-paths.ts') { console.log('HANG READY'); setInterval(()=>{},1000); return; }
fs.mkdirSync(path.dirname(config.jsonReporter.fileName), {recursive:true});
const report = JSON.parse(fs.readFileSync('fixture-report.json','utf8'));
report.files = Object.fromEntries(config.mutate.map(file => [file, report.files[file]]));
report.config = config;
if (mode === 'new-survivor' && config.mutate[0] === 'src/ci-liveness.ts') report.files[config.mutate[0]].mutants[0].status = 'Survived';
const finish = () => fs.writeFileSync(config.jsonReporter.fileName, JSON.stringify(report));
if (mode === 'isolation') {
  const file = config.mutate[0]; const before = fs.readFileSync(file);
  fs.writeFileSync(file, '// private instrumentation');
  fs.mkdirSync('node_modules/.vite', {recursive:true});
  fs.writeFileSync('node_modules/.vite/guard-isolation-marker',process.cwd());
  console.log('PRIVATE CHECKOUT '+process.cwd());
  setTimeout(()=>{ fs.writeFileSync(file,before); finish(); },250);
} else finish();
`);
  chmodSync(executable, 0o755);
  const bin = join(dir, "node_modules", ".bin"); mkdirSync(bin);
  symlinkSync(executable, join(bin, "stryker"));
  const git = (args: string[]) => execFileSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", ...args], { cwd: dir, stdio: "ignore" });
  git(["init", "--quiet"]); git(["add", "."]);
  git(["-c", "user.name=Guard fixture", "-c", "user.email=guard-fixture@example.invalid", "commit", "--quiet", "-m", "Create isolated guard CLI fixture"]);
  const reportPath = join(dir, "reports", "guard-mutation", "mutation.json");
  mkdirSync(dirname(reportPath), { recursive: true }); writeFileSync(reportPath, "{\"stale\":true}\n");
  return { dir, cli: join(dir, "src", "cli", "guard-mutation-census.ts"), reportPath };
}

describe("guard mutation fresh-run production orchestration (#1890)", () => {
  it("runs the configured guard set and fresh exclusion probe, then writes and compares a bound receipt", async () => {
    const p = freshProject(); const result = await run([], process.env, p.cli, p.dir);
    expect(result.status, result.output).toBe(0); expect(result.output).toContain("GUARD BASELINE PASS");
    const match = /GUARD BUNDLE (.+)/.exec(result.output)!;
    const manifest = JSON.parse(readFileSync(join(match[1]!, "manifest.json"), "utf8")) as { shards: { guard: string; kind: string }[] };
    expect(manifest.shards.map((shard) => shard.guard).sort()).toEqual([...GUARD_SET].sort());
    expect(manifest.shards.filter((shard) => shard.kind === "exclusion").map((shard) => shard.guard)).toEqual(["src/recorded-reasons.ts"]);
    const capture = JSON.parse(readFileSync(join(p.dir, "reports/guard-mutation/mutation.receipt.json"), "utf8")) as GuardMutationReceipt;
    expect(capture.reportSha256).toBe(guardMutationDigest(readFileSync(p.reportPath)));
    expect(capture.exclusionChecks[0]).toMatchObject({ outcome: "blocked", exitCode: 1 });
    expect(capture.toolchain.node).toBe(process.version);
    expect(existsSync(join(p.dir, "reports/guard-mutation/census.json"))).toBe(true);
  });

  it("propagates a successful exclusion falsifier as a stale baseline failure", async () => {
    const p = freshProject("measurable"); const result = await run([], process.env, p.cli, p.dir);
    expect(result.status, result.output).toBe(1); expect(result.output).toContain("stale-exclusion: src/recorded-reasons.ts");
  });

  it.each(["main-fails", "no-report"] as const)("rejects %s without falling back to a stale raw report", async (mode) => {
    const p = freshProject(mode); const result = await run([], process.env, p.cli, p.dir);
    expect(result.status, result.output).toBe(1); expect(result.output).not.toContain("GUARD BASELINE PASS");
    expect(existsSync(p.reportPath)).toBe(false);
    expect(existsSync(join(p.dir, "reports/guard-mutation/mutation.receipt.json"))).toBe(false);
  });

  it("refuses an in-place run on a dirty source tree before invoking Stryker", async () => {
    const p = freshProject(); writeFileSync(join(p.dir, "src/ci-liveness.ts"), "// uncommitted source\n");
    const result = await run([], process.env, p.cli, p.dir);
    expect(result.status, result.output).toBe(1); expect(result.output).toContain("requires a clean committed worktree");
    expect(existsSync(join(p.dir, "reports/guard-mutation/calls.jsonl"))).toBe(false);
  });
});

const bundlePath = (output: string): string => { const value = /GUARD BUNDLE (.+)/.exec(output)?.[1]; expect(value, output).toBeTruthy(); return value!; };
const readObject = <T>(path: string): T => JSON.parse(readFileSync(path, "utf8")) as T;
const writeObject = (path: string, value: unknown) => writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);

describe("bounded guard shards through the production CLI (#1891)", () => {
  it("uses independent process/filesystem identities and preserves the parent source bytes", async () => {
    const p = freshProject("isolation");
    const sources = GUARD_SET.map((file) => readFileSync(join(p.dir, file), "utf8"));
    const result = await run([], process.env, p.cli, p.dir);
    expect(result.status, result.output).toBe(0);
    const bundle = bundlePath(result.output);
    const manifest = readObject<GuardShardManifest>(join(bundle, "manifest.json"));
    expect(result.output).toContain("Test counts in sharded captures are execution records");
    expect(manifest.bounds.concurrency).toBe(2);
    expect(new Set(manifest.shards.map((shard) => shard.workspace)).size).toBe(GUARD_SET.length);
    for (const shard of manifest.shards) {
      const terminal = readObject<GuardShardTerminal>(join(bundle, "shards", shard.id, "terminal.json"));
      expect(terminal.state).toBe("completed");
      expect(terminal.startedAt >= manifest.createdAt).toBe(true);
      if (shard.kind === "mutation") expect(terminal.commands.find((command) => command.stdout.path.endsWith("/stryker.stdout.log"))!.stdout.tail).toContain(`PRIVATE CHECKOUT ${join(bundle, shard.workspace)}`);
      expect(readFileSync(join(bundle, shard.workspace, ".git", "HEAD"), "utf8").trim()).toBe(manifest.sourceCommit);
      expect(readdirSync(join(bundle, shard.workspace, "node_modules"))).toContain("@stryker-mutator");
      expect(lstatSync(join(bundle, shard.workspace, "node_modules")).isSymbolicLink()).toBe(false);
      if (shard.kind === "mutation") expect(readFileSync(join(bundle, shard.workspace, "node_modules/.vite/guard-isolation-marker"), "utf8")).toBe(join(bundle, shard.workspace));
    }
    expect(existsSync(join(p.dir, "node_modules/.vite/guard-isolation-marker"))).toBe(false);
    expect(GUARD_SET.map((file) => readFileSync(join(p.dir, file), "utf8"))).toEqual(sources);
    const conservation = readObject<{ attempted: number; accounted: number }>(join(bundle, "aggregate.conservation.json"));
    expect(conservation.attempted).toBe(8); expect(conservation.accounted).toBe(8);
    expect((await run(["--bundle", bundle], process.env, p.cli, p.dir)).status).toBe(0);
  });

  it.each(["main-fails", "hang", "no-report"] as const)("accounts for every sibling after %s and never normalizes a smaller census", async (mode) => {
    const p = freshProject(mode);
    const result = await run(["--shard-timeout-ms", "1500"], process.env, p.cli, p.dir);
    expect(result.status, result.output).toBe(1);
    const bundle = bundlePath(result.output);
    const manifest = readObject<GuardShardManifest>(join(bundle, "manifest.json"));
    const terminals = manifest.shards.map((shard) => readObject<GuardShardTerminal>(join(bundle, "shards", shard.id, "terminal.json")));
    expect(terminals).toHaveLength(GUARD_SET.length);
    expect(terminals.filter((terminal) => terminal.state === "completed")).toHaveLength(GUARD_SET.length - 1);
    const failed = terminals.find((terminal) => terminal.guard === "src/alert-paths.ts")!;
    expect(failed.state).toBe(mode === "hang" ? "timed-out" : mode === "main-fails" ? "failed" : "error");
    if (mode === "main-fails") expect(failed.commands.find((command) => command.stderr.path.endsWith("/stryker.stderr.log"))!.stderr.tail).toContain("distinct-shard-cause");
    expect(existsSync(join(bundle, "runtime.json"))).toBe(true);
    expect(existsSync(join(bundle, "census.json"))).toBe(false);
    expect(readObject<{ conservation: { declared: number; terminal: number; failed: number } }>(join(bundle, "bundle.json")).conservation).toEqual({ declared: 7, terminal: 7, completed: 6, failed: 1 });
    expect((await run(["--bundle", bundle], process.env, p.cli, p.dir)).status).toBe(1);
  });

  it("bounds the aggregate and records queued shards as not started", async () => {
    const p = freshProject("hang");
    const result = await run(["--concurrency", "1", "--aggregate-timeout-ms", "1100"], process.env, p.cli, p.dir);
    expect(result.status, result.output).toBe(1);
    const bundle = bundlePath(result.output);
    const manifest = readObject<GuardShardManifest>(join(bundle, "manifest.json"));
    const terminals = manifest.shards.map((shard) => readObject<GuardShardTerminal>(join(bundle, "shards", shard.id, "terminal.json")));
    expect(terminals).toHaveLength(GUARD_SET.length);
    expect(terminals.some((terminal) => terminal.state === "aggregate-timeout")).toBe(true);
    expect(terminals.some((terminal) => terminal.state === "not-started")).toBe(true);
    expect(terminals.every((terminal) => terminal.finishedAt)).toBe(true);
  });

  it.each(["comparison", "explicit update"])("rejects a baseline changed after MANIFEST before %s, preserving the concurrent bytes", async (mode) => {
    const p = freshProject(); const baseline = join(p.dir, "guard-mutation-baseline.json");
    const changed = readObject<GuardMutationBaseline>(baseline); changed.reviews[0]!.owner = "concurrent baseline owner";
    const concurrentBytes = `${JSON.stringify(changed, null, 2)}\n`; let changedDuringRun = false;
    const result = await run(mode === "explicit update" ? ["--update-baseline"] : [], process.env, p.cli, p.dir, (output) => {
      if (!changedDuringRun && output.includes("MANIFEST ")) { changedDuringRun = true; writeFileSync(baseline, concurrentBytes); }
    });
    expect(changedDuringRun).toBe(true); expect(result.status, result.output).toBe(1);
    expect(result.output).toContain("baseline changed during the census"); expect(result.output).not.toContain("GUARD BASELINE PASS");
    expect(readFileSync(baseline, "utf8")).toBe(concurrentBytes);
    expect(existsSync(join(bundlePath(result.output), "comparison.json"))).toBe(false);
    expect(existsSync(join(bundlePath(result.output), "aggregate.json"))).toBe(true);
  });

  it("feeds the complete aggregate into the production survivor comparator", async () => {
    const p = freshProject("new-survivor");
    const before = readFileSync(join(p.dir, "guard-mutation-baseline.json"));
    const result = await run([], process.env, p.cli, p.dir);
    expect(result.status, result.output).toBe(1); expect(result.output).toContain("new-survivor:src/ci-liveness.ts:");
    expect(readFileSync(join(p.dir, "guard-mutation-baseline.json"))).toEqual(before);
    const comparison = readObject<{ ok: boolean; reportSha256: string }>(join(bundlePath(result.output), "comparison.json"));
    expect(comparison.ok).toBe(false); expect(comparison.reportSha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it.each([["capture", "CAPTURE"], ["straße", "STRASSE"], ["STRAẞE", "strasse"], ["Σ", "ς"], ["ſ", "s"], ["ﬃ", "ffi"]])("rejects prospective bundle namespace %s aliases through %s before any child", async (name, alias) => {
    const p = freshProject(); const directory = join(p.dir, "reports", "guard-mutation"); const bundle = join(directory, name!);
    const before = readFileSync(p.reportPath);
    const result = await run(["--bundle-dir", bundle, "--normalized-out", join(directory, alias!, "shards/guard-01/config.json")], process.env, p.cli, p.dir);
    expect(result.status, result.output).toBe(1); expect(result.output).toContain("bundle output would overwrite");
    expect(result.output).not.toContain("GUARD BUNDLE"); expect(existsSync(bundle)).toBe(false);
    expect(readFileSync(p.reportPath)).toEqual(before);
  });

  it("follows directory symlinks before parent traversal for a prospective bundle namespace", async () => {
    const p = freshProject(); const directory = join(p.dir, "reports", "guard-mutation");
    mkdirSync(join(directory, "physical", "child"), { recursive: true });
    symlinkSync("physical/child", join(directory, "alias"));
    symlinkSync("alias/../capture", join(directory, "output-directory"));
    const bundle = join(directory, "physical", "capture"); const before = readFileSync(p.reportPath);
    const result = await run(["--bundle-dir", bundle, "--normalized-out", join(directory, "output-directory", "manifest.json")], process.env, p.cli, p.dir);
    expect(result.status, result.output).toBe(1); expect(result.output).toContain("bundle output would overwrite");
    expect(result.output).not.toContain("GUARD BUNDLE"); expect(existsSync(bundle)).toBe(false);
    expect(readFileSync(p.reportPath)).toEqual(before);
  });

  it.each(["mutation.json", "mutation.receipt.json"])("rejects case aliases between legacy output %s and the normalized output", async (name) => {
    const p = freshProject(); const before = readFileSync(p.reportPath);
    const result = await run(["--normalized-out", join(p.dir, "reports/guard-mutation", name.toUpperCase())], process.env, p.cli, p.dir);
    expect(result.status, result.output).toBe(1); expect(result.output).toContain("output would overwrite");
    expect(result.output).not.toContain("GUARD BUNDLE"); expect(readFileSync(p.reportPath)).toEqual(before);
  });

  it.each([["normalized-out", "src/ci-liveness.ts"], ["normalized-out", "package.json"], ["receipt", "pnpm-lock.yaml"], ["raw-report", "src/recorded-reasons.ts"], ["normalized-out", "vitest.config.ts"]])("protects the %s destination from overwriting source input %s", async (role, file) => {
    const p = freshProject(); const output = join(p.dir, file!); const before = readFileSync(output); const args: string[] = [];
    if (role === "raw-report") {
      const config = readObject<{ jsonReporter: { fileName: string } }>(join(p.dir, "stryker.guards.config.json"));
      config.jsonReporter.fileName = output;
      const custom = join(p.dir, "reports/guard-mutation/custom.config.json"); writeObject(custom, config); args.push("--config", custom);
    } else args.push(`--${role}`, output);
    const result = await run(args, process.env, p.cli, p.dir);
    expect(result.status, result.output).toBe(1); expect(result.output).toContain("output would overwrite");
    expect(result.output).not.toContain("GUARD BUNDLE"); expect(readFileSync(output)).toEqual(before);
  });

  it("rejects every bundle/output collision before any subprocess or destructive output cleanup", async () => {
    const p = freshProject(); const bundle = join(p.dir, "reports", "guard-mutation", "capture");
    const before = readFileSync(p.reportPath);
    for (const relative of ["manifest.json", "base.config.json", "shards/guard-01/config.json", "shards/guard-01/terminal.json", "shards/guard-05/stryker.stderr.log", "aggregate.json", "comparison.json"]) {
      const result = await run(["--bundle-dir", bundle, "--normalized-out", join(bundle, relative)], process.env, p.cli, p.dir);
      expect(result.status, result.output).toBe(1); expect(result.output).toContain("bundle output would overwrite");
      expect(existsSync(bundle)).toBe(false); expect(readFileSync(p.reportPath)).toEqual(before);
    }
    mkdirSync(bundle); const alias = join(p.dir, "bundle-alias"); symlinkSync(bundle, alias);
    const aliased = await run(["--bundle-dir", alias, "--normalized-out", join(bundle, "manifest.json")], process.env, p.cli, p.dir);
    expect(aliased.status, aliased.output).toBe(1); expect(aliased.output).toContain("bundle output would overwrite");
    expect(readdirSync(bundle)).toEqual([]);
  });
});

describe("immutable raw-bundle reader adversarial CLI controls (#1891)", () => {
  let project: ReturnType<typeof freshProject>;
  let original: string;
  beforeAll(async () => {
    project = freshProject(); dirs.splice(dirs.indexOf(project.dir), 1);
    const result = await run([], process.env, project.cli, project.dir);
    expect(result.status, result.output).toBe(0); original = bundlePath(result.output);
  });
  afterAll(() => rmSync(project.dir, { recursive: true, force: true }));

  async function reject(change: (bundle: string) => void, expected: string, reseal = false) {
    const dir = mkdtempSync(join(tmpdir(), "harvey-guard-tamper-")); dirs.push(dir);
    cpSync(original, dir, { recursive: true, filter: (path) => !path.includes("/workspaces") });
    change(dir);
    if (reseal) {
      const seal = readObject<{ artifacts: { path: string; sha256: string }[]; manifestSha256: string }>(join(dir, "bundle.json"));
      for (const artifact of seal.artifacts) artifact.sha256 = guardMutationDigest(readFileSync(join(dir, artifact.path)));
      seal.manifestSha256 = guardMutationDigest(readFileSync(join(dir, "manifest.json")));
      writeObject(join(dir, "bundle.json"), seal);
    }
    const result = await run(["--bundle", dir], process.env, project.cli, project.dir);
    expect(result.status, result.output).toBe(1); expect(result.output).toContain(expected);
    expect(result.output).not.toContain("GUARD BASELINE PASS");
  }

  it("rejects a case alias into a retained replay bundle before writing its artifact", async () => {
    const before = readFileSync(join(original, "manifest.json"));
    const result = await run(["--bundle", original, "--normalized-out", join(dirname(original), original.split("/").at(-1)!.toUpperCase(), "manifest.json")], process.env, project.cli, project.dir);
    expect(result.status, result.output).toBe(1); expect(result.output).toContain("bundle output would overwrite");
    expect(readFileSync(join(original, "manifest.json"))).toEqual(before);
  });

  it.each(["missing", "corrupt", "symlink", "unreadable"])("rejects a %s raw report", async (mode) => reject((dir) => {
    const path = join(dir, "shards/guard-01/mutation.json");
    if (mode === "unreadable") chmodSync(path, 0o000);
    else if (mode === "corrupt") writeFileSync(path, "{invalid-json");
    else { rmSync(path); if (mode === "symlink") symlinkSync(join(original, "shards/guard-01/mutation.json"), path); }
  }, mode === "missing" ? "bundle artifact inventory changed" : mode === "corrupt" ? "corrupt bundle artifact" : mode === "unreadable" ? "EACCES" : "nonregular bundle artifact"));

  it.each(["missing", "duplicate"])("rejects a %s guard in a freshly digest-bound manifest", async (mode) => reject((dir) => {
    const path = join(dir, "manifest.json"); const manifest = readObject<GuardShardManifest>(path);
    if (mode === "missing") manifest.shards.pop(); else manifest.shards.push(manifest.shards[0]!);
    writeObject(path, manifest);
  }, "manifest does not exactly partition", true));

  it.each(["duplicate", "timed-out", "source", "toolchain", "config", "blocking", "tail"])("rejects %s terminal evidence even after outer digests are refreshed", async (mode) => reject((dir) => {
    const path = join(dir, "shards/guard-01/terminal.json"); const terminal = readObject<GuardShardTerminal>(path);
    if (mode === "duplicate") terminal.id = "guard-02";
    if (mode === "timed-out") terminal.state = "timed-out";
    if (mode === "source") terminal.sourceSha256[terminal.guard] = "0".repeat(64);
    if (mode === "toolchain") terminal.toolchain.node = "v99.0.0";
    if (mode === "config") terminal.configSha256 = "0".repeat(64);
    if (mode === "blocking") terminal.commands[0]!.maxParentBlockMs = 59_000;
    if (mode === "tail") terminal.commands[0]!.stdout.tail = "invented output";
    writeObject(path, terminal);
  }, { duplicate: "terminal identity", "timed-out": "incomplete shard", source: "source identity mismatch", toolchain: "toolchain mismatch", config: "config receipt mismatch", blocking: "blocking budget", tail: "output tail mismatch" }[mode]!, true));

  it("refuses a missing guard population inside a correctly digest-bound raw shard", async () => reject((dir) => {
    const path = join(dir, "shards/guard-01/mutation.json"); const report = readObject<Report>(path); report.files = {}; writeObject(path, report);
    const terminalPath = join(dir, "shards/guard-01/terminal.json"); const terminal = readObject<GuardShardTerminal>(terminalPath);
    terminal.rawReport!.sha256 = guardMutationDigest(readFileSync(path)); writeObject(terminalPath, terminal);
  }, "missing or duplicate guard population", true));

  it("runs the #1890 normalizer over raw mutant identities instead of trusting an arbitrary census JSON", async () => reject((dir) => {
    const path = join(dir, "shards/guard-01/mutation.json"); const report = readObject<Report>(path);
    report.files["src/acceptance-conservation.ts"]!.mutants.push(report.files["src/acceptance-conservation.ts"]!.mutants[0]!); writeObject(path, report);
    const terminalPath = join(dir, "shards/guard-01/terminal.json"); const terminal = readObject<GuardShardTerminal>(terminalPath);
    terminal.rawReport!.sha256 = guardMutationDigest(readFileSync(path)); writeObject(terminalPath, terminal);
    writeObject(join(dir, "census.json"), { schemaVersion: 1, guards: [], ok: true });
  }, "mutant identity", true));
});
