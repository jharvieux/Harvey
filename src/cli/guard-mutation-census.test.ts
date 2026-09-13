import { execFileSync, spawn } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { guardMutationDigest, guardMutationReviewRequirements, normalizeGuardMutationCensus, type GuardMutationBaseline, type GuardMutationReceipt } from "../guard-mutation-baseline.js";
import type { StrykerMutant } from "../mutation-scan.js";
import { GUARD_SET } from "../guard-mutation-census.js";

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

function run(args: string[], env: NodeJS.ProcessEnv = process.env, cli = CLI, cwd = ROOT): Promise<{ status: number; output: string }> {
  return new Promise((done, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", cli, ...args], { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
    child.stdout.on("data", (text: string) => { output += text; });
    child.stderr.on("data", (text: string) => { output += text; });
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

function freshProject(mode: "blocked" | "measurable" | "main-fails" | "no-report" = "blocked") {
  const dir = mkdtempSync(join(tmpdir(), "harvey-guard-fresh-")); dirs.push(dir);
  const copy = (file: string, destination = file) => {
    mkdirSync(dirname(join(dir, destination)), { recursive: true });
    copyFileSync(join(ROOT, file), join(dir, destination));
  };
  for (const file of ["package.json", "pnpm-lock.yaml", "stryker.guards.config.json", "src/cli/guard-mutation-census.ts", "src/cli/args.ts", "src/cli/sync-stdio.ts", "src/guard-mutation-census.ts", "src/guard-mutation-baseline.ts", "src/mutation-scan.ts"]) copy(file);
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
if (mode === 'main-fails') process.exit(1);
if (mode === 'no-report') process.exit(0);
fs.mkdirSync(path.dirname(config.jsonReporter.fileName), {recursive:true});
fs.copyFileSync('fixture-report.json', config.jsonReporter.fileName);
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
    const calls = readFileSync(join(p.dir, "reports/guard-mutation/calls.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line) as string[]);
    expect(calls[0]?.length).toBe(GUARD_SET.length - 1); expect(calls[1]).toEqual(["src/recorded-reasons.ts"]);
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
