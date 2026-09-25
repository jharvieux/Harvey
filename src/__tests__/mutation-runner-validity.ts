import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import type { MutationRunnerValidity, StrykerReport } from "../mutation-scan.js";
import { assertCommandExecutionReceipt, verifyCommandExecutionReceiptArtifacts, type CommandExecutionReceipt } from "../producer-execution-receipt.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const FIXTURE = join(ROOT, "src", "__fixtures__", "mutation-runner-validity");
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function copyFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-runner-validity-"));
  dirs.push(dir);
  cpSync(FIXTURE, dir, { recursive: true });
  symlinkSync(join(ROOT, "node_modules"), join(dir, "node_modules"), "dir");
  return dir;
}

function runVitest(dir: string, suffix: string) {
  const resultPath = join(dir, `vitest-${suffix}.json`);
  const args = ["run", "--config", "vitest.config.ts", "src/subject.test.ts", "--reporter=json", `--outputFile=${resultPath}`];
  const run = spawnSync(join(ROOT, "node_modules", ".bin", "vitest"), args, { cwd: dir, encoding: "utf8", timeout: 15_000 });
  const report = existsSync(resultPath) ? JSON.parse(readFileSync(resultPath, "utf8")) as {
    numPassedTests?: number; numFailedTests?: number; testResults?: { message?: string }[];
  } : undefined;
  const completedTests = Number(report?.numPassedTests ?? 0) + Number(report?.numFailedTests ?? 0);
  const suiteErrors = (report?.testResults ?? []).flatMap((test) => test.message?.trim() ? [test.message.trim()] : []);
  return { run, args, completedTests, suiteErrors };
}

describe("installed Vitest/Stryker completed-test validity (#2089)", () => {
  it("distinguishes assertion kill, completed survivor, no coverage and a zero-test import failure", () => {
    const dir = copyFixture();
    const baseline = runVitest(dir, "baseline");
    expect(baseline.run.status).toBe(0);
    expect(baseline.completedTests).toBe(2);

    const artifactPath = join(mkdtempSync(join(tmpdir(), "harvey-runner-artifact-")), "m8.json");
    dirs.push(dirname(artifactPath));
    const cli = spawnSync(join(ROOT, "node_modules", ".bin", "tsx"), [join(ROOT, "src", "cli", "mutation-scan.ts"), dir, "--out", artifactPath], {
      cwd: ROOT, encoding: "utf8", timeout: 25_000,
    });
    expect(cli.error).toBeUndefined();
    expect(cli.status).toBe(0);
    const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as {
      rawReport: StrykerReport;
      effectiveReport: StrykerReport;
      runnerValidity: MutationRunnerValidity;
      executionReceipt: CommandExecutionReceipt;
      summary: { overall: { survived: number; runtimeErrors: number; noCoverage: number; killed: number } };
    };
    const report = artifact.rawReport;
    expect(report, `CLI stderr:\n${cli.stderr}\nartifact:\n${JSON.stringify(artifact, null, 2)}`).toBeTruthy();
    expect(report.framework).toMatchObject({ name: "StrykerJS", version: "9.6.1" });
    expect(report.config).toMatchObject({ testRunner: "vitest", coverageAnalysis: "perTest", vitest: { related: false, configFile: "vitest.config.ts" } });
    assertCommandExecutionReceipt(artifact.executionReceipt);
    verifyCommandExecutionReceiptArtifacts(artifact.executionReceipt);
    expect(artifact.executionReceipt).toMatchObject({
      outcome: { state: "exited", exitCode: 0 },
      toolchain: expect.arrayContaining([{ name: "StrykerJS", version: "9.6.1" }, { name: "vitest", version: "3.2.6" }]),
      measurements: { completedTests: 2, testsDiscovered: 2, suiteLoadErrors: 1 },
      artifacts: [{ role: "report" }],
    });
    const arithmetic = report.files["src/subject.ts"]!.mutants.filter((mutant) => mutant.mutatorName === "ArithmeticOperator");
    expect(arithmetic.map(({ status, testsCompleted }) => ({ status, testsCompleted }))).toEqual([
      { status: "NoCoverage", testsCompleted: undefined },
      { status: "Killed", testsCompleted: 1 },
      { status: "Survived", testsCompleted: 1 },
      { status: "Survived", testsCompleted: 0 },
    ]);

    const importFailure = arithmetic.find((mutant) => mutant.status === "Survived" && mutant.testsCompleted === 0)!;
    expect(artifact.runnerValidity).toMatchObject({
      status: "uncheckable",
      completedTestEvidence: { killed: 1, survived: 1, zeroCompletedSurvivors: 1, missingCompletedCountSurvivors: 0 },
      issues: [{
        mutantId: importFailure.id, effectiveStatus: "RuntimeError", testsCompleted: 0,
        suiteErrors: [expect.stringContaining("dimension metadata failed to load")],
        nativeComparison: { completedTests: 0, exitCode: 1, selectedTests: ["src/subject.test.ts"] },
      }],
    });
    const nativeReceipt = artifact.runnerValidity.issues[0]!.nativeComparison!.receipt!;
    assertCommandExecutionReceipt(nativeReceipt);
    verifyCommandExecutionReceiptArtifacts(nativeReceipt);
    expect(nativeReceipt).toMatchObject({
      outcome: { state: "exited", exitCode: 1 },
      toolchain: [{ name: "vitest", version: "3.2.6" }],
      measurements: { completedTests: 0, testsDiscovered: 2, suiteLoadErrors: 1 },
      artifacts: [{ role: "report" }],
    });
    expect(artifact.effectiveReport.files["src/subject.ts"]!.mutants.find((mutant) => mutant.id === importFailure.id)).toMatchObject({ status: "RuntimeError", testsCompleted: 0 });
    expect(artifact.summary.overall).toMatchObject({ killed: 1, survived: 1, noCoverage: 1, runtimeErrors: 1 });
    // Negative control: if the old raw `Survived` classification were restored to scoring, this
    // exact count would be 2 and the integration assertion above would fail.
    expect(report.files["src/subject.ts"]!.mutants.filter((mutant) => mutant.status === "Survived")).toHaveLength(2);
  });
});
