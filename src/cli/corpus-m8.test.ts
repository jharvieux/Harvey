import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";
import { M8_CORPUS_CONFIGS } from "../scan/m8-corpus.js";
import { buildM8CorpusPlan, type M8TargetResult } from "../scan/m8-corpus-artifacts.js";
import { describePreparationStages } from "../corpus-package-manager.js";

const plan = buildM8CorpusPlan(EXTERNAL_CORPUS, M8_CORPUS_CONFIGS);
const cli = join(import.meta.dirname, "corpus-m8.ts");
const tsxLoader = createRequire(import.meta.url).resolve("tsx");

describe("M8 target failure evidence (#2057)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it.each(["separate streams", "multiline preparation detail"])("retains bounded, redacted %s through target and aggregate artifacts", (shape) => {
    const root = mkdtempSync(join(tmpdir(), "harvey-m8-wrapper-"));
    dirs.push(root);
    const bin = join(root, "bin");
    mkdirSync(bin);
    const detail = describePreparationStages([{
      stage: "tool-install", outcome: "failed", exitCode: 42, command: ["pnpm", "add"],
      selected: {
        executable: "/tools/pnpm", executableSha256: "a".repeat(64), version: "11.1.3",
        launcher: "pnpm", launcherRealpath: "/tools/node", launcherSha256: "b".repeat(64),
        nodeExecutable: process.execPath, nodeVersion: process.version,
      },
      reason: "ERR_PNPM_STDOUT_2057 Authorization: Bearer abcdefgh12345678 https://alice:passwordvalue@example.invalid/pkg?token=queryvalue\nERR_PNPM_STDERR_2057 ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\n" + "peer dependency detail\n".repeat(220),
    }]);
    const output = shape === "multiline preparation detail" ? [
      `writeSync(2, ${JSON.stringify(`DEPENDENCY PREP TOOL ${detail}\nError: tool installation failed: ${detail}\n`)});`,
    ] : [
      `writeSync(1, "tool-install failed, exit 42: /tools/pnpm@11.1.3; ERR_PNPM_STDOUT_2057 Authorization: Bearer abcdefgh12345678 https://alice:passwordvalue@example.invalid/pkg?token=queryvalue\\n");`,
      `writeSync(2, "ERR_PNPM_STDERR_2057 ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\\n");`,
    ];
    writeFileSync(join(bin, "pnpm"), [
      `#!${process.execPath}`,
      `const { writeSync } = require("node:fs");`,
      `writeSync(1, "noise\\n".repeat(20000));`,
      ...output,
      `writeSync(1, "traceback filler\\n".repeat(1000));`,
      `writeSync(2, "traceback filler\\n".repeat(1000));`,
      `process.exit(42);`,
    ].join("\n"), { mode: 0o755 });
    const artifacts = join(root, "artifacts");
    const target = "proposit";
    const targetDir = join(artifacts, target);
    mkdirSync(targetDir, { recursive: true });
    const resultPath = join(targetDir, "result.json");
    execFileSync(process.execPath, ["--import", tsxLoader, cli, "target", "--target", target, "--out", resultPath], {
      cwd: root,
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` },
      stdio: "pipe",
      maxBuffer: 1024 * 1024,
    });
    const raw = readFileSync(resultPath, "utf8");
    const result = JSON.parse(raw) as M8TargetResult;
    expect(result).toMatchObject({ target, status: "failed", exitCode: 42, scorecard: null });
    expect(result.error).toContain("scorecard unavailable or corrupt");
    expect(result.error).toContain("ERR_PNPM_STDOUT_2057");
    expect(result.error).toContain("ERR_PNPM_STDERR_2057");
    expect(result.error).toContain("/tools/pnpm@11.1.3");
    expect(result.error!.length).toBeLessThan(9000);
    expect(raw).not.toContain("abcdefgh12345678");
    expect(raw).not.toContain("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345");
    expect(raw).not.toContain("passwordvalue");
    expect(raw).not.toContain("queryvalue");
    expect(raw).toContain("[REDACTED]");

    for (const other of plan.configured.filter((slug) => slug !== target)) {
      const directory = join(artifacts, other);
      mkdirSync(directory);
      writeFileSync(join(directory, "result.json"), `${JSON.stringify({
        schemaVersion: 1, target: other, status: "passed", exitCode: 0, durationMs: 1,
        phases: { clone: 0, "dependency preparation": 0, "test baseline": 0, mutation: 0, scoring: 1 },
        scorecard: { rows: [{ slug: other, check: "M8 mutation baseline", pass: true }], findings: {} },
      })}\n`);
    }
    const reportPath = join(root, "aggregate.json");
    expect(() => execFileSync(process.execPath, ["--import", tsxLoader, cli, "aggregate", "--artifacts", artifacts, "--out", reportPath], { cwd: root, stdio: "pipe" })).toThrow();
    expect(existsSync(reportPath)).toBe(true);
    const report = JSON.parse(readFileSync(reportPath, "utf8")) as { ok: boolean; failed: number; targets: M8TargetResult[] };
    expect(report).toMatchObject({ ok: false, failed: 1 });
    expect(report.targets.find((entry) => entry.target === target)?.error).toBe(result.error);
  });
});
