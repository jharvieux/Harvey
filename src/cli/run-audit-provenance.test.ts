import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, extname, join, resolve } from "node:path";
import ts from "typescript";
import { afterEach, describe, expect, it, vi } from "vitest";
import { auditContextDigest, beginFreshAuditContext } from "../audit-context.js";
import type { RunContext } from "../audit-runner.js";
import { probeExec } from "../probe-exec.js";
import type { CommandExecutionReceipt } from "../producer-execution-receipt.js";

// Evaluate the shipping command callback and output-path helpers unchanged, with the real
// subprocess and provenance observer, without starting unrelated audit modules or scanners.
function shippingCommandContext(targetDir: string, captureDir: string, freshCapture: ReturnType<typeof beginFreshAuditContext>) {
  const source = readFileSync(new URL("./run-audit.ts", import.meta.url), "utf8");
  const ast = ts.createSourceFile("run-audit.ts", source, ts.ScriptTarget.Latest, true);
  const variableNames = ["capturedPaths", "retainedInvocation", "capturedPath", "outputFlags", "commandArtifacts"];
  const helpers = variableNames.map((name) => ast.statements.find((node) => ts.isVariableStatement(node) && node.declarationList.declarations.some((declaration) => declaration.name.getText(ast) === name))?.getText(ast));
  helpers.push(ast.statements.find((node) => ts.isFunctionDeclaration(node) && node.name?.text === "invocationOutputPaths")?.getText(ast));
  expect(helpers).not.toContain(undefined);
  const ctx = ast.statements.flatMap((node) => ts.isVariableStatement(node) ? [...node.declarationList.declarations] : []).find((declaration) => declaration.name.getText(ast) === "ctx")?.initializer;
  if (!ctx || !ts.isObjectLiteralExpression(ctx)) throw new Error("shipping audit context is missing");
  const exec = ctx.properties.find((property) => ts.isPropertyAssignment(property) && property.name.getText(ast) === "exec");
  if (!exec || !ts.isPropertyAssignment(exec)) throw new Error("shipping audit exec callback is missing");
  const commandReceipts: CommandExecutionReceipt[] = [];
  const bindings = {
    probeExec, resolve, delimiter, dirname, extname, targetDir, captureDir, freshCapture, commandReceipts,
    env: { connected: false, dynamic: false, llm: false }, retainDir: join(captureDir, "retained"), replayBinding: undefined,
  };
  const code = ts.transpileModule(`${helpers.join("\n")}\nconst exec = ${exec.initializer.getText(ast)};\nreturn { exec, capturedPath, commandReceipts };`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText;
  return new Function(...Object.keys(bindings), code)(...Object.values(bindings)) as {
    exec: RunContext["exec"]; capturedPath: (path: string) => string; commandReceipts: CommandExecutionReceipt[];
  };
}

const roots: string[] = [];
afterEach(() => {
  vi.unstubAllEnvs();
  roots.splice(0).forEach((root) => rmSync(root, { recursive: true, force: true }));
});

describe("run-audit command launch provenance", () => {
  it.each(["options.env", "process.env", "relative PATH"])("binds the actual launcher when %s changes during execution", async (environmentSource) => {
    const root = mkdtempSync(join(tmpdir(), "harvey-launch-provenance-"));
    roots.push(root);
    const target = join(root, "target");
    const engineRoot = join(root, "engine");
    const captureDir = join(root, "capture");
    const originalBin = environmentSource === "relative PATH" ? join(target, "bin") : join(root, "original-bin");
    const otherBin = join(root, "later", "bin");
    for (const path of [target, join(engineRoot, "src"), captureDir, originalBin, otherBin]) mkdirSync(path, { recursive: true });
    writeFileSync(join(target, "app.ts"), "export const original = true;");
    writeFileSync(join(engineRoot, "src", "scanner.ts"), "export const version = 1;");
    const command = "harvey-provenance-launcher";
    const originalLauncher = `#!${process.execPath}\nsetTimeout(() => {
      const out = process.argv[process.argv.indexOf('--out') + 1];
      require('node:fs').writeFileSync(out, JSON.stringify({ launcher: 'ORIGINAL_LAUNCHER', inherited: process.env.HARVEY_AUDIT_PARENT_ENV, overlay: process.env.HARVEY_AUDIT_OVERLAY }));
      process.stdout.write('ORIGINAL_LAUNCHER');
    }, 80);\n`;
    const otherLauncher = `#!${process.execPath}\nprocess.stdout.write('OTHER_LAUNCHER');\n`;
    writeFileSync(join(originalBin, command), originalLauncher, { mode: 0o755 });
    writeFileSync(join(otherBin, command), otherLauncher, { mode: 0o755 });
    vi.stubEnv("PATH", environmentSource === "process.env" ? originalBin : otherBin);
    vi.stubEnv("HARVEY_AUDIT_PARENT_ENV", "parent-value");
    vi.stubEnv("HARVEY_AUDIT_OVERLAY", "parent-overlay");
    const freshCapture = beginFreshAuditContext({ target, engineRoot, configuration: { connected: false } });
    const ctx = shippingCommandContext(target, captureDir, freshCapture);
    const requested = join(captureDir, "report.json");
    const options: NonNullable<Parameters<RunContext["exec"]>[2]> = { cwd: target };
    if (environmentSource !== "process.env") options.env = { PATH: environmentSource === "relative PATH" ? "bin" : originalBin, HARVEY_AUDIT_OVERLAY: "child-overlay" };
    const originalCwd = process.cwd();
    try {
      const pending = ctx.exec(command, ["--out", requested], options);
      if (environmentSource === "relative PATH") process.chdir(dirname(otherBin));
      else if (options.env) options.env.PATH = otherBin;
      else process.env.PATH = otherBin;
      const result = await pending;
      expect(result).toMatchObject({ ok: true, output: "ORIGINAL_LAUNCHER" });
      const report = join(captureDir, "report.invocation-1.json");
      expect(ctx.capturedPath(requested)).toBe(report);
      expect(existsSync(requested)).toBe(false);
      expect(JSON.parse(readFileSync(report, "utf8"))).toEqual({
        launcher: "ORIGINAL_LAUNCHER", inherited: "parent-value",
        overlay: environmentSource !== "process.env" ? "child-overlay" : "parent-overlay",
      });
      expect(result.receipt?.artifacts).toEqual([expect.objectContaining({ path: report, sha256: createHash("sha256").update(readFileSync(report)).digest("hex") })]);
      expect(result.receipt?.command.argv).toEqual(["--out", report]);
      expect(ctx.commandReceipts).toEqual([result.receipt]);
      const context = freshCapture.finish([]);
      const identity = (launcher: string) => auditContextDigest([createHash("sha256").update(launcher).digest("hex")]);
      expect(context.producerVersions[`launcher:${command}`]).toBe(identity(originalLauncher));
      expect(context.producerVersions[`launcher:${command}`]).not.toBe(identity(otherLauncher));
    } finally {
      process.chdir(originalCwd);
    }
  });
});
