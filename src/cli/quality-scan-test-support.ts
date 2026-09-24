import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runGuardCommand } from "../guard-mutation-process.js";

/** Each suite owns its child groups and removes fixtures only after their close is acknowledged. */
export function createQualityScanTestHarness(options: { timeoutMs?: number; killGraceMs?: number } = {}) {
  const dirs: string[] = [];
  const invocations = new Map<AbortController, Promise<unknown>>();
  let cleanupFailure: Error | undefined;
  let cleaning = false;

  async function run(binPath: string, args: string[], cwd: string, input?: string | null,
    call: { timeoutMs?: number; onFirstByte?: () => void } = {}): Promise<string> {
    if (cleaning) throw new Error("quality-scan fixture cleanup has already started");
    const outputDir = mkdtempSync(join(tmpdir(), "harvey-quality-child-"));
    dirs.push(outputDir);
    const controller = new AbortController();
    const invocation = (async () => {
      const result = await runGuardCommand({
        command: [binPath, ...args], cwd, bundleDir: outputDir, outputPrefix: "scan",
        timeoutMs: call.timeoutMs ?? options.timeoutMs ?? 20_000,
        killGraceMs: options.killGraceMs ?? 500, signal: controller.signal,
        stdin: input, onFirstByte: call.onFirstByte,
      });
      if (!result.terminationAcknowledged) {
        cleanupFailure = new Error(`quality-scan process group did not acknowledge termination; retained ${outputDir}`);
        throw cleanupFailure;
      }
      const stderr = readFileSync(join(outputDir, result.stderr.path), "utf8");
      if (result.state !== "exited" || result.exitCode !== 0 || result.error) {
        throw Object.assign(new Error(`${binPath} ${result.state} (exit ${result.exitCode}, signal ${result.signal}): ${result.error ?? ""}\n${result.stderr.tail}`), {
          exitCode: result.exitCode, signal: result.signal, state: result.state, stderr,
        });
      }
      return stderr;
    })();
    invocations.set(controller, invocation);
    try { return await invocation; } finally { invocations.delete(controller); }
  }

  async function cleanup(): Promise<void> {
    cleaning = true;
    try {
      for (const controller of invocations.keys()) controller.abort();
      await Promise.allSettled(invocations.values());
      if (cleanupFailure) throw cleanupFailure;
      for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
    } finally { cleaning = false; }
  }

  return { dirs, run, cleanup };
}
