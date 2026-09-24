import { accessSync, constants, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runGuardCommand } from "../guard-mutation-process.js";
import { statSafe } from "../fs-walk.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const CLI = join(REPO_ROOT, "src", "cli", "quick-scan.ts");
export const CALIBRATION = join(REPO_ROOT, "targets", "calibration");

// The real mechanical scan keeps the same binary gate as the original heavy suite.
export const MECHANICAL_BINARIES_PRESENT = ["semgrep", "trufflehog", "gitleaks"].every((name) =>
  (process.env.PATH ?? "").split(delimiter).some((directory) => {
    try {
      const path = join(directory, name);
      accessSync(path, constants.X_OK);
      return statSafe(path)?.isFile() ?? false;
    } catch { return false; }
  }),
);

/** One owner per test file. Cleanup cancels and reaps children before touching fixtures. */
export function createQuickScanTestHarness(options: { timeoutMs?: number; killGraceMs?: number } = {}) {
  const dirs: string[] = [];
  const invocations = new Map<AbortController, Promise<unknown>>();
  let cleanupFailure: Error | undefined;
  let cleaning = false;

  async function run(args: string[], onFirstByte?: () => void): Promise<{ stdout: string }> {
    if (cleaning) throw new Error("quick-scan fixture cleanup has already started");
    const outputDir = mkdtempSync(join(tmpdir(), "harvey-quick-child-"));
    dirs.push(outputDir);
    const controller = new AbortController();
    const invocation = (async () => {
      // Spawn-to-close bounds include silent startup; first-byte callbacks let tests measure
      // responsiveness without conflating it with startup. Group teardown has 10s headroom
      // inside the unchanged 120s Vitest deadline, including the guard's acknowledgment bound.
      const result = await runGuardCommand({
        command: [process.execPath, "--import", "tsx", ...args], cwd: REPO_ROOT,
        bundleDir: outputDir, outputPrefix: "scan", timeoutMs: options.timeoutMs ?? 110_000,
        killGraceMs: options.killGraceMs ?? 500, signal: controller.signal, onFirstByte,
      });
      if (!result.terminationAcknowledged) {
        cleanupFailure = new Error(`quick-scan process group did not acknowledge termination; retained ${outputDir}`);
        throw cleanupFailure;
      }
      if (result.state !== "exited" || result.exitCode !== 0 || result.error) {
        throw new Error(`quick-scan ${result.state} (exit ${result.exitCode}, signal ${result.signal}): ${result.error ?? ""}\n${result.stderr.tail}`);
      }
      // Decode the complete byte stream once, preserving characters split across pipe chunks.
      return { stdout: readFileSync(join(outputDir, result.stdout.path), "utf8") };
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
