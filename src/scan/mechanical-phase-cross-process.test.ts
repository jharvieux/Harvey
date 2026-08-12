import { execFile, execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

interface ProcessResult {
  phases: Record<string, string>;
  events: string[];
}

const execFileAsync = promisify(execFile);

describe("mechanical phase cache across real process and checkout boundaries (#1864)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it("misses cold, then hits every deterministic phase from a separate process at a different checkout path", async () => {
    const fixture = mkdtempSync(join(tmpdir(), "harvey-phase-process-"));
    dirs.push(fixture);
    const repoA = join(fixture, "checkout-a");
    const repoB = join(fixture, "checkout-b");
    symlinkSync(process.cwd(), repoA, "dir");
    symlinkSync(process.cwd(), repoB, "dir");
    const target = join(fixture, "target");
    const cacheDir = join(fixture, "cache");
    const binDir = join(fixture, "bin");
    mkdirSync(binDir);
    const semgrep = join(binDir, "semgrep");
    writeFileSync(semgrep, '#!/bin/sh\nprintf \'%s\\n\' \'{"version":"fixture","results":[],"errors":[],"paths":{"scanned":[],"skipped":[]}}\'\n');
    chmodSync(semgrep, 0o755);
    mkdirSync(join(target, "src"), { recursive: true });
    writeFileSync(join(target, "package.json"), `${JSON.stringify({ name: "phase-process-fixture", private: true })}\n`);
    writeFileSync(join(target, "src", "route.ts"), "export function route(tenantId: string) { console.log(tenantId); return { tenantId }; }\n");
    execFileSync("git", ["init", "-q", target]);
    execFileSync("git", ["-C", target, "config", "user.email", "phase-cache@example.test"]);
    execFileSync("git", ["-C", target, "config", "user.name", "Phase Cache Test"]);
    execFileSync("git", ["-C", target, "add", "."]);
    execFileSync("git", ["-C", target, "commit", "-qm", "fixture"]);

    const registries = Array.from({ length: 6 }, (_, index) => {
      const registry = join(fixture, `fixed-registry-${index + 1}.yml`);
      writeFileSync(registry, [
        "rules:",
        `  - id: phase-cache-cross-process-${index + 1}`,
        "    languages: [typescript]",
        "    message: fixed local registry control",
        "    severity: WARNING",
        "    pattern: console.log(...)",
        "",
      ].join("\n"));
      return registry;
    });

    const runner = join(fixture, "run-phase-cache.mts");
    const identityModule = pathToFileURL(join(process.cwd(), "src", "scan", "mechanical-phase-identity.ts")).href;
    const cacheModule = pathToFileURL(join(process.cwd(), "src", "scan", "mechanical-phase-cache.ts")).href;
    const mechanicalModule = pathToFileURL(join(process.cwd(), "src", "scan", "mechanical.ts")).href;
    writeFileSync(runner, `
import { buildMechanicalPhaseCache } from ${JSON.stringify(identityModule)};
import { resolveGitTree } from ${JSON.stringify(cacheModule)};
import { runMechanicalScanDetailed } from ${JSON.stringify(mechanicalModule)};
const [repoRoot, cacheDir, target, ...registries] = process.argv.slice(2);
async function main(): Promise<void> {
  const events: string[] = [];
  const phaseCache = buildMechanicalPhaseCache({
    repoRoot,
    cacheDir,
    mode: "read-write",
    targetRevision: "fixed-target-revision",
    targetTree: resolveGitTree(target),
    optionIdentity: JSON.stringify({ skipNetworkChecks: true, skipBundleScan: true }),
    registryPackIdentity: { identity: "fixed-local-registry-v1", files: registries },
    onEvent: (message) => events.push(message),
  });
  // This test isolates whole-phase transport across processes. Family partitioning has its own
  // cross-checks; keeping it enabled here would launch twelve redundant Semgrep child processes.
  delete phaseCache.semgrepFamilies;
  const result = await runMechanicalScanDetailed({
    dir: target,
    skipNetworkChecks: true,
    skipBundleScan: true,
    phaseCache,
  });
  console.log("PHASE_PROCESS_RESULT=" + JSON.stringify({ phases: Object.fromEntries(result.phases.map((phase) => [phase.phase, phase.cache])), events }));
}
void main();
`);

    const run = async (repoRoot: string): Promise<ProcessResult> => {
      const { stdout: output } = await execFileAsync("pnpm", ["exec", "tsx", runner, repoRoot, cacheDir, target, ...registries], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: { ...process.env, NO_COLOR: "1", PATH: `${binDir}:${process.env.PATH ?? ""}` },
        maxBuffer: 1024 * 1024 * 8,
        timeout: 120_000,
      });
      const marker = output.split("\n").find((line) => line.startsWith("PHASE_PROCESS_RESULT="));
      if (!marker) throw new Error(`child process emitted no phase result: ${output}`);
      return JSON.parse(marker.slice("PHASE_PROCESS_RESULT=".length)) as ProcessResult;
    };

    const cold = await run(repoA);
    const warm = await run(repoB);
    expect(cold.phases).toMatchObject({ semgrep: "miss", configuration: "miss", "structural-ast": "miss" });
    expect(warm.phases).toMatchObject({ semgrep: "hit", configuration: "hit", "structural-ast": "hit" });
    expect(warm.events.filter((event) => event.startsWith("CACHE HIT"))).toHaveLength(3);
  });
});
