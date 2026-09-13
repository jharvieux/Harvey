import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync, constants, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, isAbsolute, join, resolve } from "node:path";
import type { PackageManager } from "./package-manager.js";

export interface InstallInvocation {
  bin: string;
  /** Selector arguments precede the manager's arguments but are not forwarded to the manager. */
  launcherArgs?: string[];
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
}

export interface SelectedPackageManager {
  launcher: string;
  launcherRealpath: string;
  launcherSha256: string;
  /** The manager entry point actually executed, after Corepack/native-pnpm selection. */
  executable: string;
  executableSha256: string;
  nodeExecutable: string;
  nodeVersion: string;
  version: string;
}

export interface DependencyPreparationStage {
  stage: "version-probe" | "offline" | "frozen" | "legacy" | "tool-install";
  outcome: "completed" | "failed";
  exitCode: number | null;
  signal?: string;
  command: string[];
  selected?: SelectedPackageManager;
  reason?: string;
}

export function matchesSelectedPackageManager(actual: SelectedPackageManager | undefined, expected: SelectedPackageManager | undefined): boolean {
  const fields = ["executable", "executableSha256", "nodeExecutable", "nodeVersion", "version"] as const;
  return actual !== undefined && expected !== undefined && fields.every((field) => actual[field] === expected[field]);
}

// A target-cwd --version is installation SETUP: Corepack and native pnpm may provision a manager
// before forwarding it. Observe the final argv at process exit (Corepack rewrites argv before
// runMain); a pnpm selector's child exits before its launcher. Only manager processes handling
// this exact command are candidates, so an npm lifecycle child is not mistaken for the installer.
const MANAGER_TRACE = String.raw`
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const destination = process.env.HARVEY_MANAGER_TRACE;
process.on("exit", () => {
  try {
    const executable = fs.realpathSync(process.argv[1]);
    let dir = path.dirname(executable);
    for (;;) {
      const manifest = path.join(dir, "package.json");
      if (fs.existsSync(manifest)) {
        const pkg = JSON.parse(fs.readFileSync(manifest, "utf8"));
        if (["npm", "pnpm", "yarn"].includes(pkg.name)) {
          fs.appendFileSync(destination, JSON.stringify({
            manager: pkg.name, version: pkg.version, executable,
            executableSha256: crypto.createHash("sha256").update(fs.readFileSync(executable)).digest("hex"),
            nodeExecutable: fs.realpathSync(process.execPath), nodeVersion: process.version, args: process.argv.slice(2),
          }) + "\n");
          break;
        }
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  } catch { /* Missing observation is rejected by the parent, never inferred as success. */ }
});
`;

function resolveLauncher(bin: string, cwd: string, environment: NodeJS.ProcessEnv): string {
  const candidates = isAbsolute(bin) || bin.includes("/")
    ? [resolve(cwd, bin)]
    : (environment.PATH ?? "").split(delimiter).map((dir) => resolve(cwd, dir, bin));
  for (const candidate of candidates) {
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch { /* Continue PATH resolution without invoking a shell or a selector. */ }
  }
  throw new Error(`${bin} executable was not found in the install PATH`);
}

function failureReason(error: unknown): string {
  const e = error as { message?: string; stdout?: Buffer | string; stderr?: Buffer | string };
  // pnpm writes its concrete ERR_PNPM_* errors to stdout; retaining only stderr loses the cause.
  const output = [e.stdout?.toString(), e.stderr?.toString()].filter(Boolean).join("\n").trim();
  return output.slice(-6000) || e.message || String(error);
}

export function observePackageManager(
  manager: PackageManager,
  stage: DependencyPreparationStage["stage"],
  invocation: InstallInvocation,
  boundSelection?: SelectedPackageManager,
): DependencyPreparationStage {
  const scratch = mkdtempSync(join(tmpdir(), "harvey-manager-observation-"));
  const trace = join(scratch, "trace.jsonl");
  const preload = join(scratch, "observe.cjs");
  const result: DependencyPreparationStage = { stage, outcome: "failed", exitCode: null, command: [invocation.bin, ...(invocation.launcherArgs ?? []), ...invocation.args] };
  try {
    // Run the target-selected entry point directly after setup. Native pnpm otherwise provisions
    // a second manager inside --store-dir, mixing selector state into the portable content store.
    // This binds the target's observed choice; it does not impose a version on other targets.
    const launcher = resolveLauncher(boundSelection?.nodeExecutable ?? invocation.bin, invocation.cwd, invocation.env);
    const args = boundSelection
      ? [boundSelection.executable, ...invocation.args]
      : [...(invocation.launcherArgs ?? []), ...invocation.args];
    const launcherRealpath = realpathSync(launcher);
    const launcherSha256 = createHash("sha256").update(readFileSync(launcherRealpath)).digest("hex");
    result.command = [launcher, ...args];
    writeFileSync(preload, MANAGER_TRACE);
    writeFileSync(trace, "");
    let stdout = "";
    try {
      stdout = execFileSync(launcher, args, {
        cwd: invocation.cwd,
        env: { ...invocation.env, NODE_OPTIONS: `--require ${JSON.stringify(preload)}`, HARVEY_MANAGER_TRACE: trace },
        encoding: "utf8",
        timeout: stage === "version-probe" ? 120_000 : 600_000,
        maxBuffer: 16 * 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
      });
      result.exitCode = 0;
      result.outcome = "completed";
    } catch (error) {
      const failure = error as { status?: number | null; signal?: string };
      result.exitCode = failure.status ?? null;
      result.signal = failure.signal;
      result.reason = failureReason(error);
    }
    const observations = readFileSync(trace, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line) as {
      manager: string; args: string[]; executable: string; executableSha256: string; nodeExecutable: string; nodeVersion: string; version: string;
    });
    const selected = observations.find((row) => row.manager === manager && JSON.stringify(row.args) === JSON.stringify(invocation.args));
    if (selected) {
      result.selected = {
        launcher, launcherRealpath, launcherSha256,
        executable: selected.executable, executableSha256: selected.executableSha256,
        nodeExecutable: selected.nodeExecutable, nodeVersion: selected.nodeVersion, version: selected.version,
      };
    }
    const identityFailure = !selected
      ? `the selected ${manager} executable/version could not be observed after selector provisioning`
      : stage === "version-probe" && result.exitCode === 0 && stdout.trim() !== selected.version
        ? `version-probe output ${JSON.stringify(stdout.trim())} disagrees with the executed ${manager}@${selected.version}`
        : undefined;
    if (identityFailure) {
      result.outcome = "failed";
      result.reason = [result.reason, identityFailure].filter(Boolean).join("; ");
    }
  } catch (error) {
    result.outcome = "failed";
    result.reason = [result.reason, failureReason(error)].filter(Boolean).join("; ");
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  return result;
}

export function selectPackageManager(
  manager: PackageManager,
  cwd: string,
  env: NodeJS.ProcessEnv,
  requestedVersion?: string,
  source: "target-declaration" | "operator-policy" = "target-declaration",
): DependencyPreparationStage[] {
  const invocation = { bin: manager, args: ["--version"], cwd, env };
  // A validated corpus policy selects an exact pnpm without changing either original lock or
  // inventing a packageManager field. Its caller separately rejects a mismatched observation.
  if (source === "operator-policy" && manager === "pnpm" && requestedVersion && /^\d+\.\d+\.\d+$/.test(requestedVersion)) {
    return [observePackageManager(manager, "version-probe", {
      ...invocation, bin: "corepack", launcherArgs: [`pnpm@${requestedVersion}`],
    })];
  }
  const native = observePackageManager(manager, "version-probe", invocation);
  const stages = [native];
  // npm shipped with Node ignores packageManager. Corepack's explicit npm launcher supports
  // the target's exact declaration without installing a global npm or rewriting its manifest.
  // Keep native pnpm/Yarn selection and failed/unobserved setup fail-closed. A successful
  // exact native npm remains usable even when Corepack or its registry is unavailable.
  if (manager === "npm" && requestedVersion && native.outcome === "completed"
    && native.selected && native.selected.version !== requestedVersion.split("+")[0]) {
    stages.push(observePackageManager(manager, "version-probe", {
      ...invocation, bin: "corepack", launcherArgs: [`npm@${requestedVersion}`],
    }));
  }
  return stages;
}

export function describePreparationStages(stages: readonly DependencyPreparationStage[]): string {
  return stages.map((entry) => {
    const identity = entry.selected
      ? `${entry.selected.executable}@${entry.selected.version} (launcher ${entry.selected.launcherRealpath})`
      : `${entry.command[0]} (selected identity unobserved)`;
    return `${entry.stage} ${entry.outcome}, exit ${entry.exitCode ?? "unknown"}${entry.signal ? `, signal ${entry.signal}` : ""}: ${identity}${entry.reason ? `; ${entry.reason}` : ""}`;
  }).join("\n");
}
