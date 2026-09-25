import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import { readEntriesSafe } from "./fs-walk.js";
import { productSourceInventoryForTarget, readStaticConfigObject } from "./source-inventory.js";
import { discoverWorkspaceInventory, type WorkspaceInventoryV1 } from "./workspaces.js";
import { detectTestRunner, verifyMutationScope } from "./mutation-scan.js";
import type { Finding } from "./findings.js";

const sourcePattern = /\.(?:[cm]?[jt]sx?|vue|svelte)$/;
const testPattern = /(?:\.(?:test|spec)\.[cm]?[jt]sx?$|(?:^|\/)(?:__tests__|test|tests)\/)/;
const configPattern = /(?:^|\/)(?:[^/]*\.)?(?:config|setup)\.[cm]?[jt]sx?$/;
const strykerPattern = /^stryker(?:\.[^.]+)*\.(?:json|jsonc|[cm]?[jt]s)$/;
const runnerPattern = /^(?:vitest|vite|jest|mocha)\.(?:config|workspace)\.[cm]?[jt]s$|^\.mocharc\./;
const posix = (path: string): string => path.split(sep).join("/");
const within = (root: string, path: string): boolean => {
  const rel = relative(root, path);
  return rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`));
};

export interface MutationWorkspacePlan {
  schemaVersion: 1;
  root: string;
  sourceSha256: string;
  inventory: WorkspaceInventoryV1;
  gaps: string[];
  files: Array<{ path: string; sha256: string; inventoryExcluded?: string }>;
  workspaces: MutationWorkspace[];
}

export interface MutationWorkspace {
  id: string;
  directory: string;
  manifest: string;
  runner: string;
  invocationDirectory: string;
  configurationDirectory: string;
  runnerConfig?: string;
  runnerConfigurations: string[];
  strykerConfigurations: Array<{ path: string; sha256: string; configuredSources: string[]; error?: string }>;
  selectedConfiguration?: string;
  configuration: Record<string, unknown>;
  productionSources: string[];
  configuredSources: string[];
  selectedSources: string[];
  unselectedSources: string[];
  candidateTests: string[];
  relatedTests: { status: "pending" | "not-applicable"; paths: string[]; reason: string };
  gaps: string[];
}

/** Static scope is a census; native runner discovery supplies the actual related-test population. */
export function planMutationWorkspaces(rootInput: string, options: { selection?: readonly string[] } = {}): MutationWorkspacePlan {
  const root = realpathSync(rootInput);
  const inventory = discoverWorkspaceInventory(root);
  const sourceInventory = productSourceInventoryForTarget(root);
  const gaps = inventory.observations.filter(row => row.kind !== "excluded").map(row => JSON.stringify(row));
  gaps.push(...sourceInventory.unresolvedConfigurations.map(row => `${row.path}: ${row.reason}`));
  const files: MutationWorkspacePlan["files"] = [];
  const visited = new Set<string>();
  const walk = (directory: string): void => {
    let physical: string;
    try { physical = realpathSync(directory); } catch { gaps.push(`Unreadable source directory: ${posix(relative(root, directory))}`); return; }
    if (!within(root, physical) || visited.has(physical)) { gaps.push(`Unresolved source directory alias: ${posix(relative(root, directory))}`); return; }
    visited.add(physical);
    let entries: ReturnType<typeof readEntriesSafe>;
    try { entries = readEntriesSafe(directory); } catch { gaps.push(`Unreadable source directory: ${posix(relative(root, directory))}`); return; }
    gaps.push(...entries.dangling.map(name => `Unresolved source link: ${posix(relative(root, join(directory, name)))}`));
    for (const entry of entries.entries) {
      const path = posix(relative(root, entry.path));
      if (path.split("/").some(part => part === "node_modules" || part === ".git")) continue;
      if (entry.isDirectory) walk(entry.path);
      else {
        try {
          if (!within(root, realpathSync(entry.path))) { gaps.push(`Source alias escapes target: ${path}`); continue; }
          const excluded = sourceInventory.exclusionsFor(path).map(row => row.reason).join("; ");
          files.push({ path, sha256: createHash("sha256").update(readFileSync(entry.path)).digest("hex"), ...(excluded ? { inventoryExcluded: excluded } : {}) });
        } catch { gaps.push(`Unreadable source input: ${path}`); }
      }
    }
  };
  walk(root);
  files.sort((a, b) => a.path.localeCompare(b.path));
  const allSource = files.filter(file => sourcePattern.test(file.path) && !/\.d\.[cm]?ts$/.test(file.path));
  const members = [...inventory.packages].sort((a, b) => b.dir.length - a.dir.length);
  const owner = (path: string): string | undefined => members.find(pkg => pkg.dir === "." || path.startsWith(`${pkg.dir}/`))?.id;
  const configFiles = files.filter(file => strykerPattern.test(basename(file.path)));
  const configs = configFiles.map(file => {
    const parsed = readStaticConfigObject(join(root, file.path));
    const directory = posix(dirname(file.path));
    const localSources = allSource.filter(source => within(join(root, directory), join(root, source.path))).map(source => posix(relative(join(root, directory), join(root, source.path))));
    const globs = Array.isArray(parsed.value?.mutate) && parsed.value.mutate.every(item => typeof item === "string") ? parsed.value.mutate as string[] : undefined;
    const scope = verifyMutationScope([], globs, localSources);
    return { file, directory, value: parsed.value, sources: (scope.files ?? []).map(row => posix(join(directory, row.path))), error: parsed.error ?? (!globs ? "No statically readable mutate array" : scope.files === undefined || scope.expectedFileCount === 0 ? scope.note : undefined) };
  });
  const allTests = allSource.filter(file => !file.inventoryExcluded && testPattern.test(file.path)).map(file => file.path);
  const workspaces = inventory.packages.flatMap(pkg => {
    const manifest = JSON.parse(readFileSync(join(root, pkg.manifestPath), "utf8")) as Record<string, unknown>;
    const productionSources = allSource.filter(file => owner(file.path) === pkg.id && !file.inventoryExcluded && !testPattern.test(file.path) && !configPattern.test(file.path)).map(file => file.path);
    const relevantConfigurations = configs.filter(config => config.directory === pkg.dir || config.sources.some(path => owner(path) === pkg.id));
    const localRunner = detectTestRunner(manifest);
    const rootManifest = existsSync(join(root, "package.json")) ? JSON.parse(readFileSync(join(root, "package.json"), "utf8")) : {};
    const groups = new Map<string, typeof configs>();
    const orderedConfigurations = [...relevantConfigurations].sort((a, b) => b.sources.filter(path => owner(path) === pkg.id).length - a.sources.filter(path => owner(path) === pkg.id).length || a.file.path.localeCompare(b.file.path));
    for (const config of orderedConfigurations.filter(row => row.sources.some(path => owner(path) === pkg.id) || (row.error && row.directory === pkg.dir))) {
      const runner = typeof config.value?.testRunner === "string" ? config.value.testRunner : localRunner?.runner ?? detectTestRunner(rootManifest)?.runner ?? "unknown";
      const settings = { ...(config.value?.[runner] as Record<string, unknown> | undefined ?? {}) };
      if (typeof settings.configFile === "string") settings.configFile = posix(join(config.directory, settings.configFile));
      const key = config.error ? config.file.path : JSON.stringify({ runner, directory: config.directory, settings });
      groups.set(key, [...(groups.get(key) ?? []), config]);
    }
    if (!groups.size) groups.set("default", []);
    return [...groups.values()].map((ordered, groupIndex) => {
      const relevant = ordered.length ? ordered : relevantConfigurations;
      const selected = ordered.find(config => config.value && !config.error);
      const configuredSources = [...new Set(relevant.flatMap(config => config.sources).filter(path => owner(path) === pkg.id && !testPattern.test(path)))].sort();
      const runner = typeof selected?.value?.testRunner === "string" ? selected.value.testRunner : localRunner?.runner ?? detectTestRunner(rootManifest)?.runner ?? "unknown";
      const invocationDirectory = selected?.directory ?? (localRunner ? pkg.dir : ".");
      const config = structuredClone(selected?.value ?? { testRunner: runner, plugins: [`@stryker-mutator/${runner}-runner`], coverageAnalysis: "perTest", reporters: ["json"], thresholds: { break: null } });
      const runnerConfigurations = files.filter(file => runnerPattern.test(basename(file.path)) && (dirname(file.path) === pkg.dir || dirname(file.path) === invocationDirectory)).map(file => file.path);
      const runnerOptions = config[runner] as { configFile?: unknown } | undefined;
      const explicitRunnerConfig = typeof runnerOptions?.configFile === "string" ? posix(join(invocationDirectory, runnerOptions.configFile)) : undefined;
      const runnerConfig = explicitRunnerConfig ?? runnerConfigurations.find(path => basename(path).startsWith(`${runner}.config`)) ?? runnerConfigurations.find(path => basename(path).startsWith("vite.config"));
      const candidates = configuredSources.length ? configuredSources : productionSources;
      const selectedSources = options.selection ? candidates.filter(path => options.selection!.includes(path)) : [...candidates];
      const workspaceGaps = relevant.flatMap(row => row.error ? [`${row.file.path}: ${row.error}`] : []);
      if (runner === "vitest" && invocationDirectory !== ".") {
        if (typeof config.tsconfigFile === "string") config.tsconfigFile = posix(join(invocationDirectory, config.tsconfigFile));
        if (typeof config.disableTypeChecks === "string") config.disableTypeChecks = posix(join(invocationDirectory, config.disableTypeChecks));
        if (config.files !== undefined || config.buildCommand !== undefined) workspaceGaps.push("Package-local Stryker files/buildCommand requires an explicit repository-root adaptation; its configured population remains unassessed");
      }
      const excludedConfigured = configuredSources.filter(path => files.find(file => file.path === path)?.inventoryExcluded);
      if (excludedConfigured.length) workspaceGaps.push(`Configured production sources excluded by inventory: ${excludedConfigured.join(", ")}`);
      if (selectedSources.some(path => /\.(?:vue|svelte)$/.test(path))) workspaceGaps.push("Stryker source instrumentation for Vue/Svelte requires target-specific support; these sources remain unassessed");
      return {
        id: groupIndex === 0 ? pkg.id : `${pkg.id}:configuration-${createHash("sha256").update(ordered[0]!.file.path).digest("hex").slice(0, 12)}`, directory: pkg.dir, manifest: pkg.manifestPath, runner, configurationDirectory: invocationDirectory, invocationDirectory: runner === "vitest" ? "." : invocationDirectory, runnerConfigurations,
        ...(runnerConfig ? { runnerConfig } : {}),
        strykerConfigurations: relevant.map(row => ({ path: row.file.path, sha256: row.file.sha256, configuredSources: row.sources.filter(path => owner(path) === pkg.id), ...(row.error ? { error: row.error } : {}) })),
        ...(selected ? { selectedConfiguration: selected.file.path } : {}), configuration: config,
        productionSources, configuredSources, selectedSources,
        unselectedSources: [...new Set([...productionSources, ...configuredSources])].filter(path => !selectedSources.includes(path)),
        candidateTests: allTests.filter(path => owner(path) === pkg.id || (runner !== "unknown" && within(join(root, runnerConfig ? dirname(runnerConfig) : invocationDirectory), join(root, path)))),
        relatedTests: { status: "pending" as const, paths: [], reason: "Native related-test discovery has not executed" }, gaps: workspaceGaps,
      };
    });
  });
  gaps.push(...configs.filter(config => config.error && !workspaces.some(workspace => workspace.strykerConfigurations.some(row => row.path === config.file.path))).map(config => `${config.file.path}: ${config.error}`));
  for (const path of options.selection ?? []) if (!workspaces.some(workspace => workspace.selectedSources.includes(path))) gaps.push(`Requested production source was not assigned to a workspace: ${path}`);
  return { schemaVersion: 1, root, inventory, files, sourceSha256: createHash("sha256").update(JSON.stringify(files)).digest("hex"), gaps, workspaces };
}

export function mutationWorkspaceFinding(workspace: MutationWorkspace, state: string, reason: string): Finding {
  return {
    id: `M8-WORKSPACE-${createHash("sha256").update(workspace.id).digest("hex").slice(0, 12)}`,
    status: "Open", category: "Test quality", severity: "Info", confidence: "N/A",
    title: `Mutation coverage: ${workspace.directory} — ${state}`,
    taxonomy: "M8 — Workspace mutation coverage", location: workspace.manifest,
    evidence: `${reason} Production population: ${workspace.productionSources.length}; configured: ${workspace.configuredSources.length}; selected: ${workspace.selectedSources.length}; candidate test files: ${workspace.candidateTests.length}. Unselected sources: ${workspace.unselectedSources.join(", ") || "none"}.`,
    impact: "This workspace contributes only its observed mutation results; unassessed source and related-test populations remain outside the score.",
    fix: "Use the retained workspace plan, configuration and command receipts to resolve this limitation, then rerun the remaining production population and prove related tests complete.",
    value: 1, ease: 1, safety: 5,
  };
}
