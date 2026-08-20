// Audit-readiness discovery is planning only. It reads retained target manifests/configuration,
// emits tokenized package-manager wrappers, and deliberately has no process-execution dependency.

import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join, posix } from "node:path";
import {
  installAllCommand,
  type PackageManager,
  type PackageManagerEvidenceSource,
  type PackageManagerResolution,
  resolvePackageManagerEvidence,
  runPackageScriptCommand,
} from "./package-manager.js";
import {
  discoverWorkspaceInventory,
  type WorkspaceId,
  type WorkspaceInventoryPackage,
  type WorkspaceInventoryV1,
  workspaceIdForDir,
} from "./workspaces.js";

const READINESS_PLAN_SCHEMA_VERSION = 1 as const;
export const READINESS_STAGE_KINDS = ["install", "codegen", "build", "typecheck", "lint", "test"] as const;
export type ReadinessStageKind = (typeof READINESS_STAGE_KINDS)[number];
type ReadinessStageId = `stage:${WorkspaceId}:${ReadinessStageKind}`;

type ReadinessSafetyClassification =
  | "executes-install-lifecycle"
  | "executes-target-script"
  | "covered-by-install-lifecycle"
  | "non-executable";

interface ReadinessProvenanceV1 {
  kind: "manifest-script" | "supported-config" | "package-manager-evidence" | "workspace-observation";
  path: string;
  pointer?: string;
  detail: string;
  /** A package script is evidence text only. It is never parsed into command argv. */
  rawScript?: string;
}

interface ReadinessCommandV1 {
  bin: PackageManager;
  args: string[];
  /** Repository-relative POSIX directory; "." is the repository root. */
  cwd: string;
  source: {
    kind: "package-manager-install" | "package-manager-script";
    path: string;
    pointer?: string;
  };
}

interface ReadinessStageBaseV1 {
  id: ReadinessStageId;
  kind: ReadinessStageKind;
  workspaceId: WorkspaceId;
  prerequisiteStageIds: ReadinessStageId[];
  safety: ReadinessSafetyClassification;
  requiredEnvNames: string[];
  provenance: ReadinessProvenanceV1[];
}

export type ReadinessStageV1 =
  | (ReadinessStageBaseV1 & {
      assessment: "planned";
      command: ReadinessCommandV1;
    })
  | (ReadinessStageBaseV1 & {
      assessment: "implicit";
      fulfilledByStageId: ReadinessStageId;
      reason: string;
      falsifier: string;
    })
  | (ReadinessStageBaseV1 & {
      assessment: "absent";
      reasonCode: "missing-script-and-config" | "placeholder-script";
      reason: string;
      falsifier: string;
    })
  | (ReadinessStageBaseV1 & {
      assessment: "not-assessed";
      reasonCode: "package-manager-not-selected" | "supported-config-without-script" | "unreadable-config" | "unreadable-manifest" | "ambiguous-scripts";
      reason: string;
      falsifier: string;
    });

export interface ReadinessWorkspaceV1 {
  id: WorkspaceId;
  dir: string;
  manifestPath: string;
  name?: string;
  installStageId: ReadinessStageId;
  /** Exactly one effective row for every stage kind; install may be shared. */
  stageIds: ReadinessStageId[];
  provenance: ReadinessProvenanceV1[];
}

export interface ReadinessPlanV1 {
  schemaVersion: 1;
  kind: "harvey-audit-readiness-plan";
  workspaceInventory: WorkspaceInventoryV1;
  packageManager: PackageManagerResolution;
  workspaces: ReadinessWorkspaceV1[];
  stages: ReadinessStageV1[];
}

const SCRIPT_NAMES: Record<Exclude<ReadinessStageKind, "install">, readonly string[]> = {
  codegen: ["codegen", "generate", "gen", "prisma:generate", "db:generate"],
  build: ["build"],
  typecheck: ["typecheck", "type-check", "check:types"],
  lint: ["lint"],
  test: ["test"],
};

const SUPPORTED_CONFIGS: Record<Exclude<ReadinessStageKind, "install">, readonly string[]> = {
  codegen: [
    "prisma/schema.prisma",
    "drizzle.config.ts",
    "drizzle.config.js",
    "codegen.ts",
    "codegen.yml",
    "codegen.yaml",
    "graphql.config.ts",
    "graphql.config.js",
    "openapi-generator-config.json",
  ],
  build: ["next.config.js", "next.config.mjs", "next.config.ts", "vite.config.js", "vite.config.ts", "webpack.config.js", "tsup.config.ts"],
  typecheck: ["tsconfig.json"],
  lint: ["eslint.config.js", "eslint.config.mjs", "eslint.config.ts", ".eslintrc", ".eslintrc.json", ".eslintrc.js"],
  test: ["vitest.config.js", "vitest.config.ts", "jest.config.js", "jest.config.ts"],
};

// Deliberately bounded to a whole, directly supported lifecycle command. This is evidence
// recognition, not shell tokenization: compound/quoted/echoed bodies remain unknown rather than
// being promoted to a codegen dependency from a plausible substring.
const CODEGEN_LIFECYCLE = /^\s*(?:prisma\s+generate|graphql-codegen|drizzle-kit\s+generate|openapi-generator(?:-cli)?(?:\s+generate)?|(?:npm|pnpm|yarn)\s+(?:run\s+)?(?:codegen|generate|gen|prisma:generate|db:generate))(?:\s+[^;&|]*)?\s*$/i;
const PLACEHOLDER_TEST = /no test specified/i;
const ENV_REFERENCE = /(?:\b(?:process\.env\.|import\.meta\.env\.)([A-Z][A-Z0-9_]*)|\$\{([A-Z][A-Z0-9_]*)\}|\$([A-Z][A-Z0-9_]*)|%([A-Z][A-Z0-9_]*)%)/g;

export function readinessStageId(workspaceId: WorkspaceId, kind: ReadinessStageKind): ReadinessStageId {
  return `stage:${workspaceId}:${kind}`;
}

function requiredEnvNames(texts: readonly string[]): string[] {
  const names = new Set<string>();
  for (const text of texts) {
    ENV_REFERENCE.lastIndex = 0;
    for (let match = ENV_REFERENCE.exec(text); match; match = ENV_REFERENCE.exec(text)) {
      const name = match.slice(1).find((candidate): candidate is string => typeof candidate === "string");
      if (name) names.add(name);
    }
  }
  return [...names].sort();
}

function mergedEnvNames(...sets: readonly string[][]): string[] {
  return [...new Set(sets.flat())].sort();
}

function provenanceKey(row: ReadinessProvenanceV1): string {
  return `${row.kind}\0${row.path}\0${row.pointer ?? ""}\0${row.detail}\0${row.rawScript ?? ""}`;
}

function normalizedProvenance(rows: readonly ReadinessProvenanceV1[]): ReadinessProvenanceV1[] {
  return [...rows].sort((a, b) => provenanceKey(a).localeCompare(provenanceKey(b)));
}

function manifestScriptProvenance(pkg: WorkspaceInventoryPackage, name: string, body: string): ReadinessProvenanceV1 {
  const script = pkg.scripts.find((candidate) => candidate.name === name);
  return {
    kind: "manifest-script",
    path: pkg.manifestPath,
    pointer: script?.source.pointer ?? `/scripts/${name.replaceAll("~", "~0").replaceAll("/", "~1")}`,
    detail: `package script ${name}`,
    rawScript: body,
  };
}

function configEvidence(repoRoot: string, pkg: WorkspaceInventoryPackage, kind: Exclude<ReadinessStageKind, "install">): {
  rows: ReadinessProvenanceV1[];
  envNames: string[];
  unreadable: string[];
} {
  const rows: ReadinessProvenanceV1[] = [];
  const texts: string[] = [];
  const unreadable: string[] = [];
  for (const rel of SUPPORTED_CONFIGS[kind]) {
    const path = pkg.dir === "." ? rel : posix.join(pkg.dir, rel);
    const absolute = join(repoRoot, ...path.split("/"));
    if (!existsSync(absolute)) continue;
    rows.push({ kind: "supported-config", path, detail: `${kind} configuration` });
    try {
      texts.push(readFileSync(absolute, "utf8"));
    } catch {
      unreadable.push(path);
    }
  }
  return { rows, envNames: requiredEnvNames(texts), unreadable };
}

function scriptMap(pkg: WorkspaceInventoryPackage): Map<string, string> {
  return new Map(pkg.scripts.map((script) => [script.name, script.body]));
}

function managerProvenance(resolution: PackageManagerResolution): ReadinessProvenanceV1[] {
  return resolution.evidence.map((source) => ({
    kind: "package-manager-evidence",
    path: source.path,
    ...(source.kind === "package-manager-field" ? { pointer: "/packageManager" } : {}),
    detail: source.kind === "lockfile"
      ? `${source.manager ?? "unknown"} lockfile`
      : `packageManager declaration${source.requestedVersion ? ` ${source.manager}@${source.requestedVersion}` : ""}`,
  }));
}

function installStage(
  pkg: WorkspaceInventoryPackage,
  resolution: PackageManagerResolution,
  manifestProblem?: { path: string; reason: string },
): ReadinessStageV1 {
  const id = readinessStageId(workspaceIdForDir("."), "install");
  const scripts = scriptMap(pkg);
  const lifecycle = ["preinstall", "install", "postinstall"]
    .flatMap((name) => scripts.has(name) ? [[name, scripts.get(name)!] as const] : []);
  const provenance = normalizedProvenance([
    ...managerProvenance(resolution),
    ...(manifestProblem ? [{ kind: "workspace-observation" as const, path: manifestProblem.path, detail: manifestProblem.reason }] : []),
    ...lifecycle.map(([name, body]) => manifestScriptProvenance(pkg, name, body)),
  ]);
  const base: ReadinessStageBaseV1 = {
    id,
    kind: "install",
    workspaceId: workspaceIdForDir("."),
    prerequisiteStageIds: [],
    safety: resolution.status === "selected" ? "executes-install-lifecycle" : "non-executable",
    requiredEnvNames: requiredEnvNames(lifecycle.map(([, body]) => body)),
    provenance,
  };
  if (resolution.status === "selected") {
    const command = installAllCommand(resolution.manager);
    return {
      ...base,
      assessment: "planned",
      command: {
        bin: resolution.manager,
        args: command.args,
        cwd: ".",
        source: { kind: "package-manager-install", path: resolution.lockfile ?? "package.json", ...(resolution.lockfile ? {} : { pointer: "/packageManager" }) },
      },
    };
  }
  return {
    ...base,
    assessment: "not-assessed",
    reasonCode: "package-manager-not-selected",
    reason: `${resolution.reason}: ${resolution.detail}`,
    falsifier: "Add one supported, non-conflicting lockfile or exact package.json#packageManager declaration and rediscover the plan.",
  };
}

function nonInstallStage(
  repoRoot: string,
  pkg: WorkspaceInventoryPackage,
  kind: Exclude<ReadinessStageKind, "install">,
  resolution: PackageManagerResolution,
  installId: ReadinessStageId,
  codegenId?: ReadinessStageId,
  manifestProblem?: { path: string; reason: string },
): ReadinessStageV1 {
  const id = readinessStageId(pkg.id, kind);
  const scripts = scriptMap(pkg);
  const prerequisites = [installId];
  if (codegenId && ["build", "typecheck", "test"].includes(kind)) prerequisites.push(codegenId);

  if (manifestProblem) {
    return {
      id,
      kind,
      workspaceId: pkg.id,
      prerequisiteStageIds: prerequisites,
      safety: "non-executable",
      requiredEnvNames: [],
      provenance: [{ kind: "workspace-observation", path: manifestProblem.path, detail: manifestProblem.reason }],
      assessment: "not-assessed",
      reasonCode: "unreadable-manifest",
      reason: `workspace manifest could not be used for ${kind} discovery: ${manifestProblem.reason}`,
      falsifier: "Provide a readable package.json for this workspace and rediscover the plan.",
    };
  }

  const config = configEvidence(repoRoot, pkg, kind);

  const postinstall = scripts.get("postinstall");
  const matchingScriptNames = SCRIPT_NAMES[kind].filter((name) => scripts.has(name));
  if (kind === "codegen" && postinstall && CODEGEN_LIFECYCLE.test(postinstall)) {
    return {
      id,
      kind,
      workspaceId: pkg.id,
      prerequisiteStageIds: [installId],
      safety: "covered-by-install-lifecycle",
      requiredEnvNames: mergedEnvNames(requiredEnvNames([postinstall]), config.envNames),
      provenance: normalizedProvenance([
        manifestScriptProvenance(pkg, "postinstall", postinstall),
        ...matchingScriptNames.map((name) => manifestScriptProvenance(pkg, name, scripts.get(name)!)),
        ...config.rows,
      ]),
      assessment: "implicit",
      fulfilledByStageId: installId,
      reason: "a supported generator is invoked by postinstall and therefore runs as part of the planned install stage",
      falsifier: "Remove the supported generator invocation from postinstall and rediscover the plan.",
    };
  }

  const scriptName = matchingScriptNames[0];
  const scriptBody = scriptName ? scripts.get(scriptName)! : undefined;
  const provenance = normalizedProvenance([
    ...(scriptName && scriptBody ? [manifestScriptProvenance(pkg, scriptName, scriptBody)] : []),
    ...config.rows,
  ]);
  const envNames = mergedEnvNames(requiredEnvNames(scriptBody ? [scriptBody] : []), config.envNames);
  const base: ReadinessStageBaseV1 = {
    id,
    kind,
    workspaceId: pkg.id,
    prerequisiteStageIds: prerequisites,
    safety: "non-executable",
    requiredEnvNames: envNames,
    provenance,
  };

  if (config.unreadable.length) {
    return {
      ...base,
      assessment: "not-assessed",
      reasonCode: "unreadable-config",
      reason: `supported ${kind} configuration could not be read: ${config.unreadable.join(", ")}`,
      falsifier: "Make every cited configuration readable and rediscover the plan.",
    };
  }
  if (matchingScriptNames.length > 1) {
    return {
      ...base,
      provenance: normalizedProvenance([
        ...matchingScriptNames.map((name) => manifestScriptProvenance(pkg, name, scripts.get(name)!)),
        ...config.rows,
      ]),
      requiredEnvNames: mergedEnvNames(...matchingScriptNames.map((name) => requiredEnvNames([scripts.get(name)!])), config.envNames),
      assessment: "not-assessed",
      reasonCode: "ambiguous-scripts",
      reason: `multiple supported ${kind} scripts exist and no target evidence declares one canonical entry: ${matchingScriptNames.join(", ")}`,
      falsifier: `Retain one canonical ${kind} script or add a supported lifecycle/config declaration that resolves the ambiguity, then rediscover the plan.`,
    };
  }
  if (scriptName && scriptBody && kind === "test" && PLACEHOLDER_TEST.test(scriptBody)) {
    return {
      ...base,
      assessment: "absent",
      reasonCode: "placeholder-script",
      reason: "package.json#scripts.test is the npm-init placeholder, not an ordinary test command",
      falsifier: "Replace the placeholder with an ordinary test script and rediscover the plan.",
    };
  }
  if (scriptName && scriptBody && resolution.status !== "selected") {
    return {
      ...base,
      assessment: "not-assessed",
      reasonCode: "package-manager-not-selected",
      reason: `script ${scriptName} exists but package-manager resolution is ${resolution.reason}`,
      falsifier: "Resolve package-manager evidence and rediscover the plan.",
    };
  }
  if (scriptName && scriptBody && resolution.status === "selected") {
    const command = runPackageScriptCommand(resolution.manager, scriptName);
    return {
      ...base,
      safety: "executes-target-script",
      assessment: "planned",
      command: {
        ...command,
        cwd: pkg.dir,
        source: { kind: "package-manager-script", path: pkg.manifestPath, pointer: provenance.find((row) => row.kind === "manifest-script")?.pointer },
      },
    };
  }
  if (config.rows.length) {
    return {
      ...base,
      assessment: "not-assessed",
      reasonCode: "supported-config-without-script",
      reason: `supported ${kind} configuration exists but no supported package script names the target command`,
      falsifier: `Add one supported ${kind} package script and rediscover the plan.`,
    };
  }
  return {
    ...base,
    assessment: "absent",
    reasonCode: "missing-script-and-config",
    reason: `no supported ${kind} package script or configuration was found`,
    falsifier: `Add a supported ${kind} script or configuration and rediscover the plan.`,
  };
}

function workspaceProvenance(pkg: WorkspaceInventoryPackage): ReadinessProvenanceV1[] {
  return normalizedProvenance(pkg.discoveredBy.map((source) => ({
    kind: "workspace-observation",
    path: source.sourcePath,
    detail: source.kind === "root-manifest" ? "repository root manifest" : `workspace glob ${source.glob ?? ""}`,
  })));
}

function normalizedInventory(inventory: WorkspaceInventoryV1): WorkspaceInventoryV1 {
  return {
    ...inventory,
    packages: [...inventory.packages]
      .map((pkg) => ({
        ...pkg,
        scripts: [...pkg.scripts].sort((a, b) => a.name.localeCompare(b.name)),
        discoveredBy: [...pkg.discoveredBy].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
      }))
      .sort((a, b) => a.id.localeCompare(b.id)),
    applicationWorkspaceIds: [...inventory.applicationWorkspaceIds].sort(),
    observations: [...inventory.observations].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
  };
}

function normalizedPlan(plan: ReadinessPlanV1): ReadinessPlanV1 {
  const stageOrder = (id: string): number => {
    const kind = READINESS_STAGE_KINDS.find((candidate) => id.endsWith(`:${candidate}`));
    return kind ? READINESS_STAGE_KINDS.indexOf(kind) : READINESS_STAGE_KINDS.length;
  };
  return {
    ...plan,
    workspaceInventory: normalizedInventory(plan.workspaceInventory),
    workspaces: [...plan.workspaces]
      .map((workspace) => ({
        ...workspace,
        stageIds: [...workspace.stageIds].sort((a, b) => stageOrder(a) - stageOrder(b) || a.localeCompare(b)),
        provenance: normalizedProvenance(workspace.provenance),
      }))
      .sort((a, b) => a.id.localeCompare(b.id)),
    stages: [...plan.stages]
      .map((stage) => ({
        ...stage,
        prerequisiteStageIds: [...stage.prerequisiteStageIds].sort(),
        requiredEnvNames: [...new Set(stage.requiredEnvNames)].sort(),
        provenance: normalizedProvenance(stage.provenance),
      }))
      .sort((a, b) => a.id.localeCompare(b.id)),
  };
}

export function discoverReadinessPlan(repoRoot: string, inventory = discoverWorkspaceInventory(repoRoot)): ReadinessPlanV1 {
  if (inventory.schemaVersion !== 1) throw new Error(`Unsupported workspace inventory schema: ${String(inventory.schemaVersion)}`);
  const packageManager = resolvePackageManagerEvidence(repoRoot);
  const rootPackage = inventory.packages.find((pkg) => pkg.id === workspaceIdForDir(".")) ?? {
    id: workspaceIdForDir("."),
    dir: ".",
    manifestPath: "package.json",
    scripts: [],
    discoveredBy: [],
  };
  const installId = readinessStageId(workspaceIdForDir("."), "install");
  const manifestProblems = new Map(inventory.observations
    .filter((observation) => observation.kind === "unreadable-manifest")
    .map((observation) => [observation.path, observation]));
  const stages: ReadinessStageV1[] = [installStage(rootPackage, packageManager, manifestProblems.get(rootPackage.manifestPath))];

  const workspaces: ReadinessWorkspaceV1[] = [];
  for (const pkg of inventory.packages) {
    const codegenId = readinessStageId(pkg.id, "codegen");
    const manifestProblem = manifestProblems.get(pkg.manifestPath);
    const codegen = nonInstallStage(repoRoot, pkg, "codegen", packageManager, installId, undefined, manifestProblem);
    const packageStages: ReadinessStageV1[] = [
      codegen,
      nonInstallStage(repoRoot, pkg, "build", packageManager, installId, codegen.assessment === "absent" ? undefined : codegenId, manifestProblem),
      nonInstallStage(repoRoot, pkg, "typecheck", packageManager, installId, codegen.assessment === "absent" ? undefined : codegenId, manifestProblem),
      nonInstallStage(repoRoot, pkg, "lint", packageManager, installId, undefined, manifestProblem),
      nonInstallStage(repoRoot, pkg, "test", packageManager, installId, codegen.assessment === "absent" ? undefined : codegenId, manifestProblem),
    ];
    stages.push(...packageStages);
    workspaces.push({
      id: pkg.id,
      dir: pkg.dir,
      manifestPath: pkg.manifestPath,
      ...(pkg.name ? { name: pkg.name } : {}),
      installStageId: installId,
      stageIds: [installId, ...packageStages.map((stage) => stage.id)],
      provenance: workspaceProvenance(pkg),
    });
  }

  const plan = normalizedPlan({
    schemaVersion: READINESS_PLAN_SCHEMA_VERSION,
    kind: "harvey-audit-readiness-plan",
    workspaceInventory: inventory,
    packageManager,
    workspaces,
    stages,
  });
  return validateReadinessPlanV1(plan);
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function canonicalRelativePath(value: unknown): value is string {
  if (typeof value !== "string" || value === "" || value.includes("\\") || isAbsolute(value) || posix.isAbsolute(value)) return false;
  if (value === ".") return true;
  const segments = value.split("/");
  return segments.every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

function assertStringArray(value: unknown, label: string): asserts value is string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) throw new Error(`${label} must be a string array`);
}

function assertExactKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const extras = Object.keys(value).filter((key) => !allowed.includes(key));
  if (extras.length) throw new Error(`${label} carries unknown field(s): ${extras.sort().join(", ")}`);
}

function validateProvenance(value: unknown, label: string): asserts value is ReadinessProvenanceV1[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  for (const [index, candidate] of value.entries()) {
    if (!record(candidate)) throw new Error(`${label}[${index}] must be an object`);
    assertExactKeys(candidate, ["kind", "path", "pointer", "detail", "rawScript"], `${label}[${index}]`);
    if (!["manifest-script", "supported-config", "package-manager-evidence", "workspace-observation"].includes(String(candidate.kind))) {
      throw new Error(`${label}[${index}] has an unknown provenance kind`);
    }
    if (!canonicalRelativePath(candidate.path) || typeof candidate.detail !== "string" || candidate.detail === "") {
      throw new Error(`${label}[${index}] needs a canonical path and detail`);
    }
    if (candidate.pointer !== undefined && typeof candidate.pointer !== "string") throw new Error(`${label}[${index}] pointer must be a string`);
    if (candidate.rawScript !== undefined && (candidate.kind !== "manifest-script" || typeof candidate.rawScript !== "string")) {
      throw new Error(`${label}[${index}] rawScript is allowed only for manifest-script evidence`);
    }
  }
}

function validatePackageManagerResolution(value: unknown): asserts value is PackageManagerResolution {
  if (!record(value) || !Array.isArray(value.evidence)) throw new Error("Readiness plan packageManager is invalid");
  const supportedManagers = ["npm", "pnpm", "yarn"] as const;
  const exactVersion = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
  if (value.status === "selected") {
    assertExactKeys(value, ["status", "manager", "requestedVersion", "lockfile", "evidence"], "selected packageManager");
    if (!(supportedManagers as readonly unknown[]).includes(value.manager)) throw new Error("selected packageManager has an unsupported manager");
    if (value.requestedVersion !== undefined && (typeof value.requestedVersion !== "string" || !exactVersion.test(value.requestedVersion))) {
      throw new Error("selected packageManager requestedVersion is invalid");
    }
    if (value.lockfile !== undefined && !canonicalRelativePath(value.lockfile)) throw new Error("selected packageManager lockfile is invalid");
  } else if (value.status === "not-assessed") {
    assertExactKeys(value, ["status", "reason", "detail", "evidence"], "not-assessed packageManager");
    if (!["missing-evidence", "conflicting-evidence", "unsupported-manager", "unsupported-version", "unreadable-manifest"].includes(String(value.reason))) {
      throw new Error("not-assessed packageManager reason is invalid");
    }
    if (typeof value.detail !== "string" || value.detail === "") throw new Error("not-assessed packageManager detail is invalid");
  } else {
    throw new Error("Readiness plan packageManager status is invalid");
  }
  const evidenceKeys = new Set<string>();
  for (const [index, candidate] of value.evidence.entries()) {
    if (!record(candidate)) throw new Error(`packageManager.evidence[${index}] must be an object`);
    assertExactKeys(candidate, ["kind", "path", "manager", "requestedVersion", "raw"], `packageManager.evidence[${index}]`);
    if (!["lockfile", "package-manager-field"].includes(String(candidate.kind)) || !canonicalRelativePath(candidate.path)) {
      throw new Error(`packageManager.evidence[${index}] is invalid`);
    }
    if (candidate.manager !== undefined && !(supportedManagers as readonly unknown[]).includes(candidate.manager)) {
      throw new Error(`packageManager.evidence[${index}] has an unsupported manager`);
    }
    if (candidate.requestedVersion !== undefined && (typeof candidate.requestedVersion !== "string" || !exactVersion.test(candidate.requestedVersion))) {
      throw new Error(`packageManager.evidence[${index}] has an invalid requestedVersion`);
    }
    if (candidate.raw !== undefined && typeof candidate.raw !== "string") throw new Error(`packageManager.evidence[${index}] raw must be a string`);
    if (candidate.kind === "lockfile") {
      const expectedManager = ({
        "npm-shrinkwrap.json": "npm",
        "package-lock.json": "npm",
        "pnpm-lock.yaml": "pnpm",
        "yarn.lock": "yarn",
      } as Record<string, PackageManager>)[String(candidate.path)];
      if (!expectedManager || candidate.manager !== expectedManager || candidate.requestedVersion !== undefined || candidate.raw !== undefined) {
        throw new Error(`packageManager.evidence[${index}] is malformed lockfile evidence`);
      }
    } else if (candidate.path !== "package.json" || typeof candidate.raw !== "string") {
      throw new Error(`packageManager.evidence[${index}] is malformed packageManager-field evidence`);
    }
    const evidenceKey = JSON.stringify(candidate);
    if (evidenceKeys.has(evidenceKey)) throw new Error(`packageManager.evidence[${index}] is duplicated`);
    evidenceKeys.add(evidenceKey);
  }
  if (value.status === "selected") {
    const selected = value as unknown as Extract<PackageManagerResolution, { status: "selected" }>;
    if (!selected.evidence.some((source: PackageManagerEvidenceSource) => source.manager === selected.manager)) {
      throw new Error("selected packageManager is detached from its evidence");
    }
    if (selected.lockfile !== undefined && !selected.evidence.some((source: PackageManagerEvidenceSource) => source.kind === "lockfile" && source.path === selected.lockfile && source.manager === selected.manager)) {
      throw new Error("selected packageManager lockfile is detached from its evidence");
    }
    if (selected.requestedVersion !== undefined && !selected.evidence.some((source: PackageManagerEvidenceSource) => source.kind === "package-manager-field" && source.manager === selected.manager && source.requestedVersion === selected.requestedVersion)) {
      throw new Error("selected packageManager version is detached from its evidence");
    }
  }
}

function validateWorkspaceInventory(value: unknown): { ids: Set<string>; packages: Map<string, WorkspaceInventoryPackage> } {
  if (!record(value) || value.schemaVersion !== 1) throw new Error("Readiness plan workspaceInventory must be schema 1");
  assertExactKeys(value, ["schemaVersion", "repoRootId", "declarationSource", "packages", "applicationWorkspaceIds", "observations"], "workspaceInventory");
  if (value.repoRootId !== "workspace:root" || typeof value.declarationSource !== "string" || value.declarationSource === "") throw new Error("workspaceInventory root/source is invalid");
  if (!Array.isArray(value.packages) || !Array.isArray(value.observations)) throw new Error("workspaceInventory packages/observations must be arrays");
  assertStringArray(value.applicationWorkspaceIds, "workspaceInventory.applicationWorkspaceIds");
  const ids = new Set<string>();
  const packages = new Map<string, WorkspaceInventoryPackage>();
  for (const [index, candidate] of value.packages.entries()) {
    if (!record(candidate)) throw new Error(`workspaceInventory.packages[${index}] must be an object`);
    assertExactKeys(candidate, ["id", "dir", "manifestPath", "name", "scripts", "discoveredBy"], `workspaceInventory.packages[${index}]`);
    if (typeof candidate.id !== "string" || ids.has(candidate.id) || !canonicalRelativePath(candidate.dir) || candidate.id !== workspaceIdForDir(candidate.dir)) {
      throw new Error(`workspaceInventory package ${String(candidate.id)} has a duplicate or non-canonical identity`);
    }
    const expectedManifest = candidate.dir === "." ? "package.json" : `${candidate.dir}/package.json`;
    if (candidate.manifestPath !== expectedManifest || (candidate.name !== undefined && typeof candidate.name !== "string")) {
      throw new Error(`workspaceInventory package ${candidate.id} has invalid manifest metadata`);
    }
    if (!Array.isArray(candidate.scripts) || !Array.isArray(candidate.discoveredBy)) throw new Error(`workspaceInventory package ${candidate.id} lacks evidence arrays`);
    const scriptNames = new Set<string>();
    for (const [scriptIndex, script] of candidate.scripts.entries()) {
      if (!record(script) || typeof script.name !== "string" || scriptNames.has(script.name) || typeof script.body !== "string" || !record(script.source)) {
        throw new Error(`workspaceInventory package ${candidate.id} has invalid or duplicate script evidence`);
      }
      assertExactKeys(script, ["name", "body", "source"], `workspaceInventory package ${candidate.id} scripts[${scriptIndex}]`);
      assertExactKeys(script.source, ["path", "pointer"], `workspaceInventory package ${candidate.id} scripts[${scriptIndex}].source`);
      const expectedPointer = `/scripts/${script.name.replaceAll("~", "~0").replaceAll("/", "~1")}`;
      if (script.name === "" || script.source.path !== candidate.manifestPath || script.source.pointer !== expectedPointer) {
        throw new Error(`workspaceInventory package ${candidate.id} has detached script provenance`);
      }
      scriptNames.add(script.name);
    }
    if (candidate.discoveredBy.length === 0) throw new Error(`workspaceInventory package ${candidate.id} lacks discovery provenance`);
    const discoveryKeys = new Set<string>();
    for (const [sourceIndex, source] of candidate.discoveredBy.entries()) {
      if (!record(source)) throw new Error(`workspaceInventory package ${candidate.id} discoveredBy[${sourceIndex}] must be an object`);
      assertExactKeys(source, ["kind", "sourcePath", "sourceField", "glob"], `workspaceInventory package ${candidate.id} discoveredBy[${sourceIndex}]`);
      if (!["root-manifest", "workspace-glob"].includes(String(source.kind)) || typeof source.sourcePath !== "string" || source.sourcePath === "") {
        throw new Error(`workspaceInventory package ${candidate.id} has invalid discovery provenance`);
      }
      if (!["root", "packages", "workspaces", "workspaces.packages"].includes(String(source.sourceField))) {
        throw new Error(`workspaceInventory package ${candidate.id} has an invalid discovery source field`);
      }
      if (source.kind === "root-manifest") {
        if (candidate.id !== "workspace:root" || source.sourcePath !== "package.json" || source.sourceField !== "root" || source.glob !== undefined) {
          throw new Error(`workspaceInventory package ${candidate.id} has malformed root discovery provenance`);
        }
      } else if (typeof source.glob !== "string" || source.glob === "" || source.glob.startsWith("!")) {
        throw new Error(`workspaceInventory package ${candidate.id} has malformed workspace-glob provenance`);
      }
      const sourceKey = JSON.stringify(source);
      if (discoveryKeys.has(sourceKey)) throw new Error(`workspaceInventory package ${candidate.id} repeats discovery provenance`);
      discoveryKeys.add(sourceKey);
    }
    ids.add(candidate.id);
    packages.set(candidate.id, candidate as unknown as WorkspaceInventoryPackage);
  }
  if (!ids.has("workspace:root")) throw new Error("workspaceInventory must contain the readable repository root exactly once");
  const negativelyExcludedIds = new Set<string>();
  for (const [index, observation] of value.observations.entries()) {
    if (!record(observation) || typeof observation.kind !== "string" || typeof observation.reason !== "string") {
      throw new Error(`workspaceInventory.observations[${index}] is invalid`);
    }
    if (observation.reason === "") throw new Error(`workspaceInventory.observations[${index}] lacks a reason`);
    if (observation.kind === "excluded") {
      assertExactKeys(observation, ["kind", "path", "glob", "sourcePath", "reason"], `workspaceInventory.observations[${index}]`);
      const observationPath = typeof observation.path === "string" ? observation.path : undefined;
      const excludedDir = observationPath === "package.json" ? "." : observationPath?.endsWith("/package.json") ? observationPath.slice(0, -"/package.json".length) : undefined;
      if (!observationPath || !excludedDir || !canonicalRelativePath(observationPath) || typeof observation.glob !== "string" || observation.glob === "" || typeof observation.sourcePath !== "string" || observation.sourcePath === "" || !["implicit-directory-policy", "negative-workspace-glob"].includes(observation.reason)) {
        throw new Error(`workspaceInventory.observations[${index}] has malformed exclusion evidence`);
      }
      if (observation.reason === "negative-workspace-glob") negativelyExcludedIds.add(workspaceIdForDir(excludedDir));
    } else if (observation.kind === "unresolved-glob" || observation.kind === "invalid-glob") {
      assertExactKeys(observation, ["kind", "glob", "sourcePath", "reason"], `workspaceInventory.observations[${index}]`);
      if (typeof observation.glob !== "string" || observation.glob === "" || typeof observation.sourcePath !== "string" || observation.sourcePath === "") {
        throw new Error(`workspaceInventory.observations[${index}] has malformed glob evidence`);
      }
    } else if (observation.kind === "unreadable-manifest") {
      assertExactKeys(observation, ["kind", "path", "reason"], `workspaceInventory.observations[${index}]`);
      if (!canonicalRelativePath(observation.path)) throw new Error(`workspaceInventory.observations[${index}] path is not canonical`);
    } else {
      throw new Error(`workspaceInventory.observations[${index}] has an unknown kind`);
    }
  }
  if (new Set(value.applicationWorkspaceIds).size !== value.applicationWorkspaceIds.length
    || value.applicationWorkspaceIds.some((id) => !ids.has(id) && !negativelyExcludedIds.has(id))) {
    throw new Error("workspaceInventory applicationWorkspaceIds must be unique package ids or evidenced negative-glob app ids");
  }
  return { ids, packages };
}

/** Runtime validator used at the producer/consumer boundary; claimed TypeScript types are not proof. */
export function validateReadinessPlanV1(value: unknown): ReadinessPlanV1 {
  if (!record(value)) throw new Error("Readiness plan must be an object");
  assertExactKeys(value, ["schemaVersion", "kind", "workspaceInventory", "packageManager", "workspaces", "stages"], "readiness plan");
  if (value.schemaVersion !== READINESS_PLAN_SCHEMA_VERSION) throw new Error(`Unsupported readiness plan schemaVersion: ${String(value.schemaVersion)}`);
  if (value.kind !== "harvey-audit-readiness-plan") throw new Error("Readiness plan kind is invalid");
  const inventory = validateWorkspaceInventory(value.workspaceInventory);
  validatePackageManagerResolution(value.packageManager);
  const packageManager = value.packageManager;
  if (!Array.isArray(value.workspaces) || !Array.isArray(value.stages)) throw new Error("Readiness plan workspaces and stages must be arrays");

  const workspaces = value.workspaces as unknown[];
  const stages = value.stages as unknown[];
  const workspaceIds = new Set<string>();
  for (const [index, candidate] of workspaces.entries()) {
    if (!record(candidate)) throw new Error(`workspaces[${index}] must be an object`);
    assertExactKeys(candidate, ["id", "dir", "manifestPath", "name", "installStageId", "stageIds", "provenance"], `workspaces[${index}]`);
    if (typeof candidate.id !== "string" || workspaceIds.has(candidate.id)) throw new Error(`duplicate or invalid workspace id: ${String(candidate.id)}`);
    if (!canonicalRelativePath(candidate.dir) || candidate.id !== workspaceIdForDir(candidate.dir)) throw new Error(`workspace ${candidate.id} has a non-canonical dir/id`);
    if (!canonicalRelativePath(candidate.manifestPath)) throw new Error(`workspace ${candidate.id} has a non-relative manifestPath`);
    if (candidate.name !== undefined && typeof candidate.name !== "string") throw new Error(`workspace ${candidate.id} has an invalid name`);
    const inventoryPackage = inventory.packages.get(candidate.id);
    if (!inventoryPackage || candidate.dir !== inventoryPackage.dir || candidate.manifestPath !== inventoryPackage.manifestPath || candidate.name !== inventoryPackage.name) {
      throw new Error(`workspace ${candidate.id} is detached from workspaceInventory metadata`);
    }
    if (typeof candidate.installStageId !== "string") throw new Error(`workspace ${candidate.id} has an invalid installStageId`);
    assertStringArray(candidate.stageIds, `workspace ${candidate.id} stageIds`);
    validateProvenance(candidate.provenance, `workspace ${candidate.id} provenance`);
    workspaceIds.add(candidate.id);
  }
  if (workspaceIds.size !== inventory.ids.size || [...workspaceIds].some((id) => !inventory.ids.has(id))) {
    throw new Error("readiness workspaces must be set-equal to workspaceInventory packages");
  }

  const stageIds = new Set<string>();
  const stageRows = new Map<string, Record<string, unknown>>();
  for (const [index, candidate] of stages.entries()) {
    if (!record(candidate)) throw new Error(`stages[${index}] must be an object`);
    const commonKeys = ["id", "kind", "workspaceId", "prerequisiteStageIds", "safety", "requiredEnvNames", "provenance", "assessment"];
    if (candidate.assessment === "planned") assertExactKeys(candidate, [...commonKeys, "command"], `stage ${String(candidate.id)}`);
    else if (candidate.assessment === "implicit") assertExactKeys(candidate, [...commonKeys, "fulfilledByStageId", "reason", "falsifier"], `stage ${String(candidate.id)}`);
    else if (candidate.assessment === "absent" || candidate.assessment === "not-assessed") assertExactKeys(candidate, [...commonKeys, "reasonCode", "reason", "falsifier"], `stage ${String(candidate.id)}`);
    if (typeof candidate.id !== "string" || stageIds.has(candidate.id)) throw new Error(`duplicate or invalid stage id: ${String(candidate.id)}`);
    if (typeof candidate.workspaceId !== "string" || (!workspaceIds.has(candidate.workspaceId) && candidate.workspaceId !== "workspace:root")) {
      throw new Error(`stage ${candidate.id} references unknown workspace ${String(candidate.workspaceId)}`);
    }
    if (!READINESS_STAGE_KINDS.includes(candidate.kind as ReadinessStageKind)) throw new Error(`stage ${candidate.id} has unknown kind ${String(candidate.kind)}`);
    if (candidate.id !== readinessStageId(candidate.workspaceId as WorkspaceId, candidate.kind as ReadinessStageKind)) throw new Error(`stage ${candidate.id} has a non-canonical identity`);
    assertStringArray(candidate.prerequisiteStageIds, `stage ${candidate.id} prerequisiteStageIds`);
    if (new Set(candidate.prerequisiteStageIds).size !== candidate.prerequisiteStageIds.length) throw new Error(`stage ${candidate.id} repeats a prerequisite`);
    assertStringArray(candidate.requiredEnvNames, `stage ${candidate.id} requiredEnvNames`);
    if (new Set(candidate.requiredEnvNames).size !== candidate.requiredEnvNames.length) throw new Error(`stage ${candidate.id} repeats an environment name`);
    if (candidate.requiredEnvNames.some((name) => !/^[A-Z][A-Z0-9_]*$/.test(name))) throw new Error(`stage ${candidate.id} has an invalid environment name`);
    validateProvenance(candidate.provenance, `stage ${candidate.id} provenance`);
    if (!["planned", "implicit", "absent", "not-assessed"].includes(String(candidate.assessment))) throw new Error(`stage ${candidate.id} has an invalid assessment`);
    if (candidate.assessment === "planned") {
      if (!record(candidate.command) || !canonicalRelativePath(candidate.command.cwd)) throw new Error(`planned stage ${candidate.id} needs a canonical relative cwd`);
      assertExactKeys(candidate.command, ["bin", "args", "cwd", "source"], `stage ${candidate.id} command`);
      if (!(["npm", "pnpm", "yarn"] as unknown[]).includes(candidate.command.bin)) throw new Error(`planned stage ${candidate.id} has an unsupported command bin`);
      assertStringArray(candidate.command.args, `stage ${candidate.id} command args`);
      if (!record(candidate.command.source) || !canonicalRelativePath(candidate.command.source.path)) throw new Error(`planned stage ${candidate.id} lacks command provenance`);
      assertExactKeys(candidate.command.source, ["kind", "path", "pointer"], `stage ${candidate.id} command source`);
      if (candidate.command.source.pointer !== undefined && typeof candidate.command.source.pointer !== "string") throw new Error(`planned stage ${candidate.id} has an invalid source pointer`);
      if (packageManager.status !== "selected" || candidate.command.bin !== packageManager.manager) throw new Error(`planned stage ${candidate.id} is detached from selected package-manager evidence`);
      if (candidate.kind === "install") {
        const expected = installAllCommand(packageManager.manager);
        const expectedSourcePath = packageManager.lockfile ?? "package.json";
        const expectedPointer = packageManager.lockfile ? undefined : "/packageManager";
        if (
          candidate.command.source.kind !== "package-manager-install"
          || candidate.command.source.path !== expectedSourcePath
          || candidate.command.source.pointer !== expectedPointer
          || candidate.command.cwd !== "."
          || JSON.stringify(candidate.command.args) !== JSON.stringify(expected.args)
          || !(candidate.provenance as unknown[]).some((row) => record(row) && row.kind === "package-manager-evidence" && row.path === expectedSourcePath)
        ) {
          throw new Error(`install stage ${candidate.id} does not match retained package-manager evidence`);
        }
      } else {
        const pkg = inventory.packages.get(String(candidate.workspaceId));
        const pointer = candidate.command.source.pointer;
        const sourcePath = candidate.command.source.path;
        const script = pkg?.scripts.find((entry) => entry.source.pointer === pointer);
        if (
          candidate.command.source.kind !== "package-manager-script"
          || sourcePath !== pkg?.manifestPath
          || candidate.command.cwd !== pkg?.dir
          || !script
          || JSON.stringify(candidate.command.args) !== JSON.stringify(["run", script.name])
          || !(candidate.provenance as unknown[]).some((row) => record(row) && row.kind === "manifest-script" && row.path === sourcePath && row.pointer === pointer)
        ) {
          throw new Error(`planned stage ${candidate.id} command is not backed by its cited package script`);
        }
      }
    } else if ("command" in candidate) {
      throw new Error(`non-planned stage ${candidate.id} must not carry a command`);
    }
    if (candidate.assessment === "implicit" && typeof candidate.fulfilledByStageId !== "string") {
      throw new Error(`implicit stage ${candidate.id} needs a fulfilledByStageId`);
    }
    if (candidate.assessment === "absent" && !["missing-script-and-config", "placeholder-script"].includes(String(candidate.reasonCode))) {
      throw new Error(`absent stage ${candidate.id} has an invalid reasonCode`);
    }
    if (candidate.assessment === "not-assessed" && !["package-manager-not-selected", "supported-config-without-script", "unreadable-config", "unreadable-manifest", "ambiguous-scripts"].includes(String(candidate.reasonCode))) {
      throw new Error(`not-assessed stage ${candidate.id} has an invalid reasonCode`);
    }
    const expectedSafety = candidate.assessment === "planned"
      ? (candidate.kind === "install" ? "executes-install-lifecycle" : "executes-target-script")
      : candidate.assessment === "implicit" ? "covered-by-install-lifecycle" : "non-executable";
    if (candidate.safety !== expectedSafety) throw new Error(`stage ${candidate.id} safety classification is inconsistent`);
    if (candidate.assessment !== "planned" && (typeof candidate.reason !== "string" || candidate.reason === "" || typeof candidate.falsifier !== "string" || candidate.falsifier === "")) {
      throw new Error(`non-planned stage ${candidate.id} needs a reason and falsifier`);
    }
    stageIds.add(candidate.id);
    stageRows.set(candidate.id, candidate);
  }

  for (const candidate of stages) {
    const stage = candidate as Record<string, unknown>;
    for (const prerequisite of stage.prerequisiteStageIds as string[]) {
      if (!stageIds.has(prerequisite)) throw new Error(`stage ${stage.id} has dangling prerequisite ${prerequisite}`);
      if (prerequisite === stage.id) throw new Error(`stage ${stage.id} depends on itself`);
    }
    if (stage.assessment === "implicit" && (!stageIds.has(String(stage.fulfilledByStageId)) || !(stage.prerequisiteStageIds as string[]).includes(String(stage.fulfilledByStageId)))) {
      throw new Error(`implicit stage ${stage.id} must depend on its fulfilledByStageId`);
    }
  }

  const sharedInstallId = readinessStageId(workspaceIdForDir("."), "install");
  if (!stageIds.has(sharedInstallId)) throw new Error("readiness plan lacks the shared install stage");
  for (const candidate of stages) {
    const stage = candidate as Record<string, unknown>;
    const kind = stage.kind as ReadinessStageKind;
    const workspaceId = stage.workspaceId as WorkspaceId;
    const expectedPrerequisites: string[] = kind === "install" ? [] : [sharedInstallId];
    if (["build", "typecheck", "test"].includes(kind)) {
      const codegen = stageRows.get(readinessStageId(workspaceId, "codegen"));
      if (codegen && codegen.assessment !== "absent") expectedPrerequisites.push(String(codegen.id));
    }
    if (JSON.stringify([...(stage.prerequisiteStageIds as string[])].sort()) !== JSON.stringify(expectedPrerequisites.sort())) {
      throw new Error(`stage ${String(stage.id)} has prerequisites inconsistent with its workspace DAG`);
    }
    if (stage.assessment === "implicit" && stage.fulfilledByStageId !== sharedInstallId) {
      throw new Error(`implicit stage ${String(stage.id)} is not fulfilled by the shared install stage`);
    }
  }

  for (const candidate of workspaces) {
    const workspace = candidate as Record<string, unknown>;
    const ids = workspace.stageIds as string[];
    if (ids.length !== READINESS_STAGE_KINDS.length || new Set(ids).size !== ids.length) throw new Error(`workspace ${workspace.id} must reference exactly one stage per kind`);
    const kinds = ids.map((id) => stageRows.get(id)?.kind);
    if (READINESS_STAGE_KINDS.some((kind) => !kinds.includes(kind))) throw new Error(`workspace ${workspace.id} is missing a stage kind`);
    for (const id of ids) {
      const row = stageRows.get(id);
      if (!row) throw new Error(`workspace ${workspace.id} references unknown stage ${id}`);
      if (row.kind !== "install" && row.workspaceId !== workspace.id) throw new Error(`workspace ${workspace.id} borrows another workspace's ${String(row.kind)} stage`);
    }
    if (workspace.installStageId !== readinessStageId(workspaceIdForDir("."), "install") || !ids.includes(String(workspace.installStageId))) {
      throw new Error(`workspace ${workspace.id} does not reference the shared install stage`);
    }
  }
  const referencedStageIds = new Set(workspaces.flatMap((candidate) => (candidate as Record<string, unknown>).stageIds as string[]));
  if (referencedStageIds.size !== stageIds.size || [...stageIds].some((id) => !referencedStageIds.has(id))) {
    throw new Error("readiness plan contains an unreferenced stage");
  }

  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (id: string): void => {
    if (visiting.has(id)) throw new Error(`readiness stage DAG contains a cycle at ${id}`);
    if (visited.has(id)) return;
    visiting.add(id);
    for (const prerequisite of stageRows.get(id)?.prerequisiteStageIds as string[] ?? []) visit(prerequisite);
    visiting.delete(id);
    visited.add(id);
  };
  for (const id of stageIds) visit(id);
  return value as unknown as ReadinessPlanV1;
}

function canonicalJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalJsonValue);
  if (!record(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().flatMap((key) => value[key] === undefined ? [] : [[key, canonicalJsonValue(value[key])]]));
}

export function serializeReadinessPlanV1(plan: ReadinessPlanV1): string {
  const normalized = normalizedPlan(plan);
  validateReadinessPlanV1(normalized);
  return JSON.stringify(canonicalJsonValue(normalized), null, 2);
}
