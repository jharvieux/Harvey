import { createHash } from "node:crypto";
import { realpath, stat } from "node:fs/promises";
import { delimiter, dirname, isAbsolute, join, relative, sep } from "node:path";
import { type ReadinessPlanV1, type ReadinessStageV1, serializeReadinessPlanV1, validateReadinessPlanV1 } from "./audit-readiness.js";
import { type DisposableTarget, type SourceSentinelV1, verifyRunRoot } from "./disposable-target.js";
import { SecretRegistry } from "./secret-argv.js";

type StageId = ReadinessStageV1["id"];

/** The discovery schema remains unchanged; this binding belongs to execution admission. */
export interface ReadinessPlanBindingV1 {
  schemaVersion: 1;
  planSha256: string;
  source: SourceSentinelV1;
}

export interface ReadinessStageAuthorization {
  stageId: StageId;
  effect: "disposable-local" | "target-install" | "network-or-service" | "unknown";
  source: string;
  reason: string;
  falsifier: string;
}

export interface ReadinessAuthorityOptions {
  allowTargetInstall: boolean;
  /** Supplied by the operator/admission caller, never inferred from target script text. */
  stageAuthorizations: readonly ReadinessStageAuthorization[];
  approvedEnvNames: readonly string[];
  /** Only values whose names are explicitly approved are read from this object. */
  environment: Readonly<Record<string, string | undefined>>;
  /** Absolute, trusted toolchain directories; the target and its dependencies are inadmissible. */
  toolchainPath?: string;
  /** Connect the receipt redactor here before any value reaches a child. */
  registerSecret?: (value: string) => void;
}

export interface ReadinessAdmissionContext {
  readonly plan: ReadinessPlanV1;
  readonly binding: ReadinessPlanBindingV1;
}

export interface ReadinessAuthorityReceipt {
  stageId: StageId;
  decision: "allowed" | "denied";
  effect: ReadinessStageAuthorization["effect"];
  source: string;
  reasonCode: string;
  reason: string;
  falsifier: string;
  requiredEnvNames: string[];
  approvedEnvNames: string[];
  lifecycle: { path: string; pointer: string }[];
}

/** Never serialize the child environment. Its own property is deliberately non-enumerable. */
export interface ReadinessSpawnRequest {
  readonly bin: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly shell: false;
  readonly env: Readonly<Record<string, string>>;
}

export type ReadinessStageAdmission =
  | { status: "admitted"; stageId: StageId; request: ReadinessSpawnRequest; authority: ReadinessAuthorityReceipt }
  | { status: "not-assessed"; stageId: StageId; reasonCode: string; reason: string; falsifier: string; authority: ReadinessAuthorityReceipt };

interface AdmissionState {
  authorizations: Map<StageId, ReadinessStageAuthorization>;
  allowTargetInstall: boolean;
  approvedEnvNames: string[];
  values: Record<string, string>;
  toolchainDirs: string[];
  secrets: SecretRegistry;
  installLifecycle: { path: string; pointer: string }[];
}

const admissions = new WeakMap<ReadinessAdmissionContext, AdmissionState>();
const PROTECTED_NAMES = /^(?:PATH|HOME|USERPROFILE|TMP|TEMP|TMPDIR|CI|LANG|LC_ALL|NO_COLOR|NODE_OPTIONS|NODE_PATH|NODE_V8_COVERAGE|BASH_ENV|ENV|SHELLOPTS|CDPATH|IFS|COMSPEC|PATHEXT|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|XDG_.*|GIT_.*|LD_.*|DYLD_.*|NPM_CONFIG_.*|PNPM_.*|YARN_.*|COREPACK_.*)$/;

function immutable<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const nested of Object.values(value)) immutable(nested);
    Object.freeze(value);
  }
  return value;
}

function sourceEqual(a: SourceSentinelV1, b: SourceSentinelV1): boolean {
  return a.sourceRoot === b.sourceRoot && a.contentSha256 === b.contentSha256 && a.entries === b.entries && a.bytes === b.bytes && JSON.stringify(a.git) === JSON.stringify(b.git);
}

function validateSource(source: SourceSentinelV1): void {
  if (!source || typeof source !== "object" || !source.git || typeof source.git !== "object"
    || Object.keys(source).some((key) => !["schemaVersion", "sourceRoot", "contentSha256", "entries", "bytes", "git"].includes(key))
    || Object.keys(source.git).some((key) => !(source.git.status === "present" ? ["status", "head", "statusSha256"] : ["status"]).includes(key))) {
    throw new Error("Readiness execution requires a valid source sentinel.");
  }
  if (source.schemaVersion !== 1 || !isAbsolute(source.sourceRoot) || !/^[a-f0-9]{64}$/.test(source.contentSha256)
    || !Number.isSafeInteger(source.entries) || source.entries <= 0 || !Number.isSafeInteger(source.bytes) || source.bytes < 0
    || !["present", "absent"].includes(source.git.status)
    || (source.git.status === "present" && (!/^[a-f0-9]{64}$/.test(source.git.statusSha256) || (source.git.head !== null && !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(source.git.head))))) {
    throw new Error("Readiness execution requires a valid source sentinel.");
  }
}

/** Capture the sentinel before discovery and ensure creation returns the same sentinel before admitting work. */
export function bindReadinessPlanV1(plan: ReadinessPlanV1, source: SourceSentinelV1): ReadinessPlanBindingV1 {
  validateSource(source);
  return immutable({ schemaVersion: 1, planSha256: createHash("sha256").update(serializeReadinessPlanV1(plan)).digest("hex"), source: structuredClone(source) });
}

/** Validate/freeze once. Downstream scheduling consumes this exact V1 plan and never rediscovers argv. */
export function createReadinessAdmission(planInput: unknown, bindingInput: ReadinessPlanBindingV1, options: ReadinessAuthorityOptions): ReadinessAdmissionContext {
  const plan = validateReadinessPlanV1(structuredClone(planInput));
  const binding = structuredClone(bindingInput);
  validateSource(binding.source);
  if (Object.keys(binding).some((key) => !["schemaVersion", "planSha256", "source"].includes(key)) || binding.schemaVersion !== 1 || binding.planSha256 !== createHash("sha256").update(serializeReadinessPlanV1(plan)).digest("hex")) {
    throw new Error("Readiness plan no longer matches its execution binding.");
  }
  const stageIds = new Set(plan.stages.map((stage) => stage.id));
  const authorizations = new Map<StageId, ReadinessStageAuthorization>();
  for (const authorization of options.stageAuthorizations) {
    if (!stageIds.has(authorization.stageId) || authorizations.has(authorization.stageId)
      || !["disposable-local", "target-install", "network-or-service", "unknown"].includes(authorization.effect)
      || [authorization.source, authorization.reason, authorization.falsifier].some((text) => typeof text !== "string" || text.trim() === "")) {
      throw new Error("Every execution authorization must name one unique planned stage and retain its effect, source, reason, and falsifier.");
    }
    authorizations.set(authorization.stageId, immutable(structuredClone(authorization)));
  }
  const approvedEnvNames = [...new Set(options.approvedEnvNames)].sort();
  if (approvedEnvNames.some((name) => !/^[A-Z][A-Z0-9_]*$/.test(name) || PROTECTED_NAMES.test(name))) {
    throw new Error("The approved environment contains an invalid name or a protected runtime/toolchain control.");
  }
  const values: Record<string, string> = Object.create(null) as Record<string, string>;
  const secrets = new SecretRegistry();
  for (const name of approvedEnvNames) {
    const value = Object.hasOwn(options.environment, name) ? options.environment[name] : undefined;
    if (value === undefined || value === "") continue;
    if (typeof value !== "string" || value.includes("\0")) throw new Error("An approved environment value is invalid for process execution.");
    values[name] = value;
    secrets.register(value);
    options.registerSecret?.(value);
  }
  const toolchainDirs = [...new Set((options.toolchainPath ?? [dirname(process.execPath), "/usr/bin", "/bin"].join(delimiter)).split(delimiter))];
  if (toolchainDirs.some((path) => !isAbsolute(path) || path.includes("\0"))) throw new Error("The toolchain PATH must contain only explicit absolute directories.");
  const context = immutable({ plan, binding });
  admissions.set(context, { authorizations, allowTargetInstall: options.allowTargetInstall === true, approvedEnvNames, values: Object.freeze(values), toolchainDirs, secrets, installLifecycle: plan.workspaceInventory.packages.flatMap((pkg) => pkg.scripts.filter((script) => ["preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"].includes(script.name)).map((script) => ({ ...script.source }))) });
  return context;
}

function receipt(stage: ReadinessStageV1, state: AdmissionState, requiredEnvNames: string[], authorization?: ReadinessStageAuthorization): ReadinessAuthorityReceipt {
  return {
    stageId: stage.id,
    decision: "denied",
    effect: authorization?.effect ?? "unknown",
    source: authorization?.source ?? "no operator stage authorization",
    reasonCode: "authority-missing",
    reason: "The stage has no explicit execution authorization.",
    falsifier: "Approve this exact bound stage as a disposable local action or the selected target install after reviewing its effects.",
    requiredEnvNames: [...requiredEnvNames],
    approvedEnvNames: [...state.approvedEnvNames],
    lifecycle: stage.kind === "install" ? state.installLifecycle.map((row) => ({ ...row })) : stage.provenance.flatMap((row) => row.kind === "manifest-script" && row.pointer && /\/scripts\/(?:preinstall|install|postinstall|prepare)$/.test(row.pointer) ? [{ path: row.path, pointer: row.pointer }] : []),
  };
}

function denied(authority: ReadinessAuthorityReceipt, reasonCode: string, reason: string, falsifier: string): ReadinessStageAdmission {
  return { status: "not-assessed", stageId: authority.stageId, reasonCode, reason, falsifier, authority: { ...authority, decision: "denied", reasonCode, reason, falsifier } };
}

function within(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`));
}

function childEnvironment(root: string, path: string, values: Record<string, string>): Record<string, string> {
  return Object.assign(Object.create(null) as Record<string, string>, {
    PATH: path,
    HOME: join(root, "home"),
    TMPDIR: join(root, "tmp"),
    TMP: join(root, "tmp"),
    TEMP: join(root, "tmp"),
    XDG_CACHE_HOME: join(root, "cache"),
    XDG_CONFIG_HOME: join(root, "home", ".config"),
    XDG_DATA_HOME: join(root, "home", ".local", "share"),
    CI: "1",
    NO_COLOR: "1",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    npm_config_cache: join(root, "cache", "npm"),
    npm_config_prefix: join(root, "home", "npm-global"),
    npm_config_userconfig: join(root, "home", ".npmrc"),
    npm_config_globalconfig: join(root, "home", ".npmrc-global"),
    npm_config_store_dir: join(root, "cache", "pnpm"),
    npm_config_update_notifier: "false",
    npm_config_audit: "false",
    npm_config_fund: "false",
    PNPM_HOME: join(root, "home", "pnpm"),
    COREPACK_HOME: join(root, "cache", "corepack"),
    COREPACK_ENABLE_DOWNLOAD_PROMPT: "0",
    COREPACK_ENABLE_NETWORK: "0",
    GIT_CEILING_DIRECTORIES: root,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: join(root, "home", ".gitconfig"),
    GIT_TERMINAL_PROMPT: "0",
    YARN_CACHE_FOLDER: join(root, "cache", "yarn"),
    YARN_GLOBAL_FOLDER: join(root, "cache", "yarn-global"),
    YARN_ENABLE_GLOBAL_CACHE: "false",
  }, values);
}

export async function admitReadinessStage(context: ReadinessAdmissionContext, stageId: StageId, target: DisposableTarget): Promise<ReadinessStageAdmission> {
  const state = admissions.get(context);
  if (!state) throw new Error("Unknown readiness admission context.");
  const stage = context.plan.stages.find((candidate) => candidate.id === stageId);
  if (!stage) throw new Error("Unknown readiness stage identity.");
  const authorization = state.authorizations.get(stage.id);
  const covered = context.plan.stages.filter((row) => row.assessment === "implicit" && row.fulfilledByStageId === stage.id);
  const requiredEnvNames = [...new Set([stage, ...covered].flatMap((row) => row.requiredEnvNames))].sort();
  const authority = receipt(stage, state, requiredEnvNames, authorization);
  if (stage.assessment !== "planned") return denied(authority, stage.assessment === "implicit" ? "covered-by-install-lifecycle" : stage.reasonCode, stage.reason, stage.falsifier);
  if (!authorization) return denied(authority, authority.reasonCode, authority.reason, authority.falsifier);
  if (authorization.effect === "network-or-service" || authorization.effect === "unknown") {
    return denied(authority, "effect-not-authorized", "Possible network/service effects or unknown effects are outside this execution authority.", "Supply a separate existing authority covering the external effect, or establish that this exact stage performs only disposable local work.");
  }
  if (stage.kind === "install") {
    if (covered.some((row) => ["network-or-service", "unknown"].includes(state.authorizations.get(row.id)?.effect ?? "covered-by-install"))) {
      return denied(authority, "lifecycle-effect-not-authorized", "An install-covered lifecycle stage has unknown or external effects outside target-install authority.", "Resolve the lifecycle effect review before authorizing the parent install.");
    }
    if (!state.allowTargetInstall || authorization.effect !== "target-install") return denied(authority, "target-install-not-authorized", "Install and its declared lifecycle scripts require the existing explicit target-install grant.", "Authorize the selected disposable install with --allow-target-install and a stage-specific target-install effect review.");
    if (context.plan.packageManager.status !== "selected" || !context.plan.packageManager.lockfile) return denied(authority, "lockfile-required", "Execution cannot substitute a non-lockfile install for a selected lockfile installation.", "Retain one supported lockfile and rediscover and bind the plan before approving installation.");
  } else if (authorization.effect !== "disposable-local") {
    return denied(authority, "effect-scope-mismatch", "The target-install grant does not authorize a separate package script.", "Approve the bound script separately after establishing disposable local effects.");
  }
  if (!sourceEqual(context.binding.source, target.sourceBefore)) return denied(authority, "source-binding-mismatch", "The target copy does not match the source root, content, or Git state bound to this readiness plan.", "Capture, discover, and bind a new plan from the exact current source before creating the disposable target.");
  const missing = requiredEnvNames.filter((name) => !state.approvedEnvNames.includes(name) || !Object.hasOwn(state.values, name));
  if (missing.length) return denied(authority, "required-environment-missing", `Required environment names are not approved and present: ${missing.join(", ")}.`, "Provide nonempty values for every required name through the operator-approved environment allowlist.");
  const root = await verifyRunRoot(target, stage.command.cwd);
  if (root.status !== "verified") return denied(authority, root.reasonCode, root.reason, root.falsifier);
  let toolchain: string[];
  try {
    toolchain = await Promise.all(state.toolchainDirs.map(async (path) => {
      const resolved = await realpath(path);
      if (!(await stat(resolved)).isDirectory()) throw new Error("not a toolchain directory");
      return resolved;
    }));
    if (toolchain.some((path) => within(target.sourceRoot, path) || within(target.root, path))) throw new Error("untrusted toolchain directory");
  } catch {
    return denied(authority, "toolchain-path-invalid", "The toolchain PATH is unavailable or resolves into source/disposable target content.", "Provide existing trusted toolchain directories outside both the original and disposable target roots.");
  }
  const argv = [stage.command.bin, ...stage.command.args];
  try {
    if (argv.some((arg) => arg.includes("\0"))) throw new Error("invalid argv");
    state.secrets.assertArgvClean("readiness admission", argv);
    // The shared registry has a historical length floor; this boundary also covers short admitted values.
    if (Object.values(state.values).some((value) => argv.some((arg) => arg.includes(value)))) throw new Error("approved value appears in argv");
  } catch {
    return denied(authority, "unsafe-argv", "The command contains an invalid argument or an approved environment value; it cannot be spawned safely.", "Keep approved values exclusively in the child environment and retain only clean tokenized plan argv.");
  }
  const request = { bin: stage.command.bin, args: Object.freeze([...stage.command.args]), cwd: root.cwd, shell: false as const } as ReadinessSpawnRequest;
  Object.defineProperty(request, "env", { value: Object.freeze(childEnvironment(target.root, toolchain.join(delimiter), state.values)), enumerable: false });
  return {
    status: "admitted",
    stageId: stage.id,
    request: Object.freeze(request),
    authority: { ...authority, decision: "allowed", reasonCode: stage.kind === "install" ? "target-install-authorized" : "disposable-local-authorized", reason: authorization.reason, falsifier: authorization.falsifier },
  };
}
