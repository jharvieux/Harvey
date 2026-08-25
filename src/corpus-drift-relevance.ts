import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { posix, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { TextDecoder } from "node:util";
import ts from "typescript";

/**
 * The production entry points frozen by the #1870 consumer census. This is an entry-point
 * contract, not a detector/scanner registry: detector ownership continues to come from the live
 * mechanical registries through `CorpusInputOwnership.producers`.
 */
export const CORPUS_DRIFT_RUNTIME_ROOTS = Object.freeze([
  "src/cli/corpus-drift.ts",
  "src/cli/corpus-pins.ts",
  "src/cli/materialize-current-semgrep.ts",
  "src/cli/mutation-scan.ts",
  "src/cli/quality-scan.ts",
  "src/cli/quick-scan.ts",
  "src/cli/replay-current-mechanical.ts",
  "src/cli/static-detect.ts",
  "src/cli/validate-current-mechanical-readiness.ts",
] as const);

const CORPUS_DRIFT_WORKFLOW = ".github/workflows/corpus-drift.yml";

export interface CorpusProducerOwnership {
  producer: string;
  phase: string;
  order: number;
  module: string;
  registryFile: string;
}

export interface CorpusTargetSelection {
  /** Sorted pinned-target identities selected by this real production consumer. */
  targets: readonly string[];
  applicability: string;
  provenance: string;
  falsifier: string;
}

export interface CorpusConsumerInputOwnership {
  consumer: string;
  /** The runtime roots this consumer owns. Across all rows these must equal the nine-root contract. */
  runtimeRoots: readonly string[];
  targetSelection: CorpusTargetSelection;
}

/** One data/config/tool input supplied by C2/C3 rather than rediscovered as a second registry. */
export interface CorpusRegisteredInputOwnership {
  consumer: string;
  path: string;
  targetSelection: CorpusTargetSelection;
}

/** The exact C3 discovery result accepted by C1's adapter boundary. */
export interface MechanicalCorpusOwnershipDiscovery {
  schema: 1;
  producers: readonly CorpusProducerOwnership[];
}

/**
 * The one canonical join between runtime reachability and discovery-produced ownership.
 *
 * `producers` accepts the exact rows returned by C3's `discoverMechanicalCorpusOwnership()`.
 * They are retained as provenance and validated here; C1 never invents detector ids or a parallel
 * scanner map. `nonImportInputs` is the injection seam for C2's registered data inputs.
 */
export interface CorpusInputOwnership {
  schema: 1;
  consumers: readonly CorpusConsumerInputOwnership[];
  nonImportInputs: readonly CorpusRegisteredInputOwnership[];
  producers: readonly CorpusProducerOwnership[];
  workflowCommandTargetSelection: CorpusTargetSelection;
}

type CorpusRelevanceReasonCode =
  | "owned-input-change"
  | "workflow-discovery-input-change"
  | "unknown-runtime-input"
  | "non-git-root"
  | "dirty-root"
  | "head-mismatch"
  | "git-command-failed"
  | "unreadable-input"
  | "nonliteral-dynamic-edge"
  | "unresolved-runtime-edge"
  | "symlink-seam"
  | "gitlink-seam"
  | "malformed-source"
  | "malformed-diff"
  | "registry-conflict"
  | "workflow-command-missing";

export interface CorpusRelevanceReason {
  code: CorpusRelevanceReasonCode;
  detail: string;
  path?: string;
  consumer?: string;
}

export interface CorpusGitProof {
  root: string;
  gitRoot: string;
  base: string;
  baseTree: string;
  head: string;
  headTree: string;
  checkedOutHead: string;
  clean: true;
  statusSha256: string;
}

interface CorpusRuntimeEdge {
  from: string;
  to: string;
  kind: "import" | "export" | "import-equals" | "dynamic-import" | "require";
  specifier: string;
  position: number;
}

interface CorpusClosureGroup {
  roots: readonly string[];
  files: readonly { path: string; object: string }[];
  edges: readonly CorpusRuntimeEdge[];
  digest: string;
}

export interface CorpusClosureSnapshot {
  commit: string;
  tree: string;
  roots: readonly string[];
  files: readonly { path: string; object: string }[];
  edges: readonly CorpusRuntimeEdge[];
  consumers: readonly { consumer: string; files: readonly string[] }[];
  nonImportInputs: readonly { consumer: string; path: string; object: string }[];
  /** The D0-frozen nine-root implementation graph, independently countable from workflow commands. */
  runtimeRootClosure: CorpusClosureGroup;
  /** Literal src/cli commands discovered from the exact corpus workflow bytes, never a producer map. */
  workflowCommandClosure: CorpusClosureGroup;
  uncertainties: readonly CorpusRelevanceReason[];
  digest: string;
}

export interface CorpusChangedPath {
  status: "A" | "C" | "D" | "M" | "R" | "T" | "U" | "X" | "B";
  score?: number;
  oldPath?: string;
  newPath?: string;
}

export interface CorpusTargetSelectionReceipt extends CorpusTargetSelection {
  consumer: string;
  changedInputs: readonly string[];
}

export interface CorpusDriftRelevanceReceipt {
  schema: 1;
  kind: "corpus-drift-relevance";
  decision: "full-scan" | "declared-no-op";
  assessment:
    | { status: "full-scan-required"; unitsAssessed: 0; statement: string }
    | { status: "nothing-assessed"; unitsAssessed: 0; statement: string };
  git: CorpusGitProof | null;
  changed: readonly CorpusChangedPath[];
  closure: { base: CorpusClosureSnapshot; head: CorpusClosureSnapshot } | null;
  closureDigest: string | null;
  ownershipDigest: string;
  targetSelections: readonly CorpusTargetSelectionReceipt[];
  hostedBackstop: {
    mode: "required-full-pinned-corpus";
    statement: string;
  };
  reasons: readonly CorpusRelevanceReason[];
}

interface ClassifyCorpusDriftRelevanceOptions {
  repoRoot: string;
  base: string;
  head?: string;
  ownership: CorpusInputOwnership;
  workflowPath?: string;
}

interface GitTreeEntry {
  mode: string;
  type: "blob" | "tree" | "commit";
  object: string;
  path: string;
}

interface GitSnapshot {
  commit: string;
  tree: string;
  entries: ReadonlyMap<string, GitTreeEntry>;
}

interface GitResult {
  status: number;
  stdout: Buffer;
  stderr: string;
}

interface ValidatedOwnership {
  consumers: readonly CorpusConsumerInputOwnership[];
  nonImportInputs: readonly CorpusRegisteredInputOwnership[];
  producers: readonly CorpusProducerOwnership[];
  workflowCommandTargetSelection: CorpusTargetSelection;
  digest: string;
  reasons: CorpusRelevanceReason[];
}

interface MutableClosure {
  snapshot: CorpusClosureSnapshot;
  pathsByConsumer: Map<string, Set<string>>;
  workflowRoots: string[];
}

const UTF8 = new TextDecoder("utf-8", { fatal: true });
const GIT_OBJECT = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/;
const SOURCE_FILE = /\.(?:[cm]?[jt]sx?)$/;
const UNKNOWN_RUNTIME_NAMESPACE = /^(?:src|tools)(?:\/|$)/;
const UNKNOWN_RUNTIME_ROOT_FILE = /^(?:package\.json|pnpm-lock\.yaml|pnpm-workspace\.yaml|\.nvmrc|tsconfig(?:\.[^/]+)?\.json)$/;

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left), Buffer.from(right));
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort(compareUtf8).map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(",")}}`;
}

function digest(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

function safeDigest(value: unknown): string {
  try {
    return digest(value);
  } catch {
    return createHash("sha256").update(String(value)).digest("hex");
  }
}

function cleanText(value: Buffer): string {
  return UTF8.decode(value);
}

function canonicalRepoPath(path: string): string | undefined {
  if (!path || path.includes("\0") || path.includes("\\") || posix.isAbsolute(path)) return undefined;
  const normalized = posix.normalize(path);
  if (normalized === "." || normalized === ".." || normalized.startsWith("../") || normalized !== path.replace(/^\.\//, "")) return undefined;
  return normalized;
}

function git(root: string, args: readonly string[]): GitResult {
  const result = spawnSync("git", ["-C", root, ...args], {
    encoding: null,
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  return {
    status: result.status ?? -1,
    stdout: result.stdout ?? Buffer.alloc(0),
    stderr: (result.stderr ?? Buffer.alloc(0)).toString("utf8").trim(),
  };
}

function gitText(root: string, args: readonly string[]): { value?: string; reason?: CorpusRelevanceReason } {
  const result = git(root, args);
  if (result.status !== 0) {
    return { reason: { code: "git-command-failed", detail: `git ${args[0] ?? "command"} failed: ${result.stderr || `exit ${result.status}`}` } };
  }
  try {
    return { value: cleanText(result.stdout).trim() };
  } catch {
    return { reason: { code: "unreadable-input", detail: `git ${args[0] ?? "command"} returned non-UTF-8 output` } };
  }
}

function parseTree(root: string, snapshot: string): { entries?: Map<string, GitTreeEntry>; reason?: CorpusRelevanceReason } {
  const result = git(root, ["ls-tree", "-r", "-z", "--full-tree", snapshot]);
  if (result.status !== 0) {
    return { reason: { code: "git-command-failed", detail: `git ls-tree failed for ${snapshot}: ${result.stderr || `exit ${result.status}`}` } };
  }
  const entries = new Map<string, GitTreeEntry>();
  for (const raw of result.stdout.toString("binary").split("\0")) {
    if (!raw) continue;
    const tab = raw.indexOf("\t");
    const match = tab >= 0 ? /^(\d{6}) (blob|tree|commit) ([a-f0-9]{40}(?:[a-f0-9]{24})?)$/.exec(raw.slice(0, tab)) : null;
    let path: string;
    try {
      path = cleanText(Buffer.from(raw.slice(tab + 1), "binary"));
    } catch {
      return { reason: { code: "unreadable-input", detail: `${snapshot}: tree contains a non-UTF-8 path` } };
    }
    const canonicalPath = canonicalRepoPath(path);
    if (!match || !canonicalPath || entries.has(canonicalPath)) {
      return { reason: { code: "malformed-diff", path, detail: `${snapshot}: malformed or duplicate Git tree entry` } };
    }
    entries.set(canonicalPath, {
      mode: match[1]!,
      type: match[2]! as GitTreeEntry["type"],
      object: match[3]!,
      path: canonicalPath,
    });
  }
  return { entries };
}

function parseChangedPaths(root: string, base: string, head: string): { changed?: CorpusChangedPath[]; reason?: CorpusRelevanceReason } {
  const result = git(root, ["diff", "--no-ext-diff", "--name-status", "-z", "-M", base, head, "--"]);
  if (result.status !== 0) {
    return { reason: { code: "git-command-failed", detail: `git diff failed: ${result.stderr || `exit ${result.status}`}` } };
  }
  let fields: string[];
  try {
    fields = cleanText(result.stdout).split("\0");
  } catch {
    return { reason: { code: "unreadable-input", detail: "git diff returned non-UTF-8 paths" } };
  }
  if (fields.at(-1) === "") fields.pop();
  const changed: CorpusChangedPath[] = [];
  for (let index = 0; index < fields.length;) {
    const rawStatus = fields[index++];
    const match = rawStatus ? /^([ACDMRTUXB])(\d{1,3})?$/.exec(rawStatus) : null;
    if (!match) return { reason: { code: "malformed-diff", detail: `malformed Git name-status token ${JSON.stringify(rawStatus)}` } };
    const status = match[1]! as CorpusChangedPath["status"];
    const first = fields[index++];
    const second = status === "R" || status === "C" ? fields[index++] : undefined;
    const oldRaw = status === "A" ? undefined : first;
    const newRaw = status === "D" ? undefined : (second ?? first);
    const oldPath = oldRaw ? canonicalRepoPath(oldRaw) : undefined;
    const newPath = newRaw ? canonicalRepoPath(newRaw) : undefined;
    if ((oldRaw && !oldPath) || (newRaw && !newPath)) {
      return { reason: { code: "malformed-diff", detail: `Git diff contains a non-canonical path: ${oldRaw ?? newRaw}` } };
    }
    changed.push({ status, ...(match[2] ? { score: Number(match[2]) } : {}), ...(oldPath ? { oldPath } : {}), ...(newPath ? { newPath } : {}) });
  }
  return { changed };
}

function readBlob(root: string, entry: GitTreeEntry): { text?: string; reason?: CorpusRelevanceReason } {
  if (entry.mode === "120000") return { reason: { code: "symlink-seam", path: entry.path, detail: `${entry.path} is a tracked symlink, not immutable implementation bytes` } };
  if (entry.mode === "160000" || entry.type === "commit") return { reason: { code: "gitlink-seam", path: entry.path, detail: `${entry.path} is a gitlink whose nested bytes are not bound by the parent tree` } };
  if (entry.type !== "blob" || !/^100(?:644|755)$/.test(entry.mode)) {
    return { reason: { code: "unreadable-input", path: entry.path, detail: `${entry.path} has unsupported Git mode/type ${entry.mode}/${entry.type}` } };
  }
  const result = git(root, ["cat-file", "blob", entry.object]);
  if (result.status !== 0) return { reason: { code: "unreadable-input", path: entry.path, detail: `cannot read Git blob ${entry.object}: ${result.stderr || `exit ${result.status}`}` } };
  try {
    return { text: cleanText(result.stdout) };
  } catch {
    return { reason: { code: "unreadable-input", path: entry.path, detail: `${entry.path} is not valid UTF-8` } };
  }
}

function sourceKind(path: string): ts.ScriptKind {
  if (/\.(?:tsx|jsx)$/.test(path)) return ts.ScriptKind.TSX;
  if (/\.(?:js|mjs|cjs)$/.test(path)) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function typeOnly(statement: ts.ImportDeclaration | ts.ExportDeclaration): boolean {
  if (ts.isImportDeclaration(statement)) {
    const clause = statement.importClause;
    if (!clause) return false;
    if (clause.isTypeOnly) return true;
    return !clause.name
      && clause.namedBindings !== undefined
      && ts.isNamedImports(clause.namedBindings)
      && clause.namedBindings.elements.length > 0
      && clause.namedBindings.elements.every((element) => element.isTypeOnly);
  }
  if (statement.isTypeOnly) return true;
  return statement.exportClause !== undefined
    && ts.isNamedExports(statement.exportClause)
    && statement.exportClause.elements.length > 0
    && statement.exportClause.elements.every((element) => element.isTypeOnly);
}

function resolutionCandidates(from: string, specifier: string): string[] | undefined {
  if (!specifier.startsWith(".")) return [];
  const joined = posix.normalize(posix.join(posix.dirname(from), specifier));
  const canonical = canonicalRepoPath(joined);
  if (!canonical) return undefined;
  const extension = posix.extname(canonical);
  const candidates: string[] = [canonical];
  const addModuleCandidates = (stem: string): void => {
    candidates.push(`${stem}.ts`, `${stem}.tsx`, `${stem}.js`, `${stem}.jsx`, `${stem}.mts`, `${stem}.cts`, `${stem}.mjs`, `${stem}.cjs`);
    candidates.push(posix.join(stem, "index.ts"), posix.join(stem, "index.tsx"), posix.join(stem, "index.js"), posix.join(stem, "index.mjs"), posix.join(stem, "index.cjs"));
  };
  if (!extension) addModuleCandidates(canonical);
  else if (extension === ".js" || extension === ".jsx") addModuleCandidates(canonical.slice(0, -extension.length));
  else if (extension === ".mjs") candidates.push(`${canonical.slice(0, -4)}.mts`);
  else if (extension === ".cjs") candidates.push(`${canonical.slice(0, -4)}.cts`);
  return [...new Set(candidates)];
}

function resolveDependency(entries: ReadonlyMap<string, GitTreeEntry>, from: string, specifier: string): { path?: string; reason?: CorpusRelevanceReason } {
  const candidates = resolutionCandidates(from, specifier);
  if (candidates === undefined) return { reason: { code: "unresolved-runtime-edge", path: from, detail: `${from} imports a path that escapes the repository: ${JSON.stringify(specifier)}` } };
  if (candidates.length === 0) return {};
  for (const candidate of candidates) {
    const entry = entries.get(candidate);
    if (!entry) continue;
    if (entry.mode === "120000") return { reason: { code: "symlink-seam", path: candidate, detail: `${from} reaches tracked symlink ${candidate}` } };
    if (entry.mode === "160000" || entry.type === "commit") return { reason: { code: "gitlink-seam", path: candidate, detail: `${from} reaches gitlink ${candidate}` } };
    if (entry.type !== "blob") return { reason: { code: "unreadable-input", path: candidate, detail: `${from} reaches non-blob ${candidate}` } };
    return { path: candidate };
  }
  return { reason: { code: "unresolved-runtime-edge", path: from, detail: `${from} cannot resolve literal relative runtime edge ${JSON.stringify(specifier)}` } };
}

function sortReasons(reasons: readonly CorpusRelevanceReason[]): CorpusRelevanceReason[] {
  return [...reasons]
    .filter((reason, index, all) => all.findIndex((candidate) => canonical(candidate) === canonical(reason)) === index)
    .sort((left, right) => compareUtf8(`${left.code}\0${left.path ?? ""}\0${left.consumer ?? ""}\0${left.detail}`, `${right.code}\0${right.path ?? ""}\0${right.consumer ?? ""}\0${right.detail}`));
}

function targetSelectionProblem(selection: CorpusTargetSelection, owner: string): string | undefined {
  const targets = [...selection.targets];
  if (targets.length === 0 || targets.some((target) => !target.trim())) return `${owner}: target selection is empty or malformed`;
  if (new Set(targets).size !== targets.length || targets.some((target, index) => index > 0 && compareUtf8(targets[index - 1]!, target) >= 0)) {
    return `${owner}: target selection must be a sorted unique set`;
  }
  if (![selection.applicability, selection.provenance, selection.falsifier].every((value) => value.trim().length > 0)) return `${owner}: applicability/provenance/falsifier is incomplete`;
  return undefined;
}

function validateOwnership(ownership: CorpusInputOwnership): ValidatedOwnership {
  const reasons: CorpusRelevanceReason[] = [];
  const conflict = (detail: string, path?: string): void => {
    reasons.push({ code: "registry-conflict", detail, ...(path ? { path } : {}) });
  };
  if (ownership.schema !== 1) conflict(`CorpusInputOwnership schema must be 1, got ${String(ownership.schema)}`);
  const seenConsumers = new Set<string>();
  const selectionByConsumer = new Map<string, string>();
  const roots: string[] = [];
  for (const consumer of ownership.consumers) {
    if (!consumer.consumer.trim() || seenConsumers.has(consumer.consumer)) conflict(`duplicate or empty consumer ownership: ${JSON.stringify(consumer.consumer)}`);
    seenConsumers.add(consumer.consumer);
    const selectionProblem = targetSelectionProblem(consumer.targetSelection, consumer.consumer);
    if (selectionProblem) conflict(selectionProblem);
    selectionByConsumer.set(consumer.consumer, canonical(consumer.targetSelection));
    for (const root of consumer.runtimeRoots) {
      const path = canonicalRepoPath(root);
      if (!path) conflict(`${consumer.consumer}: non-canonical runtime root`, root);
      else roots.push(path);
    }
  }
  if (canonical(roots) !== canonical(CORPUS_DRIFT_RUNTIME_ROOTS)) {
    conflict(`runtime roots must equal the ordered nine-root contract; got ${JSON.stringify(roots)}`);
  }
  const workflowSelectionProblem = targetSelectionProblem(ownership.workflowCommandTargetSelection, "workflow-command");
  if (workflowSelectionProblem) conflict(workflowSelectionProblem);
  const nonImportKeys = new Set<string>();
  for (const input of ownership.nonImportInputs) {
    const path = canonicalRepoPath(input.path);
    const key = `${input.consumer}\0${path ?? input.path}`;
    if (!input.consumer.trim() || !path || nonImportKeys.has(key)) conflict(`non-import ownership is malformed or duplicated for ${input.consumer}`, input.path);
    nonImportKeys.add(key);
    const selectionProblem = targetSelectionProblem(input.targetSelection, `non-import:${input.consumer}:${input.path}`);
    if (selectionProblem) conflict(selectionProblem, input.path);
    const priorSelection = selectionByConsumer.get(input.consumer);
    if (priorSelection && priorSelection !== canonical(input.targetSelection)) conflict(`${input.consumer}: conflicting target selections across runtime/non-import ownership`, input.path);
    selectionByConsumer.set(input.consumer, canonical(input.targetSelection));
  }
  const producerIds = new Set<string>();
  const previousOrderByPhase = new Map<string, number>();
  for (const producer of ownership.producers) {
    const key = `${producer.phase}\0${producer.producer}`;
    const previousOrder = previousOrderByPhase.get(producer.phase) ?? -Infinity;
    if (!producer.producer.trim() || producerIds.has(key) || !Number.isInteger(producer.order) || producer.order <= previousOrder
      || !producer.phase.trim() || !producer.module.trim() || !canonicalRepoPath(producer.registryFile)) {
      conflict(`mechanical producer ownership is malformed or conflicts at ${JSON.stringify(producer.producer)}`, producer.registryFile);
    }
    producerIds.add(key);
    previousOrderByPhase.set(producer.phase, producer.order);
  }
  return {
    consumers: ownership.consumers,
    nonImportInputs: ownership.nonImportInputs,
    producers: ownership.producers,
    workflowCommandTargetSelection: ownership.workflowCommandTargetSelection,
    digest: digest(ownership),
    reasons: sortReasons(reasons),
  };
}

function workflowCommandRoots(root: string, gitSnapshot: GitSnapshot, workflowPath: string): { roots: string[]; reasons: CorpusRelevanceReason[] } {
  const entry = gitSnapshot.entries.get(workflowPath);
  if (!entry) return { roots: [], reasons: [{ code: "workflow-command-missing", path: workflowPath, detail: `${workflowPath} is absent at ${gitSnapshot.commit}` }] };
  const read = readBlob(root, entry);
  if (read.reason || read.text === undefined) return { roots: [], reasons: [read.reason!] };
  const roots = [...read.text.matchAll(/(?:^|[^A-Za-z0-9_.-])(src\/cli\/[A-Za-z0-9._/-]+\.ts)(?=$|[^A-Za-z0-9_.-])/gm)]
    .map((match) => match[1]!)
    .filter((path, index, all) => all.indexOf(path) === index)
    .sort(compareUtf8);
  if (!roots.includes("src/cli/corpus-cache-transport.ts")) {
    return { roots, reasons: [{ code: "workflow-command-missing", path: workflowPath, detail: `${workflowPath} no longer exposes src/cli/corpus-cache-transport.ts through literal workflow-command discovery` }] };
  }
  return { roots, reasons: [] };
}

function discoverClosure(root: string, gitSnapshot: GitSnapshot, ownership: ValidatedOwnership, workflowPath: string): MutableClosure {
  const workflow = workflowCommandRoots(root, gitSnapshot, workflowPath);
  const consumers = [
    ...ownership.consumers,
    ...workflow.roots.map((runtimeRoot): CorpusConsumerInputOwnership => ({
      consumer: `workflow-command:${runtimeRoot}`,
      runtimeRoots: [runtimeRoot],
      targetSelection: ownership.workflowCommandTargetSelection,
    })),
  ];
  const pathsByConsumer = new Map<string, Set<string>>();
  const globalFiles = new Set<string>();
  const edgeMap = new Map<string, CorpusRuntimeEdge>();
  const edgesByConsumer = new Map<string, Map<string, CorpusRuntimeEdge>>();
  const reasons: CorpusRelevanceReason[] = [...workflow.reasons];
  const parsed = new Map<string, { dependencies: CorpusRuntimeEdge[]; reasons: CorpusRelevanceReason[] }>();

  const parse = (path: string): { dependencies: CorpusRuntimeEdge[]; reasons: CorpusRelevanceReason[] } => {
    const cached = parsed.get(path);
    if (cached) return cached;
    const dependencies: CorpusRuntimeEdge[] = [];
    const localReasons: CorpusRelevanceReason[] = [];
    const entry = gitSnapshot.entries.get(path);
    if (!entry) {
      localReasons.push({ code: "unresolved-runtime-edge", path, detail: `runtime root/dependency ${path} is absent at ${gitSnapshot.commit}` });
      const value = { dependencies, reasons: localReasons };
      parsed.set(path, value);
      return value;
    }
    const read = readBlob(root, entry);
    if (read.reason || read.text === undefined) {
      localReasons.push(read.reason!);
      const value = { dependencies, reasons: localReasons };
      parsed.set(path, value);
      return value;
    }
    if (!SOURCE_FILE.test(path)) {
      const value = { dependencies, reasons: localReasons };
      parsed.set(path, value);
      return value;
    }
    const source = ts.createSourceFile(path, read.text, ts.ScriptTarget.Latest, true, sourceKind(path));
    const diagnostics = (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
    if (diagnostics.length > 0) {
      localReasons.push({ code: "malformed-source", path, detail: `${path} has ${diagnostics.length} TypeScript parse diagnostic(s)` });
    }
    const add = (kind: CorpusRuntimeEdge["kind"], specifier: string, position: number): void => {
      if (!specifier.startsWith(".")) return;
      const resolved = resolveDependency(gitSnapshot.entries, path, specifier);
      if (resolved.reason) localReasons.push(resolved.reason);
      else if (resolved.path) dependencies.push({ from: path, to: resolved.path, kind, specifier, position });
    };
    for (const statement of source.statements) {
      if (ts.isImportDeclaration(statement) && ts.isStringLiteralLike(statement.moduleSpecifier) && !typeOnly(statement)) {
        add("import", statement.moduleSpecifier.text, statement.getStart(source));
      } else if (ts.isExportDeclaration(statement) && statement.moduleSpecifier && ts.isStringLiteralLike(statement.moduleSpecifier) && !typeOnly(statement)) {
        add("export", statement.moduleSpecifier.text, statement.getStart(source));
      } else if (ts.isImportEqualsDeclaration(statement)
        && !statement.isTypeOnly
        && ts.isExternalModuleReference(statement.moduleReference)
        && statement.moduleReference.expression
        && ts.isStringLiteralLike(statement.moduleReference.expression)) {
        add("import-equals", statement.moduleReference.expression.text, statement.getStart(source));
      }
    }
    const inspectCalls = (node: ts.Node): void => {
      if (ts.isCallExpression(node)
        && (node.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(node.expression) && node.expression.text === "require"))) {
        const kind = node.expression.kind === ts.SyntaxKind.ImportKeyword ? "dynamic-import" : "require";
        const argument = node.arguments[0];
        if (!argument || node.arguments.length !== 1 || !ts.isStringLiteralLike(argument)) {
          localReasons.push({ code: "nonliteral-dynamic-edge", path, detail: `${path} contains a ${kind} edge whose literal identity cannot be proven` });
        } else {
          add(kind, argument.text, node.getStart(source));
        }
      }
      ts.forEachChild(node, inspectCalls);
    };
    inspectCalls(source);
    const value = { dependencies, reasons: localReasons };
    parsed.set(path, value);
    return value;
  };

  for (const consumer of consumers) {
    const files = new Set<string>();
    pathsByConsumer.set(consumer.consumer, files);
    const consumerEdges = new Map<string, CorpusRuntimeEdge>();
    edgesByConsumer.set(consumer.consumer, consumerEdges);
    const visit = (path: string): void => {
      if (files.has(path)) return;
      files.add(path);
      globalFiles.add(path);
      const discovered = parse(path);
      reasons.push(...discovered.reasons.map((reason) => ({ ...reason, consumer: consumer.consumer })));
      for (const edge of discovered.dependencies) {
        const key = `${edge.from}\0${edge.to}\0${edge.kind}\0${edge.specifier}\0${edge.position}`;
        edgeMap.set(key, edge);
        consumerEdges.set(key, edge);
        visit(edge.to);
      }
    };
    for (const runtimeRoot of consumer.runtimeRoots) visit(runtimeRoot);
  }
  for (const input of ownership.nonImportInputs) globalFiles.add(input.path);

  const files = [...globalFiles].sort(compareUtf8).flatMap((path) => {
    const entry = gitSnapshot.entries.get(path);
    if (!entry) {
      reasons.push({ code: "unreadable-input", path, detail: `owned input ${path} is absent at ${gitSnapshot.commit}` });
      return [];
    }
    if (entry.mode === "120000") reasons.push({ code: "symlink-seam", path, detail: `owned input ${path} is a tracked symlink` });
    if (entry.mode === "160000" || entry.type === "commit") reasons.push({ code: "gitlink-seam", path, detail: `owned input ${path} is a gitlink` });
    return [{ path, object: entry.object }];
  });
  const edges = [...edgeMap.values()].sort((left, right) => compareUtf8(canonical(left), canonical(right)));
  const consumerReceipts = consumers.map((consumer) => ({
    consumer: consumer.consumer,
    files: [...(pathsByConsumer.get(consumer.consumer) ?? [])].sort(compareUtf8),
  })).sort((left, right) => compareUtf8(left.consumer, right.consumer));
  const nonImportInputs = ownership.nonImportInputs.map((input) => ({
    consumer: input.consumer,
    path: input.path,
    object: gitSnapshot.entries.get(input.path)?.object ?? "missing",
  })).sort((left, right) => compareUtf8(`${left.consumer}\0${left.path}`, `${right.consumer}\0${right.path}`));
  const uncertainties = sortReasons(reasons);
  const roots = [...CORPUS_DRIFT_RUNTIME_ROOTS, ...workflow.roots];
  const group = (groupRoots: readonly string[], consumerIds: readonly string[]): CorpusClosureGroup => {
    const groupPaths = new Set<string>();
    const groupEdges = new Map<string, CorpusRuntimeEdge>();
    for (const consumer of consumerIds) {
      for (const path of pathsByConsumer.get(consumer) ?? []) groupPaths.add(path);
      for (const [key, edge] of edgesByConsumer.get(consumer) ?? []) groupEdges.set(key, edge);
    }
    const groupFiles = [...groupPaths].sort(compareUtf8).flatMap((path) => {
      const entry = gitSnapshot.entries.get(path);
      return entry ? [{ path, object: entry.object }] : [];
    });
    const groupEdgeRows = [...groupEdges.values()].sort((left, right) => compareUtf8(canonical(left), canonical(right)));
    const material = { roots: [...groupRoots], files: groupFiles, edges: groupEdgeRows };
    return { ...material, digest: digest(material) };
  };
  const runtimeRootClosure = group(CORPUS_DRIFT_RUNTIME_ROOTS, ownership.consumers.map((consumer) => consumer.consumer));
  const workflowCommandClosure = group(workflow.roots, workflow.roots.map((path) => `workflow-command:${path}`));
  const snapshotWithoutDigest = {
    commit: gitSnapshot.commit,
    tree: gitSnapshot.tree,
    roots,
    files,
    edges,
    consumers: consumerReceipts,
    nonImportInputs,
    runtimeRootClosure,
    workflowCommandClosure,
    uncertainties,
  };
  return {
    snapshot: { ...snapshotWithoutDigest, digest: digest(snapshotWithoutDigest) },
    pathsByConsumer,
    workflowRoots: workflow.roots,
  };
}

function exactTargetSelection(targets: readonly string[]): readonly string[] {
  return [...new Set(targets)].sort(compareUtf8);
}

export function buildCorpusInputOwnership(options: {
  pinnedTargets: readonly string[];
  mechanicalOwnership: MechanicalCorpusOwnershipDiscovery;
  nonImportInputs?: readonly CorpusRegisteredInputOwnership[];
}): CorpusInputOwnership {
  if (options.mechanicalOwnership.schema !== 1 || !Array.isArray(options.mechanicalOwnership.producers)) {
    throw new Error("mechanical corpus ownership discovery must have schema 1 and a producers array");
  }
  const targets = exactTargetSelection(options.pinnedTargets);
  const selection = (root: string): CorpusTargetSelection => ({
    targets,
    applicability: `${root} is a production corpus runtime root; changes select every pinned target its real consumer executes against`,
    provenance: `The ordered runtime-root contract and live pinned-target registry supplied ${root} at this exact head`,
    falsifier: `Show that ${root} is not invoked for an excluded target through the production corpus path`,
  });
  const ownership: CorpusInputOwnership = {
    schema: 1,
    consumers: CORPUS_DRIFT_RUNTIME_ROOTS.map((root) => ({
      consumer: root,
      runtimeRoots: [root],
      targetSelection: selection(root),
    })),
    nonImportInputs: [...(options.nonImportInputs ?? [])],
    producers: [...options.mechanicalOwnership.producers],
    workflowCommandTargetSelection: {
      targets,
      applicability: "A literal workflow-command root participates in the required corpus context over the workflow's selected pinned population",
      provenance: `${CORPUS_DRIFT_WORKFLOW} is read from the exact Git tree and supplies literal src/cli/*.ts command roots`,
      falsifier: "Remove the command from the exact workflow tree or prove its step cannot execute for a selected target",
    },
  };
  const validated = validateOwnership(ownership);
  if (validated.reasons.length > 0) {
    throw new Error(`cannot generate conflicting corpus input ownership: ${validated.reasons.map((reason) => reason.detail).join("; ")}`);
  }
  return ownership;
}

export function defaultCorpusInputOwnership(pinnedTargets: readonly string[], producers: readonly CorpusProducerOwnership[] = []): CorpusInputOwnership {
  return buildCorpusInputOwnership({
    pinnedTargets,
    mechanicalOwnership: { schema: 1, producers },
  });
}

function modeReason(entry: GitTreeEntry | undefined, path: string): CorpusRelevanceReason | undefined {
  if (!entry) return undefined;
  if (entry.mode === "120000") return { code: "symlink-seam", path, detail: `${path} changes through a tracked symlink seam` };
  if (entry.mode === "160000" || entry.type === "commit") return { code: "gitlink-seam", path, detail: `${path} changes through a gitlink seam` };
  return undefined;
}

function unknownRuntimePath(path: string): boolean {
  return UNKNOWN_RUNTIME_NAMESPACE.test(path)
    || UNKNOWN_RUNTIME_ROOT_FILE.test(path)
    || path === CORPUS_DRIFT_WORKFLOW
    || path.startsWith(".github/actions/");
}

function failureReceipt(
  ownershipDigest: string,
  reasons: readonly CorpusRelevanceReason[],
  partial: Partial<Pick<CorpusDriftRelevanceReceipt, "git" | "changed" | "closure" | "closureDigest" | "targetSelections">> = {},
): CorpusDriftRelevanceReceipt {
  return {
    schema: 1,
    kind: "corpus-drift-relevance",
    decision: "full-scan",
    assessment: {
      status: "full-scan-required",
      unitsAssessed: 0,
      statement: "The relevance proof failed or found a reachable corpus input. Run the required full pinned-corpus gate; this receipt is not an assessed-clean result.",
    },
    git: partial.git ?? null,
    changed: partial.changed ?? [],
    closure: partial.closure ?? null,
    closureDigest: partial.closureDigest ?? null,
    ownershipDigest,
    targetSelections: partial.targetSelections ?? [],
    hostedBackstop: {
      mode: "required-full-pinned-corpus",
      statement: "Consumer-specific target selections guide local remeasurement only. The hosted required context remains the full-pinned-corpus backstop.",
    },
    reasons: sortReasons(reasons),
  };
}

export function classifyCorpusDriftRelevance(options: ClassifyCorpusDriftRelevanceOptions): CorpusDriftRelevanceReceipt {
  let validated: ValidatedOwnership;
  try {
    validated = validateOwnership(options.ownership);
  } catch (error) {
    return failureReceipt(safeDigest(options.ownership), [{
      code: "registry-conflict",
      detail: `CorpusInputOwnership is malformed: ${error instanceof Error ? error.message : String(error)}`,
    }]);
  }
  if (validated.reasons.length > 0) return failureReceipt(validated.digest, validated.reasons);
  const workflowPath = canonicalRepoPath(options.workflowPath ?? CORPUS_DRIFT_WORKFLOW);
  if (!workflowPath) return failureReceipt(validated.digest, [{ code: "registry-conflict", detail: "workflow path is non-canonical" }]);

  let root: string;
  try {
    root = realpathSync(resolve(options.repoRoot));
  } catch {
    return failureReceipt(validated.digest, [{ code: "non-git-root", detail: `${options.repoRoot} cannot be resolved to a physical directory` }]);
  }
  const top = gitText(root, ["rev-parse", "--show-toplevel"]);
  if (!top.value) return failureReceipt(validated.digest, [{ code: "non-git-root", detail: `${root} is not an exact Git worktree root${top.reason ? `: ${top.reason.detail}` : ""}` }]);
  let gitRoot: string;
  try {
    gitRoot = realpathSync(top.value);
  } catch {
    return failureReceipt(validated.digest, [{ code: "non-git-root", detail: `Git reported an unreadable worktree root ${top.value}` }]);
  }
  if (gitRoot !== root) return failureReceipt(validated.digest, [{ code: "non-git-root", detail: `execution root ${root} differs from exact Git root ${gitRoot}` }]);
  if (options.base.startsWith("-") || (options.head ?? "HEAD").startsWith("-")) {
    return failureReceipt(validated.digest, [{ code: "malformed-diff", detail: "Git refs may not begin with '-'" }]);
  }
  const base = gitText(root, ["rev-parse", "--verify", `${options.base}^{commit}`]);
  const head = gitText(root, ["rev-parse", "--verify", `${options.head ?? "HEAD"}^{commit}`]);
  const checkedOut = gitText(root, ["rev-parse", "--verify", "HEAD^{commit}"]);
  if (!base.value || !head.value || !checkedOut.value || !GIT_OBJECT.test(base.value) || !GIT_OBJECT.test(head.value) || !GIT_OBJECT.test(checkedOut.value)) {
    return failureReceipt(validated.digest, [base.reason ?? head.reason ?? checkedOut.reason ?? { code: "git-command-failed", detail: "base/head could not be resolved to immutable commits" }]);
  }
  if (head.value !== checkedOut.value) {
    return failureReceipt(validated.digest, [{ code: "head-mismatch", detail: `requested head ${head.value} is not the checked-out head ${checkedOut.value}` }]);
  }
  const baseTree = gitText(root, ["rev-parse", `${base.value}^{tree}`]);
  const headTree = gitText(root, ["rev-parse", `${head.value}^{tree}`]);
  if (!baseTree.value || !headTree.value || !GIT_OBJECT.test(baseTree.value) || !GIT_OBJECT.test(headTree.value)) {
    return failureReceipt(validated.digest, [baseTree.reason ?? headTree.reason ?? { code: "git-command-failed", detail: "base/head trees could not be resolved" }]);
  }
  const status = git(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"]);
  if (status.status !== 0) return failureReceipt(validated.digest, [{ code: "git-command-failed", detail: `git status failed: ${status.stderr || `exit ${status.status}`}` }]);
  if (status.stdout.length !== 0) {
    return failureReceipt(validated.digest, [{ code: "dirty-root", detail: `Git root is dirty (${status.stdout.length} porcelain byte(s)); immutable head proof is unavailable` }]);
  }
  const proof: CorpusGitProof = {
    root,
    gitRoot,
    base: base.value,
    baseTree: baseTree.value,
    head: head.value,
    headTree: headTree.value,
    checkedOutHead: checkedOut.value,
    clean: true,
    statusSha256: createHash("sha256").update(status.stdout).digest("hex"),
  };
  const baseEntries = parseTree(root, baseTree.value);
  const headEntries = parseTree(root, headTree.value);
  const changedResult = parseChangedPaths(root, base.value, head.value);
  const structuralReason = baseEntries.reason ?? headEntries.reason ?? changedResult.reason;
  if (structuralReason || !baseEntries.entries || !headEntries.entries || !changedResult.changed) {
    return failureReceipt(validated.digest, [structuralReason ?? { code: "malformed-diff", detail: "Git tree/diff materialization failed" }], { git: proof });
  }
  const baseSnapshot: GitSnapshot = { commit: base.value, tree: baseTree.value, entries: baseEntries.entries };
  const headSnapshot: GitSnapshot = { commit: head.value, tree: headTree.value, entries: headEntries.entries };
  const baseClosure = discoverClosure(root, baseSnapshot, validated, workflowPath);
  const headClosure = discoverClosure(root, headSnapshot, validated, workflowPath);
  const closure = { base: baseClosure.snapshot, head: headClosure.snapshot };
  const closureDigest = digest({ base: baseClosure.snapshot.digest, head: headClosure.snapshot.digest, ownership: validated.digest });
  const reasons: CorpusRelevanceReason[] = [...baseClosure.snapshot.uncertainties, ...headClosure.snapshot.uncertainties];

  const ownershipByPath = (mutable: MutableClosure, sideOwnership: ValidatedOwnership): Map<string, Set<string>> => {
    const map = new Map<string, Set<string>>();
    const add = (path: string, consumer: string): void => {
      const owners = map.get(path) ?? new Set<string>();
      owners.add(consumer);
      map.set(path, owners);
    };
    for (const consumer of sideOwnership.consumers) {
      for (const path of mutable.pathsByConsumer.get(consumer.consumer) ?? []) add(path, consumer.consumer);
    }
    for (const input of sideOwnership.nonImportInputs) add(input.path, input.consumer);
    for (const workflowRoot of mutable.workflowRoots) {
      const consumer = `workflow-command:${workflowRoot}`;
      for (const path of mutable.pathsByConsumer.get(consumer) ?? []) add(path, consumer);
    }
    add(workflowPath, `workflow-discovery:${workflowPath}`);
    return map;
  };
  const baseOwners = ownershipByPath(baseClosure, validated);
  const headOwners = ownershipByPath(headClosure, validated);
  const selectionByConsumer = new Map<string, CorpusTargetSelection>();
  for (const consumer of validated.consumers) selectionByConsumer.set(consumer.consumer, consumer.targetSelection);
  for (const input of validated.nonImportInputs) selectionByConsumer.set(input.consumer, input.targetSelection);
  for (const workflowRoot of new Set([...baseClosure.workflowRoots, ...headClosure.workflowRoots])) {
    selectionByConsumer.set(`workflow-command:${workflowRoot}`, validated.workflowCommandTargetSelection);
  }
  selectionByConsumer.set(`workflow-discovery:${workflowPath}`, validated.workflowCommandTargetSelection);
  const changedByConsumer = new Map<string, Set<string>>();
  const recordOwned = (path: string | undefined, owners: ReadonlyMap<string, Set<string>>, workflowInput: boolean): void => {
    if (!path) return;
    for (const consumer of owners.get(path) ?? []) {
      const paths = changedByConsumer.get(consumer) ?? new Set<string>();
      paths.add(path);
      changedByConsumer.set(consumer, paths);
      reasons.push({
        code: workflowInput ? "workflow-discovery-input-change" : "owned-input-change",
        path,
        consumer,
        detail: `${path} is owned by corpus consumer ${consumer} in the exact ${owners === baseOwners ? "base" : "head"} closure`,
      });
    }
  };
  for (const changed of changedResult.changed) {
    const oldMode = changed.oldPath ? modeReason(baseSnapshot.entries.get(changed.oldPath), changed.oldPath) : undefined;
    const newMode = changed.newPath ? modeReason(headSnapshot.entries.get(changed.newPath), changed.newPath) : undefined;
    if (oldMode) reasons.push(oldMode);
    if (newMode) reasons.push(newMode);
    if (!["A", "C", "D", "M", "R"].includes(changed.status)) {
      reasons.push({ code: "malformed-diff", path: changed.newPath ?? changed.oldPath, detail: `Git change status ${changed.status} cannot prove ordinary immutable blob semantics` });
    }
    recordOwned(changed.oldPath, baseOwners, changed.oldPath === workflowPath);
    recordOwned(changed.newPath, headOwners, changed.newPath === workflowPath);
    const owned = (changed.oldPath && baseOwners.has(changed.oldPath)) || (changed.newPath && headOwners.has(changed.newPath));
    if (!owned) {
      for (const path of [changed.oldPath, changed.newPath]) {
        if (path && unknownRuntimePath(path)) reasons.push({ code: "unknown-runtime-input", path, detail: `${path} is in a corpus-capable runtime namespace but has no discovered or registered owner` });
      }
    }
  }
  const targetSelections: CorpusTargetSelectionReceipt[] = [...changedByConsumer.entries()].map(([consumer, paths]) => {
    const selection = selectionByConsumer.get(consumer)!;
    return { consumer, changedInputs: [...paths].sort(compareUtf8), ...selection };
  }).sort((left, right) => compareUtf8(left.consumer, right.consumer));
  const receiptPartial = { git: proof, changed: changedResult.changed, closure, closureDigest, targetSelections };
  if (reasons.length > 0) return failureReceipt(validated.digest, reasons, receiptPartial);
  return {
    schema: 1,
    kind: "corpus-drift-relevance",
    decision: "declared-no-op",
    assessment: {
      status: "nothing-assessed",
      unitsAssessed: 0,
      statement: `Nothing was assessed: ${changedResult.changed.length} exact Git change(s) were proved disjoint from the base/head corpus runtime and registered-input closures. This is not an assessed-clean corpus result.`,
    },
    git: proof,
    changed: changedResult.changed,
    closure,
    closureDigest,
    ownershipDigest: validated.digest,
    targetSelections: [],
    hostedBackstop: {
      mode: "required-full-pinned-corpus",
      statement: "The hosted required full-pinned-corpus gate remains the backstop; this no-op receipt only proves the current exact Git diff cannot reach its implementation/input closure.",
    },
    reasons: [],
  };
}
