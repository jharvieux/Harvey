import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, readlinkSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AUDIT_MODULES, type AuditModule, type EngagementEnv } from "./audit-coverage.js";
import { MAX_PASS_AGE_MS, MAX_PASS_FUTURE_SKEW_MS } from "./audit-pass-artifact.js";
import { runAudit, toOutcome, type ModuleRunner, type ProbeReport, type ProbeResult } from "./audit-runner.js";
import type { ReportMeta, TestQuality } from "./findings.js";
import { readEntriesLstatSafe } from "./fs-walk.js";
import { assertCommandExecutionReceipt, type CommandExecutionReceipt } from "./producer-execution-receipt.js";

/** Scope identity is independent of a pass's display name. One surface never replaces another. */
export interface AuditEvidenceScope {
  module: AuditModule;
  workspace: string;
  tier: string;
  surface: string;
  /** Only a producer's complete module assessment may carry this claim. */
  wholeModule: boolean;
}

interface FileReceipt { path: string; sha256: string; sourcePath?: string }
interface TreeIdentity { path: string; revision: string; sha256: string }
export interface AuditReplayBinding {
  target: TreeIdentity;
  engine: { revision: string; sha256: string };
  effectiveConfig: Record<string, unknown>;
  configSha256: string;
}

export interface AuditEvidenceInput {
  scope: AuditEvidenceScope;
  generatedAt: string;
  producer: { name: string; version: string };
  result: ProbeReport;
  /** Original outputs/logs, copied byte-for-byte; never amended to look like a combined run. */
  rawArtifacts: (string | { path: string; sourcePath?: string; sha256: string })[];
  /** Historical material may be delivered, but cannot establish current execution or coverage. */
  legacyReason?: string;
  historicalOrigin?: { target: string; revision: string; tree?: string; engine: string; configProvenance: string };
  /** Explicit corrections address a same-scope producer receipt, never a different surface. */
  supersedes?: { producer: string; generatedAt: string }[];
}

interface AuditEvidenceReceipt extends Omit<AuditEvidenceInput, "rawArtifacts"> {
  id: string;
  bindingSha256: string;
  rawArtifacts: FileReceipt[];
}

interface AuditReplayManifest {
  schemaVersion: 1;
  binding: AuditReplayBinding;
  generatedAt: string;
  scopes: AuditEvidenceScope[];
  receipts: FileReceipt[];
  sbom?: FileReceipt;
  meta?: ReportMeta;
  sha256: string;
}

export interface AuditEvidenceReconciliation {
  binding: AuditReplayBinding;
  current: AuditEvidenceReceipt[];
  history: { receipt: AuditEvidenceReceipt; supersededBy: string; reason: string }[];
  missing: AuditEvidenceScope[];
  findingOwners: { id: string; receipts: string[]; rawArtifacts: FileReceipt[] }[];
  testQualityByScope: { scope: AuditEvidenceScope; receipt: string; testQuality: TestQuality }[];
}

const engineRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const digest = (value: string | Buffer): string => createHash("sha256").update(value).digest("hex");
const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.entries(value).filter(([, v]) => v !== undefined).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
  return JSON.stringify(value) ?? "null";
};
const objectDigest = (value: unknown): string => digest(canonical(value));
const scopeKey = (scope: AuditEvidenceScope): string => canonical([scope.module, scope.workspace, scope.tier, scope.surface]);

function revision(root: string): string {
  const dotGit = join(root, ".git");
  if (!existsSync(dotGit)) return "unversioned";
  const gitDir = lstatSync(dotGit).isDirectory() ? dotGit : resolve(root, readFileSync(dotGit, "utf8").trim().replace(/^gitdir:\s*/, ""));
  const commonDir = existsSync(join(gitDir, "commondir")) ? resolve(gitDir, readFileSync(join(gitDir, "commondir"), "utf8").trim()) : gitDir;
  const head = readFileSync(join(gitDir, "HEAD"), "utf8").trim();
  if (/^[a-f0-9]{40,64}$/.test(head)) return head;
  const ref = head.replace(/^ref:\s*/, "");
  if (!/^refs\//.test(ref) || ref.split("/").includes("..")) throw new Error("Unsupported Git HEAD in replay binding");
  for (const dir of [gitDir, commonDir]) if (existsSync(join(dir, ref))) return readFileSync(join(dir, ref), "utf8").trim();
  const packed = join(commonDir, "packed-refs");
  const value = existsSync(packed) ? readFileSync(packed, "utf8").split(/\r?\n/).find((line) => line.endsWith(` ${ref}`))?.split(" ")[0] : undefined;
  if (!value) throw new Error("Cannot resolve target revision for replay binding");
  return value;
}

function treeDigest(root: string, paths = ["."]): string {
  const files: [string, string, number][] = [];
  const walk = (path: string): void => {
    const stat = lstatSync(path);
    const rel = relative(root, path).replaceAll("\\", "/");
    if (stat.isSymbolicLink()) {
      // Source symlinks need an explicit materialized snapshot; hashing only the link text would
      // miss changed source at its destination. Dependency links are excluded before this point.
      throw new Error(`Replay requires a materialized source snapshot; symlink: ${rel} -> ${readlinkSync(path)}`);
    }
    if (stat.isDirectory()) {
      for (const { name } of readEntriesLstatSafe(path).sort((a, b) => a.name.localeCompare(b.name))) {
        if ([".git", "node_modules", ".pnpm-store"].includes(name)) continue;
        walk(join(path, name));
      }
    } else if (stat.isFile()) files.push([rel, digest(readFileSync(path)), stat.mode & 0o111]);
    else throw new Error(`Unsupported source object in replay snapshot: ${rel}`);
  };
  for (const path of paths) if (existsSync(join(root, path))) walk(join(root, path));
  return objectDigest(files);
}

/** Pure filesystem read: replay never needs Git, a scanner, or a target command. */
export function createAuditReplayBinding(target: string, effectiveConfig: Record<string, unknown>): AuditReplayBinding {
  const path = realpathSync(target);
  return {
    target: { path, revision: revision(path), sha256: treeDigest(path) },
    engine: { revision: revision(engineRoot), sha256: treeDigest(engineRoot, ["src", "report-template", "briefs", "package.json", "pnpm-lock.yaml"]) },
    effectiveConfig,
    configSha256: objectDigest(effectiveConfig),
  };
}

function assertScope(scope: AuditEvidenceScope): void {
  if (!scope || !AUDIT_MODULES.includes(scope.module) || !scope.workspace?.trim() || !scope.tier?.trim() || !scope.surface?.trim() || typeof scope.wholeModule !== "boolean") {
    throw new Error("Evidence needs an explicit module, workspace, tier, surface and wholeModule scope");
  }
  if (isAbsolute(scope.workspace) || scope.workspace.split(/[\\/]/).includes("..")) throw new Error("Evidence workspace must be relative to the bound target");
}

function assertFresh(generatedAt: string, now: number): void {
  const timestamp = Date.parse(generatedAt);
  if (!Number.isFinite(timestamp) || timestamp > now + MAX_PASS_FUTURE_SKEW_MS || now - timestamp > MAX_PASS_AGE_MS) {
    throw new Error(`Stale or invalid evidence timestamp ${generatedAt}; record a fresh pass for the bound target/configuration`);
  }
}

function assertResult(result: ProbeReport): void {
  if (!result || typeof result !== "object") throw new Error("Evidence result is missing");
  if (!("kind" in result) || !["examined", "not-assessed"].includes(result.kind)) throw new Error("Bound replay requires a typed examined/not-assessed result; use explicit legacy import for older evidence");
  if (result.kind === "examined" && (!Number.isFinite(result.unitsExamined) || result.unitsExamined <= 0 || !result.scope?.trim() || !Array.isArray(result.findings))) throw new Error("Examined evidence needs a positive measured unit count, scope and findings array");
  const outcome = "kind" in result ? toOutcome(result) : result;
  if (!["ran", "partial", "requires-live-run"].includes(outcome.status)) throw new Error("Evidence result has an invalid status");
  if (outcome.status !== "ran" && !outcome.reason?.trim()) throw new Error("Partial evidence needs its current limitation");
  if (outcome.status !== "requires-live-run" && (!outcome.detail?.trim() || (outcome.findings && !Array.isArray(outcome.findings)))) throw new Error("Evidence needs a measured detail and findings array");
  if ("kind" in result && result.kind === "not-assessed" && (!result.falsifier?.trim() || !["MEASURED", "TRIED", "ASSUMED"].includes(result.provenance))) throw new Error("Unassessed evidence needs provenance and a rerun falsifier");
}

function sealManifest(manifest: Omit<AuditReplayManifest, "sha256">): AuditReplayManifest {
  return { ...manifest, sha256: objectDigest(manifest) };
}

function writeRaw(dir: string, source: string): FileReceipt {
  const bytes = readFileSync(source);
  const sha256 = digest(bytes);
  const path = `raw/${sha256}`;
  mkdirSync(join(dir, "raw"), { recursive: true });
  writeFileSync(join(dir, path), bytes);
  return { path, sha256, sourcePath: resolve(source) };
}

interface RawArtifactBytes { ref: FileReceipt; bytes: Buffer }

interface CommandReceiptCatalog {
  module: AuditModule;
  reports: ProbeReport[];
  commandExecution: { kind: "command" } | { kind: "in-process"; reason: string };
  receipts: CommandExecutionReceipt[];
}

function commandReceiptsInArtifact(bytes: Buffer): CommandReceiptCatalog | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object" || !("commandExecutionReceipts" in parsed)) return undefined;
  const catalog = parsed as Record<string, unknown>;
  const receipts = catalog.commandExecutionReceipts;
  if (!Array.isArray(receipts)) throw new Error("Owning-run commandExecutionReceipts must be an array");
  if (!AUDIT_MODULES.includes(catalog.module as AuditModule) || !Array.isArray(catalog.reports)) throw new Error("Owning-run catalog needs its module and derived reports");
  const commandExecution = catalog.commandExecution as CommandReceiptCatalog["commandExecution"] | undefined;
  if (receipts.length === 0 && (commandExecution?.kind !== "in-process" || !commandExecution.reason?.trim())) throw new Error("Empty command receipt catalog needs explicit in-process execution provenance");
  if (receipts.length > 0 && commandExecution?.kind === "in-process") throw new Error("In-process provenance cannot contain command executions");
  for (const report of catalog.reports) assertResult(report as ProbeReport);
  const validated = receipts.map((receipt) => {
    assertCommandExecutionReceipt(receipt);
    return receipt;
  });
  return { module: catalog.module as AuditModule, reports: catalog.reports as ProbeReport[], commandExecution: commandExecution ?? { kind: "command" }, receipts: validated };
}

function nestedCommandReceipts(bytes: Buffer): CommandExecutionReceipt[] {
  let parsed: unknown;
  try { parsed = JSON.parse(bytes.toString("utf8")); } catch { return []; }
  const receipts: CommandExecutionReceipt[] = [];
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) { value.forEach(visit); return; }
    if (!value || typeof value !== "object") return;
    for (const [key, item] of Object.entries(value)) {
      if (key === "executionReceipt" || (key === "receipt" && item && typeof item === "object" && "invocationId" in item)) {
        assertCommandExecutionReceipt(item);
        receipts.push(item);
      } else if (key !== "commandExecutionReceipts") visit(item);
    }
  };
  visit(parsed);
  return receipts;
}

/** Bind nested invocation receipts to the exact raw files copied into this accepted pass. */
function assertCommandReceiptBindings(pass: Pick<AuditEvidenceInput, "scope" | "producer" | "result" | "legacyReason">, raw: readonly RawArtifactBytes[]): void {
  // Historical imports retain bytes without asserting that their embedded receipts
  // establish a current execution. Reconciliation always delivers these as partial.
  if (pass.legacyReason) return;
  const nestedReceipts = raw.flatMap((artifact) => nestedCommandReceipts(artifact.bytes));
  const owners = raw.flatMap((artifact) => {
    const catalog = commandReceiptsInArtifact(artifact.bytes);
    return catalog === undefined ? [] : [{ artifact, ...catalog }];
  });
  if (owners.length > 1) throw new Error("Accepted pass contains multiple owning-run command receipt catalogs");
  if (owners.length === 0) {
    if (pass.producer.name.startsWith("audit-runner:") || pass.scope.tier === "orchestrated" || nestedReceipts.length) throw new Error("Orchestrated pass is missing its owning-run command receipt catalog");
    return; // Interactive/manual evidence does not assert an orchestrated command attempt.
  }
  const owner = owners[0]!;
  if (owner.module !== pass.scope.module) throw new Error("Accepted pass is bound to another module's owning-run catalog");
  const reports = owner.reports.filter((report) => (report.instance ?? ".") === pass.scope.workspace);
  if (reports.length !== 1 || objectDigest(reports[0]) !== objectDigest(pass.result)) throw new Error("Accepted pass result differs from its owning-run derived report");
  if (owner.commandExecution.kind === "in-process" && raw.length !== 1) throw new Error("In-process provenance cannot claim additional command artifacts");
  const invocationIds = new Set<string>();
  const artifactOwners = new Map<string, string>();
  const receipts = [...owner.receipts, ...nestedReceipts];
  for (const receipt of receipts) {
    if (invocationIds.has(receipt.invocationId)) throw new Error(`Accepted pass repeats command invocation ${receipt.invocationId}`);
    invocationIds.add(receipt.invocationId);
    for (const artifact of receipt.artifacts) {
      if (artifact.sha256 === owner.artifact.ref.sha256) throw new Error(`Command receipt ${receipt.invocationId} creates a digest cycle through its owning-run catalog`);
      const matches = raw.filter((candidate) => candidate.ref.sourcePath === artifact.path && candidate.ref.sha256 === artifact.sha256 && candidate.bytes.byteLength === artifact.bytes);
      if (matches.length !== 1) throw new Error(`Command receipt ${receipt.invocationId} report ${artifact.path} is missing or mixed with another run`);
      const prior = artifactOwners.get(artifact.path);
      if (prior && prior !== receipt.invocationId) throw new Error(`Accepted report digest is ambiguously owned by invocations ${prior} and ${receipt.invocationId}`);
      artifactOwners.set(artifact.path, receipt.invocationId);
    }
  }
  for (const artifact of raw) if (artifact !== owner.artifact && !artifactOwners.has(artifact.ref.sourcePath ?? "")) throw new Error("Accepted command pass contains an artifact without an owning invocation");
}

/** Create a portable bundle only after execution has stopped; raw owning-run outputs stay intact. */
export function writeAuditReplayBundle(dir: string, input: {
  binding: AuditReplayBinding;
  scopes: AuditEvidenceScope[];
  passes: AuditEvidenceInput[];
  meta?: ReportMeta;
  sbomPath?: string;
  now?: number;
}): string {
  const now = input.now ?? Date.now();
  const output = resolve(dir);
  if (output === input.binding.target.path || output.startsWith(`${input.binding.target.path}/`)) throw new Error("Retained evidence must be outside the bound target tree");
  if (existsSync(join(output, "audit-replay.json"))) throw new Error("Replay bundle already exists; use a new directory to preserve accepted evidence");
  input.scopes.forEach(assertScope);
  if (new Set(input.scopes.map(scopeKey)).size !== input.scopes.length) throw new Error("Replay plan repeats a scope identity");
  mkdirSync(output, { recursive: true });
  const receipts = input.passes.map((pass): FileReceipt => {
    assertScope(pass.scope);
    assertFresh(pass.generatedAt, now);
    assertResult(pass.result);
    if (pass.result.instance && pass.result.instance !== pass.scope.workspace) throw new Error("Pass workspace does not match its owning-run instance");
    if (!input.scopes.some((scope) => scopeKey(scope) === scopeKey(pass.scope) && scope.wholeModule === pass.scope.wholeModule)) throw new Error("Pass scope is not in the bound evidence plan");
    if (!pass.producer.name?.trim() || !pass.producer.version?.trim() || !pass.rawArtifacts.length) throw new Error("Pass needs a producer version and raw owning-run artifacts");
    const rawInputs = pass.rawArtifacts.map((artifact) => {
      const path = typeof artifact === "string" ? artifact : artifact.path;
      const ref = writeRaw(output, path);
      if (typeof artifact !== "string") {
        if (ref.sha256 !== artifact.sha256) throw new Error("Tampered retained raw artifact");
        if (artifact.sourcePath !== undefined) {
          if (!isAbsolute(artifact.sourcePath)) throw new Error("Retained raw artifact needs an absolute original identity");
          ref.sourcePath = artifact.sourcePath;
        } else delete ref.sourcePath;
      }
      return { ref, bytes: readFileSync(path) };
    });
    assertCommandReceiptBindings(pass, rawInputs);
    const rawArtifacts = rawInputs.map(({ ref }) => ref);
    const body = { ...pass, rawArtifacts, bindingSha256: objectDigest(input.binding) };
    const id = objectDigest(body);
    const receipt: AuditEvidenceReceipt = { ...body, id };
    const bytes = `${JSON.stringify(receipt, null, 2)}\n`;
    const path = `${pass.scope.module}-${id}.receipt.json`;
    writeFileSync(join(output, path), bytes);
    return { path, sha256: digest(bytes) };
  });
  const manifest = sealManifest({
    schemaVersion: 1, binding: input.binding, generatedAt: new Date(now).toISOString(), scopes: input.scopes, receipts,
    ...(input.meta ? { meta: input.meta } : {}),
    ...(input.sbomPath ? { sbom: writeRaw(output, input.sbomPath) } : {}),
  });
  const path = join(output, "audit-replay.json");
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
  return path;
}

function readRaw(dir: string, ref: FileReceipt): Buffer {
  if (!ref || typeof ref.path !== "string" || !/^[a-f0-9]{64}$/.test(ref.sha256)) throw new Error("Malformed raw artifact reference");
  const path = resolve(dir, ref.path);
  if (!path.startsWith(`${realpathSync(dir)}/`) || isAbsolute(ref.path) || !existsSync(path) || !realpathSync(path).startsWith(`${realpathSync(dir)}/`)) throw new Error(`Missing or escaping retained artifact: ${ref.path}`);
  const bytes = readFileSync(path);
  if (digest(bytes) !== ref.sha256) throw new Error(`Tampered retained artifact: ${ref.path}`);
  return bytes;
}

/** Replay has no execution capability in its API: its only inputs are a target and retained bytes. */
export function replayAuditBundle(dir: string, target: string, options: { now?: number; effectiveConfig?: Record<string, unknown> } = {}) {
  dir = realpathSync(dir);
  const manifest = JSON.parse(readFileSync(join(dir, "audit-replay.json"), "utf8")) as AuditReplayManifest;
  const { sha256, ...body } = manifest;
  if (manifest.schemaVersion !== 1 || objectDigest(body) !== sha256) throw new Error("Tampered or unsupported replay manifest");
  const now = options.now ?? Date.now();
  assertFresh(manifest.generatedAt, now);
  const actual = createAuditReplayBinding(target, options.effectiveConfig ?? manifest.binding.effectiveConfig);
  if (objectDigest(actual.target) !== objectDigest(manifest.binding.target)) throw new Error("Replay target revision/tree mismatch; retain a new run for this exact source snapshot");
  if (actual.engine.sha256 !== manifest.binding.engine.sha256) throw new Error("Replay engine/producer version mismatch; use the producing engine or explicitly rebind verified raw evidence");
  if (actual.configSha256 !== manifest.binding.configSha256 || objectDigest(manifest.binding.effectiveConfig) !== manifest.binding.configSha256) throw new Error("Replay effective configuration mismatch");
  manifest.scopes.forEach(assertScope);
  if (new Set(manifest.scopes.map(scopeKey)).size !== manifest.scopes.length) throw new Error("Replay plan repeats a scope identity");
  const receipts = manifest.receipts.map((ref) => {
    const receipt = JSON.parse(readRaw(dir, ref).toString("utf8")) as AuditEvidenceReceipt;
    const { id, ...payload } = receipt;
    if (objectDigest(payload) !== id || receipt.bindingSha256 !== objectDigest(manifest.binding)) throw new Error("Misbound or tampered pass receipt");
    assertFresh(receipt.generatedAt, now);
    assertScope(receipt.scope);
    assertResult(receipt.result);
    if (receipt.result.instance && receipt.result.instance !== receipt.scope.workspace) throw new Error("Pass workspace does not match its owning-run instance");
    if (!receipt.producer.name?.trim() || !receipt.producer.version?.trim() || !receipt.rawArtifacts.length) throw new Error("Pass lacks producer identity or raw evidence");
    if (!manifest.scopes.some((scope) => scopeKey(scope) === scopeKey(receipt.scope) && scope.wholeModule === receipt.scope.wholeModule)) throw new Error("Unexpected pass scope");
    const raw = receipt.rawArtifacts.map((artifact) => ({ ref: artifact, bytes: readRaw(dir, artifact) }));
    assertCommandReceiptBindings(receipt, raw);
    return receipt;
  });
  if (new Set(receipts.map((receipt) => receipt.id)).size !== receipts.length) throw new Error("Replay repeats an owning-run receipt");
  const current: AuditEvidenceReceipt[] = [];
  const history: AuditEvidenceReconciliation["history"] = [];
  const missing: AuditEvidenceScope[] = [];
  for (const scope of manifest.scopes) {
    const candidates = receipts.filter((receipt) => scopeKey(receipt.scope) === scopeKey(scope)).sort((a, b) => Date.parse(b.generatedAt) - Date.parse(a.generatedAt));
    if (!candidates.length) { missing.push(scope); continue; }
    const superseded = new Set<string>();
    for (const candidate of candidates) for (const ref of candidate.supersedes ?? []) {
      const matches = candidates.filter((receipt) => receipt.producer.name === ref.producer && receipt.generatedAt === ref.generatedAt && receipt.id !== candidate.id);
      if (matches.length !== 1) throw new Error("Supersession must name exactly one receipt for the same module/workspace/tier/surface");
      superseded.add(matches[0]!.id);
    }
    const eligible = candidates.filter((receipt) => !superseded.has(receipt.id));
    if (!eligible.length) throw new Error("Cyclic evidence supersession");
    if (eligible.length > 1 && eligible[0]!.generatedAt === eligible[1]!.generatedAt) throw new Error(`Ambiguous simultaneous receipts for ${scopeKey(scope)}`);
    const selected = eligible[0]!;
    current.push(selected);
    history.push(...candidates.filter((receipt) => receipt.id !== selected.id).map((receipt) => ({ receipt, supersededBy: selected.id, reason: superseded.has(receipt.id) ? "Explicit correction for exactly the same module/workspace/tier/surface" : "Newer evidence for exactly the same module/workspace/tier/surface" })));
  }
  for (const module of AUDIT_MODULES) {
    if (!manifest.scopes.some((scope) => scope.module === module)) missing.push({ module, workspace: ".", tier: "unrecorded", surface: "module", wholeModule: false });
  }
  const testQualityByScope: AuditEvidenceReconciliation["testQualityByScope"] = [];
  const findingSources: AuditEvidenceReceipt[] = [];
  const runners: ModuleRunner[] = AUDIT_MODULES.map((module) => ({
    module, producers: [], typed: true,
    run: (): ProbeResult[] => {
      const scopes = [...manifest.scopes.filter((scope) => scope.module === module), ...missing.filter((scope) => scope.module === module && scope.tier === "unrecorded")];
      const workspaces = [...new Set(scopes.map((scope) => scope.workspace))];
      return workspaces.map((workspace): ProbeResult => {
        const selected = current.filter((receipt) => receipt.scope.module === module && receipt.scope.workspace === workspace);
        const absent = missing.filter((scope) => scope.module === module && scope.workspace === workspace);
        const findings = selected.flatMap((receipt) => {
          const outcome = "kind" in receipt.result ? toOutcome(receipt.result) : receipt.result;
          if (outcome.status === "requires-live-run") return [];
          if (outcome.testQuality) testQualityByScope.push({ scope: receipt.scope, receipt: receipt.id, testQuality: outcome.testQuality });
          findingSources.push(...(outcome.findings ?? []).map(() => receipt));
          return outcome.findings ?? [];
        });
        const outcomes = selected.map((receipt) => ({ receipt, outcome: "kind" in receipt.result ? toOutcome(receipt.result) : receipt.result }));
        // An unchanged retained module assessment is already the authoritative typed result.
        // Preserve its examined units and reason byte-for-byte, including synthesized disclosures.
        if (selected.length === 1 && !absent.length && selected[0]!.scope.wholeModule && !selected[0]!.legacyReason && "kind" in selected[0]!.result) {
          return { ...selected[0]!.result, ...(workspace !== "." ? { instance: workspace } : {}) } as ProbeResult;
        }
        const reasons = [
          ...outcomes.flatMap(({ receipt, outcome }) => [
            ...(outcome.status !== "ran" ? [`${receipt.scope.tier}/${receipt.scope.surface}: ${outcome.reason}`] : []),
            ...(receipt.legacyReason ? [`Legacy evidence is not current execution proof: ${receipt.legacyReason}`] : []),
          ]),
          ...absent.map((scope) => `${scope.tier}/${scope.surface}: no retained evidence [MEASURED from bundle inventory; falsifier: record the missing ${scope.module} pass for workspace ${workspace}]`),
        ];
        if (!scopes.some((scope) => scope.workspace === workspace && scope.wholeModule)) reasons.push("Only the explicitly listed surfaces were assessed; full module coverage is unverified [ASSUMED; falsifier: record a complete module scope assessment]");
        const instance = workspace !== "." ? { instance: workspace } : {};
        if (!outcomes.some(({ outcome }) => outcome.status !== "requires-live-run")) return { kind: "not-assessed", reason: reasons.join("; "), provenance: "MEASURED", falsifier: `record missing ${module} evidence for ${workspace}`, ...instance };
        const detail = outcomes.map(({ receipt, outcome }) => `${receipt.scope.tier}/${receipt.scope.surface} — ${outcome.status === "requires-live-run" ? "not assessed" : outcome.detail} [receipt ${receipt.id}; producer ${receipt.producer.name}@${receipt.producer.version}; ${receipt.generatedAt}]`).join("; ");
        const measured = outcomes.filter(({ outcome }) => outcome.status !== "requires-live-run");
        const hotspots = measured.flatMap(({ outcome }) => outcome.status !== "requires-live-run" ? outcome.hotspots ?? [] : []);
        const maps = measured.flatMap(({ outcome }) => outcome.status !== "requires-live-run" && outcome.dataMap ? [outcome.dataMap] : []);
        const quality = testQualityByScope.filter((row) => row.scope.module === module && row.scope.workspace === workspace).at(-1)?.testQuality;
        return { kind: "examined", unitsExamined: selected.length, scope: "bound owning-run receipts (original examined units are stated per surface)", detail, findings, ...instance, ...(reasons.length ? { reason: reasons.join("; ") } : {}), ...(hotspots.length ? { hotspots } : {}), ...(maps.length ? { dataMap: Object.assign({}, ...maps) } : {}), ...(quality ? { testQuality: quality } : {}) };
      });
    },
  }));
  const env: EngagementEnv = { connected: false, dynamic: false, llm: false };
  const result = runAudit(runners, { targetDir: target, env, exists: existsSync, exec: () => { throw new Error("Replay cannot execute commands"); } });
  // runAudit preserves production order while namespacing and disambiguating IDs. Associate
  // receipts with that final sequence, so colliding bodies retain their own raw evidence.
  if (result.findings.length !== findingSources.length) throw new Error("Replay finding ownership diverged from the produced union");
  const findingOwners = new Map<string, AuditEvidenceReconciliation["findingOwners"][number]>();
  result.findings.forEach((finding, index) => {
    const receipt = findingSources[index]!;
    const owner = findingOwners.get(finding.id) ?? { id: finding.id, receipts: [], rawArtifacts: [] };
    if (!owner.receipts.includes(receipt.id)) owner.receipts.push(receipt.id);
    for (const raw of receipt.rawArtifacts) if (!owner.rawArtifacts.some((prior) => prior.path === raw.path && prior.sha256 === raw.sha256)) owner.rawArtifacts.push(raw);
    findingOwners.set(finding.id, owner);
  });
  const evidence: AuditEvidenceReconciliation = { binding: manifest.binding, current, history, missing, findingOwners: [...findingOwners.values()], testQualityByScope };
  return { result, evidence, meta: manifest.meta, sbom: manifest.sbom ? JSON.parse(readRaw(dir, manifest.sbom).toString("utf8")) as unknown : undefined };
}
