import { createHash, randomUUID } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readlinkSync, realpathSync } from "node:fs";
import { delimiter, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AUDIT_MODULES, type AuditModule } from "./audit-coverage.js";
import type { ProbeReport } from "./audit-runner.js";
import type { AuditContext } from "./findings.js";
import { readEntriesLstatSafe } from "./fs-walk.js";
import type { CommandExecutionReceipt, ProducerExecutionReceipt } from "./producer-execution-receipt.js";
import { redactSecrets } from "./secret-redact.js";
import { productSourceInventoryForTarget } from "./source-inventory.js";

const sha = (value: string | Buffer): string => createHash("sha256").update(value).digest("hex");
const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.entries(value).filter(([, v]) => v !== undefined).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
  return JSON.stringify(value) ?? "null";
};

/** The same digest binds the original fresh context to retained, verified raw artifacts. */
export const auditContextDigest = (value: unknown): string => sha(canonical(value));

interface Snapshot { contentSha256: string; complete: boolean; gaps: string[] }
const outside = (path: string): boolean => path === ".." || path.startsWith(`../`) || isAbsolute(path);

function snapshot(root: string, paths = ["."], product = false, skipStores = true): Snapshot {
  const entries: unknown[] = [];
  const gaps: string[] = [];
  let exclusion: ((path: string) => boolean) | undefined;
  if (product) {
    try {
      const inventory = productSourceInventoryForTarget(root);
      exclusion = (path) => Boolean(inventory.excludedDirectoryFor(path));
      for (const gap of inventory.unresolvedConfigurations) gaps.push(`Source configuration ${gap.path} is unresolved: ${gap.reason}`);
    } catch { gaps.push("Product-source configuration could not be inventoried."); }
  }
  const walk = (path: string, label: string, ancestors: Set<string>): void => {
    try {
      if ((skipStores && label.split(/[\\/]/).some((part) => [".git", "node_modules", ".pnpm-store"].includes(part))) || exclusion?.(label)) return;
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) {
        entries.push([label, "link", sha(readlinkSync(path))]);
        const destination = realpathSync(path);
        if (outside(relative(root, destination))) { gaps.push(`Source alias ${label} leaves the observed tree.`); return; }
        walk(destination, label, ancestors);
      } else if (stat.isDirectory()) {
        const real = realpathSync(path);
        if (ancestors.has(real)) { gaps.push(`Source alias ${label} forms a directory cycle.`); return; }
        const next = new Set([...ancestors, real]);
        for (const entry of readEntriesLstatSafe(path).sort((a, b) => a.name.localeCompare(b.name))) walk(entry.path, label === "." ? entry.name : `${label}/${entry.name}`, next);
      } else if (stat.isFile()) entries.push([label, sha(readFileSync(path)), stat.mode & 0o111]);
      else gaps.push(`Unsupported source object ${label}.`);
    } catch { gaps.push(`Source input ${label} could not be read completely.`); }
  };
  for (const path of paths) walk(resolve(root, path), path, new Set());
  return { contentSha256: auditContextDigest(entries), complete: gaps.length === 0, gaps };
}

function gitRevision(root: string): string | undefined {
  try {
    const marker = join(root, ".git");
    const git = lstatSync(marker).isDirectory() ? marker : resolve(root, readFileSync(marker, "utf8").trim().replace(/^gitdir:\s*/, ""));
    const common = existsSync(join(git, "commondir")) ? resolve(git, readFileSync(join(git, "commondir"), "utf8").trim()) : git;
    const head = readFileSync(join(git, "HEAD"), "utf8").trim();
    if (/^[a-f0-9]{40,64}$/.test(head)) return head;
    const ref = head.replace(/^ref:\s*/, "");
    if (!ref.startsWith("refs/") || ref.split("/").includes("..")) return undefined;
    for (const dir of [git, common]) if (existsSync(join(dir, ref))) {
      const value = readFileSync(join(dir, ref), "utf8").trim();
      if (/^[a-f0-9]{40,64}$/.test(value)) return value;
    }
    const value = readFileSync(join(common, "packed-refs"), "utf8").split(/\r?\n/).find((line) => line.endsWith(` ${ref}`))?.split(" ")[0];
    return value && /^[a-f0-9]{40,64}$/.test(value) ? value : undefined;
  } catch { return undefined; }
}

type Input = { role: string; path: string; historical?: boolean };
type Observation = NonNullable<AuditContext["provenance"]>["moduleObservations"][number];

/** Observe fresh execution without imposing retained replay's materialized-tree contract. */
export function beginFreshAuditContext(options: {
  target: string; configuration: Record<string, unknown>; inputs?: Input[]; engineRoot?: string;
  retainedBinding?: unknown;
}) {
  const target = realpathSync(options.target);
  const engine = options.engineRoot ?? resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const enginePaths = ["src", "tools", "report-template", "briefs", "package.json", "pnpm-lock.yaml"].filter((path) => existsSync(join(engine, path)));
  const before = snapshot(target, ["."], true);
  const beforeRevision = gitRevision(target);
  const engineBefore = snapshot(engine, enginePaths);
  const configurationSha256 = auditContextDigest(options.configuration);
  const inputs = (options.inputs ?? []).map((input) => ({ ...input, before: snapshot(dirname(resolve(input.path)), [resolve(input.path)], false, false) }));
  const engagementId = `fresh:${randomUUID()}`;
  const observations: Observation[] = [];
  const observedScopes: [string, string][] = [];
  const receipts: string[] = [];
  const tools = new Map<string, Set<string>>();
  const commandGaps = new Set<string>();
  const secretValues = Object.entries(process.env).filter(([key, value]) => /secret|token|password|(?:^|_)api_?key|(?:^|_)db_url(?:_|$)/i.test(key) && value).map(([, value]) => value!);
  const safe = (value: string): string => redactSecrets(value, secretValues);
  const retainedBindingSha256 = options.retainedBinding ? auditContextDigest(options.retainedBinding) : undefined;
  return {
    engagementId,
    retainedBindingSha256,
    observeModule(module: AuditModule, reports: readonly ProbeReport[]): void {
      for (const report of reports) {
        observedScopes.push([module, report.instance ?? "."]);
        const typed = "kind" in report;
        observations.push({ module, instance: safe(report.instance ?? "."), status: typed ? report.kind : "legacy", unitsExamined: typed && report.kind === "examined" ? report.unitsExamined : 0, scope: typed && report.kind === "examined" ? safe(report.scope) : "No measured population", ...("reason" in report && report.reason ? { reason: safe(report.reason) } : !typed ? { reason: "Legacy probe lacks measured population evidence." } : {}) });
      }
    },
    observeCommand(command: string, receipt: CommandExecutionReceipt | undefined, environment = process.env): void {
      if (receipt) receipts.push(receipt.sha256);
      else commandGaps.add("A child command has no completed execution receipt.");
      const identity = safe(command);
      try {
        const path = command.includes("/") ? resolve(receipt?.command.cwd ?? process.cwd(), command) : (environment.PATH ?? "").split(delimiter).map((dir) => join(dir, command)).find((candidate) => existsSync(candidate));
        if (!path) throw new Error("unresolved executable");
        const versions = tools.get(identity) ?? new Set<string>();
        versions.add(sha(readFileSync(realpathSync(path))));
        tools.set(identity, versions);
      } catch { commandGaps.add(`Executable identity for ${identity} could not be observed.`); }
      commandGaps.add("Child-command receipts bind the launcher and its result, but do not attest every nested scanner, runtime dependency, rule pack, ambient setting or mutable provider response. Their actual identities remain unproved.");
    },
    finish(producers: readonly ProducerExecutionReceipt[]): AuditContext {
      const after = snapshot(target, ["."], true);
      const engineAfter = snapshot(engine, enginePaths);
      const targetStable = before.contentSha256 === after.contentSha256;
      const engineStable = engineBefore.contentSha256 === engineAfter.contentSha256;
      const limitations = [...before.gaps, ...after.gaps, ...engineBefore.gaps.map((gap) => `Engine: ${gap}`), ...engineAfter.gaps.map((gap) => `Engine: ${gap}`), ...commandGaps];
      if (!targetStable) limitations.push("Target inputs changed during execution; the final findings do not establish one stable source revision.");
      if (!engineStable) limitations.push("Harvey implementation inputs changed during execution; producer identity is unstable.");
      if (configurationSha256 !== auditContextDigest(options.configuration)) limitations.push("Effective audit configuration changed during execution.");
      if (beforeRevision !== gitRevision(target)) limitations.push("The Git revision pointer changed during execution; only the separately observed source bytes are bound.");
      const inputBindings = inputs.map((input) => {
        const afterInput = snapshot(dirname(resolve(input.path)), [resolve(input.path)], false, false);
        const complete = input.before.complete && afterInput.complete && input.before.contentSha256 === afterInput.contentSha256 && !input.historical;
        if (!complete) limitations.push(`${input.role} input is historical, unavailable or changed during execution; current-target applicability is unproved.`);
        return { role: input.role, identity: sha(resolve(input.path)), sha256: input.before.contentSha256, complete };
      });
      for (const module of AUDIT_MODULES) if (!observations.some((row) => row.module === module)) limitations.push(`${module} has no observed probe result.`);
      for (const row of observations) if (row.status !== "examined" || row.reason) limitations.push(`${row.module} (${row.instance}): ${row.reason ?? "No measured population was assessed."}`);
      if (options.configuration.connected || options.configuration.dynamic || options.configuration.llm) limitations.push("Live, dynamic or model inputs were requested; a local source digest does not bind their mutable external state.");
      const producerVersions: Record<string, string> = { engine: engineBefore.contentSha256, node: process.version };
      for (const [name, versions] of tools) producerVersions[`launcher:${name}`] = auditContextDigest([...versions].sort());
      for (const producer of producers) producerVersions[`producer:${producer.producerId}`] = producer.implementationId;
      const producerIdentityComplete = commandGaps.size === 0 && ![options.configuration.connected, options.configuration.dynamic, options.configuration.llm].some(Boolean);
      const revision = beforeRevision;
      const scopeComplete = limitations.length === 0 && producerIdentityComplete && before.complete && after.complete && targetStable && engineBefore.complete && engineAfter.complete && engineStable && inputBindings.every((input) => input.complete);
      return {
        engagementId, kind: "client-audit", target: { id: target, revision: `content:${before.contentSha256}` }, producerVersions,
        schemaVersion: "finding-dispositions/1", assessedScope: observations.map((row) => JSON.stringify([row.module, row.instance, row.status, row.scope])).sort(), scopeComplete,
        limitations: [...new Set(limitations.map(safe))],
        provenance: {
          schema: 1, kind: "fresh-execution", target: { contentSha256: before.contentSha256, ...(revision ? { gitRevision: revision } : {}), complete: before.complete && after.complete, stable: targetStable },
          engine: { contentSha256: engineBefore.contentSha256, complete: engineBefore.complete && engineAfter.complete, stable: engineStable },
          configurationSha256, inputBindings, moduleObservations: observations, observedScopesSha256: auditContextDigest(observedScopes.sort()),
          commandReceiptSha256: [...new Set(receipts)].sort(), producerIdentityComplete,
          ...(retainedBindingSha256 ? { retainedBindingSha256 } : {}),
        },
      };
    },
  };
}
