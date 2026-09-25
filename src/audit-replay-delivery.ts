import { readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { assembleEngagementDocument } from "./audit-report.js";
import { replayAuditBundle, type AuditEvidenceReconciliation } from "./audit-replay.js";
import { assertAuditComplete } from "./audit-coverage.js";
import { baselineLedger, conservationLedger, formatLedger } from "./conservation-ledger.js";
import { applyBaseline } from "./audit-diff.js";
import { enrichFindingsCwe } from "./cwe-map.js";
import { validateFindings, type AuditContext, type FindingsDocument, type ReportMeta } from "./findings.js";
import { toSarif } from "./sarif.js";
import { renderReport } from "../report-template/render.mjs";
import { statSafe } from "./fs-walk.js";
import { auditContextDigest } from "./audit-context.js";

function verifiedFreshContext(context: AuditContext | undefined, evidence: AuditEvidenceReconciliation, bundle: string): AuditContext | undefined {
  if (context?.provenance?.kind !== "fresh-execution" || context.provenance.retainedBindingSha256 !== auditContextDigest(evidence.binding)) return undefined;
  const scopes = evidence.current.map((receipt) => [receipt.scope.module, receipt.scope.workspace]);
  if (auditContextDigest(scopes.sort()) !== context.provenance.observedScopesSha256) return undefined;
  for (const receipt of evidence.current) {
    const owners = receipt.rawArtifacts.filter((artifact) => artifact.sourcePath?.endsWith(`/${receipt.scope.module}-owning-run.json`));
    if (owners.length !== 1) return undefined;
    try {
      const owner = JSON.parse(readFileSync(join(bundle, owners[0]!.path), "utf8")) as { freshExecution?: { engagementId?: string; bindingSha256?: string; auditContext?: AuditContext } };
      if (owner.freshExecution?.engagementId !== context.engagementId || owner.freshExecution.bindingSha256 !== context.provenance.retainedBindingSha256 || auditContextDigest(owner.freshExecution.auditContext) !== auditContextDigest(context)) return undefined;
    } catch { return undefined; }
  }
  return context;
}

export async function deliverAuditReplay(options: {
  target: string; bundle: string; findingsOut?: string; coverageOut?: string; sarifOut?: string;
  sbomOut?: string; htmlOut?: string; pdfOut?: string; conservationOut?: string; metaPath?: string;
  configPath?: string; baselinePath?: string;
}): Promise<void> {
  const replay = replayAuditBundle(options.bundle, options.target, {
    ...(options.configPath ? { effectiveConfig: JSON.parse(readFileSync(options.configPath, "utf8")) as Record<string, unknown> } : {}),
  });
  const { result, evidence } = replay;
  if (result.failures.length) throw new Error(`Replay failed: ${result.failures.map((failure) => `${failure.module}: ${failure.error}`).join("; ")}`);
  const env = { connected: false, dynamic: false, llm: false };
  assertAuditComplete(result.recorded, env);
  const meta = options.metaPath ? JSON.parse(readFileSync(options.metaPath, "utf8")) as ReportMeta : replay.meta;
  if (!meta) throw new Error("Replay needs retained engagement metadata or --meta");
  if (options.sbomOut && !replay.sbom) throw new Error("Requested SBOM is missing from the retained evidence; retain its original inventory before assembly");
  enrichFindingsCwe(result.findings);
  const retainedContext = replay.meta?.auditContext;
  const freshContext = verifiedFreshContext(retainedContext, evidence, options.bundle);
  const unverifiedFresh = retainedContext?.provenance?.kind === "fresh-execution" && !freshContext;
  const auditContext: AuditContext = freshContext ?? {
    engagementId: !unverifiedFresh && retainedContext?.engagementId || `retained:${realpathSync(options.bundle)}`,
    kind: !unverifiedFresh && retainedContext?.kind || "same-run-checkpoint",
    target: { id: evidence.binding.target.path, revision: `${evidence.binding.target.revision}:${evidence.binding.target.sha256}` },
    schemaVersion: "finding-dispositions/1",
    // Scope belongs in assessedScope. Repeating a producer in another workspace
    // must not masquerade as a tool change; distinct versions still remain bound.
    producerVersions: { ...Object.fromEntries(evidence.current.map((receipt) => [JSON.stringify([receipt.producer.name, receipt.producer.version]), receipt.producer.version] as const).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)), engine: evidence.binding.engine.sha256, configuration: evidence.binding.configSha256 },
    assessedScope: evidence.current.map((receipt) => JSON.stringify([receipt.scope.module, receipt.scope.workspace, receipt.scope.tier, receipt.scope.surface])).sort(),
    scopeComplete: !unverifiedFresh && evidence.missing.length === 0 && evidence.current.every((receipt) => !receipt.legacyReason) && result.recorded.every((row) => row.status === "ran"),
    ...(unverifiedFresh ? { limitations: ["The retained fresh engagement context is not bound to every verified owning-run artifact; original engagement identity remains unproved."] } : {}),
  };
  let doc: FindingsDocument & { auditEvidence: AuditEvidenceReconciliation; conservation: ReturnType<typeof conservationLedger> } = {
    ...assembleEngagementDocument(result.recorded, env, result.findings, meta, result.hotspots, result.dataMap, result.testQuality),
    auditEvidence: evidence,
    conservation: conservationLedger([], []),
    auditContext,
  };
  doc.meta = { ...doc.meta, auditContext };
  if (result.recorded.some((row) => row.module === "M2" && row.status !== "ran")) doc.meta = { ...doc.meta, tenantIsolation: "Not fully verified — see M2 scope" };
  doc.conservation = conservationLedger(result.findings, doc.findings, result.findingsByModule);
  if (!doc.conservation.ok) throw new Error(`Replay conservation failed: ${formatLedger(doc.conservation)}`);
  if (options.baselinePath) {
    const prior = JSON.parse(readFileSync(options.baselinePath, "utf8")) as FindingsDocument;
    if (!Array.isArray(prior.findings)) throw new Error("Baseline requires a findings document");
    const before = doc.findings;
    doc = { ...doc, ...applyBaseline(doc, prior, [prior.meta?.date, prior.meta?.commit].filter(Boolean).join(" @ "), { root: options.target }) };
    if (!baselineLedger(before, doc.findings, result.findingsByModule).ok) throw new Error("Baseline comparison changed the current occurrence population");
  }
  const valid = validateFindings(doc);
  if (!valid.ok) throw new Error(`Replayed document is invalid: ${valid.errors.join("; ")}`);
  const outputs: [string | undefined, unknown][] = [
    [options.findingsOut, doc], [options.coverageOut, result.recorded],
    [options.sarifOut, toSarif(doc.findings, { coverage: doc.coverage ?? [] }, { baseUri: options.target, auditContext: doc.auditContext, baseline: doc.baseline, conservation: doc.conservation })],
    [options.sbomOut, replay.sbom],
    [options.conservationOut, { ...doc.conservation, findingOwners: evidence.findingOwners, currentReceipts: evidence.current.map((receipt) => receipt.id), history: evidence.history.map((row) => ({ receipt: row.receipt.id, supersededBy: row.supersededBy, reason: row.reason })) }],
  ];
  const requested = [...outputs.flatMap(([path]) => path ? [path] : []), ...[options.htmlOut, options.pdfOut].filter((path): path is string => Boolean(path))];
  if (!requested.length) throw new Error("Assembly requires at least one requested export");
  const destinations = requested.map((path) => join(realpathSync(dirname(resolve(path))), basename(path)));
  if (new Set(destinations).size !== requested.length) throw new Error("Requested exports must have distinct paths");
  const protectedRoots = [realpathSync(options.bundle), realpathSync(options.target)];
  for (const absolute of destinations) {
    if (protectedRoots.some((root) => absolute === root || absolute.startsWith(`${root}/`)) || [options.metaPath, options.configPath, options.baselinePath].some((input) => input && realpathSync(input) === absolute)) throw new Error("Replay exports must not overwrite retained evidence, source or configuration inputs");
  }
  // Stale files from a prior attempt cannot satisfy the delivery gate for this invocation.
  for (const path of requested) rmSync(path, { force: true });
  for (const [path, data] of outputs) if (path) writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`);
  await renderReport(doc, { htmlPath: options.htmlOut, pdfPath: options.pdfOut });
  for (const path of requested) {
    const stat = statSafe(path);
    if (!stat?.isFile() || stat.size === 0) throw new Error(`Requested replay export was not written: ${path}`);
  }
  console.log(formatLedger(doc.conservation));
  console.log(`ASSEMBLY PASS — ${doc.findings.length} findings; ${requested.length} exports written from bound local evidence. No scanner, target command, network or model execution.`);
}
