import { readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { assembleEngagementDocument } from "./audit-report.js";
import { replayAuditBundle, type AuditEvidenceReconciliation } from "./audit-replay.js";
import { assertAuditComplete } from "./audit-coverage.js";
import { conservationLedger, formatLedger } from "./conservation-ledger.js";
import { enrichFindingsCwe } from "./cwe-map.js";
import { validateFindings, type FindingsDocument, type ReportMeta } from "./findings.js";
import { toSarif } from "./sarif.js";
import { renderReport } from "../report-template/render.mjs";

export async function deliverAuditReplay(options: {
  target: string; bundle: string; findingsOut?: string; coverageOut?: string; sarifOut?: string;
  sbomOut?: string; htmlOut?: string; pdfOut?: string; conservationOut?: string; metaPath?: string;
  configPath?: string;
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
  const doc: FindingsDocument & { auditEvidence: AuditEvidenceReconciliation; conservation: ReturnType<typeof conservationLedger> } = {
    ...assembleEngagementDocument(result.recorded, env, result.findings, meta, result.hotspots, result.dataMap, result.testQuality),
    auditEvidence: evidence,
    conservation: conservationLedger([], []),
  };
  if (result.recorded.some((row) => row.module === "M2" && row.status !== "ran")) doc.meta = { ...doc.meta, tenantIsolation: "Not fully verified — see M2 scope" };
  doc.conservation = conservationLedger(result.findings, doc.findings, result.findingsByModule);
  if (!doc.conservation.ok) throw new Error(`Replay conservation failed: ${formatLedger(doc.conservation)}`);
  const valid = validateFindings(doc);
  if (!valid.ok) throw new Error(`Replayed document is invalid: ${valid.errors.join("; ")}`);
  const outputs: [string | undefined, unknown][] = [
    [options.findingsOut, doc], [options.coverageOut, result.recorded],
    [options.sarifOut, toSarif(doc.findings, { coverage: doc.coverage ?? [] }, { baseUri: options.target })],
    [options.sbomOut, replay.sbom],
    [options.conservationOut, { ...doc.conservation, findingOwners: evidence.findingOwners, currentReceipts: evidence.current.map((receipt) => receipt.id), history: evidence.history.map((row) => ({ receipt: row.receipt.id, supersededBy: row.supersededBy, reason: row.reason })) }],
  ];
  const requested = [...outputs.flatMap(([path]) => path ? [path] : []), ...[options.htmlOut, options.pdfOut].filter((path): path is string => Boolean(path))];
  if (!requested.length) throw new Error("Assembly requires at least one requested export");
  const destinations = requested.map((path) => join(realpathSync(dirname(resolve(path))), basename(path)));
  if (new Set(destinations).size !== requested.length) throw new Error("Requested exports must have distinct paths");
  const protectedRoots = [realpathSync(options.bundle), realpathSync(options.target)];
  for (const absolute of destinations) {
    if (protectedRoots.some((root) => absolute === root || absolute.startsWith(`${root}/`)) || [options.metaPath, options.configPath].some((input) => input && resolve(input) === absolute)) throw new Error("Replay exports must not overwrite retained evidence, source or configuration inputs");
  }
  // Stale files from a prior attempt cannot satisfy the delivery gate for this invocation.
  for (const path of requested) rmSync(path, { force: true });
  for (const [path, data] of outputs) if (path) writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`);
  await renderReport(doc, { htmlPath: options.htmlOut, pdfPath: options.pdfOut });
  for (const path of requested) if (!statSync(path).isFile() || statSync(path).size === 0) throw new Error(`Requested replay export was not written: ${path}`);
  console.log(formatLedger(doc.conservation));
  console.log(`ASSEMBLY PASS — ${doc.findings.length} findings; ${requested.length} exports written from bound local evidence. No scanner, target command, network or model execution.`);
}
