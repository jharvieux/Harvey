import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { AUDIT_MODULES, moduleOfFinding, type AuditModule } from "./audit-coverage.js";
import { createAuditReplayBinding, replayAuditBundle, writeAuditReplayBundle, type AuditEvidenceInput, type AuditEvidenceScope } from "./audit-replay.js";
import { type Examined } from "./audit-runner.js";
import type { FindingsDocument } from "./findings.js";
import { testQualityFromArtifact } from "./mutation-scan.js";

const json = (path: string): unknown => JSON.parse(readFileSync(path, "utf8"));
const sha256 = (path: string): string => createHash("sha256").update(readFileSync(path)).digest("hex");

/** A recipe selects existing bound receipts. It cannot create execution provenance for raw files. */
export function bundleAuditEvidenceRecipe(recipePath: string, out: string): string {
  const recipe = json(recipePath) as {
    target: string; effectiveConfig: Record<string, unknown>; scopes: AuditEvidenceScope[];
    passes: { bundle: string; receiptId: string }[];
    metaFile?: string; sbomBundle?: string; expectedRevision: string;
  };
  const from = (path: string): string => resolve(dirname(recipePath), path);
  const binding = createAuditReplayBinding(from(recipe.target), recipe.effectiveConfig);
  if (recipe.expectedRevision !== binding.target.revision) throw new Error("Evidence recipe target revision mismatch");
  const passes: AuditEvidenceInput[] = recipe.passes.map((selection) => {
    if (!selection.bundle || !selection.receiptId) throw new Error("Evidence recipes require an original bound bundle and receiptId for every pass; raw result files cannot establish original execution provenance. Use explicit legacy import for unbound historical evidence.");
    const source = from(selection.bundle);
    // This validates the ORIGINAL tree, engine, configuration, timestamp, scope and raw hashes
    // before any receipt can be selected. A current snapshot must never re-sign older output.
    const replay = replayAuditBundle(source, from(recipe.target), { effectiveConfig: recipe.effectiveConfig });
    const receipt = [...replay.evidence.current, ...replay.evidence.history.map((row) => row.receipt)].find((row) => row.id === selection.receiptId);
    if (!receipt) throw new Error(`Original bound receipt not found: ${selection.receiptId}`);
    return {
      scope: receipt.scope, generatedAt: receipt.generatedAt, producer: receipt.producer, result: receipt.result,
      rawArtifacts: receipt.rawArtifacts.map((raw) => join(source, raw.path)),
      ...(receipt.legacyReason ? { legacyReason: receipt.legacyReason } : {}),
      ...(receipt.historicalOrigin ? { historicalOrigin: receipt.historicalOrigin } : {}),
      ...(receipt.supersedes ? { supersedes: receipt.supersedes } : {}),
    };
  });
  let sbomPath: string | undefined;
  if (recipe.sbomBundle) {
    const source = from(recipe.sbomBundle);
    const replay = replayAuditBundle(source, from(recipe.target), { effectiveConfig: recipe.effectiveConfig });
    if (!replay.sbom) throw new Error("Original bound SBOM is missing from the selected bundle");
    const manifest = json(join(source, "audit-replay.json")) as { sbom: { path: string } };
    sbomPath = join(source, manifest.sbom.path);
  }
  return writeAuditReplayBundle(out, { binding, scopes: recipe.scopes, passes, ...(recipe.metaFile ? { meta: json(from(recipe.metaFile)) as FindingsDocument["meta"] } : {}), ...(sbomPath ? { sbomPath } : {}) });
}

interface LegacyReconciliation {
  generated_at: string;
  target_commit: string;
  reconciliations: { module: AuditModule; final_status: string; observed: string[]; unassessed?: string[]; superseded_base_probe_text?: string; reconciliation?: string; note?: string }[];
}

/** Legacy provenance remains historical. Import hashes the retained bytes now, not at execution. */
export function importLegacyAuditEvidence(options: {
  document: string; snapshot: string; validation: string; reconciliation?: string; mutation?: string; sbom: string; out: string;
}): { manifest: string; target: string } {
  const document = json(options.document) as FindingsDocument;
  const snapshot = json(options.snapshot) as { captured_at?: string; capturedAt?: string; target: { path: string; head: string; tree?: string }; engine: { head: string } };
  const validation = json(options.validation) as { validated_at?: string; generatedAt?: string; target: { expected_head?: string; actual_head?: string; expected_tree?: string; actual_tree?: string; head?: string }; engine: { expected_head?: string; actual_head?: string; commit?: string }; exports?: { finding_count?: number }; operations?: unknown[] };
  const expectedHead = validation.target.expected_head ?? validation.target.head;
  const actualHead = validation.target.actual_head ?? validation.target.head;
  if (!snapshot.target?.head || !snapshot.engine?.head || expectedHead !== snapshot.target.head || actualHead !== expectedHead) throw new Error("Historical snapshot/validation target identities disagree or are missing");
  if ((validation.engine.actual_head ?? validation.engine.commit) !== snapshot.engine.head || (validation.engine.expected_head && validation.engine.expected_head !== snapshot.engine.head)) throw new Error("Historical engine identity mismatch");
  if (validation.target.expected_tree && (validation.target.expected_tree !== snapshot.target.tree || validation.target.actual_tree !== snapshot.target.tree)) throw new Error("Historical target tree mismatch");
  if (document.meta.commit !== snapshot.target.head && !snapshot.target.head.startsWith(document.meta.commit)) throw new Error("Historical report and snapshot revisions disagree");
  if (validation.exports?.finding_count !== undefined && validation.exports.finding_count !== document.findings.length) throw new Error("Historical acceptance finding count does not match retained document");
  const reconciliation = options.reconciliation ? json(options.reconciliation) as LegacyReconciliation : undefined;
  if (reconciliation && reconciliation.target_commit !== snapshot.target.head) throw new Error("Historical scope reconciliation belongs to another target revision");
  const generatedAt = validation.validated_at ?? validation.generatedAt ?? snapshot.captured_at ?? snapshot.capturedAt;
  if (!generatedAt) throw new Error("Historical evidence lacks an execution/acceptance timestamp");
  const origin = { target: snapshot.target.path, revision: snapshot.target.head, ...(snapshot.target.tree ? { tree: snapshot.target.tree } : {}), engine: snapshot.engine.head, configProvenance: "Retained command receipts identify attempted tiers; they do not bind every effective configuration and producer dependency version to all raw outputs at execution time." };
  const legacyReason = `Historical acceptance at ${generatedAt} covers ${origin.target}@${origin.revision} using engine ${origin.engine}. ${origin.configProvenance} Digests taken during import prove retained-byte integrity only, not a new run or current target state [MEASURED from snapshot and validation receipts; falsifier: retain a new bound audit on the intended target/configuration].`;
  // The replay target is a receipt-only archive, explicitly distinct from the original source.
  // No original target files are touched or read, and no legacy bytes are re-signed as execution.
  const target = resolve(`${options.out}-historical-receipts`);
  if (existsSync(target)) throw new Error("Historical receipt archive already exists; choose a new output directory");
  mkdirSync(target, { recursive: true });
  writeFileSync(join(target, "origin.json"), `${JSON.stringify({ ...origin, snapshotSha256: sha256(options.snapshot), validationSha256: sha256(options.validation) }, null, 2)}\n`);
  const rawArtifacts = [options.document, options.snapshot, options.validation, ...(options.reconciliation ? [options.reconciliation] : [])];
  const scopes: AuditEvidenceScope[] = [];
  const passes: AuditEvidenceInput[] = [];
  for (const module of AUDIT_MODULES) {
    const coverage = (document.coverage ?? []).filter((row) => row.module === module);
    const moduleFindings = document.findings.filter((finding) => moduleOfFinding(finding.taxonomy) === module);
    const instances = coverage.flatMap((row) => row.instance ? [row.instance] : []);
    const unattributed = moduleFindings.filter((finding) => !instances.some((instance) => finding.id.endsWith(`@${instance}`)));
    const rows = coverage.length ? [...coverage] : [{ module, name: module, status: "partial" as const, reason: "No original module coverage row" }];
    if (!rows.some((row) => !row.instance) && unattributed.length) rows.push({ module, name: module, status: "partial", reason: "These accepted findings have no original workspace attribution" });
    for (const row of rows) {
      const workspace = row.instance ?? ".";
      const findings = row.instance
        ? moduleFindings.filter((finding) => finding.id.endsWith(`@${row.instance}`)).map((finding) => ({ ...finding, id: finding.id.slice(0, -row.instance!.length - 1) }))
        : unattributed;
      const scope: AuditEvidenceScope = { module, workspace, tier: "accepted-historical-union", surface: "original-delivery", wholeModule: false };
      scopes.push(scope);
      const base: Examined = { kind: "examined", unitsExamined: 1, scope: "accepted historical findings document", detail: row.detail ?? "Retained module receipt", findings, reason: row.reason ?? "Historical evidence only" };
      passes.push({ scope, generatedAt, producer: { name: "accepted-audit-delivery", version: origin.engine }, result: base, rawArtifacts, legacyReason, historicalOrigin: origin });
      const current = reconciliation?.reconciliations.find((entry) => entry.module === module);
      if (current?.superseded_base_probe_text && base.reason?.includes(current.superseded_base_probe_text)) {
        // Exact accepted supersession replaces the stale claim. Shared project evidence is named
        // as module-wide context, never claimed as a new per-workspace execution.
        const result: Examined = { ...base, detail: `${row.detail ?? "Retained workspace evidence"}; module-wide accepted observations: ${current.observed.join("; ")}`, reason: current.unassessed?.length ? `Unassessed: ${current.unassessed.join("; ")} [MEASURED from accepted scope reconciliation; falsifier: assess these listed surfaces]` : "Historical scope reconciliation; current-execution binding remains unproven" };
        passes.push({ scope, generatedAt: reconciliation!.generated_at, producer: { name: "accepted-scope-reconciliation", version: origin.engine }, result, rawArtifacts, legacyReason, historicalOrigin: origin, supersedes: [{ producer: "accepted-audit-delivery", generatedAt }] });
      }
    }
  }
  if (options.mutation) {
    const artifact = json(options.mutation);
    const testQuality = testQualityFromArtifact(artifact);
    if (!testQuality) throw new Error("Historical mutation artifact has no measured M8 table");
    const scope: AuditEvidenceScope = { module: "M8", workspace: ".", tier: "mutation", surface: testQuality.coveredScope.join(", ") || "unstated mutation scope", wholeModule: false };
    scopes.push(scope);
    passes.push({ scope, generatedAt, producer: { name: "mutation-scan", version: origin.engine }, result: { kind: "examined", unitsExamined: 1, scope: "retained native mutation artifact", detail: "Original mutation scores and configured-file scope", reason: testQuality.scopeNote + (testQuality.lineCoverage.reason ? `; ${testQuality.lineCoverage.reason}` : ""), findings: [], testQuality }, rawArtifacts: [options.mutation, ...rawArtifacts.slice(1)], legacyReason, historicalOrigin: origin });
  }
  const binding = createAuditReplayBinding(target, { mode: "historical-evidence-only", origin, reconstructedEffectiveConfig: null });
  const manifest = writeAuditReplayBundle(options.out, { binding, scopes, passes, meta: document.meta, sbomPath: options.sbom });
  return { manifest, target };
}
