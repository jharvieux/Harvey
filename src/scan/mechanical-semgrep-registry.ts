import { realpathSync } from "node:fs";
import type { Finding } from "../findings.js";
import { NON_PRODUCT } from "../detectors/load-sources.js";
import { discoverAuthGuards } from "./auth-guard-discovery.js";
import { checkHostingConfigHeaders } from "./hosting-headers.js";
import { canonicalizeSemgrepOutput } from "./semgrep-family-cache.js";
import type { MechanicalScanContext } from "./mechanical-context.js";
import type { MechanicalPhaseCacheOptions } from "./mechanical-phase-cache.js";
import type { MechanicalProducerRecord } from "./mechanical-phase-cache.js";
import {
  checkMissingCsp,
  checkPublicDirSensitive,
  parseSemgrepFindings,
  partitionGuardTokenSuppressed,
  partitionMarkerSuppressed,
  runSemgrep,
  runSemgrepPartitioned,
  semgrepErrorFinding,
  semgrepScopeFinding,
  semgrepSuppressionFinding,
  semgrepUnavailableFinding,
} from "./semgrep.js";
import { producerAssurance, type MechanicalEngineEvidence } from "./mechanical-registry-assurance.js";
import { assertProducerTaxonomyOwnership } from "./mechanical-registry-contract.js";

interface SemgrepInput {
  scanDir: string;
  context: MechanicalScanContext;
  phaseCache?: MechanicalPhaseCacheOptions;
  authGuards?: string[];
  unitsExamined: number;
}

interface SemgrepEngineDefinition {
  id: string;
  order: number;
  module: "M1";
  phase: "semgrep";
  implementations: readonly { file: string; exportName: string }[];
  taxonomies: readonly string[];
  applicableFiles: string;
  examinedUnits: string;
  prerequisites: readonly string[];
  fallback: string;
  positiveFixture: MechanicalEngineEvidence;
  benignTwin: MechanicalEngineEvidence;
  conservation: MechanicalEngineEvidence;
  corpus: MechanicalEngineEvidence;
  cadence: MechanicalEngineEvidence;
  invoke: (input: SemgrepInput) => Promise<Finding[]>;
  select: (input: SemgrepInput) => readonly unknown[];
  countExaminedUnits: (input: SemgrepInput, selected: readonly unknown[]) => number;
}

export const SEMGREP_ENGINES: readonly SemgrepEngineDefinition[] = Object.freeze([Object.freeze({
  id: "semgrep-and-companion-config", order: 10, module: "M1", phase: "semgrep",
  implementations: Object.freeze([
    { file: "src/scan/semgrep.ts", exportName: "runSemgrep" },
    { file: "src/scan/semgrep.ts", exportName: "runSemgrepPartitioned" },
    { file: "src/scan/semgrep-family-cache.ts", exportName: "canonicalizeSemgrepOutput" },
    { file: "src/scan/auth-guard-discovery.ts", exportName: "discoverAuthGuards" },
    { file: "src/scan/semgrep.ts", exportName: "parseSemgrepFindings" },
    { file: "src/scan/semgrep.ts", exportName: "partitionGuardTokenSuppressed" },
    { file: "src/scan/semgrep.ts", exportName: "partitionMarkerSuppressed" },
    { file: "src/scan/semgrep.ts", exportName: "semgrepSuppressionFinding" },
    { file: "src/scan/semgrep.ts", exportName: "semgrepScopeFinding" },
    { file: "src/scan/semgrep.ts", exportName: "semgrepErrorFinding" },
    { file: "src/scan/semgrep.ts", exportName: "semgrepUnavailableFinding" },
    { file: "src/scan/semgrep.ts", exportName: "checkMissingCsp" },
    { file: "src/scan/hosting-headers.ts", exportName: "checkHostingConfigHeaders" },
    { file: "src/scan/semgrep.ts", exportName: "checkPublicDirSensitive" },
  ]),
  taxonomies: Object.freeze(["Semgrep rule check_id/harveyTaxonomy from the resolved rule inputs", "Missing security headers", "Sensitive file in public/ directory", "Coverage — findings suppressed by an in-repo marker", "Coverage — source files semgrep did not scan", "Coverage — files semgrep errored on or skipped", "Next.js/web footgun — coverage not assessed"]),
  applicableFiles: "all Semgrep-supported tracked source plus hosting/public configuration surfaces",
  select: ({ context }: SemgrepInput) => context.paths.filter((path) => /\.(?:[cm]?[jt]sx?|json|ya?ml|html|css)$/.test(path) || path.startsWith("public/")),
  countExaminedUnits: (_input: SemgrepInput, selected: readonly unknown[]) => selected.length,
  examinedUnits: "The phase records the immutable context's complete tracked-file population; Semgrep scope rows count skipped/error paths.",
  prerequisites: Object.freeze(["Semgrep binary or explicit SEM-00 disclosure", "resolved registry/local rule inputs"]),
  fallback: "Binary, parse, suppression, and skipped-path failures emit named disclosure rows rather than an empty result.",
  ...producerAssurance("semgrep-and-companion-config", { file: "src/scan/semgrep.ts", exportName: "runSemgrep" }, "src/scan/semgrep.test.ts"),
  invoke: runSemgrepEngine,
})]);

async function runSemgrepEngine({ scanDir, context, phaseCache, authGuards }: SemgrepInput): Promise<Finding[]> {
  const findings: Finding[] = [];
  const registryConfigs = phaseCache?.materializedInputs?.semgrep;
  const semgrep = phaseCache?.semgrepFamilies && registryConfigs
    ? await runSemgrepPartitioned(scanDir, registryConfigs, phaseCache.semgrepFamilies)
    : runSemgrep(scanDir, registryConfigs);
  if (semgrep.failure) {
    findings.push(semgrepUnavailableFinding(semgrep.failure));
  } else {
    const projectGuards = [
      ...discoverAuthGuards(context.loadedSources.filter((file) => !NON_PRODUCT.test(file.path))),
      ...(authGuards ?? []),
    ];
    const findingsFor = (raw: typeof semgrep.result): Finding[] => {
      const output = canonicalizeSemgrepOutput(raw);
      const { reported: guardCleared } = partitionGuardTokenSuppressed(output, projectGuards);
      const { reported, suppressed } = partitionMarkerSuppressed({ results: guardCleared });
      return [
        ...parseSemgrepFindings({ results: reported }),
        ...semgrepSuppressionFinding(suppressed, scanDir),
        ...semgrepScopeFinding(scanDir, output),
        ...semgrepErrorFinding(scanDir, output),
      ];
    };
    const partitionedFindings = findingsFor(semgrep.result);
    findings.push(...partitionedFindings);
    if (phaseCache?.semgrepFamilies?.mode === "verify") {
      const monolithic = runSemgrep(scanDir, registryConfigs);
      if (monolithic.failure) throw new Error(`Semgrep monolithic parity control did not complete: ${monolithic.failure}`);
      const monolithicFindings = findingsFor(monolithic.result);
      const canonicalRoot = realpathSync(scanDir);
      const scanRoots = [...new Set([scanDir, canonicalRoot])].sort((a, b) => b.length - a.length);
      const canonicalRows = (rows: Finding[]): Finding[] => JSON.parse(scanRoots.reduce((text, root) => text.replaceAll(root, "<SEMGREP_SCAN_ROOT>"), JSON.stringify(rows))) as Finding[];
      const canonicalMonolithic = canonicalRows(monolithicFindings);
      const canonicalPartitioned = canonicalRows(partitionedFindings);
      if (JSON.stringify(canonicalMonolithic) !== JSON.stringify(canonicalPartitioned)) {
        const monolithicRows = new Set(canonicalMonolithic.map((finding) => JSON.stringify(finding)));
        const partitionedRows = new Set(canonicalPartitioned.map((finding) => JSON.stringify(finding)));
        const added = canonicalPartitioned.filter((finding) => !monolithicRows.has(JSON.stringify(finding))).map((finding) => `${finding.id}@${finding.location}`).slice(0, 10);
        const missing = canonicalMonolithic.filter((finding) => !partitionedRows.has(JSON.stringify(finding))).map((finding) => `${finding.id}@${finding.location}`).slice(0, 10);
        throw new Error(`partitioned Semgrep result differs from the monolithic cold control: partitioned=${partitionedFindings.length}, monolithic=${monolithicFindings.length}; partition-only [${added.join(", ")}]; monolithic-only [${missing.join(", ")}]`);
      }
      phaseCache.onEvent?.(`SEMGREP MONOLITHIC PARITY PASS: ${partitionedFindings.length} normalized finding(s) from ${(semgrep as { records?: unknown[] }).records?.length ?? 0} exhaustive family artifact(s)`);
    }
  }
  findings.push(...checkMissingCsp(scanDir));
  findings.push(...checkHostingConfigHeaders(scanDir));
  findings.push(...checkPublicDirSensitive(scanDir));
  context.recordToolResult("semgrep", { failure: semgrep.failure, findings: findings.length });
  return findings;
}

export async function runRegisteredSemgrepEngines(input: SemgrepInput): Promise<{ findings: Finding[]; records: MechanicalProducerRecord[] }> {
  const findings: Finding[] = [];
  const records: MechanicalProducerRecord[] = [];
  for (const engine of SEMGREP_ENGINES) {
    const selected = engine.select(input);
    const started = performance.now();
    const emitted = await engine.invoke(input);
    assertProducerTaxonomyOwnership(engine, emitted);
    findings.push(...emitted);
    records.push({ detector: engine.id, phase: engine.phase, order: engine.order, module: engine.module, unitsExamined: engine.countExaminedUnits(input, selected), findings: emitted.length, durationMs: performance.now() - started, status: "ran" });
  }
  return { findings, records };
}
