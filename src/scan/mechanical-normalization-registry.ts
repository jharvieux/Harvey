import { enrichFindingsCwe } from "../cwe-map.js";
import type { Finding } from "../findings.js";
import { annotateCveReachability, unrankedCveDisclosure } from "./dep-reachability.js";
import { producerAssurance } from "./mechanical-registry-assurance.js";
import type { MechanicalProducerRecord } from "./mechanical-phase-cache.js";
import { assertProducerTaxonomyOwnership } from "./mechanical-registry-contract.js";

interface NormalizationInput {
  findings: Finding[];
  scanDir: string;
  directDeps: ReadonlySet<string>;
}

export const NORMALIZATION_ENGINES = Object.freeze([Object.freeze({
  id: "dependency-reachability-and-cwe", order: 10, module: "M1" as const, phase: "normalization" as const,
  implementations: Object.freeze([
    { file: "src/scan/dep-reachability.ts", exportName: "annotateCveReachability" },
    { file: "src/scan/dep-reachability.ts", exportName: "unrankedCveDisclosure" },
    { file: "src/cwe-map.ts", exportName: "enrichFindingsCwe" },
  ]),
  taxonomies: Object.freeze(["input finding taxonomy preserved", "Known-vulnerable dependency — reachability not assessed"]),
  applicableFiles: "the composed mechanical finding set and target import surface",
  select: ({ findings }: NormalizationInput) => findings,
  countExaminedUnits: (_input: NormalizationInput, selected: readonly unknown[]) => selected.length,
  examinedUnits: "The exact composed finding count entering reachability ordering and CWE enrichment.",
  prerequisites: Object.freeze(["all producing phases completed"]),
  fallback: "Any unranked dependency advisory emits a disclosure instead of silently sinking in the final order.",
  ...producerAssurance("dependency-reachability-and-cwe", { file: "src/scan/dep-reachability.ts", exportName: "annotateCveReachability" }, "src/scan/dep-reachability.test.ts"),
  invoke: runNormalizationEngine,
})]);

function runNormalizationEngine({ findings, scanDir, directDeps }: NormalizationInput): Finding[] {
  const ranked = annotateCveReachability(findings, scanDir, new Set(directDeps));
  if (ranked.unranked > 0) ranked.findings.push(unrankedCveDisclosure(ranked.unranked));
  return enrichFindingsCwe(ranked.findings);
}

export function runRegisteredNormalizationEngines(input: NormalizationInput): { findings: Finding[]; records: MechanicalProducerRecord[] } {
  const findings: Finding[] = [];
  const records: MechanicalProducerRecord[] = [];
  for (const engine of NORMALIZATION_ENGINES) {
    const selected = engine.select(input);
    const started = performance.now();
    const emitted = engine.invoke(input);
    assertProducerTaxonomyOwnership(engine, emitted);
    findings.push(...emitted);
    records.push({ detector: engine.id, phase: engine.phase, order: engine.order, module: engine.module, unitsExamined: engine.countExaminedUnits(input, selected), findings: emitted.length, durationMs: performance.now() - started, status: "ran" });
  }
  return { findings, records };
}
