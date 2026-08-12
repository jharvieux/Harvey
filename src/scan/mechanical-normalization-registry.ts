import { enrichFindingsCwe } from "../cwe-map.js";
import type { Finding } from "../findings.js";
import { annotateCveReachability, unrankedCveDisclosure } from "./dep-reachability.js";
import { producerAssurance } from "./mechanical-registry-assurance.js";
import {
  type MechanicalExaminedUnitIdentity,
  type MechanicalProducerRecord,
} from "./mechanical-phase-cache.js";
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

function semanticExaminedUnits(producer: string, kind: string, identities: readonly string[]): MechanicalExaminedUnitIdentity[] {
  return identities.map((identity) => ({ producer, kind, identity }));
}

function receiptRecord(input: Omit<MechanicalProducerRecord, "unitsExamined">): MechanicalProducerRecord {
  return { ...input, unitsExamined: input.examinedUnitIdentities.length };
}

export function runRegisteredNormalizationEngines(input: NormalizationInput): { findings: Finding[]; records: MechanicalProducerRecord[] } {
  const findings: Finding[] = [];
  const records: MechanicalProducerRecord[] = [];
  for (const engine of NORMALIZATION_ENGINES) {
    const selected = engine.select(input);
    const occurrences = new Map<string, number>();
    const identities = selected.map((unit) => {
      const key = `${unit.id}@${unit.location}`;
      const occurrence = (occurrences.get(key) ?? 0) + 1;
      occurrences.set(key, occurrence);
      return `${key}#${occurrence}`;
    });
    const examinedUnitIdentities = semanticExaminedUnits(engine.id, "finding", identities);
    const unitsExamined = engine.countExaminedUnits(input, selected);
    if (unitsExamined !== examinedUnitIdentities.length) throw new Error(`${engine.id}: examined-unit count ${unitsExamined} differs from exact selector receipt ${examinedUnitIdentities.length}`);
    const started = performance.now();
    const emitted = engine.invoke(input);
    assertProducerTaxonomyOwnership(engine, emitted);
    findings.push(...emitted);
    records.push(receiptRecord({ detector: engine.id, phase: engine.phase, order: engine.order, module: engine.module, examinedUnitIdentities, findings: emitted.length, durationMs: performance.now() - started, status: unitsExamined === 0 ? "not-applicable" : "ran" }));
  }
  return { findings, records };
}
