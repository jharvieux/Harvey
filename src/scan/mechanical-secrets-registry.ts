import type { Finding } from "../findings.js";
import { bundleScanSkippedFinding, resolveBundleScan, scanSecrets } from "./secrets.js";
import { producerAssurance } from "./mechanical-registry-assurance.js";
import type { MechanicalProducerRecord } from "./mechanical-phase-cache.js";
import type { MechanicalScanContext } from "./mechanical-context.js";
import { assertProducerTaxonomyOwnership } from "./mechanical-registry-contract.js";

interface SecretsInput {
  scanDir: string;
  originalDir: string;
  bundleDir?: string;
  skipBundleScan?: boolean;
  secretCandidateIdentity?: string;
  unitsExamined: number;
  context: MechanicalScanContext;
}

export const SECRETS_ENGINES = Object.freeze([Object.freeze({
  id: "secrets-history-bundle", order: 10, module: "M1" as const, phase: "secrets-history" as const,
  implementations: Object.freeze([
    { file: "src/scan/secrets.ts", exportName: "resolveBundleScan" },
    { file: "src/scan/secrets.ts", exportName: "bundleScanSkippedFinding" },
    { file: "src/scan/secrets.ts", exportName: "scanSecrets" },
  ]),
  taxonomies: Object.freeze(["Committed credential*", "Possible committed credential", "Client-inlined secret*", "Corpus CI — deterministic secret-candidate provenance"]),
  applicableFiles: "tracked source, pinned git history, and discovered or supplied built bundle",
  select: ({ context }: SecretsInput) => context.paths,
  countExaminedUnits: (_input: SecretsInput, selected: readonly unknown[]) => selected.length,
  examinedUnits: "The phase records the immutable context's tracked-file population and names bundle/history/provider applicability in findings.",
  prerequisites: Object.freeze(["gitleaks/TruffleHog binaries or explicit unavailable findings"]),
  fallback: "A deliberately skipped or unavailable bundle/history/provider tier emits a named disclosure.",
  ...producerAssurance("secrets-history-bundle", { file: "src/scan/secrets.ts", exportName: "scanSecrets" }, "src/scan/secrets.test.ts"),
  invoke: runSecretsEngine,
})]);

function runSecretsEngine(input: SecretsInput): Finding[] {
  const findings: Finding[] = [];
  const bundle = input.skipBundleScan ? { disclosure: bundleScanSkippedFinding() } : resolveBundleScan(input.originalDir, input.bundleDir);
  findings.push(...scanSecrets(input.scanDir, input.originalDir, bundle.bundleDir, input.secretCandidateIdentity
    ? { providerVerification: "deterministic-candidates", candidateIdentity: input.secretCandidateIdentity }
    : undefined));
  if (bundle.disclosure) findings.push(bundle.disclosure);
  return findings;
}

export function runRegisteredSecretsEngines(input: SecretsInput): { findings: Finding[]; records: MechanicalProducerRecord[] } {
  const findings: Finding[] = [];
  const records: MechanicalProducerRecord[] = [];
  for (const engine of SECRETS_ENGINES) {
    const selected = engine.select(input);
    const started = performance.now();
    const emitted = engine.invoke(input);
    assertProducerTaxonomyOwnership(engine, emitted);
    findings.push(...emitted);
    records.push({ detector: engine.id, phase: engine.phase, order: engine.order, module: engine.module, unitsExamined: engine.countExaminedUnits(input, selected), findings: emitted.length, durationMs: performance.now() - started, status: "ran" });
  }
  return { findings, records };
}
