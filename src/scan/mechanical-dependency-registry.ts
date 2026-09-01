import type { Finding } from "../findings.js";
import { dependencyRangeEdge, licenseScope } from "../sbom.js";
import type { MechanicalScanContext } from "./mechanical-context.js";
import { checkKnownDependencyCVEs, checkNextVersionCVEs, osvUnavailableFinding, parseOsvFindings, type OsvScanResult } from "./dependencies.js";
import {
  checkDependencyInstallScripts,
  checkInstallScripts,
  checkKnownIoc,
  checkLicenseCompliance,
  checkLockfilePresence,
  checkNonRegistryDependencies,
  checkSlopsquat,
  checkTyposquat,
  checkUnpinnedDependencies,
  NETWORK_SKIPPED_REASON,
  slopsquatCoverageFinding,
  supplyChainScopeFinding,
  type DependencyMap,
  type DeclaredDependency,
} from "./supply-chain.js";
import { producerAssurance, type MechanicalEngineEvidence } from "./mechanical-registry-assurance.js";
import {
  type MechanicalExaminedUnitIdentity,
  type MechanicalProducerRecord,
} from "./mechanical-phase-cache.js";
import { assertProducerTaxonomyOwnership } from "./mechanical-registry-contract.js";

interface MechanicalPackageJson {
  dependencies?: DependencyMap;
  devDependencies?: DependencyMap;
}

interface DependencyInput {
  context: MechanicalScanContext;
  scanDir: string;
  pkg: MechanicalPackageJson | null;
  osv: { result?: OsvScanResult; failure?: string };
  skipNetworkChecks?: boolean;
}

interface DependencyState extends DependencyInput {
  declared: DeclaredDependency[];
  rangeDeclarations: DeclaredDependency[];
  declaredNames: string[];
  workspaceInternalNames: string[];
  allNames: string[];
  license: ReturnType<typeof licenseScope>;
}

interface DependencyDetectorDefinition {
  id: string;
  order: number;
  module: "M1";
  phase: "dependency-advisory";
  stage: "early" | "supply";
  implementation: { file: string; exportName: string };
  additionalImplementations?: readonly { file: string; exportName: string }[];
  taxonomies: readonly string[];
  applicableFiles: { description: string; select: (state: DependencyState) => readonly unknown[] };
  countExaminedUnits: (state: DependencyState, selected: readonly unknown[]) => number;
  examinedUnitIdentities: (state: DependencyState, selected: readonly unknown[]) => MechanicalExaminedUnitIdentity[];
  prerequisites: readonly string[];
  fallback: string;
  positiveFixture: MechanicalEngineEvidence;
  benignTwin: MechanicalEngineEvidence;
  conservation: MechanicalEngineEvidence;
  corpus: MechanicalEngineEvidence;
  cadence: MechanicalEngineEvidence;
  enabled?: (state: DependencyState) => boolean;
  invoke: (state: DependencyState) => Finding[] | Promise<Finding[]>;
}

const fixtureFor = (file: string): string => file === "src/scan/dependencies.ts" ? "src/scan/dependencies.test.ts" : "src/scan/supply-chain.test.ts";

function definition(input: Pick<DependencyDetectorDefinition, "id" | "order" | "implementation" | "taxonomies" | "applicableFiles" | "invoke"> & Partial<DependencyDetectorDefinition>): DependencyDetectorDefinition {
  return Object.freeze({
    module: "M1", phase: "dependency-advisory", stage: "supply",
    countExaminedUnits: (_state, selected) => selected.length,
    examinedUnitIdentities: (_state: DependencyState, selected: readonly unknown[]) => dependencyExaminedUnits(input.id, selected),
    prerequisites: Object.freeze([]), fallback: "An unavailable external source emits a named disclosure; manifest-only and lockfile-only bounds remain explicit.",
    ...producerAssurance(input.id, input.implementation, fixtureFor(input.implementation.file)),
    ...input,
  } as DependencyDetectorDefinition);
}

const population = (description: string, select: (state: DependencyState) => readonly unknown[]): DependencyDetectorDefinition["applicableFiles"] => ({ description, select });
const manifests = population("root and declared workspace package manifests", ({ context }) => context.workspace.manifests);
const declaredRanges = population("root/workspace manifest declarations and admitted npm lockfile declaration edges", ({ rangeDeclarations }) => rangeDeclarations);
const resolvedDependencies = population("resolved lockfile dependency candidates", ({ license }) => license.candidates);

function targetPathExaminedUnits(producer: string, paths: readonly string[]): MechanicalExaminedUnitIdentity[] {
  return paths.map((identity) => ({ producer, kind: "target-path", identity }));
}

function semanticExaminedUnits(producer: string, kind: string, identities: readonly string[]): MechanicalExaminedUnitIdentity[] {
  return identities.map((identity) => ({ producer, kind, identity }));
}

function receiptRecord(input: Omit<MechanicalProducerRecord, "unitsExamined">): MechanicalProducerRecord {
  return { ...input, unitsExamined: input.examinedUnitIdentities.length };
}

function dependencyExaminedUnits(producer: string, selected: readonly unknown[]): MechanicalExaminedUnitIdentity[] {
  return selected.flatMap((value): MechanicalExaminedUnitIdentity[] => {
    if (typeof value === "string") return semanticExaminedUnits(producer, "dependency-name", [value]);
    if (!value || typeof value !== "object") throw new Error(`${producer}: dependency selector returned a unit with no stable semantic identity`);
    if ("label" in value && typeof value.label === "string") return targetPathExaminedUnits(producer, [value.label]);
    if ("edge" in value && value.edge && typeof value.edge === "object" && "identity" in value.edge && typeof value.edge.identity === "string") {
      return semanticExaminedUnits(producer, "declared-dependency", [value.edge.identity]);
    }
    if ("manifest" in value && typeof value.manifest === "string" && "name" in value && typeof value.name === "string") {
      return semanticExaminedUnits(producer, "declared-dependency", [`${value.manifest}#${value.name}`]);
    }
    if ("name" in value && typeof value.name === "string") {
      const version = "version" in value && typeof value.version === "string" ? value.version : "unresolved";
      return semanticExaminedUnits(producer, "resolved-dependency", [`${value.name}@${version}`]);
    }
    throw new Error(`${producer}: dependency selector returned a unit with no stable semantic identity`);
  });
}

function dependencyState(input: DependencyInput): DependencyState {
  const workspace = input.context.workspace;
  const declared = input.pkg ? workspace.manifests.flatMap((manifest) =>
    (["dependencies", "devDependencies"] as const).flatMap((section) => Object.entries(manifest[section] ?? {}).map(([name, range]) => ({
      manifest: manifest.label, name, range,
      edge: dependencyRangeEdge({ source: manifest.label, format: "package-json", sourceVersion: "unversioned",
        ownerPath: manifest.label, ownerName: manifest.name ?? manifest.label, name, range, section, direct: true }),
    })))) : [];
  const workspaceOwnNames = new Set(workspace.manifests.map((manifest) => manifest.name).filter((name): name is string => typeof name === "string"));
  const isWorkspaceInternal = (dependency: { name: string; range: string }): boolean =>
    workspaceOwnNames.has(dependency.name) || /^(workspace|link|portal):/.test(dependency.range.trim());
  const workspaceInternalNames = [...new Set(declared.filter(isWorkspaceInternal).map((dependency) => dependency.name))];
  const declaredNames = [...new Set(declared.filter((dependency) => !isWorkspaceInternal(dependency)).map((dependency) => dependency.name))];
  const license = licenseScope(input.scanDir);
  const rangeDeclarations = [...declared, ...license.rangeScopes.flatMap((scope) => scope.edges.map((edge) => ({
    manifest: edge.source, name: edge.name, range: edge.range, edge,
  })))];
  const allNames = [...new Set([...declaredNames, ...license.candidates.map((candidate) => candidate.name)])];
  return { ...input, declared, rangeDeclarations, declaredNames, workspaceInternalNames, allNames, license };
}

export const DEPENDENCY_DETECTORS: readonly DependencyDetectorDefinition[] = Object.freeze([
  definition({ id: "osv-advisories", order: 10, stage: "early", implementation: { file: "src/scan/dependencies.ts", exportName: "parseOsvFindings" }, additionalImplementations: [{ file: "src/scan/dependencies.ts", exportName: "osvUnavailableFinding" }], taxonomies: ["Known-vulnerable dependency", "Known-vulnerable dependency — coverage not assessed"], applicableFiles: resolvedDependencies, countExaminedUnits: ({ osv, license }) => osv.failure ? 0 : license.candidates.length, examinedUnitIdentities: ({ osv }, selected) => osv.failure ? [] : dependencyExaminedUnits("osv-advisories", selected), invoke: ({ osv }) => osv.failure ? [osvUnavailableFinding(osv.failure)] : parseOsvFindings(osv.result!) }),
  definition({ id: "next-curated-cves", order: 20, stage: "early", implementation: { file: "src/scan/dependencies.ts", exportName: "checkNextVersionCVEs" }, taxonomies: ["Known-vulnerable dependency", "EOL framework version"], applicableFiles: population("the declared Next.js dependency and resolved version", ({ pkg }) => pkg?.dependencies?.next ?? pkg?.devDependencies?.next ? ["next"] : []), enabled: ({ pkg }) => Boolean(pkg?.dependencies?.next ?? pkg?.devDependencies?.next), invoke: ({ pkg, context }) => checkNextVersionCVEs((pkg?.dependencies?.next ?? pkg?.devDependencies?.next)!, "package.json", context.dependencyTree) }),
  definition({ id: "dependency-typosquat", order: 30, implementation: { file: "src/scan/supply-chain.ts", exportName: "checkTyposquat" }, taxonomies: ["Possible typosquat/slopsquat"], applicableFiles: population("declared and resolved dependency names", ({ allNames }) => allNames), enabled: ({ pkg }) => Boolean(pkg), invoke: ({ allNames, license, declaredNames }) => checkTyposquat(allNames, { declared: new Set(declaredNames), source: license.source }) }),
  definition({ id: "dependency-ioc", order: 40, implementation: { file: "src/scan/supply-chain.ts", exportName: "checkKnownIoc" }, taxonomies: ["Known-malicious dependency"], applicableFiles: population("declared and resolved dependency names checked against the IOC catalog", ({ allNames }) => allNames), enabled: ({ pkg }) => Boolean(pkg), invoke: ({ allNames, license, declaredNames }) => checkKnownIoc(allNames, "package.json", { declared: new Set(declaredNames), source: license.source }) }),
  definition({ id: "curated-dependency-cves", order: 50, implementation: { file: "src/scan/dependencies.ts", exportName: "checkKnownDependencyCVEs" }, taxonomies: ["Known-vulnerable dependency"], applicableFiles: population("declared dependencies plus resolved candidates used when OSV is unavailable", ({ declared, license, osv }) => osv.failure ? [...declared, ...license.candidates] : declared), enabled: ({ pkg }) => Boolean(pkg), invoke: ({ osv, license, declared, context }) => {
    const dependencies: DependencyMap = {};
    if (osv.failure) for (const candidate of license.candidates) if (candidate.version) dependencies[candidate.name] ??= candidate.version;
    for (const dependency of declared) dependencies[dependency.name] = dependency.range;
    return checkKnownDependencyCVEs(dependencies, "package.json", context.dependencyTree);
  } }),
  definition({ id: "dependency-pinning", order: 60, implementation: { file: "src/scan/supply-chain.ts", exportName: "checkUnpinnedDependencies" }, additionalImplementations: [{ file: "src/sbom.ts", exportName: "dependencyRangeEdge" }], taxonomies: ["Unpinned dependency"], applicableFiles: declaredRanges, invoke: ({ rangeDeclarations }) => checkUnpinnedDependencies(rangeDeclarations) }),
  definition({ id: "non-registry-dependency", order: 70, implementation: { file: "src/scan/supply-chain.ts", exportName: "checkNonRegistryDependencies" }, taxonomies: ["Non-registry dependency source"], applicableFiles: declaredRanges, invoke: ({ rangeDeclarations }) => checkNonRegistryDependencies(rangeDeclarations) }),
  definition({ id: "manifest-install-scripts", order: 80, implementation: { file: "src/scan/supply-chain.ts", exportName: "checkInstallScripts" }, taxonomies: ["Install lifecycle script"], applicableFiles: manifests, enabled: ({ pkg }) => Boolean(pkg), invoke: ({ context }) => checkInstallScripts(context.workspace.manifests) }),
  definition({ id: "resolved-install-scripts", order: 90, implementation: { file: "src/scan/supply-chain.ts", exportName: "checkDependencyInstallScripts" }, taxonomies: ["Install lifecycle script (dependency)"], applicableFiles: resolvedDependencies, enabled: ({ pkg }) => Boolean(pkg), invoke: ({ license }) => checkDependencyInstallScripts(license.candidates) }),
  definition({ id: "dependency-slopsquat", order: 100, implementation: { file: "src/scan/supply-chain.ts", exportName: "checkSlopsquat" }, additionalImplementations: [{ file: "src/scan/supply-chain.ts", exportName: "slopsquatCoverageFinding" }], taxonomies: ["Slopsquatted/hallucinated dependency", "Coverage — npm-registry existence check not assessed"], applicableFiles: population("declared external registry package names", ({ declaredNames }) => declaredNames), enabled: ({ pkg }) => Boolean(pkg), invoke: ({ declaredNames, skipNetworkChecks }) => skipNetworkChecks ? [slopsquatCoverageFinding(declaredNames, NETWORK_SKIPPED_REASON)] : checkSlopsquat(declaredNames) }),
  definition({ id: "dependency-license", order: 110, implementation: { file: "src/scan/supply-chain.ts", exportName: "checkLicenseCompliance" }, taxonomies: ["Unknown/missing dependency license", "Copyleft license conflict", "Coverage — dependency license not assessed"], applicableFiles: resolvedDependencies, enabled: ({ pkg }) => Boolean(pkg), invoke: ({ license, skipNetworkChecks }) => checkLicenseCompliance(license, { skipRegistry: skipNetworkChecks }) }),
  definition({ id: "supply-chain-scope", order: 120, implementation: { file: "src/scan/supply-chain.ts", exportName: "supplyChainScopeFinding" }, taxonomies: ["Coverage — supply-chain check scope"], applicableFiles: population("declared, workspace-internal, and resolved dependency populations", ({ declaredNames, workspaceInternalNames, license }) => [...declaredNames, ...workspaceInternalNames, ...license.candidates]), enabled: ({ pkg, license }) => Boolean(pkg) || license.rangeScopes.length > 0, invoke: ({ license, declared, declaredNames, workspaceInternalNames, osv }) => [supplyChainScopeFinding({ license, treeNames: new Set(license.candidates.map((candidate) => candidate.name)).size, declaredNames: declaredNames.length, manifestDeclarations: declared.length, workspaceInternalNames, osvRan: osv.failure === undefined })] }),
  definition({ id: "lockfile-presence", order: 130, implementation: { file: "src/scan/supply-chain.ts", exportName: "checkLockfilePresence" }, taxonomies: ["Missing lockfile"], applicableFiles: population("supported lockfile paths", ({ context }) => context.paths.filter((path) => /(^|\/)(pnpm-lock\.yaml|package-lock\.json|yarn\.lock|bun\.lockb?|npm-shrinkwrap\.json)$/.test(path))), countExaminedUnits: () => 1, examinedUnitIdentities: () => semanticExaminedUnits("lockfile-presence", "semantic-check", ["supported-lockfile-presence"]), invoke: ({ scanDir }) => checkLockfilePresence(scanDir) }),
]);

export async function runRegisteredDependencyDetectors(input: DependencyInput, stage: DependencyDetectorDefinition["stage"]): Promise<{
  findings: Finding[];
  findingsByDetector: Record<string, Finding[]>;
  records: MechanicalProducerRecord[];
}> {
  const state = dependencyState(input);
  const findings: Finding[] = [];
  const findingsByDetector: Record<string, Finding[]> = {};
  const records: MechanicalProducerRecord[] = [];
  for (const detector of DEPENDENCY_DETECTORS) {
    if (detector.stage !== stage) continue;
    if (!(detector.enabled?.(state) ?? true)) {
      findingsByDetector[detector.id] = [];
      records.push(receiptRecord({ detector: detector.id, phase: detector.phase, order: detector.order, module: detector.module, examinedUnitIdentities: [], findings: 0, durationMs: 0, status: "not-applicable" }));
      continue;
    }
    const selected = detector.applicableFiles.select(state);
    const unitsExamined = detector.countExaminedUnits(state, selected);
    const examinedUnitIdentities = detector.examinedUnitIdentities(state, selected);
    if (unitsExamined !== examinedUnitIdentities.length) throw new Error(`${detector.id}: examined-unit count ${unitsExamined} differs from exact selector receipt ${examinedUnitIdentities.length}`);
    const started = performance.now();
    const emitted = await detector.invoke(state);
    assertProducerTaxonomyOwnership(detector, emitted);
    findingsByDetector[detector.id] = emitted;
    findings.push(...emitted);
    records.push(receiptRecord({ detector: detector.id, phase: detector.phase, order: detector.order, module: detector.module, examinedUnitIdentities, findings: emitted.length, durationMs: performance.now() - started, status: unitsExamined === 0 ? "not-applicable" : "ran" }));
  }
  return { findings, findingsByDetector, records };
}
