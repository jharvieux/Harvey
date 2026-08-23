import { existsSync, readFileSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { parse } from "yaml";
import { AUDIT_MODULES, type AuditModule } from "./audit-coverage.js";
import { CALIBRATION_PLANTS } from "./audit-conservation.js";
import type { ModuleRunner } from "./audit-runner.js";
import { AUDIT_RUNNERS } from "./audit-runners.js";
import { discoverEffectivenessRouteGraph, type RouteGraphImplementation } from "./effectiveness-route-graph.js";
import { HEURISTIC_CORPUS } from "./scan/heuristic-precision.js";
import { CORPUS, mechanicalCorpus } from "./scan/calibration.js";
import { m6HandrolledEntries } from "./scan/calibration/m6-handrolled.entries.js";
import { sourceTierCorpus } from "./scan/source-recall.js";
import { FREE_RECALL_CORPUS } from "./scan/free-recall-corpus.js";
import {
  EFFECTIVENESS_INVENTORY_SCHEMA,
  PRODUCER_POPULATION_CLASSES,
  PRODUCER_TIERS,
  REQUIRED_RUNTIME_EDGE,
  type EffectivenessExemption,
  type EffectivenessConservationReceipt,
  type EffectivenessFamilyCoverageReceipt,
  type EffectivenessInventory,
  type EffectivenessPopulationSummary,
  type EffectivenessProducer,
  type EffectivenessVenue,
  type ProducerFindingFamily,
  type ProducerImplementation,
  type ProducerPopulationClass,
  type ProductionProducerBinding,
} from "./effectiveness-schema.js";
import { findingFamilyKind } from "./findings.js";
import {
  checkScoredGates,
  describeCadence,
  loadGateInputs,
  SCORED_GATES,
  type ScoredGate,
} from "./scored-gates.js";
import {
  MECHANICAL_DETECTORS,
  type MechanicalDetectorDefinition,
} from "./scan/mechanical-detector-registry.js";
import {
  MECHANICAL_REGISTRY,
  type MechanicalRegistryEntry,
} from "./scan/mechanical-engine-registry.js";
import { discoverLocalSemgrepFamilies } from "./scan/semgrep-family-cache.js";
import { REGISTRY_PACKS } from "./scan/semgrep.js";
import {
  assertProducerExecutionReceipt,
  assertUniqueProducerExecutionReceipts,
  receiptHasRoute,
  type ProducerExecutionReceipt,
} from "./producer-execution-receipt.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const LOCAL_SEMGREP_ROOT = join("src", "scan", "rules", "semgrep");
const DIRECT_RESPONSE_WRITE_RULE = "javascript.express.security.audit.xss.direct-response-write.direct-response-write";

interface LocalSemgrepRule {
  readonly familyId: string;
  readonly file: string;
  readonly id: string;
  readonly taxonomy: string;
}

interface RegistryInputs {
  readonly root?: string;
  readonly auditRunners?: readonly ModuleRunner[];
  readonly mechanicalRegistry?: readonly MechanicalRegistryEntry[];
  readonly mechanicalDetectors?: readonly MechanicalDetectorDefinition[];
  readonly scoredGates?: readonly ScoredGate[];
  readonly plants?: typeof CALIBRATION_PLANTS;
  readonly registryPacks?: readonly string[];
  /** Optional exact ids from a materialized registry snapshot; the six pack identities remain stable. */
  readonly registryPackRuleIds?: Readonly<Record<string, readonly string[]>>;
  readonly producerExecutionReceipts?: readonly ProducerExecutionReceipt[];
}

const nonEmpty = (value: string): boolean => value.trim().length > 0;
const unique = <T>(values: readonly T[]): T[] => [...new Set(values)];
const byText = (a: string, b: string): number => a.localeCompare(b);

function deepFreeze<T>(value: T): T {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  return Object.freeze(value);
}

function implementation(file: string, symbol: string, kind: ProducerImplementation["kind"] = "function"): ProducerImplementation {
  return { file, symbol, kind };
}

function family(module: AuditModule, idPattern: string, taxonomyPattern: string, kind = findingFamilyKind({ id: idPattern, taxonomy: taxonomyPattern })): ProducerFindingFamily {
  return { module, idPattern, taxonomyPattern, kind };
}

function readLocalSemgrepRules(root: string): { families: string[]; rules: LocalSemgrepRule[] } {
  const configRoot = join(root, LOCAL_SEMGREP_ROOT);
  const discovered = discoverLocalSemgrepFamilies(configRoot);
  const rules: LocalSemgrepRule[] = [];
  for (const config of discovered) {
    const relativeFile = relative(root, config.configPath);
    const document = parse(readFileSync(config.configPath, "utf8")) as {
      rules?: { id?: unknown; metadata?: { harveyTaxonomy?: unknown } }[];
    };
    if (!Array.isArray(document.rules)) throw new Error(`${relativeFile}: local Semgrep config has no rules array`);
    for (const row of document.rules) {
      if (typeof row.id !== "string" || !row.id.startsWith("harvey-")) {
        throw new Error(`${relativeFile}: every local Semgrep rule needs a stable harvey-* id`);
      }
      rules.push({
        familyId: config.id,
        file: relativeFile,
        id: row.id,
        taxonomy: typeof row.metadata?.harveyTaxonomy === "string" ? row.metadata.harveyTaxonomy : row.id,
      });
    }
  }
  const ids = rules.map((rule) => rule.id);
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
  if (duplicates.length > 0) throw new Error(`duplicate local Semgrep rule ids: ${unique(duplicates).join(", ")}`);
  return {
    families: discovered.map((entry) => entry.id).sort(byText),
    rules: rules.sort((a, b) => a.id.localeCompare(b.id)),
  };
}

function templatePattern(node: ts.TemplateExpression): string {
  return `${node.head.text}${node.templateSpans.map((span) => `*${span.literal.text}`).join("")}`;
}

function stringValues(node: ts.Node): string[] {
  if (ts.isStringLiteralLike(node)) return [node.text];
  if (ts.isTemplateExpression(node)) return [templatePattern(node)];
  return node.getChildren().flatMap(stringValues);
}

function literalTaxonomies(root: string, file: string): string[] {
  const path = join(root, file);
  if (!existsSync(path)) return [];
  const source = ts.createSourceFile(
    file,
    readFileSync(path, "utf8"),
    ts.ScriptTarget.Latest,
    true,
    [".js", ".mjs", ".cjs"].includes(extname(file)) ? ts.ScriptKind.JS : ts.ScriptKind.TS,
  );
  const values: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isPropertyAssignment(node)) {
      const name = ts.isIdentifier(node.name) || ts.isStringLiteralLike(node.name) ? node.name.text : undefined;
      if (name === "taxonomy") values.push(...stringValues(node.initializer));
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return unique(values.filter(nonEmpty)).sort(byText);
}

function normalizeBinding(binding: ProductionProducerBinding, root: string): ProductionProducerBinding {
  const literal = unique(binding.implementations.flatMap((item) => literalTaxonomies(root, item.file)));
  const families = binding.findingFamilies.flatMap((entry) => {
    if (entry.taxonomyPattern !== "@literal-taxonomies") return [entry];
    const scoped = binding.modules.length === 1
      ? literal
      : literal.filter((taxonomy) => taxonomy.startsWith(`${entry.module} `) || taxonomy.startsWith(`${entry.module} —`));
    if (scoped.length === 0) throw new Error(`${binding.id}: @literal-taxonomies resolved no ${entry.module} taxonomy`);
    return scoped.map((taxonomy) => family(
      entry.module,
      entry.idPattern,
      taxonomy,
      binding.populationClass === "disclosure-only"
        ? entry.kind
        : findingFamilyKind({ id: entry.idPattern, taxonomy }),
    ));
  });
  return {
    ...binding,
    modules: unique(binding.modules).sort(byText),
    tiers: unique(binding.tiers).sort(byText),
    implementations: [...binding.implementations].sort((a, b) => `${a.file}#${a.symbol}`.localeCompare(`${b.file}#${b.symbol}`)),
    findingFamilies: unique(families.map((entry) => JSON.stringify(entry))).map((entry) => JSON.parse(entry) as ProducerFindingFamily).sort((a, b) => `${a.module}:${a.idPattern}:${a.taxonomyPattern}:${a.kind}`.localeCompare(`${b.module}:${b.idPattern}:${b.taxonomyPattern}:${b.kind}`)),
  };
}

function mechanicalFamilies(entry: MechanicalRegistryEntry, detector: MechanicalDetectorDefinition | undefined): ProducerFindingFamily[] {
  const idPattern = detector?.findingIds.join("|") || "@runtime-id";
  return entry.taxonomies.map((taxonomy) => family(entry.module, idPattern, taxonomy));
}

function normalizeMechanicalProducer(
  entry: MechanicalRegistryEntry,
  detector: MechanicalDetectorDefinition | undefined,
): ProductionProducerBinding {
  const findingFamilies = mechanicalFamilies(entry, detector);
  const inferred: ProducerPopulationClass = entry.phase === "normalization"
    ? "synthesizer"
    : detector?.populationClass
      ?? (findingFamilies.every((item) => item.kind !== "finding") ? "disclosure-only" : "true-finding-producer");
  const implementationKind: ProducerImplementation["kind"] = entry.phase === "normalization" ? "synthesizer" : "function";
  return {
    id: `mechanical:${entry.phase}:${entry.id}`,
    modules: [entry.module],
    tiers: ["free"],
    populationClass: inferred,
    implementations: entry.implementations.map((item) => implementation(item.file, item.exportName, implementationKind)),
    findingFamilies,
    deliveryKind: "registry-dispatch",
  };
}

function expandSemgrepAggregate(
  entry: MechanicalRegistryEntry,
  local: ReturnType<typeof readLocalSemgrepRules>,
  packs: readonly string[],
  resolvedPackRules: Readonly<Record<string, readonly string[]>>,
): ProductionProducerBinding[] {
  const disclosureSymbols = new Set([
    "semgrepDiagnosticEvidence",
    "partitionGuardTokenSuppressed",
    "partitionMarkerSuppressed",
    "semgrepSuppressionFinding",
    "semgrepScopeFinding",
    "semgrepErrorFinding",
    "semgrepUnavailableFinding",
  ]);
  const companionSymbols = new Set(["checkMissingCsp", "checkHostingConfigHeaders", "checkPublicDirSensitive"]);
  const disclosures = entry.implementations.filter((item) => disclosureSymbols.has(item.exportName));
  const companions = entry.implementations.filter((item) => companionSymbols.has(item.exportName));
  const adapters = entry.implementations.filter((item) => !disclosureSymbols.has(item.exportName) && !companionSymbols.has(item.exportName));
  const result: ProductionProducerBinding[] = [
    {
      id: "adapter:semgrep-runtime",
      modules: ["M1"], tiers: ["free"], populationClass: "adapter",
      implementations: adapters.map((item) => implementation(item.file, item.exportName, "adapter")),
      findingFamilies: [],
      deliveryKind: "registry-dispatch",
    },
    {
      id: "disclosure:semgrep-runtime-scope",
      modules: ["M1"], tiers: ["free"], populationClass: "disclosure-only",
      implementations: disclosures.map((item) => implementation(item.file, item.exportName)),
      findingFamilies: entry.taxonomies.filter((taxonomy) => findingFamilyKind({ id: "", taxonomy }) !== "finding").map((taxonomy) => family("M1", "@runtime-id", taxonomy)),
      deliveryKind: "registry-dispatch",
    },
    {
      id: "mechanical:semgrep:companion-config",
      modules: ["M1"], tiers: ["free"], populationClass: "true-finding-producer",
      implementations: companions.map((item) => implementation(item.file, item.exportName)),
      findingFamilies: entry.taxonomies.filter((taxonomy) => taxonomy === "Missing security headers" || taxonomy === "Sensitive file in public/ directory").map((taxonomy) => family("M1", "@runtime-id", taxonomy)),
      deliveryKind: "registry-dispatch",
    },
  ];
  for (const rule of local.rules) {
    result.push({
      id: `semgrep:local:${rule.id}`,
      modules: ["M1"], tiers: ["free"], populationClass: "true-finding-producer",
      implementations: [implementation(rule.file, rule.id, "rule")],
      findingFamilies: [family("M1", rule.id, rule.taxonomy)],
      deliveryKind: "registry-dispatch",
    });
  }
  for (const pack of packs) {
    const ruleIds = unique(resolvedPackRules[pack] ?? []).sort(byText);
    result.push({
      id: `semgrep:registry:${pack}`,
      modules: ["M1"], tiers: ["free"], populationClass: "true-finding-producer",
      implementations: [implementation("src/scan/semgrep.ts", pack, "rule")],
      findingFamilies: ruleIds.length > 0
        ? ruleIds.map((id) => family("M1", id, id))
        : [family("M1", "@resolved-registry-rule-ids", `Semgrep registry pack ${pack}`)],
      deliveryKind: "registry-dispatch",
    });
  }
  result.push({
    id: `semgrep:registry:${DIRECT_RESPONSE_WRITE_RULE}`,
    modules: ["M1"], tiers: ["free"], populationClass: "true-finding-producer",
    implementations: [implementation("src/scan/semgrep.ts", DIRECT_RESPONSE_WRITE_RULE, "rule")],
    findingFamilies: [family("M1", DIRECT_RESPONSE_WRITE_RULE, DIRECT_RESPONSE_WRITE_RULE)],
    deliveryKind: "registry-dispatch",
  });
  return result;
}

function producerPopulation(
  root: string,
  auditRunners: readonly ModuleRunner[],
  mechanicalRegistry: readonly MechanicalRegistryEntry[],
  mechanicalDetectors: readonly MechanicalDetectorDefinition[],
  plants: typeof CALIBRATION_PLANTS,
  packs: readonly string[],
  resolvedPackRules: Readonly<Record<string, readonly string[]>>,
): { bindings: ProductionProducerBinding[]; local: ReturnType<typeof readLocalSemgrepRules>; auditIds: string[]; mechanicalIds: string[] } {
  const local = readLocalSemgrepRules(root);
  const auditBindings = auditRunners.flatMap((runner) => runner.producers).map((binding) => normalizeBinding(binding, root));
  const detectorById = new Map(mechanicalDetectors.map((detector) => [detector.id, detector]));
  const mechanicalBindings = mechanicalRegistry.flatMap((entry) => entry.phase === "semgrep"
    ? expandSemgrepAggregate(entry, local, packs, resolvedPackRules)
    : [normalizeMechanicalProducer(entry, entry.phase === "structural-ast" ? detectorById.get(entry.id) : undefined)]);
  const plantBindings: ProductionProducerBinding[] = plants.map((plant) => ({
    id: `plant:${plant.module}`,
    modules: [plant.module],
    tiers: ["free"],
    populationClass: "conservation-plant",
    implementations: [implementation("src/audit-conservation.ts", "CALIBRATION_PLANTS", "plant")],
    findingFamilies: [family(plant.module, `@conservation-plant:${plant.module}`, plant.taxonomy)],
    deliveryKind: "conservation",
  }));
  return {
    bindings: [...auditBindings, ...mechanicalBindings, ...plantBindings].map((binding) => normalizeBinding(binding, root)),
    local,
    auditIds: auditBindings.map((binding) => binding.id).sort(byText),
    mechanicalIds: mechanicalRegistry.map((entry) => `${entry.phase}:${entry.id}`).sort(byText),
  };
}

interface SemanticVenueInput {
  readonly gate: ScoredGate;
  readonly rootId: string;
  readonly producerIds: ReadonlySet<string>;
  readonly callReceiptIds: readonly string[];
  readonly corpusIds: readonly string[];
  readonly corpusRows: readonly ScorerCorpusRow[];
}

interface ScorerCorpusRow {
  readonly id: string;
  readonly module: AuditModule;
  /** Exact finding-id keys consumed by the scorer, never prose descriptions or notes. */
  readonly findingIds: readonly string[];
  /** Exact finding taxonomies consumed by scorers that declare one. */
  readonly taxonomies: readonly string[];
}

function corpusRow(value: { id: string; module?: string; cls?: string; taxonomy?: string; match?: readonly string[] }): ScorerCorpusRow {
  return {
    id: value.id,
    module: AUDIT_MODULES.includes(value.module as AuditModule) ? value.module as AuditModule : "M1",
    findingIds: unique([value.id, ...(value.match ?? [])].filter(nonEmpty)).sort(byText),
    taxonomies: unique([value.taxonomy ?? ""].filter(nonEmpty)).sort(byText),
  };
}

function scorerCorpus(gateId: string): ScorerCorpusRow[] {
  if (gateId === "validate-calibration") return [...mechanicalCorpus(CORPUS), ...m6HandrolledEntries].map(corpusRow).sort((a, b) => a.id.localeCompare(b.id));
  if (gateId === "validate-precision") return HEURISTIC_CORPUS.map(corpusRow).sort((a, b) => a.id.localeCompare(b.id));
  if (gateId === "validate-source-recall") return sourceTierCorpus().map(corpusRow).sort((a, b) => a.id.localeCompare(b.id));
  if (gateId === "validate-free-recall") return FREE_RECALL_CORPUS.flatMap((target) => target.entries.map(corpusRow)).sort((a, b) => a.id.localeCompare(b.id));
  return [];
}

function patternMatches(pattern: string, value: string): boolean {
  if (pattern.startsWith("@")) return false;
  const source = pattern.split("|").map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\\*/g, ".*").replace(/<n>/gi, "[0-9]+")).join("|");
  return new RegExp(`^(?:${source})$`, "i").test(value);
}

function familyCorpusIds(entry: ProducerFindingFamily, rows: readonly ScorerCorpusRow[]): string[] {
  return rows.filter((row) => row.module === entry.module && (
    row.findingIds.some((id) => patternMatches(entry.idPattern, id))
    || row.taxonomies.some((taxonomy) => patternMatches(entry.taxonomyPattern, taxonomy))
  )).map((row) => row.id).sort(byText);
}

function buildVenues(inputs: readonly SemanticVenueInput[], coveredFamilyIds: ReadonlyMap<string, readonly string[]>): EffectivenessVenue[] {
  const byGate = new Map(inputs.map((input) => [input.gate.id, input]));
  const gates = inputs.map((input) => input.gate);
  return gates.flatMap((gate): EffectivenessVenue[] => {
    const input = byGate.get(gate.id);
    if (!input || gate.cadence.kind === "none") return [];
    const provenance = gate.cadence.kind === "verify"
      ? "package.json#scripts.verify"
      : `${gate.cadence.file}#${gate.cadence.job}`;
    const familyIds = [...(coveredFamilyIds.get(gate.id) ?? [])].sort(byText);
    return [{
      id: gate.id,
      gateId: gate.id,
      modules: unique(familyIds.map((id) => id.split("::")[1]).filter((module): module is AuditModule => AUDIT_MODULES.includes(module as AuditModule))).sort(byText),
      producerClasses: ["true-finding-producer"],
      command: `pnpm ${gate.script}`,
      cadence: { kind: gate.cadence.kind, description: describeCadence(gate.cadence) },
      provenance,
      rootId: input.rootId,
      callReceiptIds: [...input.callReceiptIds].sort(byText),
      corpusIds: [...input.corpusIds].sort(byText),
      coveredFamilyIds: familyIds,
    }];
  }).sort((a, b) => a.id.localeCompare(b.id));
}

function familyIdentity(producerId: string, entry: ProducerFindingFamily): string {
  return `${producerId}::${entry.module}::${entry.kind}::${entry.idPattern}::${entry.taxonomyPattern}`;
}

function buildExemptions(
  bindings: readonly ProductionProducerBinding[],
  venuesByFamily: ReadonlyMap<string, readonly string[]>,
): EffectivenessExemption[] {
  const result: EffectivenessExemption[] = [];
  const uncoveredFamilies = (binding: ProductionProducerBinding): string[] => binding.findingFamilies
    .map((entry) => familyIdentity(binding.id, entry))
    .filter((id) => (venuesByFamily.get(id)?.length ?? 0) === 0)
    .sort(byText);
  const m2Bindings = bindings.filter((binding) => binding.populationClass === "true-finding-producer" && binding.modules.includes("M2") && uncoveredFamilies(binding).length > 0);
  const m2 = m2Bindings.map((binding) => binding.id).sort(byText);
  const m2Families = m2Bindings.flatMap(uncoveredFamilies).sort(byText);
  if (m2Families.length > 0) result.push({
    id: "exemption:m2-live-score",
    kind: "empirical",
    applicableProducerIds: m2,
    applicableFamilyIds: m2Families,
    provenance: "src/scored-gates.ts#validate-connected; tracked by #1491",
    owner: "Harvey M2 effectiveness owner (#1491)",
    decision: "Do not publish a producer effectiveness score from an M2 venue that has never run on cadence.",
    reason: "validate-connected is the named M2 scorer, but its live Supabase calibration fixture cannot currently stand up in CI, so the scored gate has cadence none.",
    cadence: "none",
    falsifier: "A named SCORED_GATES venue invokes every applicable M2 producer on labelled vulnerable and clean targets, reports its score, and has a verified non-none cadence.",
  });

  const unscored = bindings.filter((binding) => binding.populationClass === "true-finding-producer" && !binding.modules.includes("M2") && uncoveredFamilies(binding).length > 0);
  for (const modules of unique(unscored.map((binding) => [...binding.modules].sort(byText).join("-"))).sort(byText)) {
    const ids = unscored.filter((binding) => [...binding.modules].sort(byText).join("-") === modules).map((binding) => binding.id).sort(byText);
    result.push({
      id: `exemption:unscored:${modules}`,
      kind: "structural",
      applicableProducerIds: ids,
      applicableFamilyIds: unscored.filter((binding) => [...binding.modules].sort(byText).join("-") === modules).flatMap(uncoveredFamilies).sort(byText),
      provenance: `src/scored-gates.ts and effectiveness inventory schema ${EFFECTIVENESS_INVENTORY_SCHEMA}`,
      owner: `Harvey ${modules} effectiveness owner`,
      decision: "Keep this production population explicit without manufacturing a score from an unrelated module or helper test.",
      reason: `No current scored gate directly invokes the ${modules} producer population on a labelled positive and benign twin.`,
      cadence: "none",
      falsifier: `Add a SCORED_GATES venue that directly invokes these ${modules} producers on labelled vulnerable and clean inputs and reports a module-compatible score.`,
    });
  }

  for (const populationClass of PRODUCER_POPULATION_CLASSES.filter((kind) => kind !== "true-finding-producer")) {
    const ids = bindings.filter((binding) => binding.populationClass === populationClass).map((binding) => binding.id).sort(byText);
    if (ids.length === 0) continue;
    result.push({
      id: `exemption:not-a-producer:${populationClass}`,
      kind: "not-a-producer",
      applicableProducerIds: ids,
      applicableFamilyIds: bindings.filter((binding) => binding.populationClass === populationClass).flatMap((binding) => binding.findingFamilies.map((entry) => familyIdentity(binding.id, entry))).sort(byText),
      provenance: `src/effectiveness-schema.ts#${populationClass}`,
      owner: "Harvey effectiveness registry",
      decision: "Exclude this disjoint population from the true-finding-producer denominator while retaining its client-delivery identity.",
      reason: `${populationClass} rows are disclosures, accounting controls, adapters, or synthesizers rather than independent defect detections.`,
      cadence: "none",
      falsifier: "Reclassify only after production evidence shows this identity independently detects and emits a client defect rather than adapting, synthesizing, disclosing, or planting one.",
    });
  }
  return result.sort((a, b) => a.id.localeCompare(b.id));
}

function populationSummary(producers: readonly EffectivenessProducer[]): EffectivenessPopulationSummary {
  const count = (kind: ProducerPopulationClass): number => producers.filter((producer) => producer.populationClass === kind).length;
  const classes = {
    trueFindingProducers: count("true-finding-producer"),
    disclosureOnly: count("disclosure-only"),
    typedNotAssessed: count("typed-not-assessed"),
    conservationPlants: count("conservation-plant"),
    adapters: count("adapter"),
    synthesizers: count("synthesizer"),
  };
  return {
    producers: producers.length,
    ...classes,
    // Plants can carry a finding-shaped payload and synthesizers can carry output taxonomies, but
    // neither is an independently detected defect family. The denominator therefore counts true
    // families only from true producers and excludes both control populations.
    findingFamilies: producers.filter((producer) => producer.populationClass === "true-finding-producer").flatMap((producer) => producer.findingFamilies).filter((entry) => entry.kind === "finding").length,
    disclosureFamilies: producers.flatMap((producer) => producer.findingFamilies).filter((entry) => entry.kind === "coverage-disclosure").length,
    notAssessedFamilies: producers.flatMap((producer) => producer.findingFamilies).filter((entry) => entry.kind === "not-assessed").length,
    denominatorConserved: Object.values(classes).reduce((sum, value) => sum + value, 0) === producers.length,
  };
}

function normalizeProducer(
  binding: ProductionProducerBinding,
  routes: readonly string[],
  venuesByFamily: ReadonlyMap<string, readonly string[]>,
  exemptionByFamily: ReadonlyMap<string, string>,
  executionReceiptIds: readonly string[],
): EffectivenessProducer {
  const findingFamilies = binding.findingFamilies.map((entry) => {
    const id = familyIdentity(binding.id, entry);
    const venueIds = [...(venuesByFamily.get(id) ?? [])].sort(byText);
    const exemptionId = exemptionByFamily.get(id);
    return { ...entry, id, venueIds, ...(exemptionId ? { exemptionId } : {}) };
  });
  const venueIds = unique(findingFamilies.flatMap((entry) => entry.venueIds)).sort(byText);
  const exemptions = unique(findingFamilies.flatMap((entry) => entry.exemptionId ? [entry.exemptionId] : []));
  return {
    ...binding,
    findingFamilies,
    routeIds: [...routes].sort(byText),
    venueIds,
    executionReceiptIds: [...executionReceiptIds].sort(byText),
    ...(exemptions.length === 1 ? { exemptionId: exemptions[0] } : {}),
  };
}

export function buildEffectivenessInventory(inputs: RegistryInputs = {}): EffectivenessInventory {
  const root = inputs.root ?? REPO_ROOT;
  const auditRunners = inputs.auditRunners ?? AUDIT_RUNNERS;
  const mechanicalRegistry = inputs.mechanicalRegistry ?? MECHANICAL_REGISTRY;
  const mechanicalDetectors = inputs.mechanicalDetectors ?? MECHANICAL_DETECTORS;
  const scoredGates = inputs.scoredGates ?? SCORED_GATES;
  const plants = inputs.plants ?? CALIBRATION_PLANTS;
  const packs = inputs.registryPacks ?? REGISTRY_PACKS;
  const gateProblems = checkScoredGates(loadGateInputs(root), scoredGates);
  if (gateProblems.length > 0) throw new Error(`scored venue registry is invalid:\n${gateProblems.join("\n")}`);
  const producerExecutions = [...(inputs.producerExecutionReceipts ?? [])];
  assertUniqueProducerExecutionReceipts(producerExecutions);
  const runtimePackRuleIds = Object.fromEntries(producerExecutions
    .filter((receipt) => receipt.producerId.startsWith("semgrep:registry:"))
    .map((receipt) => [receipt.producerId.slice("semgrep:registry:".length), receipt.findingFamilyIds]));
  const population = producerPopulation(root, auditRunners, mechanicalRegistry, mechanicalDetectors, plants, packs, { ...(inputs.registryPackRuleIds ?? {}), ...runtimePackRuleIds });
  const routeImplementations: RouteGraphImplementation[] = population.bindings.flatMap((binding) => binding.implementations.map((item) => ({
    ...item,
    producerId: binding.id,
    deliveryKind: binding.deliveryKind,
    endpoint: binding.deliveryKind === "conservation" ? "conservation" : binding.populationClass === "true-finding-producer" ? "client-finding-delivery" : "coverage-disclosure",
  })));
  const routeGraph = discoverEffectivenessRouteGraph(root, routeImplementations);
  const semanticVenues: SemanticVenueInput[] = scoredGates.flatMap((gate): SemanticVenueInput[] => {
    if (gate.cadence.kind === "none") return [];
    const rootId = `src/cli/${gate.id}.ts`;
    const graph = discoverEffectivenessRouteGraph(root, routeImplementations, [rootId], { detectUnknown: false });
    const corpusRows = scorerCorpus(gate.id);
    return [{
      gate,
      rootId,
      producerIds: new Set(graph.routes.map((route) => route.producerId)),
      callReceiptIds: graph.calls.map((call) => call.id),
      corpusIds: corpusRows.map((row) => row.id),
      corpusRows,
    }];
  });
  const venuesByFamily = new Map<string, string[]>();
  const familyCorpusByVenue = new Map<string, readonly string[]>();
  for (const binding of population.bindings) {
    for (const entry of binding.findingFamilies) {
      const id = familyIdentity(binding.id, entry);
      const venueIds = binding.populationClass === "true-finding-producer"
        ? semanticVenues.filter((venue) => {
            if (!venue.producerIds.has(binding.id)) return false;
            const corpusIds = familyCorpusIds(entry, venue.corpusRows);
            if (corpusIds.length === 0) return false;
            familyCorpusByVenue.set(`${id}=>${venue.gate.id}`, corpusIds);
            return true;
          }).map((venue) => venue.gate.id).sort(byText)
        : [];
      venuesByFamily.set(id, venueIds);
    }
  }
  const exemptions = buildExemptions(population.bindings, venuesByFamily);
  const exemptionByFamily = new Map(exemptions.flatMap((exemption) => exemption.applicableFamilyIds.map((id) => [id, exemption.id] as const)));
  const routesByProducer = new Map(population.bindings.map((binding) => [binding.id, routeGraph.routes.filter((route) => route.producerId === binding.id).map((route) => route.id)]));
  const producers = population.bindings.map((binding) => normalizeProducer(
    binding,
    routesByProducer.get(binding.id) ?? [],
    venuesByFamily,
    exemptionByFamily,
    producerExecutions.filter((receipt) => receipt.producerId === binding.id).map((receipt) => receipt.executionId),
  )).sort((a, b) => a.id.localeCompare(b.id));
  const coveredFamilyIds = new Map(semanticVenues.map((venue) => [venue.gate.id, producers.flatMap((producer) => producer.findingFamilies.filter((entry) => entry.venueIds.includes(venue.gate.id)).map((entry) => entry.id)).sort(byText)]));
  const venues = buildVenues(semanticVenues, coveredFamilyIds);
  const semanticVenueById = new Map(semanticVenues.map((venue) => [venue.gate.id, venue]));
  const familyCoverage: EffectivenessFamilyCoverageReceipt[] = producers.flatMap((producer) => producer.findingFamilies.map((entry) => {
    const scoredBindings = entry.venueIds.map((venueId) => ({
      venueId,
      corpusIds: [...(familyCorpusByVenue.get(`${entry.id}=>${venueId}`) ?? [])],
      callReceiptIds: [...(semanticVenueById.get(venueId)?.callReceiptIds ?? [])].sort(byText),
    }));
    return {
      id: `family-coverage:${entry.id}`,
      producerId: producer.id,
      familyId: entry.id,
      kind: scoredBindings.length > 0 ? "scored-family-binding" as const : "exempt-family-binding" as const,
      scoredBindings,
      ...(entry.exemptionId ? { exemptionId: entry.exemptionId } : {}),
    };
  })).sort((a, b) => a.id.localeCompare(b.id));
  const conservation: EffectivenessConservationReceipt[] = producers.filter((producer) => producer.populationClass === "conservation-plant").map((producer) => ({
    id: `conservation:${producer.id}`,
    producerId: producer.id,
    executionReceiptIds: [...producer.executionReceiptIds],
  })).sort((a, b) => a.id.localeCompare(b.id));
  const inventory: EffectivenessInventory = {
    schema: EFFECTIVENESS_INVENTORY_SCHEMA,
    producers,
    venues,
    exemptions,
    summary: populationSummary(producers),
    receipt: {
      mechanicalDefinitions: mechanicalRegistry.length,
      mechanicalProducerIds: population.mechanicalIds,
      localSemgrepFamilies: population.local.families.length,
      localSemgrepFamilyIds: population.local.families,
      localSemgrepRuleIds: population.local.rules.length,
      localSemgrepRules: population.local.rules.map((rule) => rule.id),
      registrySemgrepPacks: packs.length,
      registrySemgrepPackIds: [...packs].sort(byText),
      auditRunnerBindings: population.auditIds.length,
      auditRunnerProducerIds: population.auditIds,
      productionRoots: routeGraph.roots,
      calls: routeGraph.calls,
      consumers: routeGraph.consumers,
      routes: routeGraph.routes,
      familyCoverage,
      conservation,
      unresolvedFindingDispatches: routeGraph.unresolvedFindingDispatches,
      producerExecutions: producerExecutions.sort((a, b) => a.executionId.localeCompare(b.executionId)),
    },
  };
  const problems = validateEffectivenessInventory(inventory, { root, scoredGates });
  if (problems.length > 0) throw new Error(`effectiveness inventory is invalid:\n${problems.join("\n")}`);
  return deepFreeze(inventory);
}

export function validateEffectivenessInventory(
  inventory: EffectivenessInventory,
  options: { root?: string; scoredGates?: readonly ScoredGate[] } = {},
): string[] {
  const root = options.root ?? REPO_ROOT;
  const scoredGates = options.scoredGates ?? SCORED_GATES;
  const problems: string[] = [];
  for (const problem of checkScoredGates(loadGateInputs(root), scoredGates)) problems.push(`scored venue registry: ${problem}`);
  if (inventory.schema !== EFFECTIVENESS_INVENTORY_SCHEMA) problems.push(`schema ${inventory.schema} is not supported`);
  const producerIds = inventory.producers.map((producer) => producer.id);
  for (const id of unique(producerIds.filter((id, index) => producerIds.indexOf(id) !== index))) problems.push(`${id}: duplicate producer id`);
  const venueIds = inventory.venues.map((venue) => venue.id);
  for (const id of unique(venueIds.filter((id, index) => venueIds.indexOf(id) !== index))) problems.push(`${id}: duplicate scored venue id`);
  const exemptionIds = inventory.exemptions.map((exemption) => exemption.id);
  for (const id of unique(exemptionIds.filter((id, index) => exemptionIds.indexOf(id) !== index))) problems.push(`${id}: duplicate exemption id`);
  const producerById = new Map(inventory.producers.map((producer) => [producer.id, producer]));
  const venueById = new Map(inventory.venues.map((venue) => [venue.id, venue]));
  const exemptionById = new Map(inventory.exemptions.map((exemption) => [exemption.id, exemption]));
  const gateById = new Map(scoredGates.map((gate) => [gate.id, gate]));

  for (const producer of inventory.producers) {
    if (!nonEmpty(producer.id)) problems.push("producer has an empty id");
    if (!PRODUCER_POPULATION_CLASSES.includes(producer.populationClass)) problems.push(`${producer.id}: unknown population class ${producer.populationClass}`);
    if (producer.modules.length === 0 || producer.modules.some((module) => !AUDIT_MODULES.includes(module))) problems.push(`${producer.id}: module ownership is empty or invalid`);
    if (producer.tiers.length === 0 || producer.tiers.some((tier) => !PRODUCER_TIERS.includes(tier))) problems.push(`${producer.id}: tier ownership is empty or invalid`);
    if (producer.implementations.length === 0) problems.push(`${producer.id}: no implementation identity`);
    for (const item of producer.implementations) {
      const path = join(root, item.file);
      if (!existsSync(path)) {
        problems.push(`${producer.id}: orphaned implementation file ${item.file}`);
      }
    }
    // routeIds describe static candidates only. Runtime liveness is established exclusively by
    // producerExecutionReceipts and therefore an empty candidate list is not manufactured here.
    if (producer.implementations.some((item) => item.kind === "synthesizer") && producer.populationClass !== "synthesizer") {
      problems.push(`${producer.id}: synthesizer implementation is wrongly classified as ${producer.populationClass}`);
    }
    if (producer.populationClass === "synthesizer" && !producer.implementations.some((item) => item.kind === "synthesizer")) problems.push(`${producer.id}: synthesizer class has no synthesizer implementation`);
    if (producer.populationClass === "true-finding-producer" && !producer.findingFamilies.some((entry) => entry.kind === "finding")) problems.push(`${producer.id}: true producer has no finding family`);
    if (producer.populationClass === "disclosure-only" && producer.findingFamilies.some((entry) => entry.kind === "finding")) problems.push(`${producer.id}: disclosure-only producer declares a true finding family`);
    for (const entry of producer.findingFamilies) {
      if (!producer.modules.includes(entry.module)) problems.push(`${producer.id}: family ${entry.idPattern} belongs to ${entry.module}, outside producer modules [${producer.modules.join(", ")}]`);
      if (!nonEmpty(entry.idPattern) || !nonEmpty(entry.taxonomyPattern)) problems.push(`${producer.id}: empty finding-family pattern`);
      if (entry.venueIds.length > 0 && entry.exemptionId) problems.push(`${entry.id}: stale exemption ${entry.exemptionId} remains after a scored venue was assigned`);
      if (entry.venueIds.length === 0 && !entry.exemptionId) problems.push(`${entry.id}: neither scored venue nor structured exemption is assigned`);
      for (const venueId of entry.venueIds) {
        const venue = venueById.get(venueId);
        if (!venue) problems.push(`${entry.id}: scored venue ${venueId} no longer exists`);
        else if (!venue.coveredFamilyIds.includes(entry.id)) problems.push(`${entry.id}: venue ${venueId} does not point back to this family`);
      }
      if (entry.exemptionId) {
        const exemption = exemptionById.get(entry.exemptionId);
        if (!exemption) problems.push(`${entry.id}: exemption ${entry.exemptionId} no longer exists`);
        else if (!exemption.applicableFamilyIds.includes(entry.id)) problems.push(`${entry.id}: exemption ${entry.exemptionId} does not point back to this family`);
      }
    }
    for (const id of producer.venueIds) {
      const venue = venueById.get(id);
      if (!venue) {
        problems.push(`${producer.id}: scored venue ${id} no longer exists`);
        continue;
      }
      if (!venue.modules.some((module) => producer.modules.includes(module))) problems.push(`${producer.id}: venue ${id} has no compatible module`);
      if (!venue.producerClasses.includes(producer.populationClass)) problems.push(`${producer.id}: venue ${id} cannot score ${producer.populationClass}`);
    }
    if (producer.exemptionId) {
      const exemption = exemptionById.get(producer.exemptionId);
      if (!exemption) problems.push(`${producer.id}: exemption ${producer.exemptionId} no longer exists`);
      else {
        if (!exemption.applicableProducerIds.includes(producer.id)) problems.push(`${producer.id}: exemption ${producer.exemptionId} does not name this producer`);
        if (producer.populationClass === "true-finding-producer" && exemption.kind === "not-a-producer") problems.push(`${producer.id}: true producer cannot use a not-a-producer exemption`);
        if (producer.populationClass !== "true-finding-producer" && exemption.kind !== "not-a-producer") problems.push(`${producer.id}: ${producer.populationClass} must use a not-a-producer exemption`);
      }
    }
  }

  const executionIds = inventory.receipt.producerExecutions.map((receipt) => receipt.executionId);
  if (unique(executionIds).length !== executionIds.length) problems.push("producer execution receipt ids are duplicated");
  for (const receipt of inventory.receipt.producerExecutions) {
    try { assertProducerExecutionReceipt(receipt); } catch (error) {
      problems.push(`producer execution ${receipt.executionId ?? "<unknown>"}: ${error instanceof Error ? error.message : String(error)}`);
      continue;
    }
    const producer = producerById.get(receipt.producerId);
    if (!producer) {
      problems.push(`${receipt.executionId}: unknown producer ${receipt.producerId}`);
      continue;
    }
    if (!producer.executionReceiptIds.includes(receipt.executionId)) problems.push(`${receipt.executionId}: producer does not point back to this execution`);
    if (producer.modules.length !== 1 && !producer.modules.includes(receipt.module)) problems.push(`${receipt.executionId}: receipt module is outside producer ownership`);
    else if (!producer.modules.includes(receipt.module)) problems.push(`${receipt.executionId}: receipt module is outside producer ownership`);
    if (!producer.tiers.includes(receipt.tier)) problems.push(`${receipt.executionId}: receipt tier is outside producer ownership`);
    if (!producer.implementations.some((implementation) => `${implementation.file}#${implementation.symbol}` === receipt.implementationId)) {
      problems.push(`${receipt.executionId}: receipt implementation is not owned by ${producer.id}`);
    }
    const requiredEdge = producer.id.startsWith("semgrep:") ? "semgrep-family" : REQUIRED_RUNTIME_EDGE[producer.deliveryKind];
    if (!receiptHasRoute(receipt, [requiredEdge])) {
      problems.push(`${receipt.executionId}: missing required ${requiredEdge} runtime edge`);
    }
    const knownFamilies = new Set(producer.findingFamilies.flatMap((family) => [family.id, family.idPattern]));
    for (const familyId of receipt.findingFamilyIds) if (!knownFamilies.has(familyId)) problems.push(`${receipt.executionId}: unknown finding family ${familyId}`);
  }
  for (const producer of inventory.producers) {
    const expected = inventory.receipt.producerExecutions.filter((receipt) => receipt.producerId === producer.id).map((receipt) => receipt.executionId).sort(byText);
    if (JSON.stringify(expected) !== JSON.stringify([...producer.executionReceiptIds].sort(byText))) problems.push(`${producer.id}: execution receipt backlink drift`);
  }

  for (const venue of inventory.venues) {
    const gate = gateById.get(venue.gateId);
    if (!gate) problems.push(`${venue.id}: mapped scored gate ${venue.gateId} no longer exists`);
    else {
      if (gate.cadence.kind === "none") problems.push(`${venue.id}: mapped scored gate has no cadence`);
      if (venue.id !== gate.id) problems.push(`${venue.id}: venue identity must equal its live scored gate ${gate.id}`);
      if (venue.command !== `pnpm ${gate.script}`) problems.push(`${venue.id}: command no longer invokes ${gate.script}`);
      if (venue.cadence.kind !== gate.cadence.kind) problems.push(`${venue.id}: cadence kind no longer matches the live scored gate`);
      const expectedProvenance = gate.cadence.kind === "verify"
        ? "package.json#scripts.verify"
        : gate.cadence.kind === "workflow"
          ? `${gate.cadence.file}#${gate.cadence.job}`
          : undefined;
      if (expectedProvenance && venue.provenance !== expectedProvenance) problems.push(`${venue.id}: provenance no longer matches ${expectedProvenance}`);
      const expectedModules = unique(venue.coveredFamilyIds.map((id) => id.split("::")[1]).filter((module): module is AuditModule => AUDIT_MODULES.includes(module as AuditModule))).sort(byText);
      if (JSON.stringify([...venue.modules].sort(byText)) !== JSON.stringify(expectedModules)) {
        problems.push(`${venue.id}: module claims do not match the live venue population`);
      }
      if (JSON.stringify([...venue.producerClasses].sort(byText)) !== JSON.stringify(["true-finding-producer"])) {
        problems.push(`${venue.id}: scored venue must score exactly the true-finding-producer class`);
      }
      if (gate.cadence.kind === "verify") {
        const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { scripts?: Record<string, string> };
        if (!pkg.scripts?.verify?.includes(gate.script)) problems.push(`${venue.id}: package.json verify no longer invokes ${gate.script}`);
      } else if (gate.cadence.kind === "workflow") {
        const workflow = join(root, gate.cadence.file);
        if (!existsSync(workflow)) problems.push(`${venue.id}: workflow provenance file no longer exists`);
      }
    }
    if (!nonEmpty(venue.command) || !nonEmpty(venue.provenance) || !nonEmpty(venue.cadence.description)) problems.push(`${venue.id}: scored venue provenance/cadence is incomplete`);
  }
  for (const exemption of inventory.exemptions) {
    if (![exemption.provenance, exemption.owner, exemption.decision, exemption.reason, exemption.falsifier].every(nonEmpty)) problems.push(`${exemption.id}: exemption metadata is incomplete`);
    if (exemption.cadence !== "none") problems.push(`${exemption.id}: exemption cadence must be none`);
    if (exemption.applicableProducerIds.length === 0) problems.push(`${exemption.id}: exemption applies to no producers`);
    if (unique(exemption.applicableProducerIds).length !== exemption.applicableProducerIds.length) problems.push(`${exemption.id}: exemption repeats a producer id`);
    if (unique(exemption.applicableFamilyIds).length !== exemption.applicableFamilyIds.length) problems.push(`${exemption.id}: exemption repeats a family id`);
    for (const producerId of exemption.applicableProducerIds) {
      const producer = producerById.get(producerId);
      if (!producer) problems.push(`${exemption.id}: orphaned producer ${producerId}`);
      else if (!producer.findingFamilies.some((family) => family.exemptionId === exemption.id) && producer.findingFamilies.length > 0) problems.push(`${exemption.id}: ${producerId} does not point back to this exemption`);
    }
    for (const familyId of exemption.applicableFamilyIds) {
      const family = inventory.producers.flatMap((producer) => producer.findingFamilies).find((entry) => entry.id === familyId);
      if (!family) problems.push(`${exemption.id}: orphaned family ${familyId}`);
      else if (family.exemptionId !== exemption.id) problems.push(`${exemption.id}: ${familyId} does not point back to this exemption`);
    }
  }

  const implementationOwnerLists = new Map<string, string[]>();
  for (const producer of inventory.producers) {
    for (const item of producer.implementations) {
      const key = `${item.file}#${item.symbol}`;
      implementationOwnerLists.set(key, [...(implementationOwnerLists.get(key) ?? []), producer.id]);
    }
  }
  for (const [key, owners] of implementationOwnerLists) {
    if (owners.length < 2) continue;
    const ownerRows = owners.map((id) => producerById.get(id)).filter((row): row is EffectivenessProducer => !!row);
    if (!ownerRows.every((row) => row.populationClass === "conservation-plant")) {
      problems.push(`${key}: implementation is registered by multiple producer ids [${owners.join(", ")}]`);
    }
  }
  const implementationOwners = new Set(implementationOwnerLists.keys());
  for (const problem of inventory.receipt.unresolvedFindingDispatches) problems.push(problem);
  if (inventory.receipt.mechanicalDefinitions !== inventory.receipt.mechanicalProducerIds.length) problems.push("mechanical discovery receipt count does not match its identities");
  if (inventory.receipt.localSemgrepFamilies !== inventory.receipt.localSemgrepFamilyIds.length) problems.push("local Semgrep family receipt count does not match its identities");
  if (inventory.receipt.localSemgrepRuleIds !== inventory.receipt.localSemgrepRules.length) problems.push("local Semgrep rule receipt count does not match its identities");
  if (inventory.receipt.registrySemgrepPacks !== inventory.receipt.registrySemgrepPackIds.length) problems.push("registry Semgrep pack receipt count does not match its identities");
  if (inventory.receipt.auditRunnerBindings !== inventory.receipt.auditRunnerProducerIds.length) problems.push("audit-runner receipt count does not match its identities");

  const compareIdentityPopulation = (label: string, actual: readonly string[], expected: readonly string[]): void => {
    const actualUnique = unique(actual);
    if (actualUnique.length !== actual.length) problems.push(`${label} receipt repeats an identity`);
    const missing = unique(expected).filter((id) => !actualUnique.includes(id));
    const unexpected = actualUnique.filter((id) => !expected.includes(id));
    if (missing.length > 0 || unexpected.length > 0) problems.push(`${label} receipt does not close on production identities (missing: ${missing.join(", ") || "none"}; unexpected: ${unexpected.join(", ") || "none"})`);
    if (JSON.stringify(actual) !== JSON.stringify([...actual].sort(byText))) problems.push(`${label} receipt identities are not deterministic`);
  };
  const expectedMechanicalIds = MECHANICAL_REGISTRY.map((entry) => `${entry.phase}:${entry.id}`).sort(byText);
  const expectedAuditIds = AUDIT_RUNNERS.flatMap((runner) => runner.producers.map((producer) => producer.id)).sort(byText);
  const expectedLocal = readLocalSemgrepRules(root);
  compareIdentityPopulation("mechanical", inventory.receipt.mechanicalProducerIds, expectedMechanicalIds);
  compareIdentityPopulation("audit-runner", inventory.receipt.auditRunnerProducerIds, expectedAuditIds);
  compareIdentityPopulation("local Semgrep family", inventory.receipt.localSemgrepFamilyIds, expectedLocal.families);
  compareIdentityPopulation("local Semgrep rule", inventory.receipt.localSemgrepRules, expectedLocal.rules.map((rule) => rule.id));
  compareIdentityPopulation("registry Semgrep pack", inventory.receipt.registrySemgrepPackIds, [...REGISTRY_PACKS].sort(byText));
  for (const id of inventory.receipt.mechanicalProducerIds) {
    if (id.startsWith("semgrep:")) continue;
    if (!producerById.has(`mechanical:${id}`)) problems.push(`${id}: mechanical registry identity has no derived producer`);
  }
  for (const id of ["adapter:semgrep-runtime", "disclosure:semgrep-runtime-scope", "mechanical:semgrep:companion-config"]) {
    if (!producerById.has(id)) problems.push(`${id}: Semgrep aggregate identity is missing`);
  }
  for (const id of inventory.receipt.localSemgrepRules) if (!producerById.has(`semgrep:local:${id}`)) problems.push(`${id}: local Semgrep rule has no derived producer`);
  for (const id of inventory.receipt.registrySemgrepPackIds) if (!producerById.has(`semgrep:registry:${id}`)) problems.push(`${id}: registry Semgrep pack has no derived producer`);
  for (const id of inventory.receipt.auditRunnerProducerIds) if (!producerById.has(id)) problems.push(`${id}: audit-runner binding has no derived producer`);
  for (const module of AUDIT_MODULES) if (!producerById.has(`plant:${module}`)) problems.push(`${module}: conservation plant has no derived producer`);

  compareIdentityPopulation("route", inventory.receipt.routes.map((route) => route.id), inventory.receipt.routes.map((route) => route.id));
  compareIdentityPopulation("call", inventory.receipt.calls.map((call) => call.id), inventory.receipt.calls.map((call) => call.id));
  compareIdentityPopulation("consumer", inventory.receipt.consumers.map((consumer) => consumer.id), inventory.receipt.consumers.map((consumer) => consumer.id));
  const callById = new Map(inventory.receipt.calls.map((call) => [call.id, call]));
  const consumerById = new Map(inventory.receipt.consumers.map((consumer) => [consumer.id, consumer]));
  for (const consumer of inventory.receipt.consumers) {
    if (!producerById.has(consumer.producerId)) problems.push(`${consumer.id}: consumer names unknown producer ${consumer.producerId}`);
    if (!implementationOwners.has(consumer.implementationId)) problems.push(`${consumer.id}: consumer names unregistered implementation ${consumer.implementationId}`);
    if (!callById.has(consumer.callReceiptId)) problems.push(`${consumer.id}: consumer names missing call receipt ${consumer.callReceiptId}`);
  }
  for (const route of inventory.receipt.routes) {
    const owner = producerById.get(route.producerId);
    const consumer = consumerById.get(route.consumerReceiptId);
    if (!owner) problems.push(`${route.id}: route names unknown producer ${route.producerId}`);
    else {
      const ownedImplementations = owner.implementations.map((item) => `${item.file}#${item.symbol}`);
      if (!ownedImplementations.includes(route.implementationId)) problems.push(`${route.id}: route implementation ${route.implementationId} is not owned by ${route.producerId}`);
      const expectedEndpoint = owner.deliveryKind === "conservation"
        ? "conservation"
        : owner.populationClass === "true-finding-producer"
          ? "client-finding-delivery"
          : "coverage-disclosure";
      if (route.endpoint !== expectedEndpoint) problems.push(`${route.id}: route endpoint ${route.endpoint} does not match ${expectedEndpoint}`);
    }
    if (!consumer) problems.push(`${route.id}: route names missing consumer receipt ${route.consumerReceiptId}`);
    else if (consumer.producerId !== route.producerId || consumer.implementationId !== route.implementationId) problems.push(`${route.id}: route and consumer identities do not conserve`);
    if (route.callReceiptIds.length === 0) problems.push(`${route.id}: route has no typed call/registry/command/artifact receipt`);
    for (const callId of route.callReceiptIds) if (!callById.has(callId)) problems.push(`${route.id}: route names missing call receipt ${callId}`);
  }
  for (const producer of inventory.producers) {
    const expected = inventory.receipt.routes.filter((route) => route.producerId === producer.id).map((route) => route.id).sort(byText);
    if (JSON.stringify(producer.routeIds) !== JSON.stringify(expected)) problems.push(`${producer.id}: producer route ids do not close on the semantic route graph`);
  }
  const venuePairs = inventory.venues.flatMap((venue) => venue.coveredFamilyIds.map((familyId) => `${familyId}=>${venue.id}`)).sort(byText);
  const familyVenuePairs = inventory.producers.flatMap((producer) => producer.findingFamilies.flatMap((family) => family.venueIds.map((venueId) => `${family.id}=>${venueId}`))).sort(byText);
  if (JSON.stringify(venuePairs) !== JSON.stringify(familyVenuePairs)) problems.push("scored family/venue pair sets do not conserve exactly");
  const exemptionPairs = inventory.exemptions.flatMap((exemption) => exemption.applicableFamilyIds.map((familyId) => `${familyId}=>${exemption.id}`)).sort(byText);
  const familyExemptionPairs = inventory.producers.flatMap((producer) => producer.findingFamilies.flatMap((family) => family.exemptionId ? [`${family.id}=>${family.exemptionId}`] : [])).sort(byText);
  if (JSON.stringify(exemptionPairs) !== JSON.stringify(familyExemptionPairs)) problems.push("exempt family pair sets do not conserve exactly");
  const allFamilies = inventory.producers.flatMap((producer) => producer.findingFamilies.map((family) => ({ producer, family })));
  const familyById = new Map(allFamilies.map((row) => [row.family.id, row]));
  compareIdentityPopulation(
    "family coverage",
    inventory.receipt.familyCoverage.map((receipt) => receipt.familyId),
    allFamilies.map((row) => row.family.id).sort(byText),
  );
  for (const receipt of inventory.receipt.familyCoverage) {
    const row = familyById.get(receipt.familyId);
    if (!row) continue;
    if (receipt.producerId !== row.producer.id) problems.push(`${receipt.id}: family coverage names wrong producer ${receipt.producerId}`);
    const scored = row.family.venueIds.length > 0;
    const expectedKind = scored ? "scored-family-binding" : "exempt-family-binding";
    if (receipt.kind !== expectedKind) problems.push(`${receipt.id}: family coverage kind does not match ${expectedKind}`);
    if (scored) {
      if (receipt.exemptionId) problems.push(`${receipt.id}: scored family coverage also names exemption ${receipt.exemptionId}`);
      const bindingVenues = receipt.scoredBindings.map((binding) => binding.venueId).sort(byText);
      if (JSON.stringify(bindingVenues) !== JSON.stringify([...row.family.venueIds].sort(byText))) problems.push(`${receipt.id}: scored bindings do not close on family venues`);
      for (const binding of receipt.scoredBindings) {
        const venue = venueById.get(binding.venueId);
        if (!venue) continue;
        if (binding.corpusIds.length === 0 || binding.corpusIds.some((id) => !venue.corpusIds.includes(id))) problems.push(`${receipt.id}: scorer corpus ids are empty or outside ${binding.venueId}`);
        if (JSON.stringify([...binding.callReceiptIds].sort(byText)) !== JSON.stringify([...venue.callReceiptIds].sort(byText))) problems.push(`${receipt.id}: scorer call path does not close on ${binding.venueId}`);
      }
    } else {
      if (receipt.scoredBindings.length > 0) problems.push(`${receipt.id}: exempt family coverage retains scored bindings`);
      if (receipt.exemptionId !== row.family.exemptionId) problems.push(`${receipt.id}: family coverage exemption does not close on ${row.family.exemptionId ?? "none"}`);
    }
  }
  const expectedConservation = inventory.producers.filter((producer) => producer.populationClass === "conservation-plant");
  compareIdentityPopulation(
    "conservation",
    inventory.receipt.conservation.map((receipt) => receipt.producerId),
    expectedConservation.map((producer) => producer.id).sort(byText),
  );
  for (const receipt of inventory.receipt.conservation) {
    const producer = producerById.get(receipt.producerId);
    if (!producer) continue;
    if (JSON.stringify(receipt.executionReceiptIds) !== JSON.stringify(producer.executionReceiptIds)) problems.push(`${receipt.id}: conservation executions do not close on ${producer.id}`);
    if (receipt.executionReceiptIds.some((id) => !inventory.receipt.producerExecutions.some((execution) => execution.executionId === id && receiptHasRoute(execution, ["conservation-consume"])))) problems.push(`${receipt.id}: conservation execution does not contain a consume edge`);
  }
  for (const module of AUDIT_MODULES) if (!inventory.producers.some((producer) => producer.modules.includes(module))) problems.push(`${module}: no producer population is registered`);
  const summary = populationSummary(inventory.producers);
  if (JSON.stringify(summary) !== JSON.stringify(inventory.summary)) problems.push("population summary does not match the disjoint producer/family population");
  if (!inventory.summary.denominatorConserved) problems.push("producer denominator is not conserved across disjoint population classes");
  return problems;
}

interface EffectivenessDeliveryObservation {
  readonly findingId: string;
  readonly producerId: string;
  readonly familyId: string;
  readonly venueId: string;
}

/**
 * Validate the final W4 boundary. Venue calls and family declarations are intentionally ignored:
 * every delivered finding must be conserved by one producer-specific runtime route ending at the
 * exact venue, and every claimed runtime delivery must name a finding actually in the client set.
 */
export function validateEffectivenessDelivery(
  inventory: EffectivenessInventory,
  delivered: readonly EffectivenessDeliveryObservation[],
): string[] {
  const problems = validateEffectivenessInventory(inventory);
  const producerById = new Map(inventory.producers.map((producer) => [producer.id, producer]));
  const receiptByExecution = new Map(inventory.receipt.producerExecutions.map((receipt) => [receipt.executionId, receipt]));
  const observedKeys: string[] = [];
  for (const observation of delivered) {
    const producer = producerById.get(observation.producerId);
    if (!producer) {
      problems.push(`${observation.findingId}: delivery names unknown producer ${observation.producerId}`);
      continue;
    }
    const family = producer.findingFamilies.find((candidate) => candidate.id === observation.familyId || candidate.idPattern === observation.familyId);
    if (!family) {
      problems.push(`${observation.findingId}: delivery names unknown family ${observation.familyId}`);
      continue;
    }
    if (observation.venueId !== "run-audit" && !family.venueIds.includes(observation.venueId)) problems.push(`${observation.findingId}: family ${family.id} is not bound to venue ${observation.venueId}`);
    const candidates = producer.executionReceiptIds.map((id) => receiptByExecution.get(id)).filter((receipt): receipt is ProducerExecutionReceipt => !!receipt)
      .filter((receipt) => receipt.findingIds.includes(observation.findingId)
        && receipt.findingFamilyIds.some((id) => id === family.id || id === family.idPattern)
        && receipt.edges.some((edge) => edge.kind === "client-delivery" && edge.to === `venue:${observation.venueId}`));
    if (candidates.length !== 1) problems.push(`${observation.findingId}: expected one exact producer-to-client delivery receipt, found ${candidates.length}`);
    observedKeys.push(`${observation.producerId}:${observation.familyId}:${observation.venueId}:${observation.findingId}`);
  }
  if (unique(observedKeys).length !== observedKeys.length) problems.push("client delivery observations contain duplicates");
  for (const receipt of inventory.receipt.producerExecutions) {
    for (const edge of receipt.edges.filter((candidate) => candidate.kind === "client-delivery")) {
      const venueId = edge.to.startsWith("venue:") ? edge.to.slice("venue:".length) : "";
      if (venueId !== "run-audit" && !inventory.venues.some((venue) => venue.id === venueId)) problems.push(`${receipt.executionId}: client delivery names unknown venue ${edge.to}`);
      for (const findingId of receipt.findingIds) {
        if (!delivered.some((observation) => observation.findingId === findingId && observation.producerId === receipt.producerId && observation.venueId === venueId)) {
          problems.push(`${receipt.executionId}: runtime receipt claims undelivered finding ${findingId}`);
        }
      }
    }
  }
  return unique(problems);
}

export function serializeEffectivenessInventory(inventory: EffectivenessInventory): string {
  return `${JSON.stringify(inventory, null, 2)}\n`;
}

let defaultEffectivenessInventory: EffectivenessInventory | undefined;
let defaultEffectivenessInventoryJson: string | undefined;

/**
 * Construct the repository-wide inventory only when a consumer actually requests it. Importing
 * this module is common in light tests that exercise delivery validation, and building the full
 * TypeScript route graph at module evaluation blocks Vitest's worker RPC channel.
 */
export function getEffectivenessInventory(): EffectivenessInventory {
  defaultEffectivenessInventory ??= buildEffectivenessInventory();
  return defaultEffectivenessInventory;
}

/** Serialize the same memoized inventory; never trigger a second graph construction. */
export function getEffectivenessInventoryJson(): string {
  defaultEffectivenessInventoryJson ??= serializeEffectivenessInventory(getEffectivenessInventory());
  return defaultEffectivenessInventoryJson;
}
