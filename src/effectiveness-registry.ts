import { existsSync, readFileSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { parse } from "yaml";
import { AUDIT_MODULES, type AuditModule } from "./audit-coverage.js";
import { CALIBRATION_PLANTS } from "./audit-conservation.js";
import type { ModuleRunner } from "./audit-runner.js";
import { AUDIT_RUNNERS } from "./audit-runners.js";
import {
  EFFECTIVENESS_INVENTORY_SCHEMA,
  PRODUCER_POPULATION_CLASSES,
  PRODUCER_TIERS,
  type EffectivenessDiscoveredCall,
  type EffectivenessExemption,
  type EffectivenessInventory,
  type EffectivenessPopulationSummary,
  type EffectivenessProducer,
  type EffectivenessVenue,
  type ProducerConsumerHop,
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

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const LOCAL_SEMGREP_ROOT = join("src", "scan", "rules", "semgrep");
const COMPOSITION_SEAMS = [
  "src/cli/static-detect.ts",
  "src/cli/quality-scan.ts",
  "src/cli/hotspot-scan.ts",
  "src/cli/mutation-scan.ts",
  "src/cli/pentest.ts",
  "src/pentest/engine.ts",
  "tools/pii-classify.mjs",
] as const;

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

function mechanicalDelivery(entry: MechanicalRegistryEntry): ProducerConsumerHop[] {
  const phaseRunner: Record<MechanicalRegistryEntry["phase"], string> = {
    "secrets-history": "runRegisteredSecretsEngines",
    "dependency-advisory": "runRegisteredDependencyDetectors",
    semgrep: "runRegisteredSemgrepEngines",
    configuration: "runRegisteredConfigurationDetectors",
    "structural-ast": "runRegisteredMechanicalDetectors",
    normalization: "runRegisteredNormalizationEngines",
  };
  const additionalConsumers = entry.implementations.some((item) => ["detectHandrolledFindings", "checkUnassessedSfcFiles"].includes(item.exportName))
    ? [
        { file: "src/cli/static-detect.ts", contains: entry.implementations[0]!.exportName, description: "the static detector is an additional production consumer of this same producer identity" },
        { file: "src/audit-runners.ts", contains: "pnpm detect-static", description: "the M9 runner captures the additional static-detector output" },
      ]
    : [];
  return [
    { file: entry.registryFile, contains: entry.id, description: "the live mechanical phase registry owns this identity" },
    { file: "src/scan/mechanical.ts", contains: phaseRunner[entry.phase], description: "the production mechanical scan invokes this phase registry" },
    { file: "src/cli/quick-scan.ts", contains: "runMechanicalScan", description: "quick-scan consumes the mechanical result" },
    { file: "src/audit-runners.ts", contains: "pnpm quick-scan", description: "the M1 runner captures quick-scan findings" },
    { file: "src/cli/run-audit.ts", contains: "assembleEngagementDocument", description: "the engagement assembler consumes the captured findings" },
    { file: "report-template/render.mjs", contains: "findings", description: "the client report renders the finding population" },
    ...additionalConsumers,
  ];
}

function semgrepDelivery(file: string, token: string): ProducerConsumerHop[] {
  return [
    { file, contains: token, description: "the configured rule or pack identity is present in the production input" },
    { file: "src/scan/semgrep.ts", contains: "runSemgrep", description: "the Semgrep runtime executes the configured input" },
    { file: "src/scan/mechanical-semgrep-registry.ts", contains: "semgrep-and-companion-config", description: "the live mechanical phase owns Semgrep output" },
    { file: "src/scan/mechanical.ts", contains: "runRegisteredSemgrepEngines", description: "the production mechanical scan invokes the Semgrep phase" },
    { file: "src/cli/quick-scan.ts", contains: "runMechanicalScan", description: "quick-scan consumes the Semgrep result" },
    { file: "src/audit-runners.ts", contains: "pnpm quick-scan", description: "the M1 runner captures quick-scan findings" },
    { file: "src/cli/run-audit.ts", contains: "assembleEngagementDocument", description: "the engagement assembler consumes the captured findings" },
  ];
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
    consumerPath: [...binding.consumerPath],
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
    consumerPath: mechanicalDelivery(entry),
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
  const aggregatePath = mechanicalDelivery(entry);
  const result: ProductionProducerBinding[] = [
    {
      id: "adapter:semgrep-runtime",
      modules: ["M1"], tiers: ["free"], populationClass: "adapter",
      implementations: adapters.map((item) => implementation(item.file, item.exportName, "adapter")),
      findingFamilies: [], consumerPath: aggregatePath,
    },
    {
      id: "disclosure:semgrep-runtime-scope",
      modules: ["M1"], tiers: ["free"], populationClass: "disclosure-only",
      implementations: disclosures.map((item) => implementation(item.file, item.exportName)),
      findingFamilies: entry.taxonomies.filter((taxonomy) => findingFamilyKind({ id: "", taxonomy }) !== "finding").map((taxonomy) => family("M1", "@runtime-id", taxonomy)),
      consumerPath: aggregatePath,
    },
    {
      id: "mechanical:semgrep:companion-config",
      modules: ["M1"], tiers: ["free"], populationClass: "true-finding-producer",
      implementations: companions.map((item) => implementation(item.file, item.exportName)),
      findingFamilies: entry.taxonomies.filter((taxonomy) => taxonomy === "Missing security headers" || taxonomy === "Sensitive file in public/ directory").map((taxonomy) => family("M1", "@runtime-id", taxonomy)),
      consumerPath: aggregatePath,
    },
  ];
  for (const rule of local.rules) {
    result.push({
      id: `semgrep:local:${rule.id}`,
      modules: ["M1"], tiers: ["free"], populationClass: "true-finding-producer",
      implementations: [implementation(rule.file, rule.id, "rule")],
      findingFamilies: [family("M1", rule.id, rule.taxonomy)],
      consumerPath: semgrepDelivery(rule.file, rule.id),
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
      consumerPath: semgrepDelivery("src/scan/semgrep.ts", pack),
    });
  }
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
    consumerPath: [
      { file: "src/audit-conservation.ts", contains: plant.taxonomy, description: "the conserved module plant declares this finding family" },
      { file: "src/cli/validate-conservation.ts", contains: "checkConservation", description: "the conservation CLI asserts production and delivery" },
    ],
  }));
  return {
    bindings: [...auditBindings, ...mechanicalBindings, ...plantBindings].map((binding) => normalizeBinding(binding, root)),
    local,
    auditIds: auditBindings.map((binding) => binding.id).sort(byText),
    mechanicalIds: mechanicalRegistry.map((entry) => `${entry.phase}:${entry.id}`).sort(byText),
  };
}

const VENUE_MODULES: Readonly<Record<string, readonly AuditModule[]>> = {
  "validate-calibration": ["M1", "M6"],
  "validate-precision": ["M1", "M7", "M8"],
  "validate-source-recall": ["M1", "M9"],
  "validate-secbench": ["M1"],
  "validate-free-recall": ["M1"],
};

function buildVenues(gates: readonly ScoredGate[]): EffectivenessVenue[] {
  return gates.flatMap((gate): EffectivenessVenue[] => {
    const modules = VENUE_MODULES[gate.id];
    if (!modules || gate.cadence.kind === "none") return [];
    const provenance = gate.cadence.kind === "verify"
      ? "package.json#scripts.verify"
      : `${gate.cadence.file}#${gate.cadence.job}`;
    return [{
      id: gate.id,
      gateId: gate.id,
      modules,
      producerClasses: ["true-finding-producer"],
      command: `pnpm ${gate.script}`,
      cadence: { kind: gate.cadence.kind, description: describeCadence(gate.cadence) },
      provenance,
    }];
  }).sort((a, b) => a.id.localeCompare(b.id));
}

function venueIdsFor(binding: ProductionProducerBinding): string[] {
  if (binding.populationClass !== "true-finding-producer") return [];
  // #1948 added module-tagged detector fixtures that validate-calibration deliberately excludes
  // from its scored corpus. A unit/fixture pair is evidence, but it is not a scored venue. Keep
  // those producers explicit and structurally exempt until a named SCORED_GATES consumer actually
  // includes them; assigning the broad mechanical venue would manufacture M1/M5/M8 scores.
  const unscoredMechanical = new Set([
    "mechanical:structural-ast:m1-exception-flow",
    "mechanical:structural-ast:m5-exception-flow",
    "mechanical:structural-ast:m5-hardcoded-deployment",
    "mechanical:structural-ast:m5-polyglot-quality",
    "mechanical:structural-ast:m5-type-escape",
    "mechanical:structural-ast:m8-vacuous-assertion",
  ]);
  if (binding.id.startsWith("mechanical:") || binding.id.startsWith("semgrep:")) {
    return unscoredMechanical.has(binding.id) ? [] : ["validate-calibration"];
  }
  if (binding.id === "detector:app-router") return ["validate-source-recall"];
  if (["detector:perf-code", "detector:test-intent", "detector:vitest-intent"].includes(binding.id)) return ["validate-precision"];
  return [];
}

function buildExemptions(bindings: readonly ProductionProducerBinding[], venuesByProducer: ReadonlyMap<string, readonly string[]>): EffectivenessExemption[] {
  const result: EffectivenessExemption[] = [];
  const m2 = bindings.filter((binding) => binding.populationClass === "true-finding-producer" && binding.modules.includes("M2") && (venuesByProducer.get(binding.id)?.length ?? 0) === 0).map((binding) => binding.id).sort(byText);
  if (m2.length > 0) result.push({
    id: "exemption:m2-live-score",
    kind: "empirical",
    applicableProducerIds: m2,
    provenance: "src/scored-gates.ts#validate-connected; tracked by #1491",
    owner: "Harvey M2 effectiveness owner (#1491)",
    decision: "Do not publish a producer effectiveness score from an M2 venue that has never run on cadence.",
    reason: "validate-connected is the named M2 scorer, but its live Supabase calibration fixture cannot currently stand up in CI, so the scored gate has cadence none.",
    cadence: "none",
    falsifier: "A named SCORED_GATES venue invokes every applicable M2 producer on labelled vulnerable and clean targets, reports its score, and has a verified non-none cadence.",
  });

  const unscored = bindings.filter((binding) => binding.populationClass === "true-finding-producer" && !binding.modules.includes("M2") && (venuesByProducer.get(binding.id)?.length ?? 0) === 0);
  for (const modules of unique(unscored.map((binding) => [...binding.modules].sort(byText).join("-"))).sort(byText)) {
    const ids = unscored.filter((binding) => [...binding.modules].sort(byText).join("-") === modules).map((binding) => binding.id).sort(byText);
    result.push({
      id: `exemption:unscored:${modules}`,
      kind: "structural",
      applicableProducerIds: ids,
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

function sourceImportPath(root: string, sourceFile: string, specifier: string): string | undefined {
  if (!specifier.startsWith(".")) return undefined;
  const unresolved = resolve(root, dirname(sourceFile), specifier);
  const stem = unresolved.replace(/\.(?:js|mjs|cjs)$/, "");
  const candidates = [unresolved, `${stem}.ts`, `${stem}.tsx`, `${stem}.js`, `${stem}.mjs`];
  const found = candidates.find(existsSync);
  return found ? relative(root, found) : undefined;
}

// Calls already named by a live binding are always retained. For unknown calls, only finding-shaped
// names are candidates: broad detect*/check*/scan* matching incorrectly classified framework,
// package-manager, version, and test-harness discovery helpers as client-finding producers.
function producerLikeSymbol(symbol: string): boolean {
  if (symbol.endsWith("FromFindings")) return false;
  return /(?:Finding|Findings)$/.test(symbol)
    || /^run(?:Explore|Verify|ExternalTarget|GuestProbe|Realtime.*|.*Suite|.*Probe)$/.test(symbol)
    || /(?:NotAssessedRows)$/.test(symbol)
    || /^(?:applyVerifyResults|assessDuplicateEffects|routeOnlyNotAssessed)$/.test(symbol);
}

export function discoverProductionProducerCalls(
  root = REPO_ROOT,
  registeredImplementations: ReadonlySet<string> = new Set(),
  compositionSeams: readonly string[] = COMPOSITION_SEAMS,
): EffectivenessDiscoveredCall[] {
  const calls: EffectivenessDiscoveredCall[] = [];
  for (const file of compositionSeams) {
    const path = join(root, file);
    const sourceText = readFileSync(path, "utf8");
    const source = ts.createSourceFile(file, sourceText, ts.ScriptTarget.Latest, true, extname(file) === ".mjs" ? ts.ScriptKind.JS : ts.ScriptKind.TS);
    const imported = new Map<string, EffectivenessDiscoveredCall>();
    for (const statement of source.statements) {
      if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
      const importedFile = sourceImportPath(root, file, statement.moduleSpecifier.text);
      const bindings = statement.importClause?.namedBindings;
      if (!importedFile || !bindings || !ts.isNamedImports(bindings)) continue;
      for (const element of bindings.elements) imported.set(element.name.text, { file: importedFile, symbol: element.propertyName?.text ?? element.name.text });
    }
    const localFunctions = new Set(source.statements.flatMap((statement) => ts.isFunctionDeclaration(statement) && statement.name ? [statement.name.text] : []));
    const seenIdentifiers = new Set<string>();
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) seenIdentifiers.add(node.expression.text);
      if (ts.isIdentifier(node) && imported.has(node.text)) {
        const identity = imported.get(node.text)!;
        const key = `${identity.file}#${identity.symbol}`;
        if (registeredImplementations.has(key) && sourceText.match(new RegExp(`\\b${node.text}\\b`, "g"))!.length > 1) seenIdentifiers.add(node.text);
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
    for (const name of seenIdentifiers) {
      const identity = imported.get(name) ?? (localFunctions.has(name) ? { file, symbol: name } : undefined);
      if (!identity) continue;
      const key = `${identity.file}#${identity.symbol}`;
      if (registeredImplementations.has(key) || producerLikeSymbol(identity.symbol)) calls.push(identity);
    }
  }
  return unique(calls.map((call) => JSON.stringify(call))).map((call) => JSON.parse(call) as EffectivenessDiscoveredCall).sort((a, b) => `${a.file}#${a.symbol}`.localeCompare(`${b.file}#${b.symbol}`));
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

function normalizeProducer(binding: ProductionProducerBinding, venueIds: readonly string[], exemptionId?: string): EffectivenessProducer {
  return {
    ...binding,
    venueIds: [...venueIds].sort(byText),
    ...(exemptionId ? { exemptionId } : {}),
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
  const population = producerPopulation(root, auditRunners, mechanicalRegistry, mechanicalDetectors, plants, packs, inputs.registryPackRuleIds ?? {});
  const venueIds = new Map(population.bindings.map((binding) => [binding.id, venueIdsFor(binding)]));
  const exemptions = buildExemptions(population.bindings, venueIds);
  const exemptionByProducer = new Map(exemptions.flatMap((exemption) => exemption.applicableProducerIds.map((id) => [id, exemption.id] as const)));
  const producers = population.bindings.map((binding) => normalizeProducer(binding, venueIds.get(binding.id) ?? [], exemptionByProducer.get(binding.id))).sort((a, b) => a.id.localeCompare(b.id));
  const registeredImplementations = new Set(producers.flatMap((producer) => producer.implementations.map((item) => `${item.file}#${item.symbol}`)));
  const composedCalls = discoverProductionProducerCalls(root, registeredImplementations);
  const inventory: EffectivenessInventory = {
    schema: EFFECTIVENESS_INVENTORY_SCHEMA,
    producers,
    venues: buildVenues(scoredGates),
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
      discoveredComposedCalls: composedCalls.length,
      composedCalls,
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
    if (producer.consumerPath.length === 0) problems.push(`${producer.id}: no production consumer path`);
    for (const item of producer.implementations) {
      const path = join(root, item.file);
      if (!existsSync(path)) {
        problems.push(`${producer.id}: orphaned implementation file ${item.file}`);
      } else if (!readFileSync(path, "utf8").includes(item.symbol)) {
        problems.push(`${producer.id}: orphaned implementation symbol ${item.file}#${item.symbol}`);
      }
    }
    if (producer.implementations.some((item) => item.kind === "synthesizer") && producer.populationClass !== "synthesizer") {
      problems.push(`${producer.id}: synthesizer implementation is wrongly classified as ${producer.populationClass}`);
    }
    if (producer.populationClass === "synthesizer" && !producer.implementations.some((item) => item.kind === "synthesizer")) problems.push(`${producer.id}: synthesizer class has no synthesizer implementation`);
    if (producer.populationClass === "true-finding-producer" && !producer.findingFamilies.some((entry) => entry.kind === "finding")) problems.push(`${producer.id}: true producer has no finding family`);
    if (producer.populationClass === "disclosure-only" && producer.findingFamilies.some((entry) => entry.kind === "finding")) problems.push(`${producer.id}: disclosure-only producer declares a true finding family`);
    for (const entry of producer.findingFamilies) {
      if (!producer.modules.includes(entry.module)) problems.push(`${producer.id}: family ${entry.idPattern} belongs to ${entry.module}, outside producer modules [${producer.modules.join(", ")}]`);
      if (!nonEmpty(entry.idPattern) || !nonEmpty(entry.taxonomyPattern)) problems.push(`${producer.id}: empty finding-family pattern`);
    }
    for (const hop of producer.consumerPath) {
      const path = join(root, hop.file);
      if (!existsSync(path)) problems.push(`${producer.id}: orphaned consumer hop ${hop.file}`);
      else if (!readFileSync(path, "utf8").includes(hop.contains)) problems.push(`${producer.id}: consumer proof ${hop.file} no longer contains ${JSON.stringify(hop.contains)}`);
    }
    if (producer.venueIds.length > 0 && producer.exemptionId) problems.push(`${producer.id}: stale exemption ${producer.exemptionId} remains after a scored venue was assigned`);
    if (producer.venueIds.length === 0 && !producer.exemptionId) problems.push(`${producer.id}: neither scored venue nor structured exemption is assigned`);
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
      const expectedModules = VENUE_MODULES[gate.id];
      if (!expectedModules || JSON.stringify([...venue.modules].sort(byText)) !== JSON.stringify([...expectedModules].sort(byText))) {
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
    for (const producerId of exemption.applicableProducerIds) {
      const producer = producerById.get(producerId);
      if (!producer) problems.push(`${exemption.id}: orphaned producer ${producerId}`);
      else if (producer.exemptionId !== exemption.id) problems.push(`${exemption.id}: ${producerId} does not point back to this exemption`);
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
  for (const call of inventory.receipt.composedCalls) {
    if (!implementationOwners.has(`${call.file}#${call.symbol}`)) problems.push(`${call.file}#${call.symbol}: discovered production producer call is unregistered`);
  }
  if (inventory.receipt.mechanicalDefinitions !== inventory.receipt.mechanicalProducerIds.length) problems.push("mechanical discovery receipt count does not match its identities");
  if (inventory.receipt.localSemgrepFamilies !== inventory.receipt.localSemgrepFamilyIds.length) problems.push("local Semgrep family receipt count does not match its identities");
  if (inventory.receipt.localSemgrepRuleIds !== inventory.receipt.localSemgrepRules.length) problems.push("local Semgrep rule receipt count does not match its identities");
  if (inventory.receipt.registrySemgrepPacks !== inventory.receipt.registrySemgrepPackIds.length) problems.push("registry Semgrep pack receipt count does not match its identities");
  if (inventory.receipt.auditRunnerBindings !== inventory.receipt.auditRunnerProducerIds.length) problems.push("audit-runner receipt count does not match its identities");
  if (inventory.receipt.discoveredComposedCalls !== inventory.receipt.composedCalls.length) problems.push("composition receipt count does not match its identities");

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

  const discoveredNow = discoverProductionProducerCalls(root, implementationOwners);
  compareIdentityPopulation(
    "composition",
    inventory.receipt.composedCalls.map((call) => `${call.file}#${call.symbol}`),
    discoveredNow.map((call) => `${call.file}#${call.symbol}`),
  );
  for (const module of AUDIT_MODULES) if (!inventory.producers.some((producer) => producer.modules.includes(module))) problems.push(`${module}: no producer population is registered`);
  const summary = populationSummary(inventory.producers);
  if (JSON.stringify(summary) !== JSON.stringify(inventory.summary)) problems.push("population summary does not match the disjoint producer/family population");
  if (!inventory.summary.denominatorConserved) problems.push("producer denominator is not conserved across disjoint population classes");
  return problems;
}

export function serializeEffectivenessInventory(inventory: EffectivenessInventory): string {
  return `${JSON.stringify(inventory, null, 2)}\n`;
}

export const EFFECTIVENESS_INVENTORY = buildEffectivenessInventory();
export const EFFECTIVENESS_INVENTORY_JSON = serializeEffectivenessInventory(EFFECTIVENESS_INVENTORY);
