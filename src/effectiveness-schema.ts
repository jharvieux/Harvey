import type { AuditModule } from "./audit-coverage.js";
import type { FindingFamilyKind } from "./findings.js";

/** Version of the deterministic producer-inventory contract consumed by downstream metrics. */
export const EFFECTIVENESS_INVENTORY_SCHEMA = 2 as const;

export const PRODUCER_POPULATION_CLASSES = [
  "true-finding-producer",
  "disclosure-only",
  "typed-not-assessed",
  "conservation-plant",
  "adapter",
  "synthesizer",
] as const;

export const PRODUCER_TIERS = ["free", "connected", "dynamic", "paid"] as const;

export type ProducerPopulationClass = (typeof PRODUCER_POPULATION_CLASSES)[number];
export type ProducerTier = (typeof PRODUCER_TIERS)[number];

export interface ProducerImplementation {
  readonly file: string;
  /** Export, rule id, probe id, or other stable source identity within `file`. */
  readonly symbol: string;
  readonly kind: "function" | "rule" | "probe" | "adapter" | "synthesizer" | "plant";
}

export interface ProducerFindingFamily {
  readonly idPattern: string;
  readonly taxonomyPattern: string;
  readonly module: AuditModule;
  readonly kind: FindingFamilyKind;
}

/**
 * Metadata carried by a live production registry entry. These bindings are not a reporting
 * allowlist: AUDIT_RUNNERS owns non-mechanical rows and MECHANICAL_REGISTRY owns mechanical rows;
 * the effectiveness exporter only normalizes and validates them.
 */
export interface ProductionProducerBinding {
  readonly id: string;
  readonly modules: readonly AuditModule[];
  readonly tiers: readonly ProducerTier[];
  readonly populationClass: ProducerPopulationClass;
  readonly implementations: readonly ProducerImplementation[];
  readonly findingFamilies: readonly ProducerFindingFamily[];
  readonly deliveryKind: "semantic-call" | "registry-dispatch" | "artifact-ingest" | "conservation";
}

export interface EffectivenessCallReceipt {
  readonly id: string;
  readonly kind: "call" | "registry" | "command" | "artifact";
  readonly consumerFile: string;
  readonly targetFile: string;
  readonly targetSymbol: string;
}

export interface EffectivenessConsumerReceipt {
  readonly id: string;
  readonly producerId: string;
  readonly implementationId: string;
  readonly callReceiptId: string;
}

export interface EffectivenessRouteReceipt {
  readonly id: string;
  readonly producerId: string;
  readonly implementationId: string;
  readonly rootId: string;
  readonly callReceiptIds: readonly string[];
  readonly consumerReceiptId: string;
  readonly endpoint: "client-finding-delivery" | "coverage-disclosure" | "conservation";
}

export interface EffectivenessScoredFamilyBinding {
  readonly venueId: string;
  readonly corpusIds: readonly string[];
  readonly callReceiptIds: readonly string[];
}

export interface EffectivenessFamilyCoverageReceipt {
  readonly id: string;
  readonly producerId: string;
  readonly familyId: string;
  readonly kind: "scored-family-binding" | "exempt-family-binding";
  readonly scoredBindings: readonly EffectivenessScoredFamilyBinding[];
  readonly exemptionId?: string;
}

export interface EffectivenessConservationReceipt {
  readonly id: string;
  readonly producerId: string;
  readonly routeIds: readonly string[];
}

export interface EffectivenessVenue {
  readonly id: string;
  /** The SCORED_GATES id this venue is resolved against. */
  readonly gateId: string;
  readonly modules: readonly AuditModule[];
  readonly producerClasses: readonly ProducerPopulationClass[];
  readonly command: string;
  readonly cadence: {
    readonly kind: "verify" | "workflow";
    readonly description: string;
  };
  /** Source-level proof that the named venue invokes the scored gate. */
  readonly provenance: string;
  readonly rootId: string;
  readonly callReceiptIds: readonly string[];
  readonly corpusIds: readonly string[];
  readonly coveredFamilyIds: readonly string[];
}

export interface EffectivenessExemption {
  readonly id: string;
  readonly kind: "empirical" | "structural" | "not-a-producer";
  readonly applicableProducerIds: readonly string[];
  readonly applicableFamilyIds: readonly string[];
  readonly provenance: string;
  readonly owner: string;
  readonly decision: string;
  readonly reason: string;
  readonly cadence: "none";
  readonly falsifier: string;
}

export interface EffectivenessProducerFindingFamily extends ProducerFindingFamily {
  readonly id: string;
  readonly venueIds: readonly string[];
  readonly exemptionId?: string;
}

export interface EffectivenessProducer extends Omit<ProductionProducerBinding, "findingFamilies"> {
  readonly findingFamilies: readonly EffectivenessProducerFindingFamily[];
  readonly routeIds: readonly string[];
  readonly venueIds: readonly string[];
  readonly exemptionId?: string;
}

export interface EffectivenessPopulationSummary {
  readonly producers: number;
  readonly trueFindingProducers: number;
  readonly disclosureOnly: number;
  readonly typedNotAssessed: number;
  readonly conservationPlants: number;
  readonly adapters: number;
  readonly synthesizers: number;
  readonly findingFamilies: number;
  readonly disclosureFamilies: number;
  readonly notAssessedFamilies: number;
  /** Disjoint producer classes must sum to the producer total. */
  readonly denominatorConserved: boolean;
}

export interface EffectivenessDiscoveryReceipt {
  readonly mechanicalDefinitions: number;
  readonly mechanicalProducerIds: readonly string[];
  readonly localSemgrepFamilies: number;
  readonly localSemgrepFamilyIds: readonly string[];
  readonly localSemgrepRuleIds: number;
  readonly localSemgrepRules: readonly string[];
  readonly registrySemgrepPacks: number;
  readonly registrySemgrepPackIds: readonly string[];
  readonly auditRunnerBindings: number;
  readonly auditRunnerProducerIds: readonly string[];
  readonly productionRoots: readonly string[];
  readonly calls: readonly EffectivenessCallReceipt[];
  readonly consumers: readonly EffectivenessConsumerReceipt[];
  readonly routes: readonly EffectivenessRouteReceipt[];
  readonly familyCoverage: readonly EffectivenessFamilyCoverageReceipt[];
  readonly conservation: readonly EffectivenessConservationReceipt[];
  readonly unresolvedFindingDispatches: readonly string[];
}

export interface EffectivenessInventory {
  readonly schema: typeof EFFECTIVENESS_INVENTORY_SCHEMA;
  readonly producers: readonly EffectivenessProducer[];
  readonly venues: readonly EffectivenessVenue[];
  readonly exemptions: readonly EffectivenessExemption[];
  readonly summary: EffectivenessPopulationSummary;
  readonly receipt: EffectivenessDiscoveryReceipt;
}
