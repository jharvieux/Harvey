import type { AuditModule } from "./audit-coverage.js";
import type { FindingFamilyKind } from "./findings.js";

/** Version of the deterministic producer-inventory contract consumed by downstream metrics. */
export const EFFECTIVENESS_INVENTORY_SCHEMA = 1 as const;

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

export interface ProducerConsumerHop {
  readonly file: string;
  /** Literal production symbol/command/artifact name whose presence proves this hop. */
  readonly contains: string;
  readonly description: string;
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
  readonly consumerPath: readonly ProducerConsumerHop[];
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
}

export interface EffectivenessExemption {
  readonly id: string;
  readonly kind: "empirical" | "structural" | "not-a-producer";
  readonly applicableProducerIds: readonly string[];
  readonly provenance: string;
  readonly owner: string;
  readonly decision: string;
  readonly reason: string;
  readonly cadence: "none";
  readonly falsifier: string;
}

export interface EffectivenessProducer extends ProductionProducerBinding {
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

export interface EffectivenessDiscoveredCall {
  readonly file: string;
  readonly symbol: string;
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
  readonly discoveredComposedCalls: number;
  readonly composedCalls: readonly EffectivenessDiscoveredCall[];
}

export interface EffectivenessInventory {
  readonly schema: typeof EFFECTIVENESS_INVENTORY_SCHEMA;
  readonly producers: readonly EffectivenessProducer[];
  readonly venues: readonly EffectivenessVenue[];
  readonly exemptions: readonly EffectivenessExemption[];
  readonly summary: EffectivenessPopulationSummary;
  readonly receipt: EffectivenessDiscoveryReceipt;
}
