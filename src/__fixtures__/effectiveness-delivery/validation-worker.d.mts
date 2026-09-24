import type { EffectivenessDeliveryObservation } from "../../effectiveness-registry.js";
import type { EffectivenessInventory } from "../../effectiveness-schema.js";
import type { ScoredGate } from "../../scored-gates.js";

type ValidationInput = {
  kind: "inventory";
  inventory: EffectivenessInventory;
  options?: { root?: string; scoredGates?: readonly ScoredGate[] };
} | {
  kind: "delivery";
  inventory: EffectivenessInventory;
  delivered: readonly EffectivenessDeliveryObservation[];
};

interface ValidationResult {
  id: number;
  problems: string[];
  elapsedMs: number;
  pid: number;
}

export interface PendingValidation {
  readonly id: number;
  readonly completed: Promise<void>;
  readonly result?: ValidationResult;
}

export class ValidationWorker {
  constructor(root: string);
  readonly pid: number | undefined;
  start(input: ValidationInput): PendingValidation;
  waitSlice(request: PendingValidation, ms?: number): Promise<void>;
  finish(request: PendingValidation): Promise<ValidationResult>;
  validate(input: ValidationInput): Promise<string[]>;
  stop(): Promise<void>;
}
