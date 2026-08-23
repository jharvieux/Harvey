import { createHash } from "node:crypto";
import type { AuditModule } from "./audit-coverage.js";
import type { SemgrepExecutionPlanReceipt } from "./scan/semgrep-family-cache.js";
import { assertSuccessfulSemgrepExecutionReceipt } from "./scan/semgrep-family-cache.js";

export const PRODUCER_EXECUTION_RECEIPT_SCHEMA = 3 as const;

export const PRODUCER_ROUTE_EDGE_KINDS = [
  "semantic-call",
  "callback",
  "registry-iteration",
  "command",
  "semgrep-family",
  "artifact-produce",
  "artifact-ingest",
  "conservation-consume",
  "client-delivery",
] as const;

export type ProducerRouteEdgeKind = (typeof PRODUCER_ROUTE_EDGE_KINDS)[number];

export interface ProducerRouteEdge {
  readonly ordinal: number;
  readonly kind: ProducerRouteEdgeKind;
  readonly from: string;
  readonly to: string;
  /** Content identity of the runtime observation which caused this edge to be emitted. */
  readonly evidenceSha256: string;
}

export interface ProducerExecutionReceipt {
  readonly schema: typeof PRODUCER_EXECUTION_RECEIPT_SCHEMA;
  readonly status: "succeeded";
  readonly executionId: string;
  readonly producerId: string;
  readonly implementationId: string;
  readonly module: AuditModule;
  readonly tier: "free" | "connected" | "dynamic" | "paid";
  readonly findingFamilyIds: readonly string[];
  readonly findingIds: readonly string[];
  readonly edges: readonly ProducerRouteEdge[];
  readonly sha256: string;
}

type ReceiptBody = Omit<ProducerExecutionReceipt, "schema" | "status" | "sha256" | "edges"> & {
  readonly edges: readonly Omit<ProducerRouteEdge, "ordinal" | "evidenceSha256">[];
  /** Optional source evidence. It is hashed and discarded so secrets/raw output never enter receipts. */
  readonly evidence?: unknown;
};

const byBytes = (left: string, right: string): number => Buffer.compare(Buffer.from(left), Buffer.from(right));

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => byBytes(left, right))
      .map(([key, item]) => [key, canonical(item)]));
  }
  return value;
}

function canonicalReceiptJson(value: unknown): string {
  return JSON.stringify(canonical(value));
}

function receiptSha256(value: unknown): string {
  return createHash("sha256").update(canonicalReceiptJson(value)).digest("hex");
}

function receiptWithoutDigest(receipt: Omit<ProducerExecutionReceipt, "sha256"> | ProducerExecutionReceipt): Omit<ProducerExecutionReceipt, "sha256"> {
  return {
    schema: receipt.schema,
    status: receipt.status,
    executionId: receipt.executionId,
    producerId: receipt.producerId,
    implementationId: receipt.implementationId,
    module: receipt.module,
    tier: receipt.tier,
    findingFamilyIds: receipt.findingFamilyIds,
    findingIds: receipt.findingIds,
    edges: receipt.edges,
  };
}

export function createProducerExecutionReceipt(input: ReceiptBody): ProducerExecutionReceipt {
  const findingFamilyIds = [...new Set(input.findingFamilyIds)].sort(byBytes);
  const findingIds = [...input.findingIds];
  const baseEvidence = receiptSha256(input.evidence ?? {
    executionId: input.executionId,
    producerId: input.producerId,
    implementationId: input.implementationId,
    findingIds,
  });
  const edges = input.edges.map((edge, ordinal) => ({ ...edge, ordinal, evidenceSha256: receiptSha256({ baseEvidence, ordinal, edge }) }));
  const body: Omit<ProducerExecutionReceipt, "sha256"> = {
    schema: PRODUCER_EXECUTION_RECEIPT_SCHEMA,
    status: "succeeded",
    executionId: input.executionId,
    producerId: input.producerId,
    implementationId: input.implementationId,
    module: input.module,
    tier: input.tier,
    findingFamilyIds,
    findingIds,
    edges,
  };
  const receipt = { ...body, sha256: receiptSha256(body) };
  assertProducerExecutionReceipt(receipt);
  return receipt;
}

export function assertProducerExecutionReceipt(value: unknown): asserts value is ProducerExecutionReceipt {
  const receipt = value as Partial<ProducerExecutionReceipt>;
  if (!receipt || receipt.schema !== PRODUCER_EXECUTION_RECEIPT_SCHEMA || receipt.status !== "succeeded") {
    throw new Error("producer execution receipt is missing, planned, failed, or uses an unsupported schema");
  }
  for (const [label, field] of [["executionId", receipt.executionId], ["producerId", receipt.producerId], ["implementationId", receipt.implementationId]] as const) {
    if (typeof field !== "string" || !field.trim()) throw new Error(`producer execution receipt has an empty ${label}`);
  }
  if (!/^M(?:10|[1-9])$/.test(receipt.module ?? "")) throw new Error("producer execution receipt has an invalid module");
  if (!["free", "connected", "dynamic", "paid"].includes(receipt.tier ?? "")) throw new Error("producer execution receipt has an invalid tier");
  if (!Array.isArray(receipt.findingFamilyIds) || !Array.isArray(receipt.findingIds) || !Array.isArray(receipt.edges) || receipt.edges.length === 0) {
    throw new Error("producer execution receipt is missing family, finding, or route evidence");
  }
  if (new Set(receipt.findingFamilyIds).size !== receipt.findingFamilyIds.length
    || JSON.stringify([...receipt.findingFamilyIds].sort(byBytes)) !== JSON.stringify(receipt.findingFamilyIds)) {
    throw new Error("producer execution receipt finding families are duplicated or non-canonical");
  }
  receipt.edges.forEach((edge, ordinal) => {
    if (edge.ordinal !== ordinal) throw new Error("producer execution receipt edge ordering is malformed");
    if (!PRODUCER_ROUTE_EDGE_KINDS.includes(edge.kind)) throw new Error(`producer execution receipt has unknown edge kind ${edge.kind}`);
    if (!edge.from?.trim() || !edge.to?.trim() || !/^[a-f0-9]{64}$/.test(edge.evidenceSha256 ?? "")) {
      throw new Error("producer execution receipt edge identity is malformed");
    }
    if (ordinal > 0 && receipt.edges![ordinal - 1]!.to !== edge.from) {
      throw new Error("producer execution receipt edges do not form one ordered route");
    }
  });
  if (!/^[a-f0-9]{64}$/.test(receipt.sha256 ?? "") || receipt.sha256 !== receiptSha256(receiptWithoutDigest(receipt as ProducerExecutionReceipt))) {
    throw new Error("producer execution receipt digest is invalid");
  }
}

export function assertUniqueProducerExecutionReceipts(values: readonly unknown[]): asserts values is readonly ProducerExecutionReceipt[] {
  const ids = new Set<string>();
  for (const value of values) {
    assertProducerExecutionReceipt(value);
    const receipt = value as ProducerExecutionReceipt;
    if (ids.has(receipt.executionId)) throw new Error(`duplicate producer execution receipt ${receipt.executionId}`);
    ids.add(receipt.executionId);
  }
}

export function extendProducerExecutionReceipt(
  receipt: ProducerExecutionReceipt,
  edge: Omit<ProducerRouteEdge, "ordinal" | "evidenceSha256">,
  evidence?: unknown,
): ProducerExecutionReceipt {
  assertProducerExecutionReceipt(receipt);
  const previous = receipt.edges.at(-1)!;
  if (previous.to !== edge.from) throw new Error(`producer route cannot continue from ${previous.to} to ${edge.from}`);
  return createProducerExecutionReceipt({
    executionId: receipt.executionId,
    producerId: receipt.producerId,
    implementationId: receipt.implementationId,
    module: receipt.module,
    tier: receipt.tier,
    findingFamilyIds: receipt.findingFamilyIds,
    findingIds: receipt.findingIds,
    edges: [...receipt.edges.map(({ kind, from, to }) => ({ kind, from, to })), edge],
    evidence: { prior: receipt.sha256, evidence },
  });
}

/** Adapt only PR1954's validated schema-8 *successful runtime* receipt. Plans/failures are rejected. */
export function semgrepProducerExecutionReceipts(value: unknown): ProducerExecutionReceipt[] {
  assertSuccessfulSemgrepExecutionReceipt(value);
  const receipt = value as SemgrepExecutionPlanReceipt;
  return receipt.families.flatMap((family) => {
    if (family.sourceKind === "registry-pack") {
      return [createProducerExecutionReceipt({
        executionId: `semgrep:${family.ordinal}:${family.id}`,
        producerId: `semgrep:registry:${family.sourceId}`,
        implementationId: `src/scan/semgrep.ts#${family.sourceId}`,
        module: "M1",
        tier: "free",
        findingFamilyIds: family.loadedRuleIds,
        findingIds: [],
        edges: [{ kind: "semgrep-family", from: `semgrep-family:${family.id}`, to: `producer:semgrep:registry:${family.sourceId}` }],
        evidence: { ownershipSha256: receipt.ownershipSha256, family },
      })];
    }
    return family.loadedRuleIds.map((ruleId, ruleOrdinal) => createProducerExecutionReceipt({
      executionId: `semgrep:${family.ordinal}:${ruleOrdinal}:${family.id}:${ruleId}`,
      producerId: `semgrep:local:${ruleId}`,
      implementationId: `src/scan/rules/semgrep/${family.sourceId}#${ruleId}`,
      module: "M1",
      tier: "free",
      findingFamilyIds: [ruleId],
      findingIds: [],
      edges: [{ kind: "semgrep-family", from: `semgrep-family:${family.id}`, to: `producer:semgrep:local:${ruleId}` }],
      evidence: { ownershipSha256: receipt.ownershipSha256, family },
    }));
  });
}

export function receiptHasRoute(
  receipt: ProducerExecutionReceipt,
  kinds: readonly ProducerRouteEdgeKind[],
): boolean {
  assertProducerExecutionReceipt(receipt);
  let cursor = 0;
  for (const edge of receipt.edges) if (edge.kind === kinds[cursor]) cursor += 1;
  return cursor === kinds.length;
}
