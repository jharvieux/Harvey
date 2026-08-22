import { describe, expect, it } from "vitest";
import { EFFECTIVENESS_INVENTORY, validateEffectivenessDelivery } from "./effectiveness-registry.js";
import { REQUIRED_RUNTIME_EDGE, type EffectivenessInventory } from "./effectiveness-schema.js";
import { createProducerExecutionReceipt, extendProducerExecutionReceipt } from "./producer-execution-receipt.js";

function deliveredFixture(): { inventory: EffectivenessInventory; observation: { findingId: string; producerId: string; familyId: string; venueId: string } } {
  const base = JSON.parse(JSON.stringify(EFFECTIVENESS_INVENTORY)) as EffectivenessInventory;
  const producer = base.producers.find((candidate) => candidate.findingFamilies.some((family) => family.venueIds.length > 0))!;
  const family = producer.findingFamilies.find((candidate) => candidate.venueIds.length > 0)!;
  const venueId = family.venueIds[0]!;
  const implementation = producer.implementations[0]!;
  let receipt = createProducerExecutionReceipt({
    executionId: "delivery-1",
    producerId: producer.id,
    implementationId: `${implementation.file}#${implementation.symbol}`,
    module: family.module,
    tier: producer.tiers[0]!,
    findingFamilyIds: [family.id],
    findingIds: ["DELIVERED-1"],
    edges: [{ kind: REQUIRED_RUNTIME_EDGE[producer.deliveryKind], from: "runtime", to: "audit-assembly" }],
  });
  receipt = extendProducerExecutionReceipt(receipt, { kind: "client-delivery", from: "audit-assembly", to: `venue:${venueId}` });
  const inventory: EffectivenessInventory = {
    ...base,
    producers: base.producers.map((candidate) => candidate.id === producer.id ? { ...candidate, executionReceiptIds: [receipt.executionId] } : candidate),
    receipt: { ...base.receipt, producerExecutions: [receipt] },
  };
  return { inventory, observation: { findingId: "DELIVERED-1", producerId: producer.id, familyId: family.id, venueId } };
}

describe("producer-specific client delivery", () => {
  it("traces one actual execution through its exact family and venue", () => {
    const { inventory, observation } = deliveredFixture();
    expect(validateEffectivenessDelivery(inventory, [observation])).toEqual([]);
  });

  it("fails when delivery is deleted while accounting remains", () => {
    const { inventory, observation } = deliveredFixture();
    const receipt = inventory.receipt.producerExecutions[0]!;
    const withoutDelivery = createProducerExecutionReceipt({
      executionId: receipt.executionId,
      producerId: receipt.producerId,
      implementationId: receipt.implementationId,
      module: receipt.module,
      tier: receipt.tier,
      findingFamilyIds: receipt.findingFamilyIds,
      findingIds: receipt.findingIds,
      edges: receipt.edges.filter((edge) => edge.kind !== "client-delivery").map(({ kind, from, to }) => ({ kind, from, to })),
    });
    const planted = { ...inventory, receipt: { ...inventory.receipt, producerExecutions: [withoutDelivery] } };
    expect(validateEffectivenessDelivery(planted, [observation])).toContain("DELIVERED-1: expected one exact producer-to-client delivery receipt, found 0");
  });

  it("rejects venue-wide unrelated calls and duplicate observations", () => {
    const { inventory, observation } = deliveredFixture();
    const wrong = { ...observation, venueId: "unrelated-venue" };
    expect(validateEffectivenessDelivery(inventory, [wrong]).some((problem) => problem.includes("not bound") || problem.includes("found 0"))).toBe(true);
    expect(validateEffectivenessDelivery(inventory, [observation, observation])).toContain("client delivery observations contain duplicates");
  });
});
