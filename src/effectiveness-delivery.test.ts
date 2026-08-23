import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  getEffectivenessInventory,
  serializeEffectivenessInventory,
  validateEffectivenessDelivery,
} from "./effectiveness-registry.js";
import { REQUIRED_RUNTIME_EDGE, type EffectivenessInventory } from "./effectiveness-schema.js";
import { HEAVY_CLI_TESTS } from "./heavy-cli-tests.js";
import { createProducerExecutionReceipt, extendProducerExecutionReceipt } from "./producer-execution-receipt.js";

const REPO_ROOT = new URL("..", import.meta.url).pathname;
const EXPECTED_INVENTORY_SHA = "a9026a88111958495dc992bb2c8a9ea3222589b5a6e04834b637ae7cec3adc23";

function runDetectorCensus(): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("node", ["--import", "tsx", "src/cli/detector-census.ts", "--effectiveness-json"], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => { stdout += chunk; });
    child.stderr.on("data", (chunk: string) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => code === 0
      ? resolve(stdout)
      : reject(new Error(`detector-census exited ${code}: ${stderr}`)));
  });
}

function deliveredFixture(): { inventory: EffectivenessInventory; observation: { findingId: string; producerId: string; familyId: string; venueId: string } } {
  const base = JSON.parse(JSON.stringify(getEffectivenessInventory())) as EffectivenessInventory;
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

describe("awaited detector-census integration", () => {
  it("remains on the required serial heavy-test route", () => {
    expect(HEAVY_CLI_TESTS).toContain("src/effectiveness-delivery.test.ts");
  });

  it("preserves the exact default schema-v3 inventory bytes", async () => {
    const output = await runDetectorCensus();
    const canonical = serializeEffectivenessInventory(JSON.parse(output) as EffectivenessInventory);
    expect(output).toBe(`${canonical}\n`);
    expect(createHash("sha256").update(output).digest("hex")).toBe(EXPECTED_INVENTORY_SHA);
  });
});

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
