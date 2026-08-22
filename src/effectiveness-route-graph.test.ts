import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverEffectivenessRouteGraph } from "./effectiveness-route-graph.js";
import { createProducerExecutionReceipt, PRODUCER_ROUTE_EDGE_KINDS } from "./producer-execution-receipt.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function fixture(rootBody: string): string {
  const root = mkdtempSync(join(tmpdir(), "effectiveness-route-v3-"));
  roots.push(root);
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "package.json"), JSON.stringify({ type: "module" }));
  writeFileSync(join(root, "src", "producer.ts"), "export interface Finding { id: string; taxonomy: string }\nexport function produce(): Finding[] { return [] }\n");
  writeFileSync(join(root, "src", "root.ts"), rootBody);
  return root;
}

const implementation = { producerId: "one", file: "src/producer.ts", symbol: "produce", kind: "function" as const, deliveryKind: "registry-dispatch" as const };

describe("schema-v3 route graph", () => {
  it("does not manufacture liveness from a registry declaration or reachable file", () => {
    const root = fixture('import { produce } from "./producer.js"; void produce;\n');
    expect(discoverEffectivenessRouteGraph(root, [implementation], ["src/root.ts"]).routes).toEqual([]);
  });

  it("records a real semantic invocation and loses it when the invocation is deleted", () => {
    const root = fixture('import { produce } from "./producer.js"; export const findings = produce();\n');
    const live = discoverEffectivenessRouteGraph(root, [implementation], ["src/root.ts"]);
    expect(live.routes).toHaveLength(1);
    writeFileSync(join(root, "src", "root.ts"), 'import { produce } from "./producer.js"; void produce;\n');
    expect(discoverEffectivenessRouteGraph(root, [implementation], ["src/root.ts"]).routes).toEqual([]);
  });

  it("accepts every frozen ordered runtime edge kind without collapsing them", () => {
    const edges = PRODUCER_ROUTE_EDGE_KINDS.map((kind, ordinal) => ({ kind, from: `n${ordinal}`, to: `n${ordinal + 1}` }));
    const receipt = createProducerExecutionReceipt({ executionId: "all-edges", producerId: "one", implementationId: "src/producer.ts#produce", module: "M1", tier: "free", findingFamilyIds: ["ONE"], findingIds: [], edges });
    expect(receipt.edges.map((edge) => edge.kind)).toEqual(PRODUCER_ROUTE_EDGE_KINDS);
  });
});
