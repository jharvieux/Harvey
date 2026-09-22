import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverEffectivenessRouteGraph, discoverEffectivenessRouteGraphs } from "./effectiveness-route-graph.js";
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

  it("batches separate root and venue reachability without retaining stale source", () => {
    const root = fixture('import { produce } from "./producer.js"; export const findings = produce();\n');
    mkdirSync(join(root, "src", "cli"));
    writeFileSync(join(root, "src", "cli", "run-audit.ts"), 'import { produce } from "../producer.js"; export const findings = produce();\n');
    writeFileSync(join(root, "src", "venue-a.ts"), 'import { produce } from "./producer.js"; export const findings = produce();\n');
    writeFileSync(join(root, "src", "venue-b.ts"), 'import { produce } from "./producer.js"; void produce;\n');
    const venueRoots = ["src/venue-a.ts", "src/venue-b.ts"];
    const first = discoverEffectivenessRouteGraphs(root, [implementation], venueRoots);
    expect(first.production).toEqual(discoverEffectivenessRouteGraph(root, [implementation]));
    for (const [index, venueRoot] of venueRoots.entries()) {
      expect(first.venues[index]).toEqual(discoverEffectivenessRouteGraph(root, [implementation], [venueRoot], { detectUnknown: false }));
    }
    expect(first.venues[0]!.routes).toHaveLength(1);
    expect(first.venues[1]!.routes).toEqual([]);
    expect(first.venues[0]!.routes[0]!.rootId).toBe("src/venue-a.ts");
    writeFileSync(join(root, "src", "venue-a.ts"), 'import { produce } from "./producer.js"; void produce;\n');
    writeFileSync(join(root, "src", "venue-b.ts"), 'import { produce } from "./producer.js"; export const findings = produce();\n');
    const changed = discoverEffectivenessRouteGraphs(root, [implementation], venueRoots);
    expect(changed.venues[0]!.routes).toEqual([]);
    expect(changed.venues[1]!.routes).toHaveLength(1);
    expect(changed.venues[1]!.routes[0]!.rootId).toBe("src/venue-b.ts");
  });

  it("does not borrow a typed command executor from another venue", () => {
    const root = fixture("export {};\n");
    symlinkSync(join(process.cwd(), "node_modules"), join(root, "node_modules"), "dir");
    mkdirSync(join(root, "src", "cli"));
    writeFileSync(join(root, "src", "cli", "run-audit.ts"), "export {};\n");
    writeFileSync(join(root, "src", "child.ts"), 'import { produce } from "./producer.js"; produce();\n');
    writeFileSync(join(root, "src", "invoke.ts"), 'export interface Runner { run: (bin: string, args: string[]) => unknown; }\nexport function invoke(runner: Runner) { runner.run("node", ["src/child.ts"]); }\n');
    writeFileSync(join(root, "src", "venue-a.ts"), 'import { execFileSync } from "node:child_process";\nimport { invoke, type Runner } from "./invoke.js";\nconst runner: Runner = { run: execFileSync };\ninvoke(runner);\n');
    writeFileSync(join(root, "src", "venue-b.ts"), 'import { invoke, type Runner } from "./invoke.js";\nconst runner: Runner = { run: () => [] };\ninvoke(runner);\n');
    const venueRoots = ["src/venue-a.ts", "src/venue-b.ts"];
    const batch = discoverEffectivenessRouteGraphs(root, [implementation], venueRoots);
    for (const [index, venueRoot] of venueRoots.entries()) {
      expect(batch.venues[index]).toEqual(discoverEffectivenessRouteGraph(root, [implementation], [venueRoot], { detectUnknown: false }));
    }
    expect(batch.venues.map((graph) => graph.routes.length)).toEqual([1, 0]);
    expect(batch.venues[0]!.calls.map((call) => call.id)).toContain("command:src/invoke.ts->src/child.ts");
    expect(batch.venues[1]!.calls.map((call) => call.id)).not.toContain("command:src/invoke.ts->src/child.ts");
  });

  it("accepts every frozen ordered runtime edge kind without collapsing them", () => {
    const edges = PRODUCER_ROUTE_EDGE_KINDS.map((kind, ordinal) => ({ kind, from: `n${ordinal}`, to: `n${ordinal + 1}` }));
    const receipt = createProducerExecutionReceipt({ executionId: "all-edges", producerId: "one", implementationId: "src/producer.ts#produce", module: "M1", tier: "free", findingFamilyIds: ["ONE"], findingIds: [], edges });
    expect(receipt.edges.map((edge) => edge.kind)).toEqual(PRODUCER_ROUTE_EDGE_KINDS);
  });
});
