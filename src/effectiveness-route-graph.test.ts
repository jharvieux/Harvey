import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverEffectivenessRouteGraph, discoverEffectivenessRouteGraphs } from "./effectiveness-route-graph.js";
import { createProducerExecutionReceipt, PRODUCER_ROUTE_EDGE_KINDS } from "./producer-execution-receipt.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  await new Promise<void>((resolve) => setImmediate(resolve));
});

function fixture(rootBody: string): string {
  const root = mkdtempSync(join(tmpdir(), "effectiveness-route-v3-"));
  roots.push(root);
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "package.json"), JSON.stringify({ type: "module" }));
  writeFileSync(join(root, "src", "producer.ts"), "export interface Finding { id: string; taxonomy: string }\nexport function produce(): Finding[] { return [] }\n");
  writeFileSync(join(root, "src", "root.ts"), rootBody);
  return root;
}

function nodeCommandFixture(args: readonly string[]): string {
  const root = fixture("export {};\n");
  symlinkSync(join(process.cwd(), "node_modules"), join(root, "node_modules"), "dir");
  mkdirSync(join(root, "src", "cli"));
  writeFileSync(join(root, "src", "cli", "run-audit.ts"), "export {};\n");
  writeFileSync(join(root, "src", "preload.ts"), "export {};\n");
  writeFileSync(join(root, "preload.cjs"), "module.exports = {};\n");
  writeFileSync(join(root, "src", "child.ts"), 'import { produce } from "./producer.ts"; produce(); console.log("PRODUCER_EXECUTED");\n');
  writeFileSync(join(root, "src", "venue.ts"), `import { execFileSync } from "node:child_process"; execFileSync("node", ${JSON.stringify(args)});\n`);
  return root;
}

function runNode(root: string, args: readonly string[]): { status: number | null; executed: boolean } {
  const run = spawnSync(process.execPath, args, { cwd: root, encoding: "utf8", timeout: 10_000 });
  return { status: run.status, executed: run.stdout.includes("PRODUCER_EXECUTED") };
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
    const independentImplementation = { ...implementation, producerId: "independent" };
    const first = discoverEffectivenessRouteGraphs(root, [implementation], venueRoots, [independentImplementation]);
    expect(first.production).toEqual(discoverEffectivenessRouteGraph(root, [implementation]));
    for (const [index, venueRoot] of venueRoots.entries()) {
      expect(first.venues[index]).toEqual(discoverEffectivenessRouteGraph(root, [implementation], [venueRoot], { detectUnknown: false }));
    }
    expect(first.venues[0]!.routes).toHaveLength(1);
    expect(first.venues[1]!.routes).toEqual([]);
    expect(first.venues[0]!.routes[0]!.rootId).toBe("src/venue-a.ts");
    expect(first.independentVenues?.[0]?.routes.map((route) => route.producerId)).toEqual(["independent"]);
    expect(first.independentVenues?.[1]?.routes).toEqual([]);
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

  it.each([
    { name: "arrow property", member: "exec: (command, args) => execFileSync(command, args)" },
    { name: "async arrow property", member: "exec: async (command, args) => execFileSync(command, args)" },
    { name: "method property", member: "exec(command, args) { return execFileSync(command, args); }" },
  ])("retains command provenance through an anonymous $name executor wrapper", ({ member }) => {
    const root = fixture("export {};\n");
    symlinkSync(join(process.cwd(), "node_modules"), join(root, "node_modules"), "dir");
    mkdirSync(join(root, "src", "cli"));
    writeFileSync(join(root, "src", "child.ts"), 'import { produce } from "./producer.js"; produce();\n');
    const wrapped = `import { execFileSync } from "node:child_process";\ninterface Context { exec: (command: string, args: string[]) => unknown }\nconst ctx: Context = { ${member} };\nfunction run(context: Context) { context.exec("node", ["src/child.ts"]); }\nrun(ctx);\n`;
    writeFileSync(join(root, "src", "cli", "run-audit.ts"), wrapped);

    const live = discoverEffectivenessRouteGraph(root, [implementation]);
    expect(live.calls.map((call) => call.id)).toContain("command:src/cli/run-audit.ts->src/child.ts");
    expect(live.routes).toEqual([
      expect.objectContaining({
        producerId: "one",
        rootId: "src/cli/run-audit.ts",
        callReceiptIds: expect.arrayContaining([
          "command:src/cli/run-audit.ts->src/child.ts",
          "call:src/child.ts->src/producer.ts#produce",
        ]),
      }),
    ]);

    writeFileSync(join(root, "src", "cli", "run-audit.ts"), wrapped.replace("execFileSync(command, args)", "[]"));
    expect(discoverEffectivenessRouteGraph(root, [implementation]).routes).toEqual([]);
  });

  it.each([
    { name: "separate import", args: ["--import", "tsx", "src/child.ts"] },
    { name: "equals import", args: ["--import=tsx", "src/child.ts"] },
    { name: "source preload", args: ["--import", "./src/preload.ts", "src/child.ts"] },
    { name: "equals source preload", args: ["--import=./src/preload.ts", "src/child.ts"] },
    { name: "short require", args: ["-r", "./preload.cjs", "src/child.ts"] },
    { name: "long require", args: ["--require", "./preload.cjs", "src/child.ts"] },
    { name: "equals long require", args: ["--require=./preload.cjs", "src/child.ts"] },
    { name: "short condition", args: ["-C", "development", "src/child.ts"] },
    { name: "separate condition", args: ["--conditions", "development", "src/child.ts"] },
    { name: "equals condition", args: ["--conditions=development", "src/child.ts"] },
    { name: "boolean flag", args: ["--no-warnings", "src/child.ts"] },
    { name: "second boolean flag", args: ["--trace-warnings", "src/child.ts"] },
    { name: "mixed supported options", args: ["--conditions", "development", "--import", "tsx", "--no-warnings", "src/child.ts"] },
    { name: "option terminator", args: ["--", "src/child.ts"] },
    { name: "script argument after entry", args: ["src/child.ts", "--harvey-script-flag"] },
  ])("preserves execution and invocation provenance for $name", ({ args }) => {
    const root = nodeCommandFixture(args);
    expect(runNode(root, args)).toEqual({ status: 0, executed: true });
    const single = discoverEffectivenessRouteGraph(root, [implementation], ["src/venue.ts"], { detectUnknown: false });
    const graph = discoverEffectivenessRouteGraphs(root, [implementation], ["src/venue.ts"]).venues[0]!;
    expect(graph).toEqual(single);
    expect(graph.calls.map((call) => call.id)).toContain("command:src/venue.ts->src/child.ts");
    expect(graph.routes).toEqual([
      expect.objectContaining({
        producerId: "one",
        rootId: "src/venue.ts",
        callReceiptIds: expect.arrayContaining([
          "command:src/venue.ts->src/child.ts",
          "call:src/child.ts->src/producer.ts#produce",
        ]),
      }),
    ]);
  });

  it.each([
    { name: "missing import value", args: ["--import"] },
    { name: "missing import value before terminator", args: ["--import", "--", "src/child.ts"] },
    { name: "missing import value before flag", args: ["--import", "--no-warnings", "src/child.ts"] },
    { name: "empty equals import", args: ["--import=", "src/child.ts"] },
    { name: "attached short require", args: ["-r./preload.cjs", "src/child.ts"] },
    { name: "attached short condition", args: ["-Cdevelopment", "src/child.ts"] },
    { name: "eval mode", args: ["--eval", "console.log('not a file')", "src/child.ts"] },
    { name: "attached eval mode", args: ["-econsole.log('not a file')", "src/child.ts"] },
    { name: "check-only mode", args: ["--check", "src/child.ts"] },
    { name: "help mode", args: ["--help", "src/child.ts"] },
    { name: "version mode", args: ["--version", "src/child.ts"] },
    { name: "unknown option", args: ["--harvey-unsupported-flag", "src/child.ts"] },
    { name: "input type with file", args: ["--input-type=module", "src/child.ts"] },
    { name: "snapshot-building mode", args: ["--experimental-sea-config=missing.json", "src/child.ts"] },
    { name: "unsupported extension", args: ["src/child.txt"] },
  ])("does not claim execution for $name", ({ args }) => {
    const root = nodeCommandFixture(args);
    writeFileSync(join(root, "src", "child.txt"), "not executable source\n");
    expect(runNode(root, args).executed).toBe(false);
    const graph = discoverEffectivenessRouteGraphs(root, [implementation], ["src/venue.ts"]).venues[0]!;
    expect(graph.calls).toEqual([]);
    expect(graph.routes).toEqual([]);
  });

  it("keeps compiler-resolved package imports in a venue's executor scope", () => {
    const root = fixture("export {};\n");
    symlinkSync(join(process.cwd(), "node_modules"), join(root, "node_modules"), "dir");
    writeFileSync(join(root, "package.json"), JSON.stringify({ type: "module", imports: { "#runner": "./src/runner.ts" } }));
    mkdirSync(join(root, "src", "cli"));
    writeFileSync(join(root, "src", "cli", "run-audit.ts"), "export {};\n");
    writeFileSync(join(root, "src", "child.ts"), 'import { produce } from "./producer.js"; produce();\n');
    writeFileSync(join(root, "src", "runner.ts"), 'import { execFileSync } from "node:child_process"; export function run(bin: string, args: string[]) { return execFileSync(bin, args); }\n');
    writeFileSync(join(root, "src", "venue.ts"), 'import { run } from "#runner"; run("node", ["src/child.ts"]);\n');
    const single = discoverEffectivenessRouteGraph(root, [implementation], ["src/venue.ts"], { detectUnknown: false });
    const batch = discoverEffectivenessRouteGraphs(root, [implementation], ["src/venue.ts"]).venues[0]!;
    expect(batch).toEqual(single);
    expect(batch.routes).toHaveLength(1);
    expect(batch.calls.map((call) => call.id)).toContain("command:src/venue.ts->src/child.ts");
  });

  it.each([
    { name: "named package re-export", packageType: "module", index: 'export { run } from "#runner";\n', venue: 'import { run } from "./index.js"; run("node", ["src/child.ts"]);\n' },
    { name: "star package re-export", packageType: "module", index: 'export * from "#runner";\n', venue: 'import { run } from "./index.js"; run("node", ["src/child.ts"]);\n' },
    { name: "dynamic import", packageType: "module", index: "", venue: 'const runner = await import("./runner.js"); runner.run("node", ["src/child.ts"]); export {};\n' },
    { name: "import-equals", packageType: "commonjs", index: "", venue: 'import runner = require("./runner"); runner.run("node", ["src/child.ts"]);\n' },
  ])("preserves $name command evidence", ({ packageType, index, venue }) => {
    const root = fixture("export {};\n");
    symlinkSync(join(process.cwd(), "node_modules"), join(root, "node_modules"), "dir");
    writeFileSync(join(root, "package.json"), JSON.stringify({ type: packageType, imports: { "#runner": "./src/runner.ts" } }));
    mkdirSync(join(root, "src", "cli"));
    writeFileSync(join(root, "src", "cli", "run-audit.ts"), "export {};\n");
    writeFileSync(join(root, "src", "child.ts"), 'import { produce } from "./producer.js"; produce();\n');
    writeFileSync(join(root, "src", "runner.ts"), 'import { execFileSync } from "node:child_process"; export function run(bin: string, args: string[]) { return execFileSync(bin, args); }\n');
    if (index) writeFileSync(join(root, "src", "index.ts"), index);
    writeFileSync(join(root, "src", "venue.ts"), venue);
    const single = discoverEffectivenessRouteGraph(root, [implementation], ["src/venue.ts"], { detectUnknown: false });
    const batch = discoverEffectivenessRouteGraphs(root, [implementation], ["src/venue.ts"]).venues[0]!;
    expect(batch).toEqual(single);
    expect(batch.routes).toHaveLength(1);
    expect(batch.calls.map((call) => call.id)).toContain("command:src/venue.ts->src/child.ts");
  });

  it("does not borrow a venue-only type augmentation for production inference", () => {
    const root = fixture("export {};\n");
    mkdirSync(join(root, "src", "cli"));
    writeFileSync(join(root, "src", "cli", "run-audit.ts"), 'import { getOutput } from "../base.js"; getOutput();\n');
    writeFileSync(join(root, "src", "base.ts"), 'export interface Data { id: string; severity: string; location: string; } export function getOutput(): Data { return { id: "x", severity: "info", location: "x" }; }\n');
    writeFileSync(join(root, "src", "augmentation.ts"), 'import "./base.js"; declare module "./base.js" { interface Data { taxonomy?: string; } }\n');
    writeFileSync(join(root, "src", "venue.ts"), 'import "./augmentation.js"; export {};\n');
    const single = discoverEffectivenessRouteGraph(root, [implementation]);
    const batch = discoverEffectivenessRouteGraphs(root, [implementation], ["src/venue.ts"]);
    expect(batch.production).toEqual(single);
    expect(batch.production.unresolvedFindingDispatches).toEqual([]);
  });

  it("rebuilds command routes after package scripts change between invocations", () => {
    const root = fixture("export {};\n");
    symlinkSync(join(process.cwd(), "node_modules"), join(root, "node_modules"), "dir");
    const manifest = (target: string): string => JSON.stringify({ type: "module", packageManager: "pnpm@11.1.3", scripts: { launch: `node ${target}` } });
    writeFileSync(join(root, "package.json"), manifest("src/child-a.ts"));
    mkdirSync(join(root, "src", "cli"));
    writeFileSync(join(root, "src", "cli", "run-audit.ts"), "export {};\n");
    for (const suffix of ["a", "b"]) {
      writeFileSync(join(root, "src", `producer-${suffix}.ts`), `export function produce() { return ["${suffix}"]; }\n`);
      writeFileSync(join(root, "src", `child-${suffix}.ts`), `import { produce } from "./producer-${suffix}.js"; produce();\n`);
    }
    writeFileSync(join(root, "src", "venue.ts"), 'import { execFileSync } from "node:child_process"; execFileSync("pnpm", ["launch"]);\n');
    const implementations = ["a", "b"].map((suffix) => ({ ...implementation, producerId: suffix, file: `src/producer-${suffix}.ts` }));
    const first = discoverEffectivenessRouteGraphs(root, implementations, ["src/venue.ts"]).venues[0]!;
    writeFileSync(join(root, "package.json"), manifest("src/child-b.ts"));
    const changed = discoverEffectivenessRouteGraphs(root, implementations, ["src/venue.ts"]).venues[0]!;
    expect(first.routes.map((route) => route.producerId)).toEqual(["a"]);
    expect(changed.routes.map((route) => route.producerId)).toEqual(["b"]);
    expect(changed).toEqual(discoverEffectivenessRouteGraph(root, implementations, ["src/venue.ts"], { detectUnknown: false }));
  });

  it("accepts every frozen ordered runtime edge kind without collapsing them", () => {
    const edges = PRODUCER_ROUTE_EDGE_KINDS.map((kind, ordinal) => ({ kind, from: `n${ordinal}`, to: `n${ordinal + 1}` }));
    const receipt = createProducerExecutionReceipt({ executionId: "all-edges", producerId: "one", implementationId: "src/producer.ts#produce", module: "M1", tier: "free", findingFamilyIds: ["ONE"], findingIds: [], edges });
    expect(receipt.edges.map((edge) => edge.kind)).toEqual(PRODUCER_ROUTE_EDGE_KINDS);
  });
});
