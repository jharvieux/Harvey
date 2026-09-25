import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverEffectivenessRouteGraph, discoverEffectivenessRouteGraphs, discoverEffectivenessVenueRouteGraphs } from "./effectiveness-route-graph.js";
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

  it("preserves producer identity through direct, import and bounded local aliases with an execution oracle", () => {
    const root = fixture("export {};\n");
    writeFileSync(join(root, "src", "producer.mjs"), "export function produce() { console.log('PRODUCER_EXECUTED'); return [{ id: 'executed', taxonomy: 'test', severity: 'Low', location: 'fixture' }]; }\n");
    const cases = {
      direct: "import { produce } from './producer.mjs'; export const findings = produce();\n",
      "import-alias": "import { produce as alias } from './producer.mjs'; export const findings = alias();\n",
      "local-alias": "import { produce } from './producer.mjs'; const alias = produce; export const findings = alias();\n",
      "multi-hop": "import { produce } from './producer.mjs'; const first = produce; const second = first; const third = second; export const findings = third();\n",
    };
    const aliasImplementation = { ...implementation, file: "src/producer.mjs" };

    for (const [name, source] of Object.entries(cases)) {
      const file = join(root, "src", `${name}.mjs`);
      writeFileSync(file, source);
      const graph = discoverEffectivenessRouteGraph(root, [aliasImplementation], [`src/${name}.mjs`]);
      expect(graph.routes, name).toHaveLength(1);
      expect(graph.routes[0]?.implementationId, name).toBe("src/producer.mjs#produce");
      expect(runNode(root, [`src/${name}.mjs`]), name).toEqual({ status: 0, executed: true });
    }
  });

  it("discloses ambiguous aliases and suppresses guessed routes in venue mode", () => {
    const cases = {
      "const through mutable": {
        source: "import { produce } from './producer.ts'; let first = produce; const alias = first; alias();\n",
        executed: true,
        diagnostic: "mutable local alias first",
      },
      "over alias limit": {
        source: "import { produce } from './producer.ts'; const a0=produce; const a1=a0; const a2=a1; const a3=a2; const a4=a3; const a5=a4; const a6=a5; const a7=a6; const a8=a7; a8();\n",
        executed: true,
        diagnostic: "exceeds the 8-hop resolution limit",
      },
      "reassigned property": {
        source: "import { produce, type Finding } from './producer.ts'; const obj={run:produce}; obj.run=(): Finding[]=>[]; const alias=obj.run; alias();\n",
        executed: false,
        diagnostic: "mutable property alias run",
      },
    };
    for (const [name, testCase] of Object.entries(cases)) {
      const root = fixture(testCase.source);
      writeFileSync(join(root, "src", "producer.ts"), "export interface Finding { id:string; taxonomy:string; severity:string; location:string }\nexport function produce(): Finding[] { console.log('PRODUCER_EXECUTED'); return [{id:'x',taxonomy:'x',severity:'Low',location:'x'}]; }\n");
      const graph = discoverEffectivenessRouteGraph(root, [implementation], ["src/root.ts"]);
      expect(runNode(root, ["src/root.ts"]).executed, name).toBe(testCase.executed);
      expect(graph.routes, name).toEqual([]);
      expect(graph.unresolvedFindingDispatches.join("\n"), name).toContain(testCase.diagnostic);
      const venueGraph = discoverEffectivenessVenueRouteGraphs(root, [implementation], ["src/root.ts"])[0]!;
      expect(venueGraph.routes, `${name}: venue`).toEqual([]);
      expect(venueGraph.unresolvedFindingDispatches.join("\n"), `${name}: venue ambiguity disclosed`).toContain(testCase.diagnostic);
    }
  });

  it("applies property-alias provenance to reachable calls and callback registry receipts", () => {
    const producer = "export interface Finding { id:string; taxonomy:string; severity:string; location:string }\nexport function produce(): Finding[] { console.log('PRODUCER_EXECUTED'); return [{id:'x',taxonomy:'x',severity:'Low',location:'x'}]; }\n";
    const reassignedCall = "import { produce, type Finding } from './producer.ts'; const obj={run:produce}; obj.run=(): Finding[]=>[]; const alias=obj.run; alias();\n";
    const reachableRoot = fixture("import './consumer.ts';\n");
    writeFileSync(join(reachableRoot, "src", "producer.ts"), producer);
    writeFileSync(join(reachableRoot, "src", "consumer.ts"), reassignedCall);
    expect(runNode(reachableRoot, ["src/root.ts"]).executed).toBe(false);
    for (const detectUnknown of [true, false]) {
      const graph = discoverEffectivenessRouteGraph(reachableRoot, [implementation], ["src/root.ts"], { detectUnknown });
      expect(graph.routes, `reachable reassigned call, detectUnknown=${detectUnknown}`).toEqual([]);
      expect(graph.unresolvedFindingDispatches.join("\n")).toContain("ambiguous producer identity");
    }

    const callbacks = {
      immutable: {
        source: "import { produce, type Finding } from './producer.ts'; const obj={run:produce}; function invoke(fn:()=>Finding[]){fn();} invoke(obj.run);\n",
        executed: true,
        routes: 1,
      },
      reassigned: {
        source: "import { produce, type Finding } from './producer.ts'; const obj={run:produce}; obj.run=(): Finding[]=>[]; function invoke(fn:()=>Finding[]){fn();} invoke(obj.run);\n",
        executed: false,
        routes: 0,
      },
    };
    for (const [name, testCase] of Object.entries(callbacks)) {
      const root = fixture(testCase.source);
      writeFileSync(join(root, "src", "producer.ts"), producer);
      expect(runNode(root, ["src/root.ts"]).executed, `${name}: execution`).toBe(testCase.executed);
      const graph = discoverEffectivenessRouteGraph(root, [implementation], ["src/root.ts"]);
      expect(graph.routes, `${name}: production`).toHaveLength(testCase.routes);
      const venueGraph = discoverEffectivenessVenueRouteGraphs(root, [implementation], ["src/root.ts"])[0]!;
      expect(venueGraph.routes, `${name}: venue`).toHaveLength(testCase.routes);
      if (name === "reassigned") {
        expect(graph.unresolvedFindingDispatches.join("\n")).toContain("finding-bearing registry reference has ambiguous producer identity");
        expect(venueGraph.unresolvedFindingDispatches.join("\n")).toContain("finding-bearing registry reference has ambiguous producer identity");
      }
    }
  });

  it("does not invent routes for unused, unrelated, shadowed or mutable aliases", () => {
    const cases = {
      unused: "import { produce } from './producer.js'; const alias = produce; void alias;\n",
      unrelated: "import { produce } from './producer.js'; function alias() { return []; } alias(); void produce;\n",
      "same-name unrelated": "function produce() { return []; } produce();\n",
      shadowed: "import { produce } from './producer.js'; function run(produce: () => unknown[]) { produce(); } run(() => []);\n",
      reassigned: "import { produce, type Finding } from './producer.js'; const unrelated = (): Finding[] => []; let alias = produce; alias = unrelated; alias();\n",
    };
    for (const [name, source] of Object.entries(cases)) {
      const root = fixture(source);
      writeFileSync(join(root, "src", "producer.ts"), "export interface Finding { id: string; taxonomy: string; severity: string; location: string }\nexport function produce(): Finding[] { return []; }\n");
      const graph = discoverEffectivenessRouteGraph(root, [implementation], ["src/root.ts"]);
      expect(graph.routes, name).toEqual([]);
      if (name === "reassigned") {
        expect(graph.unresolvedFindingDispatches.join("\n")).toContain("mutable local alias");
      }
    }
  });

  it("reports the underlying producer when a local alias calls an unregistered implementation", () => {
    const root = fixture('import { produce } from "./producer.js"; const alias = produce; alias();\n');
    writeFileSync(join(root, "src", "producer.ts"), "export interface Finding { id: string; taxonomy: string; severity: string; location: string }\nexport function produce(): Finding[] { return []; }\n");
    const graph = discoverEffectivenessRouteGraph(root, [], ["src/root.ts"]);
    expect(graph.routes).toEqual([]);
    expect(graph.unresolvedFindingDispatches).toContain(
      "src/root.ts#produce: finding-bearing call target src/producer.ts#produce is unregistered",
    );
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
    { name: "typed arrow property", typed: true, member: "exec: (command, args) => execFileSync(command, args)" },
    { name: "typed async arrow property", typed: true, member: "exec: async (command, args) => execFileSync(command, args)" },
    { name: "typed method property", typed: true, member: "exec(command, args) { return execFileSync(command, args); }" },
    { name: "inferred arrow property", typed: false, member: "exec: (command: string, args: string[]) => execFileSync(command, args)" },
    { name: "inferred async arrow property", typed: false, member: "exec: async (command: string, args: string[]) => execFileSync(command, args)" },
    { name: "inferred method property", typed: false, member: "exec(command: string, args: string[]) { return execFileSync(command, args); }" },
    { name: "typed quoted arrow property", typed: true, member: '"exec": (command, args) => execFileSync(command, args)' },
    { name: "typed quoted method property", typed: true, member: '"exec"(command, args) { return execFileSync(command, args); }' },
    { name: "typed computed arrow property", typed: true, member: '["exec"]: (command, args) => execFileSync(command, args)' },
    { name: "inferred function-expression property", typed: false, member: "exec: function (command: string, args: string[]) { return execFileSync(command, args); }" },
    { name: "typed function-expression property", typed: true, member: "exec: function (command, args) { return execFileSync(command, args); }" },
  ])("retains command provenance through an anonymous $name executor wrapper", ({ member, typed }) => {
    const root = fixture("export {};\n");
    symlinkSync(join(process.cwd(), "node_modules"), join(root, "node_modules"), "dir");
    mkdirSync(join(root, "src", "cli"));
    writeFileSync(join(root, "src", "child.ts"), 'import { produce } from "./producer.js"; produce();\n');
    const invocation = typed
      ? 'function run(context: Context) { context.exec("node", ["src/child.ts"]); }\nrun(ctx);'
      : 'ctx.exec("node", ["src/child.ts"]);';
    const wrapped = `import { execFileSync } from "node:child_process";\ninterface Context { exec: (command: string, args: string[]) => unknown }\nconst ctx${typed ? ": Context" : ""} = { ${member} };\n${invocation}\n`;
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

  const transparentWrappers = [
    { name: "parenthesized", wrap: (body: string) => `(${body})` },
    { name: "as expression", wrap: (body: string) => `(${body}) as Context["exec"]` },
    { name: "type assertion", wrap: (body: string) => `<Context["exec"]>(${body})` },
    { name: "satisfies expression", wrap: (body: string) => `(${body}) satisfies Context["exec"]` },
    { name: "non-null expression", wrap: (body: string) => `(${body})!` },
    { name: "nested transparent expressions", wrap: (body: string) => `(((${body})!) as Context["exec"]) satisfies Context["exec"]` },
  ];
  const transparentWrapperCases = transparentWrappers.flatMap(({ name, wrap }) => [
    { name: `typed ${name} arrow`, typed: true, member: wrap("(command, args) => execFileSync(command, args)") },
    { name: `inferred ${name} arrow`, typed: false, member: wrap("(command: string, args: string[]) => execFileSync(command, args)") },
    { name: `typed ${name} function expression`, typed: true, member: wrap("function (command, args) { return execFileSync(command, args); }") },
    { name: `inferred ${name} function expression`, typed: false, member: wrap("function (command: string, args: string[]) { return execFileSync(command, args); }") },
  ]);

  it.each(transparentWrapperCases)("retains command provenance through a $name", ({ member, typed }) => {
    const root = fixture("export {};\n");
    symlinkSync(join(process.cwd(), "node_modules"), join(root, "node_modules"), "dir");
    mkdirSync(join(root, "src", "cli"));
    writeFileSync(join(root, "src", "child.ts"), 'import { produce } from "./producer.js"; produce();\n');
    const invocation = typed
      ? 'function run(context: Context) { context.exec("node", ["src/child.ts"]); }\nrun(ctx);'
      : 'ctx.exec("node", ["src/child.ts"]);';
    const wrapped = `import { execFileSync } from "node:child_process";\ninterface Context { exec: (command: string, args: string[]) => unknown }\nconst ctx${typed ? ": Context" : ""} = { exec: ${member} };\n${invocation}\n`;
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

  const transparentOwnerCases = transparentWrappers.flatMap(({ name, wrap }) => [
    { name: `${name} named arrow owner`, wrap, functionKind: "arrow" as const },
    { name: `${name} named function-expression owner`, wrap, functionKind: "function" as const },
  ]);

  it.each(transparentOwnerCases)("retains command provenance through a $name", ({ wrap, functionKind }) => {
    const root = fixture("export {};\n");
    symlinkSync(join(process.cwd(), "node_modules"), join(root, "node_modules"), "dir");
    mkdirSync(join(root, "src", "cli"));
    writeFileSync(join(root, "src", "child.ts"), 'import { produce } from "./producer.js"; produce();\n');
    const source = (native: boolean): string => {
      const result = native ? "execFileSync(command, args)" : "[]";
      const executor = functionKind === "arrow"
        ? `(command: string, args: string[]) => ${result}`
        : `function (command: string, args: string[]) { return ${result}; }`;
      return `import { execFileSync } from "node:child_process";\ninterface Context { exec: (command: string, args: string[]) => unknown }\nconst execute = ${wrap(executor)};\nexecute("node", ["src/child.ts"]);\n`;
    };
    writeFileSync(join(root, "src", "cli", "run-audit.ts"), source(true));

    const live = discoverEffectivenessRouteGraph(root, [implementation]);
    expect(live.calls.map((call) => call.id)).toContain("command:src/cli/run-audit.ts->src/child.ts");
    expect(live.routes).toHaveLength(1);

    writeFileSync(join(root, "src", "cli", "run-audit.ts"), source(false));
    expect(discoverEffectivenessRouteGraph(root, [implementation]).routes).toEqual([]);
  });

  const transparentSymbolCases = transparentWrappers.flatMap(({ name, wrap }) => [
    ...(["native executor", "named wrapper", "typed member", "own member"] as const).map((symbolKind) => ({
      name: `${name} alias of ${symbolKind}`,
      wrap,
      symbolKind,
      direct: false,
    })),
    ...(["native executor", "named wrapper", "typed member", "own member"] as const).map((symbolKind) => ({
      name: `${name} direct ${symbolKind} callee`,
      wrap,
      symbolKind,
      direct: true,
    })),
  ]);

  it.each(transparentSymbolCases)("retains command provenance through a $name", ({ wrap, symbolKind, direct }) => {
    const root = fixture("export {};\n");
    symlinkSync(join(process.cwd(), "node_modules"), join(root, "node_modules"), "dir");
    mkdirSync(join(root, "src", "cli"));
    writeFileSync(join(root, "src", "child.ts"), 'import { produce } from "./producer.js"; produce();\n');
    const source = (native: boolean): string => {
      const result = native ? "execFileSync(command, args)" : "[]";
      const setup = symbolKind === "native executor"
        ? ""
        : symbolKind === "named wrapper"
          ? `function executeNamed(command: string, args: string[]) { return ${result}; }\n`
          : symbolKind === "typed member"
            ? `const ctx: Context = { exec: (command, args) => ${result} };\n`
            : `const ctx = { exec: (command: string, args: string[]) => ${result} };\n`;
      const symbol = symbolKind === "native executor"
        ? native ? "execFileSync" : "((command: string, args: string[]) => [])"
        : symbolKind === "named wrapper"
          ? "executeNamed"
          : "ctx.exec";
      const invocation = direct
        ? `(${wrap(symbol)})("node", ["src/child.ts"]);`
        : `const execute = ${wrap(symbol)};\nexecute("node", ["src/child.ts"]);`;
      return `import { execFileSync } from "node:child_process";\ninterface Context { exec: (command: string, args: string[]) => unknown }\n${setup}${invocation}\n`;
    };
    writeFileSync(join(root, "src", "cli", "run-audit.ts"), source(true));

    const live = discoverEffectivenessRouteGraph(root, [implementation]);
    expect(live.calls.map((call) => call.id)).toContain("command:src/cli/run-audit.ts->src/child.ts");
    expect(live.routes).toHaveLength(1);

    writeFileSync(join(root, "src", "cli", "run-audit.ts"), source(false));
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
