import { execFileSync, spawn, type ChildProcessByStdio } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Readable } from "node:stream";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  serializeEffectivenessInventory,
  validateEffectivenessInventory,
} from "./effectiveness-registry.js";
import { discoverEffectivenessRouteGraph } from "./effectiveness-route-graph.js";
import type { EffectivenessInventory, EffectivenessProducer } from "./effectiveness-schema.js";
import { HEAVY_CLI_TESTS, shardHeavyTests } from "./heavy-cli-tests.js";
import { createProducerExecutionReceipt, type ProducerExecutionReceipt } from "./producer-execution-receipt.js";

const REPO_ROOT = new URL("..", import.meta.url).pathname;
const EXPECTED_INVENTORY_SHA = "002b42909d683967584929b37111689915a77f9b20dc4d9232d695897bacb107";
const CENSUS_SLICE_MS = 10_000;
const CENSUS_SLICE_COUNT = 8;
const PARENT_INVENTORY_GETTER = ["get", "Effectiveness", "Inventory"].join("");

type ManagedChild = {
  child: ChildProcessByStdio<null, Readable, Readable>;
  close: Promise<void>;
  closed: boolean;
  code: number | null | undefined;
  signal: NodeJS.Signals | null | undefined;
  error: Error | undefined;
  stdout: string;
  stderr: string;
};

function startManagedChild(command: string, args: readonly string[]): ManagedChild {
  const child = spawn(command, [...args], {
    cwd: REPO_ROOT,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let resolveClose!: () => void;
  const run: ManagedChild = {
    child,
    close: new Promise<void>((resolve) => { resolveClose = resolve; }),
    closed: false,
    code: undefined,
    signal: undefined,
    error: undefined,
    stdout: "",
    stderr: "",
  };
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => { run.stdout += chunk; });
  child.stderr.on("data", (chunk: string) => { run.stderr += chunk; });
  child.once("error", (error) => {
    run.error = error;
    if (child.pid === undefined) {
      run.closed = true;
      resolveClose();
    }
  });
  child.once("close", (code, signal) => {
    run.closed = true;
    run.code = code;
    run.signal = signal;
    resolveClose();
  });
  return run;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForClose(run: ManagedChild, ms: number): Promise<boolean> {
  if (run.closed) return true;
  await Promise.race([run.close, delay(ms)]);
  return run.closed;
}

async function terminateAndReap(run: ManagedChild): Promise<void> {
  if (run.closed) return;
  run.child.kill("SIGTERM");
  if (await waitForClose(run, 2_000)) return;
  run.child.kill("SIGKILL");
  if (!(await waitForClose(run, 5_000))) {
    throw new Error(`failed to reap child process ${run.child.pid ?? "without-pid"}`);
  }
}

async function waitForCensusSlice(run: ManagedChild): Promise<void> {
  await waitForClose(run, CENSUS_SLICE_MS);
  if (run.error !== undefined && !run.closed) {
    await terminateAndReap(run);
    throw run.error;
  }
  if (run.closed && (run.error !== undefined || run.code !== 0)) {
    throw new Error(`detector-census exited ${run.code ?? run.signal ?? "before-spawn"}: ${run.error?.message ?? run.stderr}`);
  }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

let censusRun: ManagedChild | undefined;
let censusInventory: EffectivenessInventory | undefined;

beforeAll(() => {
  censusRun = startManagedChild("node", [
    "--import",
    "tsx",
    "src/cli/detector-census.ts",
    "--effectiveness-json",
    "--reverse-effectiveness-inputs",
  ]);
});
afterEach(() => new Promise<void>((resolve) => setImmediate(resolve)));
afterAll(async () => {
  if (censusRun !== undefined) await terminateAndReap(censusRun);
});

const immutableInventory = (): EffectivenessInventory => {
  if (censusInventory === undefined) throw new Error("reversed detector-census did not produce the shared inventory fixture");
  return censusInventory;
};

const freshInventory = (): EffectivenessInventory =>
  JSON.parse(JSON.stringify(immutableInventory())) as EffectivenessInventory;

function withExecutionReceipts(
  inventory: EffectivenessInventory,
  receipts: readonly ProducerExecutionReceipt[],
): EffectivenessInventory {
  const idsFor = (producerId: string): string[] => receipts
    .filter((receipt) => receipt.producerId === producerId)
    .map((receipt) => receipt.executionId)
    .sort();
  return {
    ...inventory,
    producers: inventory.producers.map((row) => ({ ...row, executionReceiptIds: idsFor(row.id) })),
    receipt: {
      ...inventory.receipt,
      conservation: inventory.receipt.conservation.map((row) => ({
        ...row,
        executionReceiptIds: idsFor(row.producerId),
      })),
      producerExecutions: [...receipts],
    },
  };
}

function producer(inventory: EffectivenessInventory, id: string): EffectivenessProducer {
  const row = inventory.producers.find((candidate) => candidate.id === id);
  expect(row, `missing producer ${id}`).toBeDefined();
  return row!;
}

function withProducer(
  inventory: EffectivenessInventory,
  id: string,
  update: (row: EffectivenessProducer) => EffectivenessProducer,
): EffectivenessInventory {
  return {
    ...inventory,
    producers: inventory.producers.map((row) => (row.id === id ? update(row) : row)),
  };
}

const expectRestoredBaseline = (): void => {
  expect(validateEffectivenessInventory(freshInventory())).toEqual([]);
};

describe("awaited reversed detector-census integration", () => {
  it.each(Array.from({ length: CENSUS_SLICE_COUNT }, (_, index) => index + 1))(
    "yields while awaiting the one reversed census child (slice %i)",
    async () => { await waitForCensusSlice(censusRun!); },
  );

  it("preserves the exact schema-v3 inventory bytes under reversed inputs", async () => {
    if (censusRun === undefined) throw new Error("reversed detector-census child did not start");
    if (!censusRun.closed) {
      await terminateAndReap(censusRun);
      throw new Error(`reversed detector-census exceeded ${CENSUS_SLICE_COUNT} bounded wait slices`);
    }
    await waitForCensusSlice(censusRun);
    const output = censusRun.stdout;
    const canonical = serializeEffectivenessInventory(JSON.parse(output) as EffectivenessInventory);
    expect(output).toBe(`${canonical}\n`);
    expect(createHash("sha256").update(output).digest("hex")).toBe(EXPECTED_INVENTORY_SHA);
    censusInventory = deepFreeze(JSON.parse(output) as EffectivenessInventory);
  });

  it("routes both census owners once and requires their afterAll terminate-and-reap teardown", () => {
    const detectorCensusTests = execFileSync("git", ["ls-files", "*.test.ts"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
    })
      .trim()
      .split("\n")
      .filter((file) => {
        const source = readFileSync(join(REPO_ROOT, file), "utf8");
        return source.includes("src/cli/detector-census.ts") && /\bspawn\s*\(/.test(source);
      })
      .sort();
    expect(detectorCensusTests).toEqual([
      "src/effectiveness-delivery.test.ts",
      "src/effectiveness-registry.test.ts",
    ]);
    expect(detectorCensusTests.every((file) => HEAVY_CLI_TESTS.includes(file))).toBe(true);
    const afterAllCleanup = /afterAll\(\s*async\s*\(\)\s*=>\s*\{\s*if\s*\(\s*censusRun\s*!==\s*undefined\s*\)\s*await\s+terminateAndReap\(\s*censusRun\s*\);\s*\}\s*\);/;
    for (const file of detectorCensusTests) {
      const source = readFileSync(join(REPO_ROOT, file), "utf8");
      expect(source, `${file} must bound each child wait below the global timeout`).toContain("waitForCensusSlice");
      expect(source, `${file} must terminate and reap an unfinished child`).toContain("terminateAndReap");
      expect(source, `${file} must escalate cleanup when graceful termination stalls`).toContain("SIGKILL");
      expect(source, `${file} must yield between child and unit assertions`).toContain("setImmediate");
      expect(source, `${file} must not start a second parent inventory build`).not.toContain(PARENT_INVENTORY_GETTER);
      expect(source, `${file} must not directly await the unbounded child lifetime`).not.toMatch(
        /await\s+(?:runDetectorCensus\s*\(|censusRun!?\.close)/,
      );
      expect(source, `${file} must clean up its retained census child in afterAll`).toMatch(afterAllCleanup);
      const censusJsonArg = new RegExp(["--effectiveness", "json"].join("-"), "g");
      expect(source.match(censusJsonArg), `${file} must start exactly one real census`).toHaveLength(1);
    }

    const routed = shardHeavyTests(3).flat();
    expect([...routed].sort()).toEqual([...HEAVY_CLI_TESTS].sort());
    for (const file of detectorCensusTests) {
      expect(routed.filter((candidate) => candidate === file), `${file} must run exactly once`).toHaveLength(1);
    }
  });

  it("terminates and reaps an unfinished child before another test can run", async () => {
    const run = startManagedChild(process.execPath, ["-e", "setInterval(() => {}, 1000)"]);
    const pid = run.child.pid;
    expect(pid).toBeDefined();
    try {
      await terminateAndReap(run);
      expect(run.closed).toBe(true);
      expect(() => process.kill(pid!, 0)).toThrow();
    } finally {
      if (!run.closed) {
        run.child.kill("SIGKILL");
        await waitForClose(run, 5_000);
      }
    }
  });
});

describe("effectiveness producer inventory (#1910)", () => {
  beforeAll(() => {
    if (censusInventory === undefined) throw new Error("unit inventory unavailable after reversed census failure");
  });
  it("binds actual runtime receipts to their exact producer and rejects unknown or forged ownership", () => {
    const receipt = createProducerExecutionReceipt({
      executionId: "conservation:M7",
      producerId: "plant:M7",
      implementationId: "src/audit-conservation.ts#CALIBRATION_PLANTS",
      module: "M7",
      tier: "free",
      findingFamilyIds: ["@conservation-plant:M7"],
      findingIds: ["M7-plant"],
      edges: [{ kind: "conservation-consume", from: "plant:M7", to: "conservation:M7" }],
    });
    const rule = "javascript.express.security.audit.xss.direct-response-write.direct-response-write";
    const directResponseReceipt = createProducerExecutionReceipt({
      executionId: "semgrep:direct-response",
      producerId: `semgrep:registry:${rule}`,
      implementationId: `src/scan/semgrep.ts#${rule}`,
      module: "M1",
      tier: "free",
      findingFamilyIds: [rule],
      findingIds: [],
      edges: [{ kind: "semgrep-family", from: "semgrep-family:registry-singleton-direct-response-write", to: `producer:semgrep:registry:${rule}` }],
    });
    const inventory = withExecutionReceipts(freshInventory(), [receipt, directResponseReceipt]);
    expect(producer(inventory, "plant:M7").executionReceiptIds).toEqual(["conservation:M7"]);
    expect(producer(inventory, `semgrep:registry:${rule}`).executionReceiptIds).toEqual(["semgrep:direct-response"]);
    expect(validateEffectivenessInventory(inventory)).toEqual([]);
    const unknown = createProducerExecutionReceipt({
      executionId: receipt.executionId,
      producerId: "unknown",
      implementationId: receipt.implementationId,
      module: receipt.module,
      tier: receipt.tier,
      findingFamilyIds: receipt.findingFamilyIds,
      findingIds: receipt.findingIds,
      edges: receipt.edges.map(({ kind, from, to }) => ({ kind, from, to })),
    });
    expect(validateEffectivenessInventory(withExecutionReceipts(freshInventory(), [unknown])).join("\n")).toMatch(/unknown producer/);
  });
  it("closes the production registries and preserves the current exact populations", () => {
    const inventory = freshInventory();
    expect(validateEffectivenessInventory(inventory)).toEqual([]);
    expect(inventory.receipt).toMatchObject({
      mechanicalDefinitions: 73,
      localSemgrepFamilies: 10,
      localSemgrepRuleIds: 118,
      registrySemgrepPacks: 6,
    });
    expect(inventory.receipt.mechanicalProducerIds).toHaveLength(73);
    expect(inventory.receipt.localSemgrepFamilyIds).toHaveLength(10);
    expect(inventory.receipt.localSemgrepRules).toHaveLength(118);
    expect(inventory.receipt.registrySemgrepPackIds).toEqual([
      "p/nextjs",
      "p/owasp-top-ten",
      "p/react",
      "p/secrets",
      "p/security-audit",
      "p/typescript",
    ]);
  });

  it("keeps each producer class disjoint and excludes controls from the true-family count", () => {
    const inventory = freshInventory();
    const summary = inventory.summary;
    expect(
      summary.trueFindingProducers
        + summary.disclosureOnly
        + summary.typedNotAssessed
        + summary.conservationPlants
        + summary.adapters
        + summary.synthesizers,
    ).toBe(summary.producers);
    expect(summary.denominatorConserved).toBe(true);

    const trueFindingFamilies = inventory.producers
      .filter((row) => row.populationClass === "true-finding-producer")
      .flatMap((row) => row.findingFamilies)
      .filter((row) => row.kind === "finding");
    const allFindingShapedFamilies = inventory.producers
      .flatMap((row) => row.findingFamilies)
      .filter((row) => row.kind === "finding");
    expect(summary.findingFamilies).toBe(trueFindingFamilies.length);
    expect(allFindingShapedFamilies.length).toBeGreaterThan(summary.findingFamilies);
    for (const row of inventory.producers) {
      expect(row.executionReceiptIds, `${row.id} runtime evidence must be explicit`).toEqual([]);
      for (const family of row.findingFamilies) {
        expect((family.venueIds.length > 0) !== (family.exemptionId !== undefined), family.id).toBe(true);
      }
    }
  });

  it("keeps inventory construction lazy and the default census on one memoized build", () => {
    const registrySource = readFileSync(join(REPO_ROOT, "src", "effectiveness-registry.ts"), "utf8");
    const censusSource = readFileSync(join(REPO_ROOT, "src", "cli", "detector-census.ts"), "utf8");
    expect(registrySource).not.toMatch(/^(?:export )?const \w+\s*=\s*buildEffectivenessInventory\(\);$/m);
    expect(registrySource).toContain("defaultEffectivenessInventory ??= buildEffectivenessInventory()");
    expect(censusSource).toContain(`producerExecutionReceipts.length === 0\n      ? ${PARENT_INVENTORY_GETTER}()`);
    expect(serializeEffectivenessInventory(immutableInventory())).not.toContain(process.cwd());
    expect(new Set(immutableInventory().receipt.calls.map((receipt) => receipt.kind))).toEqual(new Set(["call", "command"]));
    expect(immutableInventory().receipt.producerExecutions).toEqual([]);
  });

  it("retains one handrolled, one SFC, and one M5 hardcoded producer across their multiple consumers", () => {
    const inventory = freshInventory();
    const owners = (symbol: string): EffectivenessProducer[] => inventory.producers.filter((row) =>
      row.implementations.some((item) => item.symbol === symbol));
    expect(owners("detectHandrolledFindings").map((row) => row.id)).toEqual([
      "mechanical:structural-ast:handrolled-indicators",
    ]);
    expect(owners("checkUnassessedSfcFiles").map((row) => row.id)).toEqual([
      "mechanical:configuration:sfc-coverage",
    ]);
    expect(owners("detectM5HardcodedDeploymentFindings").map((row) => row.id)).toEqual([
      "mechanical:structural-ast:m5-hardcoded-deployment",
    ]);
    expect(inventory.receipt.routes.filter((row) => row.producerId === "mechanical:structural-ast:handrolled-indicators").length).toBeGreaterThan(0);
    expect(producer(inventory, "mechanical:structural-ast:handrolled-indicators").routeIds.length).toBeGreaterThan(0);
    expect(inventory.receipt.routes.filter((row) => row.producerId === "mechanical:structural-ast:m5-hardcoded-deployment").length).toBeGreaterThan(0);
    expect(producer(inventory, "mechanical:structural-ast:m5-hardcoded-deployment").routeIds.length).toBeGreaterThan(0);
  });

  it("admits only executable production routes, never registry evidence or falsifier paths", () => {
    const inventory = freshInventory();
    const isTestFile = (path: string): boolean => /\.test\.[cm]?[jt]sx?$/.test(path);
    expect(inventory.receipt.calls.filter((receipt) =>
      isTestFile(receipt.consumerFile) || isTestFile(receipt.targetFile))).toEqual([]);
    expect(inventory.receipt.routes.filter((route) =>
      isTestFile(route.rootId)
      || isTestFile(route.implementationId.split("#")[0]!)
      || route.callReceiptIds.some((id) => /\.test\.[cm]?[jt]sx?(?:->|$)/.test(id)))).toEqual([]);

    expect(inventory.receipt.calls).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "command", consumerFile: "src/audit-runners.ts", targetFile: "src/cli/quick-scan.ts" }),
      expect.objectContaining({ kind: "command", consumerFile: "src/audit-runners.ts", targetFile: "src/cli/static-detect.ts" }),
      expect.objectContaining({ kind: "command", consumerFile: "src/audit-runners.ts", targetFile: "tools/pii-classify.mjs" }),
    ]));
    const appRouterRoutes = inventory.receipt.routes.filter((route) => route.producerId === "detector:app-router");
    expect(new Set(appRouterRoutes.flatMap((route) => route.callReceiptIds))).toEqual(new Set([
      "command:src/audit-runners.ts->src/cli/quick-scan.ts",
      "command:src/audit-runners.ts->src/cli/static-detect.ts",
      "call:src/cli/static-detect.ts->src/detectors/app-router.ts#detectAppRouterFindings",
      "call:src/health-scorecard.ts->src/detectors/app-router.ts#detectAppRouterFindings",
    ]));
  });

  it("fails when the sole registry invoke is deleted even if its evidence names a real test caller", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-effectiveness-registry-route-"));
    try {
      mkdirSync(join(root, "src", "cli"), { recursive: true });
      mkdirSync(join(root, "src", "scan"), { recursive: true });
      writeFileSync(join(root, "package.json"), JSON.stringify({ packageManager: "pnpm@10", scripts: { audit: "tsx src/cli/run-audit.ts" } }));
      writeFileSync(join(root, "src", "scan", "bola-owner.ts"), [
        "export interface Finding { id: string; taxonomy: string; severity: string; location: string }",
        "export function detectBolaOwnerFindings(): Finding[] { return []; }",
        "",
      ].join("\n"));
      writeFileSync(join(root, "src", "scan", "path-scope.test.ts"), [
        'import { detectBolaOwnerFindings } from "./bola-owner.js";',
        "export const testOnly = detectBolaOwnerFindings();",
        "",
      ].join("\n"));
      const registry = (invoke: string): string => [
        'import { detectBolaOwnerFindings } from "./bola-owner.js";',
        "const evidence = (_path: string): void => {};",
        'evidence("src/scan/path-scope.test.ts");',
        `export const detector = { invoke: ${invoke} };`,
        "",
      ].join("\n");
      writeFileSync(join(root, "src", "scan", "mechanical-detector-registry.ts"), registry("() => detectBolaOwnerFindings()"));
      writeFileSync(join(root, "src", "cli", "run-audit.ts"), 'import { detector } from "../scan/mechanical-detector-registry.js";\nexport const findings = detector.invoke();\n');
      const implementation = { producerId: "bola-owner", file: "src/scan/bola-owner.ts", symbol: "detectBolaOwnerFindings", kind: "function" as const };
      const live = discoverEffectivenessRouteGraph(root, [implementation]);
      expect(live.routes).toHaveLength(1);
      expect(live.calls.some((receipt) => receipt.consumerFile.endsWith(".test.ts") || receipt.targetFile.endsWith(".test.ts"))).toBe(false);

      writeFileSync(join(root, "src", "scan", "mechanical-detector-registry.ts"), registry("() => []"));
      expect(discoverEffectivenessRouteGraph(root, [implementation]).routes).toEqual([]);
      writeFileSync(join(root, "src", "scan", "mechanical-detector-registry.ts"), registry("() => detectBolaOwnerFindings()"));
      expect(discoverEffectivenessRouteGraph(root, [implementation])).toEqual(live);
      expectRestoredBaseline();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("expands App Router into M1/M9 finding, disclosure, and not-assessed families", () => {
    const appRouter = producer(freshInventory(), "detector:app-router");
    expect(appRouter.modules).toEqual(["M1", "M9"]);
    expect(new Set(appRouter.findingFamilies.map((row) => row.module))).toEqual(new Set(["M1", "M9"]));
    expect(new Set(appRouter.findingFamilies.map((row) => row.kind))).toEqual(
      new Set(["finding", "coverage-disclosure", "not-assessed"]),
    );
  });

  it("reconciles #1948 producers without manufacturing scored venue coverage", () => {
    const inventory = freshInventory();
    const unscored = [
      "mechanical:structural-ast:m1-exception-flow",
      "mechanical:structural-ast:m5-exception-flow",
      "mechanical:structural-ast:m5-hardcoded-deployment",
      "mechanical:structural-ast:m5-polyglot-quality",
      "mechanical:structural-ast:m5-type-escape",
      "mechanical:structural-ast:m8-vacuous-assertion",
    ];
    for (const id of unscored) {
      expect(producer(inventory, id)).toMatchObject({
        populationClass: "true-finding-producer",
        venueIds: [],
        exemptionId: expect.stringMatching(/^exemption:unscored:/),
      });
    }

    const m5Polyglot = producer(inventory, "mechanical:structural-ast:m5-polyglot-quality");
    expect(new Set(m5Polyglot.findingFamilies.map((row) => row.kind))).toEqual(
      new Set(["finding", "coverage-disclosure"]),
    );
    expect(new Set(producer(inventory, "mechanical:structural-ast:m5-hardcoded-deployment").findingFamilies.map((row) => row.kind))).toEqual(
      new Set(["finding", "not-assessed"]),
    );
    expect(producer(inventory, "mechanical:structural-ast:m6-polyglot-coverage")).toMatchObject({
      populationClass: "disclosure-only",
      venueIds: [],
      exemptionId: "exemption:not-a-producer:disclosure-only",
    });
  });

  it("does not infer hardcoded-tenant runtime liveness from scored-corpus registration", () => {
    const m1 = producer(freshInventory(), "mechanical:structural-ast:m1-hardcoded-tenant");
    expect(m1).toMatchObject({
      modules: ["M1"],
      populationClass: "true-finding-producer",
      venueIds: [],
    });
    expect(m1.exemptionId).toBeDefined();
    expect(m1.findingFamilies).toEqual([
      expect.objectContaining({
        module: "M1",
        kind: "finding",
        taxonomyPattern: "M1 — Hardcoded tenant identifier at client/request boundary",
      }),
    ]);
  });

  it("gives the current M2 true population one empirical no-cadence exemption", () => {
    const inventory = freshInventory();
    const expected = inventory.producers
      .filter((row) => row.populationClass === "true-finding-producer" && row.modules.includes("M2") && row.venueIds.length === 0)
      .map((row) => row.id)
      .sort();
    const exemption = inventory.exemptions.find((row) => row.id === "exemption:m2-live-score");
    expect(exemption).toMatchObject({
      kind: "empirical",
      provenance: "src/scored-gates.ts#validate-connected; tracked by #1491",
      cadence: "none",
    });
    expect(exemption?.applicableProducerIds).toEqual(expected);
    expect(expected).not.toHaveLength(0);
    for (const id of expected) expect(producer(inventory, id).exemptionId).toBe(exemption?.id);
  });

  it("keeps normalization and applyVerifyResults outside the true-producer denominator", () => {
    const inventory = freshInventory();
    const normalization = inventory.producers.filter((row) => row.id.startsWith("mechanical:normalization:"));
    expect(normalization).toHaveLength(1);
    expect(normalization.every((row) => row.populationClass === "synthesizer")).toBe(true);
    const applyOwner = inventory.producers.find((row) =>
      row.implementations.some((item) => item.symbol === "applyVerifyResults"));
    expect(applyOwner).toMatchObject({
      id: "synthesizer:m2-apply-verify-results",
      populationClass: "synthesizer",
    });
  });

  it("discovers a neutral-name producer through aliases and fails when its real call is deleted", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-effectiveness-discovery-"));
    try {
      mkdirSync(join(root, "src", "cli"), { recursive: true });
      writeFileSync(join(root, "package.json"), JSON.stringify({ scripts: { audit: "tsx src/cli/run-audit.ts" } }));
      writeFileSync(
        join(root, "src", "cli", "static-detect.ts"),
        'export { ordinary as aliased } from "../ghost.js";\n',
      );
      writeFileSync(
        join(root, "src", "ghost.ts"),
        'export interface Row { id: string; taxonomy: string; severity: string; location: string }\nexport function ordinary(): Row[] { return []; }\n',
      );
      const liveEntry = 'import { aliased as renamed } from "./static-detect.js";\nconst registry = { produce: renamed };\nconst apply = (callback: typeof renamed) => callback();\nexport const findings = apply(registry.produce);\n';
      writeFileSync(join(root, "src", "cli", "run-audit.ts"), liveEntry);
      const implementation = { producerId: "neutral", file: "src/ghost.ts", symbol: "ordinary", kind: "function" as const };
      const live = discoverEffectivenessRouteGraph(root, [implementation]);
      expect(live.routes.map((route) => route.producerId)).toContain("neutral");
      expect(live.unresolvedFindingDispatches).toEqual([]);

      const unregistered = discoverEffectivenessRouteGraph(root, []);
      expect(unregistered.unresolvedFindingDispatches.length).toBeGreaterThan(0);
      expect(unregistered.unresolvedFindingDispatches.every((problem) => problem.includes("finding-bearing call target"))).toBe(true);

      writeFileSync(join(root, "src", "cli", "run-audit.ts"), 'import { aliased as renamed } from "./static-detect.js";\nexport const retainedText = "ordinary";\nvoid renamed;\n');
      const deleted = discoverEffectivenessRouteGraph(root, [implementation]);
      expect(deleted.routes).toEqual([]);
      writeFileSync(join(root, "src", "cli", "run-audit.ts"), liveEntry);
      expect(discoverEffectivenessRouteGraph(root, [implementation])).toEqual(live);
      expectRestoredBaseline();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("fails a deleted scored venue and passes when it is restored", () => {
    const baseline = freshInventory();
    const planted: EffectivenessInventory = {
      ...baseline,
      venues: baseline.venues.filter((row) => row.id !== "validate-calibration"),
    };
    expect(validateEffectivenessInventory(planted).some((problem) =>
      problem.includes("scored venue validate-calibration no longer exists"))).toBe(true);
    expectRestoredBaseline();
  });

  it("fails a module-mismatched venue and passes when it is restored", () => {
    const baseline = freshInventory();
    const planted: EffectivenessInventory = {
      ...baseline,
      venues: baseline.venues.map((row) => row.id === "validate-precision"
        ? { ...row, modules: ["M2"] as const }
        : row),
    };
    expect(validateEffectivenessInventory(planted)).toContain(
      "validate-precision: module claims do not match the live venue population",
    );
    expectRestoredBaseline();
  });

  it("fails a duplicate producer id and passes when the duplicate is removed", () => {
    const baseline = freshInventory();
    const duplicate = producer(baseline, "detector:app-router");
    const planted: EffectivenessInventory = {
      ...baseline,
      producers: [...baseline.producers, duplicate],
    };
    expect(validateEffectivenessInventory(planted)).toContain("detector:app-router: duplicate producer id");
    expectRestoredBaseline();
  });

  it("does not treat a renamed implementation declaration as runtime evidence", () => {
    const baseline = freshInventory();
    const id = "detector:app-router";
    const planted = withProducer(baseline, id, (row) => ({
      ...row,
      implementations: row.implementations.map((item, index) => index === 0
        ? { ...item, symbol: "removedAppRouterProducer" }
        : item),
    }));
    expect(validateEffectivenessInventory(planted).some((problem) => problem.includes("removedAppRouterProducer") && problem.includes("live route"))).toBe(false);
    expect(producer(planted, id).executionReceiptIds).toEqual([]);
    expectRestoredBaseline();
  });

  it("fails a deleted semantic route receipt and passes when it is restored", () => {
    const baseline = freshInventory();
    const id = "detector:app-router";
    const planted = withProducer(baseline, id, (row) => ({
      ...row,
      routeIds: row.routeIds.slice(1),
    }));
    expect(validateEffectivenessInventory(planted)).toContain(
      `${id}: producer route ids do not close on the semantic route graph`,
    );
    expectRestoredBaseline();
  });

  it("fails a stale exemption after a real venue is assigned and passes when restored", () => {
    const baseline = freshInventory();
    const id = "detector:hook-deps";
    expect(producer(baseline, id)).toMatchObject({ venueIds: [], exemptionId: expect.any(String) });
    const planted = withProducer(baseline, id, (row) => ({
      ...row,
      venueIds: ["validate-precision"],
      findingFamilies: row.findingFamilies.map((family, index) => index === 0
        ? { ...family, venueIds: ["validate-precision"] }
        : family),
    }));
    const family = producer(baseline, id).findingFamilies[0]!;
    expect(validateEffectivenessInventory(planted)).toContain(
      `${family.id}: stale exemption ${family.exemptionId} remains after a scored venue was assigned`,
    );
    expectRestoredBaseline();
  });

  it("fails scored-family and exemption pair loss in either receipt direction", () => {
    const baseline = freshInventory();
    const venue = baseline.venues.find((row) => row.coveredFamilyIds.length > 0)!;
    const scoredFamily = venue.coveredFamilyIds[0]!;
    const missingVenuePair: EffectivenessInventory = {
      ...baseline,
      venues: baseline.venues.map((row) => row.id === venue.id
        ? { ...row, coveredFamilyIds: row.coveredFamilyIds.slice(1) }
        : row),
    };
    expect(validateEffectivenessInventory(missingVenuePair)).toContain("scored family/venue pair sets do not conserve exactly");

    const exemption = baseline.exemptions.find((row) => row.applicableFamilyIds.length > 0)!;
    const exemptFamily = exemption.applicableFamilyIds[0]!;
    const missingExemptionPair: EffectivenessInventory = {
      ...baseline,
      exemptions: baseline.exemptions.map((row) => row.id === exemption.id
        ? { ...row, applicableFamilyIds: row.applicableFamilyIds.filter((id) => id !== exemptFamily) }
        : row),
    };
    expect(validateEffectivenessInventory(missingExemptionPair)).toContain("exempt family pair sets do not conserve exactly");
    expect(scoredFamily).not.toBe(exemptFamily);
    expectRestoredBaseline();
  });

  it("fails an incomplete structured exemption and passes when restored", () => {
    const baseline = freshInventory();
    const id = "exemption:m2-live-score";
    const planted: EffectivenessInventory = {
      ...baseline,
      exemptions: baseline.exemptions.map((row) => row.id === id ? { ...row, owner: "" } : row),
    };
    expect(validateEffectivenessInventory(planted)).toContain(`${id}: exemption metadata is incomplete`);
    expectRestoredBaseline();
  });

  it("fails a wrongly classified synthesizer and passes when it is restored", () => {
    const baseline = freshInventory();
    const id = "synthesizer:m2-apply-verify-results";
    const planted = withProducer(baseline, id, (row) => ({
      ...row,
      populationClass: "true-finding-producer",
    }));
    expect(validateEffectivenessInventory(planted)).toContain(
      `${id}: synthesizer implementation is wrongly classified as true-finding-producer`,
    );
    expectRestoredBaseline();
  });
});
