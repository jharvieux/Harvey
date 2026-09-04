import { spawn, type ChildProcessByStdio } from "node:child_process";
import { createHash } from "node:crypto";
import type { Readable } from "node:stream";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  serializeEffectivenessInventory,
  validateEffectivenessDelivery,
} from "./effectiveness-registry.js";
import { REQUIRED_RUNTIME_EDGE, type EffectivenessInventory } from "./effectiveness-schema.js";
import { HEAVY_CLI_TESTS } from "./heavy-cli-tests.js";
import { createProducerExecutionReceipt, extendProducerExecutionReceipt } from "./producer-execution-receipt.js";

const REPO_ROOT = new URL("..", import.meta.url).pathname;
// Includes static-detect path-scope delivery (#1800), lock-range routes/corpus (#1774), and the
// audited 35-row semantic corpus identity (#1947).
const EXPECTED_INVENTORY_SHA = "f5f745f8f2ee20207fc08dae387dfde6eb4ef7388ea7d2ae832068959e162332";
const CENSUS_SLICE_MS = 10_000;
const CENSUS_SLICE_COUNT = 8;

type CensusRun = {
  child: ChildProcessByStdio<null, Readable, Readable>;
  close: Promise<void>;
  closed: boolean;
  code: number | null | undefined;
  signal: NodeJS.Signals | null | undefined;
  error: Error | undefined;
  stdout: string;
  stderr: string;
};

function startDetectorCensus(): CensusRun {
  const child = spawn("node", ["--import", "tsx", "src/cli/detector-census.ts", "--effectiveness-json"], {
    cwd: REPO_ROOT,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let resolveClose!: () => void;
  const run: CensusRun = {
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

async function waitForClose(run: CensusRun, ms: number): Promise<boolean> {
  if (run.closed) return true;
  await Promise.race([run.close, delay(ms)]);
  return run.closed;
}

async function terminateAndReap(run: CensusRun): Promise<void> {
  if (run.closed) return;
  run.child.kill("SIGTERM");
  if (await waitForClose(run, 2_000)) return;
  run.child.kill("SIGKILL");
  if (!(await waitForClose(run, 5_000))) {
    throw new Error(`failed to reap child process ${run.child.pid ?? "without-pid"}`);
  }
}

async function waitForCensusSlice(run: CensusRun): Promise<void> {
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

let censusRun: CensusRun | undefined;
let censusInventory: EffectivenessInventory | undefined;

beforeAll(() => { censusRun = startDetectorCensus(); });
afterEach(() => new Promise<void>((resolve) => setImmediate(resolve)));
afterAll(async () => {
  if (censusRun !== undefined) await terminateAndReap(censusRun);
});

function deliveredFixture(): { inventory: EffectivenessInventory; observation: { findingId: string; producerId: string; familyId: string; venueId: string } } {
  if (censusInventory === undefined) throw new Error("default detector-census did not produce the shared delivery fixture");
  const base = JSON.parse(JSON.stringify(censusInventory)) as EffectivenessInventory;
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

  it.each(Array.from({ length: CENSUS_SLICE_COUNT }, (_, index) => index + 1))(
    "yields while awaiting the one default census child (slice %i)",
    async () => { await waitForCensusSlice(censusRun!); },
  );

  it("preserves the exact default schema-v3 inventory bytes", async () => {
    if (censusRun === undefined) throw new Error("default detector-census child did not start");
    if (!censusRun.closed) {
      await terminateAndReap(censusRun);
      throw new Error(`default detector-census exceeded ${CENSUS_SLICE_COUNT} bounded wait slices`);
    }
    await waitForCensusSlice(censusRun);
    const output = censusRun.stdout;
    const canonical = serializeEffectivenessInventory(JSON.parse(output) as EffectivenessInventory);
    expect(output).toBe(`${canonical}\n`);
    expect(createHash("sha256").update(output).digest("hex")).toBe(EXPECTED_INVENTORY_SHA);
    censusInventory = deepFreeze(JSON.parse(output) as EffectivenessInventory);
  });
});

describe("producer-specific client delivery", () => {
  beforeAll(() => {
    if (censusInventory === undefined) throw new Error("delivery inventory unavailable after default census failure");
  });
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
