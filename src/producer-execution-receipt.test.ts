import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  assertProducerExecutionReceipt,
  createProducerExecutionReceipt,
  extendProducerExecutionReceipt,
  receiptHasRoute,
  semgrepProducerExecutionReceipts,
} from "./producer-execution-receipt.js";

const runtime = () => createProducerExecutionReceipt({
  executionId: "run-1:dynamic.bola",
  producerId: "dynamic.bola",
  implementationId: "src/pentest/verify.ts#runVerify",
  module: "M2",
  tier: "dynamic",
  findingFamilyIds: ["M2-BOLA-*"],
  findingIds: ["M2-BOLA-1"],
  edges: [
    { kind: "registry-iteration", from: "registry:m2", to: "producer:dynamic.bola" },
    { kind: "callback", from: "producer:dynamic.bola", to: "finding:M2-BOLA-1" },
  ],
  evidence: { invoked: true },
});

const successfulSemgrep = () => {
  const argv = ["--x-parmap", "-j", "1"];
  const stable = (value: unknown): string => Array.isArray(value) ? `[${value.map(stable).join(",")}]` : value && typeof value === "object" ? `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(",")}}` : JSON.stringify(value);
  const semantic = { argv, loadedRuleIds: ["fixture-rule"], resultCount: 0, resultsSha256: "a".repeat(64), scanned: ["<SEMGREP_TARGET_ROOT>/a.ts"], skipped: [], skippedRules: [], errors: [], loadedTaintRuleIds: [], taintCoverage: "no-timeout-observed" as const };
  const family = { ordinal: 0, id: "fixture", familyId: "fixture", sourceKind: "local-config" as const, sourceId: "fixture.yml", sourceConfigSha256: "b".repeat(64), configSha256: "b".repeat(64), ruleIds: ["fixture-rule"], ownedRuleIds: ["fixture-rule"], ownedTaintRuleIds: [], loadedRuleIds: ["fixture-rule"], loadedTaintRuleIds: [], taintCoverage: "no-timeout-observed" as const, excludedRuleIds: [], argv, topology: "single-command-v1" as const, mergeAlgorithm: "single-command-v1" as const, partitions: [], verification: "single" as const, status: "succeeded" as const, attempts: [{ status: "succeeded" as const, attempt: 1, ...semantic, semanticSha256: createHash("sha256").update(stable(semantic)).digest("hex") }] };
  const ownership = [{ ordinal: 0, id: "fixture", sourceKind: "local-config", sourceId: "fixture.yml", sourceConfigSha256: "b".repeat(64), configSha256: "b".repeat(64), ownedRuleIds: ["fixture-rule"], ownedTaintRuleIds: [], excludedRuleIds: [], semanticObjectSha256: undefined, selector: undefined, routingManifest: undefined, topology: "single-command-v1", mergeAlgorithm: "single-command-v1", partitions: [], verification: "single" }];
  return { schema: 8 as const, timeoutPolicy: "fixpoint-family-not-assessed-v1" as const, status: "succeeded" as const, strategy: "globally-owned-partitioned-families" as const, ownershipSha256: createHash("sha256").update(stable(ownership)).digest("hex"), families: [family] };
};

describe("ProducerExecutionReceipt", () => {
  it("is deterministic and preserves producer-specific ordered multiplicity", () => {
    expect(runtime()).toEqual(runtime());
    expect(runtime().findingIds).toEqual(["M2-BOLA-1"]);
    expect(receiptHasRoute(runtime(), ["registry-iteration", "callback"])).toBe(true);
  });

  it("rejects reordered and tampered receipts", () => {
    const receipt = runtime();
    expect(() => assertProducerExecutionReceipt({ ...receipt, edges: [...receipt.edges].reverse() })).toThrow(/ordering|route|digest/);
    expect(() => assertProducerExecutionReceipt({ ...receipt, producerId: "forged" })).toThrow(/digest/);
  });

  it("requires a contiguous path when appending a consumer edge", () => {
    expect(() => extendProducerExecutionReceipt(runtime(), { kind: "client-delivery", from: "unrelated", to: "client" })).toThrow(/cannot continue/);
    expect(extendProducerExecutionReceipt(runtime(), { kind: "artifact-produce", from: "finding:M2-BOLA-1", to: "artifact:M2" }).edges.at(-1)?.kind).toBe("artifact-produce");
  });

  it("rejects a planned Semgrep receipt before adapting any producers", () => {
    expect(() => semgrepProducerExecutionReceipts({ schema: 8, strategy: "globally-owned-partitioned-families", families: [] })).toThrow(/successful Semgrep/);
  });

  it("adapts only an exact schema-8 successful Semgrep family receipt", () => {
    const receipt = successfulSemgrep();
    expect(semgrepProducerExecutionReceipts(receipt)).toMatchObject([{ producerId: "semgrep:local:fixture-rule", findingFamilyIds: ["fixture-rule"] }]);
    expect(() => semgrepProducerExecutionReceipts({ ...receipt, ownershipSha256: "0".repeat(64) })).toThrow(/ownership digest/);
    expect(() => semgrepProducerExecutionReceipts({ ...receipt, status: "failed" })).toThrow(/successful Semgrep/);
  });
});
