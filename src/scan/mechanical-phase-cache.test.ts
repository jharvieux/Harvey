import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "../findings.js";
import {
  CACHEABLE_MECHANICAL_PHASES,
  assertMechanicalCacheVerification,
  createMechanicalProducerRecord,
  executeMechanicalPhase,
  MECHANICAL_PHASES,
  mechanicalExaminedUnitDigest,
  mechanicalPhasePayloadDigest,
  resolveGitTree,
  targetPathExaminedUnits,
  type MechanicalPhase,
  type MechanicalPhaseCacheOptions,
  type MechanicalPhaseRecord,
  type MechanicalExaminedUnitIdentity,
  type MechanicalProducerNotAssessed,
  type MechanicalProducerRecord,
} from "./mechanical-phase-cache.js";
import { semgrepDiagnosticEvidence } from "./semgrep-family-cache.js";

const semanticExecution = () => {
  const argv = ["--x-parmap", "-j", "9"];
  const semantic = { argv, loadedRuleIds: ["fixture-rule"], resultCount: 0, resultsSha256: "a".repeat(64), scanned: ["<SEMGREP_TARGET_ROOT>/a.ts"], skipped: [], skippedRules: [], errors: [], fixpointTimeouts: [] };
  const stable = (value: unknown): string => Array.isArray(value) ? `[${value.map(stable).join(",")}]` : value && typeof value === "object" ? `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(",")}}` : JSON.stringify(value);
  const family = { ordinal: 0, id: "fixture", familyId: "fixture", sourceKind: "local-config" as const, sourceId: "fixture.yml", sourceConfigSha256: "b".repeat(64), configSha256: "b".repeat(64), ruleIds: ["fixture-rule"], ownedRuleIds: ["fixture-rule"], loadedRuleIds: ["fixture-rule"], excludedRuleIds: [], argv, topology: "single-command-v1" as const, mergeAlgorithm: "single-command-v1" as const, partitions: [], verification: "single" as const, status: "succeeded" as const, attempts: [{ status: "succeeded" as const, attempt: 1, ...semantic, semanticSha256: createHash("sha256").update(stable(semantic)).digest("hex") }] };
  const ownership = [{ ordinal: 0, id: "fixture", sourceKind: "local-config", sourceId: "fixture.yml", sourceConfigSha256: "b".repeat(64), configSha256: "b".repeat(64), ownedRuleIds: ["fixture-rule"], excludedRuleIds: [], semanticObjectSha256: undefined, topology: "single-command-v1", mergeAlgorithm: "single-command-v1", partitions: [], verification: "single" }];
  return { schema: 5 as const, status: "succeeded" as const, strategy: "globally-owned-partitioned-families" as const, ownershipSha256: createHash("sha256").update(stable(ownership)).digest("hex"), families: [family] };
};

const finding = (id: string): Finding => ({
  id,
  title: id,
  severity: "Low",
  confidence: "Likely",
  category: "test",
  taxonomy: "M1 — test",
  location: "fixture.ts:1",
  status: "Open",
  evidence: "fixture evidence",
  impact: "fixture impact",
  fix: "fixture fix",
  value: 1,
  ease: 1,
  safety: 1,
});

interface MutableReceiptArtifact {
  findings: Finding[];
  scope: { unitsExamined: number; description: string };
  producers: (Partial<MechanicalProducerRecord> & {
    unitsExamined: number;
    examinedUnitIdentities?: MechanicalExaminedUnitIdentity[];
  })[];
  payloadDigest: string;
}

describe("content-addressed mechanical phase cache (#1864)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  const options = (overrides: Partial<MechanicalPhaseCacheOptions> = {}): MechanicalPhaseCacheOptions => {
    const dir = overrides.dir ?? mkdtempSync(join(tmpdir(), "harvey-phase-cache-"));
    if (!overrides.dir) dirs.push(dir);
    const implementations = Object.fromEntries(MECHANICAL_PHASES.map((phase) => [phase, `implementation:${phase}`])) as Record<MechanicalPhase, string>;
    const externalInputs = Object.fromEntries(MECHANICAL_PHASES.map((phase) => [phase, { runtime: "fixture-v1" }])) as unknown as Record<MechanicalPhase, Record<string, string>>;
    return {
      dir,
      mode: "read-write",
      targetRevision: "commit-a",
      targetTree: "tree-a",
      implementation: implementations,
      externalInputs,
      ...overrides,
    };
  };

  const run = (phase: MechanicalPhase, cache: MechanicalPhaseCacheOptions, id: string = phase) =>
    executeMechanicalPhase(phase, cache, () => ({ findings: [finding(id)], scope: { unitsExamined: 1_000, description: "faithful large source fixture" }, ...(phase === "semgrep" ? { evidence: { semgrepDiagnostics: semgrepDiagnosticEvidence({ errors: [], paths: { scanned: [], skipped: [] }, time: { rules: [], fixpoint_timeouts: [] } }, tmpdir()), semgrepExecution: semanticExecution() } } : {}) }));

  const producerValue = (paths: readonly string[] = ["src/a.ts", "src/b.ts", "src/c.ts"]) => {
    const examinedUnitIdentities = targetPathExaminedUnits("owned-producer", paths);
    return {
      findings: [finding("owned-finding")],
      scope: { unitsExamined: paths.length, description: "exact producer-selected source population" },
      producers: [createMechanicalProducerRecord({ detector: "owned-producer", phase: "structural-ast", order: 10, module: "M1", examinedUnitIdentities, findings: 1, durationMs: 12.5, status: "ran" })],
    };
  };

  const notAssessedReceipt = (): MechanicalProducerNotAssessed => ({
    reason: "No source admitted by the exact JavaScript/TypeScript selector was examined.",
    provenance: "Broad inventory fixture plus exact JavaScript/TypeScript selector fixture.",
    falsifier: "Add an admitted JavaScript/TypeScript source and rerun the fixture.",
    inventory: {
      broadUnits: 2,
      selectedUnits: 0,
      pathSetDigest: "b".repeat(64),
      scope: "two tracked product-source paths before the exact selector",
    },
  });

  const notAssessedValue = () => ({
    findings: [finding("M5-HARDCODED-SOURCE-COVERAGE-00")],
    scope: { unitsExamined: 2, description: "broad source inventory retained by the structural phase" },
    producers: [createMechanicalProducerRecord({
      detector: "m5-hardcoded-deployment",
      phase: "structural-ast",
      order: 350,
      module: "M5",
      examinedUnitIdentities: [],
      findings: 1,
      durationMs: 4.25,
      status: "not-assessed",
      notAssessed: notAssessedReceipt(),
    })],
  });

  it("returns byte-equivalent normalized findings and examined scope on a real cold then warm large-fixture path", async () => {
    const cache = options();
    const cold = await run("structural-ast", cache);
    const execute = vi.fn(() => ({ findings: [finding("must-not-run")], scope: { unitsExamined: 1, description: "wrong" } }));
    const warm = await executeMechanicalPhase("structural-ast", cache, execute);
    expect(cold.cache).toBe("miss");
    expect(warm.cache).toBe("hit");
    expect(execute).not.toHaveBeenCalled();
    expect({ findings: warm.findings, scope: warm.scope }).toEqual({ findings: cold.findings, scope: cold.scope });
  });

  it("conserves complete same-path Semgrep diagnostics through phase store and reread", async () => {
    const cache = options();
    const errors = [
      { path: "<SEMGREP_TARGET_ROOT>/src/broken.ts", type: ["PartialParsing", [{ line: 42 }]], message: "first" },
      { path: "<SEMGREP_TARGET_ROOT>/src/broken.ts", type: ["PartialParsing", [{ line: 47 }]], message: "second" },
    ];
    const fixpointTimeouts = [
      { path: "<SEMGREP_TARGET_ROOT>/src/broken.ts", ruleId: "harvey-first", fingerprint: "first" },
      { path: "<SEMGREP_TARGET_ROOT>/src/broken.ts", ruleId: "harvey-second", fingerprint: "second" },
    ];
    const value = {
      findings: [finding("SEM-ERR-00")],
      scope: { unitsExamined: 1, description: "one Semgrep target" },
      evidence: { semgrepDiagnostics: semgrepDiagnosticEvidence({ errors, paths: { scanned: [], skipped: [] }, time: { rules: [], fixpoint_timeouts: fixpointTimeouts } }, tmpdir()), semgrepExecution: semanticExecution() },
    };
    const withoutTimeouts = {
      ...value,
      evidence: { semgrepDiagnostics: semgrepDiagnosticEvidence({ errors, paths: { scanned: [], skipped: [] }, time: { rules: [], fixpoint_timeouts: [] } }, tmpdir()), semgrepExecution: semanticExecution() },
    };
    expect(mechanicalPhasePayloadDigest(value)).not.toBe(mechanicalPhasePayloadDigest(withoutTimeouts));
    const cold = await executeMechanicalPhase("semgrep", cache, () => value);
    const warm = await executeMechanicalPhase("semgrep", cache, () => ({ ...value, findings: [finding("must-not-run")] }));
    expect(cold.evidence?.semgrepDiagnostics.errors).toEqual(errors);
    expect(cold.evidence?.semgrepDiagnostics.fixpointTimeouts).toEqual(fixpointTimeouts);
    expect(warm.cache).toBe("hit");
    expect(warm.evidence?.semgrepDiagnostics.errors).toEqual(errors);
    expect(warm.evidence?.semgrepDiagnostics.fixpointTimeouts).toEqual(fixpointTimeouts);
  });

  it("persists the producer census deterministically and restores cache-hit status", async () => {
    const cache = options();
    const examinedUnitIdentities = targetPathExaminedUnits("owned-producer", Array.from({ length: 1_000 }, (_, index) => `src/unit-${index}.ts`));
    const value = {
      findings: [finding("owned-finding")],
      scope: { unitsExamined: 1_000, description: "faithful large source fixture" },
      producers: [createMechanicalProducerRecord({ detector: "owned-producer", phase: "structural-ast", order: 10, module: "M1", examinedUnitIdentities, findings: 1, durationMs: 12.5, status: "ran" })],
    };
    const cold = await executeMechanicalPhase("structural-ast", cache, () => value);
    const artifact = join(cache.dir, "structural-ast", `${cold.key}.json`);
    expect(JSON.parse(readFileSync(artifact, "utf8")).producers).toEqual([
      expect.objectContaining({ detector: "owned-producer", durationMs: 0, status: "ran", examinedUnitIdentities }),
    ]);

    const execute = vi.fn(() => value);
    const warm = await executeMechanicalPhase("structural-ast", cache, execute);
    expect(execute).not.toHaveBeenCalled();
    expect(warm.producers).toEqual([
      expect.objectContaining({ detector: "owned-producer", durationMs: 0, status: "cached", examinedUnitIdentities }),
    ]);
  });

  it("persists and restores a typed zero-unit NotAssessed receipt without laundering it into cached or not-applicable", async () => {
    const cache = options();
    const value = notAssessedValue();
    const cold = await executeMechanicalPhase("structural-ast", cache, () => value);
    const artifact = join(cache.dir, "structural-ast", `${cold.key}.json`);
    expect(JSON.parse(readFileSync(artifact, "utf8"))).toMatchObject({
      schema: 4,
      producers: [{
        detector: "m5-hardcoded-deployment",
        unitsExamined: 0,
        findings: 1,
        durationMs: 0,
        status: "not-assessed",
        notAssessed: notAssessedReceipt(),
      }],
    });

    const execute = vi.fn(() => notAssessedValue());
    const warm = await executeMechanicalPhase("structural-ast", cache, execute);
    expect(execute).not.toHaveBeenCalled();
    expect(warm.cache).toBe("hit");
    expect(warm.producers).toEqual([
      expect.objectContaining({
        detector: "m5-hardcoded-deployment",
        unitsExamined: 0,
        findings: 1,
        status: "not-assessed",
        notAssessed: notAssessedReceipt(),
      }),
    ]);
  });

  it("rejects checksum-valid cache artifacts that erase or corrupt the typed NotAssessed reason contract", async () => {
    const corruptions: readonly [string, (producer: Partial<MechanicalProducerRecord>) => void, RegExp][] = [
      ["missing", (producer) => { delete producer.notAssessed; }, /missing its typed reason receipt/],
      ["empty broad population", (producer) => { producer.notAssessed!.inventory.broadUnits = 0; }, /broad inventory must be non-empty/],
      ["selected work claimed", (producer) => { (producer.notAssessed!.inventory as { selectedUnits: number }).selectedUnits = 1; }, /selected inventory must be exactly zero/],
      ["local path instead of digest", (producer) => { producer.notAssessed!.inventory.pathSetDigest = "/private/tmp/checkout"; }, /path-set digest is malformed/],
    ];
    for (const [name, mutate, reason] of corruptions) {
      const events: string[] = [];
      const cache = options({ onEvent: (message) => events.push(message) });
      const cold = await executeMechanicalPhase("structural-ast", cache, notAssessedValue);
      const artifactPath = join(cache.dir, "structural-ast", `${cold.key}.json`);
      const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as MutableReceiptArtifact;
      mutate(artifact.producers[0]!);
      artifact.payloadDigest = mechanicalPhasePayloadDigest({
        findings: artifact.findings,
        scope: artifact.scope,
        producers: artifact.producers as MechanicalProducerRecord[],
      });
      writeFileSync(artifactPath, JSON.stringify(artifact));
      expect((await executeMechanicalPhase("structural-ast", cache, notAssessedValue)).cache, name).toBe("miss");
      expect(events.some((event) => reason.test(event)), name).toBe(true);
    }
  });

  it("rejects missing, duplicate, noncanonical, count-inconsistent, wrong-producer, and wrong-order cached receipts", async () => {
    const corruptions: readonly [string, (artifact: MutableReceiptArtifact) => void, RegExp][] = [
      ["missing", (artifact) => { delete artifact.producers[0]!.examinedUnitIdentities; }, /identities are missing/],
      ["duplicate", (artifact) => {
        artifact.producers[0]!.examinedUnitIdentities![1] = artifact.producers[0]!.examinedUnitIdentities![0]!;
        artifact.producers[0]!.examinedUnitDigest = mechanicalExaminedUnitDigest(artifact.producers[0]!.examinedUnitIdentities!);
      }, /duplicates an earlier unit/],
      ["noncanonical", (artifact) => {
        artifact.producers[0]!.examinedUnitIdentities![0]!.identity = "/private/tmp/checkout/src/a.ts";
        artifact.producers[0]!.examinedUnitDigest = mechanicalExaminedUnitDigest(artifact.producers[0]!.examinedUnitIdentities!);
      }, /not a canonical target-relative path/],
      ["count", (artifact) => { artifact.producers[0]!.unitsExamined += 1; }, /count differs/],
      ["producer", (artifact) => {
        artifact.producers[0]!.examinedUnitIdentities![0]!.producer = "another-producer";
        artifact.producers[0]!.examinedUnitDigest = mechanicalExaminedUnitDigest(artifact.producers[0]!.examinedUnitIdentities!);
      }, /wrong producer/],
      ["order", (artifact) => {
        const second = createMechanicalProducerRecord({ detector: "second-producer", phase: "structural-ast", order: 5, module: "M1", examinedUnitIdentities: [], findings: 0, durationMs: 0, status: "not-applicable" });
        artifact.producers.push(second);
      }, /out of sequence/],
    ];
    for (const [name, mutate, reason] of corruptions) {
      const events: string[] = [];
      const cache = options({ onEvent: (message) => events.push(message) });
      const value = producerValue();
      const cold = await executeMechanicalPhase("structural-ast", cache, () => value);
      const artifactPath = join(cache.dir, "structural-ast", `${cold.key}.json`);
      const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as MutableReceiptArtifact;
      mutate(artifact);
      if (artifact.producers.every((producer) => Array.isArray(producer.examinedUnitIdentities))) {
        artifact.payloadDigest = mechanicalPhasePayloadDigest({ findings: artifact.findings, scope: artifact.scope, producers: artifact.producers as MechanicalProducerRecord[] });
      }
      writeFileSync(artifactPath, JSON.stringify(artifact));
      expect((await executeMechanicalPhase("structural-ast", cache, () => value)).cache, name).toBe("miss");
      expect(events.some((event) => reason.test(event)), name).toBe(true);
    }
  });

  it("forced-cold comparison rejects same-count substitution and reordering even with self-consistent digests", async () => {
    for (const paths of [["src/a.ts", "src/replaced.ts", "src/c.ts"], ["src/b.ts", "src/a.ts", "src/c.ts"]]) {
      const cache = options();
      const authentic = producerValue();
      const cold = await executeMechanicalPhase("structural-ast", cache, () => authentic);
      const artifactPath = join(cache.dir, "structural-ast", `${cold.key}.json`);
      const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as MutableReceiptArtifact;
      artifact.producers = producerValue(paths).producers;
      artifact.payloadDigest = mechanicalPhasePayloadDigest({ findings: artifact.findings, scope: artifact.scope, producers: artifact.producers as MechanicalProducerRecord[] });
      writeFileSync(artifactPath, JSON.stringify(artifact));
      await expect(executeMechanicalPhase("structural-ast", { ...cache, mode: "verify" }, () => authentic)).rejects.toThrow("forced-cold result differs");
    }
  });

  it("rejects a corrupt artifact, recomputes it, and emits a visible reason", async () => {
    const events: string[] = [];
    const cache = options({ onEvent: (message) => events.push(message) });
    const cold = await run("semgrep", cache);
    const artifact = join(cache.dir, "semgrep", `${cold.key}.json`);
    writeFileSync(artifact, JSON.stringify({ schema: 1, phase: "semgrep", key: cold.key, findings: [] }));
    const recomputed = await run("semgrep", cache, "fresh");
    expect(recomputed.cache).toBe("miss");
    expect(recomputed.findings[0]?.id).toBe("fresh");
    expect(events.some((event) => event.includes("CACHE REJECT semgrep") && event.includes("recomputing"))).toBe(true);
    expect(JSON.parse(readFileSync(artifact, "utf8"))).toMatchObject({ targetRevision: "commit-a", targetTree: "tree-a" });
  });

  it("rejects a checksum-valid current-readiness Semgrep phase artifact with only legacy diagnostics", async () => {
    const events: string[] = [];
    const cache = options({ onEvent: (message) => events.push(message) });
    cache.semgrepFamilies = {
      dir: cache.dir, mode: cache.mode, targetRevision: cache.targetRevision, targetTree: cache.targetTree,
      implementation: "family-implementation", externalInputs: { runtime: "fixture" },
    };
    const cold = await run("semgrep", cache);
    const artifactPath = join(cache.dir, "semgrep", `${cold.key}.json`);
    const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as {
      findings: Finding[];
      scope: { unitsExamined: number; description: string };
      evidence: { semgrepDiagnostics: ReturnType<typeof semgrepDiagnosticEvidence>; semgrepExecution?: ReturnType<typeof semanticExecution> };
      payloadDigest: string;
    };
    delete artifact.evidence.semgrepExecution;
    artifact.payloadDigest = mechanicalPhasePayloadDigest({ findings: artifact.findings, scope: artifact.scope, evidence: artifact.evidence });
    writeFileSync(artifactPath, JSON.stringify(artifact));
    expect((await run("semgrep", cache, "fresh-after-legacy-receipt")).cache).toBe("miss");
    expect(events.some((event) => event.includes("successful Semgrep semantic execution receipt is missing"))).toBe(true);
  });

  it("rejects a well-shaped artifact whose finding payload was tampered with", async () => {
    const events: string[] = [];
    const cache = options({ onEvent: (message) => events.push(message) });
    const cold = await run("semgrep", cache);
    const artifact = join(cache.dir, "semgrep", `${cold.key}.json`);
    const parsed = JSON.parse(readFileSync(artifact, "utf8")) as { findings: { id: string }[] };
    parsed.findings[0]!.id = "tampered-but-well-shaped";
    writeFileSync(artifact, JSON.stringify(parsed));
    const recomputed = await run("semgrep", cache, "authentic");
    expect(recomputed.cache).toBe("miss");
    expect(recomputed.findings[0]?.id).toBe("authentic");
    expect(events.some((event) => event.includes("payload checksum mismatch"))).toBe(true);
  });

  it("rejects a checksum-valid finding missing required category and status fields", async () => {
    const events: string[] = [];
    const cache = options({ onEvent: (message) => events.push(message) });
    const cold = await run("semgrep", cache);
    const artifact = join(cache.dir, "semgrep", `${cold.key}.json`);
    const parsed = JSON.parse(readFileSync(artifact, "utf8")) as {
      findings: Record<string, unknown>[];
      scope: { unitsExamined: number; description: string };
      payloadDigest: string;
    };
    delete parsed.findings[0]!.category;
    delete parsed.findings[0]!.status;
    parsed.payloadDigest = mechanicalPhasePayloadDigest({ findings: parsed.findings as unknown as Finding[], scope: parsed.scope });
    writeFileSync(artifact, JSON.stringify(parsed));
    const recomputed = await run("semgrep", cache, "complete-finding");
    expect(recomputed.cache).toBe("miss");
    expect(recomputed.findings[0]?.id).toBe("complete-finding");
    expect(events.some((event) => event.includes("normalized Finding schema") && event.includes("category") && event.includes("status"))).toBe(true);
  });

  it("invalidates only Semgrep when its rules/implementation move", async () => {
    const cache = options();
    await run("semgrep", cache);
    await run("structural-ast", cache);
    const changed = options({ ...cache, implementation: { ...cache.implementation, semgrep: "rules-v2" } });
    expect((await run("semgrep", changed, "semgrep-v2")).cache).toBe("miss");
    expect((await run("structural-ast", changed)).cache).toBe("hit");
  });

  it("cannot reuse a stale artifact when another phase implementation changes", async () => {
    const cache = options();
    await run("structural-ast", cache);
    const changed = options({ ...cache, implementation: { ...cache.implementation, "structural-ast": "ast-v2" } });
    const result = await run("structural-ast", changed, "ast-v2");
    expect(result.cache).toBe("miss");
    expect(result.findings[0]?.id).toBe("ast-v2");
  });

  it("names the external identity component that moved instead of reporting an opaque miss", async () => {
    const events: string[] = [];
    const cache = options({ onEvent: (message) => events.push(message) });
    await run("configuration", cache);
    const changed = options({
      ...cache,
      externalInputs: { ...cache.externalInputs, configuration: { ...cache.externalInputs.configuration, node: "v24.19.0" } },
    });
    expect((await run("configuration", changed, "new-node")).cache).toBe("miss");
    expect(events).toContainEqual(expect.stringContaining("identity changed: externalInputs.node"));
  });

  it("invalidates every cacheable artifact when the pinned target tree changes", async () => {
    const cache = options();
    for (const phase of CACHEABLE_MECHANICAL_PHASES) await run(phase, cache);
    const changed = options({ ...cache, targetRevision: "commit-b", targetTree: "tree-b" });
    for (const phase of CACHEABLE_MECHANICAL_PHASES) {
      expect((await run(phase, changed, `${phase}-new-tree`)).cache).toBe("miss");
    }
  });

  it("never reuses live-provider-backed TruffleHog results", async () => {
    const cache = options();
    const execute = vi.fn(() => ({ findings: [finding("verified-secret")], scope: { unitsExamined: 1, description: "one source tree plus provider verification" } }));
    const first = await executeMechanicalPhase("secrets-history", cache, execute);
    const second = await executeMechanicalPhase("secrets-history", cache, execute);
    expect(first.cache).toBe("non-cacheable");
    expect(second.cache).toBe("non-cacheable");
    expect(first.reason).toContain("--only-verified");
    expect(first.reason).toContain("live provider state");
    expect(execute).toHaveBeenCalledTimes(2);
  });

  it("always reruns advisory/network work and names why it is non-cacheable", async () => {
    const cache = options();
    const execute = vi.fn(() => ({ findings: [finding("advisory")], scope: { unitsExamined: 1, description: "one lockfile" } }));
    const first = await executeMechanicalPhase("dependency-advisory", cache, execute);
    const second = await executeMechanicalPhase("dependency-advisory", cache, execute);
    expect(first.cache).toBe("non-cacheable");
    expect(second.cache).toBe("non-cacheable");
    expect(first.reason).toContain("no immutable response identity");
    expect(execute).toHaveBeenCalledTimes(2);
  });

  it("forced-cold mode re-earns a hit and fails if the result changes", async () => {
    const cache = options();
    await run("semgrep", cache);
    const verify = { ...cache, mode: "verify" as const };
    await expect(run("semgrep", verify, "changed-on-cold-run")).rejects.toThrow("forced-cold result differs");
    expect((await run("semgrep", verify)).cache).toBe("recomputed");
  });

  it("forced-cold verification fails loud when every deterministic phase is a new miss", async () => {
    const verify = options({ mode: "verify" });
    const records: MechanicalPhaseRecord[] = [];
    for (const phase of CACHEABLE_MECHANICAL_PHASES) records.push(await run(phase, verify));
    expect(records.every((record) => record.cache === "miss")).toBe(true);
    expect(() => assertMechanicalCacheVerification(records, verify)).toThrow(
      "A miss may seed a later run, but this run compared no restored artifact",
    );
  });

  it("a miss executes the phase; it can never be represented as assessed-clean", async () => {
    const cache = options();
    const execute = vi.fn(() => ({ findings: [finding("found-on-miss")], scope: { unitsExamined: 7, description: "seven files" } }));
    const result = await executeMechanicalPhase("configuration", cache, execute);
    expect(result.cache).toBe("miss");
    expect(execute).toHaveBeenCalledOnce();
    expect(result.findings.map((row) => row.id)).toEqual(["found-on-miss"]);
    expect(result.scope.unitsExamined).toBe(7);
  });

  it("fails loud when a pinned corpus target has no git tree instead of hashing a mutable install tree", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-no-git-tree-"));
    dirs.push(dir);
    expect(() => resolveGitTree(dir)).toThrow("pinned corpus target has no resolvable git tree");
  });
});
