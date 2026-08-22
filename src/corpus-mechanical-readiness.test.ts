import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readRecursiveSafe } from "./fs-walk.js";
import type { Finding } from "./findings.js";
import {
  compareCurrentMechanicalExecutions,
  assertPreparedTargetUnchanged,
  buildCurrentMechanicalPhasePlan,
  CURRENT_MECHANICAL_POPULATION,
  CURRENT_MECHANICAL_PREPARATION,
  currentTargetPinsSha256,
  currentHarnessReceipt,
  mergeCurrentMechanicalShards,
  prepareCurrentMechanicalTarget,
  type CurrentMechanicalExecutionArtifact,
} from "./corpus-mechanical-readiness.js";
import { digestParts, MECHANICAL_PHASES, mechanicalExaminedUnitDigest } from "./scan/mechanical-phase-cache.js";
import type { SemgrepCommandSemanticReceipt } from "./scan/semgrep-family-cache.js";
import { shardTargets } from "./scan/corpus-shards.js";
import { REGISTRY_PACKS, registryPackIdentity } from "./scan/semgrep.js";

const digest = "a".repeat(64);
const packBody = Buffer.from("x");
const packDigest = createHash("sha256").update(packBody).digest("hex");
const packAggregate = registryPackIdentity(REGISTRY_PACKS.map((pack) => ({ pack, body: packBody.toString("utf8") })));
const diagnosticDigest = createHash("sha256").update('{"errors":[],"fixpointTimeouts":[],"skipped":[]}').digest("hex");
const mixedRun = JSON.parse(readFileSync(new URL("./__fixtures__/current-mechanical-run-32334325227.json", import.meta.url), "utf8")) as {
  runId: number;
  commonRuntime: CurrentMechanicalExecutionArtifact["runtime"];
  producerShards: Array<{ index: number; gitVersion: string; targets: string[] }>;
  carbonCrossGit: {
    producer: { gitVersion: string; preparationSha256: string; executionPlanSha256: string; findingsSha256: string; normalizedProducersSha256: string; semgrepDiagnosticsSha256: string; findingCount: number; semgrepFindingCount: number };
    replay: { gitVersion: string; preparationSha256: string; executionPlanSha256: string; findingsSha256: string; normalizedProducersSha256: string; semgrepDiagnosticsSha256: string; findingCount: number; semgrepFindingCount: number; uniqueFinding: string };
  };
};
const target = { slug: "target", repo: "https://example.invalid/target.git", commit: "b".repeat(40), vendoredSubtrees: ["vendor/reference"] };
const finding: Finding = { id: "ROW-1", title: "row", severity: "Low", confidence: "Likely", category: "test", taxonomy: "test", location: "a.ts:1", status: "Open", evidence: "evidence", impact: "impact", fix: "fix", value: 1, ease: 1, safety: 1, mechanical: true };

function stableFixture(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableFixture).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stableFixture(item)}`).join(",")}}`;
  return JSON.stringify(value);
}

function semgrepExecutionFixture() {
  const family = (input: { ordinal: number; id: string; sourceKind: "registry-pack" | "local-config"; sourceId: string; configSha256: string; ruleIds: string[]; argv: string[] }) => {
    const semantic = { argv: input.argv, loadedRuleIds: input.ruleIds, resultCount: 1, resultsSha256: digest, scanned: ["<SEMGREP_TARGET_ROOT>/a.ts"], skipped: [], skippedRules: [], errors: [], fixpointTimeouts: [] };
    const attempts = [{ status: "succeeded" as const, attempt: 1, ...semantic, semanticSha256: createHash("sha256").update(stableFixture(semantic)).digest("hex") }];
    return { ...input, familyId: input.id, sourceConfigSha256: input.configSha256, ownedRuleIds: input.ruleIds, loadedRuleIds: input.ruleIds, excludedRuleIds: [], semanticObjectSha256: undefined as string | undefined, topology: "single-command-v1" as const, mergeAlgorithm: "single-command-v1" as const, partitions: [], verification: "single" as const, status: "succeeded" as const, attempts };
  };
  const injectionRuleIds = ["harvey-log-injection", ...Array.from({ length: 29 }, (_, index) => `harvey-injection-${index}`)].sort();
  const partitions = [
    { ordinal: 0, id: "log" as const, configSha256: "c".repeat(64), ownedRuleIds: ["harvey-log-injection"], argv: ["--x-parmap", "-j", "1", "--config", "log", "--timeout", "0"] },
    { ordinal: 1, id: "complement" as const, configSha256: "d".repeat(64), ownedRuleIds: injectionRuleIds.filter((id) => id !== "harvey-log-injection"), argv: ["--x-parmap", "-j", "1", "--config", "complement", "--timeout", "0"] },
  ];
  const injectionAttempts = [1, 2].map((attempt) => {
    const components = partitions.map((partition) => {
      const semantic = { argv: partition.argv, loadedRuleIds: partition.ownedRuleIds, resultCount: 1, resultsSha256: digest, scanned: ["<SEMGREP_TARGET_ROOT>/a.ts"], skipped: [], skippedRules: [], errors: [], fixpointTimeouts: [] };
      return { status: "succeeded" as const, ordinal: partition.ordinal, id: partition.id, configSha256: partition.configSha256, ownedRuleIds: partition.ownedRuleIds, ...semantic, semanticSha256: createHash("sha256").update(stableFixture(semantic)).digest("hex") };
    });
    const semantic = { argv: ["<SEMGREP_PARTITION_SEQUENCE:log,complement>", "<SEMGREP_MERGE:canonical-semgrep-family-output-v1>"], loadedRuleIds: injectionRuleIds, resultCount: 1, resultsSha256: digest, scanned: ["<SEMGREP_TARGET_ROOT>/a.ts"], skipped: [], skippedRules: [], errors: [], fixpointTimeouts: [], components };
    return { status: "succeeded" as const, attempt, ...semantic, semanticSha256: createHash("sha256").update(stableFixture(semantic)).digest("hex") };
  });
  const injection = { ordinal: 1, id: "local-injection", familyId: "local-injection", sourceKind: "local-config" as const, sourceId: "injection.yml", sourceConfigSha256: "b".repeat(64), configSha256: "b".repeat(64), ruleIds: injectionRuleIds, ownedRuleIds: injectionRuleIds, loadedRuleIds: injectionRuleIds, excludedRuleIds: [], semanticObjectSha256: undefined as string | undefined, argv: ["<SEMGREP_PARTITION_SEQUENCE:log,complement>", "<SEMGREP_MERGE:canonical-semgrep-family-output-v1>"], topology: "whole-root-rule-partition-v1" as const, mergeAlgorithm: "canonical-semgrep-family-output-v1" as const, partitions, verification: "paired-topology-exact" as const, status: "succeeded" as const, attempts: injectionAttempts };
  const families = [
    family({ ordinal: 0, id: "registry-0", sourceKind: "registry-pack", sourceId: "p/typescript", configSha256: digest, ruleIds: ["registry-rule"], argv: ["--x-parmap", "-j", "9", "--timeout", "0"] }),
    injection,
  ];
  const ownership = families.map(({ ordinal, id, sourceKind, sourceId, sourceConfigSha256, configSha256, ownedRuleIds, excludedRuleIds, semanticObjectSha256, topology, mergeAlgorithm, partitions, verification }) => ({ ordinal, id, sourceKind, sourceId, sourceConfigSha256, configSha256, ownedRuleIds, excludedRuleIds, semanticObjectSha256, topology, mergeAlgorithm, partitions, verification }));
  return { schema: 5 as const, status: "succeeded" as const, strategy: "globally-owned-partitioned-families" as const, ownershipSha256: createHash("sha256").update(stableFixture(ownership)).digest("hex"), families };
}

function artifact(side: CurrentMechanicalExecutionArtifact["side"]): CurrentMechanicalExecutionArtifact {
  return {
    schema: 3,
    kind: "current-mechanical-execution",
    population: CURRENT_MECHANICAL_POPULATION,
    side,
    executionId: `${side}:1/1:fixture`,
    headCommit: "c".repeat(40),
    harnessSha256: digest,
    commands: [side === "hosted-producer" ? "pnpm corpus-drift" : "pnpm replay:current-mechanical"],
    options: { skipNetworkChecks: true, skipBundleScan: true, advisoryMode: "snapshot", phaseCache: side === "hosted-producer" ? "hosted-content-addressed" : "off", bundleDir: null, handrolledIndicators: false, authGuards: [] },
    targetPinsSha256: currentTargetPinsSha256([target]),
    allTargets: [target],
    semgrepRegistry: { schema: 1, aggregateSha256: packAggregate, files: Array.from({ length: 6 }, (_, ordinal) => ({ ordinal, name: `${ordinal}-${REGISTRY_PACKS[ordinal]!.replaceAll("/", "-")}.yml`, bytes: 1, sha256: packDigest, bodyBase64: packBody.toString("base64") })) },
    runtime: { node: "v24", platform: "linux", arch: "x64", semgrep: "1", gitleaks: "1" },
    shard: { index: 1, count: 1 },
    targets: {
      target: {
        slug: "target", repo: target.repo, pin: target.commit, checkoutHead: target.commit, checkoutTree: digest,
        preparedTreeSha256: digest, gitVersion: "git version 2.54.0", preparation: CURRENT_MECHANICAL_PREPARATION, removedVendoredSubtrees: ["vendor/reference"],
        emptyGitlinks: [{ path: "apps/web/app/(marketing)", object: "f".repeat(40), representation: "empty-directory" }],
        captureBeforeInstall: true, installMutationAtCapture: false, skipBundleScan: true,
        bundleDigest: digestParts(["bundle-pinned-off-v1"]),
        advisorySha256: digest, advisoryVersion: "osv-1", secretCandidateIdentity: digest,
        findings: [finding],
        producers: [{ detector: "producer", phase: "structural-ast", order: 1, module: "M1", unitsExamined: 1, examinedUnitIdentities: [{ producer: "producer", kind: "target-path", identity: "a.ts" }], examinedUnitDigest: mechanicalExaminedUnitDigest([{ producer: "producer", kind: "target-path", identity: "a.ts" }]), findings: 1, durationMs: 1, status: "ran" }],
        context: { filesPresent: 1 } as never,
        executionPlan: {
          schema: 1,
          phases: MECHANICAL_PHASES,
          implementation: { semgrep: digest },
          externalInputs: { semgrep: { semgrep: "1", node: "v24", options: "pinned" } },
          semgrep: semgrepExecutionFixture(),
        },
        cachePolicy: { schema: 1, mode: side === "hosted-producer" ? "hosted-content-addressed" : "independent-cold-off", namespaceSha256: side === "hosted-producer" ? "d".repeat(64) : "e".repeat(64), emptyNamespaceVerified: side === "independent-replay", producerArtifactsAllowed: side === "hosted-producer" },
        semgrepDiagnostics: { schema: 2, errors: [], skipped: [], fixpointTimeouts: [], sha256: diagnosticDigest },
      },
    },
  };
}

function expectDifference(mutate: (value: CurrentMechanicalExecutionArtifact) => void, message: RegExp): void {
  const producer = artifact("hosted-producer");
  const replay = structuredClone(artifact("independent-replay"));
  mutate(replay);
  expect(() => compareCurrentMechanicalExecutions(producer, replay)).toThrow(message);
}

function rehashAttempt(attempt: SemgrepCommandSemanticReceipt): void {
  const semantic = Object.fromEntries(Object.entries(attempt).filter(([key]) => !["status", "attempt", "semanticSha256"].includes(key)));
  attempt.semanticSha256 = createHash("sha256").update(stableFixture(semantic)).digest("hex");
}

describe("fresh current mechanical producer ↔ replay readiness", () => {
  it("requires schema 3 target-bound Git provenance and rejects legacy aggregate-only receipts", () => {
    const legacy = artifact("hosted-producer") as unknown as { schema: number; runtime: Record<string, string>; targets: Record<string, { gitVersion?: string }> };
    legacy.schema = 2;
    legacy.runtime.git = legacy.targets.target!.gitVersion!;
    delete legacy.targets.target!.gitVersion;
    expect(() => mergeCurrentMechanicalShards([legacy as unknown as CurrentMechanicalExecutionArtifact], "legacy producer")).toThrow(/not a current mechanical execution artifact/);

    const missing = artifact("hosted-producer");
    delete (missing.targets.target! as { gitVersion?: string }).gitVersion;
    expect(() => mergeCurrentMechanicalShards([missing], "missing provenance")).toThrow(/Git materialization provenance is missing/);
  });

  it("wires the required aggregate to shared bytes and two fresh sides without claiming historical proof", () => {
    const workflow = readFileSync(new URL("../.github/workflows/corpus-drift.yml", import.meta.url), "utf8");
    const producer = readFileSync(new URL("./cli/corpus-drift.ts", import.meta.url), "utf8");
    expect(workflow).toContain("prepare-current-inputs:");
    expect(workflow).toContain("name: current-mechanical-semgrep-pack");
    expect(workflow).toContain("HARVEY_SEMGREP_REGISTRY_SNAPSHOT_MODE: reuse");
    expect(workflow).toContain("current-replay:");
    expect(workflow).toContain("needs: [prepare-current-inputs, shard, current-replay]");
    expect(workflow).toContain("Current registry producer ↔ independent replay equivalence/readiness");
    expect(workflow).toContain("NOT #1851.6/.7 historical manual→registry proof");
    expect(workflow).not.toContain("Old orchestrator → registry");
    expect(workflow).not.toContain("validate:mechanical-corpus-parity");
    expect(producer).toContain("const scanDir = prepared!.scanDir");
    expect(producer.match(/scriptArgs: \[scanDir(?:, "--detect-only")?\]/g)).toHaveLength(3);
    expect(producer).toContain("installTargetDeps(scanDir, target.m8?.installFlags ?? [], {");
    expect(producer).toContain("targetTree: targetTreeIdentity");
    expect(producer).toContain("dependencyPreparation }");
    expect(producer).toContain("runMutationScan(target.slug, scanDir, target.m8)");
    expect(producer).toContain("join(scanDir, m5Root)");
    expect(producer).toContain("join(scanDir, target.schemaPath)");
  });

  it("accepts two distinct exact-head executions and ignores duration/cache status only", () => {
    const producer = artifact("hosted-producer");
    const replay = artifact("independent-replay");
    replay.targets.target!.gitVersion = "git version 2.55.0";
    replay.targets.target!.producers[0]!.durationMs = 99;
    replay.targets.target!.producers[0]!.status = "cached";
    expect(() => compareCurrentMechanicalExecutions(producer, replay)).not.toThrow();
  });

  it("rejects same-count substitution, one-field mutation, reorder, add/remove, and duplicate", () => {
    expectDifference((value) => { value.targets.target!.findings[0] = { ...finding, id: "ROW-2", title: "ROW-2" }; }, /ordered raw mechanical finding/);
    expectDifference((value) => { value.targets.target!.findings[0]!.evidence = "one field changed"; }, /ordered raw mechanical finding/);
    expectDifference((value) => { value.targets.target!.findings.push({ ...finding, id: "ROW-2" }); value.targets.target!.findings.reverse(); }, /ordered raw mechanical finding/);
    expectDifference((value) => { value.targets.target!.findings.length = 0; }, /ordered raw mechanical finding/);
    expectDifference((value) => { value.targets.target!.findings.push(finding); }, /ordered raw mechanical finding/);
  });

  it("strictly compares the partition strategy, family order/membership, flags, and config bytes", () => {
    expectDifference((value) => { (value.targets.target!.executionPlan.semgrep as { schema: number }).schema = 4; }, /execution-plan|preparation/);
    expectDifference((value) => { (value.targets.target!.executionPlan.semgrep.families[1]! as unknown as { subpartitions: string[] }).subpartitions = ["invented-shard"]; }, /execution-plan|preparation/);
    expectDifference((value) => {
      const family = value.targets.target!.executionPlan.semgrep.families[0]!;
      value.targets.target!.executionPlan.semgrep.families = Array.from({ length: 22 }, (_, ordinal) => ({
        ...family,
        ordinal,
        id: `historical-subscan-${ordinal}`,
        familyId: `historical-subscan-${ordinal}`,
        sourceId: `historical-${ordinal}.yml`,
      }));
    }, /execution-plan|preparation/);
    expectDifference((value) => { value.targets.target!.executionPlan.semgrep.strategy = "monolithic" as "globally-owned-partitioned-families"; }, /execution-plan|preparation/);
    expectDifference((value) => { value.targets.target!.executionPlan.semgrep.families.reverse().forEach((family, ordinal) => { family.ordinal = ordinal; }); }, /execution-plan|preparation/);
    expectDifference((value) => { value.targets.target!.executionPlan.semgrep.families.pop(); }, /execution-plan|preparation/);
    expectDifference((value) => { value.targets.target!.executionPlan.semgrep.families[0]!.argv.push("--changed-flag"); }, /execution-plan|preparation/);
    expectDifference((value) => { value.targets.target!.executionPlan.semgrep.families[1]!.verification = "single"; }, /execution-plan|preparation/);
    expectDifference((value) => { value.targets.target!.executionPlan.semgrep.families[0]!.configSha256 = "c".repeat(64); }, /execution-plan|preparation/);
    expectDifference((value) => { value.targets.target!.executionPlan.semgrep.families[1]!.topology = "single-command-v1"; }, /topology|execution-plan|preparation/);
    expectDifference((value) => { value.targets.target!.executionPlan.semgrep.families[1]!.mergeAlgorithm = "single-command-v1"; }, /topology|execution-plan|preparation/);
    expectDifference((value) => { value.targets.target!.executionPlan.semgrep.families[1]!.partitions[0]!.argv.push("--mutated"); }, /component|execution-plan|preparation/);
    expectDifference((value) => { value.targets.target!.executionPlan.semgrep.families[1]!.partitions.pop(); }, /partition|execution-plan|preparation/);
    expectDifference((value) => { value.targets.target!.executionPlan.semgrep.families[1]!.partitions[1]!.ownedRuleIds.push("harvey-log-injection"); }, /partition|execution-plan|preparation/);
    expectDifference((value) => { value.targets.target!.executionPlan.semgrep.families[1]!.attempts[0]!.components![0]!.resultsSha256 = "e".repeat(64); }, /semantic|execution-plan|preparation/);
  });

  it("requires actual successful semantics rather than a planned, failed, or population-swapped receipt", () => {
    expectDifference((value) => {
      const receipt = value.targets.target!.executionPlan.semgrep as unknown as { status?: string; families: Array<{ status?: string; attempts?: unknown[] }> };
      delete receipt.status;
      receipt.families.forEach((family) => { delete family.status; delete family.attempts; });
    }, /successful|execution-plan/);
    expectDifference((value) => {
      const family = value.targets.target!.executionPlan.semgrep.families[0]!;
      family.loadedRuleIds = ["substituted-rule"];
      family.attempts[0]!.loadedRuleIds = ["substituted-rule"];
      rehashAttempt(family.attempts[0]!);
    }, /successful|population|execution-plan/);
    const producer = artifact("hosted-producer");
    const replay = artifact("independent-replay");
    producer.targets.target!.executionPlan.semgrep.families[0]!.status = "failed" as "succeeded";
    replay.targets.target!.executionPlan.semgrep.families[0]!.status = "failed" as "succeeded";
    expect(() => compareCurrentMechanicalExecutions(producer, replay)).toThrow(/successful|failed|execution-plan/);
  });

  it("strictly binds scanned, skipped-rule, result, and duplicate-error multiplicity in actual attempts", () => {
    expectDifference((value) => {
      const attempt = value.targets.target!.executionPlan.semgrep.families[0]!.attempts[0]!;
      attempt.scanned = ["<SEMGREP_TARGET_ROOT>/b.ts"];
      rehashAttempt(attempt);
    }, /execution-plan/);
    expectDifference((value) => {
      const attempt = value.targets.target!.executionPlan.semgrep.families[0]!.attempts[0]!;
      attempt.skippedRules = [{ ruleId: "registry-rule", reason: "not-applicable" }];
      rehashAttempt(attempt);
    }, /execution-plan/);
    expectDifference((value) => {
      const attempt = value.targets.target!.executionPlan.semgrep.families[0]!.attempts[0]!;
      attempt.resultsSha256 = "f".repeat(64);
      rehashAttempt(attempt);
    }, /execution-plan/);
    expectDifference((value) => {
      const attempt = value.targets.target!.executionPlan.semgrep.families[0]!.attempts[0]!;
      const duplicate = { path: "<SEMGREP_TARGET_ROOT>/a.ts", message: "same diagnostic twice" };
      attempt.errors = [duplicate, duplicate];
      rehashAttempt(attempt);
    }, /execution-plan/);
  });

  it("strictly compares complete ordered Semgrep errors, skipped paths, and fixpoint timeouts, not their counts", () => {
    const setDiagnostics = (value: CurrentMechanicalExecutionArtifact, errors: Array<{ path: string; message: string }>, skipped: Array<{ path: string; reason: string }>, fixpointTimeouts: Array<{ path: string; ruleId: string; fingerprint: string }> = []): void => {
      const payload = { errors, skipped, fixpointTimeouts };
      value.targets.target!.semgrepDiagnostics = { schema: 2, ...payload, sha256: createHash("sha256").update(stableFixture(payload)).digest("hex") };
    };
    expectDifference((value) => { setDiagnostics(value, [{ path: "<SEMGREP_TARGET_ROOT>/a.ts", message: "substituted" }], []); }, /ordered Semgrep/);
    expectDifference((value) => { setDiagnostics(value, [], [{ path: "<SEMGREP_TARGET_ROOT>/a.ts", reason: "too large" }]); }, /ordered Semgrep/);
    expectDifference((value) => { setDiagnostics(value, [], [], [{ path: "<SEMGREP_TARGET_ROOT>/a.ts", ruleId: "harvey-timeout", fingerprint: "one" }]); }, /ordered Semgrep/);
    const producer = artifact("hosted-producer");
    const replay = artifact("independent-replay");
    setDiagnostics(producer, [{ path: "a", message: "one" }, { path: "b", message: "two" }], []);
    setDiagnostics(replay, [{ path: "b", message: "two" }, { path: "a", message: "one" }], []);
    expect(() => compareCurrentMechanicalExecutions(producer, replay)).toThrow(/ordered Semgrep/);
  });

  it("rejects cache namespace cross-use, producer artifact permission, and gitlink receipt drift", () => {
    expectDifference((value) => { value.targets.target!.cachePolicy.namespaceSha256 = "d".repeat(64); }, /cache namespaces overlap/);
    expectDifference((value) => { value.targets.target!.cachePolicy.producerArtifactsAllowed = true; }, /cache policy\/namespace/);
    expectDifference((value) => { value.targets.target!.emptyGitlinks = []; }, /empty-gitlink/);
    expectDifference((value) => { value.targets.target!.emptyGitlinks[0]!.object = "e".repeat(40); }, /empty-gitlink/);
    expectDifference((value) => { value.targets.target!.emptyGitlinks[0]!.path = "apps/web/other"; }, /empty-gitlink/);
    expectDifference((value) => { value.targets.target!.emptyGitlinks[0]!.representation = "missing" as "empty-directory"; }, /empty-gitlink/);
  });

  it("refuses a replay namespace containing any prior artifact", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-current-replay-namespace-"));
    try {
      const cacheDir = join(root, "cache");
      mkdirSync(cacheDir);
      writeFileSync(join(cacheDir, "producer-artifact.json"), "{}\n");
      expect(() => buildCurrentMechanicalPhasePlan({
        side: "independent-replay", repoRoot: new URL("..", import.meta.url).pathname, cacheDir,
        targetRevision: target.commit, targetTree: digest, advisoryDigest: digest, advisoryVersion: "osv-1", secretCandidateIdentity: digest,
        registry: { identity: digest, files: [] },
      })).toThrow(/namespace is not empty/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("rejects examined-unit substitution/reorder and missing or duplicate producers", () => {
    expectDifference((value) => { value.targets.target!.producers[0]!.examinedUnitIdentities = [{ producer: "producer", kind: "target-path", identity: "b.ts" }]; value.targets.target!.producers[0]!.examinedUnitDigest = mechanicalExaminedUnitDigest(value.targets.target!.producers[0]!.examinedUnitIdentities); }, /exact examined-unit population/);
    expectDifference((value) => { value.targets.target!.producers[0]!.examinedUnitIdentities = [{ producer: "producer", kind: "semantic", identity: "b" }, { producer: "producer", kind: "semantic", identity: "a" }]; value.targets.target!.producers[0]!.unitsExamined = 2; value.targets.target!.producers[0]!.examinedUnitDigest = mechanicalExaminedUnitDigest(value.targets.target!.producers[0]!.examinedUnitIdentities); }, /exact examined-unit population/);
    expectDifference((value) => { value.targets.target!.producers.length = 0; }, /producer census is missing/);
    expectDifference((value) => { value.targets.target!.producers.push(structuredClone(value.targets.target!.producers[0]!)); }, /duplicate/);
  });

  it("rejects wrong head, pin, harness, missing target, changed Semgrep byte/tool, and self-comparison", () => {
    expectDifference((value) => { value.headCommit = "d".repeat(40); }, /different head/);
    expectDifference((value) => { value.harnessSha256 = "d".repeat(64); }, /different head/);
    expectDifference((value) => { value.allTargets[0]!.commit = "d".repeat(40); value.targetPinsSha256 = currentTargetPinsSha256(value.allTargets); value.targets.target!.pin = value.allTargets[0]!.commit; value.targets.target!.checkoutHead = value.allTargets[0]!.commit; }, /different head/);
    expectDifference((value) => { delete value.targets.target; }, /target population is empty/);
    expectDifference((value) => { value.semgrepRegistry.files[0]!.sha256 = "d".repeat(64); }, /bytes differ|different head/);
    expectDifference((value) => { value.runtime.semgrep = "changed"; }, /different head/);
    expectDifference((value) => { value.shard = { index: 1, count: 2 }; }, /different head/);
    const producer = artifact("hosted-producer");
    expect(() => compareCurrentMechanicalExecutions(producer, producer)).toThrow(/one real hosted producer/);
  });

  it("rejects dirty preparation: install-before-capture, retained vendored tree, or bundle-on", () => {
    expectDifference((value) => { value.targets.target!.captureBeforeInstall = false as true; }, /before install/);
    expectDifference((value) => { value.targets.target!.installMutationAtCapture = true as false; }, /before install/);
    expectDifference((value) => { value.targets.target!.removedVendoredSubtrees = []; }, /vendored-subtree/);
    expectDifference((value) => { value.targets.target!.skipBundleScan = false as true; }, /bundle input/);
  });

  it("rejects one-side, mixed, duplicate-index, and incomplete shard populations", () => {
    const left = artifact("hosted-producer");
    const second = structuredClone(left);
    left.shard = { index: 1, count: 2 };
    second.shard = { index: 1, count: 2 };
    second.executionId = "hosted-producer:1/2:second-fixture";
    expect(() => mergeCurrentMechanicalShards([left], "producer")).toThrow(/expected 2/);
    second.headCommit = "d".repeat(40);
    expect(() => mergeCurrentMechanicalShards([left, second], "producer")).toThrow(/mixed/);
    second.headCommit = left.headCommit;
    expect(() => mergeCurrentMechanicalShards([left, second], "producer")).toThrow(/index population/);
  });

  it("merges shards across hosted Git patch-level drift without weakening engine invariants", () => {
    const first = artifact("hosted-producer");
    const second = structuredClone(first);
    const otherTarget = { ...target, slug: "other", repo: "https://example.invalid/other.git", commit: "d".repeat(40) };
    const targetReceipts = {
      target: first.targets.target!,
      other: { ...structuredClone(first.targets.target!), slug: otherTarget.slug, repo: otherTarget.repo, pin: otherTarget.commit, checkoutHead: otherTarget.commit },
    };
    for (const [index, value] of [first, second].entries()) {
      value.allTargets = [target, otherTarget];
      value.targetPinsSha256 = currentTargetPinsSha256(value.allTargets);
      value.shard = { index: index + 1, count: 2 };
      value.executionId = `hosted-producer:${index + 1}/2:fixture`;
      value.targets = Object.fromEntries(
        shardTargets(value.allTargets.map((entry) => entry.slug), index + 1, 2)
          .map((slug) => [slug, targetReceipts[slug as keyof typeof targetReceipts]]),
      );
    }
    for (const receipt of Object.values(first.targets)) receipt.gitVersion = mixedRun.producerShards[0]!.gitVersion;
    for (const receipt of Object.values(second.targets)) receipt.gitVersion = mixedRun.producerShards[1]!.gitVersion;

    const merged = mergeCurrentMechanicalShards([first, second], "hosted receipts from run 32334325227");
    expect(Object.fromEntries(Object.entries(merged.targets).map(([slug, receipt]) => [slug, receipt.gitVersion]))).toEqual({
      other: "git version 2.54.0",
      target: "git version 2.55.0",
    });
    expect(Object.keys(merged.targets).sort()).toEqual(["other", "target"]);

    second.runtime.semgrep = "different-semgrep";
    expect(() => mergeCurrentMechanicalShards([first, second], "producer")).toThrow(/mixed engine\/input\/runtime/);
  });

  it("keeps exact mixed-run output drift fatal after accepting target-bound Git provenance", () => {
    const { producer: observedProducer, replay: observedReplay } = mixedRun.carbonCrossGit;
    expect(mixedRun.runId).toBe(32334325227);
    expect(mixedRun.commonRuntime).toEqual({
      node: "v24.19.0",
      platform: "linux",
      arch: "x64",
      semgrep: "1.164.0",
      gitleaks: "gitleaks version 8.30.1",
    });
    expect(mixedRun.producerShards.map(({ index, gitVersion }) => ({ index, gitVersion }))).toEqual([
      { index: 1, gitVersion: "git version 2.54.0" },
      { index: 2, gitVersion: "git version 2.55.0" },
      { index: 3, gitVersion: "git version 2.54.0" },
    ]);
    expect(mixedRun.producerShards.flatMap(({ targets }) => targets)).toEqual([
      "carbon",
      "proposit", "subscription-payments", "boxyhq", "launch-mvp", "saas-lite", "tanstack-com", "cravab", "flori-web",
      "multi-tenant-starter", "mvp-boilerplate", "ghostfolio", "rallly", "inbox-zero", "documenso", "supabase-security-labs", "effective",
    ]);
    expect(observedProducer.preparationSha256).toBe(observedReplay.preparationSha256);
    expect(observedProducer.executionPlanSha256).toBe(observedReplay.executionPlanSha256);
    expect(observedProducer.semgrepDiagnosticsSha256).toBe(observedReplay.semgrepDiagnosticsSha256);
    expect(observedProducer.findingsSha256).not.toBe(observedReplay.findingsSha256);
    expect(observedProducer.normalizedProducersSha256).not.toBe(observedReplay.normalizedProducersSha256);
    expect(observedReplay.findingCount - observedProducer.findingCount).toBe(1);
    expect(observedReplay.semgrepFindingCount - observedProducer.semgrepFindingCount).toBe(1);
    expect(observedReplay.uniqueFinding).toContain("harvey-log-injection@packages/database/supabase/functions/post-shipment/index.ts:1114");

    const producer = artifact("hosted-producer");
    const replay = artifact("independent-replay");
    producer.targets.target!.gitVersion = observedProducer.gitVersion;
    replay.targets.target!.gitVersion = observedReplay.gitVersion;
    expect(() => compareCurrentMechanicalExecutions(producer, replay)).not.toThrow();
    replay.targets.target!.findings.push({ ...finding, id: "SEM-EXTRA", location: "packages/database/supabase/functions/post-shipment/index.ts:1114" });
    expect(() => compareCurrentMechanicalExecutions(producer, replay)).toThrow(/ordered raw mechanical finding/);
  });

  it("refuses dirty tracked or untracked harness inputs before producing an artifact", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-current-harness-"));
    try {
      mkdirSync(join(root, "src"));
      mkdirSync(join(root, "src", "nested"));
      mkdirSync(join(root, ".github", "workflows"), { recursive: true });
      writeFileSync(join(root, "src", "engine.ts"), "export const engine = 1;\n");
      writeFileSync(join(root, "src", "nested", "helper.ts"), "export const helper = 1;\n");
      writeFileSync(join(root, "package.json"), "{}\n");
      writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
      writeFileSync(join(root, ".github", "workflows", "corpus-drift.yml"), "name: fixture\n");
      execFileSync("git", ["init", "-q"], { cwd: root });
      execFileSync("git", ["add", "."], { cwd: root });
      execFileSync("git", ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"], { cwd: root });
      expect(() => currentHarnessReceipt(root)).not.toThrow();
      writeFileSync(join(root, "src", "engine.ts"), "export const engine = 2;\n");
      expect(() => currentHarnessReceipt(root)).toThrow(/dirty or untracked/);
      execFileSync("git", ["checkout", "--", "src/engine.ts"], { cwd: root });
      writeFileSync(join(root, "src", "untracked.ts"), "export {};\n");
      expect(() => currentHarnessReceipt(root)).toThrow(/dirty or untracked/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("gives producer and replay the same manifest-pruned tree while retaining an empty inbox-zero gitlink", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-current-prepare-"));
    const source = join(root, "source");
    try {
      mkdirSync(join(source, "repos", "effect"), { recursive: true });
      writeFileSync(join(source, "package.json"), "{}\n");
      writeFileSync(join(source, "tracked.txt"), "pinned tracked content\n");
      writeFileSync(join(source, "run.sh"), "#!/bin/sh\nexit 0\n");
      chmodSync(join(source, "run.sh"), 0o755);
      symlinkSync("tracked.txt", join(source, "tracked-link"));
      writeFileSync(join(source, "malicious;$(touch should-not-exist)"), "safe filename\n");
      writeFileSync(join(source, "repos", "effect", "not-target.ts"), "export {};\n");
      execFileSync("git", ["init", "-q"], { cwd: source });
      execFileSync("git", ["add", "."], { cwd: source });
      execFileSync("git", ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"], { cwd: source });
      const gitlink = "8c92f838e2b4c6311c5b970d2b32635d36de9a24";
      const inboxZeroGitlink = "apps/web/app/(marketing)";
      execFileSync("git", ["update-index", "--add", "--cacheinfo", `160000,${gitlink},${inboxZeroGitlink}`], { cwd: source });
      execFileSync("git", ["update-index", "--add", "--cacheinfo", `160000,${gitlink},repos/reference-link`], { cwd: source });
      execFileSync("git", ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "record uninitialized gitlinks"], { cwd: source });
      mkdirSync(join(source, inboxZeroGitlink), { recursive: true });
      mkdirSync(join(source, "repos", "reference-link"));
      const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: source, encoding: "utf8" }).trim();
      mkdirSync(join(root, "cache"));
      cpSync(source, join(root, "cache", "fixture__source"), { recursive: true, verbatimSymlinks: true });
      const producer = prepareCurrentMechanicalTarget({
        target: { slug: "fixture", repo: "fixture/source", commit, vendoredSubtrees: ["repos"] },
        checkoutDir: join(root, "checkout"),
        preparedDir: join(root, "prepared"),
        cloneCacheDir: join(root, "cache"),
        verifyRemote: false,
        onPreparationStage: (stage, checkoutDir) => {
          if (stage !== "checkout-validated") return;
          rmSync(join(checkoutDir, ".git", "objects", "pack"), { recursive: true, force: true });
          writeFileSync(join(checkoutDir, "repos", "reference-link", "unbound-but-excluded.ts"), "export {};\n");
        },
      });
      expect(producer.checkoutHead).toBe(commit);
      expect(existsSync(join(producer.preparedDir, "repos"))).toBe(false);
      expect(existsSync(join(producer.scanDir, "repos"))).toBe(false);
      expect(existsSync(join(producer.preparedDir, ".git"))).toBe(false);
      expect(existsSync(join(producer.preparedDir, inboxZeroGitlink))).toBe(true);
      expect(existsSync(join(producer.scanDir, inboxZeroGitlink))).toBe(true);
      expect(readRecursiveSafe(join(producer.preparedDir, inboxZeroGitlink))).toEqual([]);
      expect(readRecursiveSafe(join(producer.scanDir, inboxZeroGitlink))).toEqual([]);
      expect(readFileSync(join(producer.preparedDir, "tracked.txt"), "utf8")).toBe("pinned tracked content\n");
      expect(readlinkSync(join(producer.preparedDir, "tracked-link"))).toBe("tracked.txt");
      expect(lstatSync(join(producer.preparedDir, "run.sh")).mode & 0o111).not.toBe(0);
      expect(readFileSync(join(producer.preparedDir, "malicious;$(touch should-not-exist)"), "utf8")).toBe("safe filename\n");
      expect(existsSync(join(root, "should-not-exist"))).toBe(false);
      const replay = prepareCurrentMechanicalTarget({
        target: { slug: "fixture", repo: "fixture/source", commit, vendoredSubtrees: ["repos"] },
        checkoutDir: join(root, "checkout-second"),
        preparedDir: join(root, "prepared-second"),
        cloneCacheDir: join(root, "cache"),
        verifyRemote: false,
      });
      expect(replay.preparedTreeSha256).toBe(producer.preparedTreeSha256);
      expect(readRecursiveSafe(replay.preparedDir)).toEqual(readRecursiveSafe(producer.preparedDir));
      expect(existsSync(join(replay.scanDir, "repos"))).toBe(false);
      const absent = prepareCurrentMechanicalTarget({
        target: { slug: "fixture", repo: "fixture/source", commit, vendoredSubtrees: ["repos"] },
        checkoutDir: join(root, "checkout-absent-gitlink"),
        preparedDir: join(root, "prepared-absent-gitlink"),
        cloneCacheDir: join(root, "cache"),
        verifyRemote: false,
        onPreparationStage: (stage, checkoutDir) => {
          if (stage === "checkout-validated") rmSync(join(checkoutDir, inboxZeroGitlink), { recursive: true });
        },
      });
      expect(existsSync(join(absent.preparedDir, inboxZeroGitlink))).toBe(true);
      expect(existsSync(join(absent.scanDir, inboxZeroGitlink))).toBe(true);
      expect(readRecursiveSafe(join(absent.scanDir, inboxZeroGitlink))).toEqual([]);
      expect(() => prepareCurrentMechanicalTarget({
        target: { slug: "fixture", repo: "fixture/source", commit, vendoredSubtrees: ["repos"] },
        checkoutDir: join(root, "checkout-materialized-gitlink"),
        preparedDir: join(root, "prepared-materialized-gitlink"),
        cloneCacheDir: join(root, "cache"),
        verifyRemote: false,
        onPreparationStage: (stage, checkoutDir) => {
          if (stage === "checkout-validated") writeFileSync(join(checkoutDir, inboxZeroGitlink, "outside-parent-pin.ts"), "export {};\n");
        },
      })).toThrow(/gitlink apps\/web\/app\/\(marketing\) has materialized content that is not bound/);
      expect(() => assertPreparedTargetUnchanged(producer)).not.toThrow();
      writeFileSync(join(producer.preparedDir, "package.json"), "{\"mutated\":true}\n");
      expect(() => assertPreparedTargetUnchanged(producer)).toThrow(/mutated/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("fails loud when the validated checkout revision or tracked working tree moves", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-current-prepare-invalid-"));
    const source = join(root, "source");
    try {
      mkdirSync(source);
      writeFileSync(join(source, "tracked.txt"), "pinned\n");
      execFileSync("git", ["init", "-q"], { cwd: source });
      execFileSync("git", ["add", "."], { cwd: source });
      execFileSync("git", ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"], { cwd: source });
      writeFileSync(join(source, "second.txt"), "second\n");
      execFileSync("git", ["add", "."], { cwd: source });
      execFileSync("git", ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "second"], { cwd: source });
      const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: source, encoding: "utf8" }).trim();
      mkdirSync(join(root, "cache"));
      cpSync(source, join(root, "cache", "fixture__source"), { recursive: true, verbatimSymlinks: true });
      expect(() => prepareCurrentMechanicalTarget({
        target: { slug: "fixture", repo: "fixture/source", commit }, checkoutDir: join(root, "wrong-checkout"), preparedDir: join(root, "wrong-prepared"), cloneCacheDir: join(root, "cache"), verifyRemote: false,
        onPreparationStage: (stage, checkoutDir) => { if (stage === "checkout-cloned") execFileSync("git", ["-C", checkoutDir, "reset", "--hard", "HEAD^"], { stdio: "ignore" }); },
      })).toThrow(/differs from pin/);
      expect(() => prepareCurrentMechanicalTarget({
        target: { slug: "fixture", repo: "fixture/source", commit }, checkoutDir: join(root, "dirty-checkout"), preparedDir: join(root, "dirty-prepared"), cloneCacheDir: join(root, "cache"), verifyRemote: false,
        onPreparationStage: (stage, checkoutDir) => { if (stage === "checkout-cloned") writeFileSync(join(checkoutDir, "tracked.txt"), "dirty\n"); },
      })).toThrow(/tracked checkout content differs/);
      expect(() => prepareCurrentMechanicalTarget({
        target: { slug: "fixture", repo: "fixture/source", commit }, checkoutDir: join(root, "missing-checkout"), preparedDir: join(root, "missing-prepared"), cloneCacheDir: join(root, "cache"), verifyRemote: false,
        onPreparationStage: (stage, checkoutDir) => { if (stage === "checkout-validated") rmSync(join(checkoutDir, "tracked.txt")); },
      })).toThrow(/tracked file tracked.txt is missing/);
      expect(() => prepareCurrentMechanicalTarget({
        target: { slug: "fixture", repo: "fixture/source", commit, vendoredSubtrees: ["../outside"] }, checkoutDir: join(root, "unsafe-checkout"), preparedDir: join(root, "unsafe-prepared"), cloneCacheDir: join(root, "cache"), verifyRemote: false,
      })).toThrow(/not a canonical target-relative path/);
      expect(() => prepareCurrentMechanicalTarget({
        target: { slug: "fixture", repo: "fixture/source", commit }, checkoutDir: join(root, "untracked-checkout"), preparedDir: join(root, "untracked-prepared"), cloneCacheDir: join(root, "cache"), verifyRemote: false,
        onPreparationStage: (stage, checkoutDir) => { if (stage === "checkout-validated") writeFileSync(join(checkoutDir, "untracked.ts"), "export {};\n"); },
      })).toThrow(/mutable scan tree differs from the pinned prepared population/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
