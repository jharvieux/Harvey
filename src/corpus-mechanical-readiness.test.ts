import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "./findings.js";
import {
  compareCurrentMechanicalExecutions,
  assertPreparedTargetUnchanged,
  CURRENT_MECHANICAL_POPULATION,
  CURRENT_MECHANICAL_PREPARATION,
  currentTargetPinsSha256,
  currentHarnessReceipt,
  mergeCurrentMechanicalShards,
  prepareCurrentMechanicalTarget,
  type CurrentMechanicalExecutionArtifact,
} from "./corpus-mechanical-readiness.js";
import { digestParts, mechanicalExaminedUnitDigest } from "./scan/mechanical-phase-cache.js";
import { REGISTRY_PACKS, registryPackIdentity } from "./scan/semgrep.js";

const digest = "a".repeat(64);
const packBody = Buffer.from("x");
const packDigest = createHash("sha256").update(packBody).digest("hex");
const packAggregate = registryPackIdentity(REGISTRY_PACKS.map((pack) => ({ pack, body: packBody.toString("utf8") })));
const target = { slug: "target", repo: "https://example.invalid/target.git", commit: "b".repeat(40), vendoredSubtrees: ["vendor/reference"] };
const finding: Finding = { id: "ROW-1", title: "row", severity: "Low", confidence: "Likely", category: "test", taxonomy: "test", location: "a.ts:1", status: "Open", evidence: "evidence", impact: "impact", fix: "fix", value: 1, ease: 1, safety: 1, mechanical: true };

function artifact(side: CurrentMechanicalExecutionArtifact["side"]): CurrentMechanicalExecutionArtifact {
  return {
    schema: 1,
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
    runtime: { node: "v24", platform: "linux", arch: "x64", semgrep: "1", gitleaks: "1", git: "1" },
    shard: { index: 1, count: 1 },
    targets: {
      target: {
        slug: "target", repo: target.repo, pin: target.commit, checkoutHead: target.commit, checkoutTree: digest,
        preparedTreeSha256: digest, preparation: CURRENT_MECHANICAL_PREPARATION, removedVendoredSubtrees: ["vendor/reference"],
        captureBeforeInstall: true, installMutationAtCapture: false, skipBundleScan: true,
        bundleDigest: digestParts(["bundle-pinned-off-v1"]),
        advisorySha256: digest, advisoryVersion: "osv-1", secretCandidateIdentity: digest,
        findings: [finding],
        producers: [{ detector: "producer", phase: "structural-ast", order: 1, module: "M1", unitsExamined: 1, examinedUnitIdentities: [{ producer: "producer", kind: "target-path", identity: "a.ts" }], examinedUnitDigest: mechanicalExaminedUnitDigest([{ producer: "producer", kind: "target-path", identity: "a.ts" }]), findings: 1, durationMs: 1, status: "ran" }],
        context: { filesPresent: 1 } as never,
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

describe("fresh current mechanical producer ↔ replay readiness", () => {
  it("wires the required aggregate to shared bytes and two fresh sides without claiming historical proof", () => {
    const workflow = readFileSync(new URL("../.github/workflows/corpus-drift.yml", import.meta.url), "utf8");
    expect(workflow).toContain("prepare-current-inputs:");
    expect(workflow).toContain("name: current-mechanical-semgrep-pack");
    expect(workflow).toContain("HARVEY_SEMGREP_REGISTRY_SNAPSHOT_MODE: reuse");
    expect(workflow).toContain("current-replay:");
    expect(workflow).toContain("needs: [prepare-current-inputs, shard, current-replay]");
    expect(workflow).toContain("Current registry producer ↔ independent replay equivalence/readiness");
    expect(workflow).toContain("NOT #1851.6/.7 historical manual→registry proof");
    expect(workflow).not.toContain("Old orchestrator → registry");
    expect(workflow).not.toContain("validate:mechanical-corpus-parity");
  });

  it("accepts two distinct exact-head executions and ignores duration/cache status only", () => {
    const producer = artifact("hosted-producer");
    const replay = artifact("independent-replay");
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
    const producer = artifact("hosted-producer");
    expect(() => compareCurrentMechanicalExecutions(producer, producer)).toThrow(/one real hosted producer/);
  });

  it("rejects dirty preparation: install-before-capture, retained vendored tree, or bundle-on", () => {
    expectDifference((value) => { value.targets.target!.captureBeforeInstall = false as true; }, /before install/);
    expectDifference((value) => { value.targets.target!.installMutationAtCapture = true as false; }, /before install/);
    expectDifference((value) => { value.targets.target!.removedVendoredSubtrees = []; }, /vendored-subtree/);
    expectDifference((value) => { value.targets.target!.skipBundleScan = false as true; }, /bundle input/);
  });

  it("rejects one-side, mixed, duplicate, and incomplete shard populations", () => {
    const left = artifact("hosted-producer");
    const second = structuredClone(left);
    second.shard = { index: 2, count: 2 };
    left.shard = { index: 1, count: 2 };
    second.executionId = "hosted-producer:2/2:fixture";
    expect(() => mergeCurrentMechanicalShards([left], "producer")).toThrow(/expected 2/);
    second.headCommit = "d".repeat(40);
    expect(() => mergeCurrentMechanicalShards([left, second], "producer")).toThrow(/mixed/);
    second.headCommit = left.headCommit;
    expect(() => mergeCurrentMechanicalShards([left, { ...second, shard: { index: 1, count: 2 } }], "producer")).toThrow(/index population/);
    expect(() => mergeCurrentMechanicalShards([left, second], "producer")).toThrow(/appears in more than one shard/);
  });

  it("refuses dirty tracked or untracked harness inputs before producing an artifact", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-current-harness-"));
    try {
      mkdirSync(join(root, "src"));
      mkdirSync(join(root, ".github", "workflows"), { recursive: true });
      writeFileSync(join(root, "src", "engine.ts"), "export const engine = 1;\n");
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

  it("prepares the exact pin, removes vendored subtrees, copies before mutation, and detects later writes", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-current-prepare-"));
    const source = join(root, "source");
    try {
      mkdirSync(join(source, "vendor", "reference"), { recursive: true });
      writeFileSync(join(source, "package.json"), "{}\n");
      writeFileSync(join(source, "vendor", "reference", "not-target.ts"), "export {};\n");
      execFileSync("git", ["init", "-q"], { cwd: source });
      execFileSync("git", ["add", "."], { cwd: source });
      execFileSync("git", ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"], { cwd: source });
      const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: source, encoding: "utf8" }).trim();
      mkdirSync(join(root, "cache"));
      cpSync(source, join(root, "cache", "fixture__source"), { recursive: true });
      const prepared = prepareCurrentMechanicalTarget({
        target: { slug: "fixture", repo: "fixture/source", commit, vendoredSubtrees: ["vendor/reference"] },
        checkoutDir: join(root, "checkout"),
        preparedDir: join(root, "prepared"),
        cloneCacheDir: join(root, "cache"),
        verifyRemote: false,
      });
      expect(prepared.checkoutHead).toBe(commit);
      expect(existsSync(join(prepared.preparedDir, "vendor", "reference"))).toBe(false);
      expect(() => assertPreparedTargetUnchanged(prepared)).not.toThrow();
      writeFileSync(join(prepared.preparedDir, "package.json"), "{\"mutated\":true}\n");
      expect(() => assertPreparedTargetUnchanged(prepared)).toThrow(/mutated/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
