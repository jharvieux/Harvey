import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import {
  CORPUS_ADVISORY_SNAPSHOT_DIR,
  canonicalizeCorpusOsvInput,
  type CorpusAdvisoryObservationArtifact,
  type CorpusAdvisoryObservationTarget,
  type CorpusAdvisorySnapshotEntry,
} from "./corpus-advisory-snapshot.js";
import { CORPUS_CACHE_SHARD_COUNT, partitionTargets } from "./scan/corpus-shards.js";
import { validateOsvAssessment, type OsvAssessment } from "./scan/dependencies.js";

type Provenance = NonNullable<CorpusAdvisoryObservationArtifact["provenance"]>;
type Target = CorpusAdvisoryObservationArtifact["expectedTargets"][number];

export function corpusAdvisoryObservationProvenance(registrySha256: string): Provenance {
  return {
    headSha: process.env.GITHUB_SHA ?? "local",
    runId: process.env.GITHUB_RUN_ID ?? "local",
    runAttempt: process.env.GITHUB_RUN_ATTEMPT ?? "local",
    registrySha256,
    snapshotManifestSha256: createHash("sha256").update(readFileSync(join(CORPUS_ADVISORY_SNAPSHOT_DIR, "manifest.json"))).digest("hex"),
  };
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`corpus advisory observation: ${message}`);
}

function sameMembers(actual: readonly string[], expected: readonly string[]): boolean {
  return JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort());
}

/** Merge only the canonical partition of one hosted run, preserving every raw observation. */
export function mergeCorpusAdvisoryObservations(
  inputs: readonly unknown[],
  expectedTargets: readonly Target[],
  provenance: Provenance,
  snapshots: Readonly<Record<string, CorpusAdvisorySnapshotEntry & { rawSha256: string; assessment: OsvAssessment }>>,
): CorpusAdvisoryObservationArtifact {
  assert(/^[a-f0-9]{40}$/.test(provenance.headSha) && /^\d+$/.test(provenance.runId) && /^\d+$/.test(provenance.runAttempt), "hosted run identity is required");
  assert(inputs.length === CORPUS_CACHE_SHARD_COUNT, "expected every canonical shard");
  const slugs = expectedTargets.map(({ slug }) => slug);
  assert(slugs.length > 0 && new Set(slugs).size === slugs.length, "expected target population is empty or duplicated");
  const partitions = partitionTargets(slugs, CORPUS_CACHE_SHARD_COUNT);
  const parts = inputs as CorpusAdvisoryObservationArtifact[];
  const targets: Record<string, CorpusAdvisoryObservationTarget> = {};
  const seen = new Set<number>();
  const versions = new Set<string>();
  for (const part of parts) {
    assert(part?.schema === 1 && part.mode === "live-verify", "unsupported observation schema or mode");
    assert(part.provenance && Object.entries(provenance).every(([key, value]) => part.provenance?.[key as keyof Provenance] === value), "parts do not share this run's exact head, attempt, registry and advisory snapshot inputs");
    const shard = part.shard;
    assert(shard && shard.count === CORPUS_CACHE_SHARD_COUNT && Number.isInteger(shard.index) && shard.index >= 1 && shard.index <= shard.count && !seen.has(shard.index), "missing, duplicate or invalid shard identity");
    seen.add(shard.index);
    assert(Array.isArray(part.expectedTargets) && sameMembers(part.expectedTargets.map(({ slug }) => slug), partitions[shard.index - 1]!), `shard ${shard.index} does not own its canonical target population`);
    assert(part.targets && typeof part.targets === "object" && !Array.isArray(part.targets), "target observations are missing");
    assert(Object.keys(part.targets).every((slug) => partitions[shard.index - 1]!.includes(slug)), "unowned target observation");
    assert(typeof part.liveOsvScannerVersion === "string" && part.liveOsvScannerVersion.length > 0, "live scanner version is missing");
    assert(Number.isFinite(Date.parse(part.startedAt)) && (part.completedAt === null || Number.isFinite(Date.parse(part.completedAt))), "invalid observation timestamps");
    versions.add(part.liveOsvScannerVersion);
    for (const expected of part.expectedTargets) {
      const target = expectedTargets.find(({ slug }) => slug === expected.slug)!;
      assert(expected.repo === target.repo && expected.pin === target.pin, `${target.slug} expected repository or pin differs`);
      const observation = part.targets[target.slug];
      if (!observation) continue; // Retain an interrupted part as incomplete; never invent a result.
      assert(observation.slug === target.slug && observation.repo === target.repo && observation.pin === target.pin, `${target.slug} observed repository or pin differs`);
      assert(["started", "equal", "metadata-only", "finding-change", "failed"].includes(observation.status), `${target.slug} has an invalid status`);
      if (["equal", "metadata-only", "finding-change"].includes(observation.status)) {
        const snapshot = snapshots[target.slug];
        assert(snapshot?.targetCommit === target.pin && observation.snapshot, `${target.slug} snapshot provenance is missing`);
        assert(observation.snapshot.artifactSha256 === snapshot.sha256 && observation.snapshot.capturedAt === snapshot.capturedAt && observation.snapshot.expiresAt === snapshot.expiresAt && observation.snapshot.osvScannerVersion === snapshot.osvScannerVersion, `${target.slug} snapshot provenance differs`);
        const receipt = observation.comparison;
        assert(receipt?.schema === 1 && receipt.status === observation.status && receipt.assessment, `${target.slug} comparison or input assessment is missing`);
        validateOsvAssessment(receipt.assessment.live, receipt.raw.livePayload);
        assert(isDeepStrictEqual(receipt.assessment.snapshot, snapshot.assessment), `${target.slug} committed input assessment differs`);
        assert(receipt.assessment.equal === isDeepStrictEqual(receipt.assessment.live, receipt.assessment.snapshot), `${target.slug} assessment equality contradicts its evidence`);
        const rawDigest = createHash("sha256").update(JSON.stringify(canonicalizeCorpusOsvInput(receipt.raw.livePayload))).digest("hex");
        assert(rawDigest === receipt.raw.liveSha256, `${target.slug} live payload digest differs`);
        assert(receipt.raw.snapshotSha256 === snapshot.rawSha256, `${target.slug} committed snapshot payload digest differs`);
        const status = receipt.semantic.equal ? (receipt.raw.equal ? "equal" : "metadata-only") : "finding-change";
        assert(observation.status === status && receipt.raw.equal === (receipt.raw.liveSha256 === receipt.raw.snapshotSha256), `${target.slug} comparison status contradicts its evidence`);
      }
      targets[target.slug] = observation;
    }
  }
  assert(versions.size === 1, "live scanner versions differ between shards");
  const assessments = expectedTargets.map(({ slug }) => targets[slug]?.comparison?.assessment);
  const inventoryComplete = assessments.every((assessment) => assessment?.equal);
  return {
    schema: 1,
    mode: "live-verify",
    provenance,
    startedAt: parts.map((part) => part.startedAt).sort()[0]!,
    completedAt: parts.every((part) => part.completedAt !== null) ? parts.map((part) => part.completedAt!).sort().at(-1)! : null,
    populationComplete: parts.every((part) => part.populationComplete && part.completedAt !== null) && inventoryComplete && expectedTargets.every(({ slug }) => ["equal", "metadata-only", "finding-change"].includes(targets[slug]?.status ?? "")),
    assessmentCoverage: {
      inventoryComplete,
      assessed: assessments.filter((assessment) => assessment?.live.status === "assessed").length,
      partial: assessments.filter((assessment) => assessment?.live.status === "partial").length,
      notAssessed: assessments.filter((assessment) => assessment?.live.status === "not-assessed").length,
      notApplicable: assessments.filter((assessment) => assessment?.live.status === "not-applicable").length,
    },
    liveOsvScannerVersion: [...versions][0]!,
    expectedTargets: [...expectedTargets],
    targets,
  };
}
