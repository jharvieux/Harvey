import "./sync-stdio.js";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { corpusAdvisoryObservationProvenance, mergeCorpusAdvisoryObservations } from "../corpus-advisory-observation.js";
import { CORPUS_ADVISORY_SNAPSHOT_DIR, loadCorpusAdvisorySnapshot, parseCorpusAdvisorySnapshotManifest, writeCorpusAdvisoryObservation } from "../corpus-advisory-snapshot.js";
import { validateRestoredSemgrepPackArtifact } from "../corpus-mechanical-readiness.js";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";

try {
  const args = process.argv.slice(2);
  const value = (flag: string): string => {
    const index = args.indexOf(flag);
    const result = index < 0 ? undefined : args[index + 1];
    if (!result || result.startsWith("--")) throw new Error(`${flag} is required`);
    return result;
  };
  const partsDir = value("--parts");
  const output = value("--out");
  const registry = validateRestoredSemgrepPackArtifact(value("--registry-dir"));
  const files = readdirSync(partsDir).sort();
  if (JSON.stringify(files) !== JSON.stringify([1, 2, 3, 4].map((index) => `corpus-advisory-observation-shard${index}.json`))) throw new Error("expected exactly four canonical advisory observation files");
  const manifest = parseCorpusAdvisorySnapshotManifest(JSON.parse(readFileSync(join(CORPUS_ADVISORY_SNAPSHOT_DIR, "manifest.json"), "utf8")));
  const artifact = mergeCorpusAdvisoryObservations(
    files.map((file) => JSON.parse(readFileSync(join(partsDir, file), "utf8")) as unknown),
    EXTERNAL_CORPUS.map(({ slug, repo, commit }) => ({ slug, repo, pin: commit })),
    corpusAdvisoryObservationProvenance(registry.identity!),
    Object.fromEntries(EXTERNAL_CORPUS.map(({ slug, commit }) => {
      const snapshot = loadCorpusAdvisorySnapshot(slug, commit);
      return [slug, {
        ...manifest.targets[slug]!,
        rawSha256: createHash("sha256").update(JSON.stringify(snapshot.result)).digest("hex"),
        assessment: snapshot.assessment,
      }];
    })),
  );
  writeCorpusAdvisoryObservation(output, artifact);
  if (!artifact.populationComplete) throw new Error(`incomplete live advisory population; diagnostic observations retained in ${output}`);
  console.log(`CORPUS ADVISORY OBSERVATION: ${artifact.expectedTargets.length} pinned target(s), complete live input coverage`);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
