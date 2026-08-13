import "./sync-stdio.js";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { binaryVersion } from "../scan/mechanical-phase-cache.js";
import { cloneAtPinCached } from "../scan/corpus-clone.js";
import { runOsvScanner } from "../scan/dependencies.js";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";
import { CORPUS_ADVISORY_SNAPSHOT_DIR, canonicalizeCorpusOsvInput, type CorpusAdvisorySnapshotManifest } from "../corpus-advisory-snapshot.js";

const args = process.argv.slice(2);
const outAt = args.indexOf("--out");
const outDir = outAt >= 0 ? args[outAt + 1] : CORPUS_ADVISORY_SNAPSHOT_DIR;
if (!outDir) {
  console.error("corpus-advisory-snapshot: --out needs a directory");
  process.exit(2);
}
const targetAt = args.indexOf("--target");
const onlyTarget = targetAt >= 0 ? args[targetAt + 1] : undefined;
// Migration parity and the registry corpus lane scan every pinned target, not only the six with a
// free-tier grade. The snapshot population must therefore be coextensive with EXTERNAL_CORPUS.
const targets = EXTERNAL_CORPUS.filter((target) => !onlyTarget || target.slug === onlyTarget);
if (targets.length === 0) {
  console.error(`corpus-advisory-snapshot: no snapshot target ${onlyTarget ?? "(all)"}`);
  process.exit(2);
}

mkdirSync(outDir, { recursive: true });
const priorPath = join(outDir, "manifest.json");
const prior = targetAt >= 0 ? (() => {
  try { return JSON.parse(readFileSync(priorPath, "utf8")) as CorpusAdvisorySnapshotManifest; } catch { return undefined; }
})() : undefined;
const capturedAt = new Date();
const expiresAt = new Date(capturedAt.getTime() + 7 * 24 * 60 * 60 * 1_000);
const manifest: CorpusAdvisorySnapshotManifest = {
  schema: 1,
  capturedAt: capturedAt.toISOString(),
  expiresAt: expiresAt.toISOString(),
  osvScannerVersion: binaryVersion("osv-scanner"),
  targets: { ...(prior?.targets ?? {}) },
};

for (const target of targets) {
  const dir = mkdtempSync(join(tmpdir(), `harvey-advisory-${target.slug}-`));
  try {
    cloneAtPinCached(target.repo, target.commit, dir, process.env.HARVEY_CORPUS_CACHE_DIR, true);
    const run = runOsvScanner(dir);
    if (run.failure) throw new Error(`${target.slug}: ${run.failure}`);
    const bytes = gzipSync(`${JSON.stringify(canonicalizeCorpusOsvInput(run.result))}\n`, { level: 9 });
    const file = `${target.slug}.osv.json.gz`;
    writeFileSync(join(outDir, file), bytes);
    manifest.targets[target.slug] = { file, sha256: createHash("sha256").update(bytes).digest("hex"), targetCommit: target.commit };
    console.error(`${target.slug}: captured ${bytes.length} compressed byte(s)`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
writeFileSync(priorPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`CORPUS ADVISORY SNAPSHOT: ${Object.keys(manifest.targets).length} target(s), osv=${manifest.osvScannerVersion}, captured=${manifest.capturedAt}, expires=${manifest.expiresAt}`);
