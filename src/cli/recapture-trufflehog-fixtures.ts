import "./sync-stdio.js";
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { buildGitHistoryFixture, runTruffleHogGitJson } from "../scan/git-history-secret-gate.js";
import type { TruffleHogResult } from "../scan/secrets.js";
import { checkTruffleHogContract } from "../scan/fixture-drift-contracts.js";

const outAt = process.argv.indexOf("--out");
const outDir = outAt >= 0 ? process.argv[outAt + 1] : undefined;
if (!outDir) {
  console.error("usage: pnpm exec tsx src/cli/recapture-trufflehog-fixtures.ts --out src/scan/__fixtures__");
  process.exit(2);
}

const versionRun = spawnSync("trufflehog", ["--version"], { encoding: "utf8" });
if (versionRun.error || versionRun.status !== 0) {
  throw new Error(`trufflehog version check failed: ${versionRun.error?.message ?? versionRun.stderr}`);
}
const versionText = `${versionRun.stderr}${versionRun.stdout}`;
const version = versionText.match(/trufflehog\s+(\d+\.\d+\.\d+)/)?.[1];
if (!version) throw new Error(`could not parse trufflehog version from ${JSON.stringify(versionText.trim())}`);

function sanitizedRecord(record: TruffleHogResult, retainSecret: boolean): TruffleHogResult {
  const copy = structuredClone(record) as TruffleHogResult & {
    Raw?: string;
    RawV2?: string;
    SecretParts?: Record<string, string>;
    SourceMetadata?: { Data?: { Git?: Record<string, unknown> } };
  };
  const git = copy.SourceMetadata?.Data?.Git;
  if (retainSecret) {
    if (git) {
      git.repository = "file://<fixture-repo>";
      git.repository_local_path = "<trufflehog-clone>";
    }
  } else {
    delete copy.Raw;
    delete copy.RawV2;
    delete copy.SecretParts;
    if (git) {
      delete git.repository;
      delete git.repository_local_path;
    }
  }
  return copy;
}

const fixture = buildGitHistoryFixture();
try {
  const run = runTruffleHogGitJson(fixture.dir);
  if (run.failure !== undefined) throw new Error(`trufflehog fixture capture did not complete: ${run.failure}`);
  const records = run.records as TruffleHogResult[];
  const violations = checkTruffleHogContract(records);
  if (violations.length > 0) throw new Error(`fresh trufflehog output violates the parser contract:\n- ${violations.join("\n- ")}`);

  const root = resolve(outDir);
  const parserDir = join(root, "trufflehog");
  const historyDir = join(root, "trufflehog-git-history");
  mkdirSync(parserDir, { recursive: true });
  mkdirSync(historyDir, { recursive: true });
  const parserPath = join(parserDir, `trufflehog-${version}-git-unverified.json`);
  const historyPath = join(historyDir, `trufflehog-${version}-git-history.json`);
  writeFileSync(parserPath, `${JSON.stringify(records.map((record) => sanitizedRecord(record, false)), null, 2)}\n`);
  writeFileSync(historyPath, `${JSON.stringify(records.map((record) => sanitizedRecord(record, true)), null, 2)}\n`);
  console.log(`TRUFFLEHOG FIXTURES: ${records.length} record(s), version=${version}, parser=${parserPath}, history=${historyPath}`);
} finally {
  fixture.cleanup();
}
