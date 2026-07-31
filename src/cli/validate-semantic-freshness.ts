// pnpm validate-semantic-freshness [--artifacts-dir <dir>] [--now <iso>] [--json]
//
// #1270 (remainder of #870): the M1 semantic recall gate goes dark 30 days after any pass and
// nothing said so. `validate-semantic` scores a recorded pass; this asks whether the recorded
// evidence is still inside the window that makes it evidence at all. See src/semantic-freshness.ts
// for why the two sources are reported separately.
//
// Exits 1 when any corpus target's recorded semantic measurement is older than the pass-artifact
// freshness window, or when there is no corpus to measure — a gate with nothing to assess must not
// exit 0. `--now` is the negative control: move the clock past the window and the gate must go red.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { SEMANTIC_CORPUS } from "../scan/semantic-corpus.js";
import { assessSemanticFreshness } from "../semantic-freshness.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

// The standing home for recorded semantic passes, so `pnpm record-pass --out
// reports/semantic-recall/<slug>` and `validate-semantic --artifacts-dir reports/semantic-recall`
// agree without anyone choosing a directory per session. Nothing is committed there yet, which is
// exactly what `withoutArtifact` reports.
const DEFAULT_ARTIFACTS_DIR = join(REPO_ROOT, "reports", "semantic-recall");

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

const artifactsDir = resolve(flag("--artifacts-dir") ?? DEFAULT_ARTIFACTS_DIR);

const nowFlag = flag("--now");
const now = nowFlag ? Date.parse(nowFlag) : Date.now();
if (!Number.isFinite(now)) {
  console.error(`--now ${nowFlag} is not a parseable date`);
  process.exit(2);
}

const artifactDates: Record<string, string | undefined> = {};
for (const target of SEMANTIC_CORPUS) {
  const path = join(artifactsDir, target.slug, "M1.pass.json");
  if (!existsSync(path)) continue;
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as { generatedAt?: string };
    artifactDates[target.slug] = raw.generatedAt;
  } catch (err) {
    // A pass artifact that fails to parse is not the same fact as one that is absent, and silently
    // demoting it to the corpus record would hide a corrupted recording behind a green-ish row.
    console.error(`✗ ${path} is not valid JSON (${err instanceof Error ? err.message : String(err)})`);
    process.exit(1);
  }
}

const result = assessSemanticFreshness(now, artifactDates);

if (args.includes("--json")) {
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.stale.length > 0 || result.rows.length === 0 ? 1 : 0);
}

console.log(`M1 SEMANTIC recall freshness (#1270) — window ${result.windowDays} days, artifacts under ${artifactsDir.replace(REPO_ROOT + "/", "")}\n`);

for (const r of result.rows) {
  const verdict = r.stale ? `STALE by ${-r.daysLeft}d` : `fresh, ${r.daysLeft}d left`;
  console.log(`  ${r.slug.padEnd(15)} ${r.recordedOn}  ${String(r.ageDays).padStart(3)}d old  ${verdict.padEnd(22)} source: ${r.source}`);
}

if (result.rows.length === 0) {
  console.error("\n✗ SEMANTIC FRESHNESS UNKNOWN — the semantic corpus is empty, so this gate measured nothing. An unrun gate must not exit 0.");
  process.exit(1);
}

// Disclosed on every run, pass or fail: `corpus-record` rows are dated by a measurement doc, not by
// a pass anyone re-ran. A green gate over four of those means "nobody's number has aged out yet",
// not "the semantic tier was re-scored".
if (result.withoutArtifact > 0) {
  console.log(
    `\n${result.withoutArtifact} of ${result.rows.length} target(s) have NO recorded M1.pass.json and are dated by their measurement doc's` +
      ` \`recordedOn\` alone. Record a real pass with:\n` +
      `  pnpm record-pass --module M1 --pass semantic --target <clone> --findings <triage.json> --out reports/semantic-recall/<slug>\n` +
      `then score it with \`pnpm validate:semantic --artifacts-dir reports/semantic-recall\`.` +
      ` A \`recordedOn\` moved without a re-measurement is a falsified corpus, not a fixed alarm.`,
  );
}

if (result.stale.length > 0) {
  console.error(
    `\n✗ SEMANTIC RECALL GONE DARK — ${result.stale.length} of ${result.rows.length} target(s) past the ${result.windowDays}-day window: ` +
      `${result.stale.map((r) => `${r.slug} (${-r.daysLeft}d over)`).join(", ")}.\n` +
      `  Their recorded numbers no longer describe the present, and #870's risk — a brief edit, a model change or an fp-rules.txt tweak degrading the semantic tier with nothing failing — is live again.\n` +
      `  Re-run the semantic pass over those targets (docs/design/semantic-recall-gate.md) and re-score.`,
  );
  process.exit(1);
}

console.log(`\n✓ SEMANTIC FRESHNESS OK — every recorded semantic measurement is inside the ${result.windowDays}-day window.`);
