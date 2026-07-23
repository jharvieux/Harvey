// Aggregate N per-app engagement findings.json documents into ONE anonymized corpus statistic for
// the flagship research report (#726). Consumes the exact shape run-audit --findings-out emits.
//
//   pnpm exec tsx src/cli/corpus-aggregate.ts <findings.json...> [--dir <dir>] [--out summary.json] [--summary-out summary.md]
//
// --dir adds every *.json under a directory (each expected to be one app's findings document).
// Prints the shareable text summary to stdout; --out/--summary-out also write the JSON/Markdown.
// Fail loud: an unreadable or non-findings-document input aborts the run rather than being skipped.

import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { aggregateCorpus, renderSummaryText } from "../corpus-aggregate.js";
import { type FindingsDocument, validateFindings } from "../findings.js";

function flagValue(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const args = process.argv.slice(2);
const dir = flagValue("--dir");
const out = flagValue("--out");
const summaryOut = flagValue("--summary-out");

const flagsWithValues = new Set(["--dir", "--out", "--summary-out"]);
const paths: string[] = [];
for (let i = 0; i < args.length; i++) {
  const a = args[i]!;
  if (a.startsWith("--")) {
    if (flagsWithValues.has(a)) i++; // skip its value
    continue;
  }
  paths.push(a);
}
if (dir) for (const f of readdirSync(dir)) if (f.endsWith(".json")) paths.push(join(dir, f));

if (paths.length === 0) {
  console.error("usage: pnpm exec tsx src/cli/corpus-aggregate.ts <findings.json...> [--dir <dir>] [--out summary.json] [--summary-out summary.md]");
  process.exit(2);
}

const docs: FindingsDocument[] = [];
for (const p of paths) {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(p, "utf8"));
  } catch (e) {
    console.error(`✗ ${p}: could not read/parse — ${(e as Error).message}`);
    process.exit(1);
  }
  const { ok, errors } = validateFindings(parsed);
  if (!ok) {
    console.error(`✗ ${p}: not a valid findings document:`);
    for (const err of errors.slice(0, 5)) console.error(`    ${err}`);
    process.exit(1);
  }
  docs.push(parsed as FindingsDocument);
}

const summary = aggregateCorpus(docs);
const text = renderSummaryText(summary);
console.log(text);

if (out) {
  writeFileSync(out, `${JSON.stringify(summary, null, 2)}\n`);
  console.error(`\nCorpus summary JSON → ${out}`);
}
if (summaryOut) {
  writeFileSync(summaryOut, `${text}\n`);
  console.error(`Shareable summary → ${summaryOut}`);
}
