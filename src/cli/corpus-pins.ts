// Writes EXTERNAL_CORPUS's pin set, one `<slug> <repo>@<commit>` line per target, sorted by slug
// for a deterministic byte stream. This is the single source .github/actions/corpus-clone-cache
// (#1571) reads to (a) derive its cache key via hashFiles(), so editing a pin is a cache miss by
// construction, and (b) verify a restored cache reproduces every pinned clone exactly — never a
// second, hand-maintained pin list in the workflow YAML that could drift from the manifest.
//
//   pnpm corpus-pins --out <path>
//
// Written to a FILE rather than printed to stdout on purpose: `pnpm exec`/`pnpm run` can emit its
// own banner lines to stdout ahead of a script's own output (MEASURED in this repo's own sandbox —
// "Already up to date" / "Done in Nms using pnpm vX" landed in a `> file` redirect and corrupted
// the pin list with two bogus slugs). Every other CLI here that produces a machine-read artifact
// already takes an explicit --out/--json path for the same reason; this one follows suit rather
// than trusting a stdout redirect to stay clean.
import "./sync-stdio.js";
import { writeFileSync } from "node:fs";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";

const outFlag = process.argv.indexOf("--out");
const out = outFlag >= 0 ? process.argv[outFlag + 1] : undefined;
if (!out) {
  console.error("usage: pnpm corpus-pins --out <path>");
  process.exit(2);
}

const lines = [...EXTERNAL_CORPUS].sort((a, b) => a.slug.localeCompare(b.slug)).map((t) => `${t.slug} ${t.repo}@${t.commit}`);
writeFileSync(out, `${lines.join("\n")}\n`);
