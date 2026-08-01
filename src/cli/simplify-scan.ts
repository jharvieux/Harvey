// M6 (simplification / reuse) runner — assembles a review packet for a target directory.
//
//   pnpm simplify-scan <target-dir> [--out packet.md] [--hotspots <m3-hotspot-file>]
//
// --hotspots takes the newline-ranked file list M3 emits (`hotspot-scan.ts --hotspots-out`, the
// same file M8's mutation-scan consumes): the packet then leads with the hottest files so the
// reviewer starts on the prime refactoring candidates (#442).
//
// Prints the packet (brief + source) to stdout. It does NOT invoke a model: M6's verdict is a paid
// human-reviewed judgment (docs/design/m6-simplification-eval.md §5), and `pnpm verify` must stay
// deterministic and offline. Feed the packet to a reviewer, then triage the writeup by hand.

import "./sync-stdio.js";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { readEntriesSafe } from "../fs-walk.js";
import { fileURLToPath } from "node:url";
import { buildPacket, renderPacket, scopePacketFiles } from "../simplify-scan.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const briefPath = join(repoRoot, "briefs", "quality-extras.txt");

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage"]);

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const { name: entry, path: full, isDirectory } of readEntriesSafe(dir).entries) {
    if (SKIP_DIRS.has(entry)) continue;
    if (isDirectory) out.push(...sourceFiles(full));
    else if (/\.(ts|tsx|js|jsx|mjs)$/.test(entry) && !/\.(test|spec)\./.test(entry)) out.push(full);
  }
  return out;
}

// #396: package.json manifests under the target (root, plus any workspace packages) — the packet's
// only evidence for the rubric's "already in the dependency tree" class.
function manifestFiles(dir: string): string[] {
  const out: string[] = [];
  for (const { name: entry, path: full, isDirectory } of readEntriesSafe(dir).entries) {
    if (SKIP_DIRS.has(entry)) continue;
    if (isDirectory) out.push(...manifestFiles(full));
    else if (entry === "package.json") out.push(full);
  }
  return out;
}

const args = process.argv.slice(2);
const targetArg = args.find((a) => !a.startsWith("--"));
const outIdx = args.indexOf("--out");
const outPath = outIdx >= 0 ? args[outIdx + 1] : undefined;
const hotspotsIdx = args.indexOf("--hotspots");
const hotspotsPath = hotspotsIdx >= 0 ? args[hotspotsIdx + 1] : undefined;

if (!targetArg) {
  console.error("usage: pnpm simplify-scan <target-dir> [--out packet.md] [--hotspots <m3-hotspot-file>]");
  process.exit(2);
}

const targetDir = resolve(targetArg);
const allFiles = sourceFiles(targetDir);
if (!allFiles.length) {
  console.error(`M6: no source files under ${targetDir} — nothing to review.`);
  process.exit(1);
}

const hotspots = hotspotsPath
  ? readFileSync(hotspotsPath, "utf8").split("\n").map((l) => l.trim()).filter(Boolean)
  : [];

// #621: with --hotspots the packet body is scoped to the matched hotspot files, not the full tree.
const files = scopePacketFiles(allFiles, targetDir, hotspots);
if (hotspotsPath && !files.length) {
  console.error(
    `M6: --hotspots was given but none of its ${hotspots.length} entr${hotspots.length === 1 ? "y" : "ies"} matched a source file under ${targetDir} — refusing to fall back to the full ${allFiles.length}-file tree. Check the hotspot paths are relative to the target root.`,
  );
  process.exit(1);
}

const manifests = manifestFiles(targetDir);
if (!manifests.length) {
  console.error(`M6: no package.json found under ${targetDir} — the packet will say the dependency-tree class is unverifiable.`);
}

const packet = renderPacket(buildPacket(readFileSync(briefPath, "utf8"), targetDir, files, hotspots, manifests, allFiles.length));
if (hotspotsPath) {
  console.error(`M6: scoped packet to ${files.length} file(s) matching ${hotspots.length} M3 hotspot(s) (of ${allFiles.length} source files under the target).`);
}

if (outPath) {
  writeFileSync(outPath, packet);
  console.error(`M6 review packet: ${files.length} file(s) → ${outPath}`);
} else {
  console.log(packet);
}
console.error("M6 is a judgment pass, not a detector — this packet needs TWO independent reviewers (#813): compare their verdict blocks with `pnpm exec tsx src/cli/m6-agreement.ts`, send splits to a human adjudicator, and the writeup still needs human triage before a client sees it.");
// #351: assembling this packet is NOT an M6 execution. The orchestrator records M6 `partial` (not
// `ran`) on the strength of this run, so it never clears M6's never-run alarm — only a recorded
// reviewed verdict does (see src/audit-runners.ts m6, and the #416 durable-artifact path).
console.error("This packet is an input to M6's verdict, not the verdict — it does not count as M6 having run (#351).");
