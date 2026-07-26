// M6 (simplification / reuse) runner — the VERDICT path. M6's verdict has no mechanical detector —
// it is a reviewer's judgment, not a Finding[] a tool can assert (docs/design/m6-simplification-eval.md
// §1/§5). So this does NOT score anything: it assembles the M6 brief + the target's source into one
// review packet, which a reviewer (LLM or human) then reads. That is the whole runner.
//
// (Since #267 M6 also has a mechanical FREE-tier layer — src/detectors/handrolled.ts, run via
// `pnpm detect-static` — but those are hedged, non-grading "looks hand-rolled" indicators, never
// verdicts. The judgment and the named replacement still only come from a reviewer over this packet.)
//
// Why it exists at all: before this, M6's documented entry point was "the /simplify skill", which is
// not installed — so M6's execution path was "a human remembers to invoke a tool that isn't there."
// It never ran, in any engagement, since it was defined (#266). A packet you can produce on demand
// is the minimum honest replacement: it can't make the reviewer think, but it can stop M6's absence
// from being invisible.

import { readFileSync } from "node:fs";
import { relative } from "node:path";

// The brief's M6 section only — the file also carries M5/M8 sections that would dilute the pass.
// Delimited by the "## " headings in briefs/quality-extras.txt.
export function extractM6Brief(briefText: string): string {
  const lines = briefText.split("\n");
  const start = lines.findIndex((l) => l.startsWith("## SIMPLIFICATION"));
  if (start < 0) throw new Error("quality-extras.txt has no '## SIMPLIFICATION' section — the M6 brief is the rubric; refusing to assemble a packet without it.");
  const rest = lines.slice(start + 1).findIndex((l) => l.startsWith("## "));
  const end = rest < 0 ? lines.length : start + 1 + rest;

  // The FALSE POSITIVES section is a separate heading but is part of the M6 rubric: it is what
  // separates a deliberate dep-drop or a framework-mandated shape from a genuine positive. A packet
  // without it asks the reviewer to pattern-match on shape, which is the failure the eval tests for.
  const fpStart = lines.findIndex((l) => l.startsWith("## FALSE POSITIVES"));
  if (fpStart < 0) throw new Error("quality-extras.txt has no '## FALSE POSITIVES' section — that section is the M6 negative class; refusing to assemble a packet that would invite shape-matching.");
  const fpRest = lines.slice(fpStart + 1).findIndex((l) => l.startsWith("## "));
  const fpEnd = fpRest < 0 ? lines.length : fpStart + 1 + fpRest;

  return [...lines.slice(start, end), "", ...lines.slice(fpStart, fpEnd)].join("\n").trim();
}

// #621: on a monorepo the source walk enumerates every workspace (21k+ files). When --hotspots is
// given the review is meant to be SCOPED to those files, but hotspots previously only reordered an
// all-files packet — so the packet ballooned to the whole tree (a 105MB / 21,386-file packet) while
// reporting "9 hotspots matched". Reordering keeps non-hotspot files by design (buildPacket, #442),
// so the scoping decision is made here, BEFORE buildPacket: with a hotspot list, keep only files
// whose target-relative path is in it; without one, keep everything (single-target behaviour).
export function scopePacketFiles(allFiles: string[], targetDir: string, hotspots: string[]): string[] {
  if (!hotspots.length) return allFiles;
  const wanted = new Set(hotspots);
  return allFiles.filter((f) => wanted.has(relative(targetDir, f)));
}

interface SimplifyPacket {
  brief: string;
  target: string;
  files: { path: string; source: string; hotspotRank?: number }[];
  hotspotRanked: boolean;
  manifests: { path: string; text: string }[];
  // #1083 — total source files under the target BEFORE --hotspots scoping (scopePacketFiles),
  // so renderPacket can disclose IN THE ARTIFACT when this packet is a subset. Previously this
  // was only logged to stderr (src/cli/simplify-scan.ts), which does not travel with --out.
  totalSourceFiles: number;
}

// hotspots: M3 hotspot ranking (repo-relative paths, hottest first — the same newline list M8's
// `pnpm mutation-scan --hotspots` consumes). When supplied, files that are hotspots lead the packet
// in rank order (#442) so the reviewer starts on the highest-churn×complexity code — the prime
// refactoring candidates M6 exists to name — instead of walking the tree in readdir order.
//
// manifestPaths: package.json file(s) under the target (root, plus workspace manifests) — #396.
// The rubric's "already in the dependency tree" class needs the reviewer to know what's installed;
// without this, every dep-tree claim in a packet is a guess (the miss that #396 measured: a hedge
// against `@supabase/ssr`, a library that was NOT in the target's tree, went unflagged as a guess).
export function buildPacket(
  briefText: string,
  targetDir: string,
  filePaths: string[],
  hotspots: string[] = [],
  manifestPaths: string[] = [],
  totalSourceFiles: number = filePaths.length,
): SimplifyPacket {
  const rankOf = new Map(hotspots.map((h, i) => [h, i + 1]));
  const files = filePaths.map((p) => {
    const path = relative(targetDir, p);
    return { path, source: readFileSync(p, "utf8"), hotspotRank: rankOf.get(path) };
  });
  if (rankOf.size) {
    // Stable sort (V8): hotspots ascending by rank, then non-hotspots in their original order.
    files.sort((a, b) => (a.hotspotRank ?? Infinity) - (b.hotspotRank ?? Infinity));
  }
  const manifests = manifestPaths.map((p) => ({ path: relative(targetDir, p), text: readFileSync(p, "utf8") }));
  return { brief: extractM6Brief(briefText), target: targetDir, files, hotspotRanked: rankOf.size > 0, manifests, totalSourceFiles };
}

export function renderPacket(packet: SimplifyPacket): string {
  const files = packet.files
    .map((f) => `### ${f.hotspotRank ? `[hotspot #${f.hotspotRank}] ` : ""}${f.path}\n\n\`\`\`ts\n${f.source}\n\`\`\``)
    .join("\n\n");
  const hotspotNote = packet.hotspotRanked
    ? "\nFiles are ordered by M3 hotspot rank (churn × complexity × coupling); the `[hotspot #N]`\nfiles are the highest-value refactoring candidates — review them first.\n"
    : "";
  // #396: fail loud rather than silently omit — a packet reviewer must be told when there is no
  // manifest to check, not left to assume dependency-tree claims are unverifiable for some other
  // reason (or worse, not notice at all).
  const manifestSection = packet.manifests.length
    ? packet.manifests.map((m) => `### ${m.path}\n\n\`\`\`json\n${m.text}\n\`\`\``).join("\n\n")
    : "No package.json was found under the scanned target. Treat every \"already in the dependency " +
      "tree\" claim as unverifiable and do not assert one.";
  // #1083 — this must be IN the artifact: the CLI's stderr scope line does not travel with --out,
  // so a reviewer/downstream consumer reading only packet.md never saw that most of the tree was
  // excluded, and the resulting verdict flowed into M6's record with no in-artifact caveat.
  const scopeNote = packet.totalSourceFiles > packet.files.length
    ? `\n**SCOPED REVIEW**: this packet covers ${packet.files.length} of ${packet.totalSourceFiles} source file(s) under the target (scoped to M3 hotspots, #621). The other ${packet.totalSourceFiles - packet.files.length} file(s) are NOT included here and are UNREVIEWED by this pass.\n`
    : "";
  return `# M6 — simplification / reuse review pass

Target: ${packet.target}
${scopeNote}

You are ONE OF TWO independent reviewers (docs/design/m6-simplification-eval.md §3.5, #813) —
M6's paid verdict is never asserted from a single pass. Do not consult, or attempt to infer,
the other reviewer's output; your two writeups are compared mechanically afterwards
(\`pnpm exec tsx src/cli/m6-agreement.ts <a.json> <b.json>\`), unanimous flags go to human
triage, and any split goes to a human adjudicator with both arguments — a split never goes
straight into a report. Apply the rubric below to the source that follows.

Three standing rules, from docs/design/m6-simplification-eval.md:

1. Reason about WHY the code is shaped the way it is, not just what shape it has. A hand-rolled
   primitive with a comment recording a deliberate tradeoff, and an abstraction a framework
   contract mandates, are NOT findings — see FALSE POSITIVES. Shape alone does not decide it.
2. M6's verdict is an opinion, not a fact. Say what you'd replace each item with and why; if you
   are not confident, say so rather than asserting. This output goes through human review before
   any client sees it.
3. The "already in the dependency tree" class is only appliable against the Dependency manifest
   section below — it is what's actually installed, not what a framework commonly implies. Don't
   assert dependency-tree membership from memory or convention.

## Verdict format — two-reviewer protocol (#813)

End your writeup with this machine-readable verdict block so independent passes can be
compared. Every file in this packet must appear exactly once: an unlisted file reads as
unreviewed and is reported loudly as uncompared — it does not default to "spare".

\`\`\`json
{
  "reviewer": "<model/session id unique to you>",
  "date": "<YYYY-MM-DD>",
  "target": "${packet.target}",
  "verdicts": [
    { "file": "<path exactly as its ### heading below>", "verdict": "flag | spare",
      "replacement": "<required when verdict is flag>",
      "confidence": "high | medium | low", "reason": "<one sentence>" }
  ]
}
\`\`\`

## The rubric

${packet.brief}

## Dependency manifest

${manifestSection}

## The source under review (${packet.files.length} file${packet.files.length === 1 ? "" : "s"})
${hotspotNote}
${files}
`;
}
