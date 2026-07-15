// M6 (simplification / reuse) runner. M6 has no mechanical detector and never will — its output
// is a reviewer's judgment, not a Finding[] a tool can assert (docs/design/m6-simplification-eval.md
// §1/§5). So this does NOT score anything: it assembles the M6 brief + the target's source into one
// review packet, which a reviewer (LLM or human) then reads. That is the whole runner.
//
// Why it exists at all: before this, M6's documented entry point was "the /simplify skill", which is
// not installed — so M6's execution path was "a human remembers to invoke a tool that isn't there."
// It never ran, in any engagement, since it was defined (#266). A packet you can produce on demand
// is the minimum honest replacement: it can't make the reviewer think, but it can stop M6's absence
// from being invisible.

import { readFileSync } from "node:fs";
import { relative } from "node:path";

// The brief's M6 section only — the file also carries M5/M8 sections that would dilute the pass.
// Delimited by the "## " headings in docs/quality-extras.txt.
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

interface SimplifyPacket {
  brief: string;
  files: { path: string; source: string }[];
}

export function buildPacket(briefText: string, targetDir: string, filePaths: string[]): SimplifyPacket {
  return {
    brief: extractM6Brief(briefText),
    files: filePaths.map((p) => ({ path: relative(targetDir, p), source: readFileSync(p, "utf8") })),
  };
}

export function renderPacket(packet: SimplifyPacket): string {
  const files = packet.files.map((f) => `### ${f.path}\n\n\`\`\`ts\n${f.source}\n\`\`\``).join("\n\n");
  return `# M6 — simplification / reuse review pass

You are the reviewer. Apply the rubric below to the source that follows.

Two standing rules, from docs/design/m6-simplification-eval.md:

1. Reason about WHY the code is shaped the way it is, not just what shape it has. A hand-rolled
   primitive with a comment recording a deliberate tradeoff, and an abstraction a framework
   contract mandates, are NOT findings — see FALSE POSITIVES. Shape alone does not decide it.
2. M6's verdict is an opinion, not a fact. Say what you'd replace each item with and why; if you
   are not confident, say so rather than asserting. This output goes through human review before
   any client sees it.

## The rubric

${packet.brief}

## The source under review (${packet.files.length} file${packet.files.length === 1 ? "" : "s"})

${files}
`;
}
