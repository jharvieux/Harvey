// Rendering: draft frontmatter+body -> tracker payloads, the template section-schema lint, content
// hashing for idempotency, and the results summary table (design §4.2, §8.3, §9). The builder treats
// a template's `##` headings as the section schema for its "draft is missing ## Acceptance criteria"
// lint — it never hardcodes section content.

import { createHash } from "node:crypto";

export function contentHash(body: string): string {
  return `sha256:${createHash("sha256").update(body, "utf8").digest("hex")}`;
}

function templateSections(templateBody: string): string[] {
  return templateBody
    .split("\n")
    .filter((line) => line.startsWith("## "))
    .map((line) => line.slice(3).trim());
}

// Sections the template defines that the draft is missing. Empty array = draft conforms.
export function missingSections(templateBody: string, draftBody: string): string[] {
  const present = new Set(templateSections(draftBody));
  return templateSections(templateBody).filter((section) => !present.has(section));
}

// Story body for the tracker: the draft body plus "Blocked by" reference lines for any dependency
// that has already been published (GitHub renders `#<n>` as a cross-reference). The epic linkage is
// the adapter's job (task-list line on the epic), so we don't duplicate it here.
export function renderStoryBody(draftBody: string, dependsOnRefs: string[]): string {
  if (dependsOnRefs.length === 0) return draftBody;
  const blockers = dependsOnRefs.map((ref) => `- Blocked by ${ref}`).join("\n");
  return `${draftBody.trimEnd()}\n\n## Dependencies\n${blockers}\n`;
}

export interface SummaryRow {
  seq: string; // "—" for the epic, "01".. for stories
  title: string;
  type: "epic" | "story";
  size: string; // "—" | "S" | "M" | "L"
  ref: string;
  brief: string; // "—" | "linked ✓"
}

export function renderSummary(rows: SummaryRow[], epicUrl: string): string {
  const header = ["#", "Item", "Type", "Size", "Ref", "Brief"];
  const cols = [4, 34, 7, 5, 26, 10];
  const line = (cells: string[]) => cells.map((c, i) => c.padEnd(cols[i] ?? c.length)).join(" ").trimEnd();
  const out = [
    line(header),
    cols.map((w) => "─".repeat(w)).join(" "),
    ...rows.map((r) => line([r.seq, r.title, r.type, r.size, r.ref, r.brief])),
    "",
    `Epic: ${epicUrl}`,
    "",
  ];
  return out.join("\n");
}
