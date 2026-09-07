export interface MemoryFiles {
  memory: string;
  index: string;
  archive: string;
}

export interface MemoryIssue {
  code: string;
  message: string;
}

interface MemoryPopulation {
  memory: number;
  index: number;
  archive: number;
}

interface MemoryValidationResult {
  issues: MemoryIssue[];
  population: MemoryPopulation;
}

interface BranchMemoryState {
  /** MEMORY.md at the merge base, or null when the file did not exist there. */
  ancestorMemory: string | null;
  /** MEMORY.md at the target base ref, or null when the file does not exist there. */
  targetBaseMemory: string | null;
  /** The working tree's current MEMORY.md. */
  currentMemory: string;
}

interface BranchMemoryValidationResult {
  addedIds: string[];
  issues: MemoryIssue[];
}

interface DecisionHeader {
  id: string;
  number: number;
  date: string;
  title: string;
  canonical: string;
  line: number;
  offset: number;
}

interface DecisionBlock {
  header: DecisionHeader;
  raw: string;
}

interface ParsedFile {
  headers: DecisionHeader[];
  issues: MemoryIssue[];
}

const MEMORY_HEADER = /^## (D-(\d{3,})) — (\d{4}-\d{2}-\d{2}) — (\S(?:.*\S)?)$/gm;
const MEMORY_HEADER_CANDIDATE = /^## D-[^\n]*$/gm;
const INDEX_ENTRY = /^- (D-(\d{3,})) — (\d{4}-\d{2}-\d{2}) — (\S(?:.*\S)?)$/gm;
const INDEX_ENTRY_CANDIDATE = /^- D-[^\n]*$/gm;
const ENTRIES_MARKER = /^## Entries$/gm;

function issue(code: string, message: string): MemoryIssue {
  return { code, message };
}

function lineNumber(text: string, offset: number): number {
  return text.slice(0, offset).split("\n").length;
}

function validDate(value: string): boolean {
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

function parseHeaders(text: string, kind: "memory" | "index", source: string): ParsedFile {
  const exact = kind === "memory" ? MEMORY_HEADER : INDEX_ENTRY;
  const candidate = kind === "memory" ? MEMORY_HEADER_CANDIDATE : INDEX_ENTRY_CANDIDATE;
  const prefix = kind === "memory" ? "## " : "- ";
  const headers: DecisionHeader[] = [];
  const issues: MemoryIssue[] = [];
  const exactOffsets = new Set<number>();

  exact.lastIndex = 0;
  for (const match of text.matchAll(exact)) {
    const offset = match.index;
    exactOffsets.add(offset);
    const digits = match[2]!;
    const number = Number(digits);
    const date = match[3]!;
    const title = match[4]!;
    const line = lineNumber(text, offset);

    if (number < 1 || String(number).padStart(3, "0") !== digits) {
      issues.push(issue("invalid-decision-id", `${source}:${line} has a non-canonical decision id ${match[1]}.`));
    }
    if (!validDate(date)) {
      issues.push(issue("invalid-decision-date", `${source}:${line} has an invalid calendar date ${date}.`));
    }
    if (title.length > 70) {
      issues.push(issue("decision-title-too-long", `${source}:${line} title is ${title.length} characters; the limit is 70.`));
    }

    headers.push({
      id: match[1]!,
      number,
      date,
      title,
      canonical: `${match[1]} — ${date} — ${title}`,
      line,
      offset,
    });
  }

  candidate.lastIndex = 0;
  for (const match of text.matchAll(candidate)) {
    if (!exactOffsets.has(match.index)) {
      issues.push(
        issue(
          kind === "memory" ? "malformed-memory-header" : "malformed-index-entry",
          `${source}:${lineNumber(text, match.index)} is not '${prefix}D-NNN — YYYY-MM-DD — title'.`,
        ),
      );
    }
  }

  const byId = new Map<string, number[]>();
  for (const header of headers) {
    const lines = byId.get(header.id) ?? [];
    lines.push(header.line);
    byId.set(header.id, lines);
  }
  for (const [id, lines] of byId) {
    if (lines.length > 1) {
      issues.push(issue("duplicate-decision-id", `${source} contains ${id} more than once (lines ${lines.join(", ")}).`));
    }
  }

  for (let i = 1; i < headers.length; i += 1) {
    const previous = headers[i - 1]!;
    const current = headers[i]!;
    if (previous.number <= current.number) {
      issues.push(
        issue(
          "decision-order",
          `${source}:${current.line} is not newest-first: ${current.id} follows ${previous.id}.`,
        ),
      );
    }
  }

  return { headers, issues };
}

function decisionBlocks(text: string, source: string): { blocks: DecisionBlock[]; preamble: string; issues: MemoryIssue[] } {
  const parsed = parseHeaders(text, "memory", source);
  const blocks = parsed.headers.map((header, index) => ({
    header,
    raw: text.slice(header.offset, parsed.headers[index + 1]?.offset ?? text.length),
  }));
  const preamble = text.slice(0, parsed.headers[0]?.offset ?? text.length);
  return { blocks, preamble, issues: parsed.issues };
}

function validateEntryBodies(blocks: readonly DecisionBlock[], source: string): MemoryIssue[] {
  const issues: MemoryIssue[] = [];
  for (const { header, raw } of blocks) {
    const decision = raw.indexOf("\n\n**Decision.** ");
    const why = raw.indexOf("\n\n**Why.**\n- ");
    const rejected = raw.indexOf("\n\n**Rejected.**\n- ");
    const related = raw.indexOf("\n\n**Related artifacts.** ");
    if (!(decision >= 0 && decision < why && why < rejected && rejected < related)) {
      issues.push(
        issue(
          "decision-entry-shape",
          `${source}:${header.line} ${header.id} must contain Decision, bulleted Why, bulleted Rejected, and Related artifacts in that order.`,
        ),
      );
    }
    if (!/\n\n---\n*$/.test(raw)) {
      issues.push(issue("decision-entry-separator", `${source}:${header.line} ${header.id} must end with a horizontal-rule separator.`));
    }
  }
  return issues;
}

function markerIssues(text: string, source: string): MemoryIssue[] {
  ENTRIES_MARKER.lastIndex = 0;
  const count = [...text.matchAll(ENTRIES_MARKER)].length;
  return count === 1 ? [] : [issue("entries-marker", `${source} must contain exactly one '## Entries' marker; found ${count}.`)];
}

/** Validate the three files as one self-consistent, newest-first decision ledger. */
export function validateMemorySnapshot(files: MemoryFiles): MemoryValidationResult {
  const memory = decisionBlocks(files.memory, "MEMORY.md");
  const index = parseHeaders(files.index, "index", "MEMORY-INDEX.md");
  const archive = parseHeaders(files.archive, "index", "MEMORY-INDEX-ARCHIVE.md");
  const issues = [
    ...memory.issues,
    ...index.issues,
    ...archive.issues,
    ...validateEntryBodies(memory.blocks, "MEMORY.md"),
    ...markerIssues(files.index, "MEMORY-INDEX.md"),
    ...markerIssues(files.archive, "MEMORY-INDEX-ARCHIVE.md"),
  ];

  if (memory.blocks.length === 0) {
    issues.push(issue("empty-memory", "MEMORY.md must contain at least one durable decision entry."));
  }

  const indexIds = new Set(index.headers.map((entry) => entry.id));
  const archiveIds = new Set(archive.headers.map((entry) => entry.id));
  const overlap = [...indexIds].filter((id) => archiveIds.has(id));
  if (overlap.length > 0) {
    issues.push(
      issue(
        "index-archive-overlap",
        `Decision ids must live in exactly one index; present in both: ${overlap.join(", ")}.`,
      ),
    );
  }

  const memoryById = new Map(memory.blocks.map(({ header }) => [header.id, header]));
  const allIndexHeaders = [...index.headers, ...archive.headers];
  const allIndexIds = new Set(allIndexHeaders.map((entry) => entry.id));
  const onlyInMemory = [...memoryById.keys()].filter((id) => !allIndexIds.has(id));
  const onlyInIndex = [...allIndexIds].filter((id) => !memoryById.has(id));
  if (onlyInMemory.length > 0 || onlyInIndex.length > 0) {
    issues.push(
      issue(
        "memory-index-mismatch",
        [
          onlyInMemory.length > 0 ? `missing from both indexes: ${onlyInMemory.join(", ")}` : "",
          onlyInIndex.length > 0 ? `missing from MEMORY.md: ${onlyInIndex.join(", ")}` : "",
        ]
          .filter(Boolean)
          .join("; "),
      ),
    );
  }

  for (const indexed of allIndexHeaders) {
    const logged = memoryById.get(indexed.id);
    if (logged && logged.canonical !== indexed.canonical) {
      issues.push(
        issue(
          "index-metadata-mismatch",
          `${indexed.id} metadata differs: MEMORY.md has '${logged.canonical}', index has '${indexed.canonical}'.`,
        ),
      );
    }
  }

  return {
    issues,
    population: {
      memory: memory.blocks.length,
      index: index.headers.length,
      archive: archive.headers.length,
    },
  };
}

function sequentialPrependIssues(ancestor: readonly DecisionBlock[], added: readonly DecisionBlock[]): MemoryIssue[] {
  if (added.length === 0) return [];
  const priorMaximum = ancestor.reduce((maximum, entry) => Math.max(maximum, entry.header.number), 0);
  const expected = Array.from({ length: added.length }, (_, index) => priorMaximum + added.length - index);
  const actual = added.map((entry) => entry.header.number);
  if (actual.every((number, index) => number === expected[index])) return [];
  return [
    issue(
      "decision-number-sequence",
      `New decisions must claim the next number(s), newest-first; expected ${expected.map((n) => `D-${String(n).padStart(3, "0")}`).join(", ")}, found ${added.map((entry) => entry.header.id).join(", ")}.`,
    ),
  ];
}

/**
 * Validate append-only history and detect a number independently claimed on the target base.
 * This is pure: callers provide the three file versions obtained from Git/the working tree.
 */
export function validateBranchMemory(state: BranchMemoryState): BranchMemoryValidationResult {
  const current = decisionBlocks(state.currentMemory, "working-tree MEMORY.md");
  const ancestor = state.ancestorMemory === null ? null : decisionBlocks(state.ancestorMemory, "merge-base MEMORY.md");
  const target = state.targetBaseMemory === null ? null : decisionBlocks(state.targetBaseMemory, "target-base MEMORY.md");
  const issues = [...current.issues];

  if (ancestor) issues.push(...ancestor.issues.map((entry) => issue("invalid-merge-base-memory", entry.message)));
  if (target) issues.push(...target.issues.map((entry) => issue("invalid-target-base-memory", entry.message)));

  let added: DecisionBlock[] = [];
  if (ancestor === null) {
    added = current.blocks;
  } else {
    const prefixLength = current.blocks.length - ancestor.blocks.length;
    const suffix = prefixLength < 0 ? [] : current.blocks.slice(prefixLength);
    const priorEntriesPreserved =
      prefixLength >= 0 &&
      suffix.length === ancestor.blocks.length &&
      suffix.every((entry, index) => entry.raw === ancestor.blocks[index]!.raw);
    const preamblePreserved = current.preamble === ancestor.preamble;

    if (!preamblePreserved || !priorEntriesPreserved) {
      issues.push(
        issue(
          "memory-history-rewrite",
          "MEMORY.md changed content that existed at the merge base; durable history permits only complete new entries before the prior newest entry.",
        ),
      );
    } else {
      added = current.blocks.slice(0, prefixLength);
    }
  }

  issues.push(...sequentialPrependIssues(ancestor?.blocks ?? [], added));

  const targetIds = new Set((target?.blocks ?? []).map((entry) => entry.header.id));
  const collisions = [...new Set(added.map((entry) => entry.header.id).filter((id) => targetIds.has(id)))];
  if (collisions.length > 0) {
    issues.push(
      issue(
        "base-decision-collision",
        `This branch independently added decision id(s) already present on the target base: ${collisions.join(", ")}. Rebase, then renumber only the branch-local entries.`,
      ),
    );
  }

  return { addedIds: added.map((entry) => entry.header.id), issues };
}
