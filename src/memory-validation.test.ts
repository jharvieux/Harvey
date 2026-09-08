import { describe, expect, it } from "vitest";
import { validateBranchMemory, validateMemorySnapshot, type MemoryFiles } from "./memory-validation.js";

function id(number: number): string {
  return `D-${String(number).padStart(3, "0")}`;
}

function entry(number: number, title = `Decision ${number}`, detail = `Choose option ${number}.`): string {
  return [
    `## ${id(number)} — 2026-09-07 — ${title}`,
    "",
    `**Decision.** ${detail}`,
    "",
    "**Why.**",
    "- It preserves the measured invariant.",
    "",
    "**Rejected.**",
    "- *Do nothing.* It would leave the invariant unenforced.",
    "",
    `**Related artifacts.** \`src/example-${number}.ts\`.`,
    "",
    "---",
    "",
  ].join("\n");
}

function memory(entries: readonly string[]): string {
  return `# Test memory\n\nNewest first.\n\n---\n\n${entries.join("\n")}`;
}

function index(entries: readonly { number: number; title?: string }[], archive = false): string {
  const lines = entries.map(({ number, title = `Decision ${number}` }) => `- ${id(number)} — 2026-09-07 — ${title}`);
  return `# Test ${archive ? "archive" : "index"}\n\n## Entries\n\n${lines.join("\n")}${lines.length > 0 ? "\n" : ""}`;
}

function snapshot(active = [{ number: 3 }, { number: 2 }], archived = [{ number: 1 }]): MemoryFiles {
  return {
    memory: memory([entry(3), entry(2), entry(1)]),
    index: index(active),
    archive: index(archived, true),
  };
}

function codes(issues: readonly { code: string }[]): string[] {
  return issues.map((entry) => entry.code);
}

describe("durable memory snapshot validation", () => {
  it("accepts a newest-first log mirrored across disjoint lean and archive indexes", () => {
    expect(validateMemorySnapshot(snapshot())).toEqual({
      issues: [],
      population: { memory: 3, index: 2, archive: 1 },
    });
  });

  it("NEGATIVE CONTROL — duplicate decision ids fail instead of collapsing in a set", () => {
    const files = snapshot();
    files.memory = memory([entry(3), entry(3, "A second claim"), entry(2), entry(1)]);
    expect(codes(validateMemorySnapshot(files).issues)).toContain("duplicate-decision-id");
  });

  it("NEGATIVE CONTROL — a one-sided log/index update fails", () => {
    const files = snapshot();
    files.index = index([{ number: 3 }]);
    expect(codes(validateMemorySnapshot(files).issues)).toContain("memory-index-mismatch");
  });

  it("NEGATIVE CONTROL — an archive copy that remains in the lean index fails", () => {
    const files = snapshot();
    files.index = index([{ number: 3 }, { number: 2 }, { number: 1 }]);
    expect(codes(validateMemorySnapshot(files).issues)).toContain("index-archive-overlap");
  });

  it("rejects an index line whose date or summary no longer mirrors the full header", () => {
    const files = snapshot();
    files.index = index([{ number: 3, title: "Drifted summary" }, { number: 2 }]);
    expect(codes(validateMemorySnapshot(files).issues)).toContain("index-metadata-mismatch");
  });
});

describe("append-only and target-base validation", () => {
  const first = entry(1);
  const second = entry(2);

  it("accepts complete sequential entries prepended ahead of byte-identical history", () => {
    expect(
      validateBranchMemory({
        ancestorMemory: memory([first]),
        targetBaseMemory: memory([first]),
        currentMemory: memory([second, first]),
      }),
    ).toEqual({ addedIds: ["D-002"], issues: [] });
  });

  it("NEGATIVE CONTROL — rewriting one byte of an existing entry fails", () => {
    const rewritten = first.replace("Choose option 1.", "Choose a different option.");
    const result = validateBranchMemory({
      ancestorMemory: memory([first]),
      targetBaseMemory: memory([first]),
      currentMemory: memory([rewritten]),
    });
    expect(codes(result.issues)).toContain("memory-history-rewrite");
  });

  it("NEGATIVE CONTROL — a sibling claim of the same new id fails", () => {
    const result = validateBranchMemory({
      ancestorMemory: memory([first]),
      targetBaseMemory: memory([entry(2, "Sibling decision"), first]),
      currentMemory: memory([second, first]),
    });
    expect(codes(result.issues)).toContain("base-decision-collision");
    expect(result.addedIds).toEqual(["D-002"]);
  });

  it("requires the next sequential number rather than an arbitrary free id", () => {
    const result = validateBranchMemory({
      ancestorMemory: memory([first]),
      targetBaseMemory: memory([first]),
      currentMemory: memory([entry(3), first]),
    });
    expect(codes(result.issues)).toContain("decision-number-sequence");
  });
});
