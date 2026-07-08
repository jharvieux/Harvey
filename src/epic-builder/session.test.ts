import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type {
  ClarifyQuestion,
  DraftSession,
  DraftStoryInput,
  DraftStoryResult,
  ModelClient,
  ReviseInput,
  StoryManifestEntry,
} from "./types.js";
import {
  acceptEpic,
  consistencyPass,
  draftEpic,
  fanOutStories,
  reviseArtifact,
  runClarify,
  type Templates,
} from "./session.js";
import { createWorkspace, loadSession, readDraft, readFileRaw, writeDraft, writeFile } from "./workspace.js";

const templates: Templates = {
  epic: "---\nartifact: epic\n---\n# Epic: {title}\n\n## Goal\nOne or two sentences: the user/business problem and the outcome this epic delivers.\n\n## In Scope\n- Export endpoint\n- Permission filtering\n",
  story: "---\nartifact: user-story\n---\n# Story: {title}\n\n## Acceptance Criteria\n1. TODO\n\n## Tests to Build\n- TODO\n",
  brief: "---\nartifact: implementation-brief\n---\n# Implementation Brief: {title}\n\n## Objective\nTODO\n",
};

// Deterministic fake model. Each method returns canned, assertable output so tests exercise the
// controller's wiring, not a live model.
class FakeModel implements ModelClient {
  reviseCalls: ReviseInput[] = [];
  async clarify(input: { round: number }): Promise<ClarifyQuestion[]> {
    return input.round === 1
      ? [{ question: "Who triggers export?", assumption: "org admins" }]
      : [];
  }
  async draftEpic(): Promise<string> {
    return "# Epic: CSV export\n\n## Goal\nExport findings as CSV.\n\n## In Scope\n- Export endpoint\n- Permission filtering\n";
  }
  async storyManifest(): Promise<StoryManifestEntry[]> {
    return [
      { title: "Export endpoint", scope: "the endpoint", sizing: "M" },
      { title: "Permission filtering", scope: "rls filter", sizing: "M" },
    ];
  }
  async draftStory(input: DraftStoryInput): Promise<DraftStoryResult> {
    return {
      body: `# Story: ${input.entry.title}\n\n## Acceptance Criteria\n1. Works\n\n## Tests to Build\n- t1\n`,
      brief: `# Implementation Brief: ${input.entry.title}\n\n## Objective\nDo it.\n`,
    };
  }
  async revise(input: ReviseInput): Promise<string> {
    this.reviseCalls.push(input);
    // Simulate an AI that resolves the comment: it strips the comment block.
    return input.current.replace(/\n> \[!comment\][\s\S]*?(?=\n##|\n?$)/g, "\n") + (input.instruction ? `\n<!-- ${input.instruction} -->\n` : "");
  }
}

let dir: string;
let session: DraftSession;
const model = new FakeModel();

beforeEach(() => {
  const cwd = mkdtempSync(join(tmpdir(), "epic-test-"));
  const created = createWorkspace(cwd, "Customers should be able to export audit findings as CSV");
  dir = created.dir;
  session = created.session;
});

afterEach(() => {
  model.reviseCalls = [];
});

describe("intake -> clarify -> epic draft", () => {
  it("persists the Q&A transcript and advances to epic-review", async () => {
    await runClarify(dir, session, model, async () => "1: admins only");
    expect(session.clarifyRounds).toBe(1);
    expect(readFileRaw(dir, "intake.md")).toContain("1: admins only");

    await draftEpic(dir, session, model, templates);
    expect(session.state).toBe("epic-review");
    const epic = readDraft(dir, "epic.md");
    expect(epic.data.kind).toBe("epic");
    expect(epic.data.title).toBe("CSV export");
    expect(epic.data.status).toBe("in-review");
    // The persisted session reflects the same position (design §3.2).
    expect(loadSession(dir).state).toBe("epic-review");
  });
});

describe("revision protocol (diff-before-apply)", () => {
  beforeEach(async () => {
    await runClarify(dir, session, model, async () => "defaults");
    await draftEpic(dir, session, model, templates);
  });

  it("applies a comment-driven revision only after the diff is confirmed", async () => {
    const withComment = readFileRaw(dir, "epic.md").replace(
      "## In Scope",
      "> [!comment]\n> Tighten the goal.\n\n## In Scope",
    );
    writeFile(dir, "epic.md", withComment);

    const result = await reviseArtifact(dir, session, model, "epic.md", undefined, async () => true);
    expect(result.applied).toBe(true);
    expect(result.unresolvedComments).toBe(false);
    expect(model.reviseCalls[0]?.comments).toEqual(["Tighten the goal."]);
    expect(readFileRaw(dir, "epic.md")).not.toContain("[!comment]");
    expect(session.epic.revisions).toBe(1);
  });

  it("discards the revision and leaves the file untouched when rejected", async () => {
    const before = readFileRaw(dir, "epic.md");
    const result = await reviseArtifact(dir, session, model, "epic.md", "make it punchier", async () => false);
    expect(result.applied).toBe(false);
    expect(readFileRaw(dir, "epic.md")).toBe(before);
    expect(session.epic.revisions).toBe(0);
  });
});

describe("story fan-out + consistency pass", () => {
  beforeEach(async () => {
    await runClarify(dir, session, model, async () => "defaults");
    await draftEpic(dir, session, model, templates);
    acceptEpic(dir, session);
  });

  it("drafts a story + brief per manifest entry and numbers sequences", async () => {
    await fanOutStories(dir, session, model, templates, async (entries) => entries);
    expect(session.state).toBe("stories-review");
    expect(session.stories).toHaveLength(2);
    for (const s of session.stories) {
      const doc = readDraft(dir, s.file);
      expect(doc.data.kind).toBe("story");
      expect(typeof doc.data.sequence).toBe("number");
    }
    const briefs = session.stories.map((s) => s.file.replace("stories/", "briefs/").replace(".md", ".brief.md"));
    for (const b of briefs) expect(readFileRaw(dir, b)).toContain("Implementation Brief");
  });

  it("honours a trimmed manifest", async () => {
    await fanOutStories(dir, session, model, templates, async (entries) => entries.slice(0, 1));
    expect(session.stories).toHaveLength(1);
  });

  it("flags an oversized story in the consistency report", async () => {
    await fanOutStories(dir, session, model, templates, async (entries) => entries.slice(0, 1));
    const file = session.stories[0]!.file;
    const doc = readDraft(dir, file);
    doc.body = `# Story\n\n## Acceptance Criteria\n${Array.from({ length: 9 }, (_, i) => `${i + 1}. ac`).join("\n")}\n\n## Tests to Build\n- t\n`;
    writeDraft(dir, file, doc);
    const report = consistencyPass(dir, session, templates);
    expect(report.some((r) => /SPIDR split/.test(r))).toBe(true);
  });
});
