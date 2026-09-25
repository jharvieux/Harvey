import { mkdtempSync } from "node:fs";
import { readNamesSafe } from "../fs-walk.js";
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
  acceptStory,
  consistencyPass,
  draftEpic,
  fanOutStories,
  reviseArtifact,
  runClarify,
  skipStory,
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

function modelWith(overrides: Partial<ModelClient>): ModelClient {
  return Object.assign(Object.create(model) as ModelClient, overrides);
}

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

  it("persists a resumable clarify checkpoint when the model throws", async () => {
    let attempts = 0;
    const failsOnce = modelWith({
      async clarify(input) {
        attempts++;
        if (attempts === 1) throw new Error("model unavailable");
        return model.clarify(input);
      },
    });
    await expect(runClarify(dir, session, failsOnce, async () => "defaults")).rejects.toThrow("model unavailable");
    expect(loadSession(dir).state).toBe("clarify");
    expect(readFileRaw(dir, "intake.md")).toContain("Clarifying Q&A");

    const resumed = loadSession(dir);
    await runClarify(dir, resumed, failsOnce, async () => "defaults");
    expect(loadSession(dir).state).toBe("epic-draft");
    expect(attempts).toBe(2);
  });

  it("guards an illegal draft before the model or an accepted artifact can be touched", async () => {
    writeDraft(dir, "epic.md", {
      data: { kind: "epic", epic: session.slug, title: "Accepted", status: "accepted" },
      body: "# Epic: Accepted\n",
    });
    const before = readFileRaw(dir, "epic.md");
    let modelCalls = 0;
    const countingModel = modelWith({ async draftEpic() { modelCalls++; return "# replacement"; } });
    await expect(draftEpic(dir, session, countingModel, templates)).rejects.toThrow(/invalid transition/);
    expect(modelCalls).toBe(0);
    expect(readFileRaw(dir, "epic.md")).toBe(before);
    expect(loadSession(dir).state).toBe("intake");
  });

  it("guards an illegal accept before changing frontmatter or durable session state", () => {
    writeDraft(dir, "epic.md", {
      data: { kind: "epic", epic: session.slug, title: "Existing", status: "in-review" },
      body: "# Epic: Existing\n",
    });
    const before = readFileRaw(dir, "epic.md");
    expect(() => acceptEpic(dir, session)).toThrow(/not reviewable/);
    expect(readFileRaw(dir, "epic.md")).toBe(before);
    expect(loadSession(dir).state).toBe("intake");
  });

  it("rejects an unknown durable session state instead of treating it as resumable", () => {
    writeFile(dir, "session.json", `${JSON.stringify({ ...session, state: "success-ish" })}\n`);
    expect(() => loadSession(dir)).toThrow(/invalid state.*success-ish/);
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
    expect(loadSession(dir).state).toBe("stories-review");
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

  it("rejects malformed/duplicate manifests and model failures without partial files or success state", async () => {
    const cases: { name: string; model: ModelClient; confirm?: (entries: StoryManifestEntry[]) => Promise<StoryManifestEntry[]> }[] = [
      { name: "non-array", model: modelWith({ async storyManifest() { return null as never; } }) },
      { name: "bad entry", model: modelWith({ async storyManifest() { return [{ title: "", scope: "scope", sizing: "M" }] as StoryManifestEntry[]; } }) },
      { name: "duplicate slug", model: modelWith({ async storyManifest() { return [
        { title: "Same title", scope: "one", sizing: "M" },
        { title: "same-title", scope: "two", sizing: "S" },
      ]; } }) },
      { name: "manifest exception", model: modelWith({ async storyManifest() { throw new Error("manifest unavailable"); } }) },
      { name: "draft exception", model: modelWith({ async draftStory(input) {
        if (input.entry.title === "Permission filtering") throw new Error("draft unavailable");
        return model.draftStory(input);
      } }) },
      { name: "malformed draft", model: modelWith({ async draftStory(input) {
        if (input.entry.title === "Permission filtering") return { body: "", brief: "brief" };
        return model.draftStory(input);
      } }) },
      { name: "malformed confirmed selection", model, confirm: async () => [] },
    ];

    for (const testCase of cases) {
      expect(readNamesSafe(join(dir, "stories")), testCase.name).toEqual([]);
      await expect(fanOutStories(dir, session, testCase.model, templates, testCase.confirm ?? (async (entries) => entries)), testCase.name)
        .rejects.toThrow();
      expect(readNamesSafe(join(dir, "stories")), testCase.name).toEqual([]);
      expect(readNamesSafe(join(dir, "briefs")), testCase.name).toEqual([]);
      expect(session.state, testCase.name).toBe("stories-fan-out");
      expect(loadSession(dir).state, testCase.name).toBe("stories-fan-out");
    }
  });

  it("persists the valid review path and advances when the final story is skipped", async () => {
    await fanOutStories(dir, session, model, templates, async (entries) => entries);
    const [first, second] = session.stories;
    acceptStory(dir, session, first!.file);
    expect(loadSession(dir).state).toBe("stories-review");
    expect(readDraft(dir, first!.file).data.status).toBe("accepted");
    skipStory(dir, session, second!.file);
    expect(loadSession(dir).state).toBe("publish");
    expect(readDraft(dir, second!.file).data.status).toBe("skipped");
  });

  it("does not overwrite an accepted story when fan-out is invoked from a disallowed state", async () => {
    await fanOutStories(dir, session, model, templates, async (entries) => entries);
    const accepted = session.stories[0]!;
    acceptStory(dir, session, accepted.file);
    const before = readFileRaw(dir, accepted.file);
    let modelCalls = 0;
    const countingModel = modelWith({ async storyManifest() { modelCalls++; return []; } });
    await expect(fanOutStories(dir, session, countingModel, templates, async (entries) => entries)).rejects.toThrow(/invalid transition/);
    expect(modelCalls).toBe(0);
    expect(readFileRaw(dir, accepted.file)).toBe(before);
    expect(loadSession(dir).state).toBe("stories-review");
  });
});

describe("frontmatter failures through the session consumer", () => {
  it("does not accept or rewrite an epic with missing, malformed, or duplicate frontmatter", async () => {
    await runClarify(dir, session, model, async () => "defaults");
    await draftEpic(dir, session, model, templates);
    const malformed = [
      "# missing\n",
      "---\nstatus: in-review\npublished:\n  ref: one\n    url: changed\n---\n# body\n",
      "---\ntitle malformed\n---\n# body\n",
      "---\ntitle: one\ntitle: two\nstatus: in-review\n---\n# body\n",
    ];
    for (const raw of malformed) {
      writeFile(dir, "epic.md", raw);
      await expect(Promise.resolve().then(() => acceptEpic(dir, session))).rejects.toThrow(/frontmatter|malformed|duplicate/);
      expect(readFileRaw(dir, "epic.md")).toBe(raw);
      expect(session.state).toBe("epic-review");
      expect(loadSession(dir).state).toBe("epic-review");
    }
  });
});

describe("generated story metadata through durable session fan-out (#2081)", () => {
  it.each(['Two\nlines', 'Bad\nstatus: accepted', 'Title with "quotes"', 'C:\\notes\\file', 'true', '1.25'])("retains the exact title %s through write and consistency reads", async (title) => {
    await runClarify(dir, session, model, async () => "defaults");
    await draftEpic(dir, session, model, templates);
    acceptEpic(dir, session);
    const generated = modelWith({ async storyManifest() {
      return [{ title: "First", scope: "first", sizing: "M" }, { title, scope: "second", sizing: "M" }];
    } });
    await fanOutStories(dir, session, generated, templates, async (entries) => entries);
    const persisted = loadSession(dir);
    expect(persisted.state).toBe("stories-review");
    expect(persisted.stories).toHaveLength(2);
    expect(readNamesSafe(join(dir, "stories")).sort()).toEqual(persisted.stories.map((story) => story.file.slice("stories/".length)).sort());
    expect(readNamesSafe(join(dir, "briefs"))).toHaveLength(2);
    const draft = readDraft(dir, persisted.stories[1]!.file);
    expect(draft.data.title).toBe(title);
    expect(draft.data.status).toBe("draft");
    expect(draft.body).toContain(title);
  });
});
