import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AttachedRef, CreatedRef, ItemInput, Tracker, UpdateStoryPatch } from "../trackers/types.js";
import { GitHubTracker } from "../trackers/github.js";
import { NoopTracker, publish } from "./publish.js";
import type { DraftSession } from "./types.js";
import { createWorkspace, readDraft, writeDraft, writeFile } from "./workspace.js";

// A recording fake of the delivered #22/#50 Tracker interface. `failTitles` lets a test simulate a
// mid-publish adapter failure to prove idempotent recovery. `findByMarker` searches the descriptions
// of everything created so far — a realistic stand-in for a tracker's full-text body search — so
// tests can simulate "created remotely on a prior run, marker present" by seeding the tracker
// directly before calling publish().
class FakeTracker implements Tracker {
  epics: ItemInput[] = [];
  stories: { input: ItemInput; epicId: string }[] = [];
  labels: { id: string; labels: string[] }[] = [];
  briefs: string[] = [];
  updates: { id: string; patch: UpdateStoryPatch }[] = [];
  failTitles = new Set<string>();
  #n = 0;
  #createdByDescription: { description: string; ref: CreatedRef }[] = [];
  async createEpic(input: ItemInput): Promise<CreatedRef> {
    this.epics.push(input);
    return this.#record(input, "E");
  }
  async createStory(input: ItemInput, epicId: string): Promise<CreatedRef> {
    if (this.failTitles.has(input.title)) throw new Error(`simulated failure creating ${input.title}`);
    this.stories.push({ input, epicId });
    return this.#record(input, "S");
  }
  async findByMarker(marker: string): Promise<CreatedRef | null> {
    return this.#createdByDescription.find((c) => c.description.includes(marker))?.ref ?? null;
  }
  async setLabels(id: string, labels: string[]): Promise<void> {
    this.labels.push({ id, labels });
  }
  async setEstimate(): Promise<void> {}
  async attachBrief(id: string, briefMarkdown: string): Promise<AttachedRef> {
    this.briefs.push(briefMarkdown);
    return { url: `https://tracker.test/brief/${id}` };
  }
  async updateStory(id: string, patch: UpdateStoryPatch): Promise<void> {
    this.updates.push({ id, patch });
  }
  #record(input: ItemInput, prefix: string): CreatedRef {
    const ref = this.#ref(prefix);
    this.#createdByDescription.push({ description: input.description, ref });
    return ref;
  }
  #ref(prefix: string): CreatedRef {
    const n = ++this.#n;
    return { id: `${prefix}${n}`, url: `https://tracker.test/item/${n}` };
  }
}

// Build an accepted, publish-ready workspace: one epic, two stories (story 2 depends on story 1),
// each with a brief.
function seedWorkspace(): { dir: string; session: DraftSession } {
  const cwd = mkdtempSync(join(tmpdir(), "epic-pub-"));
  const { dir, session } = createWorkspace(cwd, "CSV export of audit findings");
  writeDraft(dir, "epic.md", { data: { kind: "epic", title: "CSV export", status: "accepted" }, body: "# Epic: CSV export\n\nBody.\n" });
  writeDraft(dir, "stories/01-endpoint.md", {
    data: { kind: "story", sequence: 1, title: "Export endpoint", status: "accepted", sizing: "M", dependsOn: [] },
    body: "# Story: Export endpoint\n\nAC.\n",
  });
  writeDraft(dir, "stories/02-filter.md", {
    data: { kind: "story", sequence: 2, title: "Permission filtering", status: "accepted", sizing: "S", dependsOn: ["01-endpoint"] },
    body: "# Story: Permission filtering\n\nAC.\n",
  });
  writeFile(dir, "briefs/01-endpoint.brief.md", "# Brief: endpoint\n");
  writeFile(dir, "briefs/02-filter.brief.md", "# Brief: filter\n");
  session.state = "publish";
  session.stories = [
    { file: "stories/01-endpoint.md", status: "accepted", revisions: 0 },
    { file: "stories/02-filter.md", status: "accepted", revisions: 0 },
  ];
  return { dir, session };
}

describe("publish orchestrator", () => {
  let dir: string;
  let session: DraftSession;
  beforeEach(() => {
    ({ dir, session } = seedWorkspace());
  });

  it("creates the epic then stories in dependency order with labels and briefs", async () => {
    const tracker = new FakeTracker();
    const outcome = await publish(dir, session, tracker);

    expect(tracker.epics).toHaveLength(1);
    expect(tracker.stories.map((s) => s.input.title)).toEqual(["Export endpoint", "Permission filtering"]);
    expect(outcome.created).toBe(3);
    expect(outcome.skipped).toBe(0);
    // Epic labelled "epic"; stories labelled "story" + their size.
    expect(tracker.labels).toContainEqual({ id: "E1", labels: ["epic"] });
    expect(tracker.labels).toContainEqual({ id: "S2", labels: ["story", "size:M"] });
    // The dependent story renders a "Blocked by" reference to its published prerequisite.
    const filter = tracker.stories.find((s) => s.input.title === "Permission filtering")!;
    expect(filter.input.description).toMatch(/Blocked by #S2/);
    // Both briefs were attached.
    expect(tracker.briefs).toHaveLength(2);
    // Each brief's URL (only known after attachBrief returns) is pushed into the story's remote
    // body via updateStory (#50) — frontmatter alone wouldn't be visible on the tracker item.
    expect(tracker.updates).toHaveLength(2);
    const endpointUpdate = tracker.updates.find((u) => u.id === "S2");
    expect(endpointUpdate?.patch.body).toContain("📄 Implementation brief: https://tracker.test/brief/S2");
    // The local record is written so a re-run is idempotent (design §8.2).
    expect(readDraft(dir, "epic.md").data.published).toMatchObject({ ref: "E1" });
  });

  it("is idempotent: a re-run creates nothing", async () => {
    await publish(dir, session, new FakeTracker());
    const second = new FakeTracker();
    const outcome = await publish(dir, session, second);
    expect(second.epics).toHaveLength(0);
    expect(second.stories).toHaveLength(0);
    expect(outcome.created).toBe(0);
    expect(outcome.skipped).toBe(3);
  });

  it("recovers from a mid-publish failure without duplicating created items", async () => {
    const failing = new FakeTracker();
    failing.failTitles.add("Permission filtering");
    await expect(publish(dir, session, failing)).rejects.toThrow(/simulated failure/);
    // Epic + story 1 were recorded before the failure.
    expect(failing.epics).toHaveLength(1);
    expect(failing.stories).toHaveLength(1);

    const retry = new FakeTracker(); // failure cleared
    const outcome = await publish(dir, session, retry);
    expect(retry.epics).toHaveLength(0); // already published -> skipped
    expect(retry.stories.map((s) => s.input.title)).toEqual(["Permission filtering"]); // only the missing one
    expect(outcome.created).toBe(1);
  });

  it("recovers a remote item via findByMarker instead of duplicating, when the local record was lost (#50)", async () => {
    const tracker = new FakeTracker();
    // Simulate a prior run that created the epic remotely — its stamped marker is in the body —
    // but crashed before epic.md's `published` frontmatter block was ever written, so the local
    // record readPublished() would find is missing even though the remote item exists.
    const epicBody = readDraft(dir, "epic.md").body;
    const priorRef = await tracker.createEpic({
      title: "CSV export",
      description: `${epicBody}\n\n<!-- epic-builder:${session.slug}/epic -->\n`,
    });
    expect(tracker.epics).toHaveLength(1);
    expect(readDraft(dir, "epic.md").data.published).toBeUndefined();

    const outcome = await publish(dir, session, tracker);

    // No duplicate epic created — the orchestrator found the existing remote item by its marker.
    expect(tracker.epics).toHaveLength(1);
    expect(readDraft(dir, "epic.md").data.published).toMatchObject({ ref: priorRef.id, url: priorRef.url });
    // The two stories genuinely didn't exist yet, so those still get created.
    expect(outcome.created).toBe(2);
    expect(outcome.skipped).toBe(1); // the recovered epic
  });

  it("dry-run fabricates a plan without writing local records", async () => {
    const outcome = await publish(dir, session, new NoopTracker(), { dryRun: true });
    expect(outcome.created).toBe(3);
    expect(outcome.summary).toContain("Epic: dry-run://");
    // No published block persisted, so a later real publish still creates everything.
    expect(readDraft(dir, "epic.md").data.published).toBeUndefined();
  });
});

describe("publish through the real GitHub adapter (mocked HTTP)", () => {
  it("creates issues, links stories, and commits briefs via the Contents API", async () => {
    let issueNo = 40;
    const calls: { method: string; url: string }[] = [];
    const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const u = String(url);
      const method = init?.method ?? "GET";
      calls.push({ method, url: u });
      const ok = (data: unknown) =>
        ({ ok: true, status: 200, json: async () => data, text: async () => "" }) as unknown as Response;
      if (method === "POST" && u.endsWith("/issues")) {
        const n = ++issueNo;
        return ok({ number: n, html_url: `https://github.com/o/r/issues/${n}`, body: "" });
      }
      if (method === "GET" && /\/issues\/\d+$/.test(u)) return ok({ number: 41, html_url: "", body: "epic body" });
      if (method === "GET" && u.includes("/search/issues?")) return ok({ items: [] }); // no prior run to recover (#50)
      if (method === "PATCH" && /\/issues\/\d+$/.test(u)) return ok({});
      if (method === "PUT" && /\/labels$/.test(u)) return ok([]);
      if (method === "POST" && /\/labels$/.test(u)) return ok([]);
      if (method === "PUT" && /\/contents\//.test(u)) return ok({ content: { html_url: `https://github.com/o/r/blob/main/${u.split("/contents/")[1]}` } });
      throw new Error(`unexpected request: ${method} ${u}`);
    });

    const tracker = new GitHubTracker({ token: "t", owner: "o", repo: "r", fetchImpl: fetchImpl as unknown as typeof fetch });
    const { dir, session } = seedWorkspace();
    const outcome = await publish(dir, session, tracker);

    expect(outcome.created).toBe(3);
    expect(outcome.epicRef.url).toBe("https://github.com/o/r/issues/41");
    // Three issues created (1 epic + 2 stories) and two briefs committed.
    expect(calls.filter((c) => c.method === "POST" && c.url.endsWith("/issues"))).toHaveLength(3);
    expect(calls.filter((c) => c.method === "PUT" && c.url.includes("/contents/"))).toHaveLength(2);
    // The persisted story now links to its committed brief.
    expect(readDraft(dir, "stories/01-endpoint.md").data.brief).toContain("github.com/o/r/blob");
  });
});
