// Proves the web MVP's core path end-to-end without a live model, a live tracker, or an HTTP server:
// it drives lib/core.ts (the exact functions the API routes call) with a deterministic fake
// ModelClient and a real GitHubTracker whose HTTP is mocked. Asserts intake -> clarify -> epic draft
// -> AI revision (visible diff) -> accept -> story fan-out -> per-story accept -> dry-run publish ->
// real publish (GitHub issue set) -> idempotent re-run, plus that the tracker token never leaks.

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { GitHubTracker } from "../../src/trackers/github.js";
import type { Tracker } from "../../src/trackers/types.js";
import type { Templates } from "../../src/epic-builder/session.js";
import type {
  ClarifyQuestion,
  DraftStoryResult,
  ModelClient,
  ReviseInput,
  StoryManifestEntry,
} from "../../src/epic-builder/types.js";
import { fanOut, getState, NoopTracker, previewManifest, reviewAction, runPublish, startSession, submitClarify, type CoreDeps, type ViewState } from "../lib/core.js";

const TOKEN = "SECRET-PAT-do-not-leak-0xC0FFEE";

const templates: Templates = {
  epic: "# Epic: {title}\n\n## Overview\nProblem.\n\n## In scope\n- The core capability\n",
  story: "# {title}\n\n## Acceptance criteria\n- It works\n",
  brief: "# Brief: {title}\n\n## Plan\nSteps.\n",
};

// Deterministic model: one clarifying question, a titled epic, two stories, and a revise that visibly
// changes the body (so the diff is non-empty and we can assert the revision applied).
class FakeModel implements ModelClient {
  async clarify(input: { round: number }): Promise<ClarifyQuestion[]> {
    return input.round > 1 ? [] : [{ question: "Who is the primary user?", assumption: "org admins" }];
  }
  async draftEpic(): Promise<string> {
    return "# Epic: CSV export\n\n## Overview\nExport findings as CSV.\n\n## In scope\n- Export endpoint\n- Permission filter\n";
  }
  async storyManifest(): Promise<StoryManifestEntry[]> {
    return [
      { title: "Export endpoint", scope: "endpoint", sizing: "M" },
      { title: "Permission filter", scope: "rls", sizing: "M" },
    ];
  }
  async draftStory(input: { entry: StoryManifestEntry }): Promise<DraftStoryResult> {
    return { body: `# ${input.entry.title}\n\n## Acceptance criteria\n- It works\n`, brief: `# Brief\n` };
  }
  async revise(input: ReviseInput): Promise<string> {
    return `${input.current.trimEnd()}\n\nREVISED: ${input.instruction ?? "addressed comments"}\n`;
  }
}

// Stateful mock of the GitHub REST endpoints the publish orchestrator touches (design §8.4).
function mockGitHubFetch() {
  let n = 40;
  const calls: { method: string; url: string }[] = [];
  const fetchImpl = vi.fn(async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    const method = init?.method ?? "GET";
    calls.push({ method, url: u });
    const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
    if (u.includes("/search/issues")) return ok({ items: [] }); // findByMarker: nothing pre-exists
    if (u.includes("/contents/")) return ok({ content: { html_url: `https://github.com/o/r/blob/main/brief.md` } });
    if (/\/issues\/\d+\/labels$/.test(u)) return ok({});
    if (/\/issues\/\d+$/.test(u) && method === "GET") return ok({ number: 41, html_url: "u", body: "" });
    if (/\/issues\/\d+$/.test(u) && method === "PATCH") return ok({});
    if (u.endsWith("/issues") && method === "POST") {
      const num = ++n;
      return ok({ number: num, html_url: `https://github.com/o/r/issues/${num}`, body: null });
    }
    return ok({});
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

let deps: CoreDeps;
let ghCalls: { method: string; url: string }[];
let makeReal: (dryRun: boolean) => Tracker;

beforeEach(() => {
  const cwd = mkdtempSync(join(tmpdir(), "epic-web-"));
  const { fetchImpl, calls } = mockGitHubFetch();
  ghCalls = calls;
  makeReal = (dryRun) =>
    dryRun
      ? ({} as Tracker) // dry run uses NoopTracker via the wrapper, never this
      : new GitHubTracker({ token: TOKEN, owner: "o", repo: "r", fetchImpl });
  deps = { model: new FakeModel(), cwd, templates, makeTracker: makeReal };
});

// Real dry-run/publish path needs the NoopTracker for dry runs; rebuild deps so dry runs use it.
function withNoopForDry(base: CoreDeps): CoreDeps {
  return {
    ...base,
    makeTracker: (dryRun) => (dryRun ? new NoopTracker() : base.makeTracker(false)),
  };
}

async function acceptAllStories(d: CoreDeps, slug: string, from: ViewState): Promise<ViewState> {
  let v = from;
  while (v.state === "stories-review" && v.reviewTarget) {
    v = await reviewAction(d, slug, { action: "accept", target: v.reviewTarget });
  }
  return v;
}

describe("epic-builder web flow", () => {
  it("drives intake -> clarify -> revise -> accept -> fan-out -> publish, idempotently", async () => {
    // intake
    const { slug, questions } = await startSession(deps, "Customers should export findings as CSV");
    expect(questions.length).toBeGreaterThan(0);

    // clarify -> epic draft lands in epic-review
    let v = await submitClarify(deps, slug, "1: admins only");
    expect(v.state).toBe("epic-review");
    expect(v.reviewTarget).toBe("epic.md");
    expect(v.body).toContain("CSV export");

    // AI revision produces a visible, applied diff
    const revised = await reviewAction(deps, slug, { action: "revise", target: "epic.md", instruction: "tighten scope" });
    expect(revised.applied).toBe(true);
    expect(revised.diff && revised.diff.length).toBeTruthy();
    expect(getState(deps, slug).body).toContain("REVISED: tighten scope");

    // accept epic -> fan out
    v = await reviewAction(deps, slug, { action: "accept", target: "epic.md" });
    expect(v.state).toBe("stories-fan-out");

    const manifest = await previewManifest(deps, slug);
    expect(manifest).toHaveLength(2);

    v = await fanOut(deps, slug, [0, 1]);
    expect(v.state).toBe("stories-review");
    expect(v.stories).toHaveLength(2);

    v = await acceptAllStories(deps, slug, v);
    expect(v.state).toBe("publish");

    // dry run (NoopTracker) — no HTTP, fabricated refs
    const dryDeps = withNoopForDry(deps);
    const dry = await runPublish(dryDeps, slug, true);
    expect(dry.dryRun).toBe(true);
    expect(dry.created).toBe(3); // 1 epic + 2 stories
    expect(dry.epicUrl).toContain("dry-run://");
    expect(ghCalls.length).toBe(0); // dry run touched no real endpoint

    // real publish — creates the GitHub issue set through the mocked adapter
    const pub = await runPublish(deps, slug, false);
    expect(pub.created).toBe(3);
    expect(pub.epicUrl).toContain("github.com/o/r/issues/");
    expect(pub.storyUrls).toHaveLength(2);
    expect(ghCalls.some((c) => c.method === "POST" && c.url.endsWith("/issues"))).toBe(true);
    expect(getState(deps, slug).state).toBe("done");

    // token never leaks into what the wrapper returns
    expect(JSON.stringify(pub)).not.toContain(TOKEN);

    // idempotent re-run — everything already published, nothing re-created
    const again = await runPublish(deps, slug, false);
    expect(again.created).toBe(0);
    expect(again.skipped).toBe(3);
  });
});
