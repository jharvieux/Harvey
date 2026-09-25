// GitLab tracker adapter (issue #733 — completes the five-tracker set named in the add-on). Talks
// to the GitLab REST API v4 with an injected access token. Native group-level Epics are a
// Premium/Ultimate-only feature, so — to stay usable on any tier and project-scoped like the other
// adapters — the mapping mirrors the GitHub adapter:
//   - Epic  -> a project Issue.
//   - Story -> a project Issue, linked to its epic by appending a task-list line "- [ ] #<iid> <title>"
//     to the epic issue's description. GitLab renders a task-list item that references an issue iid
//     as a tracked child, exactly like GitHub's `#<n>` reference.
//   - Labels   -> the issue's `labels` field (a comma-separated string; PUT replaces the whole set).
//   - Estimate -> the issue `weight` field, GitLab's native per-issue estimate.
//   - Brief    -> uploaded to the project via the /uploads endpoint (native file upload); the hosted
//     file's canonical URL (host + full_path) is returned.
//
// Auth: a personal/project/group access token with the `api` scope, sent as a Bearer token in the
// Authorization header (GitLab accepts access tokens as Bearer tokens). The raw token never leaves
// the Authorization header — see credentials.test.ts.
//
// findByMarker searches the project's issue descriptions (`in=description`); updateStory PUTs the
// description and/or labels via the same issue endpoint setLabels uses.

import { appendTrackerBody, assertTrackerRef, PartialTrackerWriteError, trackerRecoveryPages } from "./recovery.js";
import { trackerFetch, trackerFetchJson } from "./http.js";
import type { AttachedRef, CreatedRef, ItemInput, TicketState, TicketWriteback, Tracker, UpdateStoryPatch } from "./types.js";

export interface GitLabConfig {
  token: string;
  projectId: string; // numeric id or URL-encoded "group/project" path
  baseUrl?: string; // default https://gitlab.com/api/v4 (override for self-managed)
  fetchImpl?: typeof fetch; // injection point for tests
}

interface GitLabIssue {
  iid: number;
  web_url: string;
  description: string | null;
  project_id?: number;
  labels?: string[];
}

interface GitLabUpload {
  full_path: string; // instance-absolute path to the uploaded file, e.g. /-/project/1/uploads/<hash>/brief.md
}

export class GitLabTracker implements Tracker, TicketWriteback {
  readonly #token: string;
  readonly #projectId: string;
  readonly #scopeId: string;
  readonly #base: string;
  readonly #fetch: typeof fetch;

  constructor(config: GitLabConfig) {
    this.#token = config.token;
    this.#scopeId = decodeURIComponent(config.projectId);
    this.#projectId = encodeURIComponent(this.#scopeId);
    this.#base = (config.baseUrl ?? "https://gitlab.com/api/v4").replace(/\/$/, "");
    this.#fetch = config.fetchImpl ?? fetch;
  }

  #headers(): Record<string, string> {
    return { Authorization: `Bearer ${this.#token}`, "Content-Type": "application/json" };
  }

  #issuesUrl(path = ""): string {
    return `${this.#base}/projects/${this.#projectId}/issues${path}`;
  }

  async createEpic(input: ItemInput): Promise<CreatedRef> {
    return this.#createIssue(input);
  }

  async createStory(input: ItemInput, epicId: string): Promise<CreatedRef> {
    const marker = input.description.match(/<!-- (?:harvey-finding|epic-builder):[^>]+ -->/)?.[0];
    const story = (marker ? await this.findByMarker(marker) : null) ?? await this.#createIssue(input);
    try { await this.#linkToEpic(epicId, story.id, input.title); }
    catch (error) { throw new PartialTrackerWriteError(story, "epic link", error); }
    return story;
  }

  async #createIssue(input: ItemInput): Promise<CreatedRef> {
    const issue = await trackerFetchJson<GitLabIssue>(this.#fetch, this.#issuesUrl(), {
      method: "POST",
      headers: this.#headers(),
      body: JSON.stringify({ title: input.title, description: input.description }),
    });
    return assertTrackerRef({ id: String(issue.iid), url: issue.web_url });
  }

  // Read-modify-write the epic issue's description so the story shows up as a tracked task-list item.
  async #linkToEpic(epicIid: string, storyIid: string, storyTitle: string): Promise<void> {
    const epic = await trackerFetchJson<GitLabIssue>(this.#fetch, this.#issuesUrl(`/${epicIid}`), {
      method: "GET",
      headers: this.#headers(),
    });
    if (epic.description?.split("\n").some(line => line.startsWith(`- [ ] #${storyIid} `) || line.startsWith(`- [x] #${storyIid} `))) return;
    const taskLine = `- [ ] #${storyIid} ${storyTitle}`;
    const description = epic.description ? `${epic.description}\n${taskLine}` : taskLine;
    await trackerFetch(this.#fetch, this.#issuesUrl(`/${epicIid}`), {
      method: "PUT",
      headers: this.#headers(),
      body: JSON.stringify({ description }),
    });
  }

  async findByMarker(marker: string): Promise<CreatedRef | null> {
    const matches = new Map<string, CreatedRef>();
    const query = new URLSearchParams({search: marker, in: "description", scope: "all", per_page: "100", page: "1"});
    for await (const rows of trackerRecoveryPages<GitLabIssue>(this.#fetch, this.#issuesUrl(`?${query}`), this.#headers())) {
      for (const hit of rows) {
        if (!Number.isSafeInteger(hit.iid) || hit.iid <= 0 || typeof hit.web_url !== "string" || (/^\d+$/.test(this.#scopeId) && !Number.isSafeInteger(hit.project_id))) throw new Error("GitLab marker lookup lacks verified scope or identity");
        const inProject = /^\d+$/.test(this.#scopeId)
          ? String(hit.project_id) === this.#scopeId
          : new URL(hit.web_url).origin === new URL(this.#base).origin && new URL(hit.web_url).pathname === `/${this.#scopeId}/-/issues/${hit.iid}`;
        if (inProject && hit.description?.includes(marker)) matches.set(String(hit.iid), {id: String(hit.iid), url: hit.web_url});
      }
      if (matches.size > 1) throw new Error("GitLab marker lookup ambiguous: multiple exact matches in project");
    }
    return [...matches.values()][0] ?? null;
  }

  async completeStory(id: string, input: ItemInput, labels: string[], epicId?: string): Promise<void> {
    if (epicId) await this.#linkToEpic(epicId, id, input.title);
    const issue = await trackerFetchJson<GitLabIssue>(this.#fetch, this.#issuesUrl(`/${id}`), {method: "GET", headers: this.#headers()});
    const existing = issue.labels ?? [];
    if (labels.some(label => !existing.includes(label))) await this.setLabels(id, [...new Set([...existing, ...labels])]);
  }

  async setLabels(id: string, labels: string[]): Promise<void> {
    await trackerFetch(this.#fetch, this.#issuesUrl(`/${id}`), {
      method: "PUT",
      headers: this.#headers(),
      body: JSON.stringify({ labels: labels.join(",") }),
    });
  }

  async updateStory(id: string, patch: UpdateStoryPatch): Promise<void> {
    const fields: Record<string, unknown> = {};
    if (patch.body !== undefined) fields.description = patch.body;
    if (patch.appendBody !== undefined) {
      const issue = await trackerFetchJson<{ description: string | null }>(this.#fetch, this.#issuesUrl(`/${id}`), { method: "GET", headers: this.#headers() });
      const body = appendTrackerBody(issue.description, patch.appendBody);
      if (body !== undefined) fields.description = body;
    }
    if (patch.labels !== undefined) fields.labels = patch.labels.join(",");
    if (Object.keys(fields).length === 0) return;
    await trackerFetch(this.#fetch, this.#issuesUrl(`/${id}`), {
      method: "PUT",
      headers: this.#headers(),
      body: JSON.stringify(fields),
    });
  }

  // #883 fix-verification write-back: a note appends to the discussion (never the description);
  // state moves via GitLab's state_event on the issue itself.
  async addComment(id: string, body: string): Promise<void> {
    const marker = body.match(/<!-- harvey-writeback:[a-f0-9]+ -->/)?.[0];
    if (marker) {
      for await (const comments of trackerRecoveryPages<{ body: string }>(this.#fetch, this.#issuesUrl(`/${id}/notes?per_page=100&page=1`), this.#headers())) {
        if (comments.some(comment => !comment || typeof comment.body !== "string")) throw new Error("gitlab comment recovery returned malformed content");
        if (comments.some(comment => comment.body.includes(marker))) return;
      }
    }
    await trackerFetch(this.#fetch, this.#issuesUrl(`/${id}/notes`), {
      method: "POST",
      headers: this.#headers(),
      body: JSON.stringify({ body }),
    });
  }

  async transitionState(id: string, to: TicketState): Promise<void> {
    await trackerFetch(this.#fetch, this.#issuesUrl(`/${id}`), {
      method: "PUT",
      headers: this.#headers(),
      body: JSON.stringify({ state_event: to === "closed" ? "close" : "reopen" }),
    });
  }

  async setEstimate(id: string, estimate: number): Promise<void> {
    await trackerFetch(this.#fetch, this.#issuesUrl(`/${id}`), {
      method: "PUT",
      headers: this.#headers(),
      body: JSON.stringify({ weight: estimate }),
    });
  }

  async attachBrief(id: string, briefMarkdown: string): Promise<AttachedRef> {
    const form = new FormData();
    form.append("file", new Blob([briefMarkdown], { type: "text/markdown" }), `brief-${id}.md`);
    // No Content-Type header — fetch sets the multipart boundary.
    const upload = await trackerFetchJson<GitLabUpload>(
      this.#fetch,
      `${this.#base}/projects/${this.#projectId}/uploads`,
      { method: "POST", headers: { Authorization: `Bearer ${this.#token}` }, body: form },
    );
    return { url: `${this.#base.replace(/\/api\/v4$/, "")}${upload.full_path}` };
  }
}
