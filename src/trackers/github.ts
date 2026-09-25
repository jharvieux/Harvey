// GitHub tracker adapter (issue #22, the primary target). Talks to the GitHub REST API directly
// with an injected token rather than shelling out to `gh`: credentials are then explicit and
// per-engagement (not the machine's ambient `gh` auth), and the HTTP layer is mockable in tests.
// No new dependency — the repo already uses global fetch (see src/scan/supabase.ts).
//
// GitHub has no native epic / story / estimate / issue-attachment concepts, so the mapping is:
//   - Epic  -> an issue.
//   - Story -> an issue, linked to its epic by appending a task-list line "- [ ] #<n> <title>"
//     to the epic issue's body. GitHub renders task-list items that reference an issue number as
//     tracked sub-items. This is chosen over the newer REST sub-issues API because that API keys
//     off an issue's internal database id (not its number) and is still relatively new; the
//     task-list approach is stable and needs only the issue number we already have.
//   - Labels   -> issue labels (PUT replaces the whole set).
//   - Estimate -> no native field, so it's encoded as an "estimate:<n>" label, ADDED (POST) so it
//     doesn't disturb labels set via setLabels. (Projects v2 has a real estimate field, but that's
//     GraphQL and out of scope here.)
//   - Brief    -> issues can't take file uploads via the API, so the brief markdown is committed to
//     the repo at briefs/issue-<n>.md via the Contents API and the file's canonical URL returned.
//     Chosen over a gist so the brief is versioned with the repo and needs no extra token scope.
//
// #50: findByMarker uses the Issues Search API (in:body) scoped to this repo; updateStory PATCHes
// the issue body and/or re-PUTs labels via the same endpoints createStory/setLabels already use.

import { appendTrackerBody, assertTrackerRef, PartialTrackerWriteError, trackerNextLink, trackerRecoveryPages } from "./recovery.js";
import { trackerFetch, trackerFetchJson } from "./http.js";
import type { AttachedRef, CreatedRef, ItemInput, TicketState, TicketWriteback, Tracker, UpdateStoryPatch } from "./types.js";

export interface GitHubConfig {
  token: string;
  owner: string;
  repo: string;
  apiBaseUrl?: string; // default https://api.github.com (override for GitHub Enterprise)
  fetchImpl?: typeof fetch; // injection point for tests
}

interface GitHubIssue {
  number: number;
  html_url: string;
  body: string | null;
  labels?: ({ name: string } | string)[];
  repository_url?: string;
  pull_request?: unknown;
}

interface GitHubContentResponse {
  content: { html_url: string };
}

interface GitHubSearchResponse {
  items: GitHubIssue[];
  total_count?: number;
  incomplete_results?: boolean;
}

export class GitHubTracker implements Tracker, TicketWriteback {
  readonly #token: string;
  readonly #owner: string;
  readonly #repo: string;
  readonly #base: string;
  readonly #fetch: typeof fetch;

  constructor(config: GitHubConfig) {
    this.#token = config.token;
    this.#owner = config.owner;
    this.#repo = config.repo;
    this.#base = config.apiBaseUrl ?? "https://api.github.com";
    this.#fetch = config.fetchImpl ?? fetch;
  }

  #headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.#token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
    };
  }

  #repoUrl(path: string): string {
    return `${this.#base}/repos/${this.#owner}/${this.#repo}${path}`;
  }

  async createEpic(input: ItemInput): Promise<CreatedRef> {
    const issue = await trackerFetchJson<GitHubIssue>(this.#fetch, this.#repoUrl("/issues"), {
      method: "POST",
      headers: this.#headers(),
      body: JSON.stringify({ title: input.title, body: input.description }),
    });
    return assertTrackerRef({ id: String(issue.number), url: issue.html_url });
  }

  async createStory(input: ItemInput, epicId: string): Promise<CreatedRef> {
    const marker = input.description.match(/<!-- (?:harvey-finding|epic-builder):[^\n]*? -->/)?.[0];
    const existing = marker ? await this.findByMarker(marker) : null;
    const ref = existing ?? await this.createEpic(input);
    try { await this.#linkToEpic(epicId, Number(ref.id), input.title); }
    catch (error) { throw new PartialTrackerWriteError(ref, "link", error); }
    return ref;
  }

  async completeStory(id: string, input: ItemInput, labels: string[], epicId?: string): Promise<void> {
    if (epicId) await this.#linkToEpic(epicId, Number(id), input.title);
    const issue = await trackerFetchJson<GitHubIssue>(this.#fetch, this.#repoUrl(`/issues/${id}`), { method: "GET", headers: this.#headers() });
    const existing = (issue.labels ?? []).map(label => typeof label === "string" ? label : label.name);
    if (labels.some(label => !existing.includes(label))) await this.setLabels(id, [...new Set([...existing, ...labels])]);
  }

  // Read-modify-write the epic body so the story shows up as a tracked task-list item.
  async #linkToEpic(epicId: string, storyNumber: number, storyTitle: string): Promise<void> {
    const epic = await trackerFetchJson<GitHubIssue>(this.#fetch, this.#repoUrl(`/issues/${epicId}`), {
      method: "GET",
      headers: this.#headers(),
    });
    if (epic.body?.split("\n").some(line => line.startsWith(`- [ ] #${storyNumber} `) || line.startsWith(`- [x] #${storyNumber} `))) return;
    const taskLine = `- [ ] #${storyNumber} ${storyTitle}`;
    const body = epic.body ? `${epic.body}\n${taskLine}` : taskLine;
    await trackerFetch(this.#fetch, this.#repoUrl(`/issues/${epicId}`), {
      method: "PATCH",
      headers: this.#headers(),
      body: JSON.stringify({ body }),
    });
  }

  // Issue search scoped to this repo's body text (design §8.2 mechanism 2). GitHub's search index
  // lags writes by a few seconds, which is an accepted MVP limitation here — same as the design.
  async findByMarker(marker: string): Promise<CreatedRef | null> {
    const q = `repo:${this.#owner}/${this.#repo} is:issue in:body "${marker.replaceAll('"', '\\"')}"`;
    const matches = new Map<string, CreatedRef>();
    const seen = new Set<string>();
    const identities = new Set<string>();
    let total: number | undefined;
    let url = `${this.#base}/search/issues?q=${encodeURIComponent(q)}&per_page=100&page=1`;
    for (let page = 1; page <= 10; page++) {
      if (seen.has(url)) throw new Error("GitHub marker lookup repeats a page");
      seen.add(url);
      const response = await trackerFetch(this.#fetch, url, { method: "GET", headers: this.#headers() });
      const res = await response.json() as GitHubSearchResponse;
      if (!Array.isArray(res.items) || !Number.isSafeInteger(res.total_count) || res.total_count! < 0 || res.incomplete_results !== false) throw new Error("GitHub marker lookup incomplete; refusing ambiguous recovery");
      if (total !== undefined && total !== res.total_count) throw new Error("GitHub marker lookup population changed during recovery");
      total = res.total_count!;
      for (const hit of res.items) {
        if (typeof hit.repository_url !== "string" || !hit.repository_url || !Number.isSafeInteger(hit.number) || hit.number <= 0 || typeof hit.html_url !== "string") throw new Error("GitHub marker lookup lacks verified scope or identity");
        const repository = hit.repository_url;
        const identity = `${repository}#${hit.number}`;
        if (identities.has(identity)) throw new Error("GitHub marker lookup repeats an issue across pages");
        identities.add(identity);
        const expected = this.#repoUrl("");
        if (!hit.pull_request && repository === expected && hit.body?.includes(marker)) {
          matches.set(String(hit.number), { id: String(hit.number), url: hit.html_url });
        }
      }
      if (matches.size > 1) throw new Error("GitHub marker lookup ambiguous: multiple exact matches in repository");
      const next = trackerNextLink(response, url);
      if (identities.size > total || (next && identities.size >= total)) throw new Error("GitHub marker lookup has contradictory pagination");
      if (!next && identities.size === total) return [...matches.values()][0] ?? null;
      if (res.items.length === 0) throw new Error("GitHub marker lookup has an empty incomplete page");
      if (next) url = next;
      else {
        const fallback = new URL(url);
        const currentPage = Number(fallback.searchParams.get("page"));
        if (!Number.isSafeInteger(currentPage) || currentPage < 1) throw new Error("GitHub marker lookup has invalid continuation");
        fallback.searchParams.set("page", String(currentPage + 1)); url = fallback.href;
      }
    }
    throw new Error("GitHub marker lookup exceeds search limit; refusing incomplete recovery");
  }

  async setLabels(id: string, labels: string[]): Promise<void> {
    await trackerFetch(this.#fetch, this.#repoUrl(`/issues/${id}/labels`), {
      method: "PUT",
      headers: this.#headers(),
      body: JSON.stringify({ labels }),
    });
  }

  async updateStory(id: string, patch: UpdateStoryPatch): Promise<void> {
    let body = patch.body;
    if (patch.appendBody !== undefined) {
      const issue = await trackerFetchJson<GitHubIssue>(this.#fetch, this.#repoUrl(`/issues/${id}`), { method: "GET", headers: this.#headers() });
      body = appendTrackerBody(issue.body, patch.appendBody);
    }
    if (body !== undefined) {
      await trackerFetch(this.#fetch, this.#repoUrl(`/issues/${id}`), {
        method: "PATCH",
        headers: this.#headers(),
        body: JSON.stringify({ body }),
      });
    }
    if (patch.labels !== undefined) await this.setLabels(id, patch.labels);
  }

  // #883 fix-verification write-back: a comment appends (never touches the body the client may
  // have edited); state maps directly to GitHub's open/closed. state_reason distinguishes a
  // verified-resolved close from "not planned".
  async addComment(id: string, body: string): Promise<void> {
    const marker = body.match(/<!-- harvey-writeback:[a-f0-9]+ -->/)?.[0];
    if (marker) {
      for await (const comments of trackerRecoveryPages<{ body: string }>(this.#fetch, this.#repoUrl(`/issues/${id}/comments?per_page=100&page=1`), this.#headers())) {
        if (comments.some(comment => !comment || typeof comment.body !== "string")) throw new Error("github comment recovery returned malformed content");
        if (comments.some(comment => comment.body.includes(marker))) return;
      }
    }
    await trackerFetch(this.#fetch, this.#repoUrl(`/issues/${id}/comments`), {
      method: "POST",
      headers: this.#headers(),
      body: JSON.stringify({ body }),
    });
  }

  async transitionState(id: string, to: TicketState): Promise<void> {
    const patch = to === "closed" ? { state: "closed", state_reason: "completed" } : { state: "open", state_reason: "reopened" };
    await trackerFetch(this.#fetch, this.#repoUrl(`/issues/${id}`), {
      method: "PATCH",
      headers: this.#headers(),
      body: JSON.stringify(patch),
    });
  }

  async setEstimate(id: string, estimate: number): Promise<void> {
    await trackerFetch(this.#fetch, this.#repoUrl(`/issues/${id}/labels`), {
      method: "POST",
      headers: this.#headers(),
      body: JSON.stringify({ labels: [`estimate:${estimate}`] }),
    });
  }

  async attachBrief(id: string, briefMarkdown: string): Promise<AttachedRef> {
    const path = `briefs/issue-${id}.md`;
    const res = await trackerFetchJson<GitHubContentResponse>(this.#fetch, this.#repoUrl(`/contents/${path}`), {
      method: "PUT",
      headers: this.#headers(),
      body: JSON.stringify({
        message: `Add implementation brief for #${id}`,
        content: Buffer.from(briefMarkdown, "utf8").toString("base64"),
      }),
    });
    return { url: res.content.html_url };
  }
}
