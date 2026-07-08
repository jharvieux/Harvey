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

import { trackerFetch, trackerFetchJson } from "./http.js";
import type { AttachedRef, CreatedRef, ItemInput, Tracker } from "./types.js";

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
}

interface GitHubContentResponse {
  content: { html_url: string };
}

export class GitHubTracker implements Tracker {
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
    return { id: String(issue.number), url: issue.html_url };
  }

  async createStory(input: ItemInput, epicId: string): Promise<CreatedRef> {
    const story = await trackerFetchJson<GitHubIssue>(this.#fetch, this.#repoUrl("/issues"), {
      method: "POST",
      headers: this.#headers(),
      body: JSON.stringify({ title: input.title, body: input.description }),
    });
    await this.#linkToEpic(epicId, story.number, input.title);
    return { id: String(story.number), url: story.html_url };
  }

  // Read-modify-write the epic body so the story shows up as a tracked task-list item.
  async #linkToEpic(epicId: string, storyNumber: number, storyTitle: string): Promise<void> {
    const epic = await trackerFetchJson<GitHubIssue>(this.#fetch, this.#repoUrl(`/issues/${epicId}`), {
      method: "GET",
      headers: this.#headers(),
    });
    const taskLine = `- [ ] #${storyNumber} ${storyTitle}`;
    const body = epic.body ? `${epic.body}\n${taskLine}` : taskLine;
    await trackerFetch(this.#fetch, this.#repoUrl(`/issues/${epicId}`), {
      method: "PATCH",
      headers: this.#headers(),
      body: JSON.stringify({ body }),
    });
  }

  async setLabels(id: string, labels: string[]): Promise<void> {
    await trackerFetch(this.#fetch, this.#repoUrl(`/issues/${id}/labels`), {
      method: "PUT",
      headers: this.#headers(),
      body: JSON.stringify({ labels }),
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
