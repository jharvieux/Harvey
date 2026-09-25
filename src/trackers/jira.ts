// Jira Cloud tracker adapter (issue #22). REST API v3.
//
// Bodies are Atlassian Document Format (ADF): createEpic/createStory descriptions are converted
// by a minimal markdown->ADF pass (each blank-line-separated block becomes a paragraph). This is
// intentionally not a full markdown parser — it's enough for the prose descriptions this layer
// writes, and it produces a valid ADF document (docs: developer.atlassian.com/cloud/jira/platform/apis/document/structure).
// Attachments are native (multipart upload, guarded by the required X-Atlassian-Token: no-check header).
//
// Auth: Jira Cloud uses HTTP Basic with the account email + an API token; the header is built from
// injected { email, apiToken }. Epic linkage uses the modern `parent` field. Story points live in an
// instance-specific custom field, so its id is configurable (default customfield_10016, the common
// Jira Cloud default) — confirm the field id for the target instance before the first real run.
//
// #50: findByMarker runs a JQL `text ~` search (see caveat on the method); updateStory PUTs
// description/labels fields via the same endpoint setLabels/setEstimate use.

import { assertTrackerRef } from "./recovery.js";
import { trackerFetch, trackerFetchJson } from "./http.js";
import type { AttachedRef, CreatedRef, ItemInput, TicketState, TicketWriteback, Tracker, UpdateStoryPatch } from "./types.js";

export interface JiraConfig {
  baseUrl: string; // https://your-domain.atlassian.net
  email: string;
  apiToken: string;
  projectKey: string;
  epicIssueType?: string; // default "Epic"
  storyIssueType?: string; // default "Story"
  storyPointsField?: string; // default "customfield_10016"
  fetchImpl?: typeof fetch; // injection point for tests
}

interface JiraCreatedIssue {
  key: string;
}

interface JiraAttachment {
  content: string; // canonical download URL of the uploaded file
}

interface JiraSearchResponse {
  issues: (JiraCreatedIssue & { fields?: { project?: { key?: string }; description?: AdfNode } })[];
  nextPageToken?: string;
  isLast?: boolean;
}

interface JiraTransitionsResponse {
  transitions: { id: string; name: string; to: { statusCategory: { key: string } } }[];
}

interface AdfNode {
  type: string;
  content?: AdfNode[];
  text?: string;
}

function markdownToAdf(markdown: string): { type: "doc"; version: 1; content: AdfNode[] } {
  const blocks = markdown
    .split(/\n{2,}/)
    .map((b) => b.trim())
    .filter(Boolean);
  const content: AdfNode[] = blocks.length
    ? blocks.map((text) => ({ type: "paragraph", content: [{ type: "text", text }] }))
    : [{ type: "paragraph" }]; // an empty paragraph is valid ADF; an empty text node is not
  return { type: "doc", version: 1, content };
}

export class JiraTracker implements Tracker, TicketWriteback {
  readonly #auth: string;
  readonly #baseUrl: string;
  readonly #projectKey: string;
  readonly #epicType: string;
  readonly #storyType: string;
  readonly #storyPointsField: string;
  readonly #fetch: typeof fetch;

  constructor(config: JiraConfig) {
    this.#auth = `Basic ${Buffer.from(`${config.email}:${config.apiToken}`).toString("base64")}`;
    this.#baseUrl = config.baseUrl.replace(/\/$/, "");
    this.#projectKey = config.projectKey;
    this.#epicType = config.epicIssueType ?? "Epic";
    this.#storyType = config.storyIssueType ?? "Story";
    this.#storyPointsField = config.storyPointsField ?? "customfield_10016";
    this.#fetch = config.fetchImpl ?? fetch;
  }

  #jsonHeaders(): Record<string, string> {
    return { Authorization: this.#auth, Accept: "application/json", "Content-Type": "application/json" };
  }

  createEpic(input: ItemInput): Promise<CreatedRef> {
    return this.#create(input, this.#epicType);
  }

  createStory(input: ItemInput, epicId: string): Promise<CreatedRef> {
    return this.#create(input, this.#storyType, epicId);
  }

  async #create(input: ItemInput, issueType: string, parentKey?: string): Promise<CreatedRef> {
    const fields: Record<string, unknown> = {
      project: { key: this.#projectKey },
      issuetype: { name: issueType },
      summary: input.title,
      description: markdownToAdf(input.description),
    };
    if (parentKey) fields.parent = { key: parentKey };
    const created = await trackerFetchJson<JiraCreatedIssue>(this.#fetch, `${this.#baseUrl}/rest/api/3/issue`, {
      method: "POST",
      headers: this.#jsonHeaders(),
      body: JSON.stringify({ fields }),
    });
    return assertTrackerRef({ id: created.key, url: `${this.#baseUrl}/browse/${created.key}` });
  }

  // Search is candidate discovery: verify the complete marker and configured project locally.
  async findByMarker(marker: string): Promise<CreatedRef | null> {
    const quote = (value: string) => value.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
    const jql = `project = "${quote(this.#projectKey)}" AND text ~ "${quote(marker)}"`;
    const text = (node: AdfNode): string => (node.text ?? "") + (node.content?.map(text).join("") ?? "");
    const matches = new Map<string, CreatedRef>();
    const seen = new Set<string>();
    let token = "";
    for (let page = 0; page < 100; page++) {
      const query = new URLSearchParams({ jql, fields: "description,project", maxResults: "100", ...(token ? { nextPageToken: token } : {}) });
      const res = await trackerFetchJson<JiraSearchResponse>(this.#fetch, `${this.#baseUrl}/rest/api/3/search/jql?${query}`,
        { method: "GET", headers: this.#jsonHeaders() });
      if (!Array.isArray(res.issues) || typeof res.isLast !== "boolean" || (res.nextPageToken != null && typeof res.nextPageToken !== "string")) throw new Error("Jira marker lookup has incomplete pagination");
      for (const hit of res.issues) {
        if (typeof hit.fields?.project?.key !== "string" || !hit.fields.project.key || typeof hit.key !== "string" || !hit.key) throw new Error("Jira marker lookup lacks verified scope or identity");
        if (hit.fields?.project?.key === this.#projectKey && hit.fields.description && text(hit.fields.description).includes(marker)) {
          matches.set(hit.key, { id: hit.key, url: `${this.#baseUrl}/browse/${hit.key}` });
        }
      }
      if (matches.size > 1) throw new Error("Jira marker lookup ambiguous: multiple exact matches in project");
      if (res.isLast !== false && !res.nextPageToken) return [...matches.values()][0] ?? null;
      if (!res.nextPageToken || seen.has(res.nextPageToken)) throw new Error("Jira marker lookup incomplete: invalid pagination");
      token = res.nextPageToken; seen.add(token);
    }
    throw new Error("Jira marker lookup incomplete: pagination limit");
  }

  async completeStory(id: string, _input: ItemInput, labels: string[]): Promise<void> {
    const issue = await trackerFetchJson<{ fields: { labels: string[] } }>(this.#fetch, `${this.#baseUrl}/rest/api/3/issue/${id}?fields=labels`, { method: "GET", headers: this.#jsonHeaders() });
    const existing = issue.fields.labels;
    if (labels.some(label => !existing.includes(label))) await this.setLabels(id, [...new Set([...existing, ...labels])]);
  }

  async setLabels(id: string, labels: string[]): Promise<void> {
    await trackerFetch(this.#fetch, `${this.#baseUrl}/rest/api/3/issue/${id}`, {
      method: "PUT",
      headers: this.#jsonHeaders(),
      body: JSON.stringify({ fields: { labels } }),
    });
  }

  async updateStory(id: string, patch: UpdateStoryPatch): Promise<void> {
    const fields: Record<string, unknown> = {};
    if (patch.body !== undefined) fields.description = markdownToAdf(patch.body);
    if (patch.appendBody !== undefined) {
      const issue = await trackerFetchJson<{ fields: { description: AdfNode | null } }>(this.#fetch, `${this.#baseUrl}/rest/api/3/issue/${id}?fields=description`, { method: "GET", headers: this.#jsonHeaders() });
      const current = issue.fields?.description;
      if (current !== null && (!current || current.type !== "doc" || !Array.isArray(current.content))) throw new Error("Jira description is unavailable; refusing to overwrite client content");
      const text = (node: AdfNode): string => (node.text ?? "") + (node.content?.map(text).join("") ?? "");
      if (!current?.content?.some(node => text(node).trim() === patch.appendBody!.trim())) {
        fields.description = { ...(current ?? { type: "doc", version: 1 }), content: [...(current?.content ?? []), ...markdownToAdf(patch.appendBody).content] };
      }
    }
    if (patch.labels !== undefined) fields.labels = patch.labels;
    if (Object.keys(fields).length === 0) return;
    await trackerFetch(this.#fetch, `${this.#baseUrl}/rest/api/3/issue/${id}`, {
      method: "PUT",
      headers: this.#jsonHeaders(),
      body: JSON.stringify({ fields }),
    });
  }

  // #883 fix-verification write-back. Comments are ADF like descriptions. Jira has no universal
  // "closed" state — workflows are per-project — so transitionState resolves the available
  // transitions at call time by STATUS CATEGORY (the one Jira concept that is workflow-invariant):
  // "closed" takes the first transition into the done category; "reopened" prefers the new/to-do
  // category, falling back to any non-done transition. No candidate ⇒ throw (fail loud — a ticket
  // that cannot be transitioned must surface as a write-back failure, never a silent skip).
  async addComment(id: string, body: string): Promise<void> {
    const marker = body.match(/<!-- harvey-writeback:[a-f0-9]+ -->/)?.[0];
    if (marker) {
      const text = (node: AdfNode): string => (node.text ?? "") + (node.content?.map(text).join("") ?? "");
      let complete = false;
      let startAt = 0;
      for (let page = 0; page < 100; page++) {
        const res = await trackerFetchJson<{ comments: { body: AdfNode }[]; total: number }>(this.#fetch, `${this.#baseUrl}/rest/api/3/issue/${id}/comment?startAt=${startAt}&maxResults=100`, { method: "GET", headers: this.#jsonHeaders() });
        if (!Array.isArray(res.comments) || !Number.isSafeInteger(res.total) || res.total < startAt + res.comments.length) throw new Error("Jira comment recovery has invalid pagination");
        if (res.comments.some(comment => text(comment.body).includes(marker))) return;
        startAt += res.comments.length;
        if (startAt >= res.total) { complete = true; break; }
        if (!res.comments.length) throw new Error("Jira comment recovery incomplete: empty page");
      }
      if (!complete) throw new Error("Jira comment recovery incomplete: pagination limit");
    }
    await trackerFetch(this.#fetch, `${this.#baseUrl}/rest/api/3/issue/${id}/comment`, {
      method: "POST",
      headers: this.#jsonHeaders(),
      body: JSON.stringify({ body: markdownToAdf(body) }),
    });
  }

  async transitionState(id: string, to: TicketState): Promise<void> {
    const url = `${this.#baseUrl}/rest/api/3/issue/${id}/transitions`;
    const res = await trackerFetchJson<JiraTransitionsResponse>(this.#fetch, url, { method: "GET", headers: this.#jsonHeaders() });
    const category = (t: JiraTransitionsResponse["transitions"][number]) => t.to.statusCategory.key;
    const target =
      to === "closed"
        ? res.transitions.find((t) => category(t) === "done")
        : (res.transitions.find((t) => category(t) === "new") ?? res.transitions.find((t) => category(t) !== "done"));
    if (!target) throw new Error(`Jira issue ${id}: no workflow transition to a ${to === "closed" ? "done" : "reopened"}-category status is available`);
    await trackerFetch(this.#fetch, url, {
      method: "POST",
      headers: this.#jsonHeaders(),
      body: JSON.stringify({ transition: { id: target.id } }),
    });
  }

  async setEstimate(id: string, estimate: number): Promise<void> {
    await trackerFetch(this.#fetch, `${this.#baseUrl}/rest/api/3/issue/${id}`, {
      method: "PUT",
      headers: this.#jsonHeaders(),
      body: JSON.stringify({ fields: { [this.#storyPointsField]: estimate } }),
    });
  }

  async attachBrief(id: string, briefMarkdown: string): Promise<AttachedRef> {
    const form = new FormData();
    form.append("file", new Blob([briefMarkdown], { type: "text/markdown" }), `brief-${id}.md`);
    // No Content-Type header — fetch sets the multipart boundary. X-Atlassian-Token defeats XSRF checks.
    const attachments = await trackerFetchJson<JiraAttachment[]>(
      this.#fetch,
      `${this.#baseUrl}/rest/api/3/issue/${id}/attachments`,
      { method: "POST", headers: { Authorization: this.#auth, "X-Atlassian-Token": "no-check" }, body: form },
    );
    const attachment = attachments[0];
    if (!attachment) throw new Error(`Jira attachment upload for ${id} returned no attachment`);
    return { url: attachment.content };
  }
}
