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

import { trackerFetch, trackerFetchJson } from "./http.js";
import type { AttachedRef, CreatedRef, ItemInput, Tracker } from "./types.js";

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

export class JiraTracker implements Tracker {
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
    return { id: created.key, url: `${this.#baseUrl}/browse/${created.key}` };
  }

  async setLabels(id: string, labels: string[]): Promise<void> {
    await trackerFetch(this.#fetch, `${this.#baseUrl}/rest/api/3/issue/${id}`, {
      method: "PUT",
      headers: this.#jsonHeaders(),
      body: JSON.stringify({ fields: { labels } }),
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
