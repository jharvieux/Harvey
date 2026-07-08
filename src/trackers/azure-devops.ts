// Azure DevOps tracker adapter (issue #22). Work Items REST API (docs:
// learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items).
//
// Creates and field updates use the JSON-Patch document format (Content-Type
// application/json-patch+json) — an array of { op, path, value } operations. Epic->story linkage is a
// parent/child work-item link (System.LinkTypes.Hierarchy-Reverse points a child at its parent).
// Attachments are a two-step upload-then-link: POST the bytes to the attachments endpoint, then add
// an AttachedFile relation to the work item pointing at the returned attachment URL.
//
// Auth: a Personal Access Token sent as HTTP Basic with an empty username
// (Authorization: Basic base64(":" + pat)). Work-item type names are process-dependent, so the
// epic/story type names are configurable (defaults "Epic" / "User Story", the Agile process).

import { trackerFetch, trackerFetchJson } from "./http.js";
import type { AttachedRef, CreatedRef, ItemInput, Tracker } from "./types.js";

export interface AzureDevOpsConfig {
  orgUrl: string; // https://dev.azure.com/{org}
  project: string;
  pat: string;
  epicWorkItemType?: string; // default "Epic"
  storyWorkItemType?: string; // default "User Story"
  apiVersion?: string; // default "7.1"
  fetchImpl?: typeof fetch; // injection point for tests
}

interface JsonPatchOp {
  op: "add";
  path: string;
  value: unknown;
}

interface AdoWorkItem {
  id: number;
  _links: { html: { href: string } };
}

interface AdoAttachment {
  url: string;
}

export class AzureDevOpsTracker implements Tracker {
  readonly #auth: string;
  readonly #orgUrl: string;
  readonly #project: string;
  readonly #epicType: string;
  readonly #storyType: string;
  readonly #apiVersion: string;
  readonly #fetch: typeof fetch;

  constructor(config: AzureDevOpsConfig) {
    this.#auth = `Basic ${Buffer.from(`:${config.pat}`).toString("base64")}`;
    this.#orgUrl = config.orgUrl.replace(/\/$/, "");
    this.#project = config.project;
    this.#epicType = config.epicWorkItemType ?? "Epic";
    this.#storyType = config.storyWorkItemType ?? "User Story";
    this.#apiVersion = config.apiVersion ?? "7.1";
    this.#fetch = config.fetchImpl ?? fetch;
  }

  #workItemApiUrl(id: string): string {
    return `${this.#orgUrl}/_apis/wit/workItems/${id}`;
  }

  createEpic(input: ItemInput): Promise<CreatedRef> {
    return this.#createWorkItem(this.#epicType, [
      { op: "add", path: "/fields/System.Title", value: input.title },
      { op: "add", path: "/fields/System.Description", value: input.description },
    ]);
  }

  createStory(input: ItemInput, epicId: string): Promise<CreatedRef> {
    return this.#createWorkItem(this.#storyType, [
      { op: "add", path: "/fields/System.Title", value: input.title },
      { op: "add", path: "/fields/System.Description", value: input.description },
      {
        op: "add",
        path: "/relations/-",
        value: { rel: "System.LinkTypes.Hierarchy-Reverse", url: this.#workItemApiUrl(epicId) },
      },
    ]);
  }

  async #createWorkItem(type: string, patch: JsonPatchOp[]): Promise<CreatedRef> {
    const url = `${this.#orgUrl}/${this.#project}/_apis/wit/workitems/$${encodeURIComponent(type)}?api-version=${this.#apiVersion}`;
    const wi = await trackerFetchJson<AdoWorkItem>(this.#fetch, url, {
      method: "POST",
      headers: { Authorization: this.#auth, "Content-Type": "application/json-patch+json" },
      body: JSON.stringify(patch),
    });
    return { id: String(wi.id), url: wi._links.html.href };
  }

  #patchWorkItem(id: string, patch: JsonPatchOp[]): Promise<Response> {
    return trackerFetch(this.#fetch, `${this.#orgUrl}/${this.#project}/_apis/wit/workitems/${id}?api-version=${this.#apiVersion}`, {
      method: "PATCH",
      headers: { Authorization: this.#auth, "Content-Type": "application/json-patch+json" },
      body: JSON.stringify(patch),
    });
  }

  async setLabels(id: string, labels: string[]): Promise<void> {
    await this.#patchWorkItem(id, [{ op: "add", path: "/fields/System.Tags", value: labels.join("; ") }]);
  }

  async setEstimate(id: string, estimate: number): Promise<void> {
    await this.#patchWorkItem(id, [{ op: "add", path: "/fields/Microsoft.VSTS.Scheduling.StoryPoints", value: estimate }]);
  }

  async attachBrief(id: string, briefMarkdown: string): Promise<AttachedRef> {
    const uploadUrl = `${this.#orgUrl}/${this.#project}/_apis/wit/attachments?fileName=brief-${id}.md&api-version=${this.#apiVersion}`;
    const attachment = await trackerFetchJson<AdoAttachment>(this.#fetch, uploadUrl, {
      method: "POST",
      headers: { Authorization: this.#auth, "Content-Type": "application/octet-stream" },
      body: briefMarkdown,
    });
    await this.#patchWorkItem(id, [
      {
        op: "add",
        path: "/relations/-",
        value: { rel: "AttachedFile", url: attachment.url, attributes: { comment: "Implementation brief" } },
      },
    ]);
    return { url: attachment.url };
  }
}
