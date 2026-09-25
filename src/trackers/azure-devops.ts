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
//
// #50: findByMarker runs a WIQL CONTAINS query then fetches the hit for its html link; updateStory
// PATCHes System.Description / System.Tags via the same JSON-Patch endpoint setLabels/setEstimate use.

import { trackerFetch, trackerFetchJson } from "./http.js";
import type { AttachedRef, CreatedRef, ItemInput, TicketState, TicketWriteback, Tracker, UpdateStoryPatch } from "./types.js";

export interface AzureDevOpsConfig {
  orgUrl: string; // https://dev.azure.com/{org}
  project: string;
  pat: string;
  epicWorkItemType?: string; // default "Epic"
  storyWorkItemType?: string; // default "User Story"
  // #883: System.State values are process-template-dependent, so — like the work-item type names
  // above — the states transitionState writes are configurable, defaulting to the Agile process.
  closedStateName?: string; // default "Closed"
  reopenedStateName?: string; // default "New"
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
  fields?: Record<string, string>;
  relations?: {rel: string; url: string}[];
}

interface AdoAttachment {
  url: string;
}

interface AdoWiqlResult {
  workItems: { id: number }[];
}

export class AzureDevOpsTracker implements Tracker, TicketWriteback {
  readonly #auth: string;
  readonly #orgUrl: string;
  readonly #project: string;
  readonly #epicType: string;
  readonly #storyType: string;
  readonly #closedState: string;
  readonly #reopenedState: string;
  readonly #apiVersion: string;
  readonly #fetch: typeof fetch;

  constructor(config: AzureDevOpsConfig) {
    this.#auth = `Basic ${Buffer.from(`:${config.pat}`).toString("base64")}`;
    this.#orgUrl = config.orgUrl.replace(/\/$/, "");
    this.#project = config.project;
    this.#epicType = config.epicWorkItemType ?? "Epic";
    this.#storyType = config.storyWorkItemType ?? "User Story";
    this.#closedState = config.closedStateName ?? "Closed";
    this.#reopenedState = config.reopenedStateName ?? "New";
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

  // WIQL text search (real shape, #50), then a follow-up GET for the html link since WIQL only
  // returns work-item ids.
  async findByMarker(marker: string): Promise<CreatedRef | null> {
    const wiql = `SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = '${this.#project.replace(/'/g, "''")}' AND [System.Description] CONTAINS '${marker.replace(/'/g, "''")}'`;
    const result = await trackerFetchJson<AdoWiqlResult>(
      this.#fetch,
      `${this.#orgUrl}/${this.#project}/_apis/wit/wiql?api-version=${this.#apiVersion}`,
      { method: "POST", headers: { Authorization: this.#auth, "Content-Type": "application/json" }, body: JSON.stringify({ query: wiql }) },
    );
    const matches = new Map<string, CreatedRef>();
    for (const hit of result.workItems) {
      const wi = await trackerFetchJson<AdoWorkItem>(this.#fetch, `${this.#workItemApiUrl(String(hit.id))}?api-version=${this.#apiVersion}`, {
        method: "GET", headers: {Authorization: this.#auth},
      });
      if (wi.fields?.["System.TeamProject"] === this.#project && wi.fields["System.Description"]?.includes(marker)) matches.set(String(wi.id), {id: String(wi.id), url: wi._links.html.href});
      if (matches.size > 1) throw new Error("Azure marker lookup ambiguous: multiple exact matches in project");
    }
    return [...matches.values()][0] ?? null;
  }

  async completeStory(id: string, _input: ItemInput, labels: string[], epicId?: string): Promise<void> {
    const wi = await trackerFetchJson<AdoWorkItem>(this.#fetch, `${this.#workItemApiUrl(id)}?$expand=relations&api-version=${this.#apiVersion}`, {method: "GET", headers: {Authorization: this.#auth}});
    const existing = (wi.fields?.["System.Tags"] ?? "").split(";").map(label => label.trim()).filter(Boolean);
    const ops: JsonPatchOp[] = [];
    if (labels.some(label => !existing.includes(label))) ops.push({op: "add", path: "/fields/System.Tags", value: [...new Set([...existing, ...labels])].join("; ")});
    if (epicId) {
      const parents = (wi.relations ?? []).filter(rel => rel.rel === "System.LinkTypes.Hierarchy-Reverse");
      if (parents.some(parent => parent.url !== this.#workItemApiUrl(epicId))) throw new Error("Azure story already belongs to another epic");
      if (!parents.length) ops.push({op: "add", path: "/relations/-", value: {rel: "System.LinkTypes.Hierarchy-Reverse", url: this.#workItemApiUrl(epicId)}});
    }
    if (ops.length) await this.#patchWorkItem(id, ops);
  }

  async setLabels(id: string, labels: string[]): Promise<void> {
    await this.#patchWorkItem(id, [{ op: "add", path: "/fields/System.Tags", value: labels.join("; ") }]);
  }

  async updateStory(id: string, patch: UpdateStoryPatch): Promise<void> {
    const ops: JsonPatchOp[] = [];
    if (patch.body !== undefined) ops.push({ op: "add", path: "/fields/System.Description", value: patch.body });
    if (patch.labels !== undefined) ops.push({ op: "add", path: "/fields/System.Tags", value: patch.labels.join("; ") });
    if (ops.length === 0) return;
    await this.#patchWorkItem(id, ops);
  }

  // #883 fix-verification write-back. A System.History add is Azure's discussion-comment write —
  // it appends to the work item's Discussion, never touching System.Description. State writes the
  // configured process-template state name; a wrong name for the project's process fails the PATCH
  // loudly (surfaced as a write-back failure), it is never silently absorbed.
  async addComment(id: string, body: string): Promise<void> {
    const marker = body.match(/<!-- harvey-writeback:[a-f0-9]+ -->/)?.[0];
    if (marker) {
      let token: string | undefined;
      const seen = new Set<string>();
      let complete = false;
      for (let page = 0; page < 100; page++) {
        const query = new URLSearchParams({"api-version": `${this.#apiVersion}-preview.4`, "$top": "200", includeDeleted: "false"});
        if (token) query.set("continuationToken", token);
        const result = await trackerFetchJson<{comments: {text: string}[]; continuationToken?: string}>(this.#fetch, `${this.#orgUrl}/${this.#project}/_apis/wit/workItems/${id}/comments?${query}`, {method: "GET", headers: {Authorization: this.#auth}});
        if (result.comments.some(comment => comment.text.includes(marker))) return;
        if (!result.continuationToken) {complete = true; break;}
        if (seen.has(result.continuationToken)) throw new Error("Azure comment recovery incomplete: repeated cursor");
        token = result.continuationToken; seen.add(token);
      }
      if (!complete) throw new Error("Azure comment recovery incomplete: pagination limit");
    }
    await this.#patchWorkItem(id, [{ op: "add", path: "/fields/System.History", value: body }]);
  }

  async transitionState(id: string, to: TicketState): Promise<void> {
    const state = to === "closed" ? this.#closedState : this.#reopenedState;
    await this.#patchWorkItem(id, [{ op: "add", path: "/fields/System.State", value: state }]);
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
