// Linear tracker adapter (issue #733 — completes the five-tracker set named in the add-on). Linear's
// API is GraphQL: every operation is a POST to a single endpoint carrying { query, variables }.
//
// Linear has no separate epic/story types — it has Issues with a parent/child (sub-issue) relation —
// so the mapping is:
//   - Epic  -> an Issue.
//   - Story -> an Issue with parentId set to the epic, i.e. a sub-issue.
//   - Labels   -> Linear labels are entities referenced by id, not free strings, so setLabels resolves
//     each name to a team label id, CREATING any that don't exist yet (dropping a name would silently
//     lose a finding's severity label), then sets labelIds via issueUpdate.
//   - Estimate -> the issue's native `estimate` number field.
//   - Brief    -> Linear has no simple hosted-file endpoint, so the brief markdown is posted as a
//     comment on the issue (comments render markdown) and the comment's canonical URL is returned.
//
// Auth: a personal API key (or OAuth token) supplied by the caller, sent verbatim in the Authorization
// header — Linear's scheme for API keys, no "Bearer" prefix. The raw key never leaves that header
// (see credentials.test.ts).
//
// findByMarker filters issues whose description contains the marker. NOTE: as with the Jira adapter's
// JQL search, confirm the `description` filter behaves as an exact substring match against a real
// Linear workspace before relying on it for idempotency recovery.

import { appendTrackerBody, assertTrackerRef } from "./recovery.js";
import { trackerFetchJson } from "./http.js";
import type { AttachedRef, CreatedRef, ItemInput, TicketState, TicketWriteback, Tracker, UpdateStoryPatch } from "./types.js";

export interface LinearConfig {
  apiKey: string;
  teamId: string;
  apiUrl?: string; // default https://api.linear.app/graphql
  fetchImpl?: typeof fetch; // injection point for tests
}

interface GraphQLResponse<T> {
  data?: T;
  errors?: { message: string }[];
}

interface IssueRef {
  id: string;
  url: string;
}

export class LinearTracker implements Tracker, TicketWriteback {
  readonly #apiKey: string;
  readonly #teamId: string;
  readonly #url: string;
  readonly #fetch: typeof fetch;

  constructor(config: LinearConfig) {
    this.#apiKey = config.apiKey;
    this.#teamId = config.teamId;
    this.#url = config.apiUrl ?? "https://api.linear.app/graphql";
    this.#fetch = config.fetchImpl ?? fetch;
  }

  // Runs one GraphQL operation. A GraphQL endpoint answers 200 even for query errors, so a non-empty
  // `errors` array is surfaced as a throw here (the transport-level non-2xx throw lives in http.ts).
  async #graphql<T>(query: string, variables: Record<string, unknown>, mutation?: "issueCreate" | "commentCreate" | "issueUpdate" | "issueLabelCreate"): Promise<T> {
    const res = await trackerFetchJson<GraphQLResponse<T>>(this.#fetch, this.#url, {
      method: "POST",
      headers: { Authorization: this.#apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({ query, variables }),
    });
    if (res.errors?.length) throw new Error(`Linear GraphQL error: ${res.errors.map((e) => e.message).join("; ")}`);
    if (!res.data) throw new Error("Linear GraphQL response has no data");
    if (/^\s*mutation\b/.test(query)) {
      if (!mutation || !Object.hasOwn(res.data, mutation)) throw new Error("Linear mutation response has no operation result for the requested mutation");
      const value: unknown = (res.data as Record<string, unknown>)[mutation];
      if (!value || typeof value !== "object" || !("success" in value) || value.success !== true) throw new Error(`Linear ${mutation} failed: success was not true`);
    }
    return res.data as T;
  }

  createEpic(input: ItemInput): Promise<CreatedRef> {
    return this.#createIssue(input);
  }

  createStory(input: ItemInput, epicId: string): Promise<CreatedRef> {
    return this.#createIssue(input, epicId);
  }

  async #createIssue(input: ItemInput, parentId?: string): Promise<CreatedRef> {
    const data = await this.#graphql<{ issueCreate: { issue: IssueRef } }>(
      `mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id url } } }`,
      { input: { teamId: this.#teamId, title: input.title, description: input.description, parentId } },
      "issueCreate",
    );
    const issue = data.issueCreate.issue;
    return assertTrackerRef({ id: issue?.id, url: issue?.url });
  }

  async findByMarker(marker: string): Promise<CreatedRef | null> {
    const matches = new Map<string, CreatedRef>();
    const seen = new Set<string>();
    let after: string | undefined;
    for (let page = 0; page < 100; page++) {
      const data = await this.#graphql<{ issues: { nodes: (IssueRef & { description?: string; team?: { id: string } })[]; pageInfo?: { hasNextPage: boolean; endCursor?: string } } }>(
        `query($marker: String!, $teamId: String!, $after: String) { issues(filter: { description: { contains: $marker }, team: { id: { eq: $teamId } } }, first: 100, after: $after) { nodes { id url description team { id } } pageInfo { hasNextPage endCursor } } }`,
        { marker, teamId: this.#teamId, after });
      if (!Array.isArray(data.issues?.nodes) || typeof data.issues.pageInfo?.hasNextPage !== "boolean") throw new Error("Linear marker lookup has incomplete pagination");
      for (const hit of data.issues.nodes) {
        if (typeof hit.team?.id !== "string" || !hit.team.id || typeof hit.id !== "string" || !hit.id || typeof hit.url !== "string") throw new Error("Linear marker lookup lacks verified scope or identity");
        if (hit.team?.id === this.#teamId && hit.description?.includes(marker)) matches.set(hit.id, { id: hit.id, url: hit.url });
      }
      if (matches.size > 1) throw new Error("Linear marker lookup ambiguous: multiple exact matches in team");
      if (!data.issues.pageInfo?.hasNextPage) return [...matches.values()][0] ?? null;
      const cursor = data.issues.pageInfo.endCursor;
      if (!cursor || seen.has(cursor)) throw new Error("Linear marker lookup incomplete: invalid pagination");
      after = cursor; seen.add(cursor);
    }
    throw new Error("Linear marker lookup incomplete: pagination limit");
  }

  async completeStory(id: string, _input: ItemInput, labels: string[]): Promise<void> {
    const data = await this.#graphql<{ issue: { labels: { nodes: { id: string }[]; pageInfo: { hasNextPage: boolean } } } }>(
      `query($id: String!) { issue(id: $id) { labels(first: 250) { nodes { id } pageInfo { hasNextPage } } } }`, { id });
    if (data.issue.labels.pageInfo.hasNextPage) throw new Error("Linear label recovery incomplete: pagination limit");
    const existing = data.issue.labels.nodes.map(label => label.id);
    const requested = await this.#resolveLabelIds(labels);
    if (requested.some(label => !existing.includes(label))) await this.#updateIssue(id, { labelIds: [...new Set([...existing, ...requested])] });
  }

  async setLabels(id: string, labels: string[]): Promise<void> {
    const labelIds = await this.#resolveLabelIds(labels);
    await this.#updateIssue(id, { labelIds });
  }

  async updateStory(id: string, patch: UpdateStoryPatch): Promise<void> {
    const input: Record<string, unknown> = {};
    if (patch.body !== undefined) input.description = patch.body;
    if (patch.appendBody !== undefined) {
      const data = await this.#graphql<{ issue: { description: string | null } }>(
        `query($id: String!) { issue(id: $id) { description } }`, { id });
      const body = appendTrackerBody(data.issue?.description, patch.appendBody);
      if (body !== undefined) input.description = body;
    }
    if (patch.labels !== undefined) input.labelIds = await this.#resolveLabelIds(patch.labels);
    if (Object.keys(input).length === 0) return;
    await this.#updateIssue(id, input);
  }

  async setEstimate(id: string, estimate: number): Promise<void> {
    await this.#updateIssue(id, { estimate });
  }

  async attachBrief(id: string, briefMarkdown: string): Promise<AttachedRef> {
    const data = await this.#graphql<{ commentCreate: { comment: { url: string } } }>(
      `mutation($input: CommentCreateInput!) { commentCreate(input: $input) { success comment { url } } }`,
      { input: { issueId: id, body: briefMarkdown } },
      "commentCreate",
    );
    return { url: data.commentCreate.comment.url };
  }

  // #883 fix-verification write-back. Comments are native (same mutation attachBrief uses). Linear
  // issue states are per-team workflow-state ENTITIES, so transitionState resolves the team's
  // states at call time by their workflow-invariant `type`: "closed" takes the first completed-type
  // state; "reopened" prefers unstarted, falling back to backlog. No candidate ⇒ throw (fail loud).
  async addComment(id: string, body: string): Promise<void> {
    const marker = body.match(/<!-- harvey-writeback:[a-f0-9]+ -->/)?.[0];
    if (marker) {
      let after: string | undefined;
      const seen = new Set<string>();
      let complete = false;
      for (let page = 0; page < 100; page++) {
        const data = await this.#graphql<{ issue: { comments: { nodes: { body: string }[]; pageInfo: { hasNextPage: boolean; endCursor?: string } } } }>(
          `query($id: String!, $after: String) { issue(id: $id) { comments(first: 100, after: $after) { nodes { body } pageInfo { hasNextPage endCursor } } } }`, { id, after });
        if (!Array.isArray(data.issue?.comments?.nodes) || typeof data.issue.comments.pageInfo?.hasNextPage !== "boolean") throw new Error("Linear comment recovery has incomplete pagination");
        if (data.issue.comments.nodes.some(comment => comment.body.includes(marker))) return;
        if (!data.issue.comments.pageInfo.hasNextPage) { complete = true; break; }
        const cursor = data.issue.comments.pageInfo.endCursor;
        if (!cursor || seen.has(cursor)) throw new Error("Linear comment recovery incomplete: invalid pagination");
        seen.add(cursor); after = cursor;
      }
      if (!complete) throw new Error("Linear comment recovery incomplete: pagination limit");
    }
    await this.#graphql(
      `mutation($input: CommentCreateInput!) { commentCreate(input: $input) { success comment { url } } }`,
      { input: { issueId: id, body } },
      "commentCreate",
    );
  }

  async transitionState(id: string, to: TicketState): Promise<void> {
    const data = await this.#graphql<{ team: { states: { nodes: { id: string; name: string; type: string }[] } } }>(
      `query($teamId: String!) { team(id: $teamId) { states(first: 100) { nodes { id name type } } } }`,
      { teamId: this.#teamId },
    );
    const nodes = data.team.states.nodes;
    const state =
      to === "closed"
        ? nodes.find((s) => s.type === "completed")
        : (nodes.find((s) => s.type === "unstarted") ?? nodes.find((s) => s.type === "backlog"));
    if (!state) throw new Error(`Linear team ${this.#teamId}: no ${to === "closed" ? "completed" : "unstarted/backlog"}-type workflow state is available`);
    await this.#updateIssue(id, { stateId: state.id });
  }

  async #updateIssue(id: string, input: Record<string, unknown>): Promise<void> {
    const data = await this.#graphql<{ issueUpdate: { success: boolean } }>(
      `mutation($id: String!, $input: IssueUpdateInput!) { issueUpdate(id: $id, input: $input) { success } }`,
      { id, input },
      "issueUpdate",
    );
    if (data.issueUpdate?.success !== true) throw new Error("Linear issueUpdate failed: success was not true");
  }

  // Map label names to Linear label ids, creating any the team doesn't have yet.
  async #resolveLabelIds(names: string[]): Promise<string[]> {
    if (names.length === 0) return [];
    const data = await this.#graphql<{ team: { labels: { nodes: { id: string; name: string }[] } } }>(
      `query($teamId: String!) { team(id: $teamId) { labels(first: 250) { nodes { id name } } } }`,
      { teamId: this.#teamId },
    );
    const byName = new Map(data.team.labels.nodes.map((l) => [l.name, l.id]));
    const ids: string[] = [];
    for (const name of names) {
      const existing = byName.get(name);
      ids.push(existing ?? (await this.#createLabel(name)));
    }
    return ids;
  }

  async #createLabel(name: string): Promise<string> {
    const data = await this.#graphql<{ issueLabelCreate: { issueLabel: { id: string } } }>(
      `mutation($input: IssueLabelCreateInput!) { issueLabelCreate(input: $input) { success issueLabel { id } } }`,
      { input: { teamId: this.#teamId, name } },
      "issueLabelCreate",
    );
    return data.issueLabelCreate.issueLabel.id;
  }
}
