import { describe, expect, it } from "vitest";
import { GitLabTracker } from "./gitlab.js";
import { AzureDevOpsTracker } from "./azure-devops.js";
import { GitHubTracker } from "./github.js";
import { JiraTracker } from "./jira.js";
import { LinearTracker } from "./linear.js";

const marker = "<!-- harvey-finding:123456789abc -->";
const near = "<!-- harvey-finding:123456789abcdef -->";
const adf = (text: string) => ({ type: "doc", version: 1, content: [{ type: "paragraph", content: [{ type: "text", text }] }] });

function identityFixture(kind: "github" | "jira" | "linear" | "gitlab" | "azure", ambiguous = false) {
  const expected = { id: "42", url: "https://github.com/acme/app/issues/42" };
  const rows = [
    { id: "1", body: near, scope: "app" },
    { id: "2", body: marker, scope: "other" },
    { id: "42", body: `Client notes\n${marker}\n`, scope: "app" },
    ...(ambiguous ? [{ id: "43", body: marker, scope: "app" }] : []),
  ];
  const calls: { url: string; method: string }[] = [];
  const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
    calls.push({ url: String(url), method: init?.method ?? "GET" });
    if (kind === "gitlab") return Response.json(rows.map(r => ({iid: Number(r.id), web_url: `https://gitlab.com/acme/${r.scope}/-/issues/${r.id}`, description: r.body, project_id: r.scope === "app" ? 7 : 8})));
    if (kind === "azure") {
      if (String(url).includes("/wiql?")) return Response.json({workItems: rows.map(r => ({id: Number(r.id)}))});
      const id = new URL(url).pathname.split("/").at(-1)!;
      const row = rows.find(r => r.id === id)!;
      return Response.json({id: Number(id), _links: {html: {href: `https://dev.azure.com/acme/${row.scope}/_workitems/edit/${id}`}}, fields: {"System.TeamProject": row.scope, "System.Description": row.body}});
    }
    if (kind === "github") return new Response(JSON.stringify({ items: rows.map(r => ({ number: Number(r.id), html_url: `https://github.com/acme/${r.scope}/issues/${r.id}`, repository_url: `https://api.github.com/repos/acme/${r.scope}`, body: r.body })), total_count: rows.length, incomplete_results: false }));
    if (kind === "jira") return new Response(JSON.stringify({ issues: rows.map(r => ({ key: `AUD-${r.id}`, fields: { project: { key: r.scope === "app" ? "AUD" : "OTHER" }, description: adf(r.body) } })), isLast: true }));
    return new Response(JSON.stringify({ data: { issues: { nodes: rows.map(r => ({ id: r.id, url: `https://linear.app/acme/issue/${r.id}`, description: r.body, team: { id: r.scope } })), pageInfo: { hasNextPage: false, endCursor: null } } } }));
  }) as typeof fetch;
  const tracker = kind === "github" ? new GitHubTracker({ token: "synthetic", owner: "acme", repo: "app", fetchImpl })
    : kind === "jira" ? new JiraTracker({ baseUrl: "https://jira.invalid", email: "fixture@example.invalid", apiToken: "synthetic", projectKey: "AUD", fetchImpl })
      : kind === "linear" ? new LinearTracker({ apiKey: "synthetic", teamId: "app", fetchImpl })
        : kind === "gitlab" ? new GitLabTracker({token: "synthetic", projectId: "7", fetchImpl})
          : new AzureDevOpsTracker({orgUrl: "https://dev.azure.com/acme", project: "app", pat: "synthetic", fetchImpl});
  if (kind === "jira") Object.assign(expected, { id: "AUD-42", url: "https://jira.invalid/browse/AUD-42" });
  if (kind === "linear") expected.url = "https://linear.app/acme/issue/42";
  if (kind === "gitlab") expected.url = "https://gitlab.com/acme/app/-/issues/42";
  if (kind === "azure") expected.url = "https://dev.azure.com/acme/app/_workitems/edit/42";
  return { tracker, expected, calls };
}

describe("tracker identity through actual response consumers", () => {
  for (const kind of ["github", "jira", "linear", "gitlab", "azure"] as const) {
    it(`${kind} rejects near markers and other configured scopes`, async () => {
      const f = identityFixture(kind);
      expect(await f.tracker.findByMarker(marker)).toEqual(f.expected);
      expect(f.calls.every(c => c.method === "GET" || kind === "linear" || kind === "azure")).toBe(true);
    });
    it(`${kind} refuses ambiguous exact matches`, async () => {
      const f = identityFixture(kind, true);
      await expect(f.tracker.findByMarker(marker)).rejects.toThrow(/ambiguous/i);
    });
  }
  it("treats Linear issueUpdate success:false as an unsuccessful remote write", async () => {
    const tracker = new LinearTracker({ apiKey: "synthetic", teamId: "app", fetchImpl: (async () => new Response(JSON.stringify({ data: { issueUpdate: { success: false } } }))) as typeof fetch });
    await expect(tracker.setEstimate("42", 3)).rejects.toThrow(/issueUpdate.*failed/i);
  });
});

function githubState() {
  const issues = new Map<number, { number: number; html_url: string; repository_url: string; body: string; labels: string[]; state: string }>();
  const comments: { issue: number; body: string }[] = [];
  const failures = { link: false, labels: false, transition: false };
  let next = 1;
  const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
    const u = new URL(url);
    const method = init?.method ?? "GET";
    const data = init?.body ? JSON.parse(String(init.body)) : {};
    const json = (value: unknown) => new Response(JSON.stringify(value));
    if (u.pathname === "/search/issues") {
      const m = u.searchParams.get("q")?.match(/<!-- .*? -->/)?.[0] ?? "";
      const items = [...issues.values()].filter(i => i.body.includes(m));
      return json({ items, total_count: items.length, incomplete_results: false });
    }
    if (u.pathname === "/repos/acme/app/issues" && method === "POST") {
      const number = next++;
      const issue = { number, html_url: `https://github.com/acme/app/issues/${number}`, repository_url: "https://api.github.com/repos/acme/app", body: data.body, labels: [], state: "open" };
      issues.set(number, issue); return json(issue);
    }
    const match = u.pathname.match(/^\/repos\/acme\/app\/issues\/(\d+)(\/comments|\/labels)?$/);
    if (!match) throw new Error(`unhandled fixture ${method} ${u.pathname}`);
    const id = Number(match[1]); const issue = issues.get(id);
    if (!issue) return new Response("missing", { status: 404 });
    if (match[2] === "/comments") {
      if (method === "GET") return json(comments.filter(c => c.issue === id));
      comments.push({ issue: id, body: data.body }); return json({ id: comments.length });
    }
    if (match[2] === "/labels") {
      if (failures.labels) { failures.labels = false; return new Response("labels failed", { status: 500 }); }
      issue.labels = data.labels; return json(issue.labels);
    }
    if (method === "GET") return json(issue);
    if (method === "PATCH") {
      if (data.body !== undefined && failures.link) { failures.link = false; return new Response("link failed", { status: 500 }); }
      if (data.state !== undefined && failures.transition) { failures.transition = false; return new Response("transition failed", { status: 500 }); }
      Object.assign(issue, data); return json(issue);
    }
    throw new Error(`unhandled fixture ${method} ${u.pathname}`);
  }) as typeof fetch;
  const tracker = () => new GitHubTracker({ token: "synthetic", owner: "acme", repo: "app", fetchImpl });
  return { tracker, issues, comments, failures };
}

import { fileFindings } from "./findings-to-tickets.js";
import { writeBackVerification } from "./verify-writeback.js";
import type { Finding } from "../findings.js";
import type { GateReport } from "../fix/gate.js";
const finding: Finding = { status: "open", impact: "Synthetic", value: 5, ease: 4, safety: 5, id: "F-01", title: "Finding", severity: "High", confidence: "Confirmed", category: "Test", taxonomy: "TEST", location: "a.ts:1", evidence: "Evidence", fix: "Repair" };

describe("stateful remote effect recovery", () => {
  for (const stage of ["link", "labels"] as const) it(`retains creation after ${stage} failure and repairs it without duplicates or description loss`, async () => {
    const f = githubState(); f.failures[stage] = true;
    const first = await fileFindings(f.tracker(), [finding], { paid: true, engagement: "synthetic" });
    expect(first.failed).toHaveLength(1);
    expect(first.created).toHaveLength(1);
    expect(first.failed[0]?.ref?.id).toBe("2");
    const persisted = JSON.parse(JSON.stringify(first));
    expect(persisted.created[0].ref.id).toBe("2");
    const story = f.issues.get(2)!; story.body += "\nClient annotation"; story.labels.push("client-priority");
    const second = await fileFindings(f.tracker(), [finding], { paid: true, engagement: "synthetic" });
    expect(second.failed).toEqual([]);
    expect(second.skipped).toHaveLength(1);
    expect(f.issues.size).toBe(2);
    expect(f.issues.get(1)?.body.match(/- \[ \] #2 /g)).toHaveLength(1);
    expect(story.body).toContain("Client annotation");
    expect(story.labels).toContain("client-priority");
    expect(story.labels).toContain("harvey");
  });

  it("retries a completed comment followed by failed state change without adding a second comment", async () => {
    const f = githubState();
    const tracker = f.tracker();
    await tracker.createEpic({ title: "Existing", description: `Client prose\n${marker}` });
    const report: GateReport = { engagement: "synthetic", targetDir: "/synthetic", commit: "abc", generatedAt: "2026-01-01T00:00:00Z", counts: { resolved: 1, persistent: 0, regressed: 0, unverifiable: 0 }, results: [{ findingId: "F-01", marker, identity: "synthetic", title: "Finding", taxonomy: "TEST", location: "a.ts:1", status: "resolved", detail: "Detector ran" }] };
    f.failures.transition = true;
    const first = await writeBackVerification(tracker, report);
    expect(first.failed).toBe(1);
    expect(JSON.parse(JSON.stringify(first)).records[0]).toMatchObject({ ticket: { id: "1" }, commentCompleted: true, action: "none" });
    expect(f.comments).toHaveLength(1);
    const second = await writeBackVerification(f.tracker(), report);
    expect(second.closed).toBe(1);
    expect(f.comments).toHaveLength(1);
    expect(f.issues.get(1)).toMatchObject({ body: `Client prose\n${marker}`, state: "closed" });
  });
  it("retains a Linear comment while success:false prevents a reported state transition, then recovers", async () => {
    const comments: string[] = [];
    let state = "open";
    let rejectUpdate = true;
    const fetchImpl = (async (_url: string | URL, init?: RequestInit) => {
      const {query, variables} = JSON.parse(String(init?.body));
      const json = (data: unknown) => Response.json({data});
      if (query.includes("issues(filter:")) return json({issues: {nodes: [{id: "42", url: "https://linear.app/acme/issue/42", description: marker, team: {id: "app"}}], pageInfo: {hasNextPage: false}}});
      if (query.includes("comments(first:")) return json({issue: {comments: {nodes: comments.map(body => ({body})), pageInfo: {hasNextPage: false}}}});
      if (query.includes("commentCreate(")) {comments.push(variables.input.body); return json({commentCreate: {success: true, comment: {url: "https://linear.app/comment/1"}}});}
      if (query.includes("states(first:")) return json({team: {states: {nodes: [{id: "closed", name: "Done", type: "completed"}]}}});
      if (query.includes("issueUpdate(")) {
        if (rejectUpdate) {rejectUpdate = false; return json({issueUpdate: {success: false}});}
        state = variables.input.stateId; return json({issueUpdate: {success: true}});
      }
      throw new Error(`Unexpected Linear fixture query ${query}`);
    }) as typeof fetch;
    const tracker = () => new LinearTracker({apiKey: "synthetic", teamId: "app", fetchImpl});
    const report: GateReport = {engagement: "synthetic", targetDir: "/synthetic", commit: "abc", generatedAt: "2026-01-01T00:00:00Z", counts: {resolved: 1, persistent: 0, regressed: 0, unverifiable: 0}, results: [{findingId: "F-01", marker, identity: "synthetic", title: "Finding", taxonomy: "TEST", location: "a.ts:1", status: "resolved", detail: "Detector ran"}]};
    const first = await writeBackVerification(tracker(), report);
    expect(first).toMatchObject({closed: 0, failed: 1, records: [{ticket: {id: "42"}, commentCompleted: true, action: "none", error: expect.stringContaining("issueUpdate failed")}]});
    expect(state).toBe("open"); expect(comments).toHaveLength(1);
    const second = await writeBackVerification(tracker(), report);
    expect(second).toMatchObject({closed: 1, failed: 0});
    expect(state).toBe("closed"); expect(comments).toHaveLength(1);
  });

  it.each(["gitlab", "azure"] as const)("%s reuses the retained writeback comment marker", async kind => {
    const comments: string[] = [];
    const fetchImpl = (async (_url: string | URL, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "GET") return kind === "gitlab" ? Response.json(comments.map(body => ({body}))) : Response.json({comments: comments.map(text => ({text}))});
      const payload = JSON.parse(String(init?.body));
      comments.push(kind === "gitlab" ? payload.body : payload[0].value);
      return Response.json({});
    }) as typeof fetch;
    const tracker = () => kind === "gitlab" ? new GitLabTracker({token: "synthetic", projectId: "7", fetchImpl}) : new AzureDevOpsTracker({orgUrl: "https://dev.azure.com/acme", project: "app", pat: "synthetic", fetchImpl});
    const body = "Result\n<!-- harvey-writeback:abcdef -->";
    await tracker().addComment("42", body);
    await tracker().addComment("42", body);
    expect(comments).toEqual([body]);
  });

});
