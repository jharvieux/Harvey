import { describe, expect, it } from "vitest";
import { GitHubTracker } from "./github.js";
import { GitLabTracker } from "./gitlab.js";
import { JiraTracker } from "./jira.js";
import { LinearTracker } from "./linear.js";
import { AzureDevOpsTracker } from "./azure-devops.js";
import { fileFindings } from "./findings-to-tickets.js";
import type { Finding } from "../findings.js";

const marker = "<!-- harvey-finding:abc123 -->";
const comment = "<!-- harvey-writeback:abcdef -->";
const finding: Finding = { id: "F-1", title: "Finding", severity: "High", confidence: "Confirmed", category: "Correctness", taxonomy: "M5 — Missing error handling", location: "a.ts:1", status: "Open", evidence: "Observed", impact: "Broken behavior", fix: "Handle errors", precisionTier: "high", value: 3, ease: 3, safety: 3 };
type Kind = "github" | "gitlab" | "jira" | "linear" | "azure";
function adapter(kind: Kind, fetchImpl: typeof fetch) {
  if (kind === "github") return new GitHubTracker({ token: "synthetic", owner: "acme", repo: "app", fetchImpl });
  if (kind === "gitlab") return new GitLabTracker({ token: "synthetic", projectId: "7", fetchImpl });
  if (kind === "jira") return new JiraTracker({ baseUrl: "https://jira.invalid", email: "synthetic@example.invalid", apiToken: "synthetic", projectKey: "APP", fetchImpl });
  if (kind === "linear") return new LinearTracker({ apiKey: "synthetic", teamId: "APP", fetchImpl });
  return new AzureDevOpsTracker({ orgUrl: "https://dev.azure.com/acme", project: "APP", pat: "synthetic", fetchImpl });
}

describe("recovery refuses unproved remote state", () => {
  it.each(["github", "jira", "linear"] as const)("%s requires explicit complete marker pagination before accepting an empty result", async kind => {
    let writes = 0;
    const fetchImpl = (async (_url: string | URL, init?: RequestInit) => {
      if ((init?.method ?? "GET") !== "GET" && !(kind === "linear" && String(init?.body).includes("issues(filter:"))) writes++;
      return Response.json(kind === "github" ? { items: [] } : kind === "jira" ? { issues: [] } : { data: { issues: { nodes: [] } } });
    }) as typeof fetch;
    const result = await fileFindings(adapter(kind, fetchImpl), [finding], { grouping: "flat", paid: true });
    expect(result.failed).toHaveLength(1);
    expect(result.failed[0]?.stage).toBe("lookup");
    expect(writes).toBe(0);
  });

  for (const kind of ["github", "gitlab", "jira", "linear", "azure"] as const) {
    it(`${kind} does not create or modify after scope identity is omitted`, async () => {
      let writes = 0;
      const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
        const body = String(init?.body ?? "");
        const query = kind === "linear" && body.includes("issues(filter:");
        const wiql = kind === "azure" && String(url).includes("/wiql?");
        if ((init?.method ?? "GET") !== "GET" && !query && !wiql) writes++;
        if (kind === "github") return Response.json({ items: [{ number: 42, html_url: "https://foreign.invalid/acme/app/issues/42", body: marker }], total_count: 1, incomplete_results: false });
        if (kind === "gitlab") return Response.json([{ iid: 42, web_url: "https://gitlab.com/acme/app/-/issues/42", description: marker }]);
        if (kind === "jira") return Response.json({ issues: [{ key: "APP-42", fields: { description: { type: "doc", content: [{ type: "text", text: marker }] } } }], isLast: true });
        if (kind === "linear") return Response.json({ data: { issues: { nodes: [{ id: "42", url: "https://linear.app/issue/42", description: marker }], pageInfo: { hasNextPage: false } } } });
        return wiql ? Response.json({ workItems: [{ id: 42 }] }) : Response.json({ id: 42, fields: { "System.Description": marker }, _links: { html: { href: "https://dev.azure.com/acme/APP/_workitems/edit/42" } } });
      }) as typeof fetch;
      const result = await fileFindings(adapter(kind, fetchImpl), [finding], { grouping: "flat", paid: true });
      expect(result.failed).toHaveLength(1);
      expect(result.failed[0]?.stage).toBe("lookup");
      expect(result.created).toEqual([]);
      expect(writes).toBe(0);
    });
    it(`${kind} rejects a create response without a usable remote reference`, async () => {
      const fetchImpl = (async () => Response.json(kind === "linear" ? { data: { issueCreate: { success: true, issue: {} } } } : {})) as typeof fetch;
      await expect(adapter(kind, fetchImpl).createEpic({ title: "Synthetic", description: marker })).rejects.toThrow();
    });
  }

  for (const kind of ["github", "gitlab"] as const) {
    it(`${kind} follows a short comment page's next Link and preserves the existing comment`, async () => {
      let writes = 0;
      const pages: string[] = [];
      const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
        if ((init?.method ?? "GET") !== "GET") { writes++; return Response.json({}); }
        pages.push(String(url));
        const next = new URL(url); next.searchParams.set("page", "2");
        return pages.length === 1 ? Response.json([{ body: "Client notes" }], { headers: { Link: `<${next}>; rel="next"` } }) : Response.json([{ body: comment }]);
      }) as typeof fetch;
      await adapter(kind, fetchImpl).addComment("42", comment);
      expect(pages).toHaveLength(2);
      expect(writes).toBe(0);
    });
    it(`${kind} refuses a next Link that would send credentials to another origin`, async () => {
      const urls: string[] = [];
      const fetchImpl = (async (url: string | URL) => { urls.push(String(url)); return Response.json([], { headers: { Link: '<https://foreign.invalid/next>; rel="next"' } }); }) as typeof fetch;
      await expect(adapter(kind, fetchImpl).addComment("42", comment)).rejects.toThrow(/endpoint scope/);
      expect(urls).toHaveLength(1);
    });
  }

  it("GitLab reads later identity pages before accepting one exact candidate", async () => {
    let pages = 0;
    const fetchImpl = (async (url: string | URL) => {
      pages++;
      const next = new URL(url); next.searchParams.set("page", "2");
      const rows = [{ iid: pages, project_id: 7, web_url: `https://gitlab.com/acme/app/-/issues/${pages}`, description: marker }];
      return Response.json(rows, pages === 1 ? { headers: { Link: `<${next}>; rel=next` } } : undefined);
    }) as typeof fetch;
    await expect(adapter("gitlab", fetchImpl).findByMarker(marker)).rejects.toThrow(/ambiguous/);
    expect(pages).toBe(2);
  });

  it.each([undefined, null, false, {}, { success: null }, { success: false }])("Linear does not accept a malformed comment mutation result: %j", async result => {
    const tracker = adapter("linear", (async () => Response.json({ data: { commentCreate: result } })) as typeof fetch);
    await expect(tracker.addComment("42", "Unstamped comment")).rejects.toThrow(/failed|no operation/);
  });

  it.each(["jira", "linear", "azure"] as const)("%s refuses malformed comment pagination before posting", async kind => {
    let writes = 0;
    const fetchImpl = (async (_url: string | URL, init?: RequestInit) => {
      const isRead = (init?.method ?? "GET") === "GET" || (kind === "linear" && String(init?.body).includes("comments(first:"));
      if (!isRead) writes++;
      return Response.json(kind === "jira" ? { comments: [], total: -1 }
        : kind === "linear" ? { data: { issue: { comments: { nodes: [], pageInfo: { hasNextPage: 0 } } } } }
          : { comments: [], continuationToken: 0 });
    }) as typeof fetch;
    await expect(adapter(kind, fetchImpl).addComment("42", comment)).rejects.toThrow(/pagination/);
    expect(writes).toBe(0);
  });
});
