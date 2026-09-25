import { describe, expect, it } from "vitest";
import { GitHubTracker } from "./github.js";
import { GitLabTracker } from "./gitlab.js";
import { LinearTracker } from "./linear.js";
import { JiraTracker } from "./jira.js";
import { AzureDevOpsTracker } from "./azure-devops.js";
import type { Tracker } from "./types.js";

describe("brief links preserve remote descriptions on retry", () => {
  it.each(["github", "gitlab", "linear", "jira", "azure"])("appends once through the actual %s adapter", async name => {
    const addition = "📄 Implementation brief: https://fixture.test/brief";
    const annotation = "Client annotation that must survive";
    const richNode = { type: "paragraph", content: [{ type: "text", text: annotation, marks: [{ type: "strong" }] }] };
    let description: unknown = name === "jira" ? { type: "doc", version: 1, content: [richNode] } : annotation;
    let writes = 0;
    const fetchImpl: typeof fetch = async (_url, init) => {
      const method = init?.method ?? "GET";
      const input = typeof init?.body === "string" ? JSON.parse(init.body) : {};
      if (name === "linear") {
        if (input.query.includes("query(")) return Response.json({ data: { issue: { description } } });
        writes++; description = input.variables.input.description;
        return Response.json({ data: { issueUpdate: { success: true } } });
      }
      if (method === "GET") {
        if (name === "github") return Response.json({ body: description });
        if (name === "gitlab") return Response.json({ description });
        return Response.json({ fields: { [name === "jira" ? "description" : "System.Description"]: description } });
      }
      writes++;
      if (name === "github") description = input.body;
      if (name === "gitlab") description = input.description;
      if (name === "jira") description = input.fields.description;
      if (name === "azure") description = input[0].value;
      return Response.json({});
    };
    const trackers: Record<string, () => Tracker> = {
      github: () => new GitHubTracker({ token: "fixture-token", owner: "o", repo: "r", fetchImpl }),
      gitlab: () => new GitLabTracker({ token: "fixture-token", projectId: "1", fetchImpl }),
      linear: () => new LinearTracker({ apiKey: "fixture-token", teamId: "T", fetchImpl }),
      jira: () => new JiraTracker({ baseUrl: "https://fixture.test", email: "fixture@example.test", apiToken: "fixture-token", projectKey: "P", fetchImpl }),
      azure: () => new AzureDevOpsTracker({ orgUrl: "https://dev.azure.com/fixture", project: "P", pat: "fixture-token", fetchImpl }),
    };
    const tracker = trackers[name]!();
    await tracker.updateStory("1", { appendBody: addition });
    await tracker.updateStory("1", { appendBody: addition });
    expect(writes).toBe(1);
    expect(JSON.stringify(description)).toContain(annotation);
    expect(JSON.stringify(description)).toContain(addition);
    if (name === "jira") expect(description).toMatchObject({ content: [richNode, { type: "paragraph" }] });
    description = undefined;
    await expect(tracker.updateStory("1", { appendBody: addition })).rejects.toThrow(/description|content/i);
    expect(writes).toBe(1);
  });
});
