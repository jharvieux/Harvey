import { describe, expect, it, vi } from "vitest";
import { JiraTracker, type JiraConfig } from "./jira.js";

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: RequestInit["body"];
}

function harness(routes: (call: Call) => unknown) {
  const calls: Call[] = [];
  const fetchImpl = vi.fn(async (url: string | URL, init?: RequestInit) => {
    calls.push({
      url: url.toString(),
      method: init?.method ?? "GET",
      headers: (init?.headers as Record<string, string>) ?? {},
      body: init?.body,
    });
    return new Response(JSON.stringify(routes({ url: url.toString(), method: init?.method ?? "GET", headers: {}, body: init?.body }) ?? {}));
  }) as unknown as typeof fetch;
  const config: JiraConfig = {
    baseUrl: "https://acme.atlassian.net",
    email: "auditor@acme.com",
    apiToken: "jira-token",
    projectKey: "AUD",
    fetchImpl,
  };
  const tracker = new JiraTracker(config);
  return { tracker, calls };
}

function jsonBody(call: Call | undefined): Record<string, unknown> {
  return JSON.parse(String(call?.body)) as Record<string, unknown>;
}

describe("JiraTracker", () => {
  it("creates an epic with an ADF description and returns the issue key + browse URL", async () => {
    const { tracker, calls } = harness(() => ({ key: "AUD-1" }));
    const ref = await tracker.createEpic({ title: "Epic A", description: "First para.\n\nSecond para." });

    expect(ref).toEqual({ id: "AUD-1", url: "https://acme.atlassian.net/browse/AUD-1" });
    const fields = (jsonBody(calls[0]).fields as Record<string, unknown>);
    expect((fields.issuetype as { name: string }).name).toBe("Epic");
    const adf = fields.description as { type: string; content: { type: string }[] };
    expect(adf.type).toBe("doc");
    expect(adf.content).toHaveLength(2); // one paragraph per blank-line-separated block
    expect(adf.content.every((n) => n.type === "paragraph")).toBe(true);
    // HTTP Basic from email:apiToken.
    expect(calls[0]?.headers.Authorization).toBe(`Basic ${Buffer.from("auditor@acme.com:jira-token").toString("base64")}`);
  });

  it("links a story to its epic via the parent field", async () => {
    const { tracker, calls } = harness(() => ({ key: "AUD-2" }));
    const ref = await tracker.createStory({ title: "Story", description: "desc" }, "AUD-1");

    expect(ref.id).toBe("AUD-2");
    const fields = jsonBody(calls[0]).fields as { parent: { key: string }; issuetype: { name: string } };
    expect(fields.parent.key).toBe("AUD-1");
    expect(fields.issuetype.name).toBe("Story");
  });

  it("sets labels and story points (via the configured custom field)", async () => {
    const { tracker, calls } = harness(() => ({}));
    await tracker.setLabels("AUD-2", ["security"]);
    await tracker.setEstimate("AUD-2", 8);

    expect(jsonBody(calls[0])).toEqual({ fields: { labels: ["security"] } });
    expect(jsonBody(calls[1])).toEqual({ fields: { customfield_10016: 8 } });
  });

  it("uploads the brief as a native multipart attachment and returns its content URL", async () => {
    const { tracker, calls } = harness(() => [{ content: "https://acme.atlassian.net/rest/api/3/attachment/content/99" }]);
    const ref = await tracker.attachBrief("AUD-2", "# Brief");

    expect(ref).toEqual({ url: "https://acme.atlassian.net/rest/api/3/attachment/content/99" });
    expect(calls[0]?.url).toBe("https://acme.atlassian.net/rest/api/3/issue/AUD-2/attachments");
    expect(calls[0]?.headers["X-Atlassian-Token"]).toBe("no-check");
    expect(calls[0]?.body).toBeInstanceOf(FormData);
  });

  it("throws when the attachment upload returns no attachment", async () => {
    const { tracker } = harness(() => []);
    await expect(tracker.attachBrief("AUD-2", "x")).rejects.toThrow(/no attachment/);
  });

  it("finds an existing item by marker via a JQL text search (#50)", async () => {
    const { tracker, calls } = harness(() => ({ issues: [{ key: "AUD-9" }] }));
    const ref = await tracker.findByMarker("<!-- epic-builder:csv-export/epic -->");

    expect(ref).toEqual({ id: "AUD-9", url: "https://acme.atlassian.net/browse/AUD-9" });
    expect(calls[0]?.url).toContain("/rest/api/3/search?jql=");
    const jql = decodeURIComponent(String(calls[0]?.url).split("?jql=")[1] ?? "");
    expect(jql).toBe('project = AUD AND text ~ "<!-- epic-builder:csv-export/epic -->"');
  });

  it("returns null from findByMarker when the JQL search has no hits", async () => {
    const { tracker } = harness(() => ({ issues: [] }));
    expect(await tracker.findByMarker("<!-- epic-builder:csv-export/epic -->")).toBeNull();
  });

  it("updateStory PUTs description and/or labels only when the patch provides them", async () => {
    const { tracker, calls } = harness(() => ({}));
    await tracker.updateStory("AUD-2", { body: "First para.\n\nSecond para.", labels: ["security"] });

    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("https://acme.atlassian.net/rest/api/3/issue/AUD-2");
    const fields = jsonBody(calls[0]).fields as { description: { type: string; content: unknown[] }; labels: string[] };
    expect(fields.description.type).toBe("doc");
    expect(fields.description.content).toHaveLength(2);
    expect(fields.labels).toEqual(["security"]);
  });

  it("updateStory makes no request when the patch is empty", async () => {
    const { tracker, calls } = harness(() => ({}));
    await tracker.updateStory("AUD-2", {});
    expect(calls).toHaveLength(0);
  });
});
