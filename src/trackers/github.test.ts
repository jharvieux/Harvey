import { describe, expect, it, vi } from "vitest";
import { GitHubTracker, type GitHubConfig } from "./github.js";

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

// Records every request and routes by method+path to a canned GitHub-shaped response.
function harness(routes: (call: Call) => unknown) {
  const calls: Call[] = [];
  const fetchImpl = vi.fn(async (url: string | URL, init?: RequestInit) => {
    const call: Call = {
      url: url.toString(),
      method: init?.method ?? "GET",
      headers: (init?.headers as Record<string, string>) ?? {},
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    };
    calls.push(call);
    return new Response(JSON.stringify(routes(call) ?? {}));
  }) as unknown as typeof fetch;
  const config: GitHubConfig = { token: "gh-token", owner: "acme", repo: "app", fetchImpl };
  const tracker = new GitHubTracker(config);
  return { tracker, calls };
}

describe("GitHubTracker", () => {
  it("creates an epic as an issue and returns its number as id + canonical html_url", async () => {
    const { tracker, calls } = harness(() => ({ number: 10, html_url: "https://github.com/acme/app/issues/10", body: null }));
    const ref = await tracker.createEpic({ title: "Epic A", description: "body" });

    expect(ref).toEqual({ id: "10", url: "https://github.com/acme/app/issues/10" });
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.url).toBe("https://api.github.com/repos/acme/app/issues");
    expect(calls[0]?.headers.Authorization).toBe("Bearer gh-token");
    expect(calls[0]?.body).toEqual({ title: "Epic A", body: "body" });
  });

  it("links a story to its epic by appending a task-list item to the epic body", async () => {
    const { tracker, calls } = harness((call) => {
      if (call.method === "POST" && call.url.endsWith("/issues")) {
        return { number: 11, html_url: "https://github.com/acme/app/issues/11", body: null };
      }
      if (call.method === "GET") return { number: 10, html_url: "x", body: "Existing epic body" };
      return {};
    });

    const ref = await tracker.createStory({ title: "Story One", description: "desc" }, "10");
    expect(ref.id).toBe("11");

    const patch = calls.find((c) => c.method === "PATCH");
    expect(patch?.url).toBe("https://api.github.com/repos/acme/app/issues/10");
    expect((patch?.body as { body: string }).body).toBe("Existing epic body\n- [ ] #11 Story One");
  });

  it("replaces labels with PUT and adds an estimate label with POST", async () => {
    const { tracker, calls } = harness(() => ({}));
    await tracker.setLabels("10", ["security", "backend"]);
    await tracker.setEstimate("10", 5);

    expect(calls[0]?.method).toBe("PUT");
    expect(calls[0]?.body).toEqual({ labels: ["security", "backend"] });
    expect(calls[1]?.method).toBe("POST");
    expect(calls[1]?.body).toEqual({ labels: ["estimate:5"] });
  });

  it("commits the brief to the repo (base64) and returns the committed file URL", async () => {
    const fileUrl = "https://github.com/acme/app/blob/main/briefs/issue-10.md";
    const { tracker, calls } = harness(() => ({ content: { html_url: fileUrl } }));

    const ref = await tracker.attachBrief("10", "# Brief\n\nhello");
    expect(ref).toEqual({ url: fileUrl });

    const put = calls[0];
    expect(put?.method).toBe("PUT");
    expect(put?.url).toBe("https://api.github.com/repos/acme/app/contents/briefs/issue-10.md");
    const body = put?.body as { content: string };
    expect(Buffer.from(body.content, "base64").toString("utf8")).toBe("# Brief\n\nhello");
  });

  it("throws with the HTTP status when GitHub rejects the request", async () => {
    const fetchImpl = vi.fn(async () => new Response("Not Found", { status: 404 })) as unknown as typeof fetch;
    const tracker = new GitHubTracker({ token: "gh-token", owner: "acme", repo: "app", fetchImpl });
    await expect(tracker.createEpic({ title: "x", description: "y" })).rejects.toThrow(/404/);
  });

  it("finds an existing item by marker via a repo-scoped body search (#50)", async () => {
    const { tracker } = harness((call) => {
      expect(call.method).toBe("GET");
      expect(call.url).toContain("/search/issues?q=");
      const q = decodeURIComponent(call.url.split("?q=")[1] ?? "");
      expect(q).toBe('repo:acme/app in:body "<!-- epic-builder:csv-export/epic -->"');
      return { items: [{ number: 41, html_url: "https://github.com/acme/app/issues/41", body: "..." }] };
    });

    const ref = await tracker.findByMarker("<!-- epic-builder:csv-export/epic -->");
    expect(ref).toEqual({ id: "41", url: "https://github.com/acme/app/issues/41" });
  });

  it("returns null from findByMarker when the search has no hits", async () => {
    const { tracker } = harness(() => ({ items: [] }));
    const ref = await tracker.findByMarker("<!-- epic-builder:csv-export/epic -->");
    expect(ref).toBeNull();
  });

  it("updateStory PATCHes the body and PUTs labels only when the patch provides them", async () => {
    const { tracker, calls } = harness(() => ({}));
    await tracker.updateStory("11", { body: "new body" });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ method: "PATCH", url: "https://api.github.com/repos/acme/app/issues/11" });
    expect(calls[0]?.body).toEqual({ body: "new body" });

    const { tracker: tracker2, calls: calls2 } = harness(() => ({}));
    await tracker2.updateStory("11", { labels: ["security"] });
    expect(calls2).toHaveLength(1);
    expect(calls2[0]).toMatchObject({ method: "PUT", url: "https://api.github.com/repos/acme/app/issues/11/labels" });
    expect(calls2[0]?.body).toEqual({ labels: ["security"] });

    const { tracker: tracker3, calls: calls3 } = harness(() => ({}));
    await tracker3.updateStory("11", { body: "new body", labels: ["security"] });
    expect(calls3.map((c) => c.method)).toEqual(["PATCH", "PUT"]);
  });
});
