import { describe, expect, it, vi } from "vitest";
import { GitLabTracker, type GitLabConfig } from "./gitlab.js";

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

// Records every request and routes by method+path to a canned GitLab-shaped response. JSON bodies are
// parsed; a FormData body (the /uploads multipart) is passed through untouched.
function harness(routes: (call: Call) => unknown) {
  const calls: Call[] = [];
  const fetchImpl = vi.fn(async (url: string | URL, init?: RequestInit) => {
    const rawBody = init?.body;
    const call: Call = {
      url: url.toString(),
      method: init?.method ?? "GET",
      headers: (init?.headers as Record<string, string>) ?? {},
      body: typeof rawBody === "string" ? JSON.parse(rawBody) : rawBody,
    };
    calls.push(call);
    return new Response(JSON.stringify(routes(call) ?? {}));
  }) as unknown as typeof fetch;
  const config: GitLabConfig = { token: "gl-token", projectId: "acme/app", fetchImpl };
  const tracker = new GitLabTracker(config);
  return { tracker, calls };
}

describe("GitLabTracker", () => {
  it("creates an epic as an issue and returns its iid as id + web_url", async () => {
    const { tracker, calls } = harness(() => ({ iid: 10, web_url: "https://gitlab.com/acme/app/-/issues/10" }));
    const ref = await tracker.createEpic({ title: "Epic A", description: "body" });

    expect(ref).toEqual({ id: "10", url: "https://gitlab.com/acme/app/-/issues/10" });
    expect(calls[0]?.method).toBe("POST");
    // projectId is URL-encoded into the path.
    expect(calls[0]?.url).toBe("https://gitlab.com/api/v4/projects/acme%2Fapp/issues");
    expect(calls[0]?.headers.Authorization).toBe("Bearer gl-token");
    expect(calls[0]?.body).toEqual({ title: "Epic A", description: "body" });
  });

  it("links a story to its epic by appending a task-list item to the epic description", async () => {
    const { tracker, calls } = harness((call) => {
      if (call.method === "POST") return { iid: 11, web_url: "https://gitlab.com/acme/app/-/issues/11" };
      if (call.method === "GET") return { iid: 10, web_url: "x", description: "Existing epic body" };
      return {};
    });

    const ref = await tracker.createStory({ title: "Story One", description: "desc" }, "10");
    expect(ref.id).toBe("11");

    const put = calls.find((c) => c.method === "PUT");
    expect(put?.url).toBe("https://gitlab.com/api/v4/projects/acme%2Fapp/issues/10");
    expect((put?.body as { description: string }).description).toBe("Existing epic body\n- [ ] #11 Story One");
  });

  it("replaces labels with a comma-joined string and sets the estimate as weight", async () => {
    const { tracker, calls } = harness(() => ({}));
    await tracker.setLabels("10", ["security", "backend"]);
    await tracker.setEstimate("10", 5);

    expect(calls[0]?.method).toBe("PUT");
    expect(calls[0]?.body).toEqual({ labels: "security,backend" });
    expect(calls[1]?.body).toEqual({ weight: 5 });
  });

  it("uploads the brief via /uploads and returns the hosted file's canonical URL", async () => {
    const { tracker, calls } = harness(() => ({ full_path: "/-/project/1/uploads/abc/brief-10.md" }));
    const ref = await tracker.attachBrief("10", "# Brief");

    expect(ref).toEqual({ url: "https://gitlab.com/-/project/1/uploads/abc/brief-10.md" });
    expect(calls[0]?.url).toBe("https://gitlab.com/api/v4/projects/acme%2Fapp/uploads");
    expect(calls[0]?.body).toBeInstanceOf(FormData);
  });

  it("finds an existing item by marker via a description-scoped search (#733)", async () => {
    const { tracker, calls } = harness((call) => {
      expect(call.method).toBe("GET");
      expect(call.url).toContain("in=description");
      return [{ iid: 41, web_url: "https://gitlab.com/acme/app/-/issues/41" }];
    });

    const ref = await tracker.findByMarker("<!-- epic-builder:csv-export/epic -->");
    expect(ref).toEqual({ id: "41", url: "https://gitlab.com/acme/app/-/issues/41" });
    const search = decodeURIComponent(calls[0]?.url.split("search=")[1]?.split("&")[0] ?? "");
    expect(search).toBe("<!-- epic-builder:csv-export/epic -->");
  });

  it("returns null from findByMarker when the search has no hits", async () => {
    const { tracker } = harness(() => []);
    expect(await tracker.findByMarker("<!-- epic-builder:csv-export/epic -->")).toBeNull();
  });

  it("updateStory PUTs description and/or labels only when the patch provides them", async () => {
    const { tracker, calls } = harness(() => ({}));
    await tracker.updateStory("11", { body: "new body", labels: ["security"] });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe("PUT");
    expect(calls[0]?.body).toEqual({ description: "new body", labels: "security" });

    const { tracker: t2, calls: c2 } = harness(() => ({}));
    await t2.updateStory("11", {});
    expect(c2).toHaveLength(0);
  });

  it("throws with the HTTP status when GitLab rejects the request", async () => {
    const fetchImpl = vi.fn(async () => new Response("Forbidden", { status: 403 })) as unknown as typeof fetch;
    const tracker = new GitLabTracker({ token: "gl-token", projectId: "acme/app", fetchImpl });
    await expect(tracker.createEpic({ title: "x", description: "y" })).rejects.toThrow(/403/);
  });
});
