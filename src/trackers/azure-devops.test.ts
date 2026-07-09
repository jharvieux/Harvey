import { describe, expect, it, vi } from "vitest";
import { AzureDevOpsTracker, type AzureDevOpsConfig } from "./azure-devops.js";

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  bodyText: string;
}

function harness(routes: (call: Call) => unknown) {
  const calls: Call[] = [];
  const fetchImpl = vi.fn(async (url: string | URL, init?: RequestInit) => {
    const call: Call = {
      url: url.toString(),
      method: init?.method ?? "GET",
      headers: (init?.headers as Record<string, string>) ?? {},
      bodyText: init?.body ? String(init.body) : "",
    };
    calls.push(call);
    return new Response(JSON.stringify(routes(call) ?? {}));
  }) as unknown as typeof fetch;
  const config: AzureDevOpsConfig = {
    orgUrl: "https://dev.azure.com/acme",
    project: "Audit",
    pat: "ado-pat",
    fetchImpl,
  };
  const tracker = new AzureDevOpsTracker(config);
  return { tracker, calls };
}

const workItem = (id: number) => ({ id, _links: { html: { href: `https://dev.azure.com/acme/Audit/_workitems/edit/${id}` } } });

describe("AzureDevOpsTracker", () => {
  it("creates an epic via a JSON-Patch work-item POST and returns id + html link", async () => {
    const { tracker, calls } = harness(() => workItem(5));
    const ref = await tracker.createEpic({ title: "Epic A", description: "body" });

    expect(ref).toEqual({ id: "5", url: "https://dev.azure.com/acme/Audit/_workitems/edit/5" });
    expect(calls[0]?.url).toBe("https://dev.azure.com/acme/Audit/_apis/wit/workitems/$Epic?api-version=7.1");
    expect(calls[0]?.headers["Content-Type"]).toBe("application/json-patch+json");
    // PAT sent as Basic with empty username.
    expect(calls[0]?.headers.Authorization).toBe(`Basic ${Buffer.from(":ado-pat").toString("base64")}`);
    const patch = JSON.parse(calls[0]!.bodyText) as { path: string; value: unknown }[];
    expect(patch).toContainEqual({ op: "add", path: "/fields/System.Title", value: "Epic A" });
  });

  it("links a story to its epic via a Hierarchy-Reverse relation to the parent's API URL", async () => {
    const { tracker, calls } = harness(() => workItem(6));
    const ref = await tracker.createStory({ title: "Story", description: "d" }, "5");

    expect(ref.id).toBe("6");
    expect(calls[0]?.url).toBe("https://dev.azure.com/acme/Audit/_apis/wit/workitems/$User%20Story?api-version=7.1");
    const patch = JSON.parse(calls[0]!.bodyText) as { path: string; value: { rel: string; url: string } }[];
    const relation = patch.find((p) => p.path === "/relations/-");
    expect(relation?.value).toEqual({
      rel: "System.LinkTypes.Hierarchy-Reverse",
      url: "https://dev.azure.com/acme/_apis/wit/workItems/5",
    });
  });

  it("sets tags (semicolon-joined) and story points via JSON-Patch PATCH", async () => {
    const { tracker, calls } = harness(() => workItem(6));
    await tracker.setLabels("6", ["security", "backend"]);
    await tracker.setEstimate("6", 8);

    expect(calls[0]?.method).toBe("PATCH");
    expect(JSON.parse(calls[0]!.bodyText)).toEqual([{ op: "add", path: "/fields/System.Tags", value: "security; backend" }]);
    expect(JSON.parse(calls[1]!.bodyText)).toEqual([
      { op: "add", path: "/fields/Microsoft.VSTS.Scheduling.StoryPoints", value: 8 },
    ]);
  });

  it("uploads the brief then links it as an AttachedFile relation, returning the attachment URL", async () => {
    const attachmentUrl = "https://dev.azure.com/acme/Audit/_apis/wit/attachments/abc";
    const { tracker, calls } = harness((call) => (call.url.includes("/attachments?") ? { url: attachmentUrl } : workItem(6)));

    const ref = await tracker.attachBrief("6", "# Brief");
    expect(ref).toEqual({ url: attachmentUrl });

    expect(calls[0]?.url).toBe("https://dev.azure.com/acme/Audit/_apis/wit/attachments?fileName=brief-6.md&api-version=7.1");
    expect(calls[0]?.headers["Content-Type"]).toBe("application/octet-stream");
    const patch = JSON.parse(calls[1]!.bodyText) as { value: { rel: string; url: string } }[];
    expect(patch[0]?.value.rel).toBe("AttachedFile");
    expect(patch[0]?.value.url).toBe(attachmentUrl);
  });

  it("finds an existing item by marker via a WIQL CONTAINS query, then fetches its html link (#50)", async () => {
    const { tracker, calls } = harness((call) =>
      call.url.includes("/wiql?") ? { workItems: [{ id: 9 }] } : workItem(9),
    );
    const ref = await tracker.findByMarker("<!-- epic-builder:csv-export/epic -->");

    expect(ref).toEqual({ id: "9", url: "https://dev.azure.com/acme/Audit/_workitems/edit/9" });
    expect(calls[0]?.url).toBe("https://dev.azure.com/acme/Audit/_apis/wit/wiql?api-version=7.1");
    const body = JSON.parse(calls[0]!.bodyText) as { query: string };
    expect(body.query).toContain("[System.Description] CONTAINS '<!-- epic-builder:csv-export/epic -->'");
    expect(calls[1]?.url).toBe("https://dev.azure.com/acme/_apis/wit/workItems/9?api-version=7.1");
  });

  it("returns null from findByMarker when the WIQL query has no hits", async () => {
    const { tracker } = harness(() => ({ workItems: [] }));
    expect(await tracker.findByMarker("<!-- epic-builder:csv-export/epic -->")).toBeNull();
  });

  it("updateStory PATCHes description and/or tags only when the patch provides them", async () => {
    const { tracker, calls } = harness(() => workItem(6));
    await tracker.updateStory("6", { body: "new description", labels: ["security", "backend"] });

    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe("PATCH");
    expect(JSON.parse(calls[0]!.bodyText)).toEqual([
      { op: "add", path: "/fields/System.Description", value: "new description" },
      { op: "add", path: "/fields/System.Tags", value: "security; backend" },
    ]);
  });

  it("updateStory makes no request when the patch is empty", async () => {
    const { tracker, calls } = harness(() => workItem(6));
    await tracker.updateStory("6", {});
    expect(calls).toHaveLength(0);
  });
});
