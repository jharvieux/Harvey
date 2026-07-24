import { describe, expect, it, vi } from "vitest";
import { LinearTracker, type LinearConfig } from "./linear.js";

interface GraphQLCall {
  query: string;
  variables: Record<string, unknown>;
  authorization: string;
}

// Every Linear operation is a POST of { query, variables } to one endpoint, so the harness records the
// parsed body and lets each test answer based on the operation name found in the query string.
function harness(respond: (call: GraphQLCall) => unknown) {
  const calls: GraphQLCall[] = [];
  const fetchImpl = vi.fn(async (_url: string | URL, init?: RequestInit) => {
    const parsed = JSON.parse(String(init?.body)) as { query: string; variables: Record<string, unknown> };
    const call: GraphQLCall = {
      query: parsed.query,
      variables: parsed.variables,
      authorization: (init?.headers as Record<string, string>)?.Authorization ?? "",
    };
    calls.push(call);
    return new Response(JSON.stringify({ data: respond(call) }));
  }) as unknown as typeof fetch;
  const config: LinearConfig = { apiKey: "lin_api_key", teamId: "team-1", fetchImpl };
  const tracker = new LinearTracker(config);
  return { tracker, calls };
}

describe("LinearTracker", () => {
  it("creates an epic via issueCreate and sends the raw API key as the Authorization header", async () => {
    const { tracker, calls } = harness(() => ({ issueCreate: { issue: { id: "iss-1", url: "https://linear.app/acme/issue/ENG-1" } } }));
    const ref = await tracker.createEpic({ title: "Epic A", description: "body" });

    expect(ref).toEqual({ id: "iss-1", url: "https://linear.app/acme/issue/ENG-1" });
    expect(calls[0]?.authorization).toBe("lin_api_key"); // raw key, no Bearer prefix
    const input = calls[0]?.variables.input as Record<string, unknown>;
    expect(input).toEqual({ teamId: "team-1", title: "Epic A", description: "body", parentId: undefined });
  });

  it("creates a story as a sub-issue by setting parentId to the epic", async () => {
    const { tracker, calls } = harness(() => ({ issueCreate: { issue: { id: "iss-2", url: "u" } } }));
    const ref = await tracker.createStory({ title: "Story", description: "desc" }, "iss-1");

    expect(ref.id).toBe("iss-2");
    expect((calls[0]?.variables.input as { parentId: string }).parentId).toBe("iss-1");
  });

  it("resolves label names to ids (creating missing ones) before setting labelIds", async () => {
    const { tracker, calls } = harness((call) => {
      if (call.query.includes("labels(first")) return { team: { labels: { nodes: [{ id: "lbl-sec", name: "security" }] } } };
      if (call.query.includes("issueLabelCreate")) return { issueLabelCreate: { issueLabel: { id: "lbl-new" } } };
      return { issueUpdate: { success: true } };
    });

    await tracker.setLabels("iss-1", ["security", "high"]); // "security" exists, "high" must be created

    const create = calls.find((c) => c.query.includes("issueLabelCreate"));
    expect((create?.variables.input as { name: string }).name).toBe("high");
    const update = calls.find((c) => c.query.includes("issueUpdate"));
    expect((update?.variables.input as { labelIds: string[] }).labelIds).toEqual(["lbl-sec", "lbl-new"]);
  });

  it("sets the estimate via the native estimate field", async () => {
    const { tracker, calls } = harness(() => ({ issueUpdate: { success: true } }));
    await tracker.setEstimate("iss-1", 3);
    expect((calls[0]?.variables.input as { estimate: number }).estimate).toBe(3);
  });

  it("posts the brief as a comment and returns the comment URL", async () => {
    const { tracker, calls } = harness(() => ({ commentCreate: { comment: { url: "https://linear.app/acme/issue/ENG-1#comment-9" } } }));
    const ref = await tracker.attachBrief("iss-1", "# Brief");

    expect(ref).toEqual({ url: "https://linear.app/acme/issue/ENG-1#comment-9" });
    expect((calls[0]?.variables.input as { issueId: string; body: string })).toEqual({ issueId: "iss-1", body: "# Brief" });
  });

  it("finds an existing item by a description-contains filter, returning null on no hit", async () => {
    const { tracker, calls } = harness(() => ({ issues: { nodes: [{ id: "iss-9", url: "u9" }] } }));
    const ref = await tracker.findByMarker("<!-- epic-builder:csv-export/epic -->");
    expect(ref).toEqual({ id: "iss-9", url: "u9" });
    expect(calls[0]?.variables.marker).toBe("<!-- epic-builder:csv-export/epic -->");

    const { tracker: t2 } = harness(() => ({ issues: { nodes: [] } }));
    expect(await t2.findByMarker("x")).toBeNull();
  });

  it("updateStory sends description and/or labelIds only when the patch provides them", async () => {
    const { tracker, calls } = harness((call) =>
      call.query.includes("labels(first") ? { team: { labels: { nodes: [{ id: "lbl-sec", name: "security" }] } } } : { issueUpdate: { success: true } },
    );
    await tracker.updateStory("iss-2", { body: "new body", labels: ["security"] });
    const update = calls.find((c) => c.query.includes("issueUpdate"));
    expect(update?.variables.input).toEqual({ description: "new body", labelIds: ["lbl-sec"] });

    const { tracker: t2, calls: c2 } = harness(() => ({}));
    await t2.updateStory("iss-2", {});
    expect(c2).toHaveLength(0);
  });

  it("surfaces a GraphQL errors payload as a throw", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ errors: [{ message: "team not found" }] }))) as unknown as typeof fetch;
    const tracker = new LinearTracker({ apiKey: "lin_api_key", teamId: "team-1", fetchImpl });
    await expect(tracker.createEpic({ title: "x", description: "y" })).rejects.toThrow(/team not found/);
  });

  it("throws with the HTTP status when Linear returns a non-2xx", async () => {
    const fetchImpl = vi.fn(async () => new Response("Unauthorized", { status: 401 })) as unknown as typeof fetch;
    const tracker = new LinearTracker({ apiKey: "lin_api_key", teamId: "team-1", fetchImpl });
    await expect(tracker.createEpic({ title: "x", description: "y" })).rejects.toThrow(/401/);
  });

  // #883 fix-verification write-back
  it("adds a comment via commentCreate", async () => {
    const { tracker, calls } = harness(() => ({ commentCreate: { comment: { url: "u" } } }));
    await tracker.addComment("iss-1", "verified resolved");
    expect(calls[0]?.query).toContain("commentCreate");
    expect(calls[0]?.variables.input).toEqual({ issueId: "iss-1", body: "verified resolved" });
  });

  const states = {
    nodes: [
      { id: "st-backlog", name: "Backlog", type: "backlog" },
      { id: "st-todo", name: "Todo", type: "unstarted" },
      { id: "st-done", name: "Done", type: "completed" },
    ],
  };

  it("closes by resolving the team's completed-type state and setting stateId", async () => {
    const { tracker, calls } = harness((call) =>
      call.query.includes("states") ? { team: { states } } : { issueUpdate: { success: true } },
    );
    await tracker.transitionState("iss-1", "closed");
    expect((calls[1]?.variables.input as { stateId: string }).stateId).toBe("st-done");
  });

  it("reopens preferring the unstarted-type state", async () => {
    const { tracker, calls } = harness((call) =>
      call.query.includes("states") ? { team: { states } } : { issueUpdate: { success: true } },
    );
    await tracker.transitionState("iss-1", "reopened");
    expect((calls[1]?.variables.input as { stateId: string }).stateId).toBe("st-todo");
  });

  it("throws — never silently skips — when the team has no state of the wanted type", async () => {
    const { tracker } = harness(() => ({ team: { states: { nodes: [{ id: "s", name: "Started", type: "started" }] } } }));
    await expect(tracker.transitionState("iss-1", "closed")).rejects.toThrow(/no completed/);
  });
});
