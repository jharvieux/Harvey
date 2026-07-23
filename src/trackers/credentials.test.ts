import { afterEach, describe, expect, it, vi } from "vitest";
import { AzureDevOpsTracker } from "./azure-devops.js";
import { GitHubTracker } from "./github.js";
import { GitLabTracker } from "./gitlab.js";
import { TrackerError } from "./http.js";
import { JiraTracker } from "./jira.js";
import { LinearTracker } from "./linear.js";
import type { Tracker } from "./types.js";

// The security-relevant contract for issue #22: a tracker adapter is handed a per-engagement
// PAT/OAuth token by the caller, must USE it to authenticate, but must NEVER let the raw token
// escape into a log line, an error message, or a serialization. These tests assert both halves.

const TOKEN = "SUPER-SECRET-PAT-do-not-leak-0xDEADBEEF";

// Each adapter, constructed with TOKEN, plus an assertion the token reached the Authorization header
// (so we know the "no leak" result isn't just because the token was never used).
const adapters: { name: string; make: (fetchImpl: typeof fetch) => Tracker; tokenSent: (auth: string) => boolean }[] = [
  {
    name: "GitHubTracker",
    make: (fetchImpl) => new GitHubTracker({ token: TOKEN, owner: "acme", repo: "app", fetchImpl }),
    tokenSent: (auth) => auth === `Bearer ${TOKEN}`,
  },
  {
    name: "JiraTracker",
    make: (fetchImpl) =>
      new JiraTracker({ baseUrl: "https://acme.atlassian.net", email: "a@acme.com", apiToken: TOKEN, projectKey: "AUD", fetchImpl }),
    tokenSent: (auth) => auth.startsWith("Basic ") && Buffer.from(auth.slice(6), "base64").toString("utf8").includes(TOKEN),
  },
  {
    name: "AzureDevOpsTracker",
    make: (fetchImpl) => new AzureDevOpsTracker({ orgUrl: "https://dev.azure.com/acme", project: "Audit", pat: TOKEN, fetchImpl }),
    tokenSent: (auth) => auth.startsWith("Basic ") && Buffer.from(auth.slice(6), "base64").toString("utf8").includes(TOKEN),
  },
  {
    name: "GitLabTracker",
    make: (fetchImpl) => new GitLabTracker({ token: TOKEN, projectId: "acme/app", fetchImpl }),
    tokenSent: (auth) => auth === `Bearer ${TOKEN}`,
  },
  {
    name: "LinearTracker",
    make: (fetchImpl) => new LinearTracker({ apiKey: TOKEN, teamId: "team-1", fetchImpl }),
    tokenSent: (auth) => auth === TOKEN, // Linear sends the API key verbatim, no Bearer prefix
  },
];

const consoleMethods = ["log", "info", "warn", "error", "debug"] as const;

afterEach(() => vi.restoreAllMocks());

describe.each(adapters)("$name credential handling", ({ make, tokenSent }) => {
  it("does not expose the token via JSON serialization of the adapter instance", () => {
    const tracker = make(vi.fn() as unknown as typeof fetch);
    expect(JSON.stringify(tracker)).not.toContain(TOKEN);
  });

  it("sends the token in the Authorization header (proving it is actually used)", async () => {
    let seenAuth = "";
    const fetchImpl = vi.fn(async (_url: string | URL, init?: RequestInit) => {
      seenAuth = (init?.headers as Record<string, string>)?.Authorization ?? "";
      // Superset body: fields for every adapter's createEpic parse path (GitHub/Jira/Azure/GitLab REST +
      // Linear GraphQL) so createEpic resolves for all of them from one canned response.
      return new Response(
        JSON.stringify({
          number: 1,
          id: 1,
          key: "AUD-1",
          html_url: "u",
          body: null,
          iid: 1,
          web_url: "u",
          _links: { html: { href: "u" } },
          data: { issueCreate: { issue: { id: "lin-1", url: "u" } } },
        }),
      );
    }) as unknown as typeof fetch;

    await make(fetchImpl).createEpic({ title: "t", description: "d" });
    expect(tokenSent(seenAuth)).toBe(true);
  });

  it("never puts the token in a thrown error (message, stack, or serialized form)", async () => {
    const fetchImpl = vi.fn(async () => new Response("upstream said no", { status: 401 })) as unknown as typeof fetch;
    const tracker = make(fetchImpl);

    let err: unknown;
    try {
      await tracker.createEpic({ title: "t", description: "d" });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(TrackerError); // adapters surface a typed HTTP error carrying only status/url/body
    expect((err as TrackerError).status).toBe(401);
    const error = err as Error;
    expect(error.message).not.toContain(TOKEN);
    expect(String(error.stack ?? "")).not.toContain(TOKEN);
    expect(JSON.stringify(error)).not.toContain(TOKEN);
  });

  it("sends the token for findByMarker and updateStory too (#50 additions)", async () => {
    const seenAuth: string[] = [];
    const fetchImpl = vi.fn(async (_url: string | URL, init?: RequestInit) => {
      seenAuth.push((init?.headers as Record<string, string>)?.Authorization ?? "");
      // Superset body: an empty result set for every adapter's marker search shape, plus the Linear
      // GraphQL sub-objects its updateStory label-resolution path reads (team labels, label create,
      // issue update) — one canned response that satisfies findByMarker and updateStory for all five.
      return new Response(
        JSON.stringify({
          items: [],
          issues: [],
          workItems: [],
          data: {
            issues: { nodes: [] },
            team: { labels: { nodes: [] } },
            issueLabelCreate: { issueLabel: { id: "lbl-1" } },
            issueUpdate: { success: true },
          },
        }),
      );
    }) as unknown as typeof fetch;

    const tracker = make(fetchImpl);
    expect(await tracker.findByMarker("<!-- epic-builder:acme/epic -->")).toBeNull();
    await tracker.updateStory("1", { body: "new body", labels: ["security"] });

    expect(seenAuth.length).toBeGreaterThan(0);
    for (const auth of seenAuth) expect(tokenSent(auth)).toBe(true);
  });

  it("never puts the token in a thrown error from findByMarker or updateStory", async () => {
    const fetchImpl = vi.fn(async () => new Response("upstream said no", { status: 401 })) as unknown as typeof fetch;
    const tracker = make(fetchImpl);

    for (const attempt of [
      () => tracker.findByMarker("<!-- epic-builder:acme/epic -->"),
      () => tracker.updateStory("1", { body: "new body" }),
    ]) {
      let err: unknown;
      try {
        await attempt();
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(TrackerError);
      const error = err as Error;
      expect(error.message).not.toContain(TOKEN);
      expect(String(error.stack ?? "")).not.toContain(TOKEN);
      expect(JSON.stringify(error)).not.toContain(TOKEN);
    }
  });

  it("never writes the token to the console during a failing call", async () => {
    const spies = consoleMethods.map((m) => vi.spyOn(console, m).mockImplementation(() => {}));
    const fetchImpl = vi.fn(async () => new Response("nope", { status: 403 })) as unknown as typeof fetch;

    await make(fetchImpl)
      .createEpic({ title: "t", description: "d" })
      .catch(() => {});

    for (const spy of spies) {
      for (const call of spy.mock.calls) {
        expect(JSON.stringify(call)).not.toContain(TOKEN);
      }
    }
  });
});
